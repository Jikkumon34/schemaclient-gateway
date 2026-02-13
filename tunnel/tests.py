import json
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from .models import Tunnel, TunnelRequest


@override_settings(
    ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1", ".mysmeclabs.com"],
    TUNNEL_BASE_DOMAIN="mysmeclabs.com",
    TUNNEL_PUBLIC_SCHEME="https",
    TUNNEL_REQUEST_TIMEOUT_SECONDS=1,
)
class TunnelApiTests(TestCase):
    def test_tunnel_health_endpoint(self):
        response = self.client.get("/api/tunnels/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "websocket")
        self.assertEqual(payload["base_domain"], "mysmeclabs.com")
        self.assertIn("websocket_ready", payload)

    def test_create_tunnel_returns_public_url_on_root_domain(self):
        response = self.client.post(
            "/api/tunnels/create",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertIn("tunnel_id", payload)
        self.assertIn("connect_key", payload)
        self.assertEqual(
            payload["public_url"],
            f"https://{payload['tunnel_id']}.mysmeclabs.com",
        )

    def test_connect_and_disconnect_cycle(self):
        connect_key = "secret-key"
        tunnel = Tunnel.objects.create(
            tunnel_id="demo1234",
            connect_key_hash=Tunnel.hash_connect_key(connect_key),
            is_active=False,
        )

        connect_response = self.client.post(
            "/api/tunnels/connect",
            data=json.dumps(
                {
                    "tunnel_id": tunnel.tunnel_id,
                    "connect_key": connect_key,
                    "local_target_url": "http://127.0.0.1:8000",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(connect_response.status_code, 200)

        tunnel.refresh_from_db()
        self.assertTrue(tunnel.is_active)
        self.assertEqual(tunnel.local_target_url, "http://127.0.0.1:8000")

        disconnect_response = self.client.post(
            "/api/tunnels/disconnect",
            data=json.dumps({"tunnel_id": tunnel.tunnel_id, "connect_key": connect_key}),
            content_type="application/json",
        )
        self.assertEqual(disconnect_response.status_code, 200)

        tunnel.refresh_from_db()
        self.assertFalse(tunnel.is_active)
        self.assertFalse(tunnel.ws_connected)
        self.assertEqual(tunnel.ws_connection_count, 0)

    def test_legacy_polling_endpoints_removed(self):
        self.assertEqual(self.client.post("/api/tunnels/heartbeat").status_code, 404)
        self.assertEqual(self.client.get("/api/tunnels/pull").status_code, 404)
        self.assertEqual(self.client.post("/api/tunnels/respond").status_code, 404)

    def test_gateway_dispatch_on_main_domain(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Gateway", response.content.decode("utf-8"))

    def test_gateway_dispatch_times_out_for_offline_tunnel(self):
        Tunnel.objects.create(
            tunnel_id="offline1",
            connect_key_hash=Tunnel.hash_connect_key("abc"),
            is_active=False,
            last_seen=timezone.now(),
        )
        response = self.client.get("/api/posts", HTTP_HOST="offline1.mysmeclabs.com")
        self.assertEqual(response.status_code, 503)

    def test_gateway_dispatch_times_out_without_response(self):
        tunnel = Tunnel.objects.create(
            tunnel_id="online11",
            connect_key_hash=Tunnel.hash_connect_key("abc"),
            is_active=True,
            ws_connected=True,
            ws_connection_count=1,
            last_seen=timezone.now(),
        )

        response = self.client.get("/api/posts", HTTP_HOST="online11.mysmeclabs.com")
        self.assertEqual(response.status_code, 504)

        req = TunnelRequest.objects.filter(tunnel=tunnel).order_by("-created_at").first()
        self.assertIsNotNone(req)
        assert req is not None
        self.assertEqual(req.status, TunnelRequest.STATUS_TIMED_OUT)


class AuthApiTests(TestCase):
    def test_guest_login_returns_jwt_and_guest_profile(self):
        response = self.client.post("/api/auth/guest", data=json.dumps({}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["mode"], "guest")
        self.assertTrue(payload["user"]["is_guest"])
        self.assertIn("access_token", payload)
        self.assertIn("refresh_token", payload)

    def test_desktop_login_exchange_flow(self):
        user_model = get_user_model()
        user_model.objects.create_user(username="alice", password="StrongPass!123", email="alice@example.com")

        start_response = self.client.get(
            "/api/auth/desktop/login",
            {
                "redirect_uri": "http://127.0.0.1:4567/auth/callback",
                "state": "abc123",
            },
        )
        self.assertEqual(start_response.status_code, 302)
        self.assertIn("/api/auth/login", start_response["Location"])

        login_url = urlparse(start_response["Location"])
        next_url = parse_qs(login_url.query).get("next", [""])[0]
        login_response = self.client.post(
            "/api/auth/login",
            data={
                "username": "alice",
                "password": "StrongPass!123",
                "next": next_url,
            },
        )
        self.assertEqual(login_response.status_code, 302)

        desktop_redirect = self.client.get(login_response["Location"])
        self.assertEqual(desktop_redirect.status_code, 302)

        redirect_target = desktop_redirect["Location"]
        parsed = urlparse(redirect_target)
        query = parse_qs(parsed.query)
        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", "http://127.0.0.1:4567/auth/callback")
        self.assertEqual(query.get("state", [None])[0], "abc123")
        self.assertIn("code", query)
        code = query["code"][0]

        exchange = self.client.post(
            "/api/auth/desktop/exchange",
            data=json.dumps({"code": code}),
            content_type="application/json",
        )
        self.assertEqual(exchange.status_code, 200)
        exchange_payload = exchange.json()
        self.assertEqual(exchange_payload["mode"], "authenticated")
        self.assertEqual(exchange_payload["user"]["username"], "alice")

        reused = self.client.post(
            "/api/auth/desktop/exchange",
            data=json.dumps({"code": code}),
            content_type="application/json",
        )
        self.assertEqual(reused.status_code, 400)

    def test_me_endpoint_with_bearer_token(self):
        guest_response = self.client.post("/api/auth/guest", data=json.dumps({}), content_type="application/json")
        token = guest_response.json()["access_token"]

        me_response = self.client.get("/api/auth/me", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(me_response.status_code, 200)
        self.assertTrue(me_response.json()["user"]["is_guest"])

    def test_desktop_login_rejects_invalid_redirect_uri(self):
        response = self.client.get(
            "/api/auth/desktop/login",
            {
                "redirect_uri": "https://example.com/callback",
                "state": "abc123",
            },
        )
        self.assertEqual(response.status_code, 400)
