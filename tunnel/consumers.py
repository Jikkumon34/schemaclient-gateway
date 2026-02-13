from __future__ import annotations

import base64
import json
import logging
from typing import Any
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import BooleanField, Case, F, Value, When
from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from .models import Tunnel, TunnelRequest
from .runtime import notify_response_waiter

User = get_user_model()
logger = logging.getLogger(__name__)


class TunnelConsumer(AsyncWebsocketConsumer):
    tunnel_id: str
    group_name: str
    tunnel_pk: int

    async def connect(self) -> None:
        try:
            tunnel_id = (self.scope.get("url_route", {}).get("kwargs", {}).get("tunnel_id") or "").strip().lower()
            connect_key = self._read_connect_key()
            raw_auth_token = self._read_auth_token()

            if not tunnel_id or not connect_key or not raw_auth_token:
                await self.close(code=4401)
                return

            user = await self._resolve_authenticated_user(raw_auth_token)
            if user is None:
                await self.close(code=4401)
                return

            tunnel = await self._get_tunnel(tunnel_id)
            if tunnel is None:
                await self.close(code=4404)
                return

            if tunnel.get("owner_id") is None or int(tunnel["owner_id"]) != int(user.id):
                await self.close(code=4403)
                return

            verified = await self._verify_connect_key(tunnel["pk"], connect_key)
            if not verified:
                await self.close(code=4401)
                return

            if self.channel_layer is None:
                logger.error("Tunnel websocket rejected because channel layer is unavailable")
                await self.close(code=4500)
                return

            self.tunnel_id = tunnel_id
            self.tunnel_pk = tunnel["pk"]
            self.group_name = f"tunnel.{tunnel_id}"

            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            await self._mark_connected(self.tunnel_pk)
            await self.send_json(
                {
                    "type": "connected",
                    "tunnel_id": self.tunnel_id,
                    "timestamp": timezone.now().isoformat(),
                }
            )
        except Exception:
            logger.exception("Unhandled tunnel websocket connect failure")
            await self.close(code=4500)

    async def disconnect(self, close_code: int) -> None:
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        if hasattr(self, "tunnel_pk"):
            await self._mark_disconnected(self.tunnel_pk)

    async def receive(self, text_data: str | None = None, bytes_data: bytes | None = None) -> None:
        if not text_data:
            return

        try:
            payload = json.loads(text_data)
        except json.JSONDecodeError:
            await self.send_json({"type": "error", "detail": "Invalid JSON"})
            return

        message_type = str(payload.get("type") or "").strip().lower()
        if message_type == "heartbeat":
            await self._touch_tunnel(self.tunnel_pk)
            return

        if message_type == "response":
            ok, error = await self._store_response(payload)
            if ok:
                await self._touch_tunnel(self.tunnel_pk)
            else:
                await self.send_json({"type": "error", "detail": error})
            return

        await self.send_json({"type": "error", "detail": f"Unsupported message type: {message_type}"})

    async def tunnel_forward_request(self, event: dict[str, Any]) -> None:
        payload = event.get("payload") or {}
        await self.send_json(payload)

    async def send_json(self, payload: dict[str, Any]) -> None:
        await self.send(text_data=json.dumps(payload))

    def _header_value(self, header_name: bytes) -> str:
        headers = self.scope.get("headers") or []
        for key, value in headers:
            if key.lower() == header_name.lower():
                return value.decode("utf-8", errors="ignore").strip()
        return ""

    def _query_value(self, key: str) -> str:
        query_string = (self.scope.get("query_string") or b"").decode("utf-8", errors="ignore")
        if not query_string:
            return ""
        query = parse_qs(query_string)
        return (query.get(key) or [""])[0].strip()

    def _read_connect_key(self) -> str:
        raw = self._header_value(b"x-tunnel-key")
        if raw:
            return raw
        raw_auth = self._header_value(b"authorization")
        prefix = "TunnelKey "
        if raw_auth.startswith(prefix):
            return raw_auth[len(prefix) :].strip()
        query_connect_key = self._query_value("connect_key")
        if query_connect_key:
            return query_connect_key
        return ""

    def _read_auth_token(self) -> str:
        raw_auth = self._header_value(b"authorization")
        raw_token = ""
        bearer_prefix = "Bearer "
        if raw_auth.startswith(bearer_prefix):
            raw_token = raw_auth[len(bearer_prefix) :].strip()
        if not raw_token:
            raw_header_token = self._header_value(b"x-auth-token")
            if raw_header_token.startswith(bearer_prefix):
                raw_token = raw_header_token[len(bearer_prefix) :].strip()
            else:
                raw_token = raw_header_token.strip()
        if not raw_token:
            raw_token = self._query_value("access_token")
        if not raw_token:
            raw_token = self._query_value("auth_token")
        if not raw_token:
            return ""
        return raw_token

    @database_sync_to_async
    def _resolve_authenticated_user(self, raw_token: str) -> User | None:
        auth = JWTAuthentication()
        try:
            validated = auth.get_validated_token(raw_token)
            user = auth.get_user(validated)
        except (InvalidToken, TokenError, TypeError, ValueError):
            return None
        if not isinstance(user, User):
            return None
        return user

    @database_sync_to_async
    def _get_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        try:
            tunnel = Tunnel.objects.get(tunnel_id=tunnel_id)
            return {"pk": tunnel.pk, "owner_id": tunnel.owner_id}
        except Tunnel.DoesNotExist:
            return None

    @database_sync_to_async
    def _verify_connect_key(self, tunnel_pk: int, connect_key: str) -> bool:
        try:
            tunnel = Tunnel.objects.get(pk=tunnel_pk)
        except Tunnel.DoesNotExist:
            return False
        return tunnel.verify_connect_key(connect_key)

    @database_sync_to_async
    def _mark_connected(self, tunnel_pk: int) -> None:
        now = timezone.now()
        Tunnel.objects.filter(pk=tunnel_pk).update(
            ws_connection_count=F("ws_connection_count") + 1,
            ws_connected=True,
            ws_connected_at=now,
            is_active=True,
            last_seen=now,
            updated_at=now,
        )

    @database_sync_to_async
    def _mark_disconnected(self, tunnel_pk: int) -> None:
        now = timezone.now()
        Tunnel.objects.filter(pk=tunnel_pk).update(
            ws_connection_count=F("ws_connection_count") - 1,
            updated_at=now,
        )
        Tunnel.objects.filter(pk=tunnel_pk, ws_connection_count__lt=0).update(ws_connection_count=0, updated_at=now)
        Tunnel.objects.filter(pk=tunnel_pk).update(
            ws_connected=Case(
                When(ws_connection_count__gt=0, then=Value(True)),
                default=Value(False),
                output_field=BooleanField(),
            ),
            is_active=Case(
                When(ws_connection_count__gt=0, then=Value(True)),
                default=Value(False),
                output_field=BooleanField(),
            ),
            updated_at=now,
        )

    @database_sync_to_async
    def _touch_tunnel(self, tunnel_pk: int) -> None:
        now = timezone.now()
        Tunnel.objects.filter(pk=tunnel_pk).update(is_active=True, last_seen=now, updated_at=now)

    @database_sync_to_async
    def _store_response(self, payload: dict[str, Any]) -> tuple[bool, str]:
        request_id = str(payload.get("request_id") or "").strip()
        if not request_id:
            return False, "request_id is required"

        try:
            status = int(payload.get("status"))
        except (TypeError, ValueError):
            return False, "status must be an integer"

        if status < 100 or status > 599:
            return False, "status must be a valid HTTP status code"

        headers = payload.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        sanitized_headers = {str(k): str(v) for k, v in headers.items() if str(k).strip()}

        body_b64 = str(payload.get("body_b64") or "")
        raw_max = getattr(settings, "TUNNEL_MAX_RESPONSE_BODY_BYTES", 5 * 1024 * 1024)
        try:
            max_response_body_bytes = int(raw_max)
        except (TypeError, ValueError):
            max_response_body_bytes = 5 * 1024 * 1024
        max_response_body_bytes = max(1024, max_response_body_bytes)
        response_body = b""
        if body_b64:
            try:
                response_body = base64.b64decode(body_b64.encode("ascii"), validate=True)
            except (ValueError, TypeError):
                return False, "body_b64 must be valid base64"

        if len(response_body) > max_response_body_bytes:
            return False, "Response body too large for tunnel forwarding"

        body_binary = bool(payload.get("body_binary", False))
        body_size = len(response_body)
        normalized_body_b64 = base64.b64encode(response_body).decode("ascii") if response_body else ""

        try:
            tunnel_request = TunnelRequest.objects.get(request_id=request_id, tunnel_id=self.tunnel_pk)
        except TunnelRequest.DoesNotExist:
            return False, "Tunnel request not found"

        tunnel_request.status = TunnelRequest.STATUS_RESPONDED
        tunnel_request.responded_at = timezone.now()
        tunnel_request.response_status = status
        tunnel_request.response_headers = sanitized_headers
        tunnel_request.response_body_b64 = normalized_body_b64
        tunnel_request.response_body_binary = body_binary
        tunnel_request.response_body_size = body_size
        tunnel_request.save(
            update_fields=[
                "status",
                "responded_at",
                "response_status",
                "response_headers",
                "response_body_b64",
                "response_body_binary",
                "response_body_size",
            ]
        )
        notify_response_waiter(request_id)

        return True, ""
