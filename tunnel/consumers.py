from __future__ import annotations

import base64
import json
from typing import Any

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from django.db.models import BooleanField, Case, F, Value, When
from django.utils import timezone

from .models import Tunnel, TunnelRequest
from .runtime import notify_response_waiter


class TunnelConsumer(AsyncWebsocketConsumer):
    tunnel_id: str
    group_name: str
    tunnel_pk: int

    async def connect(self) -> None:
        tunnel_id = (self.scope.get("url_route", {}).get("kwargs", {}).get("tunnel_id") or "").strip().lower()
        connect_key = self._read_connect_key_from_authorization()

        if not tunnel_id or not connect_key:
            await self.close(code=4401)
            return

        tunnel = await self._get_tunnel(tunnel_id)
        if tunnel is None:
            await self.close(code=4404)
            return

        verified = await self._verify_connect_key(tunnel["pk"], connect_key)
        if not verified:
            await self.close(code=4401)
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

    def _read_connect_key_from_authorization(self) -> str:
        headers = self.scope.get("headers") or []
        raw_auth = ""
        for key, value in headers:
            if key.lower() == b"authorization":
                raw_auth = value.decode("utf-8", errors="ignore").strip()
                break
        if not raw_auth:
            return ""
        prefix = "TunnelKey "
        if not raw_auth.startswith(prefix):
            return ""
        return raw_auth[len(prefix) :].strip()

    @database_sync_to_async
    def _get_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        try:
            tunnel = Tunnel.objects.get(tunnel_id=tunnel_id)
            return {"pk": tunnel.pk}
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
