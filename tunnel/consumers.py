from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.db.models import F
from django.utils import timezone

from .models import Tunnel, TunnelRequest


class TunnelConsumer(AsyncWebsocketConsumer):
    tunnel_id: str
    group_name: str
    tunnel_pk: int

    async def connect(self) -> None:
        tunnel_id = (self.scope.get("url_route", {}).get("kwargs", {}).get("tunnel_id") or "").strip().lower()
        connect_key = self._query_param("connect_key")

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

    def _query_param(self, name: str) -> str:
        raw = (self.scope.get("query_string") or b"").decode("utf-8", errors="ignore")
        parsed = parse_qs(raw, keep_blank_values=True)
        values = parsed.get(name)
        if not values:
            return ""
        return str(values[0]).strip()

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
        try:
            tunnel = Tunnel.objects.get(pk=tunnel_pk)
        except Tunnel.DoesNotExist:
            return

        new_count = max(0, tunnel.ws_connection_count - 1)
        tunnel.ws_connection_count = new_count
        tunnel.ws_connected = new_count > 0
        if not tunnel.ws_connected:
            tunnel.is_active = False
        tunnel.save(update_fields=["ws_connection_count", "ws_connected", "is_active", "updated_at"])

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
        body_binary = bool(payload.get("body_binary", False))

        try:
            body_size = int(payload.get("body_size", 0) or 0)
        except (TypeError, ValueError):
            body_size = 0

        try:
            tunnel_request = TunnelRequest.objects.get(request_id=request_id, tunnel_id=self.tunnel_pk)
        except TunnelRequest.DoesNotExist:
            return False, "Tunnel request not found"

        tunnel_request.status = TunnelRequest.STATUS_RESPONDED
        tunnel_request.responded_at = timezone.now()
        tunnel_request.response_status = status
        tunnel_request.response_headers = sanitized_headers
        tunnel_request.response_body_b64 = body_b64
        tunnel_request.response_body_binary = body_binary
        tunnel_request.response_body_size = max(0, body_size)
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

        return True, ""
