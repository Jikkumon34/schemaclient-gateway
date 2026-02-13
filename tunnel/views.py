from __future__ import annotations

import base64
import json
import re
import secrets
import string
import time
from typing import Any
from urllib.parse import urlparse

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseNotFound, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Tunnel, TunnelRequest


TUNNEL_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{2,30}[a-z0-9])?$")

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _setting_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = getattr(settings, name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _json_error(detail: str, status: int) -> JsonResponse:
    return JsonResponse({"detail": detail}, status=status)


def _parse_json_object(request: HttpRequest) -> tuple[dict[str, Any], JsonResponse | None]:
    if not request.body:
        return {}, None
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, _json_error("Invalid JSON payload", 400)
    if not isinstance(payload, dict):
        return {}, _json_error("JSON payload must be an object", 400)
    return payload, None


def _normalize_tunnel_id(raw_tunnel_id: Any) -> str | None:
    tunnel_id = str(raw_tunnel_id or "").strip().lower()
    if not tunnel_id:
        return None
    if not TUNNEL_ID_PATTERN.fullmatch(tunnel_id):
        return None
    return tunnel_id


def _random_tunnel_id(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _generate_unique_tunnel_id() -> str:
    for _ in range(20):
        candidate = _random_tunnel_id(8)
        if not Tunnel.objects.filter(tunnel_id=candidate).exists():
            return candidate
    while True:
        candidate = _random_tunnel_id(12)
        if not Tunnel.objects.filter(tunnel_id=candidate).exists():
            return candidate


def _build_public_url(request: HttpRequest, tunnel_id: str) -> str:
    scheme = str(getattr(settings, "TUNNEL_PUBLIC_SCHEME", "https")).strip().lower() or "https"
    base_domain = str(getattr(settings, "TUNNEL_BASE_DOMAIN", "")).strip().lower()
    if not base_domain:
        base_domain = request.get_host().split(":")[0].lower()
    return f"{scheme}://{tunnel_id}.{base_domain}"


def _sanitize_headers(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    sanitized: dict[str, str] = {}
    for key, value in raw.items():
        key_str = str(key).strip()
        if key_str:
            sanitized[key_str] = str(value)
    return sanitized


def _normalize_local_target_url(raw_value: Any) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return value.rstrip("/")


def _read_tunnel_credentials(request: HttpRequest, payload: dict[str, Any] | None = None) -> tuple[str, str]:
    source = payload if payload is not None else request.GET
    tunnel_id = _normalize_tunnel_id(source.get("tunnel_id"))
    connect_key = str(source.get("connect_key") or "").strip()
    return tunnel_id or "", connect_key


def _authenticate_tunnel(request: HttpRequest, payload: dict[str, Any] | None = None) -> tuple[Tunnel | None, JsonResponse | None]:
    tunnel_id, connect_key = _read_tunnel_credentials(request, payload)
    if not tunnel_id or not connect_key:
        return None, _json_error("tunnel_id and connect_key are required", 400)

    try:
        tunnel = Tunnel.objects.get(tunnel_id=tunnel_id)
    except Tunnel.DoesNotExist:
        return None, _json_error("Tunnel not found", 404)

    if not tunnel.verify_connect_key(connect_key):
        return None, _json_error("Invalid connect key", 401)
    return tunnel, None


def _is_tunnel_online(tunnel: Tunnel) -> bool:
    heartbeat_ttl_seconds = _setting_int("TUNNEL_HEARTBEAT_TTL_SECONDS", 120, 10, 600)
    now = timezone.now()
    if not tunnel.is_active or not tunnel.ws_connected or tunnel.ws_connection_count <= 0 or not tunnel.last_seen:
        return False
    return (now - tunnel.last_seen).total_seconds() <= heartbeat_ttl_seconds


def _mark_tunnel_timed_out(tunnel_request: TunnelRequest, message: str) -> None:
    tunnel_request.status = TunnelRequest.STATUS_TIMED_OUT
    tunnel_request.error_message = message
    tunnel_request.save(update_fields=["status", "error_message"])


def _decode_response_body(tunnel_request: TunnelRequest) -> bytes:
    if not tunnel_request.response_body_b64:
        return b""
    try:
        return base64.b64decode(tunnel_request.response_body_b64.encode("ascii"))
    except (ValueError, TypeError):
        return b""


@require_http_methods(["GET"])
def tunnel_health(request: HttpRequest) -> JsonResponse:
    channel_layer = get_channel_layer()
    return JsonResponse(
        {
            "ok": True,
            "service": "schemaclient-gateway",
            "mode": "websocket",
            "host": request.get_host().split(":")[0].lower(),
            "base_domain": str(getattr(settings, "TUNNEL_BASE_DOMAIN", "")).strip().lower(),
            "websocket_ready": channel_layer is not None,
            "channel_layer_backend": (
                f"{channel_layer.__class__.__module__}.{channel_layer.__class__.__name__}"
                if channel_layer is not None
                else None
            ),
            "version": 2,
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def create_tunnel(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json_object(request)
    if error:
        return error

    requested_tunnel_id = _normalize_tunnel_id(payload.get("tunnel_id")) if payload.get("tunnel_id") else None
    if payload.get("tunnel_id") and not requested_tunnel_id:
        return _json_error("Invalid tunnel_id format", 400)

    tunnel_id = requested_tunnel_id or _generate_unique_tunnel_id()
    if Tunnel.objects.filter(tunnel_id=tunnel_id).exists():
        return _json_error("Tunnel ID already exists", 409)

    connect_key = secrets.token_urlsafe(24)
    tunnel = Tunnel.objects.create(
        tunnel_id=tunnel_id,
        connect_key_hash=Tunnel.hash_connect_key(connect_key),
        is_active=False,
        ws_connected=False,
        ws_connection_count=0,
    )

    return JsonResponse(
        {
            "tunnel_id": tunnel.tunnel_id,
            "public_url": _build_public_url(request, tunnel.tunnel_id),
            "connect_key": connect_key,
        },
        status=201,
    )


@csrf_exempt
@require_http_methods(["POST"])
def connect_tunnel(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json_object(request)
    if error:
        return error

    tunnel, auth_error = _authenticate_tunnel(request, payload)
    if auth_error:
        return auth_error

    local_target_url = _normalize_local_target_url(payload.get("local_target_url"))
    if payload.get("local_target_url") and not local_target_url:
        return _json_error("Invalid local_target_url", 400)

    tunnel.is_active = True
    tunnel.last_seen = timezone.now()
    if local_target_url:
        tunnel.local_target_url = local_target_url
    tunnel.save(update_fields=["is_active", "last_seen", "local_target_url", "updated_at"])

    return JsonResponse(
        {
            "ok": True,
            "tunnel_id": tunnel.tunnel_id,
            "public_url": _build_public_url(request, tunnel.tunnel_id),
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def disconnect_tunnel(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json_object(request)
    if error:
        return error

    tunnel, auth_error = _authenticate_tunnel(request, payload)
    if auth_error:
        return auth_error

    tunnel.is_active = False
    tunnel.ws_connected = False
    tunnel.ws_connection_count = 0
    tunnel.save(update_fields=["is_active", "ws_connected", "ws_connection_count", "updated_at"])

    return JsonResponse({"ok": True, "tunnel_id": tunnel.tunnel_id})


@require_http_methods(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def unsupported_tunnel_api(_: HttpRequest, path: str = "") -> JsonResponse:
    del path
    return _json_error("Tunnel API endpoint not found", 404)


@csrf_exempt
@require_http_methods(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def gateway_dispatch(request: HttpRequest, path: str = "") -> HttpResponse:
    del path  # Dispatch path comes from request.path; keep signature for URL resolver compatibility.

    tunnel_id = getattr(request, "tunnel_id", None)
    if not tunnel_id:
        if request.path in {"", "/"} and request.method == "GET":
            max_request_body_bytes = _setting_int(
                "TUNNEL_MAX_REQUEST_BODY_BYTES",
                5 * 1024 * 1024,
                1024,
                50 * 1024 * 1024,
            )
            context = {
                "base_domain": str(getattr(settings, "TUNNEL_BASE_DOMAIN", "")).strip().lower()
                or request.get_host().split(":")[0].lower(),
                "public_scheme": str(getattr(settings, "TUNNEL_PUBLIC_SCHEME", "https")).strip().lower() or "https",
                "request_timeout_seconds": _setting_int("TUNNEL_REQUEST_TIMEOUT_SECONDS", 40, 1, 180),
                "heartbeat_ttl_seconds": _setting_int("TUNNEL_HEARTBEAT_TTL_SECONDS", 120, 10, 600),
                "db_poll_interval_ms": _setting_int("TUNNEL_DB_POLL_INTERVAL_MS", 120, 25, 1000),
                "max_request_body_bytes": max_request_body_bytes,
                "max_request_body_mb": round(max_request_body_bytes / (1024 * 1024), 1),
            }
            return render(request, "tunnel/home.html", context)
        return HttpResponseNotFound("Not found")

    try:
        tunnel = Tunnel.objects.get(tunnel_id=tunnel_id)
    except Tunnel.DoesNotExist:
        return _json_error("Tunnel not found for ammu", 404)

    if not _is_tunnel_online(tunnel):
        return _json_error("Tunnel is offline for ardfs", 503)

    max_request_body_bytes = _setting_int("TUNNEL_MAX_REQUEST_BODY_BYTES", 5 * 1024 * 1024, 1024, 50 * 1024 * 1024)
    body_bytes = request.body or b""
    if len(body_bytes) > max_request_body_bytes:
        return _json_error("Request body too large for tunnel forwarding", 413)

    body_binary = False
    try:
        body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_binary = True

    tunnel_request = TunnelRequest.objects.create(
        tunnel=tunnel,
        method=request.method,
        path=request.path,
        query_string=request.META.get("QUERY_STRING", ""),
        request_headers={k: str(v) for k, v in request.headers.items()},
        request_body_b64=base64.b64encode(body_bytes).decode("ascii") if body_bytes else "",
        request_body_size=len(body_bytes),
        request_body_binary=body_binary,
        status=TunnelRequest.STATUS_LEASED,
        leased_at=timezone.now(),
    )

    channel_layer = get_channel_layer()
    if channel_layer is None:
        _mark_tunnel_timed_out(tunnel_request, "Channel layer unavailable")
        return _json_error("Gateway channel layer unavailable", 503)

    outbound_payload = {
        "type": "request",
        "request_id": str(tunnel_request.request_id),
        "method": tunnel_request.method,
        "path": tunnel_request.path,
        "query_string": tunnel_request.query_string,
        "headers": tunnel_request.request_headers,
        "body_b64": tunnel_request.request_body_b64,
        "body_size": tunnel_request.request_body_size,
        "body_binary": tunnel_request.request_body_binary,
    }
    try:
        async_to_sync(channel_layer.group_send)(
            f"tunnel.{tunnel_id}",
            {
                "type": "tunnel.forward_request",
                "payload": outbound_payload,
            },
        )
    except Exception:
        _mark_tunnel_timed_out(tunnel_request, "Failed to publish request to websocket client")
        return _json_error("Gateway could not dispatch request", 503)

    timeout_seconds = _setting_int("TUNNEL_REQUEST_TIMEOUT_SECONDS", 40, 1, 180)
    poll_interval_seconds = _setting_int("TUNNEL_DB_POLL_INTERVAL_MS", 120, 25, 1000) / 1000
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        tunnel_request.refresh_from_db(
            fields=[
                "status",
                "response_status",
                "response_headers",
                "response_body_b64",
            ]
        )
        if tunnel_request.status == TunnelRequest.STATUS_RESPONDED and tunnel_request.response_status:
            response = HttpResponse(_decode_response_body(tunnel_request), status=tunnel_request.response_status)
            for key, value in (tunnel_request.response_headers or {}).items():
                name = str(key).strip()
                if not name:
                    continue
                lower_name = name.lower()
                if lower_name in HOP_BY_HOP_HEADERS or lower_name == "content-length":
                    continue
                response[name] = str(value)
            return response
        time.sleep(poll_interval_seconds)

    _mark_tunnel_timed_out(tunnel_request, "Gateway timed out waiting for desktop client response")
    return _json_error("Tunnel request timed out", 504)


def gateway_root(request: HttpRequest) -> HttpResponse:
    return gateway_dispatch(request)
