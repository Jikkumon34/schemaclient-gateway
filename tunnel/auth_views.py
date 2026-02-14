from __future__ import annotations

import json
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from django import forms
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import DesktopAuthCode, User


class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_email(self) -> str:
        email = str(self.cleaned_data.get("email") or "").strip().lower()
        if not email:
            raise forms.ValidationError("Email is required.")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


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


def _serialize_user(user: User) -> dict[str, Any]:
    display_name = user.get_full_name().strip() or user.username
    return {
        "id": user.pk,
        "username": user.username,
        "email": user.email,
        "display_name": display_name,
        "is_guest": bool(user.is_guest),
    }


def _token_response(user: User) -> dict[str, Any]:
    refresh = RefreshToken.for_user(user)
    refresh["username"] = user.username
    refresh["is_guest"] = bool(user.is_guest)
    access = refresh.access_token
    return _session_payload(
        user=user,
        access_token=str(access),
        refresh_token=str(refresh),
        expires_at=int(access["exp"]),
    )


def _session_payload(*, user: User, access_token: str, refresh_token: str, expires_at: int) -> dict[str, Any]:
    return {
        "mode": "guest" if user.is_guest else "authenticated",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "user": _serialize_user(user),
    }


def _extract_optional_refresh_token(request: HttpRequest) -> str:
    if not request.body:
        return ""
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    raw = payload.get("refresh_token") or payload.get("refresh")
    return str(raw or "").strip()


def _is_allowed_redirect_uri(redirect_uri: str) -> bool:
    if not redirect_uri:
        return False
    try:
        parsed = urlparse(redirect_uri)
    except ValueError:
        return False

    if parsed.scheme in {"http", "https"}:
        if parsed.scheme != "http":
            return False
        return parsed.hostname in {"127.0.0.1", "localhost"} and bool(parsed.port)

    if parsed.scheme == "schemaclient":
        return True
    return False


def _safe_next_url(
    request: HttpRequest,
    raw_next: str | None,
    *,
    default_url_name: str = "desktop_login_start",
) -> str:
    if raw_next and raw_next.startswith("/"):
        return raw_next
    if raw_next and url_has_allowed_host_and_scheme(
        url=raw_next,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return raw_next
    return reverse(default_url_name)


def _authenticate_bearer_user(request: HttpRequest) -> User:
    auth = JWTAuthentication()
    header = auth.get_header(request)
    if header is None:
        raise InvalidToken("Authorization header missing")
    raw_token = auth.get_raw_token(header)
    if raw_token is None:
        raise InvalidToken("Invalid bearer token")
    validated = auth.get_validated_token(raw_token)
    user = auth.get_user(validated)
    if not isinstance(user, User):
        raise InvalidToken("User not found")
    return user


def _parse_truthy(raw: str | None, *, default: bool = False) -> bool:
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _desktop_login_next_target(request: HttpRequest, *, mark_force_login_done: bool) -> str:
    parsed = urlparse(request.get_full_path())
    params = parse_qsl(parsed.query, keep_blank_values=True)

    force_login = _parse_truthy(request.GET.get("force_login"), default=True)
    if force_login:
        params = [(k, v) for (k, v) in params if k != "force_login_done"]
        if not any(k == "force_login" for (k, _v) in params):
            params.append(("force_login", "1"))
        if mark_force_login_done:
            params.append(("force_login_done", "1"))

    query = urlencode(params, doseq=True)
    return urlunparse(("", "", parsed.path, "", query, ""))


@require_GET
def desktop_login_start(request: HttpRequest) -> HttpResponse:
    redirect_uri = str(request.GET.get("redirect_uri", "")).strip()
    state = str(request.GET.get("state", "")).strip()
    force_login = _parse_truthy(request.GET.get("force_login"), default=True)
    force_login_done = _parse_truthy(request.GET.get("force_login_done"), default=False)
    if not _is_allowed_redirect_uri(redirect_uri):
        return HttpResponse("Invalid redirect_uri. Use localhost callback URL.", status=400)

    if force_login and not force_login_done and request.user.is_authenticated:
        logout(request)

    if not request.user.is_authenticated:
        login_url = reverse("desktop_login_form")
        next_target = _desktop_login_next_target(request, mark_force_login_done=True)
        return redirect(f"{login_url}?{urlencode({'next': next_target})}")

    user = request.user
    if not isinstance(user, User):
        return HttpResponse("Authenticated user is invalid", status=400)
    auth_code = DesktopAuthCode.issue(user=user, redirect_uri=redirect_uri, state=state)

    callback_params = {"code": auth_code.code}
    if state:
        callback_params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{separator}{urlencode(callback_params)}")


@require_http_methods(["GET", "POST"])
def desktop_login_form(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = AuthenticationForm(request=request, data=request.POST)
        next_url = _safe_next_url(request, request.POST.get("next"))
        if form.is_valid():
            login(request, form.get_user())
            return redirect(next_url)
    else:
        form = AuthenticationForm(request=request)
        next_url = _safe_next_url(request, request.GET.get("next"))

    return render(
        request,
        "tunnel/login.html",
        {
            "form": form,
            "next": next_url,
        },
    )


@require_http_methods(["GET", "POST"])
def desktop_register_form(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        next_url = _safe_next_url(request, request.POST.get("next"), default_url_name="desktop_login_form")
        if form.is_valid():
            user = form.save(commit=False)
            user.is_guest = False
            user.email = form.cleaned_data["email"]
            user.save()
            login(request, user)
            return redirect(next_url)
    else:
        form = UserRegistrationForm()
        next_url = _safe_next_url(request, request.GET.get("next"), default_url_name="desktop_login_form")

    return render(
        request,
        "tunnel/register.html",
        {
            "form": form,
            "next": next_url,
        },
    )


@csrf_exempt
@require_http_methods(["POST"])
def desktop_exchange_code(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json_object(request)
    if error:
        return error

    code = str(payload.get("code", "")).strip()
    if not code:
        return _json_error("code is required", 400)

    with transaction.atomic():
        auth_code = (
            DesktopAuthCode.objects.select_for_update()
            .select_related("user")
            .filter(code=code)
            .first()
        )
        if auth_code is None or not auth_code.can_exchange():
            return _json_error("Invalid or expired code", 400)
        auth_code.used_at = timezone.now()
        auth_code.save(update_fields=["used_at"])

    return JsonResponse(_token_response(auth_code.user))


@csrf_exempt
@require_http_methods(["POST"])
def guest_login(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json_object(request)
    if error:
        return error
    del payload

    while True:
        username = f"guest-{secrets.token_hex(6)}"
        if not User.objects.filter(username=username).exists():
            break

    user = User(username=username, is_guest=True)
    user.set_unusable_password()
    user.save()
    return JsonResponse(_token_response(user))


@csrf_exempt
@require_http_methods(["POST"])
def desktop_refresh_token(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json_object(request)
    if error:
        return error

    refresh_token = str(payload.get("refresh_token") or payload.get("refresh") or "").strip()
    if not refresh_token:
        return _json_error("refresh token is required", 400)

    serializer = TokenRefreshSerializer(data={"refresh": refresh_token})
    try:
        serializer.is_valid(raise_exception=True)
    except (InvalidToken, TokenError):
        return _json_error("Unauthorized", 401)

    validated_data = serializer.validated_data
    access_token = str(validated_data.get("access") or "").strip()
    next_refresh_token = str(validated_data.get("refresh") or refresh_token).strip()
    if not access_token:
        return _json_error("Unauthorized", 401)

    auth = JWTAuthentication()
    try:
        validated_access = auth.get_validated_token(access_token)
        user = auth.get_user(validated_access)
    except (InvalidToken, TokenError):
        return _json_error("Unauthorized", 401)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    expires_at = int(validated_access["exp"])
    response_payload = _session_payload(
        user=user,
        access_token=access_token,
        refresh_token=next_refresh_token,
        expires_at=expires_at,
    )
    # Keep SimpleJWT-compatible keys for clients that still expect the default shape.
    response_payload["access"] = access_token
    response_payload["refresh"] = next_refresh_token
    return JsonResponse(response_payload)


@require_GET
def auth_me(request: HttpRequest) -> JsonResponse:
    try:
        user = _authenticate_bearer_user(request)
    except (InvalidToken, TokenError):
        return _json_error("Unauthorized", 401)

    return JsonResponse({"user": _serialize_user(user)})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def auth_logout(request: HttpRequest) -> JsonResponse:
    refresh_token = _extract_optional_refresh_token(request)
    refresh_revoked = False
    if refresh_token:
        try:
            RefreshToken(refresh_token).blacklist()
            refresh_revoked = True
        except TokenError:
            refresh_revoked = False

    was_authenticated = bool(request.user.is_authenticated)
    logout(request)
    return JsonResponse(
        {
            "ok": True,
            "was_authenticated": was_authenticated,
            "refresh_revoked": refresh_revoked,
        }
    )
