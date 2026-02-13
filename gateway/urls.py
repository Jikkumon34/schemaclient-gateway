from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from django.contrib import admin
from django.http import HttpRequest, HttpResponse
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from tunnel import views
from tunnel import auth_views
from tunnel import data_views


def _subdomain_passthrough(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    @wraps(view_func)
    def _wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if getattr(request, "tunnel_id", None):
            return views.gateway_dispatch(request, path=request.path.lstrip("/"))
        return view_func(request, *args, **kwargs)

    return _wrapped


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/login", _subdomain_passthrough(auth_views.desktop_login_form), name="desktop_login_form"),
    path("api/auth/register", _subdomain_passthrough(auth_views.desktop_register_form), name="desktop_register_form"),
    path("api/auth/logout", _subdomain_passthrough(auth_views.auth_logout), name="auth_logout"),
    path("api/auth/desktop/login", _subdomain_passthrough(auth_views.desktop_login_start), name="desktop_login_start"),
    path("api/auth/desktop/exchange", _subdomain_passthrough(auth_views.desktop_exchange_code)),
    path("api/auth/guest", _subdomain_passthrough(auth_views.guest_login)),
    path("api/auth/me", _subdomain_passthrough(auth_views.auth_me)),
    path("api/auth/token/refresh", _subdomain_passthrough(TokenRefreshView.as_view()), name="token_refresh"),
    path("api/tunnels/health", _subdomain_passthrough(views.tunnel_health)),
    path("api/tunnels/create", _subdomain_passthrough(views.create_tunnel)),
    path("api/tunnels/connect", _subdomain_passthrough(views.connect_tunnel)),
    path("api/tunnels/disconnect", _subdomain_passthrough(views.disconnect_tunnel)),
    path("api/collections", _subdomain_passthrough(data_views.collections_snapshot)),
    path("api/schemas", _subdomain_passthrough(data_views.schemas_snapshot)),
    path("api/tunnels/<path:path>", _subdomain_passthrough(views.unsupported_tunnel_api)),
    path("", views.gateway_dispatch),
    path("<path:path>", views.gateway_dispatch),
]
