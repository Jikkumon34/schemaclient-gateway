from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from tunnel import views
from tunnel import auth_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/login", auth_views.desktop_login_form, name="desktop_login_form"),
    path("api/auth/register", auth_views.desktop_register_form, name="desktop_register_form"),
    path("api/auth/desktop/login", auth_views.desktop_login_start, name="desktop_login_start"),
    path("api/auth/desktop/exchange", auth_views.desktop_exchange_code),
    path("api/auth/guest", auth_views.guest_login),
    path("api/auth/me", auth_views.auth_me),
    path("api/auth/token/refresh", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/tunnels/health", views.tunnel_health),
    path("api/tunnels/create", views.create_tunnel),
    path("api/tunnels/connect", views.connect_tunnel),
    path("api/tunnels/disconnect", views.disconnect_tunnel),
    path("api/tunnels/<path:path>", views.unsupported_tunnel_api),
    path("", views.gateway_dispatch),
    path("<path:path>", views.gateway_dispatch),
]
