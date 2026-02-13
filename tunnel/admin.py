from django.contrib import admin

from .models import Tunnel, TunnelRequest


@admin.register(Tunnel)
class TunnelAdmin(admin.ModelAdmin):
    list_display = (
        "tunnel_id",
        "is_active",
        "ws_connected",
        "ws_connection_count",
        "local_target_url",
        "last_seen",
        "created_at",
    )
    search_fields = ("tunnel_id", "local_target_url")
    list_filter = ("is_active", "created_at")


@admin.register(TunnelRequest)
class TunnelRequestAdmin(admin.ModelAdmin):
    list_display = ("request_id", "tunnel", "method", "path", "status", "response_status", "created_at")
    search_fields = ("request_id", "tunnel__tunnel_id", "path")
    list_filter = ("status", "method", "created_at")
    readonly_fields = ("request_id", "created_at", "leased_at", "responded_at")
