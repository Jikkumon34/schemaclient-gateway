from django.contrib import admin

from .models import ApiCollection, ApiCollectionItem, ApiSchema, Tunnel, TunnelRequest


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


@admin.register(ApiCollection)
class ApiCollectionAdmin(admin.ModelAdmin):
    list_display = ("owner", "name", "client_id", "updated_at", "created_at")
    search_fields = ("name", "client_id", "owner__username", "owner__email")
    list_filter = ("created_at", "updated_at")


@admin.register(ApiCollectionItem)
class ApiCollectionItemAdmin(admin.ModelAdmin):
    list_display = ("collection", "name", "item_type", "method", "parent_client_id", "sort_order")
    search_fields = ("name", "client_id", "collection__name", "collection__owner__username")
    list_filter = ("item_type", "method", "created_at")


@admin.register(ApiSchema)
class ApiSchemaAdmin(admin.ModelAdmin):
    list_display = ("owner", "name", "client_id", "version", "updated_at", "created_at")
    search_fields = ("name", "client_id", "owner__username", "owner__email")
    list_filter = ("created_at", "updated_at")
