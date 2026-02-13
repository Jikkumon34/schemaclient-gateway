from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import DesktopAuthCode, User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    list_display = ("username", "email", "is_staff", "is_active", "is_guest")
    list_filter = ("is_staff", "is_superuser", "is_active", "is_guest")
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("SchemaClient", {"fields": ("is_guest",)}),
    )


@admin.register(DesktopAuthCode)
class DesktopAuthCodeAdmin(admin.ModelAdmin):
    list_display = ("code", "user", "expires_at", "used_at", "created_at")
    search_fields = ("code", "user__username", "user__email")
    list_filter = ("expires_at", "used_at", "created_at")
    readonly_fields = ("code", "created_at", "used_at", "expires_at")
