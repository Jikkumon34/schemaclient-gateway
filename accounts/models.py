from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    is_guest = models.BooleanField(default=False, db_index=True)

    class Meta:
        ordering = ["username"]


class DesktopAuthCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="desktop_auth_codes")
    code = models.CharField(max_length=96, unique=True)
    redirect_uri = models.TextField()
    state = models.CharField(max_length=128, blank=True, default="")
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["code", "expires_at"], name="desktop_code_exp_idx"),
        ]

    @classmethod
    def issue(cls, user: User, redirect_uri: str, state: str = "") -> "DesktopAuthCode":
        ttl = max(30, int(getattr(settings, "DESKTOP_AUTH_CODE_TTL_SECONDS", 180)))
        return cls.objects.create(
            user=user,
            code=secrets.token_urlsafe(36),
            redirect_uri=redirect_uri,
            state=state,
            expires_at=timezone.now() + timedelta(seconds=ttl),
        )

    def can_exchange(self) -> bool:
        return self.used_at is None and self.expires_at > timezone.now()
