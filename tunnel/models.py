from __future__ import annotations

import hashlib
import hmac
import uuid

from django.core.validators import RegexValidator
from django.db import models


TUNNEL_ID_VALIDATOR = RegexValidator(
    regex=r"^[a-z0-9](?:[a-z0-9-]{2,30}[a-z0-9])?$",
    message="Tunnel ID must be 4-32 chars, lowercase letters/digits/hyphen, and cannot start/end with hyphen.",
)


class Tunnel(models.Model):
    owner = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="tunnels", null=True, blank=True)
    tunnel_id = models.CharField(max_length=32, unique=True, validators=[TUNNEL_ID_VALIDATOR])
    connect_key_hash = models.CharField(max_length=64)
    is_active = models.BooleanField(default=False)
    ws_connected = models.BooleanField(default=False)
    ws_connection_count = models.PositiveIntegerField(default=0)
    ws_connected_at = models.DateTimeField(null=True, blank=True)
    local_target_url = models.URLField(blank=True, default="")
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["owner", "created_at"], name="tunnel_owner_created_idx"),
            models.Index(fields=["is_active", "last_seen"], name="tunnel_active_seen_idx"),
        ]

    def __str__(self) -> str:
        return self.tunnel_id

    @staticmethod
    def hash_connect_key(connect_key: str) -> str:
        return hashlib.sha256(connect_key.encode("utf-8")).hexdigest()

    def verify_connect_key(self, connect_key: str) -> bool:
        if not connect_key:
            return False
        return hmac.compare_digest(self.connect_key_hash, self.hash_connect_key(connect_key))


class TunnelRequest(models.Model):
    STATUS_PENDING = "pending"
    STATUS_LEASED = "leased"
    STATUS_RESPONDED = "responded"
    STATUS_TIMED_OUT = "timed_out"

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_LEASED, "Leased"),
        (STATUS_RESPONDED, "Responded"),
        (STATUS_TIMED_OUT, "Timed out"),
    ]

    request_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    tunnel = models.ForeignKey(Tunnel, on_delete=models.CASCADE, related_name="requests")

    method = models.CharField(max_length=16)
    path = models.TextField()
    query_string = models.TextField(blank=True, default="")
    request_headers = models.JSONField(default=dict)
    request_body_b64 = models.TextField(blank=True, default="")
    request_body_size = models.PositiveIntegerField(default=0)
    request_body_binary = models.BooleanField(default=False)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    leased_at = models.DateTimeField(null=True, blank=True)

    responded_at = models.DateTimeField(null=True, blank=True)
    response_status = models.PositiveIntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict)
    response_body_b64 = models.TextField(blank=True, default="")
    response_body_size = models.PositiveIntegerField(default=0)
    response_body_binary = models.BooleanField(default=False)

    error_message = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tunnel", "status", "created_at"], name="tunnel_req_queue_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.tunnel.tunnel_id}:{self.request_id}"

    @property
    def full_path(self) -> str:
        if self.query_string:
            return f"{self.path}?{self.query_string}"
        return self.path
