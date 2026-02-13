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

HTTP_METHOD_CHOICES = [
    ("GET", "GET"),
    ("POST", "POST"),
    ("PUT", "PUT"),
    ("PATCH", "PATCH"),
    ("DELETE", "DELETE"),
    ("HEAD", "HEAD"),
    ("OPTIONS", "OPTIONS"),
]

COLLECTION_ITEM_TYPE_CHOICES = [
    ("folder", "Folder"),
    ("request", "Request"),
]


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


class ApiCollection(models.Model):
    owner = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="api_collections")
    client_id = models.CharField(max_length=64)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True, default="")
    base_url = models.URLField(blank=True, default="")
    tags = models.JSONField(default=list, blank=True)
    variables = models.JSONField(default=list, blank=True)
    auth = models.JSONField(default=dict, blank=True)
    scripts = models.JSONField(default=dict, blank=True)
    created_at_ms = models.BigIntegerField(default=0)
    updated_at_ms = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["owner", "client_id"], name="api_collection_owner_client_uidx"),
        ]
        indexes = [
            models.Index(fields=["owner", "updated_at"], name="api_coll_owner_updated_idx"),
            models.Index(fields=["owner", "created_at"], name="api_coll_owner_created_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.owner_id}:{self.name}"


class ApiCollectionItem(models.Model):
    collection = models.ForeignKey(ApiCollection, on_delete=models.CASCADE, related_name="items")
    client_id = models.CharField(max_length=64)
    parent_client_id = models.CharField(max_length=64, null=True, blank=True)
    item_type = models.CharField(max_length=16, choices=COLLECTION_ITEM_TYPE_CHOICES, default="request", db_index=True)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True, default="")
    method = models.CharField(max_length=8, choices=HTTP_METHOD_CHOICES, blank=True, default="")
    url = models.TextField(blank=True, default="")
    headers = models.JSONField(default=list, blank=True)
    params = models.JSONField(default=list, blank=True)
    body = models.JSONField(default=dict, blank=True)
    sort_order = models.PositiveIntegerField(default=0)
    created_at_ms = models.BigIntegerField(default=0)
    updated_at_ms = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ["sort_order", "created_at"]
        constraints = [
            models.UniqueConstraint(fields=["collection", "client_id"], name="api_coll_item_collection_client_uidx"),
        ]
        indexes = [
            models.Index(fields=["collection", "parent_client_id", "sort_order"], name="api_item_tree_idx"),
            models.Index(fields=["collection", "item_type"], name="api_item_type_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.collection_id}:{self.name}"


class ApiSchema(models.Model):
    owner = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="api_schemas")
    client_id = models.CharField(max_length=64)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True, default="")
    version = models.CharField(max_length=32, blank=True, default="")
    source = models.TextField(blank=True, default="")
    request_schema = models.JSONField(default=dict, blank=True)
    response_schema = models.JSONField(default=dict, blank=True)
    created_at_ms = models.BigIntegerField(default=0)
    updated_at_ms = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["owner", "client_id"], name="api_schema_owner_client_uidx"),
        ]
        indexes = [
            models.Index(fields=["owner", "updated_at"], name="api_schema_owner_updated_idx"),
            models.Index(fields=["owner", "created_at"], name="api_schema_owner_created_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.owner_id}:{self.name}"
