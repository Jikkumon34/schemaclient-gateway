from __future__ import annotations

import json
import uuid
from typing import Any

from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from .models import ApiCollection, ApiCollectionItem, ApiSchema


User = get_user_model()

MAX_COLLECTIONS = 300
MAX_ITEMS_PER_COLLECTION = 3000
MAX_TOTAL_ITEMS = 10000
MAX_SCHEMAS = 2000
MAX_TEXT_LEN = 20000

VALID_COLLECTION_AUTH_TYPES = {"none", "bearer", "basic", "apikey"}
VALID_REQUEST_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
VALID_COLLECTION_ITEM_TYPES = {"folder", "request"}
VALID_BODY_TYPES = {"none", "raw", "json"}


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


def _authenticate_bearer_user(
    request: HttpRequest,
    *,
    allow_guest: bool = False,
) -> tuple[User | None, JsonResponse | None]:
    auth = JWTAuthentication()
    try:
        header = auth.get_header(request)
        if header is None:
            return None, _json_error("Unauthorized", 401)
        raw_token = auth.get_raw_token(header)
        if raw_token is None:
            return None, _json_error("Unauthorized", 401)
        validated = auth.get_validated_token(raw_token)
        user = auth.get_user(validated)
    except (InvalidToken, TokenError):
        return None, _json_error("Unauthorized", 401)

    if not isinstance(user, User):
        return None, _json_error("Unauthorized", 401)
    if not allow_guest and bool(user.is_guest):
        return None, _json_error("Login required", 403)
    return user, None


def _normalize_client_id(raw: Any, *, prefix: str) -> str:
    value = str(raw or "").strip()
    if not value:
        value = f"{prefix}-{uuid.uuid4().hex[:16]}"
    return value[:64]


def _normalize_text(raw: Any, *, max_length: int = MAX_TEXT_LEN) -> str:
    value = str(raw or "").strip()
    if len(value) > max_length:
        return value[:max_length]
    return value


def _normalize_timestamp_ms(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    if value < 0:
        return 0
    return value


def _normalize_tags(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for value in raw:
        text = _normalize_text(value, max_length=64)
        if text and text not in out:
            out.append(text)
        if len(out) >= 50:
            break
    return out


def _normalize_kv_items(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        out.append(
            {
                "id": _normalize_client_id(entry.get("id"), prefix="kv"),
                "key": _normalize_text(entry.get("key"), max_length=256),
                "value": _normalize_text(entry.get("value"), max_length=4000),
                "enabled": bool(entry.get("enabled", True)),
            }
        )
        if len(out) >= 500:
            break
    return out


def _normalize_collection_auth(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"type": "none"}
    auth_type = _normalize_text(raw.get("type"), max_length=32).lower()
    if auth_type not in VALID_COLLECTION_AUTH_TYPES:
        auth_type = "none"
    auth: dict[str, Any] = {"type": auth_type}
    if auth_type == "bearer":
        auth["token"] = _normalize_text(raw.get("token"), max_length=4096)
    elif auth_type == "basic":
        auth["username"] = _normalize_text(raw.get("username"), max_length=256)
        auth["password"] = _normalize_text(raw.get("password"), max_length=4096)
    elif auth_type == "apikey":
        location = _normalize_text(raw.get("apiKeyLocation"), max_length=16).lower()
        if location not in {"header", "query"}:
            location = "header"
        auth["apiKeyName"] = _normalize_text(raw.get("apiKeyName"), max_length=256)
        auth["apiKeyValue"] = _normalize_text(raw.get("apiKeyValue"), max_length=4096)
        auth["apiKeyLocation"] = location
    return auth


def _normalize_scripts(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {"preRequest": "", "tests": ""}
    return {
        "preRequest": _normalize_text(raw.get("preRequest"), max_length=MAX_TEXT_LEN),
        "tests": _normalize_text(raw.get("tests"), max_length=MAX_TEXT_LEN),
    }


def _normalize_body(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {"type": "none", "content": ""}
    body_type = _normalize_text(raw.get("type"), max_length=16).lower()
    if body_type not in VALID_BODY_TYPES:
        body_type = "none"
    return {
        "type": body_type,
        "content": _normalize_text(raw.get("content"), max_length=MAX_TEXT_LEN),
    }


def _normalize_collection_item(raw: Any, *, sort_order: int) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    item_type = _normalize_text(raw.get("type"), max_length=16).lower()
    if item_type not in VALID_COLLECTION_ITEM_TYPES:
        item_type = "request"

    parent_client_id_raw = _normalize_text(raw.get("parentId"), max_length=64)
    parent_client_id = parent_client_id_raw or None

    method = _normalize_text(raw.get("method"), max_length=8).upper()
    if method not in VALID_REQUEST_METHODS:
        method = "GET"

    item: dict[str, Any] = {
        "id": _normalize_client_id(raw.get("id"), prefix="item"),
        "type": item_type,
        "name": _normalize_text(raw.get("name"), max_length=160) or "Untitled",
        "parentId": parent_client_id,
        "description": _normalize_text(raw.get("description"), max_length=MAX_TEXT_LEN),
        "method": method if item_type == "request" else "",
        "url": _normalize_text(raw.get("url"), max_length=4000) if item_type == "request" else "",
        "headers": _normalize_kv_items(raw.get("headers")) if item_type == "request" else [],
        "params": _normalize_kv_items(raw.get("params")) if item_type == "request" else [],
        "body": _normalize_body(raw.get("body")) if item_type == "request" else {"type": "none", "content": ""},
        "sortOrder": sort_order,
        "createdAt": _normalize_timestamp_ms(raw.get("createdAt")),
        "updatedAt": _normalize_timestamp_ms(raw.get("updatedAt")),
    }
    return item


def _normalize_collection(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    raw_items = raw.get("items")
    items_list = raw_items if isinstance(raw_items, list) else []
    if len(items_list) > MAX_ITEMS_PER_COLLECTION:
        items_list = items_list[:MAX_ITEMS_PER_COLLECTION]

    items: list[dict[str, Any]] = []
    for idx, raw_item in enumerate(items_list):
        normalized = _normalize_collection_item(raw_item, sort_order=idx)
        if normalized is not None:
            items.append(normalized)

    return {
        "id": _normalize_client_id(raw.get("id"), prefix="collection"),
        "name": _normalize_text(raw.get("name"), max_length=160) or "Untitled Collection",
        "description": _normalize_text(raw.get("description"), max_length=MAX_TEXT_LEN),
        "baseUrl": _normalize_text(raw.get("baseUrl"), max_length=4000),
        "tags": _normalize_tags(raw.get("tags")),
        "variables": _normalize_kv_items(raw.get("variables")),
        "auth": _normalize_collection_auth(raw.get("auth")),
        "scripts": _normalize_scripts(raw.get("scripts")),
        "items": items,
        "createdAt": _normalize_timestamp_ms(raw.get("createdAt")),
        "updatedAt": _normalize_timestamp_ms(raw.get("updatedAt")),
    }


def _normalize_schema_blob(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    return {}


def _normalize_schema(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    return {
        "id": _normalize_client_id(raw.get("id"), prefix="schema"),
        "name": _normalize_text(raw.get("name"), max_length=160) or "Untitled Schema",
        "description": _normalize_text(raw.get("description"), max_length=MAX_TEXT_LEN),
        "version": _normalize_text(raw.get("version"), max_length=32),
        "source": _normalize_text(raw.get("source"), max_length=MAX_TEXT_LEN),
        "request": _normalize_schema_blob(raw.get("request")),
        "response": _normalize_schema_blob(raw.get("response")),
        "createdAt": _normalize_timestamp_ms(raw.get("createdAt")),
        "updatedAt": _normalize_timestamp_ms(raw.get("updatedAt")),
    }


def _serialize_collection_item(item: ApiCollectionItem) -> dict[str, Any]:
    return {
        "id": item.client_id,
        "type": item.item_type,
        "name": item.name,
        "parentId": item.parent_client_id,
        "description": item.description,
        "method": item.method or None,
        "url": item.url,
        "headers": item.headers or [],
        "params": item.params or [],
        "body": item.body or {"type": "none", "content": ""},
        "createdAt": item.created_at_ms or int(item.created_at.timestamp() * 1000),
        "updatedAt": item.updated_at_ms or int(item.updated_at.timestamp() * 1000),
    }


def _serialize_collections(owner: User) -> list[dict[str, Any]]:
    collections = list(ApiCollection.objects.filter(owner=owner).order_by("-updated_at", "-created_at"))
    if not collections:
        return []

    collection_ids = [collection.id for collection in collections]
    items_by_collection_id: dict[int, list[dict[str, Any]]] = {collection_id: [] for collection_id in collection_ids}

    for item in (
        ApiCollectionItem.objects.filter(collection_id__in=collection_ids)
        .order_by("sort_order", "created_at")
        .iterator()
    ):
        items_by_collection_id[item.collection_id].append(_serialize_collection_item(item))

    serialized: list[dict[str, Any]] = []
    for collection in collections:
        serialized.append(
            {
                "id": collection.client_id,
                "name": collection.name,
                "description": collection.description,
                "baseUrl": collection.base_url,
                "tags": collection.tags or [],
                "variables": collection.variables or [],
                "auth": collection.auth or {"type": "none"},
                "scripts": collection.scripts or {"preRequest": "", "tests": ""},
                "items": items_by_collection_id.get(collection.id, []),
                "createdAt": collection.created_at_ms or int(collection.created_at.timestamp() * 1000),
                "updatedAt": collection.updated_at_ms or int(collection.updated_at.timestamp() * 1000),
            }
        )
    return serialized


def _serialize_schemas(owner: User) -> list[dict[str, Any]]:
    schemas = ApiSchema.objects.filter(owner=owner).order_by("-updated_at", "-created_at")
    serialized: list[dict[str, Any]] = []
    for schema in schemas:
        serialized.append(
            {
                "id": schema.client_id,
                "name": schema.name,
                "description": schema.description,
                "version": schema.version,
                "source": schema.source,
                "request": schema.request_schema or {},
                "response": schema.response_schema or {},
                "createdAt": schema.created_at_ms or int(schema.created_at.timestamp() * 1000),
                "updatedAt": schema.updated_at_ms or int(schema.updated_at.timestamp() * 1000),
            }
        )
    return serialized


def _save_collections_snapshot(owner: User, collections: list[dict[str, Any]]) -> None:
    incoming_ids = [collection["id"] for collection in collections]
    existing_qs = ApiCollection.objects.filter(owner=owner)
    existing_by_client_id = {collection.client_id: collection for collection in existing_qs}

    create_batch: list[ApiCollection] = []
    update_batch: list[ApiCollection] = []
    sync_now = timezone.now()

    for incoming in collections:
        collection = existing_by_client_id.get(incoming["id"])
        if collection is None:
            collection = ApiCollection(owner=owner, client_id=incoming["id"])

        collection.name = incoming["name"]
        collection.description = incoming["description"]
        collection.base_url = incoming["baseUrl"]
        collection.tags = incoming["tags"]
        collection.variables = incoming["variables"]
        collection.auth = incoming["auth"]
        collection.scripts = incoming["scripts"]
        collection.created_at_ms = incoming["createdAt"]
        collection.updated_at_ms = incoming["updatedAt"]
        collection.updated_at = sync_now

        if collection.pk is None:
            create_batch.append(collection)
        else:
            update_batch.append(collection)

    with transaction.atomic():
        if create_batch:
            ApiCollection.objects.bulk_create(create_batch, batch_size=200)
        if update_batch:
            ApiCollection.objects.bulk_update(
                update_batch,
                [
                    "name",
                    "description",
                    "base_url",
                    "tags",
                    "variables",
                    "auth",
                    "scripts",
                    "created_at_ms",
                    "updated_at_ms",
                    "updated_at",
                ],
                batch_size=200,
            )

        if incoming_ids:
            existing_qs.exclude(client_id__in=incoming_ids).delete()
        else:
            existing_qs.delete()

        if not incoming_ids:
            return

        db_collections = {
            collection.client_id: collection
            for collection in ApiCollection.objects.filter(owner=owner, client_id__in=incoming_ids)
        }

        ApiCollectionItem.objects.filter(
            collection__owner=owner,
            collection__client_id__in=incoming_ids,
        ).delete()

        item_batch: list[ApiCollectionItem] = []
        for incoming in collections:
            db_collection = db_collections.get(incoming["id"])
            if db_collection is None:
                continue
            for item in incoming["items"]:
                item_batch.append(
                    ApiCollectionItem(
                        collection=db_collection,
                        client_id=item["id"],
                        parent_client_id=item["parentId"],
                        item_type=item["type"],
                        name=item["name"],
                        description=item["description"],
                        method=item["method"],
                        url=item["url"],
                        headers=item["headers"],
                        params=item["params"],
                        body=item["body"],
                        sort_order=item["sortOrder"],
                        created_at_ms=item["createdAt"],
                        updated_at_ms=item["updatedAt"],
                    )
                )

        if item_batch:
            ApiCollectionItem.objects.bulk_create(item_batch, batch_size=1000)


def _save_schemas_snapshot(owner: User, schemas: list[dict[str, Any]]) -> None:
    incoming_ids = [schema["id"] for schema in schemas]
    existing_qs = ApiSchema.objects.filter(owner=owner)
    existing_by_client_id = {schema.client_id: schema for schema in existing_qs}

    create_batch: list[ApiSchema] = []
    update_batch: list[ApiSchema] = []
    sync_now = timezone.now()

    for incoming in schemas:
        schema = existing_by_client_id.get(incoming["id"])
        if schema is None:
            schema = ApiSchema(owner=owner, client_id=incoming["id"])

        schema.name = incoming["name"]
        schema.description = incoming["description"]
        schema.version = incoming["version"]
        schema.source = incoming["source"]
        schema.request_schema = incoming["request"]
        schema.response_schema = incoming["response"]
        schema.created_at_ms = incoming["createdAt"]
        schema.updated_at_ms = incoming["updatedAt"]
        schema.updated_at = sync_now

        if schema.pk is None:
            create_batch.append(schema)
        else:
            update_batch.append(schema)

    with transaction.atomic():
        if create_batch:
            ApiSchema.objects.bulk_create(create_batch, batch_size=500)
        if update_batch:
            ApiSchema.objects.bulk_update(
                update_batch,
                [
                    "name",
                    "description",
                    "version",
                    "source",
                    "request_schema",
                    "response_schema",
                    "created_at_ms",
                    "updated_at_ms",
                    "updated_at",
                ],
                batch_size=500,
            )

        if incoming_ids:
            existing_qs.exclude(client_id__in=incoming_ids).delete()
        else:
            existing_qs.delete()


@csrf_exempt
@require_http_methods(["GET", "PUT"])
def collections_snapshot(request: HttpRequest) -> JsonResponse:
    user, auth_error = _authenticate_bearer_user(request, allow_guest=False)
    if auth_error:
        return auth_error
    assert user is not None

    if request.method == "GET":
        return JsonResponse({"collections": _serialize_collections(user)})

    payload, payload_error = _parse_json_object(request)
    if payload_error:
        return payload_error

    raw_collections = payload.get("collections", [])
    if not isinstance(raw_collections, list):
        return _json_error("collections must be an array", 400)
    if len(raw_collections) > MAX_COLLECTIONS:
        return _json_error(f"Maximum {MAX_COLLECTIONS} collections are allowed", 400)

    normalized_collections: list[dict[str, Any]] = []
    total_items = 0
    for raw in raw_collections:
        normalized = _normalize_collection(raw)
        if normalized is None:
            continue
        total_items += len(normalized["items"])
        if total_items > MAX_TOTAL_ITEMS:
            return _json_error(f"Maximum {MAX_TOTAL_ITEMS} total collection items are allowed", 400)
        normalized_collections.append(normalized)

    _save_collections_snapshot(user, normalized_collections)
    return JsonResponse({"collections": _serialize_collections(user)})


@csrf_exempt
@require_http_methods(["GET", "PUT"])
def schemas_snapshot(request: HttpRequest) -> JsonResponse:
    user, auth_error = _authenticate_bearer_user(request, allow_guest=False)
    if auth_error:
        return auth_error
    assert user is not None

    if request.method == "GET":
        return JsonResponse({"schemas": _serialize_schemas(user)})

    payload, payload_error = _parse_json_object(request)
    if payload_error:
        return payload_error

    raw_schemas = payload.get("schemas", [])
    if not isinstance(raw_schemas, list):
        return _json_error("schemas must be an array", 400)
    if len(raw_schemas) > MAX_SCHEMAS:
        return _json_error(f"Maximum {MAX_SCHEMAS} schemas are allowed", 400)

    normalized_schemas: list[dict[str, Any]] = []
    for raw in raw_schemas:
        normalized = _normalize_schema(raw)
        if normalized is not None:
            normalized_schemas.append(normalized)

    _save_schemas_snapshot(user, normalized_schemas)
    return JsonResponse({"schemas": _serialize_schemas(user)})
