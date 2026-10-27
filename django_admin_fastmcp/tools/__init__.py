"""Shared resolution for every tool (SPEC.md section 5).

Each tool resolves its target once, through `resolve`. Denies, in order: an
inactive user, a non-staff user, a hidden model, an unregistered model, and a
ModelAdmin that refuses the action. Every failure path denies. No branch
allows a call because a lookup returned None.
"""

from typing import Literal

from django.apps import apps
from django.contrib.admin import ModelAdmin
from django.db.models import Model
from django.http import HttpRequest

from django_admin_fastmcp import exposure
from django_admin_fastmcp.errors import ToolError, denied
from django_admin_fastmcp.request import admin_request

Action = Literal["view", "add", "change", "delete"]


def resolve(
    user, label: str, action: Action, data=None, method=None
) -> tuple[type[Model], ModelAdmin, HttpRequest]:
    """Return the model, its ModelAdmin, and a synthetic request, or raise."""
    if not (user.is_active and user.is_staff):
        raise denied("not a staff user")
    if not exposure.is_exposed(label):
        raise ToolError(f"model {label} is not exposed")
    model = apps.get_model(label)  # is_exposed already resolved it
    model_admin = exposure.admin_site()._registry.get(model)
    if model_admin is None:
        raise ToolError(f"model {label} is not registered in the admin")
    request = admin_request(
        user, model_admin, method=method or ("GET" if action == "view" else "POST"), data=data
    )
    if not exposure.admin_site().has_permission(request):
        raise denied("admin site access denied")
    if not model_admin.has_module_permission(request):
        raise denied("admin module access denied")
    if not getattr(model_admin, f"has_{action}_permission")(request):
        raise denied(f"no {action} permission on {label}")
    return model, model_admin, request


def require_write(label: str) -> None:
    """The deployment-level write gate (SPEC.md section 9).

    WRITABLE_MODELS is the only MCP-side gate. Per-user authorization is
    entirely the admin's: `resolve` asks has_add/change/delete_permission
    right after this, so a user without the model permission is refused
    there. Leave a model out of WRITABLE_MODELS to ban all writes to it, an
    event log for example, whatever any user may do in the admin UI.
    """
    if not exposure.is_writable(label):
        raise denied(f"model {label} is not in WRITABLE_MODELS")


def validate_lookup_path(model: type[Model], lookup: str, model_admin=None, request=None) -> None:
    """Permit visible direct fields and a bounded set of scalar lookups only.

    Relation traversal could probe rows or fields the related admin denies.
    Custom changelist filters are handled separately through their own classes.
    """
    from django_admin_fastmcp.serialize import concrete_fields, readable_fields

    segments = lookup.removeprefix("-").split("__")
    field_names = {f.name for f in concrete_fields(model)}
    if segments[0] not in field_names:
        raise ToolError(f"unknown field {segments[0]!r} on {exposure.label_of(model)}")
    if model_admin is not None and segments[0] not in readable_fields(model_admin, request):
        raise denied("cannot filter or order by a hidden field")
    if any(exposure.is_redacted(segment) for segment in segments):
        raise denied("cannot filter or order by a redacted field")
    allowed = {
        "exact",
        "iexact",
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "isnull",
        "range",
    }
    if len(segments) > 2 or (len(segments) == 2 and segments[1] not in allowed):
        raise denied("relation traversal and unsupported lookups are not allowed")


def validate_relation_filter(model, key, value, request):
    """Only filter by identities the user may retrieve from the related admin."""
    field = model._meta.get_field(key.split("__", 1)[0])
    if not field.is_relation:
        return
    lookup = key.split("__", 1)[1] if "__" in key else "exact"
    if lookup not in {"exact", "in"} or field.related_model is None:
        raise denied("relation filters require visible exact identities")
    values = value if lookup == "in" and isinstance(value, list) else [value]
    if not values or any(v is None or isinstance(v, dict | list) for v in values):
        raise denied("relation filters require visible exact identities")
    label = exposure.label_of(field.related_model)
    try:
        _, related_admin, related_request = resolve(request.user, label, "view")
        lookup_name = field.target_field.name if hasattr(field, "target_field") else "pk"
        rows = list(
            related_admin.get_queryset(related_request).filter(**{f"{lookup_name}__in": values})
        )
        if len(rows) != len({str(v) for v in values}) or any(
            not related_admin.has_view_permission(related_request, obj) for obj in rows
        ):
            raise denied("relation filter target is not accessible")
    except (ValueError, TypeError):
        raise ToolError("invalid relation filter") from None
