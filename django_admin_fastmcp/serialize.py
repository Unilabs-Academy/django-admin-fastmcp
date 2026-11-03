"""instance -> dict, from admin metadata (SPEC.md section 7).

Never `model_to_dict`. It drops non-editable fields, including the primary
key, and it includes every editable field, including password hashes.

Serialization walks `model._meta.get_fields()` and produces concrete fields
by value, the primary key always as a string, foreign keys as
`{"pk": ..., "label": str(obj)}`, many-to-many as a capped and counted list
of the same shape, readonly fields flagged, redacted values as
`"[redacted]"`, and an `admin_url`. Reverse relations are not expanded.
"""

import datetime
import decimal
import uuid
from typing import Any

from django.contrib.admin import ModelAdmin
from django.db.models import Field, ForeignKey, ManyToManyField, Model
from django.http import HttpRequest
from django.urls import NoReverseMatch, reverse

REDACTED = "[redacted]"
M2M_CAP = 20


def scalar(value: Any) -> Any:
    if isinstance(value, datetime.datetime | datetime.date | datetime.time):
        return value.isoformat()
    if isinstance(value, decimal.Decimal | uuid.UUID):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None or isinstance(value, bool | int | float | str):
        return value
    return str(value)


def safe_label(obj):
    # __str__ can embed fields deliberately hidden by admin configuration.
    return f"{obj._meta.verbose_name} #{obj.pk}"


def _related_shape(obj: Model | None) -> dict | None:
    if obj is None:
        return None
    return {"pk": str(obj.pk), "label": safe_label(obj)}


def admin_url(instance: Model) -> str | None:
    opts = instance._meta
    try:
        return reverse(f"admin:{opts.app_label}_{opts.model_name}_change", args=[instance.pk])
    except NoReverseMatch:
        return None


def concrete_fields(model: type[Model]) -> list[Field]:
    return [f for f in model._meta.get_fields() if isinstance(f, Field)]


def readable_fields(model_admin, request, obj=None) -> list[str]:
    from django_admin_fastmcp import exposure

    fields = concrete_fields(model_admin.model)
    names = exposure.visible_field_names(model_admin, [f.name for f in fields])
    excluded = set(model_admin.get_exclude(request, obj) or ())
    from django.contrib.admin.utils import flatten_fieldsets

    configured = set(flatten_fieldsets(model_admin.get_fieldsets(request, obj)))
    names = [
        name for name in names if name in configured or name == model_admin.model._meta.pk.name
    ]
    return [name for name in names if name not in excluded]


def visible_related(instance, field, request):
    from django_admin_fastmcp import conf, exposure
    from django_admin_fastmcp.errors import ToolError

    related_model = field.related_model
    label = exposure.label_of(related_model)
    if not exposure.is_exposed(label):
        return []
    model_admin = exposure.admin_site()._registry[related_model]
    if not model_admin.has_module_permission(request) or not model_admin.has_view_permission(
        request
    ):
        return []
    if isinstance(field, ManyToManyField):
        pks = getattr(instance, field.name).values_list("pk", flat=True)
        queryset = model_admin.get_queryset(request).filter(pk__in=pks)
    else:
        queryset = model_admin.get_queryset(request).filter(pk=getattr(instance, field.attname))
    candidates = list(queryset[: conf.get("MAX_SCAN_ROWS") + 1])
    if len(candidates) > conf.get("MAX_SCAN_ROWS"):
        raise ToolError("too many related rows; use a dedicated bounded relation tool")
    return [obj for obj in candidates if model_admin.has_view_permission(request, obj)]


def serialize_instance(
    instance: Model,
    model_admin: ModelAdmin,
    request: HttpRequest,
) -> dict[str, Any]:
    from django_admin_fastmcp import exposure

    model = type(instance)
    fields = concrete_fields(model)
    names = readable_fields(model_admin, request, instance)
    readonly = set(model_admin.get_readonly_fields(request, instance))

    data: dict[str, Any] = {}
    for field in fields:
        if field.name not in names:
            continue
        if exposure.is_redacted(field.name):
            data[field.name] = REDACTED
        elif isinstance(field, ManyToManyField):
            related = visible_related(instance, field, request)
            total = len(related)
            data[field.name] = {
                "items": [_related_shape(obj) for obj in related[:M2M_CAP]],
                "total": total,
            }
        elif isinstance(field, ForeignKey):
            related = visible_related(instance, field, request)
            data[field.name] = _related_shape(related[0]) if related else None
        else:
            data[field.name] = scalar(getattr(instance, field.name))

    return {
        "pk": str(instance.pk),
        "fields": data,
        "readonly_fields": sorted(readonly & set(names)),
        "admin_url": admin_url(instance),
        "str": safe_label(instance),
    }
