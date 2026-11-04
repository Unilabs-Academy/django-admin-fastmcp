"""create_object, update_object, delete_object (SPEC.md section 4).

Writes go through the admin's own ModelForm and save_model, then record a
LogEntry. Every write tool runs inside `transaction.atomic()`. A write that
cannot record a LogEntry rolls back (SPEC.md section 9).
"""

from typing import Any

from django.contrib.admin.models import ADDITION, CHANGE, DELETION, LogEntry
from django.db import transaction

from django_admin_fastmcp import exposure
from django_admin_fastmcp.auth import client_name, current_user
from django_admin_fastmcp.errors import ToolError, denied
from django_admin_fastmcp.request import collected_messages
from django_admin_fastmcp.serialize import readable_fields, safe_label, serialize_instance
from django_admin_fastmcp.tools import require_write, resolve
from django_admin_fastmcp.tools.read import _get_visible


def _log(request, obj, action_flag: int, change_message: str) -> None:
    """One LogEntry per mutation, attributed to the grant's user."""
    if hasattr(LogEntry.objects, "log_actions"):
        LogEntry.objects.log_actions(
            request.user.pk, [obj], action_flag, change_message, single_object=True
        )
    else:  # Django 5.0
        from django.contrib.contenttypes.models import ContentType

        LogEntry.objects.log_action(
            user_id=request.user.pk,
            content_type_id=ContentType.objects.get_for_model(type(obj)).pk,
            object_id=obj.pk,
            object_repr=str(obj),
            action_flag=action_flag,
            change_message=change_message,
        )


def _via_mcp(text: str) -> str:
    return f"{text} Via MCP (client: {client_name()})."


def _form_errors(form) -> ToolError:
    errors = {
        field: [e["message"] for e in field_errors]
        for field, field_errors in form.errors.get_json_data().items()
    }
    return ToolError(f"validation failed: {errors}")


def _check_field_names(form_class, data: dict[str, Any], label: str) -> None:
    unknown = set(data) - set(form_class.base_fields)
    if unknown:
        raise ToolError(f"unknown fields for {label}: {sorted(unknown)}")


def bound_form_data(form_class, data, instance=None):
    """Bind JSON values through Django widgets, retaining omitted update fields."""
    from django.forms import MultiWidget
    from django.http import QueryDict
    from django.utils.dateparse import parse_datetime

    initial_form = form_class(instance=instance)
    post = QueryDict("", mutable=True)
    for name, field in initial_form.fields.items():
        if name not in data and instance is None:
            continue
        value = data.get(name, initial_form.get_initial_for_field(field, name))
        if isinstance(field.widget, MultiWidget):
            if isinstance(value, str):
                parsed = parse_datetime(value)
                if parsed is not None:
                    value = parsed
            values = value if isinstance(value, list | tuple) else field.widget.decompress(value)
            for suffix, widget, part in zip(
                field.widget.widgets_names, field.widget.widgets, values, strict=True
            ):
                formatted = widget.format_value(part)
                post[name + suffix] = "" if formatted is None else str(formatted)
        else:
            value = field.prepare_value(value)
            values = value if isinstance(value, list | tuple) else [value]
            post.setlist(name, ["" if v is None else str(v) for v in values])
    return post


def _check_exposed_fields(model_admin, request, data, obj=None):
    readable = set(readable_fields(model_admin, request, obj))
    form_fields = set(model_admin.get_form(request, obj).base_fields)
    # Form-only fields are also subject to explicit MCP allow/deny lists.
    model_fields = {field.name for field in model_admin.model._meta.get_fields()}
    exposed = set(
        exposure.visible_field_names(model_admin, list(readable | (form_fields - model_fields)))
    )
    denied_fields = set(data) - exposed
    denied_fields |= {name for name in data if exposure.is_redacted(name)}
    if denied_fields:
        raise denied(f"fields are not writable over MCP: {sorted(denied_fields)}")


def _check_inline_support(model_admin, request, obj=None):
    if model_admin.get_inline_instances(request, obj):
        raise ToolError(
            "inline formsets require native admin workflows (admin permission mode) or the browser"
        )


def create_object(model: str, data: dict[str, Any]) -> dict[str, Any]:
    """Create one object using the admin form and save hooks (without inline formsets).

    `model` is "app_label.ModelName". `data` maps field names to values:
    scalars by value, foreign keys by primary key, many-to-many by a list of
    primary keys (use the autocomplete tool to find them). Validation is the
    admin form's own. Refuses when you lack add permission, when the model
    is not writable on this server, or when your grant is read-only.
    Returns the created object.
    """
    user = current_user()
    require_write(model)
    _, model_admin, request = resolve(user, model, "add", data=data)

    form_class = model_admin.get_form(request)
    _check_field_names(form_class, data, model)
    _check_exposed_fields(model_admin, request, data)
    _check_inline_support(model_admin, request)
    form = form_class(data=bound_form_data(form_class, data))
    if not form.is_valid():
        raise _form_errors(form)
    with transaction.atomic():
        obj = model_admin.save_form(request, form, change=False)
        model_admin.save_model(request, obj, form, change=False)
        model_admin.save_related(request, form, formsets=[], change=False)
        _log(request, obj, ADDITION, _via_mcp("Added."))
    result = serialize_instance(obj, model_admin, request)
    result["messages"] = collected_messages(request)
    return result


def update_object(model: str, pk: str, data: dict[str, Any]) -> dict[str, Any]:
    """Partially update one object, as the admin change form would.

    For a before/after review, prefer prepare_changes and apply_change_proposal.
    This legacy tool writes immediately. Only the submitted fields change.
    Fields that are read-only for you are
    ignored, not written. Values follow the same shape as create_object.
    Refuses when you lack change permission on the model or on this exact
    object, when the object is hidden from you, when the model is not
    writable on this server, or when your grant is read-only. Returns the
    updated object.
    """
    user = current_user()
    require_write(model)
    model_class, model_admin, request = resolve(user, model, "change", data=data)
    obj = _get_visible(model_admin.get_queryset(request), model_class, pk)
    if not model_admin.has_change_permission(request, obj):
        raise denied(f"no change permission on this {model} object")

    if not model_admin.has_view_permission(request, obj):
        raise denied("no view permission on this object")
    _check_exposed_fields(model_admin, request, data, obj)
    _check_inline_support(model_admin, request, obj)
    # Readonly covers get_readonly_fields plus non-editable model fields.
    # Submitting one is ignored, not written and not an error (SPEC.md
    # section 11). Anything else outside the admin form is unknown: an error.
    from django_admin_fastmcp.serialize import concrete_fields

    readonly = set(model_admin.get_readonly_fields(request, obj)) | {
        f.name for f in concrete_fields(model_class) if not f.editable
    }
    full_form_class = model_admin.get_form(request, obj, change=True)
    unknown = set(data) - set(full_form_class.base_fields) - readonly
    if unknown:
        raise ToolError(f"unknown fields for {model}: {sorted(unknown)}")
    fields = [name for name in data if name not in readonly]
    if fields:
        form_class = full_form_class
        form = form_class(data=bound_form_data(form_class, data, obj), instance=obj)
        if not form.is_valid():
            raise _form_errors(form)
        with transaction.atomic():
            obj = model_admin.save_form(request, form, change=True)
            model_admin.save_model(request, obj, form, change=True)
            model_admin.save_related(request, form, formsets=[], change=True)
            _log(request, obj, CHANGE, _via_mcp(f"Changed {', '.join(fields)}."))
    result = serialize_instance(obj, model_admin, request)
    result["ignored_readonly_fields"] = sorted(set(data) & readonly)
    result["messages"] = collected_messages(request)
    return result


def _cascade_preview(model_admin, obj, request) -> dict[str, Any]:
    from django.contrib.admin.utils import NestedObjects
    from django.db import router

    from django_admin_fastmcp import conf

    _, _, perms_needed, protected = model_admin.get_deleted_objects([obj], request)
    collector = NestedObjects(using=router.db_for_write(type(obj)))
    collector.collect([obj])
    summary = []
    counts = {}
    total = 0
    for model, instances in collector.data.items():
        if model._meta.auto_created:
            continue
        total += len(instances)
        if total > conf.get("MAX_PKS"):
            raise ToolError("deletion cascade exceeds MAX_PKS; use a dedicated workflow")
        label = exposure.label_of(model)
        require_write(label)
        _, related_admin, related_request = resolve(request.user, label, "delete")
        allowed = set(
            related_admin.get_queryset(related_request)
            .filter(pk__in=[item.pk for item in instances])
            .values_list("pk", flat=True)
        )
        for item in instances:
            if (
                item.pk not in allowed
                or not related_admin.has_view_permission(related_request, item)
                or not related_admin.has_delete_permission(related_request, item)
            ):
                raise denied("deletion cascade includes an object outside your access")
            summary.append({"model": label, "pk": str(item.pk)})
        counts[str(model._meta.verbose_name_plural)] = len(instances)
    return {
        "to_delete": summary,
        "counts": counts,
        "perms_needed": sorted(str(p) for p in perms_needed),
        "protected": ["protected relation"] if protected else [],
    }


def delete_object(model: str, pk: str, confirm: bool = False) -> dict[str, Any]:
    """Preview deletion by default; pass confirm=true only after approval.

    With confirm=false (the default) nothing changes: the answer is the exact
    cascade the admin would show, everything that would be deleted along with
    this object. Read it, then call again with confirm=true to delete.
    Refuses when you lack delete permission on the model or on this exact
    object, when the cascade needs permissions you do not have, when the
    model is not writable on this server, or when your grant is read-only.
    """
    user = current_user()
    require_write(model)
    model_class, model_admin, request = resolve(user, model, "delete")
    obj = _get_visible(model_admin.get_queryset(request), model_class, pk)
    if not model_admin.has_view_permission(request, obj):
        raise denied("no view permission on this object")
    if not model_admin.has_delete_permission(request, obj):
        raise denied(f"no delete permission on this {model} object")

    preview = _cascade_preview(model_admin, obj, request)
    if not confirm:
        return {"confirm": False, "would_delete": preview}
    if preview["perms_needed"]:
        raise denied(f"cascade needs permissions you lack: {preview['perms_needed']}")
    if preview["protected"]:
        raise ToolError(f"protected relations prevent deletion: {preview['protected']}")
    object_repr = safe_label(obj)
    with transaction.atomic():
        _log(request, obj, DELETION, _via_mcp("Deleted."))
        model_admin.delete_model(request, obj)
    return {
        "confirm": True,
        "deleted": {"model": model, "pk": pk, "str": object_repr},
        "messages": collected_messages(request),
    }
