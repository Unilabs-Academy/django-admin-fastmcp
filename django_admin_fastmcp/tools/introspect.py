"""list_models, describe_model (SPEC.md section 4)."""

from typing import Any

from django.db.models import Field
from django.urls import NoReverseMatch, reverse

from django_admin_fastmcp import exposure
from django_admin_fastmcp.auth import current_user
from django_admin_fastmcp.errors import ToolError
from django_admin_fastmcp.request import admin_request
from django_admin_fastmcp.serialize import concrete_fields, readable_fields
from django_admin_fastmcp.tools import resolve


def _changelist_url(model) -> str | None:
    opts = model._meta
    try:
        return reverse(f"admin:{opts.app_label}_{opts.model_name}_changelist")
    except NoReverseMatch:
        return None


def list_models() -> list[dict[str, Any]]:
    """List every model you may read over this connection.

    Returns one entry per model with its "app_label.ModelName" label (the
    `model` argument every other tool takes), verbose names, your view, add,
    change, and delete permission flags, and a link into the real admin.
    Models you cannot view are omitted entirely.
    """
    user = current_user()
    result = []
    for model, model_admin in exposure.exposed_models():
        request = admin_request(user, model_admin)
        if (
            not exposure.admin_site().has_permission(request)
            or not model_admin.has_module_permission(request)
            or not model_admin.has_view_permission(request)
        ):
            continue
        opts = model._meta
        result.append(
            {
                "model": exposure.label_of(model),
                "verbose_name": str(opts.verbose_name),
                "verbose_name_plural": str(opts.verbose_name_plural),
                "permissions": {
                    "view": True,
                    "add": model_admin.has_add_permission(request),
                    "change": model_admin.has_change_permission(request),
                    "delete": model_admin.has_delete_permission(request),
                },
                "admin_url": _changelist_url(model),
            }
        )
    return sorted(result, key=lambda entry: entry["model"])


def _field_info(field: Field) -> dict[str, Any]:
    info: dict[str, Any] = {
        "name": field.name,
        "type": field.get_internal_type(),
        "required": not field.blank and field.editable and not field.has_default(),
        "editable": field.editable,
    }
    if field.help_text:
        info["help_text"] = str(field.help_text)
    if field.choices:
        info["choices"] = [[value, str(label)] for value, label in field.flatchoices]
    if field.is_relation and field.related_model is not None:
        info["related_model"] = exposure.label_of(field.related_model)
    return info


def describe_model(model: str) -> dict[str, Any]:
    """Describe one model: fields, admin configuration, and your actions.

    `model` is "app_label.ModelName" as returned by list_models. The answer
    covers field names, types, whether each is required, choices and related
    models, the admin's list display, filters, search fields and ordering,
    which fields are read-only for you, inline models, reverse relation
    names (query those through their own model), and the actions you may run
    with run_action. Refuses models you cannot view.
    """
    user = current_user()
    model_class, model_admin, request = resolve(user, model, "view")

    field_names = readable_fields(model_admin, request)
    fields = [_field_info(f) for f in concrete_fields(model_class) if f.name in field_names]

    def _names(items) -> list[str]:
        return [
            item if isinstance(item, str) else getattr(item, "__name__", str(item))
            for item in items
        ]

    def can_view(related_model):
        try:
            resolve(user, exposure.label_of(related_model), "view")
            return True
        except ToolError:
            return False

    for info in fields:
        if "related_model" in info:
            related_model = model_class._meta.get_field(info["name"]).related_model
            if not can_view(related_model):
                info.pop("related_model")

    reverse_relations = sorted(
        f.get_accessor_name()
        for f in model_class._meta.get_fields()
        if f.auto_created
        and not f.concrete
        and f.related_model is not None
        and f.get_accessor_name()
        and can_view(f.related_model)
    )
    actions = {
        name: str(description)
        for func, name, description in model_admin.get_actions(request).values()
    }
    return {
        "model": exposure.label_of(model_class),
        "fields": fields,
        "list_display": [
            name for name in _names(model_admin.get_list_display(request)) if name in field_names
        ],
        "list_filter": [
            name for name in _names(model_admin.get_list_filter(request)) if name in field_names
        ],
        "search_fields": [
            name
            for name in model_admin.get_search_fields(request)
            if name.lstrip("^=@") in field_names
        ],
        "ordering": [
            name
            for name in (model_admin.get_ordering(request) or ())
            if name.lstrip("-") in field_names
        ],
        "readonly_fields": [
            name for name in _names(model_admin.get_readonly_fields(request)) if name in field_names
        ],
        "inlines": [
            exposure.label_of(inline.model)
            for inline in model_admin.get_inline_instances(request)
            if can_view(inline.model) and inline.has_view_permission(request)
        ],
        "inline_editing_supported": False,
        "reverse_relations": reverse_relations,
        "actions": actions,
    }
