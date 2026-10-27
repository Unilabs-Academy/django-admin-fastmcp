"""autocomplete (SPEC.md section 4).

Resolve a foreign-key value to a primary key, through the related model's
`ModelAdmin.get_search_results`. Lets the caller set a relation without
guessing identifiers.
"""

from typing import Any

from django.core.exceptions import FieldDoesNotExist

from django_admin_fastmcp import conf, exposure
from django_admin_fastmcp.auth import current_user
from django_admin_fastmcp.errors import ToolError, denied
from django_admin_fastmcp.serialize import readable_fields, safe_label
from django_admin_fastmcp.tools import resolve, validate_lookup_path

RESULT_CAP = 20


def autocomplete(model: str, field: str, q: str) -> list[dict[str, Any]]:
    """Find primary keys for a relation field by searching labels.

    `model` is the model you are editing, `field` is its foreign-key or
    many-to-many field, and `q` searches the related model the same way its
    admin search box would. Returns up to 20 {"pk", "label"} pairs. Use the
    pk in create_object or update_object. Refuses fields that are not
    relations and related models you may not view.
    """
    user = current_user()
    model_class, _model_admin, _request = resolve(user, model, "view")
    if field not in readable_fields(_model_admin, _request):
        raise denied("field is not exposed")
    try:
        model_field = model_class._meta.get_field(field)
    except FieldDoesNotExist:
        raise ToolError(f"unknown field {field!r} on {model}") from None
    if not model_field.is_relation or model_field.related_model is None:
        raise ToolError(f"field {field!r} on {model} is not a relation")

    related_label = exposure.label_of(model_field.related_model)
    _related_class, related_admin, related_request = resolve(user, related_label, "view")
    queryset = related_admin.get_queryset(related_request)
    for search_field in related_admin.get_search_fields(related_request):
        validate_lookup_path(
            _related_class, search_field.lstrip("^=@"), related_admin, related_request
        )
        if _related_class._meta.get_field(search_field.lstrip("^=@").split("__", 1)[0]).is_relation:
            raise denied("relation search requires a dedicated scoped tool")
    queryset, _ = related_admin.get_search_results(related_request, queryset, q)
    return [
        {"pk": str(obj.pk), "label": safe_label(obj)}
        for obj in queryset[: conf.get("MAX_SCAN_ROWS")]
        if related_admin.has_view_permission(related_request, obj)
    ][:RESULT_CAP]
