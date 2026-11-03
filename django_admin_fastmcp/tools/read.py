"""search_objects, get_object, object_history, recent_actions (SPEC.md section 4).

Every read starts from `ModelAdmin.get_queryset(request)`, never from
`Model.objects.all()`. That single rule is what makes row-level overrides
apply for free.
"""

from typing import Any

from django.contrib.admin.models import LogEntry
from django.core.exceptions import FieldError, ValidationError
from django.db.models import Model

from django_admin_fastmcp import conf, exposure
from django_admin_fastmcp.auth import current_user
from django_admin_fastmcp.errors import ToolError, denied, not_found
from django_admin_fastmcp.serialize import serialize_instance
from django_admin_fastmcp.tools import resolve, validate_lookup_path, validate_relation_filter


def _get_visible(queryset, model: type[Model], pk: str):
    """Fetch one row from an admin queryset. Hidden and missing look the same."""
    label = exposure.label_of(model)
    try:
        return queryset.get(pk=pk)
    except (model.DoesNotExist, ValueError, ValidationError):
        raise not_found(label, pk) from None


def search_objects(
    model: str,
    q: str | None = None,
    filters: dict[str, Any] | None = None,
    order_by: list[str] | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Search rows of one model, as the admin changelist would.

    `model` is "app_label.ModelName". `q` runs the admin's own search over
    the model's search_fields. `filters` is a mapping of Django field lookups
    to values, for example {"published": true} or {"author__name": "Ada"}.
    An unknown field or lookup is an error, never a silent no-op. `order_by`
    is a list of field names, prefix "-" for descending. `page_size` is
    capped by the server. Returns {"rows": [...], "total": n, "page": n}.
    Rows you may not see, per the admin's own queryset, are absent.
    """
    user = current_user()
    model_class, model_admin, request = resolve(user, model, "view")
    queryset = model_admin.get_queryset(request)

    if q:
        for field in model_admin.get_search_fields(request):
            field = field.lstrip("^=@")
            validate_lookup_path(model_class, field, model_admin, request)
            if model_class._meta.get_field(field.split("__", 1)[0]).is_relation:
                raise denied("relation search requires a dedicated scoped tool")
        queryset, may_have_duplicates = model_admin.get_search_results(request, queryset, q)
        if may_have_duplicates:
            queryset = queryset.distinct()
    if filters:
        from django.contrib.admin import SimpleListFilter
        from django.http import QueryDict

        query = QueryDict("", mutable=True)
        for key, value in filters.items():
            query.setlist(key, [str(v) for v in (value if isinstance(value, list) else [value])])
        request.GET = query
        custom_filters = {
            item.parameter_name: item
            for item in model_admin.get_list_filter(request)
            if isinstance(item, type) and issubclass(item, SimpleListFilter)
        }
        direct_filters = {}
        for key, value in filters.items():
            if key in custom_filters:
                filter_instance = custom_filters[key](
                    request, {key: [str(value)]}, model_class, model_admin
                )
                choices = {str(choice) for choice, _ in filter_instance.lookup_choices}
                if str(value) not in choices:
                    raise ToolError(f"invalid choice for admin filter {key}")
                filtered = filter_instance.queryset(request, queryset)
                if filtered is not None:
                    # A filter may return a fresh queryset; retain the original visibility scope.
                    queryset = queryset.filter(pk__in=filtered.values("pk"))
            else:
                validate_lookup_path(model_class, key, model_admin, request)
                validate_relation_filter(model_class, key, value, request)
                direct_filters[key] = value
        try:
            queryset = queryset.filter(**direct_filters)
        except (FieldError, ValueError, ValidationError) as error:
            raise ToolError(f"invalid filters: {error}") from None
    if order_by:
        for key in order_by:
            validate_lookup_path(model_class, key, model_admin, request)
            if model_class._meta.get_field(key.lstrip("-").split("__", 1)[0]).is_relation:
                raise denied("ordering by relations is not supported")
        try:
            queryset = queryset.order_by(*order_by)
        except FieldError as error:
            raise ToolError(f"invalid order_by: {error}") from None

    page = max(page, 1)
    page_size = max(1, min(page_size, conf.get("MAX_PAGE_SIZE")))
    # Object-level overrides must apply before pagination and totals.
    candidates = list(queryset[: conf.get("MAX_SCAN_ROWS") + 1])
    if len(candidates) > conf.get("MAX_SCAN_ROWS"):
        raise ToolError("too many candidate rows; narrow the search filters")
    visible = [obj for obj in candidates if model_admin.has_view_permission(request, obj)]
    total = len(visible)
    start = (page - 1) * page_size
    rows = [
        serialize_instance(obj, model_admin, request) for obj in visible[start : start + page_size]
    ]
    return {"rows": rows, "total": total, "page": page, "page_size": page_size}


def get_object(model: str, pk: str) -> dict[str, Any]:
    """Read one object by primary key.

    `model` is "app_label.ModelName", `pk` is the primary key as a string.
    Returns the serialized instance: field values (sensitive fields read
    "[redacted]"), which fields are read-only for you, and a link into the
    real admin. Refuses objects the admin would not show you.
    """
    user = current_user()
    model_class, model_admin, request = resolve(user, model, "view")
    obj = _get_visible(model_admin.get_queryset(request), model_class, pk)
    if not model_admin.has_view_permission(request, obj):
        raise denied("no view permission on this object")
    return serialize_instance(obj, model_admin, request)


def _serialize_log_entry(entry: LogEntry) -> dict[str, Any]:
    return {
        "action_time": entry.action_time.isoformat(),
        "user": str(entry.user),
        "action": entry.get_action_flag_display(),
        "model": (
            f"{entry.content_type.app_label}.{entry.content_type.model}"
            if entry.content_type
            else None
        ),
        "object_id": entry.object_id,
        "object_repr": (
            f"{entry.content_type.model if entry.content_type else 'object'} #{entry.object_id}"
        ),
    }


def object_history(model: str, pk: str) -> list[dict[str, Any]]:
    """Read the admin history of one object, newest first.

    Returns the admin LogEntry rows: when, who, what action, and the change
    message. MCP edits appear here too, marked with the client name.
    """
    from django.contrib.contenttypes.models import ContentType

    user = current_user()
    model_class, model_admin, request = resolve(user, model, "view")
    obj = _get_visible(model_admin.get_queryset(request), model_class, pk)
    if not model_admin.has_view_permission(request, obj):
        raise denied("no view permission on this object")
    entries = (
        LogEntry.objects.filter(
            content_type=ContentType.objects.get_for_model(model_class),
            object_id=str(obj.pk),
        )
        .select_related("user", "content_type")
        .order_by("-action_time")
    )
    return [_serialize_log_entry(entry) for entry in entries[: conf.get("MAX_PAGE_SIZE")]]


def recent_actions(limit: int = 25) -> list[dict[str, Any]]:
    """List recent admin actions, newest first.

    Shows your own actions. A superuser sees everyone's. `limit` is capped
    by the server.
    """
    user = current_user()
    limit = max(1, min(limit, conf.get("MAX_PAGE_SIZE")))
    entries = LogEntry.objects.select_related("user", "content_type").order_by("-action_time")
    if not user.is_superuser:
        entries = entries.filter(user=user)
    result = []
    for entry in entries[: conf.get("MAX_SCAN_ROWS")].iterator():
        if not entry.content_type or not entry.object_id:
            continue
        model = entry.content_type.model_class()
        if model is None:
            continue
        try:
            _, model_admin, request = resolve(user, exposure.label_of(model), "view")
            obj = _get_visible(model_admin.get_queryset(request), model, entry.object_id)
            if not model_admin.has_view_permission(request, obj):
                continue
        except ToolError:
            continue
        result.append(_serialize_log_entry(entry))
        if len(result) == limit:
            break
    return result
