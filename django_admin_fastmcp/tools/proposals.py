"""Saved, grant-bound previews for ordinary single and batch model edits."""

import json
from copy import deepcopy
from datetime import timedelta
from typing import Any

from django.contrib.admin.models import CHANGE
from django.contrib.auth import get_user_model
from django.db import router, transaction
from django.db.models import FileField
from django.utils import timezone
from django.utils.crypto import salted_hmac

from django_admin_fastmcp import conf, exposure
from django_admin_fastmcp.auth import current_grant, current_user
from django_admin_fastmcp.errors import ToolError, denied
from django_admin_fastmcp.models import McpChangeProposal
from django_admin_fastmcp.request import collected_messages
from django_admin_fastmcp.serialize import readable_fields, serialize_instance
from django_admin_fastmcp.tools import require_write, resolve
from django_admin_fastmcp.tools.read import _get_visible
from django_admin_fastmcp.tools.write import (
    _check_exposed_fields,
    _check_inline_support,
    _form_errors,
    _log,
    _via_mcp,
    bound_form_data,
)

NOTICE = (
    "Proposed values come from admin form validation; save hooks, signals and external "
    "side effects are not simulated. Preparation does not invoke save hooks. "
    "This is a review aid, not proof of human approval. Existing write tools remain available."
)


def _identity():
    user = get_user_model().objects.get(pk=current_user().pk)
    if not user.is_active or not user.is_staff:
        raise denied("active staff access is required")
    return user, current_grant()


def _target(user, item, *, lock=False):
    if "update_object" in conf.get("DISABLED_TOOLS"):
        raise denied("updates are disabled on this server")
    require_write(item["model"])
    model, admin, request = resolve(user, item["model"], "change", data=item["data"])
    queryset = admin.get_queryset(request)
    if queryset.db != "default" or router.db_for_write(model) != "default":
        raise ToolError("change proposals require the default database")
    if lock:
        queryset = queryset.select_for_update()
    obj = _get_visible(queryset, model, item["pk"])
    if not admin.has_view_permission(request, obj) or not admin.has_change_permission(request, obj):
        raise denied("no view/change permission on this object")
    _check_exposed_fields(admin, request, item["data"], obj)
    _check_inline_support(admin, request, obj)
    return obj, admin, request


def _fingerprint(obj):
    state = {f.attname: getattr(obj, f.attname) for f in obj._meta.concrete_fields}
    for field in obj._meta.many_to_many:
        values = list(
            getattr(obj, field.name).values_list("pk", flat=True)[: conf.get("MAX_SCAN_ROWS") + 1]
        )
        if len(values) > conf.get("MAX_SCAN_ROWS"):
            raise ToolError("too many related rows for a bounded change proposal")
        state[field.name] = sorted(str(value) for value in values)
    return salted_hmac(
        "admin-mcp-change-proposal",
        json.dumps(state, sort_keys=True, default=str, allow_nan=False),
        algorithm="sha256",
    ).hexdigest()


def _prepare(user, item, *, lock=False):
    obj, admin, request = _target(user, item, lock=lock)
    fingerprint = _fingerprint(obj)
    before = serialize_instance(obj, admin, request)
    original = deepcopy({f.name: getattr(obj, f.attname) for f in obj._meta.concrete_fields})
    fields = {f.name: f for f in obj._meta.concrete_fields}
    form_class = admin.get_form(request, obj, change=True)
    readonly = set(admin.get_readonly_fields(request, obj))
    for name in item["data"]:
        field = fields.get(name)
        if field is None or isinstance(field, FileField):
            raise ToolError(
                "proposals support scalar/foreign-key fields; use native workflows for other inputs"
            )
        if name in readonly or not field.editable or name not in form_class.base_fields:
            raise denied(f"field is not editable: {name}")
    form = form_class(data=bound_form_data(form_class, item["data"], obj), instance=obj)
    if not form.is_valid():
        raise _form_errors(form)
    after = serialize_instance(form.instance, admin, request)
    changes = {
        name: {"before": value, "after": after["fields"].get(name)}
        for name, value in before["fields"].items()
        if name in after["fields"]
        and value != after["fields"][name]
        and not exposure.is_redacted(name)
    }
    for field in obj._meta.concrete_fields:
        old, new = original[field.name], getattr(form.instance, field.attname)
        if old == new:
            continue
        name = field.name
        if name not in changes or exposure.is_redacted(name):
            raise denied("form changes cannot be represented in a visible field preview")
        if field.is_relation and (
            (old is not None and before["fields"].get(name) is None)
            or (new is not None and after["fields"].get(name) is None)
        ):
            raise denied("changed relation is outside your visible access")
    review = {
        "model": exposure.label_of(type(obj)),
        "pk": str(obj.pk),
        "admin_url": before["admin_url"],
        "changes": changes,
    }
    return fingerprint, review, (obj, admin, request, form)


def _proposal(proposal_id, *, lock=False):
    user, grant = _identity()
    queryset = McpChangeProposal.objects.select_for_update() if lock else McpChangeProposal.objects
    row = queryset.filter(
        pk=proposal_id, user=user, grant=grant, expires_at__gt=timezone.now()
    ).first()
    if row is None:
        raise denied("proposal is unavailable or expired")
    return row, user


def _describe(row):
    return {
        "proposal_id": row.pk,
        "status": row.status,
        "expires_at": row.expires_at.isoformat(),
        "records": [item["review"] for item in row.items],
        "notice": NOTICE,
    }


def prepare_changes(changes: list[dict[str, Any]]) -> dict:
    """Prepare ordinary single/batch edits without saving the target records.

    Each item is {model: 'app.Model', pk: '123', data: {field: value}}.
    Return a saved proposal and validated before/after values to present for review.
    Use explicit record IDs, not search filters. Do not claim save-hook effects are
    previewed. File, inline, many-to-many and form-only edits use native workflows.
    Applying later uses the saved inputs; no replacement payload is accepted.
    """
    if not changes or len(changes) > min(conf.get("MAX_PKS"), 100):
        raise ToolError("provide between 1 and min(MAX_PKS, 100) changes")
    try:
        encoded = json.dumps(changes, allow_nan=False)
        if len(encoded.encode()) > 128 * 1024:
            raise ToolError("proposal inputs exceed 128 KiB")
        changes = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ToolError("changes must contain JSON values") from exc
    user, grant = _identity()
    items, identities = [], set()
    with transaction.atomic():
        # Serialize creation so simultaneous requests cannot evade the pending-plan limit.
        get_user_model().objects.select_for_update().get(pk=user.pk)
        McpChangeProposal.objects.filter(expires_at__lte=timezone.now()).delete()
        if McpChangeProposal.objects.filter(user=user, grant=grant, status="pending").count() >= 10:
            raise ToolError("discard an existing pending proposal first (limit 10)")
        for item in changes:
            if not isinstance(item, dict) or set(item) != {"model", "pk", "data"}:
                raise ToolError("each change requires exactly model, pk and data")
            if (
                not isinstance(item["model"], str)
                or not isinstance(item["pk"], str)
                or not isinstance(item["data"], dict)
                or not item["data"]
            ):
                raise ToolError("model/pk must be strings and data a nonempty object")
            with transaction.atomic():
                fingerprint, review, _ = _prepare(user, item)
                # Custom validation may write to the database; a preview must not retain it.
                transaction.set_rollback(True)
            key = (review["model"], review["pk"])
            if key in identities:
                raise ToolError("combine duplicate record edits into one change")
            identities.add(key)
            item.update(
                model=review["model"], pk=review["pk"], fingerprint=fingerprint, review=review
            )
            items.append(item)
        if len(json.dumps(items).encode()) > 512 * 1024:
            raise ToolError("proposal preview exceeds 512 KiB; use smaller edits")
        row = McpChangeProposal.objects.create(
            user=user,
            grant=grant,
            items=items,
            expires_at=timezone.now() + timedelta(minutes=conf.get("PROPOSAL_TTL_MINUTES")),
        )
    return _describe(row)


def inspect_change_proposal(proposal_id: str) -> dict:
    """Read a saved proposal and its execution status. Rechecks current access."""
    row, user = _proposal(proposal_id)
    for item in row.items:
        obj, admin, request = _target(user, item)
        visible = set(readable_fields(admin, request, obj))
        if any(
            name not in visible or exposure.is_redacted(name) for name in item["review"]["changes"]
        ):
            raise denied("proposal preview fields are no longer visible")
        for name, diff in item["review"]["changes"].items():
            field = obj._meta.get_field(name)
            if not field.is_relation:
                continue
            _, related_admin, related_request = resolve(
                user, exposure.label_of(field.related_model), "view"
            )
            for value in (diff["before"], diff["after"]):
                if value is None:
                    continue
                related = related_admin.get_queryset(related_request).filter(pk=value["pk"]).first()
                if related is None or not related_admin.has_view_permission(
                    related_request, related
                ):
                    raise denied("proposal relation is no longer visible")
    return _describe(row)


def discard_change_proposal(proposal_id: str) -> dict:
    """Discard a pending proposal without changing its target records."""
    with transaction.atomic():
        row, _ = _proposal(proposal_id, lock=True)
        if row.status != "pending":
            raise ToolError("only pending proposals can be discarded")
        row.status = "discarded"
        row.save(update_fields=["status"])
    return {"proposal_id": row.pk, "status": row.status}


def apply_change_proposal(proposal_id: str) -> dict:
    """Apply the saved edits after review; does not enforce human approval.

    Only the proposal ID is accepted. All target rows are locked and checked for
    changes and current permissions before saving any. Stale/expired proposals
    must be prepared again. Each proposal can be attempted only once, including
    failures; check effects before preparing another after an interrupted attempt.
    Database writes/audit entries are atomic; external side effects may not be.
    """
    with transaction.atomic():
        row, user = _proposal(proposal_id, lock=True)
        if row.status != "pending":
            raise ToolError(f"proposal is already {row.status}; inspect it before continuing")
        row.status = "applying"
        row.save(update_fields=["status"])
    try:
        results = []
        with transaction.atomic():
            prepared = {}
            for item in sorted(row.items, key=lambda i: (i["model"], i["pk"])):
                fingerprint, review, entry = _prepare(user, item, lock=True)
                if fingerprint != item["fingerprint"] or review != item["review"]:
                    raise ToolError(
                        "proposal is stale: record or validated changes changed; prepare again"
                    )
                prepared[(item["model"], item["pk"])] = entry
            for item in row.items:
                obj, admin, request, form = prepared[(item["model"], item["pk"])]
                if item["review"]["changes"]:
                    obj = admin.save_form(request, form, change=True)
                    admin.save_model(request, obj, form, change=True)
                    admin.save_related(request, form, formsets=[], change=True)
                    _log(request, obj, CHANGE, _via_mcp(f"Applied change proposal {row.pk}."))
                    obj.refresh_from_db()
                result = serialize_instance(obj, admin, request)
                result.update(model=item["model"], messages=collected_messages(request))
                results.append(result)
            row.status = "applied"
            row.save(update_fields=["status"])
        return {"proposal_id": row.pk, "status": "applied", "results": results}
    except Exception:
        McpChangeProposal.objects.filter(pk=row.pk, status="applying").update(status="failed")
        raise
