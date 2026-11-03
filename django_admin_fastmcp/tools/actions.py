"""Admin actions with form inputs, explicit response handling, and audit logging."""

import base64
from html.parser import HTMLParser
from typing import Any

from django.contrib.admin.helpers import ACTION_CHECKBOX_NAME
from django.contrib.admin.models import CHANGE
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect, StreamingHttpResponse

from django_admin_fastmcp import conf
from django_admin_fastmcp.auth import current_user
from django_admin_fastmcp.errors import ToolError, denied
from django_admin_fastmcp.request import collected_messages
from django_admin_fastmcp.tools import require_write, resolve
from django_admin_fastmcp.tools.write import _cascade_preview, _log, _via_mcp


class FormDescription(HTMLParser):
    """Describe controls without forwarding scripts, CSRF tokens, or whole pages."""

    def __init__(self):
        super().__init__()
        self.fields = []
        self.current = None
        self.option = None
        self.textarea = False
        self.error_depth = 0
        self.errors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        name = attrs.get("name")
        if self.error_depth:
            self.error_depth += 1
        elif "errorlist" in attrs.get("class", "").split():
            self.error_depth = 1
        if tag in {"input", "select", "textarea", "button"} and name:
            if name in {"csrfmiddlewaretoken", ACTION_CHECKBOX_NAME, "action"}:
                return
            self.current = {
                "name": name,
                "type": attrs.get("type", tag),
                "required": "required" in attrs,
            }
            if "value" in attrs:
                self.current["value"] = attrs["value"]
            if "multiple" in attrs:
                self.current["multiple"] = True
            if tag == "select":
                self.current["choices"] = []
            if "checked" in attrs:
                self.current["checked"] = True
            if tag == "textarea":
                self.textarea = True
                self.current["value"] = ""
            self.fields.append(self.current)
        elif tag == "option" and self.current is not None and "choices" in self.current:
            self.option = {"value": attrs.get("value", ""), "label": ""}
            if "selected" in attrs:
                self.option["selected"] = True
            self.current["choices"].append(self.option)

    def handle_data(self, data):
        if self.option is not None:
            self.option["label"] += data
        if self.textarea and self.current is not None:
            self.current["value"] += data
        if self.error_depth and data.strip():
            self.errors.append(data.strip())

    def handle_endtag(self, tag):
        if self.error_depth:
            self.error_depth -= 1
        if tag == "textarea":
            self.textarea = False
        if tag == "option":
            self.option = None
        if tag in {"select", "textarea"}:
            self.current = None


def _response_result(response):
    if isinstance(response, HttpResponse) and response.status_code >= 400:
        raise ToolError(f"admin action returned HTTP {response.status_code}")
    if isinstance(response, HttpResponseRedirect):
        return {"status": "completed", "redirect": response.url}
    if isinstance(response, StreamingHttpResponse):
        response.close()
        raise ToolError("streaming action responses are unsupported; use a dedicated tool")
    if not isinstance(response, HttpResponse):
        return {"status": "completed"}
    if hasattr(response, "render"):
        response.render()
    body = response.content
    if len(body) > conf.get("MAX_ACTION_RESPONSE_BYTES"):
        raise ToolError("action response exceeds MAX_ACTION_RESPONSE_BYTES")
    content_type = response.get("Content-Type", "")
    if "text/html" in content_type:
        parser = FormDescription()
        parser.feed(body.decode(response.charset or "utf-8", errors="replace"))
        return {
            "status": "requires_input",
            "fields": parser.fields,
            "errors": parser.errors,
            "instruction": "Submit form fields in parameters; an HTML response is not completion.",
        }
    return {
        "status": "completed",
        "file": {
            "content_type": content_type,
            "content_base64": base64.b64encode(body).decode("ascii"),
        },
    }


def run_action(
    model: str,
    action: str,
    pks: list[str],
    confirm: bool = False,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preview or execute an existing admin action.

    Preview never invokes the action. After confirmation, form-based actions may
    return requires_input with form controls; send their values in parameters on
    the next call (including the form's apply/post submit value). Selection and
    action name are controlled by this tool, never by parameters. HTTP pages are
    not execution success. The caller must obtain user approval for mutations.
    """
    user = current_user()
    require_write(model)
    if not pks or len(pks) > conf.get("MAX_PKS"):
        raise ToolError(f"select 1..MAX_PKS={conf.get('MAX_PKS')} objects")
    parameters = parameters or {}
    reserved = {"action", ACTION_CHECKBOX_NAME, "select_across", "csrfmiddlewaretoken"}
    if reserved & parameters.keys():
        raise ToolError("parameters cannot override action, selection, or CSRF fields")
    for value in parameters.values():
        values = value if isinstance(value, list) else [value]
        if any(not isinstance(item, str | int | float | bool | type(None)) for item in values):
            raise ToolError("action parameters must contain scalar values or lists of scalars")
    data = {**parameters, "action": action, ACTION_CHECKBOX_NAME: pks, "select_across": "0"}
    _, model_admin, request = resolve(user, model, "view", data=data, method="POST")
    available = model_admin.get_actions(request)
    if action not in available:
        raise denied(f"action {action!r} is not available to you on {model}")
    entry = available[action]
    func = getattr(entry, "func", None) or entry[0]
    description = getattr(entry, "description", None) or entry[2]
    queryset = model_admin.get_queryset(request).filter(pk__in=pks)
    selected = list(queryset)
    if len(selected) != len(set(pks)):
        raise ToolError("not all selected objects are visible to you")
    permissions = getattr(func, "allowed_permissions", ("change",))
    for obj in selected:
        if not model_admin.has_view_permission(request, obj) or not any(
            (
                getattr(model_admin, f"has_{permission}_permission")(request, obj)
                if permission in {"view", "change", "delete"}
                else getattr(model_admin, f"has_{permission}_permission")(request)
            )
            for permission in permissions
        ):
            raise denied("action permission denied on a selected object")
    if action == "delete_selected":
        for obj in selected:
            cascade = _cascade_preview(model_admin, obj, request)
            if cascade["perms_needed"] or cascade["protected"]:
                raise denied("deletion cascade is protected or requires additional permissions")
    if not confirm:
        return {
            "confirm": False,
            "action": action,
            "description": str(description),
            "affected": len(selected),
        }
    with transaction.atomic():
        # Record invocation before the callback: selected rows may be deleted.
        # The action may return a form without mutating, so never claim a change.
        for obj in selected:
            _log(request, obj, CHANGE, _via_mcp(f"Invoked admin action {action}."))
        response = func(model_admin, request, queryset)
        result = _response_result(response)
    return {
        "confirm": True,
        "action": action,
        "affected": len(selected),
        "messages": collected_messages(request),
        **result,
    }
