import json

import pytest
from demo.models import Book
from django import forms
from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse

from django_admin_fastmcp.auth import impersonate
from django_admin_fastmcp.errors import ToolError
from django_admin_fastmcp.tools.actions import FormDescription, run_action
from django_admin_fastmcp.tools.read import get_object, search_objects
from django_admin_fastmcp.tools.write import update_object


def test_object_view_denial_applies_to_detail_search_and_totals(viewer, books, monkeypatch):
    ma = admin.site._registry[Book]
    monkeypatch.setattr(ma, "has_view_permission", lambda request, obj=None: obj is None)
    with impersonate(viewer):
        with pytest.raises(ToolError, match="view permission"):
            get_object("demo.Book", str(books["plain"].pk))
        assert search_objects("demo.Book")["total"] == 0


@pytest.mark.parametrize("configuration", ["exclude", "mcp_exclude_fields"])
def test_hidden_field_absent_from_entire_response_and_unfilterable(
    viewer, books, monkeypatch, configuration
):
    ma = admin.site._registry[Book]
    monkeypatch.setattr(ma, configuration, ("title",), raising=False)
    with impersonate(viewer):
        result = get_object("demo.Book", str(books["plain"].pk))
        assert "Plain" not in json.dumps(result)
        with pytest.raises(ToolError, match="hidden field"):
            search_objects("demo.Book", filters={"title": "Plain"})
        with pytest.raises(ToolError, match="hidden field"):
            search_objects("demo.Book", q="Plain")


def test_dynamic_fields_are_enforced(viewer, books, monkeypatch):
    monkeypatch.setattr(
        admin.site._registry[Book], "get_fields", lambda request, obj=None: ["author"]
    )
    with impersonate(viewer):
        result = get_object("demo.Book", str(books["plain"].pk))
    assert set(result["fields"]) == {"id", "author"}


def test_hidden_field_is_not_writable(editor, books, monkeypatch):
    monkeypatch.setattr(admin.site._registry[Book], "mcp_exclude_fields", ("title",), raising=False)
    with impersonate(editor), pytest.raises(ToolError, match="not writable"):
        update_object("demo.Book", str(books["plain"].pk), {"title": "Changed"})
    books["plain"].refresh_from_db()
    assert books["plain"].title == "Plain"


def test_site_denial_blocks_reads(viewer, books, monkeypatch):
    monkeypatch.setattr(admin.site, "has_permission", lambda request: False)
    with impersonate(viewer), pytest.raises(ToolError, match="site access"):
        get_object("demo.Book", str(books["plain"].pk))


def test_related_object_denial_hides_its_identity(viewer, books, author, monkeypatch):
    ma = admin.site._registry[type(author)]
    monkeypatch.setattr(ma, "has_view_permission", lambda request, obj=None: False)
    with impersonate(viewer):
        result = get_object("demo.Book", str(books["plain"].pk))
    assert result["fields"]["author"] is None


def test_relation_filter_traversal_denied(viewer, books):
    with impersonate(viewer), pytest.raises(ToolError, match="traversal"):
        search_objects("demo.Book", filters={"author__name": "Ada"})


def test_candidate_limit_requires_narrower_query(viewer, books, settings):
    settings.ADMIN_FASTMCP = {**settings.ADMIN_FASTMCP, "MAX_SCAN_ROWS": 1}
    with impersonate(viewer), pytest.raises(ToolError, match="narrow"):
        search_objects("demo.Book")


def install_action(monkeypatch, action, permissions=("change",)):
    action.allowed_permissions = permissions
    monkeypatch.setattr(
        admin.site._registry[Book],
        "get_actions",
        lambda request: {"custom": (action, "custom", "Custom action")},
    )


def test_form_action_can_receive_inputs_and_reports_completion(editor, books, monkeypatch):
    def action(ma, request, qs):
        if "apply" not in request.POST:
            return HttpResponse(
                '<form><input name="title"><button name="apply" value="yes">Apply</button></form>'
            )
        assert request.method == "POST"
        assert request.POST.getlist("_selected_action") == [str(books["plain"].pk)]
        qs.update(title=request.POST["title"])
        return HttpResponseRedirect("/admin/")

    install_action(monkeypatch, action)
    with impersonate(editor):
        first = run_action("demo.Book", "custom", [str(books["plain"].pk)], confirm=True)
        assert first["status"] == "requires_input"
        assert any(f["name"] == "apply" for f in first["fields"])
        result = run_action(
            "demo.Book",
            "custom",
            [str(books["plain"].pk)],
            confirm=True,
            parameters={"apply": "yes", "title": "Renamed"},
        )
    assert result["status"] == "completed"
    books["plain"].refresh_from_db()
    assert books["plain"].title == "Renamed"
    assert LogEntry.objects.filter(user=editor, object_id=str(books["plain"].pk)).count() == 2


def test_action_preview_does_not_invoke_or_log(editor, books, monkeypatch):
    def action(*args):
        raise AssertionError("preview must not execute")

    install_action(monkeypatch, action)
    with impersonate(editor):
        assert not run_action("demo.Book", "custom", [str(books["plain"].pk)])["confirm"]
    assert not LogEntry.objects.exists()


def test_action_enforces_object_permissions(editor, books):
    with impersonate(editor), pytest.raises(ToolError, match="permission denied"):
        run_action("demo.Book", "publish_books", [str(books["locked"].pk)], confirm=True)


def test_action_add_permission_signature(editor, books, monkeypatch):
    install_action(monkeypatch, lambda ma, request, qs: None, permissions=("add",))
    with impersonate(editor):
        assert (
            run_action("demo.Book", "custom", [str(books["plain"].pk)], confirm=True)["status"]
            == "completed"
        )


def test_action_cannot_override_selection(editor, books):
    with impersonate(editor), pytest.raises(ToolError, match="override"):
        run_action(
            "demo.Book",
            "publish_books",
            [str(books["plain"].pk)],
            confirm=True,
            parameters={"select_across": "1"},
        )


def test_action_error_response_rolls_back_database_and_audit(editor, books, monkeypatch):
    def action(ma, request, qs):
        qs.update(published=True)
        return JsonResponse({"error": "denied"}, status=403)

    install_action(monkeypatch, action)
    with impersonate(editor), pytest.raises(ToolError, match="HTTP 403"):
        run_action("demo.Book", "custom", [str(books["plain"].pk)], confirm=True)
    assert not Book.objects.get(pk=books["plain"].pk).published
    assert not LogEntry.objects.exists()


def test_action_validation_and_controls_described():
    parser = FormDescription()
    parser.feed(
        '<ul class="errorlist"><li>Invalid date</li></ul><textarea name="body">Hello</textarea>'
        '<select name="kind"><option value="a" selected>A</option></select>'
        '<input name="flag" type="checkbox" checked><button name="apply" value="yes">Go</button>'
        '<input name="csrfmiddlewaretoken" value="sensitive">'
    )
    assert parser.errors == ["Invalid date"]
    fields = {f["name"]: f for f in parser.fields}
    assert fields["body"]["value"] == "Hello"
    assert fields["kind"]["choices"][0]["selected"]
    assert fields["flag"]["checked"]
    assert fields["apply"]["value"] == "yes"
    assert "csrfmiddlewaretoken" not in fields


def test_update_uses_full_form_for_cross_field_validation(editor, books, monkeypatch):
    class BookForm(forms.ModelForm):
        class Meta:
            model = Book
            fields = "__all__"

        def clean(self):
            data = super().clean()
            if data.get("published") and data.get("title") == "Plain":
                raise forms.ValidationError("Published books need a new title")
            return data

    monkeypatch.setattr(admin.site._registry[Book], "form", BookForm)
    with impersonate(editor), pytest.raises(ToolError, match="new title"):
        update_object("demo.Book", str(books["plain"].pk), {"published": True})
    assert not Book.objects.get(pk=books["plain"].pk).published


def test_request_post_and_save_form_hooks_are_preserved(editor, books, monkeypatch):
    ma = admin.site._registry[Book]
    original_get_form = ma.get_form
    original_save_form = ma.save_form

    def get_form(request, *args, **kwargs):
        assert request.POST["title"] == "Renamed"
        return original_get_form(request, *args, **kwargs)

    def save_form(request, form, change):
        obj = original_save_form(request, form, change)
        obj.published = True
        return obj

    monkeypatch.setattr(ma, "get_form", get_form)
    monkeypatch.setattr(ma, "save_form", save_form)
    with impersonate(editor):
        update_object("demo.Book", str(books["plain"].pk), {"title": "Renamed"})
    books["plain"].refresh_from_db()
    assert books["plain"].published


def test_custom_filter_runs_and_preserves_visibility(viewer, books, monkeypatch):
    class CustomFilter(admin.SimpleListFilter):
        title = "Published"
        parameter_name = "published_only"

        def lookups(self, request, model_admin):
            return [("yes", "Yes")]

        def queryset(self, request, queryset):
            # A badly scoped custom filter must not escape the base admin queryset.
            return Book.objects.all()

    monkeypatch.setattr(admin.site._registry[Book], "list_filter", [CustomFilter])
    with impersonate(viewer):
        result = search_objects("demo.Book", filters={"published_only": "yes"})
        assert result["total"] == 2
        with pytest.raises(ToolError, match="invalid choice"):
            search_objects("demo.Book", filters={"published_only": "bogus"})


def test_delete_cascade_cannot_escape_queryset(editor, author, books):
    from django_admin_fastmcp.tools.write import delete_object

    with impersonate(editor), pytest.raises(ToolError, match="outside your access"):
        delete_object("demo.Author", str(author.pk), confirm=True)
    assert Book.objects.count() == 3


def test_delete_preview_does_not_leak_hidden_labels(editor, books, monkeypatch):
    from django_admin_fastmcp.tools.write import delete_object

    monkeypatch.setattr(admin.site._registry[Book], "mcp_exclude_fields", ("title",), raising=False)
    with impersonate(editor):
        result = delete_object("demo.Book", str(books["plain"].pk))
    assert "Plain" not in json.dumps(result)


def test_custom_form_cannot_reintroduce_hidden_model_field(editor, books, monkeypatch):
    class BroadForm(forms.ModelForm):
        class Meta:
            model = Book
            fields = ("title", "author")

    ma = admin.site._registry[Book]
    monkeypatch.setattr(ma, "get_form", lambda *args, **kwargs: BroadForm)
    monkeypatch.setattr(ma, "get_fieldsets", lambda *args: [(None, {"fields": ["author"]})])
    with impersonate(editor), pytest.raises(ToolError, match="not writable"):
        update_object("demo.Book", str(books["plain"].pk), {"title": "Changed"})


def test_inline_writes_are_explicitly_unsupported(editor, books, monkeypatch):
    monkeypatch.setattr(
        admin.site._registry[Book], "get_inline_instances", lambda *args: [object()]
    )
    with impersonate(editor), pytest.raises(ToolError, match="inline formsets"):
        update_object("demo.Book", str(books["plain"].pk), {"title": "Changed"})


def test_split_datetime_json_and_boolean_round_trip():
    from django.db import models
    from django.forms import ModelForm, SplitDateTimeField

    from django_admin_fastmcp.tools.write import bound_form_data

    class Sample(models.Model):
        occurred = models.DateTimeField()
        metadata = models.JSONField(default=dict)
        flag = models.BooleanField(default=False)

        class Meta:
            app_label = "demo"
            managed = False

    class SampleForm(ModelForm):
        occurred = SplitDateTimeField()

        class Meta:
            model = Sample
            fields = ("occurred", "metadata", "flag")

    form = SampleForm(
        data=bound_form_data(
            SampleForm,
            {
                "occurred": "2026-10-27T10:30:00Z",
                "metadata": {"test": 1},
                "flag": True,
            },
        )
    )
    assert form.is_valid(), form.errors
    obj = form.save(commit=False)
    retained = SampleForm(data=bound_form_data(SampleForm, {"flag": False}, obj), instance=obj)
    assert retained.is_valid(), retained.errors
    assert retained.cleaned_data["metadata"] == {"test": 1}
    assert retained.cleaned_data["occurred"] == form.cleaned_data["occurred"]
    assert retained.cleaned_data["flag"] is False


def test_chunked_body_limit_is_enforced():
    import asyncio

    from django_admin_fastmcp.server import MAX_BODY_BYTES, BodySizeLimit

    sent = []
    chunks = iter(
        [
            {"type": "http.request", "body": b"x" * MAX_BODY_BYTES, "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": False},
        ]
    )

    async def receive():
        return next(chunks)

    async def send(message):
        sent.append(message)

    async def app(*args):
        raise AssertionError("oversized body must not reach app")

    asyncio.run(BodySizeLimit(app)({"type": "http"}, receive, send))
    assert sent[0]["status"] == 413


def test_bulk_delete_cannot_bypass_cascade_scope(editor, author, books):
    with impersonate(editor), pytest.raises(ToolError, match="outside your access"):
        run_action(
            "demo.Author",
            "delete_selected",
            [str(author.pk)],
            confirm=True,
            parameters={"post": "yes"},
        )
    assert Book.objects.count() == 3


def test_relation_filter_requires_access_to_target(viewer, books, author, monkeypatch):
    with impersonate(viewer):
        assert search_objects("demo.Book", filters={"author": str(author.pk)})["total"] == 2
    monkeypatch.setattr(
        admin.site._registry[type(author)], "has_view_permission", lambda *args: False
    )
    with impersonate(viewer), pytest.raises(ToolError):
        search_objects("demo.Book", filters={"author": str(author.pk)})


def test_discovery_omits_hidden_metadata(viewer, books, monkeypatch):
    from django_admin_fastmcp.tools.introspect import describe_model

    monkeypatch.setattr(admin.site._registry[Book], "mcp_exclude_fields", ("title",), raising=False)
    with impersonate(viewer):
        result = describe_model("demo.Book")
    assert "title" not in result["list_display"]
    assert "title" not in result["search_fields"]
