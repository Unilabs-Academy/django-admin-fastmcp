import base64
import sys
import types
from datetime import timedelta

import nested_admin
import pytest
from demo.models import Author, Book, BookNote
from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, StreamingHttpResponse
from django.middleware.csrf import get_token
from django.urls import clear_url_caches, include, path
from django.utils import timezone

from django_admin_fastmcp import conf
from django_admin_fastmcp.auth import DjangoAdminTokenVerifier, impersonate
from django_admin_fastmcp.errors import ToolError
from django_admin_fastmcp.models import McpClient, McpToken, McpWorkflow
from django_admin_fastmcp.tools.workflows import (
    close_admin_workflow,
    download_admin_file,
    inspect_admin_workflow,
    open_admin_page,
    submit_admin_form,
    upload_admin_file,
)

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def workflow_settings(settings, tmp_path):
    settings.ADMIN_FASTMCP = {**settings.ADMIN_FASTMCP, "PERMISSION_MODE": "admin"}
    settings.MEDIA_ROOT = str(tmp_path)


def form_index(page, name):
    for form in page["forms"]:
        fields = inspect_admin_workflow(page["workflow_id"], form["index"])["fields"]
        if any(f["name"] == name for f in fields):
            return form["index"]
    raise AssertionError(name)


def submit(page, name, parameters, **kwargs):
    return submit_admin_form(
        page["workflow_id"],
        page["revision"],
        form_index(page, name),
        parameters,
        confirm=True,
        **kwargs,
    )


def test_native_form_validation_preservation_audit_and_replay(editor, books):
    with impersonate(editor):
        page = open_admin_page(f"/admin/demo/book/{books['plain'].pk}/change/", confirm=True)
        assert page["status"] == 200
        invalid = submit(page, "title", {"title": "", "_save": "Save"})
        assert invalid["errors"]
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"
        saved = submit(invalid, "title", {"title": "Native edit", "_save": "Save"})
        assert saved["status"] == 302
        updated = Book.objects.get(pk=books["plain"].pk)
        assert updated.title == "Native edit"
        assert updated.author_id == books["plain"].author_id
        assert LogEntry.objects.get(object_id=str(updated.pk)).user_id == editor.pk
        with pytest.raises(ToolError, match=r"stale|already"):
            open_admin_page("/admin/", page["workflow_id"], page["revision"], confirm=True)
        close_admin_workflow(page["workflow_id"])
        with pytest.raises(ToolError, match="unavailable"):
            inspect_admin_workflow(page["workflow_id"])


def test_native_permissions_and_no_arbitrary_urls(viewer, books, superuser):
    with impersonate(viewer):
        page = open_admin_page(f"/admin/demo/book/{books['plain'].pk}/change/", confirm=True)
        fields = [
            field
            for f in page["forms"]
            for field in inspect_admin_workflow(page["workflow_id"], f["index"])["fields"]
        ]
        assert not any(f["name"] in {"title", "_save"} for f in fields)
        denied_page = open_admin_page("/admin/demo/book/add/", confirm=True)
        assert denied_page["status"] == 403
    with impersonate(superuser):
        for url in [
            "https://example.com/admin/",
            "/admin/login/",
            "/admin/mcp/token",
            "/admin/django_admin_fastmcp/mcptoken/",
            "/admin/demo/secretproject/",
        ]:
            with pytest.raises(ToolError):
                open_admin_page(url, confirm=True)


def test_cross_user_expiry_and_unknown_field_rejection(editor, viewer, books):
    with impersonate(editor):
        page = open_admin_page(f"/admin/demo/book/{books['plain'].pk}/change/", confirm=True)
        with pytest.raises(ToolError, match="editable control"):
            submit(page, "title", {"is_superuser": "1"})
        with pytest.raises(ToolError, match="editable control"):
            submit(page, "title", {"csrfmiddlewaretoken": "forged"})
    with impersonate(viewer), pytest.raises(ToolError, match="unavailable"):
        inspect_admin_workflow(page["workflow_id"])
    McpWorkflow.objects.filter(pk=page["workflow_id"]).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    with impersonate(editor), pytest.raises(ToolError, match="unavailable"):
        inspect_admin_workflow(page["workflow_id"])


def test_current_permissions_rechecked_between_steps(editor, books):
    with impersonate(editor):
        page = open_admin_page(f"/admin/demo/book/{books['plain'].pk}/change/", confirm=True)
        editor.user_permissions.clear()
        result = submit(page, "title", {"title": "Forbidden", "_save": "Save"})
        assert result["status"] == 403
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"


@pytest.fixture
def custom_admin(monkeypatch, settings):
    class NoteInline(nested_admin.NestedTabularInline):
        model = BookNote
        extra = 0

    class BookInline(nested_admin.NestedStackedInline):
        model = Book
        extra = 0
        inlines = (NoteInline,)

    class WorkflowAuthorAdmin(nested_admin.NestedModelAdmin):
        inlines = (BookInline,)

        def get_urls(self):
            return [
                path("wizard/", self.admin_site.admin_view(self.wizard)),
                path("export/", self.admin_site.admin_view(self.export)),
                *super().get_urls(),
            ]

        def wizard(self, request):
            if not self.has_change_permission(request):
                raise PermissionDenied
            if request.method == "POST":
                if request.POST.get("step") == "first":
                    request.session["wizard_name"] = request.POST["name"]
                else:
                    Author.objects.create(name=request.session["wizard_name"])
                    return HttpResponseRedirect("/admin/demo/author/")
            step = "second" if request.session.get("wizard_name") else "first"
            return HttpResponse(
                '<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="'
                + get_token(request)
                + '"><input name="name"><input name="step" value="'
                + step
                + '"><button name="apply" value="1">Apply</button></form>'
            )

        def export(self, request):
            if not self.has_view_permission(request):
                raise PermissionDenied
            return StreamingHttpResponse(iter([b"first,", b"second\n"]), content_type="text/csv")

    monkeypatch.setitem(admin.site._registry, Author, WorkflowAuthorAdmin(Author, admin.site))
    urls = types.ModuleType("workflow_test_urls")
    urls.urlpatterns = [
        path("admin/", admin.site.urls),
        path("_nested_admin/", include("nested_admin.urls")),
    ]
    monkeypatch.setitem(sys.modules, "workflow_test_urls", urls)
    settings.ROOT_URLCONF = "workflow_test_urls"
    clear_url_caches()
    yield
    clear_url_caches()


def test_session_wizard_and_streaming_export(editor, custom_admin):
    with impersonate(editor):
        page = open_admin_page("/admin/demo/author/wizard/", confirm=True)
        second = submit(page, "name", {"name": "Session Author", "apply": "1"})
        final = submit(second, "step", {"apply": "1"})
        assert final["status"] == 302
        assert Author.objects.filter(name="Session Author").count() == 1
        result = open_admin_page(
            "/admin/demo/author/export/", final["workflow_id"], final["revision"], confirm=True
        )
        file = download_admin_file(result["workflow_id"], result["download"]["file_id"])
        assert base64.b64decode(file["content_base64"]) == b"first,second\n"


def test_nested_inline_create_with_upload(superuser, custom_admin):
    with impersonate(superuser):
        page = open_admin_page("/admin/demo/author/add/", confirm=True)
        assert page["status"] == 200
        chunk = upload_admin_file(
            page["workflow_id"], "note.txt", base64.b64encode(b"first").decode(), complete=False
        )
        done = upload_admin_file(
            page["workflow_id"],
            "note.txt",
            base64.b64encode(b" second").decode(),
            file_id=chunk["file_id"],
            offset=chunk["next_offset"],
        )
        result = submit(
            page,
            "name",
            {
                "name": "Nested author",
                "_save": "Save",
                "books-TOTAL_FORMS": "1",
                "books-0-title": "Nested book",
                "books-0-notes-TOTAL_FORMS": "1",
                "books-0-notes-INITIAL_FORMS": "0",
                "books-0-notes-MIN_NUM_FORMS": "0",
                "books-0-notes-MAX_NUM_FORMS": "1000",
                "books-0-notes-0-text": "File note",
            },
            files={"books-0-notes-0-attachment": done["file_id"]},
        )
        assert result["status"] == 302, result
        note = BookNote.objects.get(text="File note")
        assert note.book.author.name == "Nested author"
        assert note.attachment.read() == b"first second"


def test_file_limits_ownership_and_retry(editor, viewer, settings):
    with impersonate(editor):
        page = open_admin_page("/admin/", confirm=True)
        settings.ADMIN_FASTMCP["MAX_WORKFLOW_BYTES"] = 8
        chunk = upload_admin_file(page["workflow_id"], "x.txt", "YWJj", complete=False)
        retry = upload_admin_file(page["workflow_id"], "x.txt", "YWJj", chunk["file_id"], 0, False)
        assert retry["next_offset"] == 3
        with pytest.raises(ToolError, match="byte limit"):
            upload_admin_file(page["workflow_id"], "x.txt", "YWJjYWJj", chunk["file_id"], 3)
    with impersonate(viewer), pytest.raises(ToolError, match="unavailable"):
        upload_admin_file(page["workflow_id"], "x.txt", "", chunk["file_id"], 3)


def test_grant_isolation_and_revocation(editor, monkeypatch):
    from django_admin_fastmcp import auth

    client = McpClient.objects.create(
        name="workflow", redirect_uris=["https://example.com/callback"]
    )
    grant, wire, _ = McpToken.issue(
        user=editor, client=client, scopes=["admin"], resource=conf.mcp_resource_url()
    )
    access = DjangoAdminTokenVerifier().verify_token_sync(wire)
    monkeypatch.setattr(auth, "_access_token", lambda: access)
    page = open_admin_page("/admin/", confirm=True)
    _other_grant, other_wire, _ = McpToken.issue(
        user=editor, client=client, scopes=["admin"], resource=conf.mcp_resource_url()
    )
    other_access = DjangoAdminTokenVerifier().verify_token_sync(other_wire)
    monkeypatch.setattr(auth, "_access_token", lambda: other_access)
    with pytest.raises(ToolError, match="unavailable"):
        inspect_admin_workflow(page["workflow_id"])
    monkeypatch.setattr(auth, "_access_token", lambda: access)
    grant.revoked_at = timezone.now()
    grant.save()
    with pytest.raises(ToolError, match="revoked"):
        inspect_admin_workflow(page["workflow_id"])


@pytest.mark.django_db(transaction=True)
def test_overlapping_native_submissions_execute_once(editor, books, monkeypatch):
    from threading import Event

    from django.db import close_old_connections, connection

    from tests.test_oauth_concurrency import _overlap

    if connection.vendor != "postgresql":
        pytest.skip("requires PostgreSQL row locks")
    with impersonate(editor):
        page = open_admin_page(f"/admin/demo/book/{books['plain'].pk}/change/", confirm=True)
        index = form_index(page, "title")
    entered, release = Event(), Event()
    original_save = McpWorkflow.save

    def paused_save(row, *args, **kwargs):
        if row.state.get("busy") and not entered.is_set():
            entered.set()
            assert release.wait(7)
        return original_save(row, *args, **kwargs)

    monkeypatch.setattr(McpWorkflow, "save", paused_save)

    def invoke():
        close_old_connections()
        try:
            with impersonate(editor):
                try:
                    return submit_admin_form(
                        page["workflow_id"],
                        page["revision"],
                        index,
                        {"title": "Exactly once", "_save": "Save"},
                        confirm=True,
                    )["status"]
                except ToolError:
                    return "stale"
        finally:
            close_old_connections()

    results = _overlap(invoke, invoke, entered, release)
    assert set(results) == {302, "stale"}
    assert LogEntry.objects.filter(object_id=str(books["plain"].pk)).count() == 1


def test_native_delete_confirmation_and_bulk_action(superuser, books):
    with impersonate(superuser):
        page = open_admin_page("/admin/demo/book/", confirm=True)
        result = submit(
            page,
            "action",
            {
                "action": "publish_books",
                "index": "0",
                "select_across": "0",
                "_selected_action": [str(books["plain"].pk)],
            },
        )
        assert result["status"] == 302
        assert Book.objects.get(pk=books["plain"].pk).published
        assert result["messages"]
        page = open_admin_page(
            f"/admin/demo/book/{books['plain'].pk}/delete/",
            result["workflow_id"],
            result["revision"],
            confirm=True,
        )
        assert Book.objects.filter(pk=books["plain"].pk).exists()
        result = submit(page, "post", {"post": "yes"})
        assert result["status"] == 302
        assert not Book.objects.filter(pk=books["plain"].pk).exists()
        assert LogEntry.objects.filter(
            user=superuser, object_id=str(books["plain"].pk), action_flag=3
        ).exists()


def test_native_inline_exclusions_cannot_be_bypassed(superuser, custom_admin, settings):
    settings.ADMIN_FASTMCP["EXCLUDE_MODELS"] = ("demo.BookNote",)
    with impersonate(superuser):
        page = open_admin_page("/admin/demo/author/add/", confirm=True)
        assert page["status"] == 403
        assert not page["forms"]
