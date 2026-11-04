from datetime import timedelta

import pytest
from demo.models import Author, Book
from django import forms
from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.utils import timezone

from django_admin_fastmcp import conf
from django_admin_fastmcp.auth import DjangoAdminTokenVerifier, impersonate
from django_admin_fastmcp.errors import ToolError
from django_admin_fastmcp.models import McpChangeProposal, McpClient, McpToken
from django_admin_fastmcp.tools.proposals import (
    apply_change_proposal,
    discard_change_proposal,
    inspect_change_proposal,
    prepare_changes,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def isolated_settings(settings):
    settings.ADMIN_FASTMCP = {**settings.ADMIN_FASTMCP}


def change(book, **data):
    return {"model": "demo.Book", "pk": str(book.pk), "data": data}


def test_batch_preview_normalization_apply_audit_and_replay(editor, books):
    second = Book.objects.create(title="Second", author=books["plain"].author)
    with impersonate(editor):
        plan = prepare_changes(
            [change(books["plain"], title=" New title "), change(second, published=True)]
        )
        assert plan["records"][0]["changes"] == {"title": {"before": "Plain", "after": "New title"}}
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"
        assert not LogEntry.objects.exists()
        applied = apply_change_proposal(plan["proposal_id"])
        assert applied["status"] == "applied"
        assert Book.objects.get(pk=second.pk).published
        assert Book.objects.get(pk=books["plain"].pk).title == "New title"
        assert (
            LogEntry.objects.filter(
                user=editor, change_message__contains=plan["proposal_id"]
            ).count()
            == 2
        )
        assert inspect_change_proposal(plan["proposal_id"])["status"] == "applied"
        with pytest.raises(ToolError, match="already applied"):
            apply_change_proposal(plan["proposal_id"])


def test_stale_batch_saves_nothing_and_is_consumed(editor, books):
    second = Book.objects.create(title="Second", author=books["plain"].author)
    with impersonate(editor):
        plan = prepare_changes([change(books["plain"], title="New"), change(second, title="Other")])
        Book.objects.filter(pk=second.pk).update(published=True)
        with pytest.raises(ToolError, match="stale"):
            apply_change_proposal(plan["proposal_id"])
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"
        assert not LogEntry.objects.exists()
        assert inspect_change_proposal(plan["proposal_id"])["status"] == "failed"
        with pytest.raises(ToolError, match="already failed"):
            apply_change_proposal(plan["proposal_id"])


def test_save_failure_rolls_back_batch_and_prevents_retry(editor, books, monkeypatch):
    second = Book.objects.create(title="Second", author=books["plain"].author)
    ma = admin.site._registry[Book]
    original = ma.save_model
    calls = []

    def save(request, obj, form, change):
        calls.append(obj.pk)
        if obj.pk == second.pk:
            raise RuntimeError("external side effect may have happened")
        original(request, obj, form, change)

    with impersonate(editor):
        plan = prepare_changes([change(books["plain"], title="New"), change(second, title="Other")])
        monkeypatch.setattr(ma, "save_model", save)
        with pytest.raises(RuntimeError):
            apply_change_proposal(plan["proposal_id"])
        assert len(calls) == 2
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"
        assert not LogEntry.objects.exists()
        with pytest.raises(ToolError, match="already failed"):
            apply_change_proposal(plan["proposal_id"])
        assert len(calls) == 2


def test_current_permissions_and_ownership(editor, viewer, books):
    with impersonate(editor):
        plan = prepare_changes([change(books["plain"], title="New")])
    with impersonate(viewer), pytest.raises(ToolError, match="unavailable"):
        inspect_change_proposal(plan["proposal_id"])
    editor.user_permissions.clear()
    with impersonate(editor):
        with pytest.raises(ToolError, match=r"permission|access"):
            apply_change_proposal(plan["proposal_id"])
        with pytest.raises(ToolError, match=r"permission|access"):
            inspect_change_proposal(plan["proposal_id"])
    assert Book.objects.get(pk=books["plain"].pk).title == "Plain"


def test_expiry_discard_duplicates_and_limits(editor, books, settings):
    with impersonate(editor):
        with pytest.raises(ToolError, match="duplicate"):
            prepare_changes([change(books["plain"], title="A"), change(books["plain"], title="B")])
        assert not McpChangeProposal.objects.exists()
        plan = prepare_changes([change(books["plain"], title="New")])
        discard_change_proposal(plan["proposal_id"])
        with pytest.raises(ToolError, match="already discarded"):
            apply_change_proposal(plan["proposal_id"])
        plan = prepare_changes([change(books["plain"], title="New")])
        McpChangeProposal.objects.filter(pk=plan["proposal_id"]).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        with pytest.raises(ToolError, match="expired"):
            apply_change_proposal(plan["proposal_id"])
        settings.ADMIN_FASTMCP["MAX_PKS"] = 1
        with pytest.raises(ToolError, match="between"):
            prepare_changes([change(books["plain"], title="A"), change(books["plain"], title="B")])


def test_disabled_writes_readonly_and_hidden_fields(editor, books, settings, monkeypatch):
    with impersonate(editor):
        with pytest.raises(ToolError, match="not editable"):
            prepare_changes([change(books["plain"], created_at="2020-01-01")])
        with pytest.raises(ToolError):
            prepare_changes([change(books["hidden"], title="New")])
        with pytest.raises(ToolError, match=r"permission|access"):
            prepare_changes([change(books["locked"], title="New")])
        monkeypatch.setattr(admin.site._registry[Book], "exclude", ("title",))
        with pytest.raises(ToolError, match="not writable"):
            prepare_changes([change(books["plain"], title="New")])
        settings.ADMIN_FASTMCP["DISABLED_TOOLS"] = ("update_object",)
        with pytest.raises(ToolError, match="disabled"):
            prepare_changes([change(books["plain"], published=True)])


def test_validation_and_changed_validation_are_checked(editor, books, monkeypatch):
    with impersonate(editor):
        with pytest.raises(ToolError, match="validation"):
            prepare_changes([change(books["plain"], title="")])
        plan = prepare_changes([change(books["plain"], title="New")])

        class ChangedForm(forms.ModelForm):
            class Meta:
                model = Book
                fields = "__all__"

            def clean_title(self):
                return self.cleaned_data["title"].upper()

        monkeypatch.setattr(admin.site._registry[Book], "form", ChangedForm)
        with pytest.raises(ToolError, match="stale"):
            apply_change_proposal(plan["proposal_id"])
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"


def test_grant_isolation_and_revocation(editor, books, monkeypatch):
    from django_admin_fastmcp import auth

    client = McpClient.objects.create(
        name="proposals", redirect_uris=["https://example.com/callback"]
    )
    grant, wire, _ = McpToken.issue(
        user=editor, client=client, scopes=["admin"], resource=conf.mcp_resource_url()
    )
    access = DjangoAdminTokenVerifier().verify_token_sync(wire)
    monkeypatch.setattr(auth, "_access_token", lambda: access)
    plan = prepare_changes([change(books["plain"], title="New")])
    _, other_wire, _ = McpToken.issue(
        user=editor, client=client, scopes=["admin"], resource=conf.mcp_resource_url()
    )
    other_access = DjangoAdminTokenVerifier().verify_token_sync(other_wire)
    monkeypatch.setattr(auth, "_access_token", lambda: other_access)
    with pytest.raises(ToolError, match="unavailable"):
        apply_change_proposal(plan["proposal_id"])
    monkeypatch.setattr(auth, "_access_token", lambda: access)
    grant.revoke()
    with pytest.raises(ToolError, match="revoked"):
        apply_change_proposal(plan["proposal_id"])


def test_foreign_key_preview_hides_inaccessible_relations(editor, books, monkeypatch):
    other = Author.objects.create(name="Other")
    with impersonate(editor):
        plan = prepare_changes([change(books["plain"], author=str(other.pk))])
        assert plan["records"][0]["changes"]["author"]["after"]["pk"] == str(other.pk)
        monkeypatch.setattr(
            admin.site._registry[Author], "has_view_permission", lambda request, obj=None: False
        )
        with pytest.raises(ToolError, match="visible"):
            prepare_changes([change(books["plain"], author=str(other.pk), title="New")])


@pytest.mark.django_db(transaction=True)
def test_concurrent_apply_runs_once(editor, books, monkeypatch):
    from threading import Event

    from django.db import close_old_connections, connection

    from tests.test_oauth_concurrency import _overlap

    if connection.vendor != "postgresql":
        pytest.skip("requires PostgreSQL row locks")
    with impersonate(editor):
        plan = prepare_changes([change(books["plain"], title="Once")])
    entered, release = Event(), Event()
    original = McpChangeProposal.save

    def paused_save(row, *args, **kwargs):
        if row.status == "applying" and not entered.is_set():
            entered.set()
            assert release.wait(7)
        return original(row, *args, **kwargs)

    monkeypatch.setattr(McpChangeProposal, "save", paused_save)

    def invoke():
        close_old_connections()
        try:
            with impersonate(editor):
                try:
                    return apply_change_proposal(plan["proposal_id"])["status"]
                except ToolError:
                    return "rejected"
        finally:
            close_old_connections()

    assert set(_overlap(invoke, invoke, entered, release)) == {"applied", "rejected"}
    assert LogEntry.objects.filter(object_id=str(books["plain"].pk)).count() == 1


def test_preview_rolls_back_custom_validation_writes(editor, books, monkeypatch):
    class SideEffectForm(forms.ModelForm):
        class Meta:
            model = Book
            fields = "__all__"

        def clean_title(self):
            Author.objects.create(name="Validation side effect")
            return self.cleaned_data["title"]

    monkeypatch.setattr(admin.site._registry[Book], "form", SideEffectForm)
    with impersonate(editor):
        plan = prepare_changes([change(books["plain"], title="New")])
        assert plan["status"] == "pending"
        assert not Author.objects.filter(name="Validation side effect").exists()
        assert Book.objects.get(pk=books["plain"].pk).title == "Plain"
