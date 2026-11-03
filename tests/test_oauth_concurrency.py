"""Exercise real PostgreSQL locks with overlapping OAuth requests."""

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from django.db import close_old_connections, connection
from django.test import Client
from django.urls import reverse

from django_admin_fastmcp import conf
from django_admin_fastmcp.auth import DjangoAdminTokenVerifier
from django_admin_fastmcp.models import McpAuthorizationCode, McpClient, McpToken
from tests.test_auth import REDIRECT_URI, make_pkce

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(connection.vendor != "postgresql", reason="requires PostgreSQL row locks"),
]


def _request(endpoint, data):
    close_old_connections()
    try:
        return Client().post(reverse(f"django_admin_fastmcp:{endpoint}"), data)
    finally:
        close_old_connections()


def _wait_for_lock():
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid() "
                "AND wait_event_type = 'Lock' AND query LIKE '%%django_admin_fastmcp%%')"
            )
            if cursor.fetchone()[0]:
                return
        Event().wait(0.02)
    pytest.fail("the concurrent request did not wait for the OAuth row lock")


def _overlap(first, second, entered, release):
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_result = executor.submit(first)
        try:
            assert entered.wait(5), "first request never reached the locked mutation"
            second_result = executor.submit(second)
            _wait_for_lock()
        finally:
            release.set()
        return first_result.result(timeout=10), second_result.result(timeout=10)


def _grant(superuser):
    client = McpClient.objects.create(name="Concurrency test", redirect_uris=[REDIRECT_URI])
    return client, McpToken.issue(
        user=superuser, client=client, scopes=["admin"], resource=conf.get("MCP_URL")
    )


def _refresh_data(client, refresh):
    return {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "client_id": client.client_id,
        "resource": conf.get("MCP_URL"),
    }


def test_overlapping_code_redemptions_issue_once_and_revoke_replay(superuser, monkeypatch):
    client = McpClient.objects.create(name="Concurrency test", redirect_uris=[REDIRECT_URI])
    verifier, challenge = make_pkce()
    code = McpAuthorizationCode.mint(
        client=client,
        user=superuser,
        scopes=["admin"],
        redirect_uri=REDIRECT_URI,
        code_challenge=challenge,
        resource=conf.get("MCP_URL"),
    )
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        "resource": conf.get("MCP_URL"),
    }
    entered, release = Event(), Event()
    issue = McpToken.issue

    def paused_issue(cls, **kwargs):
        entered.set()
        assert release.wait(7)
        return issue(**kwargs)

    monkeypatch.setattr(McpToken, "issue", classmethod(paused_issue))
    first, second = _overlap(
        lambda: _request("token", params), lambda: _request("token", params), entered, release
    )
    assert first.status_code == 200
    assert second.status_code == 400
    assert McpToken.objects.count() == 1
    assert McpToken.objects.get().is_revoked
    assert DjangoAdminTokenVerifier().verify_token_sync(first.json()["access_token"]) is None


def test_overlapping_refreshes_revoke_the_replacement_grant(superuser, monkeypatch):
    client, (grant, _, refresh) = _grant(superuser)
    params = _refresh_data(client, refresh)
    entered, release = Event(), Event()
    rotate = McpToken.rotate

    def paused_rotate(self):
        entered.set()
        assert release.wait(7)
        return rotate(self)

    monkeypatch.setattr(McpToken, "rotate", paused_rotate)
    first, second = _overlap(
        lambda: _request("token", params), lambda: _request("token", params), entered, release
    )
    assert first.status_code == 200
    assert second.status_code == 400
    grant.refresh_from_db()
    assert grant.is_revoked
    assert grant.refresh_uses.count() == 1
    assert DjangoAdminTokenVerifier().verify_token_sync(first.json()["access_token"]) is None


@pytest.mark.parametrize("first_operation", ["refresh", "revoke"])
def test_revocation_wins_over_overlapping_refresh(superuser, monkeypatch, first_operation):
    client, (grant, _, refresh) = _grant(superuser)
    params = _refresh_data(client, refresh)
    entered, release = Event(), Event()
    method = "rotate" if first_operation == "refresh" else "revoke"
    original = getattr(McpToken, method)

    def paused_mutation(self):
        entered.set()
        assert release.wait(7)
        return original(self)

    monkeypatch.setattr(McpToken, method, paused_mutation)
    refresh_call = lambda: _request("token", params)  # noqa: E731
    revoke_call = lambda: _request("revoke", {"token": refresh})  # noqa: E731
    first, second = _overlap(
        refresh_call if first_operation == "refresh" else revoke_call,
        revoke_call if first_operation == "refresh" else refresh_call,
        entered,
        release,
    )
    assert first.status_code == 200
    assert second.status_code == (200 if first_operation == "refresh" else 400)
    grant.refresh_from_db()
    assert grant.is_revoked
    if first_operation == "refresh":
        assert DjangoAdminTokenVerifier().verify_token_sync(first.json()["access_token"]) is None
