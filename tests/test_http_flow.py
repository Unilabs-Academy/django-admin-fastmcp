"""OAuth token -> authenticated HTTP MCP tools -> revocation, without impersonation."""

import pytest
from django.contrib.admin.models import LogEntry
from starlette.testclient import TestClient

from django_admin_fastmcp import conf
from django_admin_fastmcp.server import BodySizeLimit, build_server
from tests.test_auth import full_flow


@pytest.mark.django_db(transaction=True)
def test_oauth_http_permissions_and_revocation(client, viewer, books):
    tokens = full_flow(client, viewer)
    app = build_server().http_app(path=conf.mcp_path(), stateless_http=True, json_response=True)
    headers = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "Accept": "application/json, text/event-stream",
    }
    with TestClient(BodySizeLimit(app)) as http:
        initialized = http.post(
            conf.mcp_path(),
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "integration-test", "version": "1"},
                },
            },
        )
        assert initialized.status_code == 200
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "admin_search_objects",
                "arguments": {"model": "demo.Book", "q": "Plain"},
            },
        }
        result = http.post(conf.mcp_path(), headers=headers, json=call)
        assert result.status_code == 200
        assert result.json()["result"]["structuredContent"]["total"] == 1
        mutation = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "admin_update_object",
                "arguments": {
                    "model": "demo.Book",
                    "pk": str(books["plain"].pk),
                    "data": {"title": "Forbidden"},
                },
            },
        }
        denied = http.post(conf.mcp_path(), headers=headers, json=mutation)
        assert denied.json()["result"]["isError"]
        assert not LogEntry.objects.filter(user=viewer).exists()
        client.post("/admin/mcp/revoke", {"token": tokens["refresh_token"]})
        assert http.post(conf.mcp_path(), headers=headers, json=call).status_code == 401
