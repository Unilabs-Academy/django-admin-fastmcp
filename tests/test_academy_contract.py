"""Optional source-contract checks; never imports or connects to the host application.

Set ACADEMY_SOURCE_DIR to the local aca_django checkout. Methods are loaded from
source and exercised with isolated fixture models and stubbed external effects.
This is not a full application integration test.
"""

import ast
import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from demo.models import Book
from django.contrib import admin
from django.http import HttpResponse, HttpResponseRedirect

from django_admin_fastmcp.auth import impersonate
from django_admin_fastmcp.request import admin_request
from django_admin_fastmcp.tools.actions import run_action


def method_source(name):
    root = os.environ.get("ACADEMY_SOURCE_DIR")
    if not root:
        pytest.skip("set ACADEMY_SOURCE_DIR for optional host source-contract tests")
    module = ast.parse((Path(root) / "services/admin.py").read_text())
    methods = [
        node for node in ast.walk(module) if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if name == "get_form":
        methods = [node for node in methods if "professional_domain" in ast.unparse(node)]
    assert len(methods) == 1
    methods[0].decorator_list = []
    return ast.unparse(methods[0])


def test_host_copy_action_with_date_input(editor, books, monkeypatch):
    namespace = {
        "datetime": datetime,
        "HttpResponseRedirect": HttpResponseRedirect,
        "render": lambda *args, **kwargs: HttpResponse(
            '<form><input name="start_date" type="date"><input name="start_time" type="time">'
            '<input name="apply" value="yes" type="submit"></form>'
        ),
        "copy_service_to_new_date": lambda source, date: Book.objects.create(
            title=date.isoformat(), author=source.author
        ),
    }
    exec("from __future__ import annotations\n" + method_source("copy_service"), namespace)  # noqa: S102 - trusted local source contract
    action = namespace["copy_service"]
    monkeypatch.setattr(Book, "start_date", None, raising=False)
    monkeypatch.setattr(
        admin.site._registry[Book],
        "get_actions",
        lambda request: {"copy_service": (action, "copy_service", "Copy service to new date")},
    )
    with impersonate(editor):
        first = run_action("demo.Book", "copy_service", [str(books["plain"].pk)], confirm=True)
        assert first["status"] == "requires_input"
        result = run_action(
            "demo.Book",
            "copy_service",
            [str(books["plain"].pk)],
            confirm=True,
            parameters={"apply": "yes", "start_date": "2026-11-01", "start_time": "10:30"},
        )
    assert result["status"] == "completed"
    assert Book.objects.filter(title="2026-11-01T10:30:00").exists()


def test_host_form_reads_submitted_domain(editor):
    calls = []

    class Queryset:
        def filter(self, **kwargs):
            calls.append(kwargs)
            return self

        def none(self):
            raise AssertionError("submitted domain must be available to get_form")

    field = SimpleNamespace(queryset=Queryset(), widget=SimpleNamespace(attrs={}))
    form = SimpleNamespace(base_fields={"lecturers": field})

    class Base:
        def get_form(self, *args, **kwargs):
            return form

    source = method_source("get_form")
    namespace = {"Base": Base, "Domain": SimpleNamespace(values=["test-domain"])}
    exec(  # noqa: S102 - trusted local source contract
        "from __future__ import annotations\nclass HostAdmin(Base):\n"
        + "\n".join("    " + line for line in source.splitlines()),
        namespace,
    )
    request = admin_request(editor, method="POST", data={"domain": "test-domain"})
    namespace["HostAdmin"]().get_form(request)
    assert calls == [{"profile__professional_domain": "test-domain"}]
