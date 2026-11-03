"""Opt-in isolated PostgreSQL settings for transactional concurrency tests."""

import os

from .settings import *  # noqa: F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("MCP_TEST_PG_DATABASE", "mcp_review"),
        "USER": os.environ.get("MCP_TEST_PG_USER", "postgres"),
        "PASSWORD": os.environ.get("MCP_TEST_PG_PASSWORD", ""),
        "HOST": os.environ.get("MCP_TEST_PG_HOST", "127.0.0.1"),
        "PORT": os.environ.get("MCP_TEST_PG_PORT", "55439"),
        "OPTIONS": {"options": "-c statement_timeout=10000 -c lock_timeout=8000"},
    }
}
