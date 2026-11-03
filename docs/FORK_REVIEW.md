# Adapter fork review

This is an undeployed pilot candidate based on edelvalle/django-admin-fastmcp
0.1.3, upstream commit `ebd557ac2b799836cb7871744a5f30f7e41dd521`.
Fork version: `0.1.3+academy.1`. Review date: 2026-10-27.

## Implemented changes

- Enforce admin-site/module checks, object-level read/action permissions, and
  scoped querysets. Deletion additionally validates each cascaded object's
  exposure, writable-model status, queryset membership and view/delete access.
  The built-in `delete_selected` action uses these same cascade checks.
- Honor request-aware admin fields/fieldsets and exclusions in reads. Apply MCP
  allow/deny fields and redaction to writes too. Use neutral model/PK labels;
  arbitrary `__str__` output can reveal excluded fields. History exposes action
  metadata, not free-text messages or object representations.
- Deny hidden-field probes through search/filter/order. Relation equality/in
  filters require visible target identities. Generic relation traversal,
  relation text search and relation ordering are deliberately unsupported.
- Bound candidate-row scans, related-row scans, history results and action
  responses. Support declared `SimpleListFilter` choices without letting a
  filter expand the original visibility queryset.
- Populate synthetic request POST data and the configured origin. Bind full
  admin ModelForms while retaining omitted update values; preserve JSON,
  Boolean and split-datetime values. Invoke `save_form`, `save_model` and
  `save_related` hooks. Inline-formset writes fail explicitly.
- Accept scalar/list action parameters, including form submit controls. Protect
  action name and selected IDs from parameter overrides. Describe returned HTML
  controls, values and validation errors, reporting `requires_input` rather than
  completion. Return bounded non-HTML downloads as base64; reject streaming
  responses. Log action invocation under the delegated user before calling it,
  inside the database transaction. This records form-producing invocations too;
  it does not claim that every invocation mutated data.
- Require canonical OAuth audiences. Check the real browser's admin-site access
  at consent. Lock code exchanges, refreshes and revocations; retain consumed
  refresh credential hashes so authenticated replay revokes the grant family.
  Never use tokens as URLs or log token values. Token responses are noncacheable.
- Count actual HTTP body bytes, including chunked requests, and annotate MCP
  tools with read/write/idempotency hints. Hints are not authorization controls.

## Review and validation

Two additional reviewer agents examined OAuth and adapter behavior. The adapter
review ran three passes; its final focused review found no remaining blocker in
reviewed fixes and independently passed all 28 adapter regression cases. Parent
review found a canonical URL mismatch and required an additional regression.
This is a targeted engineering review, not a complete independent security audit.

Verification targets Python 3.11, Django 5.2.17, FastMCP 3.4.6, and PostgreSQL 17.
Tests cover permissions, hidden-field inference, forms, action retries and
responses, audit attribution, rollback, OAuth/revocation, actual HTTP MCP calls,
and deterministic concurrent token exchanges. The concurrency tests observe
PostgreSQL lock contention rather than relying on timing alone.

Optional host-source contract tests read two methods from a trusted local
checkout, exercise them against isolated fixture models, and stub external
side effects. They do not import the whole host application or connect to its
services. They establish compatibility of the inspected calling conventions,
not complete integration. Full host dependency resolution was also checked.

See the accompanying verification record for final commands and test totals.

## Reproduce

```sh
uv venv --python 3.11 .venv-academy
uv pip install --python .venv-academy/bin/python -e . \
  'Django==5.2.17' 'fastmcp==3.4.6' 'pytest~=8.4' \
  'pytest-django~=4.13' 'psycopg[binary]'
.venv-academy/bin/python -m pytest -q -o addopts=''
```

To exercise transactional races, provision an isolated PostgreSQL test database
and run with `--ds=tests.project.settings_postgres`. Defaults are localhost port
55439, database `mcp_review`, user `postgres`; the settings document the
`MCP_TEST_PG_*` overrides. Never point these test settings at application data.
Set `ACADEMY_SOURCE_DIR` to a trusted local `aca_django` checkout to enable the two
optional source-contract checks. Only those optional checks execute loaded local
source. CI runs PostgreSQL tests without host application code.

## Deliberate limits and adoption gates

- No deployment or connection to the team's ChatGPT workspace has been made.
  The actual reverse proxy, workspace OAuth connection, deployed authentication
  policy, and end-to-end application side effects still need staging validation.
- Inline/nested-inline editing, file uploads, JavaScript custom widgets/pages,
  and workflows depending on persistent browser session state are unsupported.
  Do not treat this as complete parity with Django admin.
- Synthetic remote requests do not inherit the browser cookie/session or claim
  to be MFA-verified. A custom/OTP AdminSite that requires a browser-only property
  will fail closed. Decide and review a delegated-access policy for that site
  before use; do not bypass its check by fabricating an MFA flag.
- `confirm` is an application input, not proof of human approval or a single-use
  authorization. The MCP host must apply its approval policy. Repeating a write
  or action can repeat its side effects; use dedicated idempotent domain tools
  for sensitive or retry-prone operations.
- Transactions roll back database changes, not email, tasks, files or other
  external effects of arbitrary admin callbacks. Such callbacks remain trusted
  application code and require workflow-specific integration tests.
- Neutral labels, conservative field rules and relation restrictions trade some
  convenience for explicit access boundaries. Reads scan at most MAX_SCAN_ROWS
  candidates (default 10,000), then require a narrower query; output pages remain
  capped independently. Large or complex workflows need tailored tools.
- Actions that return HTML are reported as requiring input even if they already
  performed work. Redirects are returned as metadata and never followed. Form
  descriptions are untrusted application data, not agent instructions.
- Protect public OAuth registration/token endpoints with deployment rate limits.
  Retain consumed-refresh hashes until their grants expire or are deleted;
  removing them early weakens replay detection. Existing unbound tokens need
  reauthorization, and migration 0002 must be applied in the chosen environment.

Begin with explicit MODELS/EXCLUDE_MODELS and empty WRITABLE_MODELS. Add tested
models and workflows individually. Keep user, group, permission, credential and
other sensitive admin surfaces out of the first pilot. These deployment choices
have not been applied to the host application.
