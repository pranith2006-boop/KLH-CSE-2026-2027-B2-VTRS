# VulnTrack API

Base URL: `http://127.0.0.1:5001`. JSON responses use UTF-8. Unless noted, protected routes require `Authorization: Bearer <JWT>`. Tokens are HS256, last one hour, and are signed with `VULNTRACK_JWT_SECRET`.

## Authentication and access

| Route | Access | Purpose |
|---|---|---|
| `GET /api/health` | Public | Runs `semgrep --version` and a SQLite `SELECT 1`. |
| `POST /api/auth/login` | Public | Accepts `{"username":"admin","password":"…"}`; returns `{token,user}`. Invalid credentials return 401; missing JWT configuration returns 503. |
| `GET /api/auth/me` | Authenticated | Returns the signed-in account. |
| `GET /api/users` | Admin | Lists account IDs, usernames, and roles for assignment choices. |

Admins can list all projects/findings, start scans, assign findings, grant project access, and read audit logs. Developers see findings assigned to them or in projects where they have membership. Developers can update status and remediation notes only. The server enforces these rules regardless of UI visibility.

## Projects, scans, and findings

| Route | Access | Purpose |
|---|---|---|
| `POST /api/scans` | Admin | Multipart field `files` (multiple source files or ZIP), or `file` (one file/ZIP); optional form field `project_name`. |
| `GET /api/projects` | Admin or visible Developer projects | Lists projects visible to the caller. |
| `GET /api/projects/{project_id}/scans` | Admin or authorized Developer | Returns scan history. |
| `POST /api/projects/{project_id}/rescan` | Admin | Re-scans the latest stored source snapshot. |
| `POST /api/projects/{project_id}/members` | Admin | Accepts `{"username":"developer"}` to authorize that Developer for the project. |
| `GET /api/projects/{project_id}/members` | Admin | Lists project-specific Developer access. |
| `DELETE /api/projects/{project_id}/members/{user_id}` | Admin | Revokes project-specific access. |
| `GET /api/vulnerabilities` | Admin or Developer | Lists visible findings; optional `?project_id=...`. |
| `PATCH /api/vulnerabilities/{id}` | Admin or authorized Developer | Updates status, assignment (Admin only), and/or remediation notes. |

Scan response statuses are `completed`, `completed_with_errors`, and `failed`. HTTP 201 means completed, HTTP 207 means valid Semgrep output with Semgrep or auxiliary checker errors, HTTP 400 means invalid upload, and HTTP 502 means scanner failure. Failed scans include error text and are not represented as zero-finding scans. Uploads are stored as private snapshots under `backend/data/snapshots` (or `VULNTRACK_SOURCE_ROOT`) for reviewed fixes and repeat scans.

Finding updates accept these statuses: `Open`, `In Progress`, `Fixed`, `Accepted Risk`. Example Developer request:

```json
{"status":"In Progress","remediation_notes":"Use a parameterized query and add a regression check."}
```

Admins assign with a Developer username, for example `{"assignee":"developer"}`. Use `{"assignee":"Unassigned"}` to clear assignment. Every update refreshes `updated_at` and writes an audit event.

Findings are snapshots linked by `scan_id`. A SHA-256 fingerprint covers rule ID, relative file, line, and code hash; duplicate fingerprints are stored once within a scan. The same finding in a later scan is a separate snapshot so history is retained. Findings may include `category`, `cwe`, and `owasp`; unmapped values are blank. `npm audit` and `pip-audit` may require internet access and report errors in the scan summary when manifests or advisory services are unavailable.

## Audit and optional AI

| Route | Access | Purpose |
|---|---|---|
| `GET /api/audit-logs` | Admin | Lists recent audit events with actor usernames. Passwords and tokens are never logged. |
| `GET /api/ai/status` | Authenticated | Reports whether an AI provider key is configured and identifies provider/model; does not expose the key. |
| `POST /api/ai/remediation` | Authenticated, finding access required | Accepts `{"vulnerabilityId":"…"}`. Returns a pending suggestion with explanation, vulnerable/fixed code, rationale, provider/model, and suggestion ID. Does not apply changes. |
| `POST /api/ai/remediation/batch` | Authenticated, access required for every finding | Accepts 1–10 `vulnerabilityIds`; total snippets capped at 12,000 characters. Returns pending candidates; does not apply changes. |
| `POST /api/ai/remediation/{suggestion_id}/decision` | Authenticated, same user or Admin | Accepts `{"decision":"apply"}` or `{"decision":"reject"}`. Apply changes the matching code in the latest stored project snapshot and automatically creates a verification scan. |

OpenRouter is preferred when `OPENROUTER_API_KEY` is set and uses its chat completions endpoint. `VULNTRACK_AI_MODEL` defaults to `openrouter/free`; the key and model must be available to the backend process. Legacy direct OpenAI support remains available with `OPENAI_API_KEY` if no OpenRouter key is set. Requests have a configurable per-user rate limit (`VULNTRACK_AI_REQUESTS_PER_MINUTE`, default 5), a provider timeout, and a 4,000-character per-snippet / 12,000-character batch cap. Provider HTTP 429 responses return HTTP 429 and `Retry-After`. The user must click Apply or Reject after reviewing the proposal. Apply edits VulnTrack's stored snapshot, does not alter the user's local original files, and starts a verification scan. The source change must match the stored vulnerable snippet exactly once; otherwise apply returns HTTP 409 for manual review.
