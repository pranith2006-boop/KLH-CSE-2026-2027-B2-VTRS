# VulnTrack backend

Flask REST API with SQLite persistence and offline Semgrep scanning. Uploaded source is read as data and is never executed. The bundled `rules/vulntrack.yml` makes the demo independent of registry/network access. Upload extensions, request/expanded size, file count, and ZIP paths are checked; relative paths are preserved in a temporary directory and removed after the scan.

## Database and scan history

- Projects are reused by normalized name: trim whitespace, collapse repeated spaces, then compare without case sensitivity. The database enforces this key as unique.
- Every accepted scan creates a `scans` row with status, timestamps, file/finding counts, and error text. Legacy project rows are migrated into scan history; duplicate legacy project names are merged while retaining their old scan records and findings.
- Findings are snapshots tied to one `scan_id`. Their fingerprint hashes the rule ID, relative file path, line, and code. The same fingerprint is stored only once within a scan. A later scan stores a new snapshot, so history can show that a finding reappeared.
- Tables: `users`, `project_members`, `projects`, `scans`, `vulnerabilities`, and `audit_logs`.

## Setup (Windows PowerShell)

```powershell
cd D:\SOAProject\vulntrack-v2-ai-remediation\backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env: set a private JWT secret and demo passwords; AI keys are optional.
python seed_users.py
python app.py
```

The backend loads `backend/.env` automatically. Use the file's `VULNTRACK_DB=vulntrack-v2.db` and `PORT=5001` values; the API listens on `http://127.0.0.1:5001`. If you prefer your existing global Python, install the packages into that interpreter instead of using a virtual environment.

## API

- `GET /api/health` — runs `semgrep --version` and `SELECT 1` against SQLite
- `POST /api/auth/login` — JSON `username` and `password`; returns a one-hour HS256 JWT
- `GET /api/auth/me` — current account from a Bearer token
- `POST /api/scans` — multipart form with `files` (or one `file`, source or ZIP), optional `project_name`; runs the bundled local rules and saves the scan
- `GET /api/projects` — stored projects
- `GET /api/projects/<id>/scans` — scan history for one project
- `POST /api/projects/<id>/rescan` — re-scan the latest stored source snapshot (Admin)
- `POST /api/projects/<id>/members` — Admin grants a Developer project access using `{"username":"developer"}`
- `GET /api/projects/<id>/members` and `DELETE /api/projects/<id>/members/<user_id>` — Admin manages project access
- `GET /api/vulnerabilities` — stored findings; optional `?project_id=...`
- `PATCH /api/vulnerabilities/<id>` — JSON body with `status`, `assignee`, and/or `remediation_notes`
- `GET /api/audit-logs` — latest stored audit events

Scan statuses are `completed`, `completed_with_errors`, and `failed`. A failed scanner run returns HTTP 502 with the error text and is not presented as a zero-finding scan. Invalid uploads return HTTP 400. Completed scans return HTTP 201; valid results with Semgrep-reported errors return HTTP 207 and preserve both findings and error details. Severity maps Semgrep `ERROR/WARNING/INFO` to VulnTrack `High/Medium/Low`.

All API routes except health and login require `Authorization: Bearer <token>`. Admins see all projects and findings, start scans, assign findings to Developer accounts, manage project access, and read audit logs. Developers see findings assigned to them or in projects they are authorized for, and can update finding status and remediation notes. The backend checks these permissions on every request. Status values are `Open`, `In Progress`, `Fixed`, and `Accepted Risk`.

Demo users are created only when `seed_users.py` is run manually; the application never seeds accounts on startup. It reads usernames/passwords from the environment, stores Werkzeug password hashes, and refuses to run the seed command unless `VULNTRACK_ENV=development`. `VULNTRACK_JWT_SECRET` must be set before login. Passwords and tokens are not written to audit logs.

Optional AI suggestions support OpenRouter with `OPENROUTER_API_KEY`; `VULNTRACK_AI_MODEL` defaults to `openrouter/free`. If the OpenRouter key is unset, legacy direct OpenAI support uses `OPENAI_API_KEY` and defaults to `gpt-6-astra`. Without either key, `/api/ai/status` reports `configured: false` and the rest of the API works normally. Generation returns structured review data and never changes source until a user explicitly applies it. Apply changes only the stored source snapshot and triggers a verification scan. AI requests are rate limited per user and code-size capped. Check provider/model data handling terms before sending sensitive code.

Source archives are retained under `backend/data/snapshots` (configurable with `VULNTRACK_SOURCE_ROOT`) so Apply and Re-scan operate on a known copy. Protect this folder and the SQLite file as source code data.

## Tests

```powershell
python -m pytest tests -v
```

Vite default origin `http://localhost:5173` is allowed.
