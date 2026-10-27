# VulnTrack v2 · AI remediation

This is an isolated upgrade of the existing VulnTrack React/Vite + Flask + SQLite application. It preserves login/RBAC, scanning, finding tracking, projects, audit activity, and the existing Semgrep workflow. Uploaded source is stored as a private server-side scan snapshot so an explicitly approved AI fix can be applied to that copy and re-scanned. VulnTrack never executes uploaded code.

## Run v2 on Windows

Use Python 3.11+ and Node.js 20.19+ (or 22.12+). Keep the backend and frontend in separate terminals.

### Backend

```powershell
cd D:\SOAProject\vulntrack-v2-ai-remediation\backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

In `backend\.env`, set a private `VULNTRACK_JWT_SECRET`, admin/developer passwords, and optionally `OPENROUTER_API_KEY`. Keep `VULNTRACK_DB=vulntrack-v2.db` and `PORT=5001`. Then run:

```powershell
python seed_users.py
python app.py
```

The v2 API listens on `http://127.0.0.1:5001`. The backend loads `backend\.env` automatically. Seeding is only allowed when `VULNTRACK_ENV=development`.

### Frontend

```powershell
cd D:\SOAProject\vulntrack-v2-ai-remediation
npm ci
Copy-Item .env.example .env
npm run dev
```

Vite serves v2 on `http://localhost:5174`; `.env` sets the API base to port 5001. Sign in with the account values from `backend\.env`.

## Keep the original running independently

The original folder remains at `D:\SOAProject\vulntrack`; its backend defaults to port 5000 and database `backend\vulntrack.db`, and its Vite server defaults to port 5173. Start its backend and frontend from that folder using its original setup, in separate terminals. V2 uses a separate database file (`backend\vulntrack-v2.db`), `.env` files, Python virtual environment, Node dependencies, ports, and browser token key.

## Scan and remediate

1. Sign in as Admin and upload individual source files or a ZIP.
2. VulnTrack runs bundled Semgrep rules and checks recognized dependency manifests. Findings retain severity, file/line, CWE/OWASP mapping when available, category, status, and scan history.
3. Filter/sort findings, grant project access, assign developers, and update statuses as before.
4. Click **Fix with AI** for one finding or **Fix all with AI** in the remediation center. Batch generation handles up to 10 findings and 12,000 source characters per request.
5. Review the explanation, vulnerable/fixed code diff, and why the change should work. Each candidate remains pending until explicitly applied or rejected.
6. Apply changes only to VulnTrack's stored scan copy. VulnTrack automatically re-scans that copy and reports whether the same rule/file still has a matching finding. Your original local files are not changed.

## Detection coverage and data handling

The local rules now include targeted Python and JavaScript/TypeScript checks for SQL injection, XSS, command execution, path traversal, weak hashes, and likely hardcoded credentials. Python policy checks look for unguarded API routes and risky CORS/security-header configuration. `npm audit` runs for `package.json` + `package-lock.json`; `pip-audit` runs for `requirements*.txt`. Dependency checks need network access and send dependency names/versions to the configured package advisory services; they do not upload application source. A manifest without a matching lockfile or an unavailable audit service is reported as a scan warning/error.

These are heuristic static checks, not a full security audit. Missing input validation is not generally provable from local patterns; taint rules catch selected input-to-sink flows. Bundled Semgrep rules cover Python and JavaScript/TypeScript only; other accepted file types may have no applicable rules. Dependency audit results depend on registry/advisory availability.

AI remediation is optional. `OPENROUTER_API_KEY` is preferred; `VULNTRACK_AI_MODEL` defaults to `openrouter/free`. Direct OpenAI remains supported if the OpenRouter key is unset. The backend enforces a per-user request limit, provider timeouts, code-size caps, and structured output checks. AI receives the selected snippet plus its finding title/rule/description only after the user requests a suggestion. The model/provider's own privacy and retention terms still apply. The server-side source snapshots contain uploaded project code; protect `backend\data\snapshots` and the SQLite database.

## Checks

```powershell
cd D:\SOAProject\vulntrack-v2-ai-remediation
npm run lint
npm test
npm run build
cd backend
python -m pytest tests -v
```

## Docs

- [API reference](API.md)
- [Backend setup and data model](backend/README.md)
- [Changes from the original](CHANGELOG.md)

V2 remains a local demonstration: it uses SQLite, browser local storage for JWTs, process-local AI rate limiting, and the Flask development server. It does not provision production users or support multiple production workers.
