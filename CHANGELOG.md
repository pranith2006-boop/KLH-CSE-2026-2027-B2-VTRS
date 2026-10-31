# Changelog

## v2 · AI remediation and scanner extension

- Created an isolated sibling copy while preserving the existing React/Vite + Flask/SQLite structure and features.
- Separated the v2 Vite/API ports (5174/5001), SQLite database (`backend/vulntrack-v2.db`), `.env` configuration, and browser token key from the original instance.
- Added dotenv-backed backend configuration, safe `.env.example` files, `.gitignore` coverage, and setup instructions. The copied OpenRouter key value was blanked; no key is included in the v2 examples.
- Added targeted Semgrep checks for Python and JavaScript/TypeScript SQL injection, XSS, command execution, path traversal, weak hashing, and likely hardcoded secrets.
- Added Python AST policy checks for Flask API routes without recognized auth decorators, wildcard CORS, and missing explicit security response headers.
- Added optional `npm audit` and `pip-audit` processing for recognized lockfiles/requirements files, including vulnerability findings and scanner error reporting.
- Preserved uploaded source trees in scan snapshots; added Admin re-scan for the latest snapshot and stored-copy project modification during explicit AI apply.
- Added CWE/OWASP fields to findings and filters/sorting by severity/status/title/file, plus search across category and classification.
- Completed project history and Developer project-access grant/revoke screens using authenticated API routes.
- Upgraded AI remediation to structured explanation, vulnerable code, fixed code, and rationale; added side-by-side line diff, Apply/Reject review, per-user rate limits, timeout and output-size caps, provider 429 handling, and automatic verification re-scan.
- Added batch remediation suggestions (maximum 10 findings and 12,000 total snippet characters per request) with separate review decisions for each candidate.
- Added ESLint, Vitest, React Testing Library, frontend tests, and backend tests for policy/dependency scans and remediation decisions.
- Updated README, API docs, environment examples, and this changelog.
- Expanded Python and JavaScript taint sources/sinks for common request property access, `Path` file reads/writes, `send_file`, DOM HTML sinks, and Node `execSync`; added an authenticated end-to-end regression scan for SQL injection, path traversal, weak hashing, hardcoded credentials, XSS, and command injection.

## Known limitations

- Semgrep and policy checks are targeted heuristics; they do not prove absence of vulnerabilities or generally infer missing input validation. Python and JavaScript/TypeScript have bundled custom rules; accepted languages without rules can scan with zero language findings.
- Dependency checks require network access and recognized manifests; npm audit needs a package lock, and Python checks currently target `requirements*.txt`.
- AI apply modifies only the server-side snapshot, not the original local files. An authenticated source archive export route was not added, so users must make the reviewed change in their local project themselves. Each applied candidate starts its own verification scan.
- AI provider behavior, OpenRouter free-model availability, and provider privacy/retention vary. No live provider-key request is part of automated tests.
- Rate limiting is process-local, not shared across multiple workers. The included Flask server and SQLite setup are for local demonstration.
