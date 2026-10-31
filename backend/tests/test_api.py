"""API tests use isolated temporary SQLite files and real bundled Semgrep rules."""
import atexit
import io
import json
import os
import sqlite3
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from pathlib import Path
import zipfile

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

_import_db_dir = Path(tempfile.mkdtemp(prefix="vulntrack-test-import-"))
os.environ["VULNTRACK_DB"] = str(_import_db_dir / "import.db")
atexit.register(shutil.rmtree, _import_db_dir, ignore_errors=True)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(api, "SOURCE_SNAPSHOT_ROOT", tmp_path / "snapshots")
    monkeypatch.setenv("VULNTRACK_JWT_SECRET", "unit-test-secret-not-for-production")
    api.init_db()
    with api.connect_db() as db:
        db.executemany(
            "INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)",
            [
                ("admin-test", "admin", generate_password_hash("admin-pass"), "Admin"),
                ("developer-test", "developer", generate_password_hash("developer-pass"), "Developer"),
            ],
        )
    return api.app.test_client()


def login(client, username="admin", password="admin-pass"):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.json
    return {"Authorization": f"Bearer {response.json['token']}"}


def scan_fixture(client, filename, project_name="Fixture Project"):
    data = {
        "project_name": project_name,
        "files": (io.BytesIO((FIXTURES / filename).read_bytes()), filename),
    }
    return client.post("/api/scans", data=data, content_type="multipart/form-data", headers=login(client))


def test_bundled_rules_find_expected_patterns():
    result, status, errors = api.run_semgrep(FIXTURES / "vulnerable.py")
    expected = {
        "vulntrack.python.eval", "vulntrack.python.exec",
        "vulntrack.python.subprocess-shell-true", "vulntrack.python.pickle-loads",
        "vulntrack.python.yaml-load", "vulntrack.python.sql-fstring",
    }
    assert status == "completed"
    assert errors is None
    assert {finding["check_id"].replace("backend.rules.", "") for finding in result["results"]} == expected
    assert "backend\\tests\\fixtures\\vulnerable.py" in result["paths"]["scanned"] or "vulnerable.py" in result["paths"]["scanned"][0]


def test_extended_python_and_javascript_detection_through_scan_api(client):
    python_source = """from flask import request
import hashlib
import os
from pathlib import Path

def search(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    path = request.args.get("path")
    return Path(path).read_text()

def run_command():
    os.system(request.args["cmd"])

def digest(value):
    return hashlib.md5(value).hexdigest()

api_key = "notarealsecret0123456789abcdefghijklmnop"
"""
    javascript_source = """const child_process = require('child_process');
function render(req, element) {
  const value = req.query.term;
  element.innerHTML = value;
  child_process.exec(value);
}
"""
    response = client.post(
        "/api/scans",
        data={
            "project_name": "Extended Detection Project",
            "files": [
                (io.BytesIO(python_source.encode()), "app.py"),
                (io.BytesIO(javascript_source.encode()), "client.js"),
            ],
        },
        content_type="multipart/form-data",
        headers=login(client),
    )
    assert response.status_code == 201, response.json
    findings = response.json["findings"]
    rule_ids = {item["rule_id"] for item in findings}
    categories = {item["category"] for item in findings}
    assert any(rule.endswith("python.sql-taint") for rule in rule_ids)
    assert any(rule.endswith("python.path-traversal-request") for rule in rule_ids)
    assert any(rule.endswith("python.weak-hash") for rule in rule_ids)
    assert any(rule.endswith("generic.hardcoded-secret") for rule in rule_ids)
    assert any(rule.endswith("javascript.tainted-dom-xss") for rule in rule_ids)
    assert any(rule.endswith("javascript.tainted-command") for rule in rule_ids)
    assert {"sql-injection", "path-traversal", "weak-cryptography", "hardcoded-secret", "cross-site-scripting", "command-injection"} <= categories


def test_clean_file_completes_with_zero_findings(client):
    response = scan_fixture(client, "clean.py")
    assert response.status_code == 201
    assert response.json["scan"]["status"] == "completed"
    assert response.json["summary"]["total"] == 0
    assert response.json["findings"] == []


def test_scanner_failure_is_non_2xx_and_saved(client, monkeypatch):
    def fail(_root):
        raise api.SemgrepFailure("Semgrep test failure")

    monkeypatch.setattr(api, "run_semgrep", fail)
    response = scan_fixture(client, "clean.py", "Failure Project")
    assert response.status_code == 502
    assert response.json["scanStatus"] == "failed"
    with api.connect_db() as db:
        scan = db.execute("SELECT status,error FROM scans").fetchone()
        assert tuple(scan) == ("failed", "Semgrep test failure")


def test_repeated_scans_reuse_project_and_add_history(client):
    first = scan_fixture(client, "clean.py", "Repeated Project")
    second = scan_fixture(client, "clean.py", "  repeated   project ")
    assert first.status_code == second.status_code == 201
    assert first.json["project"]["id"] == second.json["project"]["id"]
    project_id = first.json["project"]["id"]
    headers = login(client)
    assert len(client.get("/api/projects", headers=headers).json["projects"]) == 1
    scans = client.get(f"/api/projects/{project_id}/scans", headers=headers).json["scans"]
    assert len(scans) == 2
    assert all(scan["status"] == "completed" for scan in scans)


def test_invalid_upload_is_rejected(client):
    response = client.post(
        "/api/scans",
        data={"file": (io.BytesIO(b"not source"), "notes.txt")},
        content_type="multipart/form-data",
        headers=login(client),
    )
    assert response.status_code == 400
    assert "Unsupported source extension" in response.json["error"]


def test_zip_path_traversal_is_rejected(client):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../escape.py", "print('not executed')")
    response = client.post(
        "/api/scans",
        data={"file": (io.BytesIO(archive.getvalue()), "source.zip")},
        content_type="multipart/form-data",
        headers=login(client),
    )
    assert response.status_code == 400
    assert "unsafe path" in response.json["error"]


def test_findings_survive_database_reinitialization(client):
    response = scan_fixture(client, "vulnerable.py", "Persistence Project")
    assert response.status_code == 201
    assert response.json["summary"]["total"] == 6
    by_rule = {item["rule_id"]: item for item in response.json["findings"]}
    eval_finding = next(item for rule, item in by_rule.items() if rule.endswith("vulntrack.python.eval"))
    yaml_finding = next(item for rule, item in by_rule.items() if rule.endswith("vulntrack.python.yaml-load"))
    assert eval_finding["severity"] == "High"
    assert yaml_finding["severity"] == "Medium"
    assert eval_finding["recommendation"] != "python"
    child_code = (
        "import sys; from pathlib import Path; "
        f"sys.path.insert(0, {str(api.BASE_DIR)!r}); import app; "
        "db=app.connect_db(); print(db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]); db.close()"
    )
    restarted = subprocess.run(
        [sys.executable, "-c", child_code], cwd=api.BASE_DIR.parent,
        env={**os.environ, "VULNTRACK_DB": str(api.DB_PATH)},
        capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
    )
    assert restarted.returncode == 0, restarted.stderr
    assert restarted.stdout.strip() == "6"
    stored = client.get("/api/vulnerabilities", headers=login(client)).json["vulnerabilities"]
    assert len(stored) == 6
    assert all(item["scanId"] == response.json["scan"]["id"] for item in stored)


def test_health_checks_database_and_semgrep(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json["database"] == "available"
    assert response.json["scanner"] == "available"
    assert response.json["scanner_version"]


def test_authentication_and_role_guards(client):
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/projects", headers={"Authorization": "Bearer invalid"}).status_code == 401
    developer_headers = login(client, "developer", "developer-pass")
    assert client.get("/api/audit-logs", headers=developer_headers).status_code == 403
    assert client.get("/api/users", headers=developer_headers).status_code == 403
    assert client.post("/api/scans", headers=developer_headers).status_code == 403
    admin_headers = login(client)
    assert client.get("/api/projects", headers=admin_headers).status_code == 200
    assert client.get("/api/audit-logs", headers=admin_headers).status_code == 200
    assert client.get("/api/users", headers=admin_headers).status_code == 200


def test_seed_script_hashes_environment_passwords_and_fails_closed(tmp_path):
    database = tmp_path / "seed.db"
    environment = {
        **os.environ,
        "VULNTRACK_ENV": "development",
        "VULNTRACK_DB": str(database),
        "VULNTRACK_ADMIN_USERNAME": "",
        "VULNTRACK_ADMIN_PASSWORD": "private-admin-password",
        "VULNTRACK_DEVELOPER_USERNAME": "",
        "VULNTRACK_DEVELOPER_PASSWORD": "private-developer-password",
    }
    seeded = subprocess.run(
        [sys.executable, "seed_users.py"], cwd=api.BASE_DIR,
        env=environment, capture_output=True, text=True, timeout=20, check=False,
    )
    assert seeded.returncode == 0, seeded.stderr
    assert "private-admin-password" not in seeded.stdout + seeded.stderr
    with sqlite3.connect(database) as db:
        rows = db.execute("SELECT username,password_hash,role FROM users ORDER BY username").fetchall()
    assert [row[0] for row in rows] == ["admin", "developer"]
    assert check_password_hash(rows[0][1], "private-admin-password")
    assert check_password_hash(rows[1][1], "private-developer-password")

    production_db = tmp_path / "production-seed.db"
    blocked = subprocess.run(
        [sys.executable, "seed_users.py"], cwd=api.BASE_DIR,
        env={**environment, "VULNTRACK_ENV": "production", "VULNTRACK_DB": str(production_db)},
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert blocked.returncode != 0
    assert not production_db.exists()


def test_optional_ai_reports_not_configured_without_a_key(client, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    headers = login(client)
    status = client.get("/api/ai/status", headers=headers)
    assert status.status_code == 200
    assert status.json["configured"] is False
    response = client.post(
        "/api/ai/remediation", json={"vulnerabilityId": "not-used-without-key"}, headers=headers
    )
    assert response.status_code == 503
    assert response.json["error"] == "AI not configured."


def test_policy_checks_flag_missing_auth_and_insecure_cors(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "from flask import Flask\nfrom flask_cors import CORS\napp=Flask(__name__)\n"
        "CORS(app, origins='*')\n@app.get('/api/private')\ndef private(): return 'ok'\n",
        encoding="utf-8",
    )
    findings, errors = api.run_policy_checks(tmp_path, "p", "s")
    assert errors == []
    rules = {finding["rule_id"] for finding in findings}
    assert "vulntrack.python.missing-route-auth" in rules
    assert "vulntrack.python.cors-wildcard" in rules
    assert "vulntrack.python.security-headers" in rules
    assert all(finding["cwe"] and finding["owasp"] for finding in findings)


def test_npm_audit_output_becomes_dependency_finding(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    (root / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (root / "package-lock.json").write_text('{"name":"demo","lockfileVersion":3}', encoding="utf-8")
    report = {"vulnerabilities": {"lodash": {
        "severity": "high", "range": "<4.17.21",
        "via": [{"title": "Prototype pollution", "url": "https://example.invalid/advisory"}],
    }}}
    monkeypatch.setattr(api.shutil, "which", lambda name: "npm" if name == "npm" else None)
    monkeypatch.setattr(api.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=json.dumps(report), stderr=""))
    findings, errors = api.run_dependency_audits(root, "p", "s")
    assert errors == []
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["file"] == "package-lock.json"
    assert findings[0]["detected_by"] == "npm audit/pip-audit"


def test_openrouter_remediation_uses_chat_completions(client, monkeypatch):
    scan = scan_fixture(client, "vulnerable.py", "OpenRouter Project")
    finding_id = scan.json["findings"][0]["id"]
    headers = login(client)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    monkeypatch.setenv("VULNTRACK_AI_MODEL", "openrouter/free")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            finding = scan.json["findings"][0]
            fixed = finding["code"].replace("eval(source)", "str(source)")
            payload = {"choices": [{"message": {"content": json.dumps({
                "explanation": "Avoid dynamic code execution.",
                "vulnerable_code": finding["code"],
                "fixed_code": fixed,
                "why_it_works": "It treats the input as text rather than code.",
            })}}]}
            return json.dumps(payload).encode("utf-8")

    def fake_urlopen(outbound, timeout):
        captured["url"] = outbound.full_url
        captured["headers"] = dict(outbound.header_items())
        captured["body"] = json.loads(outbound.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(api.urllib.request, "urlopen", fake_urlopen)
    response = client.post(
        "/api/ai/remediation", json={"vulnerabilityId": finding_id}, headers=headers
    )
    assert response.status_code == 200, response.json
    assert response.json["explanation"] == "Avoid dynamic code execution."
    assert response.json["fixed_code"] == scan.json["findings"][0]["code"].replace("eval(source)", "str(source)")
    assert response.json["provider"] == "OpenRouter"
    assert response.json["model"] == "openrouter/free"
    assert response.json["applied"] is False
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer test-openrouter-key"
    assert captured["body"]["model"] == "openrouter/free"
    assert "messages" in captured["body"] and "input" not in captured["body"]
    assert scan.json["findings"][0]["code"].strip() in captured["body"]["messages"][1]["content"]
    assert response.json["suggestionId"]
    assert response.json["applied"] is False
    db = api.connect_db()
    try:
        assert db.execute("SELECT status FROM ai_remediations").fetchone()[0] == "pending"
    finally:
        db.close()


def test_batch_ai_returns_reviewable_candidates(client, monkeypatch):
    scan = scan_fixture(client, "vulnerable.py", "Batch AI Project")
    selected = scan.json["findings"][:2]
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("VULNTRACK_AI_MODEL", "openrouter/free")
    candidates = [{
        "vulnerability_id": item["id"],
        "explanation": "Replace unsafe execution with validated handling.",
        "fixed_code": item["code"].replace("eval(source)", "str(source)").replace("exec(source)", "source"),
        "why_it_works": "The replacement does not execute attacker-controlled text.",
    } for item in selected]

    class FakeResponse:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return json.dumps({"choices": [{"message": {"content": json.dumps({"remediations": candidates})}}]}).encode()

    monkeypatch.setattr(api.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse())
    response = client.post("/api/ai/remediation/batch", json={"vulnerabilityIds": [item["id"] for item in selected]}, headers=login(client))
    assert response.status_code == 200, response.json
    assert len(response.json["remediations"]) == 2
    assert all(item["suggestionId"] and item["vulnerable_code"] for item in response.json["remediations"])
    assert response.json["applied"] is False


def test_reviewed_ai_fix_updates_snapshot_and_rescans(client, monkeypatch):
    scan = scan_fixture(client, "vulnerable.py", "Apply AI Project")
    finding = next(item for item in scan.json["findings"] if item["rule_id"].endswith("python.eval"))
    original = finding["code"].strip()
    fixed = original.replace("eval(source)", "str(source)")
    suggestion_id = "reviewed-suggestion"
    with api.connect_db() as db:
        db.execute(
            """INSERT INTO ai_remediations
               (id,vulnerability_id,user_id,status,explanation,vulnerable_code,fixed_code,why_it_works,created_at,updated_at)
               VALUES(?,?,?,'pending',?,?,?,?,?,?)""",
            (suggestion_id, finding["id"], "admin-test", "Use a safe conversion.", original, fixed,
             "This avoids dynamic code execution.", "now", "now"),
        )
    monkeypatch.setattr(api, "run_semgrep", lambda _root: ({"results": [], "errors": []}, "completed", None))
    monkeypatch.setattr(api, "run_dependency_audits", lambda *_args: ([], []))
    monkeypatch.setattr(api, "run_policy_checks", lambda *_args: ([], []))
    response = client.post(
        f"/api/ai/remediation/{suggestion_id}/decision", json={"decision": "apply"}, headers=login(client)
    )
    assert response.status_code == 200, response.json
    assert response.json["applied"] is True
    assert response.json["verification"]["remainingMatchingFinding"] is False
    assert response.json["verification"]["scan"]["status"] == "completed"


def test_assignment_project_access_and_developer_updates(client):
    scan = scan_fixture(client, "vulnerable.py", "RBAC Project")
    project_id = scan.json["project"]["id"]
    finding_id = scan.json["findings"][0]["id"]
    admin_headers = login(client)

    assigned = client.patch(
        f"/api/vulnerabilities/{finding_id}", json={"assignee": "developer"}, headers=admin_headers
    )
    assert assigned.status_code == 200
    assert assigned.json["vulnerability"]["assigneeId"] == "developer-test"

    developer_headers = login(client, "developer", "developer-pass")
    assigned_findings = client.get("/api/vulnerabilities", headers=developer_headers)
    assert len(assigned_findings.json["vulnerabilities"]) == 1
    updated = client.patch(
        f"/api/vulnerabilities/{finding_id}",
        json={"status": "In Progress", "remediation_notes": "Reviewed the source."},
        headers=developer_headers,
    )
    assert updated.status_code == 200
    assert updated.json["vulnerability"]["status"] == "In Progress"
    assert updated.json["vulnerability"]["remediation_notes"] == "Reviewed the source."
    denied_assignment = client.patch(
        f"/api/vulnerabilities/{finding_id}", json={"assignee": "admin"}, headers=developer_headers
    )
    assert denied_assignment.status_code == 403

    access = client.post(
        f"/api/projects/{project_id}/members", json={"username": "developer"}, headers=admin_headers
    )
    assert access.status_code == 201
    project_findings = client.get("/api/vulnerabilities", headers=developer_headers)
    assert len(project_findings.json["vulnerabilities"]) == 6
    assert len(client.get("/api/projects", headers=developer_headers).json["projects"]) == 1

    audit_logs = client.get("/api/audit-logs", headers=admin_headers).json["auditLogs"]
    actions = {item["action"] for item in audit_logs}
    assert {"Login", "Project Created", "Scan Started", "Scan Finished", "Vulnerability Assigned", "Status Changed"} <= actions
    assert all(item["actor_id"] for item in audit_logs if item["action"] in {"Login", "Scan Started", "Scan Finished", "Vulnerability Assigned", "Status Changed"})


def test_unknown_vulnerability_returns_404(client):
    response = client.patch("/api/vulnerabilities/missing", json={"status": "Fixed"}, headers=login(client))
    assert response.status_code == 404
