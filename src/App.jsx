import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./style.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:5001";
const TOKEN_STORAGE_KEY = "vulntrack_v2_token";

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_STORAGE_KEY));
  const [user, setUser] = useState(null);
  const role = user?.role || "Developer";
  const [authLoading, setAuthLoading] = useState(Boolean(token));
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataFailed, setDataFailed] = useState(false);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [projects, setProjects] = useState([]);
  const [developers, setDevelopers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [projectHistory, setProjectHistory] = useState(null);
  const [projectHistoryLoading, setProjectHistoryLoading] = useState(false);
  const [projectHistoryError, setProjectHistoryError] = useState("");

  const [selectedVulnerability, setSelectedVulnerability] =
    useState(null);

  const [showUpload, setShowUpload] = useState(false);
  const [showDetails, setShowDetails] = useState(false);

  const [showAI, setShowAI] = useState(false);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [findingSort, setFindingSort] = useState("severity");

  const [scanState, setScanState] = useState("idle");

  const [uploadedFiles, setUploadedFiles] = useState([]);

  const [scanResult, setScanResult] = useState(null);
  const [apiError, setApiError] = useState("");

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken(null);
    setUser(null);
    setSelectedVulnerability(null);
    setApiError("");
    setDataLoading(false);
    setVulnerabilities([]);
    setProjects([]);
    setAuditLogs([]);
    setDevelopers([]);
    setActivePage("dashboard");
  }, []);

  const handleLogin = async (credentials) => {
    setLoginLoading(true);
    setLoginError("");
    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Sign-in failed (${response.status}).`);
      localStorage.setItem(TOKEN_STORAGE_KEY, result.token);
      setUser(result.user);
      setToken(result.token);
      setAuthLoading(false);
      setActivePage("dashboard");
    } catch (error) {
      setLoginError(error.message || "Unable to reach the VulnTrack API.");
    } finally {
      setLoginLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    const verifyToken = async () => {
      if (!token) {
        setUser(null);
        setAuthLoading(false);
        return;
      }
      try {
        const response = await fetch(`${API_BASE}/api/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || "Session expired. Please sign in again.");
        if (cancelled) return;
        setUser(result.user);
        setLoginError("");
      } catch (error) {
        if (cancelled) return;
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        setToken(null);
        setUser(null);
        setLoginError(error.message || "Unable to validate your session.");
      } finally {
        if (!cancelled) setAuthLoading(false);
      }
    };
    verifyToken();
    return () => { cancelled = true; };
  }, [token]);

  const apiRequest = useCallback(async (path, options = {}, authToken = token) => {
    const headers = { ...(options.headers || {}) };
    if (authToken) headers.Authorization = `Bearer ${authToken}`;
    if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
    const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(result.error || `Request failed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return result;
  }, [token]);

  const loadData = useCallback(async (authToken = token, currentUser = user, quiet = false) => {
    if (!authToken || !currentUser) return;
    if (!quiet) setDataLoading(true);
    try {
      const [vulnData, projectData, auditData, userData] = await Promise.all([
        apiRequest("/api/vulnerabilities", {}, authToken),
        apiRequest("/api/projects", {}, authToken),
        currentUser.role === "Admin" ? apiRequest("/api/audit-logs", {}, authToken) : Promise.resolve({ auditLogs: [] }),
        currentUser.role === "Admin" ? apiRequest("/api/users", {}, authToken) : Promise.resolve({ users: [] }),
      ]);
      setVulnerabilities(vulnData.vulnerabilities || []);
      setProjects(projectData.projects || []);
      setAuditLogs(auditData.auditLogs || []);
      setDevelopers((userData.users || []).filter((item) => item.role === "Developer"));
      setDataFailed(false);
      if (!quiet) setApiError("");
    } catch (error) {
      setDataFailed(true);
      setApiError(error.message || "Unable to load data from the backend.");
      if (error.status === 401) logout();
    } finally {
      if (!quiet) setDataLoading(false);
    }
  }, [apiRequest, logout, token, user]);

  useEffect(() => {
    if (token && user) {
      const timer = window.setTimeout(() => { void loadData(token, user); }, 0);
      return () => window.clearTimeout(timer);
    }
  }, [token, user, loadData]);

  const notifications = auditLogs.slice(0, 20).map((log) => ({
    id: log.id,
    text: log.details,
    type: log.action,
    time: log.created_at,
    unread: false,
  }));
  const unreadNotifications = 0;

  const filteredVulnerabilities = useMemo(() => {
    const query = search.toLowerCase();

    const filtered = vulnerabilities.filter((v) => {
      const matchesQuery = (
        v.id.toLowerCase().includes(query) ||
        v.title.toLowerCase().includes(query) ||
        v.file.toLowerCase().includes(query) ||
        v.severity.toLowerCase().includes(query) ||
        v.status.toLowerCase().includes(query) ||
        String(v.assignee || "Unassigned").toLowerCase().includes(query) ||
        String(v.category || "").toLowerCase().includes(query) ||
        String(v.cwe || "").toLowerCase().includes(query) ||
        String(v.owasp || "").toLowerCase().includes(query)
      );
      return matchesQuery && (severityFilter === "All" || v.severity === severityFilter)
        && (statusFilter === "All" || v.status === statusFilter);
    });
    const ranks = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    return filtered.sort((a, b) => {
      if (findingSort === "severity") return (ranks[b.severity] || 0) - (ranks[a.severity] || 0);
      if (findingSort === "file") return a.file.localeCompare(b.file);
      if (findingSort === "status") return a.status.localeCompare(b.status);
      return a.title.localeCompare(b.title);
    });
  }, [vulnerabilities, search, severityFilter, statusFilter, findingSort]);

  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(
      (v) => v.severity === "Critical"
    ).length,
    high: vulnerabilities.filter(
      (v) => v.severity === "High"
    ).length,
    medium: vulnerabilities.filter(
      (v) => v.severity === "Medium"
    ).length,
    resolved: vulnerabilities.filter(
      (v) =>
        v.status === "Fixed" ||
        v.status === "Accepted Risk"
    ).length,
  };

  const handleUpload = (event) => {
    const files = Array.from(event.target.files);

    if (!files.length) return;

    setUploadedFiles(files);

    setScanResult({
      projectName: files[0].name.replace(/\.[^/.]+$/, ""),
      fileCount: files.length,
      totalSize: files.reduce(
        (sum, file) => sum + file.size,
        0
      ),
    });
  };

  const startScan = async () => {
    if (!uploadedFiles.length) {
      setApiError("Choose source files before starting a scan.");
      return;
    }

    setScanState("scanning");
    setShowUpload(false);
    setApiError("");
    try {
      const formData = new FormData();
      uploadedFiles.forEach((file) => formData.append("files", file, file.name));
      formData.append("project_name", uploadedFiles[0].name.replace(/\.[^/.]+$/, ""));
      const result = await apiRequest("/api/scans", {
        method: "POST",
        body: formData,
      });
      setScanResult({
        projectName: result.project.name,
        fileCount: result.project.files,
        totalSize: uploadedFiles.reduce((sum, file) => sum + file.size, 0),
        findingCount: result.summary.total,
      });
      setScanState(result.scan.status);
      setApiError(result.scan.status === "completed_with_errors"
        ? `Scan completed with scanner errors: ${result.scan.error}`
        : "");
      await loadData(token, user, true);
      setActivePage("vulnerabilities");
    } catch (error) {
      setScanState("failed");
      setApiError(`Scan failed: ${error.message || "Unable to reach the backend."}`);
    }
  };

  const updateFinding = async (id, changes) => {
    setApiError("");
    try {
      const result = await apiRequest(`/api/vulnerabilities/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify(changes),
      });
      await loadData(token, user, true);
      setSelectedVulnerability(result.vulnerability);
    } catch (error) {
      setApiError(error.message || "Unable to save the finding.");
    }
  };

  const assignDeveloper = (id, developer) => updateFinding(id, { assignee: developer });
  const updateStatus = (id, status) => updateFinding(id, { status });
  const updateNotes = (id, remediation_notes) => updateFinding(id, { remediation_notes });

  const openVulnerability = (vulnerability) => {
    setSelectedVulnerability(vulnerability);
    setShowDetails(true);
  };

  const openAI = (vulnerability) => {
    setSelectedVulnerability(vulnerability);
    setShowAI(true);
  };

  const openProjectHistory = async (project) => {
    setProjectHistory({ project, scans: [] });
    setProjectHistoryError("");
    setProjectHistoryLoading(true);
    try {
      const result = await apiRequest(`/api/projects/${encodeURIComponent(project.id)}/scans`);
      setProjectHistory({ project, scans: result.scans || [] });
    } catch (error) {
      setProjectHistoryError(error.message || "Unable to load scan history.");
    } finally {
      setProjectHistoryLoading(false);
    }
  };

  const renderPage = () => {
    switch (activePage) {
      case "dashboard":
        return (
          <Dashboard
            stats={stats}
            vulnerabilities={vulnerabilities}
            projects={projects}
            onHistory={openProjectHistory}
            onUpload={role === "Admin" ? () => setShowUpload(true) : null}
            onOpen={openVulnerability}
          />
        );

      case "scan":
        return (
          <ScanPage
            projects={projects}
            onHistory={openProjectHistory}
            onUpload={() => setShowUpload(true)}
            scanState={scanState}
            apiError={apiError}
          />
        );

      case "vulnerabilities":
        return (
          <VulnerabilityPage
            vulnerabilities={filteredVulnerabilities}
            search={search}
            setSearch={setSearch}
            severityFilter={severityFilter}
            setSeverityFilter={setSeverityFilter}
            statusFilter={statusFilter}
            setStatusFilter={setStatusFilter}
            findingSort={findingSort}
            setFindingSort={setFindingSort}
            onOpen={openVulnerability}
            onAI={openAI}
            assignDeveloper={assignDeveloper}
            developers={developers}
            canAssign={role === "Admin"}
          />
        );

      case "remediation":
        return (
          <RemediationPage
            vulnerabilities={vulnerabilities}
            onAI={openAI}
            updateStatus={updateStatus}
            developers={developers}
            assignDeveloper={assignDeveloper}
            canAssign={role === "Admin"}
            apiRequest={apiRequest}
            onRefresh={() => loadData(token, user, true)}
          />
        );

      case "users":
        return (
          <UsersPage
            role={role}
            developers={developers}
            projects={projects}
            apiRequest={apiRequest}
          />
        );

      case "notifications":
        return (
          <NotificationPage
            notifications={notifications}
          />
        );

      case "audit":
        return <AuditPage logs={auditLogs} />;

      default:
        return null;
    }
  };

  if (authLoading) {
    return <div className="auth-loading">Checking your VulnTrack session…</div>;
  }
  if (!user) {
    return <LoginPage onSubmit={handleLogin} loading={loginLoading} error={loginError} />;
  }

  return (
    <div className="app">
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
        unreadNotifications={unreadNotifications}
        role={role}
      />

      <div className="main">
        <Topbar
          role={role}
          username={user.username}
          onLogout={logout}
          unreadNotifications={unreadNotifications}
          setActivePage={setActivePage}
        />

        <main className="content">
          {dataLoading && <div className="state-banner">Loading projects and findings…</div>}
          {dataFailed && <div className="state-banner error">Unable to load saved data: {apiError}</div>}
          {!dataLoading && scanState === "completed" && scanResult && (
            <div className="state-banner success">
              Scan completed: {scanResult.findingCount === 0
                ? "no findings were detected."
                : `${scanResult.findingCount} finding(s) were saved.`}
            </div>
          )}
          {apiError && !dataFailed && <div className="state-banner error">{apiError}</div>}
          {renderPage()}
        </main>
      </div>

      {showUpload && (
        <UploadModal
          uploadedFiles={uploadedFiles}
          scanResult={scanResult}
          onUpload={handleUpload}
          onStartScan={startScan}
          onClose={() => setShowUpload(false)}
          scanState={scanState}
        />
      )}

      {showDetails && selectedVulnerability && (
        <VulnerabilityModal
          vulnerability={selectedVulnerability}
          onClose={() => setShowDetails(false)}
          onAI={() => {
            setShowDetails(false);
            setShowAI(true);
          }}
          assignDeveloper={assignDeveloper}
          developers={developers}
          updateStatus={updateStatus}
          updateNotes={updateNotes}
          canAssign={role === "Admin"}
        />
      )}

      {showAI && selectedVulnerability && (
        <AIModal
          vulnerability={selectedVulnerability}
          onClose={() => setShowAI(false)}
          apiRequest={apiRequest}
          onRefresh={() => loadData(token, user, true)}
        />
      )}
      {projectHistory && <ProjectHistoryModal
        project={projectHistory.project}
        scans={projectHistory.scans}
        loading={projectHistoryLoading}
        error={projectHistoryError}
        onClose={() => setProjectHistory(null)}
      />}
    </div>
  );
}

function LoginPage({ onSubmit, loading, error }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (event) => {
    event.preventDefault();
    onSubmit({ username, password });
  };

  return (
    <main className="login-shell">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="brand-mark">V</div>
        <span className="eyebrow">VULNTRACK SECURITY PLATFORM</span>
        <h1>Sign in</h1>
        <p>Use your VulnTrack account to review projects and findings.</p>
        <label htmlFor="login-username">Username</label>
        <input id="login-username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required />
        <label htmlFor="login-password">Password</label>
        <input id="login-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
        {error && <div className="state-banner error">{error}</div>}
        <button className="primary-button large" type="submit" disabled={loading}>
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

/* =========================================================
   SIDEBAR
========================================================= */

function Sidebar({
  activePage,
  setActivePage,
  unreadNotifications,
  role,
}) {
  const allItems = [
    ["dashboard", "Dashboard", "▦"],
    ["scan", "Code Scanner", "⌁"],
    ["vulnerabilities", "Vulnerabilities", "⚠"],
    ["remediation", "AI Remediation", "✦"],
    ["users", "Users & RBAC", "♙"],
    ["notifications", "Notifications", "🔔"],
    ["audit", "Audit Logs", "◴"],
  ];
  const items = allItems.filter(([id]) =>
    role === "Admin" || !["scan", "users", "notifications", "audit"].includes(id)
  );

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">V</div>

        <div>
          <h1>VulnTrack</h1>
          <span>Security Platform</span>
        </div>
      </div>

      <div className="sidebar-label">
        MANAGEMENT
      </div>

      <nav>
        {items.map(([id, label, icon]) => (
          <button
            key={id}
            className={`nav-item ${
              activePage === id ? "active" : ""
            }`}
            onClick={() => setActivePage(id)}
          >
            <span className="nav-icon">{icon}</span>

            <span>{label}</span>

            {id === "notifications" &&
              unreadNotifications > 0 && (
                <span className="nav-count">
                  {unreadNotifications}
                </span>
              )}
          </button>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="system-online">
          <span></span>
          System Operational
        </div>

        <small>
          Automated vulnerability management
        </small>
      </div>
    </aside>
  );
}

/* =========================================================
   TOPBAR
========================================================= */

function Topbar({
  role,
  username,
  onLogout,
  unreadNotifications,
  setActivePage,
}) {
  return (
    <header className="topbar">
      <div>
        <div className="breadcrumb">
          VulnTrack / Security Management
        </div>

        <h2>Vulnerability Tracking & Remediation</h2>
      </div>

      <div className="top-actions">
        <button
          className="notification-button"
          onClick={() =>
            setActivePage("notifications")
          }
        >
          🔔

          {unreadNotifications > 0 && (
            <span>{unreadNotifications}</span>
          )}
        </button>

        <div className="profile">
          <div className="profile-avatar">
            {role.charAt(0)}
          </div>

          <div>
            <strong>{username}</strong>
            <span>{role}</span>
          </div>
        </div>
        <button className="secondary-button logout-button" onClick={onLogout}>Sign out</button>
      </div>
    </header>
  );
}

/* =========================================================
   DASHBOARD
========================================================= */

function Dashboard({
  stats,
  vulnerabilities,
  projects,
  onHistory,
  onUpload,
  onOpen,
}) {
  return (
    <>
      <div className="hero">
        <div>
          <span className="eyebrow">
            SECURITY OPERATIONS
          </span>

          <h1>
            Secure your code before attackers find
            the flaw.
          </h1>

          <p>
            Upload source code, automatically detect
            vulnerabilities, assign remediation tasks,
            and use AI to generate secure fixes.
          </p>
        </div>

        {onUpload && <button
          className="primary-button large"
          onClick={onUpload}
        >
          <span>＋</span>
          Scan New Code
        </button>}
      </div>

      <div className="stats-grid">
        <Stat
          label="Total Vulnerabilities"
          value={stats.total}
          icon="⚠"
        />

        <Stat
          label="Critical"
          value={stats.critical}
          icon="!"
          danger
        />

        <Stat
          label="High Severity"
          value={stats.high}
          icon="↑"
        />

        <Stat
          label="Fixed / Risk Accepted"
          value={stats.resolved}
          icon="✓"
          success
        />
      </div>

      <div className="dashboard-grid">
        <div className="panel">
          <PanelTitle
            title="Severity Overview"
            subtitle="Current security findings"
          />

          <SeverityChart
            vulnerabilities={vulnerabilities}
          />
        </div>

        <div className="panel">
          <PanelTitle
            title="Security Workflow"
            subtitle="Vulnerability lifecycle"
          />

          <Workflow />
        </div>
      </div>

      <div className="panel">
        <PanelTitle
          title="Recent Vulnerabilities"
          subtitle="Latest security findings from code scans"
        />

        <VulnerabilityTable
          vulnerabilities={vulnerabilities.slice(0, 5)}
          onOpen={onOpen}
        />
      </div>

      <div className="panel">
        <PanelTitle
          title="Recent Projects"
          subtitle="Source code repositories and scan status"
        />

        <ProjectTable projects={projects} onHistory={onHistory} />
      </div>
    </>
  );
}

function Stat({
  label,
  value,
  icon,
  danger,
  success,
}) {
  return (
    <div className="stat-card">
      <div
        className={`stat-icon ${
          danger ? "danger" : ""
        } ${success ? "success" : ""}`}
      >
        {icon}
      </div>

      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function SeverityChart({ vulnerabilities }) {
  const values = ["Critical", "High", "Medium", "Low"];

  return (
    <div className="severity-chart">
      {values.map((severity) => {
        const count = vulnerabilities.filter(
          (v) => v.severity === severity
        ).length;

        const max = Math.max(
          vulnerabilities.length,
          1
        );

        return (
          <div className="severity-row" key={severity}>
            <div>
              <span>{severity}</span>
              <strong>{count}</strong>
            </div>

            <div className="chart-track">
              <div
                className={`chart-bar ${severity.toLowerCase()}`}
                style={{
                  width: `${Math.max(
                    count === 0
                      ? 0
                      : (count / max) * 100,
                    count ? 8 : 0
                  )}%`,
                }}
              ></div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Workflow() {
  const steps = [
    ["01", "Code Upload", "Source code submitted"],
    ["02", "Detection", "Security scanner analyzes code"],
    ["03", "Assignment", "RBAC assigns developers"],
    ["04", "AI Remediation", "AI generates secure fix"],
    ["05", "Verification", "Code is re-scanned"],
  ];

  return (
    <div className="workflow">
      {steps.map(([number, title, text]) => (
        <div className="workflow-step" key={number}>
          <div className="workflow-number">
            {number}
          </div>

          <div>
            <strong>{title}</strong>
            <span>{text}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* =========================================================
   SCANNER PAGE
========================================================= */

function ScanPage({
  projects,
  onHistory,
  onUpload,
  scanState,
}) {
  return (
    <>
      <PageHeader
        eyebrow="CODE SECURITY"
        title="Source Code Scanner"
        description="Upload application source code and automatically scan it for security vulnerabilities."
        action={
          <button
            className="primary-button"
            onClick={onUpload}
          >
            📤 Upload Code
          </button>
        }
      />

      <div className="scanner-banner">
        <div className="scanner-icon">⌁</div>

        <div>
          <h3>
            Automated Security Analysis
          </h3>

          <p>
            VulnTrack analyzes uploaded source code
            for insecure coding patterns, secrets,
            injection vulnerabilities and other
            security weaknesses.
          </p>
        </div>

        <div className="scanner-status">
          <span></span>
          {scanState === "scanning"
            ? "Scanning"
            : scanState === "failed"
            ? "Scan Failed"
            : scanState === "completed_with_errors"
            ? "Completed with errors"
            : scanState === "completed"
            ? "Scan Complete"
            : "Scanner Ready"}
        </div>
      </div>

      <div className="panel">
        <PanelTitle
          title="Scanned Projects"
          subtitle="Previously analyzed source code"
        />

        <ProjectTable projects={projects} onHistory={onHistory} />
      </div>
    </>
  );
}

/* =========================================================
   VULNERABILITY PAGE
========================================================= */

function VulnerabilityPage({
  vulnerabilities,
  search,
  setSearch,
  severityFilter,
  setSeverityFilter,
  statusFilter,
  setStatusFilter,
  findingSort,
  setFindingSort,
  onOpen,
  onAI,
  assignDeveloper,
  developers,
  canAssign,
}) {
  return (
    <>
      <PageHeader
        eyebrow="FINDINGS"
        title="Vulnerabilities"
        description="Review detected vulnerabilities, assign developers and manage remediation."
      />

      <div className="filter-panel">
        <div className="search-box">
          <span>⌕</span>

          <input
            aria-label="Search findings"
            placeholder="Search vulnerability, file, severity or developer..."
            value={search}
            onChange={(e) =>
              setSearch(e.target.value)
            }
          />
        </div>

        <label className="filter-control">
          <span>Severity</span>
          <select aria-label="Filter by severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
          </select>
        </label>
        <label className="filter-control">
          <span>Status</span>
          <select aria-label="Filter by status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option>All</option><option>Open</option><option>In Progress</option><option>Fixed</option><option>Accepted Risk</option>
          </select>
        </label>
        <label className="filter-control">
          <span>Sort</span>
          <select aria-label="Sort findings" value={findingSort} onChange={(event) => setFindingSort(event.target.value)}>
            <option value="severity">Severity</option><option value="title">Title</option><option value="file">File</option><option value="status">Status</option>
          </select>
        </label>

        <div className="filter-summary">
          {vulnerabilities.length} findings
        </div>
      </div>

      <div className="panel">
        <VulnerabilityTable
          vulnerabilities={vulnerabilities}
          onOpen={onOpen}
          onAI={onAI}
          assignDeveloper={assignDeveloper}
          developers={developers}
          canAssign={canAssign}
          extended
        />
      </div>
    </>
  );
}

/* =========================================================
   VULNERABILITY TABLE
========================================================= */

function VulnerabilityTable({
  vulnerabilities,
  onOpen,
  onAI,
  assignDeveloper,
  developers,
  extended,
  canAssign,
}) {
  if (!vulnerabilities.length) {
    return (
      <div className="empty">
        <div>✓</div>
        <h3>No vulnerabilities found</h3>
        <p>No findings match the current search and filters. Clear them to see all findings.</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Vulnerability</th>
            <th>Location</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Assigned To</th>
            {extended && <th>Actions</th>}
          </tr>
        </thead>

        <tbody>
          {vulnerabilities.map((v) => (
            <tr key={v.id}>
              <td>
                <span className="vul-id">
                  {v.id}
                </span>
              </td>

              <td>
                <div className="table-title">
                  <strong>{v.title}</strong>
                  <span>{v.category}{v.cwe ? ` · ${v.cwe}` : ""}</span>
                </div>
              </td>

              <td>
                <div className="location">
                  <code>{v.file}</code>
                  <span>Line {v.line}</span>
                </div>
              </td>

              <td>
                <Severity severity={v.severity} />
              </td>

              <td>
                <Status status={v.status} />
              </td>

              <td>
                {extended && canAssign ? (
                  <select
                    className="inline-select"
                    value={v.assignee}
                    onChange={(e) =>
                      assignDeveloper(
                        v.id,
                        e.target.value
                      )
                    }
                  >
                    <option>
                      Unassigned
                    </option>

                    {developers.map((d) => (
                      <option
                        key={d.id}
                        value={d.username}
                      >
                        {d.username}
                      </option>
                    ))}
                  </select>
                ) : (
                  v.assignee || "Unassigned"
                )}
              </td>

              {extended && (
                <td>
                  <div className="table-actions">
                    <button
                      className="small-button"
                      onClick={() => onOpen(v)}
                    >
                      View
                    </button>

                    <button
                      className="ai-button"
                      onClick={() => onAI(v)}
                    >
                      ✦ AI Fix
                    </button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* =========================================================
   REMEDIATION PAGE
========================================================= */

function RemediationPage({
  vulnerabilities,
  onAI,
  updateStatus,
  developers,
  assignDeveloper,
  canAssign,
  apiRequest,
  onRefresh,
}) {
  const [showBatch, setShowBatch] = useState(false);
  const active = vulnerabilities.filter(
    (v) =>
      v.status !== "Fixed" &&
      v.status !== "Accepted Risk"
  );

  return (
    <>
      <PageHeader
        eyebrow="REMEDIATION"
        title="AI Remediation Center"
        description="Manage vulnerability fixes and use AI to generate secure code recommendations."
        action={active.length > 0 ? <button className="primary-button" onClick={() => setShowBatch(true)}>✦ Fix all with AI ({active.length})</button> : null}
      />

      {active.length === 0 ? <div className="panel empty"><h3>All findings are resolved</h3><p>New findings will appear here after a scan.</p></div> : <div className="remediation-layout">
        {active.map((v) => (
          <div className="remediation-card" key={v.id}>
            <div className="remediation-heading">
              <span className="vul-id">
                {v.id}
              </span>

              <Severity severity={v.severity} />
            </div>

            <h3>{v.title}</h3>

            <div className="file-line">
              📄 {v.file}:{v.line}
            </div>

            <p>{v.description}</p>

            {canAssign && <div className="assignment">
              <span>Developer</span>

              <select
                value={v.assignee}
                onChange={(e) =>
                  assignDeveloper(
                    v.id,
                    e.target.value
                  )
                }
              >
                <option>Unassigned</option>

                {developers.map((d) => (
                  <option
                    key={d.id}
                    value={d.username}
                  >
                    {d.username}
                  </option>
                ))}
              </select>
            </div>}

            <div className="remediation-status">
              <span>Status</span>
              <Status status={v.status} />
            </div>

            <div className="remediation-buttons">
              <button
                className="ai-button large"
                onClick={() => onAI(v)}
              >
                ✦ Fix with AI
              </button>

              <select
                value={v.status}
                onChange={(e) =>
                  updateStatus(
                    v.id,
                    e.target.value
                  )
                }
              >
                <option>Open</option>
                <option>In Progress</option>
                <option>Fixed</option>
                <option>Accepted Risk</option>
              </select>
            </div>
          </div>
        ))}
      </div>}
      {showBatch && <BatchRemediationModal
        vulnerabilities={active}
        onClose={() => setShowBatch(false)}
        apiRequest={apiRequest}
        onRefresh={onRefresh}
      />}
    </>
  );
}

/* =========================================================
   USERS / RBAC
========================================================= */

function UsersPage({
  role,
  developers,
  projects,
  apiRequest,
}) {
  const [membersByProject, setMembersByProject] = useState({});
  const [selectedDeveloper, setSelectedDeveloper] = useState({});
  const [accessError, setAccessError] = useState("");
  const [accessBusy, setAccessBusy] = useState(false);
  const refreshMembers = useCallback(async () => {
    if (role !== "Admin") return;
    try {
      const entries = await Promise.all(projects.map(async (project) => {
        const result = await apiRequest(`/api/projects/${encodeURIComponent(project.id)}/members`);
        return [project.id, result.members || []];
      }));
      setMembersByProject(Object.fromEntries(entries));
    } catch (error) {
      setAccessError(error.message || "Unable to load project access.");
    }
  }, [apiRequest, projects, role]);
  useEffect(() => {
    const timer = window.setTimeout(() => { void refreshMembers(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refreshMembers]);
  const grantAccess = async (projectId) => {
    const username = selectedDeveloper[projectId] || developers[0]?.username;
    if (!username) return;
    setAccessError(""); setAccessBusy(true);
    try {
      await apiRequest(`/api/projects/${encodeURIComponent(projectId)}/members`, {
        method: "POST", body: JSON.stringify({ username }),
      });
      await refreshMembers();
    } catch (error) {
      setAccessError(error.message || "Unable to grant project access.");
    } finally { setAccessBusy(false); }
  };
  const revokeAccess = async (projectId, userId) => {
    setAccessError(""); setAccessBusy(true);
    try {
      await apiRequest(`/api/projects/${encodeURIComponent(projectId)}/members/${encodeURIComponent(userId)}`, { method: "DELETE" });
      await refreshMembers();
    } catch (error) {
      setAccessError(error.message || "Unable to revoke project access.");
    } finally { setAccessBusy(false); }
  };
  const permissions = {
    Admin: [
      "View all projects and findings",
      "Upload and scan source code",
      "Assign vulnerabilities",
      "Authorize Developers for projects",
      "Review audit logs",
    ],
    Developer: [
      "View assigned or authorized findings",
      "Update finding status",
      "Add remediation notes",
    ],
  };

  return (
    <>
      <PageHeader
        eyebrow="ACCESS CONTROL"
        title="Users & RBAC"
        description="Role-based access control determines what each project member can perform."
      />

      <div className="rbac-grid">
        <div className="rbac-card active-role">
          <div className="rbac-icon">♙</div>

          <h3>{role}</h3>

          <span className="role-tag">
            Current Role
          </span>

          <div className="permission-list">
            {permissions[role].map((permission) => (
              <div key={permission}>
                <span>✓</span>
                {permission}
              </div>
            ))}
          </div>
        </div>

        {role === "Admin" && <div className="panel">
          <PanelTitle
            title="Development Team"
            subtitle="Developer accounts available for assignment"
          />

          <div className="developer-list">
            {developers.map((developer) => (
              <div
                className="developer-row"
                key={developer.id}
              >
                <div className="developer-avatar">
                  {developer.username.charAt(0).toUpperCase()}
                </div>

                <div>
                  <strong>
                    {developer.username}
                  </strong>
                  <span>Available for assignments and project access</span>
                </div>

                <span className="role-tag">
                  Developer
                </span>
              </div>
            ))}
          </div>
        </div>}
      </div>
      {role === "Admin" && <section className="panel project-access-panel">
        <PanelTitle title="Project access" subtitle="Grant or revoke Developer access for each project." />
        {accessError && <div className="state-banner error" role="alert">{accessError}</div>}
        {!projects.length && <div className="empty"><h3>No projects yet</h3><p>Scan source code to create a project.</p></div>}
        {projects.map((project) => {
          const members = membersByProject[project.id] || [];
          return <div className="project-access-row" key={project.id}>
            <div><strong>{project.name}</strong><span>{members.length} authorized developer{members.length === 1 ? "" : "s"}</span></div>
            <div className="project-access-controls">
              {developers.length > 0 && <>
                <select aria-label={`Choose developer for ${project.name}`} value={selectedDeveloper[project.id] || developers[0].username}
                  onChange={(event) => setSelectedDeveloper((current) => ({ ...current, [project.id]: event.target.value }))}>
                  {developers.map((developer) => <option key={developer.id} value={developer.username}>{developer.username}</option>)}
                </select>
                <button className="small-button" disabled={accessBusy} onClick={() => grantAccess(project.id)}>Grant access</button>
              </>}
            </div>
            <div className="project-member-list">
              {members.map((member) => <span key={member.id} className="member-chip">{member.username}
                <button aria-label={`Revoke ${member.username} from ${project.name}`} disabled={accessBusy} onClick={() => revokeAccess(project.id, member.id)}>×</button>
              </span>)}
              {!members.length && <span className="muted-text">No project-specific members</span>}
            </div>
          </div>;
        })}
      </section>}
    </>
  );
}

/* =========================================================
   NOTIFICATIONS
========================================================= */

function NotificationPage({ notifications }) {
  return (
    <>
      <PageHeader
        eyebrow="SYSTEM EVENTS"
        title="Recent Activity"
        description="Recent events recorded by the backend audit log."
      />

      <div className="panel">
        <div className="notification-list">
          {notifications.length === 0 && <div className="empty"><h3>No recorded activity</h3></div>}
          {notifications.map((notification) => (
            <div
              className={`notification-row ${
                notification.unread
                  ? "unread"
                  : ""
              }`}
              key={notification.id}
            >
              <div className="notification-symbol">
                {notification.type === "Scan"
                  ? "⌁"
                  : notification.type ===
                    "Assignment"
                  ? "♙"
                  : "⚠"}
              </div>

              <div>
                <strong>
                  {notification.text}
                </strong>

                <span>
                  {notification.type} ·{" "}
                  {notification.time}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* =========================================================
   AUDIT
========================================================= */

function AuditPage({ logs }) {
  return (
    <>
      <PageHeader
        eyebrow="COMPLIANCE"
        title="Audit Logs"
        description="Track vulnerability, assignment, AI and remediation activity."
      />

      <div className="panel">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>User</th>
                <th>Details</th>
                <th>Time</th>
              </tr>
            </thead>

            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td>
                    <strong>{log.action}</strong>
                  </td>

                  <td>{log.actor_username || "System"}</td>

                  <td>{log.details}</td>

                  <td>{log.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

/* =========================================================
   UPLOAD MODAL
========================================================= */

function UploadModal({
  uploadedFiles,
  scanResult,
  onUpload,
  onStartScan,
  onClose,
  scanState,
}) {
  const inputRef = useRef(null);

  return (
    <div className="modal-backdrop">
      <div className="modal upload-modal">
        <button
          className="modal-close"
          onClick={onClose}
        >
          ×
        </button>

        <div className="modal-icon">
          ⬆
        </div>

        <h2>Upload Source Code</h2>

        <p className="modal-description">
          Upload source code files or a project ZIP
          to automatically scan for security
          vulnerabilities.
        </p>

        <div
          className="drop-zone"
          onClick={() =>
            inputRef.current?.click()
          }
        >
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".js,.jsx,.ts,.tsx,.py,.java,.c,.cpp,.h,.cs,.go,.php,.rb,.zip"
            onChange={onUpload}
            hidden
          />

          <div className="drop-icon">
            📁
          </div>

          <h3>
            Drop your source code here
          </h3>

          <span>
            or click to browse files
          </span>

          <small>
            JS · TS · Python · Java · C/C++ · Go ·
            PHP · ZIP
          </small>
        </div>

        {uploadedFiles.length > 0 && (
          <div className="uploaded-files">
            <div className="uploaded-header">
              <strong>
                Selected Files
              </strong>

              <span>
                {uploadedFiles.length} file
                {uploadedFiles.length !== 1
                  ? "s"
                  : ""}
              </span>
            </div>

            {uploadedFiles
              .slice(0, 5)
              .map((file) => (
                <div
                  className="file-item"
                  key={`${file.name}-${file.size}`}
                >
                  <span>📄</span>

                  <div>
                    <strong>{file.name}</strong>
                    <small>
                      {formatSize(file.size)}
                    </small>
                  </div>

                  <span className="file-check">
                    ✓
                  </span>
                </div>
              ))}
          </div>
        )}

        {scanResult && (
          <div className="upload-summary">
            <div>
              <span>Files</span>
              <strong>
                {scanResult.fileCount}
              </strong>
            </div>

            <div>
              <span>Size</span>
              <strong>
                {formatSize(scanResult.totalSize)}
              </strong>
            </div>

            <div>
              <span>Ready</span>
              <strong>✓</strong>
            </div>
          </div>
        )}

        <div className="modal-actions">
          <button
            className="secondary-button"
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            className="primary-button"
            disabled={
              !uploadedFiles.length ||
              scanState === "scanning"
            }
            onClick={onStartScan}
          >
            {scanState === "scanning"
              ? "Scanning..."
              : "Start Security Scan →"}
          </button>
        </div>

        {scanState === "scanning" && (
          <div className="scan-progress">
            <div className="spinner"></div>

            <div>
              <strong>
                Analyzing source code...
              </strong>

              <span>
                Checking security patterns,
                secrets and vulnerable functions.
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   VULNERABILITY DETAILS MODAL
========================================================= */

function VulnerabilityModal({
  vulnerability,
  onClose,
  onAI,
  assignDeveloper,
  developers,
  updateStatus,
  updateNotes,
  canAssign,
}) {
  const [noteDraft, setNoteDraft] = useState(vulnerability.remediation_notes || "");

  return (
    <div className="modal-backdrop">
      <div className="modal details-modal">
        <button
          className="modal-close"
          onClick={onClose}
        >
          ×
        </button>

        <div className="details-header">
          <div>
            <span className="vul-id">
              {vulnerability.id}
            </span>

            <h2>{vulnerability.title}</h2>

            <div className="header-badges">
              <Severity
                severity={vulnerability.severity}
              />

              <Status
                status={vulnerability.status}
              />
            </div>
          </div>
        </div>

        <div className="code-location">
          <div>
            <span>FILE</span>
            <code>
              {vulnerability.file}
            </code>
          </div>

          <div>
            <span>LINE</span>
            <code>
              {vulnerability.line}
            </code>
          </div>

          <div>
            <span>DETECTION</span>
            <strong>
              {vulnerability.detectedBy}
            </strong>
          </div>
        </div>

        <div className="detail-section">
          <h3>Detected Code</h3>

          <pre>
            <code>
              {vulnerability.code}
            </code>
          </pre>
        </div>

        <div className="detail-section">
          <h3>Security Analysis</h3>

          <p>
            {vulnerability.description}
          </p>
          <div className="finding-taxonomy">
            <span><strong>Category:</strong> {vulnerability.category || "—"}</span>
            <span><strong>CWE:</strong> {vulnerability.cwe || "Not mapped"}</span>
            <span><strong>OWASP:</strong> {vulnerability.owasp || "Not mapped"}</span>
          </div>
        </div>

        <div className="assignment-panel">
          {canAssign && <div>
            <span>Assign Developer</span>

            <select
              value={vulnerability.assignee}
              onChange={(e) =>
                assignDeveloper(
                  vulnerability.id,
                  e.target.value
                )
              }
            >
              <option>
                Unassigned
              </option>

              {developers.map((developer) => (
                <option
                  key={developer.id}
                    value={developer.username}
                >
                  {developer.username}
                </option>
              ))}
            </select>
          </div>}

          <div>
            <span>Lifecycle Status</span>

            <select
              value={vulnerability.status}
              onChange={(e) =>
                updateStatus(
                  vulnerability.id,
                  e.target.value
                )
              }
            >
              <option>Open</option>
              <option>In Progress</option>
              <option>Fixed</option>
              <option>Accepted Risk</option>
            </select>
          </div>
        </div>

        <div className="detail-section">
          <h3>Remediation Notes</h3>
          <textarea value={noteDraft} onChange={(event) => setNoteDraft(event.target.value)} rows={4} maxLength={4000} placeholder="Record the remediation steps or review notes." />
          <button className="secondary-button" onClick={() => updateNotes(vulnerability.id, noteDraft)}>Save Notes</button>
        </div>

        <div className="modal-actions">
          <button
            className="secondary-button"
            onClick={onClose}
          >
            Close
          </button>

          <button
            className="ai-button large"
            onClick={onAI}
          >
            ✦ Generate AI Fix
          </button>
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   AI REMEDIATION MODAL
========================================================= */

export function AIModal({ vulnerability, onClose, apiRequest, onRefresh }) {
  const [aiConfig, setAiConfig] = useState(null);
  const [loading, setLoading] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState(false);
  const [error, setError] = useState('');
  const [remediation, setRemediation] = useState(null);
  const [decision, setDecision] = useState('');
  const [verification, setVerification] = useState(null);

  useEffect(() => {
    let active = true;
    apiRequest('/api/ai/status')
      .then((result) => { if (active) setAiConfig(result); })
      .catch((requestError) => { if (active) setError(requestError.message || 'Unable to check AI configuration.'); });
    return () => { active = false; };
  }, [apiRequest]);

  const requestSuggestion = async () => {
    setError('');
    setRemediation(null);
    setDecision('');
    setVerification(null);
    setLoading(true);
    try {
      const result = await apiRequest('/api/ai/remediation', {
        method: 'POST',
        body: JSON.stringify({ vulnerabilityId: vulnerability.id }),
      });
      setRemediation(result);
    } catch (requestError) {
      setError(requestError.status === 503 ? 'AI not configured.' : (requestError.message || 'Unable to generate a suggestion.'));
    } finally {
      setLoading(false);
    }
  };

  const decide = async (choice) => {
    if (!remediation?.suggestionId) return;
    setError('');
    setDecisionLoading(true);
    try {
      const result = await apiRequest(`/api/ai/remediation/${encodeURIComponent(remediation.suggestionId)}/decision`, {
        method: 'POST', body: JSON.stringify({ decision: choice }),
      });
      setDecision(result.status);
      setVerification(result.verification || null);
      if (choice === 'apply') await onRefresh?.();
    } catch (requestError) {
      setError(requestError.message || 'Unable to save this review decision.');
    } finally {
      setDecisionLoading(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal ai-modal" role="dialog" aria-modal="true" aria-labelledby="ai-remediation-title">
        <button className="modal-close" onClick={onClose} aria-label="Close">×</button>
        <div className="ai-header">
          <div className="ai-symbol">✦</div>
          <div><span>OPTIONAL AI ASSISTANCE</span><h2 id="ai-remediation-title">Remediation Suggestion</h2></div>
        </div>
        <div className="ai-vulnerability">
          <div><span>{vulnerability.id}</span><strong>{vulnerability.title}</strong></div>
          <Severity severity={vulnerability.severity} />
        </div>
        <div className="detail-section">
          <h3>Selected Snippet</h3>
          <pre><code>{vulnerability.code || 'No source snippet is stored for this finding.'}</code></pre>
        </div>
        <div className="ai-disclaimer">
          <p>
            When you request a suggestion, this finding's code snippet and rule context are sent to the configured AI provider.
            Apply updates VulnTrack's stored scan copy and starts a verification scan; it does not modify your original local files.
          </p>
        </div>
        {aiConfig?.configured === false && <div className="state-banner">AI not configured. Set OPENROUTER_API_KEY on the backend to enable suggestions.</div>}
        {aiConfig?.configured === true && !remediation && (
          <button className="ai-button large" onClick={requestSuggestion} disabled={loading}>
            {loading ? 'Generating suggestion…' : 'Send snippet and generate suggestion'}
          </button>
        )}
        {aiConfig === null && !error && <div className="state-banner">Checking AI configuration…</div>}
        {error && <div className="state-banner error">{error}</div>}
        {remediation && (
          <div className="ai-section">
            <p className="ai-provider-label">{remediation.provider} · {remediation.model}</p>
            <h3>Explanation</h3>
            <p>{remediation.explanation}</p>
            <CodeDiff before={remediation.vulnerable_code} after={remediation.fixed_code} />
            <h3>Why this works</h3>
            <p>{remediation.why_it_works}</p>
            {!decision && <div className="modal-actions">
              <button className="primary-button" onClick={() => decide('apply')} disabled={decisionLoading}>
                {decisionLoading ? 'Applying and re-scanning…' : 'Apply to stored copy and re-scan'}
              </button>
              <button className="secondary-button" onClick={() => decide('reject')} disabled={decisionLoading}>Reject</button>
            </div>}
            {decision === 'rejected' && <div className="state-banner">Suggestion rejected. No source copy was changed.</div>}
            {decision === 'applied' && <div className={`state-banner ${verification?.remainingMatchingFinding ? 'error' : 'success'}`}>
              {verification?.error ? `Fix was applied, but verification scan failed: ${verification.error}`
                : verification?.remainingMatchingFinding ? 'Fix was applied, but the same rule still reports this file. Review the new scan.'
                  : 'Fix was applied to the stored copy and the matching finding was not reported by the verification scan.'}
            </div>}
          </div>
        )}
        <div className="modal-actions">
          <button className="secondary-button" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

function BatchRemediationModal({ vulnerabilities, onClose, apiRequest, onRefresh }) {
  const [batchFindings] = useState(vulnerabilities);
  const [offset, setOffset] = useState(0);
  const [items, setItems] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const currentBatch = batchFindings.slice(offset, offset + 10);
  const selected = items[selectedIndex];
  const allDecided = items.length > 0 && items.every((item) => item.status !== 'pending');
  const remaining = offset + currentBatch.length < batchFindings.length;

  const generateBatch = async () => {
    setError('');
    setLoading(true);
    try {
      const result = await apiRequest('/api/ai/remediation/batch', {
        method: 'POST',
        body: JSON.stringify({ vulnerabilityIds: currentBatch.map((item) => item.id) }),
      });
      setItems((result.remediations || []).map((item) => ({ ...item, status: 'pending' })));
      setSelectedIndex(0);
    } catch (requestError) {
      setError(requestError.message || 'Unable to generate batch suggestions.');
    } finally {
      setLoading(false);
    }
  };

  const decide = async (choice) => {
    if (!selected?.suggestionId) return;
    setError('');
    setLoading(true);
    try {
      const result = await apiRequest(`/api/ai/remediation/${encodeURIComponent(selected.suggestionId)}/decision`, {
        method: 'POST', body: JSON.stringify({ decision: choice }),
      });
      setItems((current) => current.map((item, index) => index === selectedIndex
        ? { ...item, status: result.status, verification: result.verification || null }
        : item));
      if (choice === 'apply') await onRefresh?.();
    } catch (requestError) {
      setError(requestError.message || 'Unable to save the review decision.');
    } finally {
      setLoading(false);
    }
  };

  const nextBatch = () => {
    setOffset((value) => value + items.length);
    setItems([]);
    setError('');
  };

  return <div className="modal-backdrop">
    <div className="modal ai-modal batch-ai-modal" role="dialog" aria-modal="true" aria-labelledby="batch-remediation-title">
      <button className="modal-close" onClick={onClose} aria-label="Close batch remediation">×</button>
      <div className="ai-header"><div className="ai-symbol">✦</div><div><span>BATCH REVIEW</span><h2 id="batch-remediation-title">Fix findings with AI</h2></div></div>
      <p>Suggestions are generated for up to 10 findings per batch (12,000 code characters total). Review every suggestion; apply or reject each one. Applying updates VulnTrack’s stored source copy and re-scans it. Your original local files are not modified.</p>
      {!items.length && <>
        <div className="state-banner">Batch {Math.floor(offset / 10) + 1}: {currentBatch.length} of {batchFindings.length - offset} remaining findings.</div>
        <button className="ai-button large" onClick={generateBatch} disabled={loading || !currentBatch.length}>
          {loading ? 'Generating reviewed candidates…' : 'Generate suggestions for this batch'}
        </button>
      </>}
      {items.length > 0 && <>
        <div className="batch-review-layout">
          <nav className="batch-finding-list" aria-label="Batch findings">
            {items.map((item, index) => <button key={item.suggestionId} className={index === selectedIndex ? 'selected' : ''} onClick={() => setSelectedIndex(index)}>
              <span>{item.vulnerabilityId.slice(0, 10)}</span><small>{item.status}</small>
            </button>)}
          </nav>
          {selected && <section className="batch-finding-detail">
            <p className="ai-provider-label">{selected.provider || 'Batch suggestion'} {selected.model ? `· ${selected.model}` : ''}</p>
            <h3>Explanation</h3><p>{selected.explanation}</p>
            <CodeDiff before={selected.vulnerable_code} after={selected.fixed_code} />
            <h3>Why it works</h3><p>{selected.why_it_works}</p>
            {selected.status === 'pending' ? <div className="modal-actions">
              <button className="primary-button" onClick={() => decide('apply')} disabled={loading}>{loading ? 'Applying and scanning…' : 'Apply and re-scan'}</button>
              <button className="secondary-button" onClick={() => decide('reject')} disabled={loading}>Reject</button>
            </div> : <div className={`state-banner ${selected.status === 'applied' && selected.verification?.remainingMatchingFinding ? 'error' : 'success'}`}>
              {selected.status === 'rejected' ? 'Rejected; no source copy was changed.'
                : selected.verification?.error ? `Applied, but verification scan failed: ${selected.verification.error}`
                  : selected.verification?.remainingMatchingFinding ? 'Applied, but the same rule still reports this file.'
                    : 'Reviewed and applied to the stored copy.'}
            </div>}
          </section>}
        </div>
        {allDecided && remaining && <button className="primary-button" onClick={nextBatch}>Review next batch ({batchFindings.length - offset - items.length} remaining)</button>}
        {allDecided && !remaining && <div className="state-banner success">Every generated suggestion was reviewed.</div>}
      </>}
      {error && <div className="state-banner error" role="alert">{error}</div>}
      <div className="modal-actions"><button className="secondary-button" onClick={onClose}>Close</button></div>
    </div>
  </div>;
}

export function CodeDiff({ before, after }) {
  const oldLines = String(before || '').split('\n');
  const newLines = String(after || '').split('\n');
  if (oldLines.length * newLines.length > 40000) {
    return <div className="diff-columns">
      <div className="diff-pane removed"><h3>Vulnerable code</h3><pre><code>{before}</code></pre></div>
      <div className="diff-pane added"><h3>Fixed code</h3><pre><code>{after}</code></pre></div>
    </div>;
  }
  const table = Array.from({ length: oldLines.length + 1 }, () => new Uint16Array(newLines.length + 1));
  for (let i = oldLines.length - 1; i >= 0; i -= 1) {
    for (let j = newLines.length - 1; j >= 0; j -= 1) {
      table[i][j] = oldLines[i] === newLines[j]
        ? table[i + 1][j + 1] + 1
        : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  const rows = [];
  let i = 0; let j = 0;
  while (i < oldLines.length || j < newLines.length) {
    if (i < oldLines.length && j < newLines.length && oldLines[i] === newLines[j]) {
      rows.push({ left: oldLines[i], right: newLines[j], kind: 'same' }); i += 1; j += 1;
    } else if (i < oldLines.length && (j === newLines.length || table[i + 1][j] >= table[i][j + 1])) {
      rows.push({ left: oldLines[i], right: '', kind: 'removed' }); i += 1;
    } else {
      rows.push({ left: '', right: newLines[j], kind: 'added' }); j += 1;
    }
  }
  return <div className="diff-wrap">
    <div className="diff-headings"><strong>Vulnerable code</strong><strong>Proposed fix</strong></div>
    <table className="diff-table"><tbody>{rows.map((row, index) => (
      <tr key={index} className={row.kind}>
        <td><pre>{row.left || ' '}</pre></td><td><pre>{row.right || ' '}</pre></td>
      </tr>
    ))}</tbody></table>
  </div>;
}
/* =========================================================
   PROJECT TABLE
========================================================= */

function ProjectHistoryModal({ project, scans, loading, error, onClose }) {
  return <div className="modal-backdrop">
    <div className="modal history-modal" role="dialog" aria-modal="true" aria-labelledby="project-history-title">
      <button className="modal-close" aria-label="Close scan history" onClick={onClose}>×</button>
      <h2 id="project-history-title">Scan history · {project.name}</h2>
      {loading && <div className="state-banner">Loading scans…</div>}
      {error && <div className="state-banner error" role="alert">{error}</div>}
      {!loading && !error && scans.length === 0 && <div className="empty"><h3>No scan history</h3></div>}
      {!loading && scans.length > 0 && <div className="table-container"><table>
        <thead><tr><th>Status</th><th>Started</th><th>Finished</th><th>Files</th><th>Findings</th></tr></thead>
        <tbody>{scans.map((scan) => <tr key={scan.id}>
          <td><Status status={scan.status} /></td><td>{scan.startedAt}</td><td>{scan.finishedAt || "—"}</td>
          <td>{scan.fileCount}</td><td>{scan.findingCount}</td>
        </tr>)}</tbody>
      </table></div>}
      <div className="modal-actions"><button className="secondary-button" onClick={onClose}>Close</button></div>
    </div>
  </div>;
}

function ProjectTable({ projects, onHistory }) {
  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Project</th>
            <th>Language</th>
            <th>Files</th>
            <th>Lines</th>
            <th>Findings</th>
            <th>Status</th>
            <th>History</th>
          </tr>
        </thead>

        <tbody>
          {projects.map((project) => (
            <tr key={project.id}>
              <td>
                <strong>
                  {project.name}
                </strong>
              </td>

              <td>
                <span className="language-tag">
                  {project.language || "—"}
                </span>
              </td>

              <td>{project.files}</td>

              <td>
                {project.lines.toLocaleString()}
              </td>

              <td>
                <strong>
                  {project.vulnerabilities}
                </strong>
              </td>

              <td>
                <Status status={project.status} />
              </td>

              <td><button className="small-button" onClick={() => onHistory?.(project)}>View scans</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* =========================================================
   SMALL COMPONENTS
========================================================= */

function PageHeader({
  eyebrow,
  title,
  description,
  action,
}) {
  return (
    <div className="page-header">
      <div>
        <span className="eyebrow">
          {eyebrow}
        </span>

        <h1>{title}</h1>

        <p>{description}</p>
      </div>

      {action && <div>{action}</div>}
    </div>
  );
}

function PanelTitle({
  title,
  subtitle,
}) {
  return (
    <div className="panel-title">
      <div>
        <h3>{title}</h3>
        <p>{subtitle}</p>
      </div>
    </div>
  );
}

function Severity({ severity }) {
  return (
    <span
      className={`severity ${severity.toLowerCase()}`}
    >
      {severity}
    </span>
  );
}

function Status({ status }) {
  return (
    <span
      className={`status ${status
        .toLowerCase()
        .replace(/\s+/g, "-")}`}
    >
      {status}
    </span>
  );
}

/* =========================================================
   HELPERS
========================================================= */

function formatSize(bytes) {
  if (bytes === 0) return "0 B";

  const units = ["B", "KB", "MB", "GB"];
  const index = Math.floor(
    Math.log(bytes) / Math.log(1024)
  );

  return `${(
    bytes / Math.pow(1024, index)
  ).toFixed(index === 0 ? 0 : 1)} ${
    units[index]
  }`;
}

export default App;


