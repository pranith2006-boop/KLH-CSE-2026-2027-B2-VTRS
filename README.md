# VulnTrack – Vulnerability Tracking and AI Remediation System

**Identify • Track • Analyze • Remediate**

## Team Members

| S.No | University ID | Name |
|---|---|---|
| 1 | 2420030158 | MODALLA PRANITH REDDY |
| 2 | 2420030636 | V Praneeth |
| 3 | 2420030351 | Y Karthikeya |

## Project Supervisor

**Venkateswari Ketineni**

---

## Abstract

VulnTrack is a vulnerability tracking and AI-powered remediation platform designed to help developers and security teams identify, manage, prioritize, and resolve security vulnerabilities in application source code.

The system provides a centralized platform for uploading source files or ZIP archives, performing automated static code analysis, detecting security vulnerabilities, and tracking their remediation status. It uses Semgrep-based security rules and dependency auditing tools to identify potential security issues such as SQL injection, Cross-Site Scripting (XSS), command execution, path traversal, weak hashing algorithms, and hardcoded credentials.

VulnTrack implements Role-Based Access Control (RBAC) to manage administrators and developers, allowing users to manage projects, assign findings, update vulnerability statuses, and maintain audit activity records.

The upgraded **VulnTrack v2** introduces AI-powered vulnerability remediation. Users can request AI-generated fixes for individual vulnerabilities or multiple findings. The system provides explanations, vulnerable and corrected code comparisons, and suggested remediation approaches. Proposed fixes remain pending until explicitly approved by the user. Once approved, changes are applied only to the server-side scan snapshot and automatically re-scanned to verify whether the vulnerability has been resolved.

The platform aims to simplify vulnerability management, improve security awareness, and assist developers in identifying and fixing security issues efficiently.

## Problem Statement

Identifying and managing security vulnerabilities manually is time-consuming and error-prone. Developers need an efficient platform to detect vulnerabilities, prioritize security issues, assign remediation tasks, and verify whether fixes are successful.

VulnTrack addresses this challenge through automated static code analysis, centralized vulnerability tracking, role-based access control, dependency auditing, and AI-assisted remediation.

## Project Objectives

- Develop a centralized vulnerability tracking platform.
- Automatically identify security vulnerabilities in uploaded source code.
- Detect common security issues using Semgrep rules.
- Perform dependency vulnerability auditing.
- Classify findings based on severity and vulnerability categories.
- Implement Role-Based Access Control for administrators and developers.
- Allow project access management and vulnerability assignment.
- Track vulnerability status and maintain scan history.
- Maintain audit logs of important user and system activities.
- Integrate AI-powered vulnerability remediation.
- Generate explanations and corrected code suggestions.
- Allow users to review, approve, or reject AI-generated fixes.
- Automatically re-scan code after applying approved fixes.
- Provide a user-friendly dashboard for vulnerability management.

## Technologies Used

| Category | Technologies |
|---|---|
| Frontend | React.js, Vite, JavaScript |
| Backend | Python, Flask |
| Database | SQLite |
| Authentication | JWT, Role-Based Access Control |
| Static Code Analysis | Semgrep |
| Dependency Auditing | npm audit, pip-audit |
| AI Integration | OpenRouter API, OpenAI API |
| Version Control | Git, GitHub |
| Development Tools | Visual Studio Code, Node.js, Python |
| Testing | Vitest, Pytest |
| Build Tool | Vite |

## System Architecture

VulnTrack v2 follows a client-server architecture consisting of the following components:

### 1. Frontend Layer
- Developed using React.js and Vite.
- Provides the user interface for authentication, dashboards, projects, vulnerability tracking, and AI remediation.
- Communicates with the backend through REST APIs.

### 2. Backend Layer
- Developed using Python and Flask.
- Handles authentication, authorization, source-code uploads, scanning, vulnerability management, and remediation workflows.
- Provides REST API endpoints for frontend communication.

### 3. Vulnerability Detection Layer
- Uses Semgrep with bundled security rules.
- Identifies selected security vulnerabilities in Python and JavaScript/TypeScript files.
- Performs dependency security checks using npm audit and pip-audit.

### 4. AI Remediation Layer
- Integrates AI providers through OpenRouter or OpenAI.
- Generates suggested fixes for selected vulnerabilities.
- Provides explanations and vulnerable-versus-fixed code comparisons.
- Requires explicit user approval before applying changes.

### 5. Database and Storage Layer
- Uses SQLite for application data.
- Stores user information, projects, findings, scan history, and audit activity.
- Stores uploaded source-code snapshots privately on the backend.

### Architecture Workflow

```text
          User / Administrator
                  |
                  v
          React + Vite Frontend
                  |
                  v
            Flask REST API
                  |
          +-------+--------+
          |                |
          v                v
      SQLite DB       Source Upload
                           |
                           v
                    Private Snapshot
                           |
                           v
                    Semgrep Scanner
                           |
                    +------+------+
                    |             |
                    v             v
               Code Analysis  Dependency Audit
                    |             |
                    +------+------+
                           |
                           v
                   Vulnerability Findings
                           |
                           v
                    AI Remediation
                           |
                    User Approval
                           |
                           v
                   Apply Suggested Fix
                           |
                           v
                    Automatic Re-scan
                           |
                           v
                   Updated Findings
```

## Key Features

### 1. User Authentication and Authorization
- Secure login using JWT authentication.
- Role-Based Access Control.
- Separate permissions for administrators and developers.

### 2. Source Code Upload
- Upload individual source files.
- Upload ZIP archives containing project source code.
- Store uploaded source code as private server-side scan snapshots.
- Original local files remain unchanged.

### 3. Automated Vulnerability Detection
- Static source-code analysis using Semgrep.
- Detection of selected SQL injection vulnerabilities.
- Cross-Site Scripting (XSS) checks.
- Command execution vulnerability checks.
- Path traversal checks.
- Weak hashing algorithm detection.
- Likely hardcoded credential detection.

### 4. Dependency Vulnerability Auditing
- npm audit for Node.js dependencies.
- pip-audit for Python dependencies.
- Identification of known dependency vulnerabilities.
- Reporting of dependency audit warnings and errors.

### 5. Vulnerability Management
- View detected security findings.
- Filter and sort vulnerabilities.
- View severity, file location, line number, and vulnerability details.
- Track finding status.
- Assign developers to findings.
- Manage project access.

### 6. AI-Powered Remediation
- Generate AI-powered fixes for individual findings.
- Generate fixes for multiple findings through the remediation center.
- Support batch remediation of up to 10 findings per request.
- Review AI-generated explanations.
- Compare vulnerable and fixed code.
- Understand why the suggested changes should resolve the issue.

### 7. Approval-Based Fix Application
- AI-generated fixes remain pending until user approval.
- Users can approve or reject proposed changes.
- Approved fixes are applied only to the stored scan snapshot.
- Automatically re-scan the modified snapshot.
- Report whether the same rule and file still contain a matching finding.

### 8. Audit Activity and Scan History
- Maintain records of important user and system activities.
- Track vulnerability status changes.
- Maintain scan history for uploaded source snapshots.

## Project Structure

```text
vulntrack-v2-ai-remediation/
│
├── backend/
│   ├── app.py
│   ├── seed_users.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── tests/
│   ├── data/
│   │   └── snapshots/
│   └── vulntrack-v2.db
│
├── src/
│   ├── components/
│   ├── pages/
│   ├── assets/
│   └── ...
│
├── public/
├── tests/
├── .env.example
├── package.json
├── package-lock.json
├── vite.config.js
├── README.md
│
└── docs/
```

*Note: The structure above represents the main application layout. Individual component and configuration filenames may vary.*

## Installation and Execution

### Prerequisites

Install the following software:

- Python 3.11 or later
- Node.js 20.19+ or 22.12+
- npm
- Git
- Visual Studio Code

### 1. Clone the Repository

```bash
git clone https://github.com/pranith2006-boop/KLH-CSE-2026-2027-B2-VTRS.git
```

Navigate to the project directory:

```bash
cd KLH-CSE-2026-2027-B2-VTRS
```

### 2. Backend Setup

Open a terminal and navigate to the backend directory:

```powershell
cd D:\SOAProject\vulntrack-v2-ai-remediation\backend
```

Create a Python virtual environment:

```powershell
py -3.11 -m venv .venv
```

Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Create the environment configuration:

```powershell
Copy-Item .env.example .env
```

Open the `.env` file and configure:

- `VULNTRACK_JWT_SECRET`
- Administrator credentials
- Developer credentials
- `OPENROUTER_API_KEY` (optional)
- `VULNTRACK_DB=vulntrack-v2.db`
- `PORT=5001`

Initialize development users:

```bash
python seed_users.py
```

Start the backend server:

```bash
python app.py
```

Backend URL:

`http://127.0.0.1:5001`

### 3. Frontend Setup

Open another terminal and navigate to the frontend project directory:

```powershell
cd D:\SOAProject\vulntrack-v2-ai-remediation
```

Install dependencies:

```bash
npm ci
```

Create the frontend environment configuration:

```powershell
Copy-Item .env.example .env
```

Start the frontend:

```bash
npm run dev
```

Frontend URL:

`http://localhost:5174`

### 4. Access the Application

Open the frontend URL in your browser and sign in using the administrator or developer credentials configured in the backend environment file.

## Testing and Validation

The project includes frontend and backend testing to validate application functionality.

### Frontend Checks

Run linting:

```bash
npm run lint
```

Run frontend tests:

```bash
npm test
```

Build the frontend:

```bash
npm run build
```

### Backend Checks

Navigate to the backend directory and execute:

```bash
python -m pytest tests -v
```

## Security and Data Handling

- Uploaded source code is stored in private server-side snapshots.
- VulnTrack does not execute uploaded application code.
- AI receives only the selected source snippet and relevant vulnerability information after a user explicitly requests a suggestion.
- AI-generated fixes require user approval.
- Approved changes affect only the stored scan snapshot, not the original local source files.
- Dependency auditing sends dependency names and versions to the configured package advisory services.
- AI provider privacy and data-retention policies apply when using external AI services.
- Snapshot storage and SQLite database files must be protected.

## Limitations

- Static analysis relies on heuristic security rules and does not constitute a complete security audit.
- Bundled Semgrep rules currently target Python and JavaScript/TypeScript.
- Other accepted file types may not have applicable security rules.
- Dependency auditing requires network connectivity and available advisory services.
- Dependency manifests without matching lockfiles may produce scan warnings or errors.
- AI-generated fixes may not resolve every vulnerability and require human review.
- SQLite and process-local AI rate limiting are intended for local demonstration.
- JWT tokens are stored in browser local storage.
- The application uses the Flask development server and is not configured for production deployment or multiple production workers.

## Project Status

**Current Version:** VulnTrack v2 – AI Remediation

**Status:** AI-powered vulnerability tracking and remediation implementation.

### Implemented Features
- React/Vite frontend.
- Flask backend.
- SQLite database integration.
- JWT authentication and RBAC.
- Source-code and ZIP uploads.
- Semgrep-based vulnerability detection.
- Dependency auditing.
- Vulnerability tracking and assignment.
- Project access management.
- Audit activity and scan history.
- AI-powered remediation suggestions.
- Approval-based fix application.
- Automatic re-scanning after remediation.

### Future Enhancements
- Expand security-rule coverage.
- Add support for more programming languages.
- Improve vulnerability verification and remediation accuracy.
- Introduce production-grade database infrastructure.
- Implement distributed rate limiting.
- Add production deployment and containerization.
- Enhance reporting and security analytics.
- Integrate CI/CD security scanning workflows.

## Repository

**GitHub:** https://github.com/pranith2006-boop/KLH-CSE-2026-2027-B2-VTRS

## Academic Information

This project is developed as part of the **Software Oriented Architecture (SOA) Programming and Microservices course**.

## License

This project is developed for academic and educational purposes as part of the university curriculum.

---

**VulnTrack – Identify vulnerabilities, track security risks, and simplify remediation with AI.**
