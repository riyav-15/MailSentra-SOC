# MailSentra SOC (PhishGuard SOC)

MailSentra SOC (originally developed as PhishGuard SOC) is an enterprise defensive cybersecurity platform designed for suspicious phishing email reporting, automated static indicator extraction, rule-based risk scoring, SOC incident triage, campaign correlation, audit logging, and forensic PDF reporting.

---

## 1. Problem Statement

Organizations face constant phishing and social engineering attacks. Employees frequently forward suspicious emails through informal or unmonitored channels, leading to delayed triaging, lost evidence, and lack of visibility. 

MailSentra SOC provides a centralized platform where:
- Employees can quickly submit suspicious `.eml` files, raw email headers/text, or QR code screenshots.
- The platform executes a zero-trust static analysis pipeline to extract Indicators of Compromise (IOCs) and calculate risk without visiting untrusted links or executing payloads.
- SOC analysts receive an enriched, explainable incident queue with MITRE ATT&CK mappings, containment playbooks, and forensic PDF generation.
- Security administrators can configure detection rule weights, monitor threat campaigns, manage brand watchlists, and review system audit logs.

---

## 2. Core Features

- **Role-Based Access Control (RBAC)**: Distinct workflows and views for `employee`, `analyst`, and `admin` roles, backed by secure JWT tokens.
- **Zero-Trust Static Analysis**: Safe parsing of headers, MIME trees, display names, email addresses, and attachment metadata without external execution.
- **Authentication Header Inspection**: Parses SPF, DKIM, and DMARC results (`fail`, `softfail`, `temperror`, `permerror`) directly from message headers.
- **Suspicious URL & Domain Heuristics**: Detects URL shorteners, raw IP hosts, suspicious TLDs, mismatched anchor text vs. href targets, and punycode/IDN homographs.
- **Brand Impersonation & Typo-Squatting Detection**: Levenshtein edit distance and homoglyph normalization algorithms match targets against an admin-managed Brand Watchlist.
- **Quishing (QR Phishing) Detection**: Local, offline QR payload extraction using OpenCV/Pillow to decode hidden URLs without making network requests.
- **BEC & Payment Fraud Workflows**: Specialized heuristics for wire transfer updates, invoice alterations, and executive impersonation with an integrated verification checklist.
- **Campaign Correlation**: Automatically clusters incoming incidents across multiple employees based on subject similarity, sender domains, attachment hashes, and time windows.
- **MITRE ATT&CK & NIST CSF Mapping**: Maps triggered phishing indicators to industry frameworks (e.g., T1566.001, T1566.002).
- **Incident Response & Playbooks**: Structured SOC triage queue, analyst notes, verdict suggestions, SOAR-style containment action simulators, and exportable PDF incident reports.
- **Executive & SOC Dashboards**: Real-time visualization of queue metrics, severity distributions, response timing, and targeted enterprise brands.

---

## 3. Technology Stack

- **Backend**:
  - Framework: Python 3.12, FastAPI, Pydantic v2
  - Database & ORM: PostgreSQL 16, SQLAlchemy 2.0, Alembic migrations
  - Authentication: JWT (`python-jose`), bcrypt password hashing (`passlib`)
  - Testing & Quality: `pytest`, `httpx`
  - Forensics & Media: ReportLab (PDF generation), OpenCV / Pillow / qrcode (offline QR analysis)
- **Frontend**:
  - Framework: React 18, Vite, React Router v6
  - Styling & UI: Tailwind CSS, Lucide React icons
  - Charts & Visualizations: Recharts
  - HTTP Client: Axios
- **DevOps & Deployment**:
  - Containerization: Docker, Docker Compose
  - Environment: Cross-platform `.env` configuration

---

## 4. Repository Structure

```text
MailSentra-SOC/
├── backend/
│   ├── alembic/              # Database migration scripts
│   │   ├── versions/         # Migration revisions (0001 - 0004)
│   │   └── env.py            # Alembic runtime environment
│   ├── app/
│   │   ├── routers/          # FastAPI API endpoints (auth, reports, incidents, etc.)
│   │   ├── services/         # Core business logic (email_analyzer, risk_engine, etc.)
│   │   ├── tests/            # Automated test suite (pytest)
│   │   ├── auth.py           # Authentication dependencies & RBAC
│   │   ├── database.py       # SQLAlchemy engine & session factory
│   │   ├── main.py           # Application factory & startup hooks
│   │   ├── models.py         # SQLAlchemy ORM data models
│   │   ├── schemas.py        # Pydantic request/response schemas
│   │   └── security.py       # Password hashing & JWT token configuration
│   ├── alembic.ini           # Alembic configuration
│   ├── Dockerfile            # Container definition for FastAPI backend
│   └── requirements.txt      # Python package dependencies
├── frontend/
│   ├── src/
│   │   ├── components/       # Reusable UI components (Layout, StatCard, Badge, etc.)
│   │   ├── context/          # Authentication context & provider
│   │   ├── pages/            # View pages (Dashboard, Incidents, SubmitReport, etc.)
│   │   ├── services/         # Axios API clients
│   │   ├── App.jsx           # Root route configuration
│   │   └── main.jsx          # React DOM entry point
│   ├── Dockerfile            # Container definition for React frontend
│   ├── package.json          # Node.js dependencies & scripts
│   ├── tailwind.config.js    # Tailwind CSS configuration
│   └── vite.config.js        # Vite bundler configuration
├── samples/                  # Benign test .eml email samples for demonstrations
├── .env.example              # Documented environment variables template
├── .gitignore                # Git ignore rules
├── docker-compose.yml        # Multi-container orchestration (Postgres, Backend, Frontend)
└── README.md                 # Project documentation
```

---

## 5. Environment Configuration

1. Copy the example environment file to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Review `.env` and configure values as needed:
   - `DATABASE_URL`: Connection string for PostgreSQL (e.g., `postgresql+psycopg://phishguard:phishguard_password@localhost:5432/phishguard`).
   - `JWT_SECRET_KEY`: A cryptographically secure random string used to sign session tokens.
   - `CORS_ORIGINS`: Origins permitted to connect to the backend (default: `http://localhost:5173,http://127.0.0.1:5173`).
   - `REPORT_DIR`: Local filesystem directory for generated forensic PDF reports.
   - `VITE_API_URL`: Backend URL for frontend network requests (default: `http://localhost:8000`).

---

## 6. Database Configuration & Migrations

The database models are managed via **SQLAlchemy 2.0** and version-controlled using **Alembic**.

### Running Migrations Manually
When running the application outside Docker against a PostgreSQL or SQLite database:

```bash
cd backend
# Run all migration revisions to set up tables and relationships
alembic upgrade head
```

### Seed Data
Upon initial startup, the backend automatically seeds default detection rules, supported brand profiles, and initial test user accounts.

Default demo credentials:

| Role | Email | Password |
|---|---|---|
| **Admin** | `admin@phishguard.local` | `AdminPass123!` |
| **SOC Analyst** | `analyst@phishguard.local` | `AnalystPass123!` |
| **Employee** | `employee@phishguard.local` | `EmployeePass123!` |

---

## 7. Running the Application

### Option A: Using Docker Compose (Recommended)

To launch the complete multi-container stack (PostgreSQL database, FastAPI backend, and React frontend):

```bash
# 1. Ensure .env is created
cp .env.example .env

# 2. Build and launch all services
docker compose up --build
```

Access points:
- **Frontend Web Application**: [http://localhost:5173](http://localhost:5173)
- **Backend API & Health**: [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option B: Running Manually (Local Development)

#### 1. Backend Setup
```bash
cd backend

# Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations (or use SQLite for rapid local prototyping)
# Windows:
set DATABASE_URL=sqlite:///./phishguard.db
set JWT_SECRET_KEY=local-dev-secret-key-12345
# Linux/macOS:
# export DATABASE_URL="sqlite:///./phishguard.db"
# export JWT_SECRET_KEY="local-dev-secret-key-12345"

alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 2. Frontend Setup
```bash
cd frontend

# Install Node modules
npm install

# Start Vite development server
npm run dev
```

---

## 8. Automated Testing

The backend includes a `pytest` test suite covering safe email parsing, header detection, risk scoring thresholds, campaign clustering, and incident ingestion:

```bash
cd backend

# Run the test suite
pytest
```

To run a quick one-line sanity check on the email parser without pytest:
```bash
cd backend
python -c "from app.services.email_analyzer import parse_email, calculate_risk_score; raw=open('../samples/fake_password_reset.eml').read(); parsed=parse_email(raw); print(calculate_risk_score(parsed))"
```

---

## 9. Integrations Requiring External Credentials

While the core static analysis, Quishing decoder, and rule engine run **100% locally and offline without external dependencies**, the following optional enterprise integrations require third-party credentials:

| Integration / Feature | Purpose | Required Credentials / Configuration |
|---|---|---|
| **Live Threat Intel Lookups** | Querying real-time reputation for IPs, domains, and hashes | VirusTotal API Key, AbuseIPDB API Key (Configured under Admin Integrations) |
| **Enterprise SSO / SAML** | Single Sign-On corporate identity synchronization | Identity Provider Metadata URL, Client ID, Client Secret (Okta / Azure AD / Google Workspace) |
| **Email Gateway / M365 Ingestion** | Ingesting user reports directly from Outlook or Google reporting buttons | Microsoft Graph API Client ID / Tenant Secret, or Google Workspace Service Account JSON |
| **SIEM Forwarding Connector** | Exporting incident events and IOCs to enterprise SIEMs | Splunk HEC Token / Webhook URL, Elasticsearch Endpoint, or Syslog Server Host/Port |

*(Note: In the absence of external credentials, all integration screens operate in safe simulation mode.)*

---

## 10. Security Disclaimer

MailSentra SOC is built exclusively for authorized defensive security engineering, educational analysis, and SOC operations. It does not generate phishing campaigns, execute untrusted binaries, collect live user passwords, or make outbound connection attempts to hostile servers.
