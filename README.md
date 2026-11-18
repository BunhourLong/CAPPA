# Cappa — Layer 7 Web Threat Monitoring & Response

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![NGINX](https://img.shields.io/badge/NGINX-1.27-009639?logo=nginx&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)

Cappa is a self-hosted security layer in front of a website or API. NGINX writes `access.log`; the security engine tails it, runs eight detectors, scores IP reputation and writes an NGINX blocklist. A FastAPI app serves an Angular dashboard to analysts, with events, alerts, reputation history and audit records stored in PostgreSQL 16.

---

## Key Features

- **Log monitoring** — tails NGINX `access.log` and parses each new line into an event.
- **8 detectors** — rate abuse, brute force, SQL injection, XSS, path probing, scraping, credential stuffing and user-agent rotation.
- **IP reputation** — five states (trusted, unknown, suspicious, throttled, blocked), score decay and an alert hold for non-safe alerts.
- **NGINX enforcement** — writes `deny` rules to an included blocklist; NGINX checks it every 2 seconds and reloads when it changes.
- **Analyst dashboard** — alert queue, status workflow, statistics and a geographic map.
- **GeoIP and ASN context** — MaxMind GeoLite2 City and ASN data for country, city, organisation and hosting-provider flags on map points.
- **IP controls** — block, unblock, trust, whitelist, suppress auto-blocking or force an unblock.
- **Audit records** — reputation transitions and analyst actions are stored in PostgreSQL.
- **Role-based access** — readonly, analyst and admin.
- **Compose stack** — one `docker compose up --build -d` starts NGINX, FastAPI, the engine and PostgreSQL, plus the companion site.

---

## Architecture

```
                        Internet / Attacker
                               │
                               ▼
                    ┌─────────────────────┐
                    │     NGINX (port 80) │
                    │  /       → site     │
                    │  /admin/ → admin    │
                    │  /siem/  → Cappa    │
                    │  blocklist include  │
                    │  access.log write   │
                    └──┬───────────────┬──┘
       /siem/ proxy    │               │ access.log (volume)
                       ▼               ▼
        ┌──────────────────────┐   ┌────────────────────────┐
        │ Cappa API (FastAPI)  │   │ Security Engine        │
        │ port 8000            │   │ LogMonitorService      │
        │ ─ dashboard UI       │   │ ─ tail access.log      │
        │ ─ alerts REST API    │   │ ─ parse log lines      │
        │ ─ IP control routes  │   │ ─ run 8 detectors      │
        │ ─ session auth       │   │ ─ score reputation     │
        │ ─ map data           │   │ ─ write blocklist ─────┼──► NGINX reload
        └──────────┬───────────┘   └───────────┬────────────┘
                   │                           │
                   └─────────────┬─────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │  PostgreSQL 16         │
                    │  ─ events              │
                    │  ─ alerts              │
                    │  ─ ip_reputations      │
                    │  ─ ip_reputation_      │
                    │    transitions (audit) │
                    │  ─ users, audit_logs   │
                    └────────────────────────┘
```

**Data flow:**

1. A request hits NGINX. NGINX logs it to `access.log` and applies the current blocklist.
2. `LogMonitorService` reads new log lines from the file (starting at the end) and parses each one into an `HTTPLogEvent`.
3. `SecurityEngine` runs all eight detectors against the event and persists the event and any alerts.
4. `EnforcementService` recalculates the IP's reputation and rewrites the blocklist when its state changes.
5. NGINX checks the blocklist every 2 seconds and runs `nginx -s reload` when it changes.
6. The UI polls the JSON API: the alerts page every 5 seconds, the dashboard and map every 15 seconds.

---

## Domain & Routing

NGINX handles all path routing. The host it answers on comes from a single environment variable, so switching environments does not require editing the NGINX config.

| Path | Destination | Access |
|---|---|---|
| `/` | BookMark-Publisher (Express) | Public site |
| `/admin/` | BookMark-Publisher admin panel | Proxied to the companion app |
| `/siem` | Redirects to `/siem/login` | Public |
| `/siem/` | Cappa dashboard and API | Public shell; data needs a session |
| `/health` | NGINX | Public, returns `ok` |

Public routes are the SPA shell (`/siem/`, `/siem/login`, `/siem/dashboard`, `/siem/denied`, and `/siem/alerts` when the request accepts HTML), the login/logout endpoints and `/siem/health`. Data endpoints under `/siem/api/` require a session, apart from login and logout:

- **readonly** — dashboard, statistics and map.
- **analyst** (and admin) — alert list, alert detail, alert status changes, IP block/unblock.
- **admin** — IP trust/whitelist/suppression/force-unblock controls and deleting all alerts.

`POST /siem/ingest-event` returns 404 at the edge. The API's `/ingest-event` route is for internal senders and requires the token set in `SIEM_INGEST_TOKEN`.

To change the domain, edit one line in `stack/.env`:

```bash
# Local development
NGINX_HOST=localhost

# EC2 / production
NGINX_HOST=capnova.duckdns.org
```

Then recreate NGINX: `docker compose up -d --force-recreate nginx`.

---

## Quick Start (Local — Docker Compose)

### Prerequisites

- Docker and Docker Compose v2
- The BookMark-Publisher repository checked out as a sibling directory (the stack builds it)
- GeoLite2 City and ASN databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`), downloaded free from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) into `data/`

### Steps

```bash
# 1. Clone this repository and its companion site side by side
git clone https://github.com/BunhourLong/CYBERSIEM.git cybersiem
git clone <bookmark-publisher-repository> bookmark-publisher

# Required layout:
# FYP/
#   cybersiem/          ← this repository (stack/ lives inside)
#   bookmark-publisher/

# 2. Create the environment file
cd cybersiem/stack
cp .env.example .env

# 3. Edit .env before starting:
#    SIEM_SESSION_SECRET   a random value of at least 32 bytes
#    SIEM_ADMIN_PASSWORD   at least 12 characters
#    POSTGRES_PASSWORD     a real password, also used in DATABASE_URL
#    Generate secrets with: openssl rand -base64 32

# 4. Build and start
docker compose up --build -d

# 5. Verify
curl http://localhost/health        # → ok
curl http://localhost/siem          # → 301 to /siem/login
```

Open `http://localhost/siem/login` and sign in with `SIEM_ADMIN_USERNAME` and `SIEM_ADMIN_PASSWORD`. The admin account is seeded at API startup only when the password is at least 12 characters; the API refuses to start while `SIEM_SESSION_SECRET` is a placeholder or shorter than 32 bytes.

### Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NGINX_HOST` | `localhost` | Host NGINX answers on; change it for EC2 or a custom domain |
| `SIEM_SESSION_SECRET` | `change_me` | HMAC secret for session cookies. Must be 32+ bytes and not a placeholder; the API refuses to start otherwise |
| `SIEM_ADMIN_USERNAME` | `admin` | Admin account created at first startup |
| `SIEM_ADMIN_PASSWORD` | `change_me_min_12_chars` | Must be 12+ characters, or the admin seed is skipped |
| `SIEM_INGEST_TOKEN` | empty | Bearer token for `/ingest-event`; empty disables the route |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | `cybersiem`, `cybersiem`, `change_me` | PostgreSQL credentials; change the password |
| `DATABASE_URL` | `postgresql://cybersiem:change_me@postgres:5432/cybersiem` | Must match the `POSTGRES_*` settings |
| `TRUSTED_PROXY_CIDRS` | empty | Comma-separated CIDRs of load balancers in front of NGINX; no wider than /8 (IPv4) or /32 (IPv6) |
| `GEOIP_DB_PATH`, `GEOIP_ASN_DB_PATH` | `/data/GeoLite2-City.mmdb`, `/data/GeoLite2-ASN.mmdb` | Container paths to the MaxMind databases |
| `RATE_ABUSE_THRESHOLD`, `RATE_ABUSE_WINDOW_SECONDS` | `30`, `60` | Dynamic requests per IP per window before a `rate_abuse` alert. Successful static assets do not count |
| `SESSION_SECURE` | `false` | Set to `true` only after HTTPS is configured |

`stack/.env.example` documents the remaining options, including the reputation tuning variables. On Docker Desktop, published ports can make every client appear as the gateway; send a request from another machine and confirm its IP is the first field of NGINX's `access.log`.

---

## EC2 Deployment

```bash
# 1. Provision: Ubuntu 24.04, t3.small+, ports 22 and 80 open

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu && newgrp docker

# 3. Clone both repositories
mkdir ~/apps && cd ~/apps
git clone https://github.com/BunhourLong/CYBERSIEM.git cybersiem
git clone <bookmark-publisher-repository> bookmark-publisher

# 4. Refresh the GeoIP databases if needed
scp GeoLite2-*.mmdb ubuntu@<EC2_IP>:~/apps/cybersiem/data/

# 5. Create .env
cd ~/apps/cybersiem/stack
cp .env.example .env
nano .env
# Set:
#   NGINX_HOST=<your domain>
#   SIEM_SESSION_SECRET=<openssl rand -base64 32>
#   SIEM_ADMIN_PASSWORD=<12+ character password>
#   POSTGRES_PASSWORD=<strong password> and the matching DATABASE_URL
#   EXPRESS_ADMIN_PASSWORD=<strong password>
#   SECURITY_ADMIN_TOKEN=<openssl rand -hex 32>
#   SECURITY_LAB_MODE=false

# 6. Point the domain at the EC2 IP

# 7. Launch and follow the logs
docker compose up --build -d
docker compose logs -f
```

---

## Detection Capabilities

`build_detectors()` returns the eight detectors below. They implement `Detector.evaluate(HTTPLogEvent)` and run in sequence for each parsed line. The behavioural detectors keep per-IP sliding windows.

| Detector | Alert type | What it catches | Thresholds | Severity |
|---|---|---|---|---|
| **BruteForceDetector** | `brute_force` | Failed logins on `/login` | 5 failures (401/403) in 300 s | Medium |
| **RateAbuseDetector** | `rate_abuse` | High dynamic-request volume from one IP (static assets excluded) | 30 requests in 60 s (`RATE_ABUSE_*`) | Medium |
| **PayloadDetector** | `payload_sqli` | SQL injection in the decoded request target or user agent: `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `information_schema`, SQL comment terminators | Pattern match | High |
| **XSSPayloadDetector** | `xss_payload` | XSS signatures such as `<script>`, event handlers, `javascript:`, `<iframe>`, `eval(`, `document.cookie` | 13 patterns | High |
| **CredentialStuffingDetector** | `credential_stuffing` | Auth failures spread across endpoints or user agents | 10 failures in 300 s, with 2+ endpoints or 3+ user agents | High if 3+ user agents, otherwise Medium |
| **PathProbeDetector** | `404_spray` / `path_probe` | 404 spray and broad endpoint enumeration | 15 404s in 120 s, or 20 requests across 10+ unique paths in 120 s | Medium |
| **ScrapingDetector** | `scraping` | Successful GET requests to many distinct endpoints | 50 GETs across 30+ unique endpoints in 60 s | Medium |
| **UserAgentRotationDetector** | `user_agent_rotation` | User-agent cycling and generic bot clients | 5 distinct user agents in 300 s | High if a generic bot user agent is present, otherwise Medium |

Rate-abuse limits are configurable with `RATE_ABUSE_THRESHOLD` and `RATE_ABUSE_WINDOW_SECONDS` (defaults: 30 dynamic requests in 60 s) in both the API and the security engine. Successful static asset requests do not count: Angular's hashed bundles at the app root (`main-*.js`, `styles-*.css`, `polyfills-*.js` and lazy `chunk-*.js`) with or without the `/siem/` mount, and files under asset directories. Missing or error responses, and ambiguous server-side names such as `x.php.js`, still count.

### Reputation Scoring

Each active alert contributes its base weight to the IP's score. Alerts marked safe stop contributing; `lifetime_score` keeps the historical total. A repeat active alert within 15 minutes of the previous active alert counts 1.35× its base weight. Scores decay at **8 points per hour** after a 15-minute grace period.

| Score | State |
|---|---|
| < 10 | trusted |
| 10–24 | unknown |
| 25–44 | suspicious |
| 45–69 | throttled |
| ≥ 70 | blocked |

| Alert type | Weight |
|---|---|
| `payload_sqli` | 35 |
| `credential_stuffing` | 25 |
| `xss_payload` | 18 |
| `path_probe` | 12 |
| `scraping` | 12 |
| `rate_abuse` | 10 |
| `brute_force` | 10 |
| `404_spray` | 10 |
| `user_agent_rotation` | 8 |

**Blocking rules:**

- **Alert hold.** An unresolved or malicious alert with weight ≥ 20, or any high-severity alert, holds the IP in `blocked` with no timer until every such alert is marked safe. A single XSS or SQL injection alert therefore blocks until it is marked safe.
- **Timed block.** Three active alerts with weight ≥ 10 within 15 minutes, or a score of 70 or more, blocks the IP for **30 minutes**. One brute-force alert (five failures) does not block; three within 15 minutes do.
- **Cooldown.** After a timed block expires, the IP enters a **30-minute cooldown**. Alerts from before the release do not re-block it, but fresh repeat offences can.
- **Overrides.** A manual block has no timer. Trust or whitelist sets the state to `trusted`. Admin force-unblock overrides an alert hold for a suppression window.

The default thresholds, weights and durations can be overridden with `REPUTATION_*` variables. State changes and overrides are recorded in `ip_reputation_transitions`; analyst actions are recorded in `audit_logs`.

### Analyst Actions

From the dashboard:

- Mark alerts as **unresolved**, **safe** or **malicious**.
- **Block** an IP manually with a reason, or **unblock** it. Unblocking is refused while an alert hold is active; admins can force an unblock instead.
- **Trust** or **whitelist** known-good IPs.
- **Suppress auto-blocking** temporarily, or **clear** an override.

Analysts can view alerts and block/unblock IPs. Trust, whitelist, suppression and force-unblock controls are admin-only, as is deleting all alerts.

---

## Tech Stack

| Layer | Technology |
|---|---|
| API / UI backend | Python 3.12, FastAPI, Uvicorn |
| Database | PostgreSQL 16, psycopg3 |
| Reverse proxy | NGINX 1.27 (Alpine) |
| GeoIP | MaxMind GeoLite2 (City + ASN) |
| Data validation | Pydantic v2 |
| Containerisation | Docker, Docker Compose v2 |
| Frontend | Angular 22 (standalone components, signals), Leaflet, Vitest |

---

## Development

Prerequisites: **Task 3**, **uv**, **Node 24** and **Docker**. The scanners are pinned in `Taskfile.yml`, so nothing else needs installing.

```bash
task check      # lint, Python tests, detection corpus, frontend tests and build
task test       # Python tests (pytest)
task eval       # replay the labelled detection corpus
task security   # run every security scanner
task fmt        # format Python and frontend code
```

`task test` accepts pytest arguments, for example `task test -- tests/unit/test_detectors.py`. `task eval` replays `tests/corpus` through the detectors and fails if a benign line would be blocked; it must stay green. Commits follow Conventional Commits.

---

## Frontend Development

The UI lives in `frontend/` (Angular 22). Each screen is a standalone component with its own `.html`, `.ts` and `.css` files; shared styles are in `frontend/src/styles.css`. The Docker build compiles the UI into the API image, so `docker compose up` needs nothing extra.

For live reload, start the API on `http://localhost:8000` (the proxy target in `frontend/proxy.conf.json`) and start the dev server:

```bash
cd frontend
npm ci
npm start          # http://localhost:4200
npm test           # unit tests (Vitest)
npm run build      # production bundle → frontend/dist/cappa/browser
```

The UI talks to FastAPI through relative JSON endpoints under `/api/`: `/api/auth/*`, `/api/ui/dashboard`, `/api/ui/map-points`, `/api/ui/alerts`, `/api/alerts/{id}/status`, `/api/blocked-ips` and `/api/ip-controls`.

---

## Folder Structure

```
cybersiem/
├── data/                        # GeoLite2 City and ASN databases
├── docker/                      # Dockerfiles and PostgreSQL init SQL
│   ├── api.Dockerfile
│   ├── security_engine.Dockerfile
│   └── postgres/init.sql        # Schema: events, alerts, reputations, transitions, users, audit
├── frontend/                    # Angular UI (served by the FastAPI container)
│   └── src/app/
│       ├── core/                # API client, session, guards, shared helpers
│       ├── shared/app-header/   # Top bar
│       └── pages/               # login, dashboard (+ attack-map), alerts, denied
├── scripts/                     # Admin bootstrap and helper scripts
├── src/
│   ├── api/                     # FastAPI app (main.py, auth.py, schemas.py)
│   ├── core/                    # HTTPLogEvent models, GeoIP helpers
│   └── security_engine/         # Engine, log tail, parser, detectors, reputation, repository
├── stack/                       # Docker Compose deployment config
│   ├── docker-compose.yml
│   ├── nginx/nginx.conf.template  # NGINX config; NGINX_HOST substituted at startup
│   └── .env.example             # Documented template — copy to .env and fill in
└── tests/                       # Unit tests and the detection corpus
```

---

## Security Notes

- `SIEM_SESSION_SECRET` must be at least 32 bytes and must not contain a placeholder such as `change_me`; the API refuses to start otherwise. Generate it with `openssl rand -base64 32`.
- `SIEM_ADMIN_PASSWORD` must be at least 12 characters, or no admin account is seeded. Change every `change_me` value before exposing the stack.
- Set `SESSION_SECURE=true` after HTTPS is configured.
- Leave `API_DOCS_ENABLED` unset or `false` in production; interactive docs are off by default.
- If you run the companion BookMark-Publisher app, set `EXPRESS_ADMIN_PASSWORD` and `SECURITY_ADMIN_TOKEN`, and set `SECURITY_LAB_MODE=false` for a hardened deployment.
- Restrict port 22 to your own IP in the EC2 security group.
- The blocklist volume is shared between NGINX and the security engine; do not expose it outside the stack.

---

## Roadmap

- [ ] HTTPS via Certbot / Let's Encrypt auto-renewal
- [ ] Email / webhook alerting on high-severity detections
- [ ] ML-based anomaly scoring alongside rule-based detectors
- [ ] Multi-tenant / SaaS reverse proxy mode
- [ ] Slack / Discord notification integrations
- [ ] SIEM export (CEF / syslog / JSON stream)
- [ ] Granular RBAC with per-analyst audit logs
- [ ] Alert correlation across multiple IPs (campaign detection)
- [ ] Kubernetes deployment manifests

---

## License

No license has been chosen yet; all rights reserved.

> Built as a Final Year Project (2025–2026). Bunhour Long · Student ID: 2023145 · Supervisor: Chandan Mukherjee
