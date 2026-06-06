# Mini SOC / IDS

A learning-oriented **Security Operations Center** in miniature: live packet capture, rule-based intrusion detection, MySQL storage, a FastAPI backend, and a React dashboard.

---

## Table of contents

1. [Architecture](#architecture)
2. [Project structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Setup](#setup)
5. [Running the full stack](#running-the-full-stack)
6. [Backend — collector & detector](#backend--collector--detector)
7. [Backend — REST API](#backend--rest-api)
8. [Frontend — dashboard](#frontend--dashboard)
9. [Database](#database)
10. [Scripts & utilities](#scripts--utilities)
11. [Test traffic](#test-traffic)
12. [Environment variables](#environment-variables)
13. [Known limitations](#known-limitations)

---

## Architecture

```text
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  collector      │────▶│   packets    │────▶│    detector     │
│  (Scapy sniff)  │     │   (MySQL)    │     │  (rule engine)  │
└─────────────────┘     └──────────────┘     └────────┬────────┘
                                                     │
                                                     ▼
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   frontend      │◀────│  api         │◀────│ alerts          │
│   (React)       │     │  (FastAPI)   │     │ alert_packets   │
└─────────────────┘     └──────────────┘     └─────────────────┘
```

**Data flow:** network packet → parse & insert → evaluate `detection_rules` → create/correlate alerts → expose via API → visualize in dashboard.

---

## Project structure

```text
miniSoc/
├── schemaMySql.sql          # MySQL schema (source of truth)
├── requirements.txt         # Python dependencies
├── .env.example             # MySQL credentials template
├── README.md                # This file
│
├── collector/               # Packet capture pipeline
│   ├── sniffer/
│   │   ├── capture.py       # Scapy live sniff loop
│   │   ├── parser.py        # Raw packet → PacketRecord
│   │   └── models.py        # PacketRecord, Protocol enum
│   ├── storage/
│   │   └── packet_repository.py
│   ├── run_live_soc.py      # ★ Main live pipeline (sniff + detect + alert)
│   ├── step1_print_packets.py
│   ├── step2_save_packets.py
│   └── step3_detect_packets.py
│
├── detector/                # Detection engine
│   ├── engine.py            # Rule evaluation (JSON conditions)
│   ├── alerts_repository.py # Alert create / correlate
│   ├── rules_repository.py
│   ├── packets_repository.py
│   └── models.py
│
├── api/                     # FastAPI (read-only)
│   ├── main.py
│   ├── routes/              # alerts, packets, rules, stats
│   └── services/            # SQL queries
│
├── frontend/                # React dashboard (Vite)
│   ├── src/
│   │   ├── pages/           # Dashboard, Alerts, Packets, Rules, Stats
│   │   ├── components/
│   │   └── services/api.js  # API client
│   ├── vite.config.js       # Dev proxy /api → :8000
│   └── package.json
│
├── shared/                  # Shared Python utilities
│   ├── db/
│   │   ├── config.py        # DatabaseSettings from .env
│   │   ├── connection.py    # get_connection, db_session, get_db
│   │   └── serialize.py     # MySQL rows → JSON
│   └── net/
│       └── ip.py            # IP string ↔ VARBINARY
│
└── scripts/
    ├── test_db_connection.py
    └── seed_detection_rules.py
```

---

## Prerequisites

| Requirement | Used for |
|-------------|----------|
| Python 3.11+ | Collector, detector, API |
| MySQL 8+ (or MariaDB) | Data storage |
| Node.js 18+ | Frontend dashboard |
| `sudo` (macOS/Linux) | Live packet capture |

---

## Setup

### 1. Database

```bash
mysql -u root -p < schemaMySql.sql
```

### 2. Python environment

From the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # edit MYSQL_* if needed
python scripts/test_db_connection.py
python scripts/seed_detection_rules.py
```

### 3. Frontend

```bash
cd frontend
npm install
cp .env.example .env               # optional; dev uses Vite proxy
cd ..
```

---

## Running the full stack

You need **three terminals** for the complete system.

### Terminal 1 — Live SOC pipeline

Captures packets, writes to MySQL, runs detection, creates/correlates alerts.

```bash
source .venv/bin/activate
sudo .venv/bin/python collector/run_live_soc.py --iface en0 --filter "ip"
```

Useful flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--iface` | Scapy default | Network interface (e.g. `en0`, `lo0`) |
| `--filter` | `ip` | BPF filter |
| `--correlate-window-secs` | `300` | Merge repeat alerts within N seconds |
| `--reload-rules-every` | `200` | Reload rules from DB every N packets |
| `--list-ifaces` | — | List interfaces and exit |

List interfaces:

```bash
python collector/run_live_soc.py --list-ifaces
```

Stop with **Ctrl+C**.

### Terminal 2 — API server

```bash
source .venv/bin/activate
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

- Swagger UI: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

### Terminal 3 — Dashboard

```bash
cd frontend
npm run dev
```

Open: **http://localhost:5173**

In development, the frontend proxies `/api/*` to FastAPI (see `frontend/vite.config.js`).

---

## Backend — collector & detector

### Live pipeline (`run_live_soc.py`)

Per packet:

1. **Parse** — extract IPs, ports, protocol, TCP flags, payload hash/preview
2. **Insert** into `packets`
3. **Evaluate** all enabled rules from `detection_rules`
4. **On match** — create a new alert or correlate into an existing open one (same rule + 5-tuple within time window)
5. **Commit** atomically (rollback on error)

### Step-by-step scripts (learning / debugging)

| Script | What it does |
|--------|----------------|
| `step1_print_packets.py` | Capture and print only |
| `step2_save_packets.py` | Capture → insert into `packets` |
| `step3_detect_packets.py` | Read packets from DB, print rule matches (no alert write) |

### Detection rules

Rules are stored in `detection_rules.conditions` as JSON:

```json
{
  "all": [
    { "field": "protocol", "op": "eq", "value": "tcp" },
    { "field": "dst_port", "op": "eq", "value": 22 }
  ]
}
```

Supported logic: `all` (AND), `any` (OR), `clause` (single).  
Operators: `eq`, `in`, `contains`, `not_contains`, `regex`, `gt`, `gte`, `lt`, `lte`.

Seed default rules:

```bash
python scripts/seed_detection_rules.py
```

---

## Backend — REST API

Read-only FastAPI layer. No authentication (MVP).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | API status |
| GET | `/alerts?limit=50` | Latest alerts (`last_seen_at` DESC) |
| GET | `/packets?limit=50` | Latest packets (`captured_at` DESC) |
| GET | `/rules` | All detection rules |
| GET | `/stats?top_ips=10` | Aggregated statistics |

### Example `/stats` response

```json
{
  "total_alerts": 12,
  "total_packets": 4500,
  "total_rules": 15,
  "enabled_rules": 14,
  "alerts_by_severity": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 8
  },
  "top_source_ips": [
    { "src_ip": "192.168.1.10", "alert_count": 5 }
  ]
}
```

---

## Frontend — dashboard

React + Vite, dark SOC-style UI.

### Pages

| Route | Content |
|-------|---------|
| `/` | Dashboard — totals, severity breakdown, charts |
| `/alerts` | Alert table (id, rule, severity, IPs, status, last seen) |
| `/packets` | Recent packets, auto-refresh every 5s |
| `/rules` | Detection rules with enabled/disabled status |
| `/stats` | Severity chart, top source IPs, alerts over time |

### Development

```bash
cd frontend
npm run dev
```

Requests go to `/api/...` → proxied to `http://127.0.0.1:8000`.

### Production build

```bash
cd frontend
npm run build
npm run preview
```

For a standalone build without the Vite proxy, set in `frontend/.env`:

```env
VITE_API_URL=http://127.0.0.1:8000
```

### Tech stack

- React 18 + React Router 6
- Vite 6
- Native `fetch` (no axios)
- Plain CSS (no UI framework)

---

## Database

Main tables (see `schemaMySql.sql`):

| Table | Purpose |
|-------|---------|
| `packets` | Captured network telemetry |
| `detection_rules` | IDS signatures / heuristics |
| `alerts` | Security events |
| `alert_packets` | Links alerts to triggering/related packets |
| `alert_actions` | Audit trail (created, acknowledged, …) |
| `users` | Reserved for future authentication |
| `detection_stats_hourly` | Reserved for future hourly stats |

Key column: `packets.payload_preview` — short text/hex preview of packet payload for signature rules.

---

## Scripts & utilities

| Script | Purpose |
|--------|---------|
| `scripts/test_db_connection.py` | Verify MySQL + table presence |
| `scripts/seed_detection_rules.py` | Upsert baseline detection rules |
| `collector/run_live_soc.py` | Full live pipeline |
| `collector/step1_print_packets.py` | Sniff only |
| `collector/step2_save_packets.py` | Sniff → DB |
| `collector/step3_detect_packets.py` | Offline detection test |

---

## Test traffic

With live SOC on `en0`:

```bash
ping -c 5 8.8.8.8              # ICMP rule
curl -v http://example.com/    # HTTP payload rule
nc -vz 127.0.0.1 22            # Port-based rules (SSH)
```

> **Note:** `curl http://localhost/...` uses the **loopback** interface (`lo0`), not Wi‑Fi (`en0`).  
> To capture localhost traffic: `--iface lo0`

Verify in MySQL:

```sql
SELECT id, title, severity, event_count, last_seen_at
FROM alerts ORDER BY id DESC LIMIT 10;

SELECT id, protocol, packet_size, LEFT(payload_preview, 40)
FROM packets ORDER BY id DESC LIMIT 10;
```

---

## Environment variables

Root `.env` (Python backend):

```env
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=
MYSQL_DATABASE=mini_soc
```

Frontend `frontend/.env` (optional):

```env
# Leave empty in dev (uses Vite proxy). Set for production builds.
VITE_API_URL=
```

---

## Known limitations

- No authentication on API or dashboard
- Signature-based detection only (no machine learning)
- Primarily IPv4 on a single selected interface
- Chart timelines use the latest N alerts from the API, not full historical data
- High-volume networks: consider reducing console output in the live pipeline

---

## License / usage

Educational project — suitable for portfolios, university labs, and SOC/IDS learning exercises.
