# Mini SOC / IDS

Sistema didattico di **Security Operations Center** in miniatura: cattura pacchetti, detection basata su regole, alert su MySQL, API REST e dashboard web.

## Architettura

```text
collector (Scapy)  →  packets (MySQL)
                         ↓
detector (regole)  →  alerts + alert_packets
                         ↓
api (FastAPI)      →  frontend (React)
```

| Cartella | Ruolo |
|----------|--------|
| `collector/` | Sniffer e pipeline live (`run_live_soc.py`) |
| `detector/` | Motore regole e gestione alert |
| `api/` | API read-only |
| `frontend/` | Dashboard React |
| `shared/` | Config DB, connessioni, serializzazione, IP |
| `scripts/` | Seed regole, test DB, migrazioni |

## Prerequisiti

- Python 3.11+
- MySQL 8+ (o MariaDB compatibile)
- Node.js 18+ (solo per il frontend)
- macOS/Linux: permessi root per sniff live (`sudo`)

## Setup iniziale

### 1. Database

Crea il database e le tabelle:

```bash
mysql -u root -p < schemaMySql.sql
```

Se il DB esisteva **prima** dell’aggiunta di `payload_preview`:

```bash
python scripts/migrate_payload_preview.py
```

### 2. Python

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # modifica MYSQL_* se serve
python scripts/test_db_connection.py
python scripts/seed_detection_rules.py
```

### 3. Frontend (opzionale)

```bash
cd frontend
npm install
cp .env.example .env
```

## Avvio — 3 terminali

### Terminale 1 — Pipeline live (sniff + detection + alert)

```bash
source .venv/bin/activate
sudo .venv/bin/python collector/run_live_soc.py --iface en0 --filter "ip"
```

Interfacce disponibili:

```bash
python collector/run_live_soc.py --list-ifaces
```

### Terminale 2 — API

```bash
source .venv/bin/activate
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

Documentazione: http://127.0.0.1:8000/docs

### Terminale 3 — Dashboard

```bash
cd frontend
npm run dev
```

Apri: http://localhost:5173

## Endpoint API

| Metodo | Path | Descrizione |
|--------|------|-------------|
| GET | `/health` | Stato API |
| GET | `/alerts?limit=50` | Ultimi alert (`last_seen_at` DESC) |
| GET | `/packets?limit=50` | Ultimi pacchetti (`captured_at` DESC) |
| GET | `/rules` | Regole detection |
| GET | `/stats` | Totali alert/pacchetti/regole, severità, top IP |

Esempio risposta `/stats`:

```json
{
  "total_alerts": 12,
  "total_packets": 4500,
  "total_rules": 15,
  "enabled_rules": 14,
  "alerts_by_severity": { "low": 10, "medium": 2 },
  "top_source_ips": [{ "src_ip": "192.168.1.10", "alert_count": 5 }]
}
```

## Script utili

| Script | Uso |
|--------|-----|
| `scripts/test_db_connection.py` | Verifica MySQL e tabelle |
| `scripts/seed_detection_rules.py` | Carica/aggiorna regole (idempotente) |
| `scripts/migrate_payload_preview.py` | Aggiunge colonna `payload_preview` se manca |
| `collector/step1_print_packets.py` | Solo sniff (no DB) |
| `collector/step2_save_packets.py` | Sniff → `packets` |
| `collector/step3_detect_packets.py` | Detection offline (solo print) |

## Generare traffico di test

Con il live SOC attivo su `en0`:

```bash
ping -c 5 8.8.8.8
curl -v http://example.com/
nc -vz 127.0.0.1 22
```

> `curl http://localhost/...` passa da **lo0**, non da `en0` — per vederlo usa `--iface lo0`.

## Variabili ambiente (`.env`)

```env
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=
MYSQL_DATABASE=mini_soc
```

## Struttura file principali

```text
schemaMySql.sql
collector/run_live_soc.py
detector/engine.py
detector/alerts_repository.py
api/main.py
shared/db/connection.py
frontend/src/pages/Dashboard.jsx
```

## Limitazioni note (MVP)

- Nessuna autenticazione API/dashboard
- Detection signature-based (no ML)
- Sniff principalmente IPv4 su interfaccia scelta
- Timeline grafici derivati dagli ultimi N alert in API, non storico completo

## Licenza / uso

Progetto educativo — adatta a portfolio e laboratori SOC/IDS.
