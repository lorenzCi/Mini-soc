# Mini SOC Dashboard (React)

## Prerequisiti

- Node.js 18+
- API FastAPI in esecuzione su `http://127.0.0.1:8000`

## Avvio in sviluppo

```bash
cd frontend
npm install
npm run dev
```

Apri http://localhost:5173 — le richieste `/api/*` sono in proxy verso FastAPI (vedi `vite.config.js`).

## Produzione locale

```bash
npm run build
npm run preview
```

Imposta `VITE_API_URL=http://127.0.0.1:8000` in `.env` se servi il build senza proxy.

## Pagine

| Route | Contenuto |
|-------|-----------|
| `/` | Dashboard — KPI, severità, grafici |
| `/alerts` | Tabella alert |
| `/packets` | Pacchetti recenti (refresh 5s) |
| `/rules` | Regole detection |
| `/stats` | Grafici severità, IP, timeline |
