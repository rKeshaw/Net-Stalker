# 🛡️ Net-Stalker
> **Phishing detection and network forensics in one place.**

Net-Stalker is a self-hosted analysis platform for investigating phishing threats. It runs static heuristics, external threat intelligence lookups, headless browser behavioral analysis, live packet capture, and LLM-assisted verdicts against URLs, emails, raw text, QR codes, and PCAP files — then ties the results into a single investigative workspace.

---

## What It Does

Phishing investigations typically involve juggling four or five separate tools. Net-Stalker consolidates the core workflow:

- **URL Analysis** — domain age, SSL state, redirect chain, geo-IP hop tracing, form detection, and full behavioral execution in a headless browser.
- **Email Analysis** — EML parsing, SPF/DKIM checks, reply-to mismatch detection, link and attachment triage.
- **Text Analysis** — social engineering signal extraction from raw message content.
- **QR Code Forensics** — QR payload decoding, URL unfurling through redirect chains, and destination reputation checks. Detects quishing attempts embedded in page screenshots during behavioral analysis.
- **PCAP Analysis** — protocol distribution, traffic flow, DNS/HTTP statistics, per-IP geo mapping, and a filterable packet table.
- **External Threat Intelligence** — parallel lookups against VirusTotal, Google Safe Browsing, AlienVault OTX, and PhishTank, with aggregated verdicts.
- **Behavioral Analysis** — Playwright-driven browser session with network traffic inspection, honeypot credential submission to detected login forms, and exfiltration detection.
- **Live Packet Capture** — optional Scapy-based capture running alongside the browser session, automatically analyzed and available for download.
- **Report Generation** — PDF forensic reports with screenshot evidence, hop chain, honeypot results, and PCAP summary.

---

## Architecture

```
┌─────────────────────────────────┐     ┌───────────────────────────┐
│  Frontend (static HTML/CSS/JS)  │────▶│  Backend (FastAPI)        │
│  frontend/                      │     │  backend/app.py           │
│                                 │     │                           │
│  - phishing.html (URL/email/    │     │  Analysis engines:        │
│    text/QR workspace)           │     │  - analyzer.py            │
│  - packet.html (PCAP workspace) │     │  - email_analyzer.py      │
│  - script.js (SSE streaming,    │     │  - behavioral_analyzer.py │
│    chart rendering, filters)    │     │  - qr_analyzer.py         │
└─────────────────────────────────┘     │  - pcap_analyzer.py       │
                                        │  - llm_analyzer.py        │
                                        │  - external_apis.py       │
                                        │  - report_generator.py    │
                                        └────────────┬──────────────┘
                                                     │
                                        ┌────────────▼──────────────┐
                                        │  Browserless (Chromium)   │
                                        │  Remote Playwright WS     │
                                        └───────────────────────────┘
```

URL analyses run asynchronously. The backend creates a task, a background coroutine runs the full pipeline (feature extraction → behavioral → external APIs → LLM), and the frontend streams real-time progress via SSE. Email and text analyses are synchronous, with any extracted URLs queued as background deep-scan tasks.

---

## Quick Start

### 1. Configure environment

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key

# External threat intelligence (all optional, but more keys = better coverage)
VIRUSTOTAL_API_KEY=your_key
GOOGLE_SAFE_BROWSING_API_KEY=your_key
ALIENVAULT_OTX_KEY=your_key
PHISHTANK_API_KEY=your_key

# Stubbed integrations (reserved for future use)
OPSWAT_API_KEY=optional
CISCO_UMBRELLA_KEY=optional
```

The platform functions without external API keys — those checks will be skipped. The only hard requirement for full analysis is `GROQ_API_KEY`.

### 2. Run with Docker (recommended)

Behavioral analysis actively visits potentially malicious pages. Docker provides isolation and handles the NET_ADMIN/NET_RAW capabilities required for live packet capture.

```bash
docker-compose build
docker-compose up
```

Open `frontend/index.html` in your browser.

### 3. Run locally

```bash
pip install -r backend/requirements.txt
playwright install chromium
cd backend
python app.py
```

Note: live packet capture requires root or equivalent privileges when running locally. Without them, packet capture will fail gracefully and the rest of analysis continues.

---

## GeoIP Database

PCAP geo-mapping and URL hop geolocation require a MaxMind GeoLite2-City database. Download it from [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free registration) and place the `.mmdb` file at:

```
backend/pcap_utils/GeoIP/GeoLite2-City.mmdb
```

Geo features are silently skipped if the file is absent.

---

## API Surface

```
POST   /analyze/url                  URL analysis (async by default)
POST   /analyze/email                EML file analysis
POST   /analyze/text                 Raw text analysis
POST   /analyze/qr                   QR code image analysis
POST   /analyze/pcap                 PCAP file analysis

GET    /task/{task_id}               Poll task status and result
GET    /task/{task_id}/stream        SSE stream of real-time progress
GET    /report/{task_id}/download    Generate and download PDF report
GET    /screenshot/{filename}        Serve captured page screenshot
GET    /pcap/{filename}              Download captured PCAP file
GET    /apis                         List configured external API status
GET    /health                       Liveness probe
```

Full request/response shapes are visible in the FastAPI auto-docs at `http://localhost:8000/docs`.

---

## Configuration

All runtime settings are controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOW_ORIGINS` | `*` | Comma-separated allowed origins |
| `MAX_UPLOAD_SIZE_BYTES` | `10485760` | Max file upload size (10 MB) |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit rolling window |
| `RATE_LIMIT_MAX_REQUESTS` | `30` | Max requests per IP per window |
| `PLAYWRIGHT_WS_ENDPOINT` | (none) | Remote Browserless WebSocket URL; local Chromium used if unset |
| `LOG_LEVEL` | `INFO` | Python log level |
| `LOG_FILE` | `/tmp/net-stalker/app.log` | Rotating log file path |

---

## Notes on Deployment

- The service has no authentication layer. Do not expose it to the public internet as-is.
- The backend container runs as root with `NET_ADMIN` and `NET_RAW` capabilities for packet capture. Scope access accordingly.
- Task results are held in memory and evicted after 60 minutes. Screenshots and PCAP files persist under `/tmp` until manually cleared.
- The frontend `API_URL` is hardcoded to `http://localhost:8000` in `script.js`. Change this if deploying the frontend separately or behind a reverse proxy.

---

## Acknowledgements

Packet analysis implementation and the files under `backend/pcap_utils/GeoIP/` and `backend/pcap_utils/protocol/` were adapted from [`err0rgod/MidStalker`](https://github.com/err0rgod/MidStalker).

---

## License

MIT. See [LICENSE](LICENSE) for details.

---

Contributions are welcome — new detection techniques, additional threat intel integrations, or improvements to existing analyzers.
