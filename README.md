# 🛡️ Phish-Net

> **Threat intel + behavioral forensics + AI reasoning for phishing detection.**

Phish-Net is a full-stack phishing analysis lab designed for defenders, analysts, and curious builders. It combines static checks, external threat intelligence, browser-based behavioral analysis, and LLM-assisted reasoning into one workflow.

---

## Why Phish-Net

Phishing investigations usually require jumping between tools. Phish-Net consolidates that process into one platform:

- **URL Analysis** with feature extraction and risk scoring.
- **Email Analysis** for suspicious metadata and embedded artifacts.
- **Text Analysis** for social engineering signals.
- **QR Analysis** for QR payload and destination checks.
- **PCAP Analysis** for packet-level triage and network behavior insights.
- **External Threat Intel Integrations** (VirusTotal, Google Safe Browsing, OTX, PhishTank, etc.).
- **Behavioral Browser Analysis** for runtime observations and screenshots.
- **Report Generation** for investigation handoff.

---

## Architecture (High Level)

- **Frontend:** static HTML/CSS/JS dashboard (`frontend/`)
- **Backend:** FastAPI service (`backend/app.py`)
- **Analysis Engines:** custom analyzers for URL/email/text/QR/PCAP
- **Async Execution:** background tasks + real-time progress streaming

---

## Quick Start

### 1) Configure environment

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key

# External APIs
VIRUSTOTAL_API_KEY=your_key
GOOGLE_SAFE_BROWSING_API_KEY=your_key
ALIENVAULT_OTX_KEY=your_key
PHISHTANK_API_KEY=your_key

# Optional / stubbed integrations
OPSWAT_API_KEY=optional
CISCO_UMBRELLA_KEY=optional
```

### 2) Run with Docker (recommended)

This is the safer mode because behavioral analysis may actively visit suspicious pages.

```bash
docker-compose build
docker-compose up
```

### 3) Run locally (without Docker)

```bash
pip install -r backend/requirements.txt
cd backend
python app.py
```

Open `frontend/index.html` in your browser to use the dashboard.

---

## API Surface (selected)

- `POST /analyze/url`
- `POST /analyze/email`
- `POST /analyze/text`
- `POST /analyze/qr`
- `POST /analyze/pcap`
- `GET /task/{task_id}`
- `GET /task/{task_id}/stream`
- `GET /report/{task_id}/download`
- `GET /pcap/{filename}`

---

## Operational Notes

- For behavioral analysis, isolate runtime environments when possible.
- Treat uploaded samples and captured artifacts as sensitive evidence.
- Rotate API keys and avoid committing secrets.
- Prefer Docker or sandboxed hosts for untrusted content.

---
## Acknowledgement

Packet analysis idea (and files in `backend/pcap_utils/GeoIP` and `backend/pcap_utils/protocol`) have been adapted from `err0rgod/MidStalker`.

## LICENSE

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

## Welcome Invitation

This project welcomes new ideas that can be added to improve the detection, or add new features.
