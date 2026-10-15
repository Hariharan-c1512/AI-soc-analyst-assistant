# AI SOC Analyst Assistant

AI-assisted Security Operations Center platform: alert ingestion, Sigma detection,
ML severity prediction, MITRE ATT&CK mapping, and a local LLM + RAG pipeline for
incident summaries and remediation — all presented in a Streamlit dashboard.

**Stack:** Python (FastAPI) · Streamlit · Wazuh · SQLite/PostgreSQL · scikit-learn ·
Ollama (optional TinyLlama) · ChromaDB (optional)

## Quick Start (zero external dependencies)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Recommended) Train the severity ML model
python -m scripts.train_model --samples 2000

# 3. Seed the database with sample alerts
python -m scripts.seed_data --count 100

# 4. Start the backend (also auto-generates alerts every 30s)
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000

# 5. In a second terminal, start the dashboard
streamlit run frontend/dashboard.py
```

Open http://localhost:8501

## Modes

| Mode | `.env` setting | Requires |
|------|---------------|----------|
| `mock` ingestion | `INGESTION_MODE=mock` | Nothing — generates realistic alerts |
| `system` ingestion | `INGESTION_MODE=system` | Nothing — detects real events from journald (SSH brute force, sudo misuse, user changes) |
| `wazuh` ingestion | `INGESTION_MODE=wazuh` | Wazuh Manager and Indexer + Indexer credentials |
| `offline` LLM | `LLM_MODE=offline` | Nothing — template-based analysis |
| `ollama` LLM | `LLM_MODE=ollama` | `ollama pull tinyllama` + server |

### Manual attack testing (no Wazuh needed)

Simulate attacks instantly:
```bash
python -m scripts.inject_alert --list                 # see all attacks
python -m scripts.inject_alert --attack ransomware    # inject one
python -m scripts.inject_alert --attack ssh_bruteforce --count 5
```

OR detect real attacks on the machine (requires `INGESTION_MODE=system`):
```bash
# SSH brute force (target: localhost)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
# sudo misuse (run as a user, type wrong password)
sudo ls   # type wrong password 3x
# create a user
sudo useradd evil_user
```

## Connect a Real LLM (optional)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull tinyllama
ollama serve
```
Then set `LLM_MODE=ollama` in `.env`.

## Connect Wazuh (optional)

```bash
docker compose up -d
```
The backend searches alert documents through the Wazuh Indexer at
`https://localhost:9200`. Set `INGESTION_MODE=wazuh` and the matching
`WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, and `WAZUH_INDEXER_PASSWORD` values in
`.env`, then restart the backend. The included local Compose stack uses the
sample `admin` credentials; replace them for any non-local deployment. Set
`WAZUH_VERIFY_SSL=true` when using a certificate trusted by the backend.

## Project Layout

```
backend/app/        FastAPI app (ingester, sigma, ml, mitre, rag, llm, routers)
backend/sigma_rules/  Sigma YAML detection rules
frontend/           Streamlit dashboard
scripts/            train_model.py, seed_data.py
data/               SQLite DB, vector store, datasets
tests/              pytest suite
```

See the [project flow chart](docs/project-flowchart.md) for the ingestion,
enrichment, storage, and analyst interaction paths.
For a full component explanation and a timed four-person mentor presentation,
see the [mentor presentation guide](docs/mentor-presentation.md).

## API Endpoints

- `GET /alerts` — list/filter alerts
- `GET /alerts/{id}` — alert detail with full AI analysis
- `PATCH /alerts/{id}/status` — acknowledge/escalate/mark FP
- `POST /feedback` — analyst feedback (used for retraining)
- `POST /chat` — AI assistant Q&A
- `GET /stats`, `GET /health`, `GET /model-info`

Interactive docs at http://localhost:8000/docs
