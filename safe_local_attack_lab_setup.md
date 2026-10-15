# One-Laptop Local Log Lab

This lab uses only this laptop, the project's existing Python environment, and its built-in system-log ingestion. It does not require Docker, another machine, external APIs, Hydra, or a vulnerable web app.

## What it does

The project polls the local system journal, recognizes selected events such as sudo authentication failures, then sends detections through the normal alert pipeline. In this setup, the laptop is both the event source and the SOC host.

```mermaid
flowchart LR
    U[You on this laptop] -->|Local sudo test| J[Linux system journal]
    J -->|journalctl polling| I[Project system-log ingester]
    I --> P[Sigma / ML / MITRE / offline analysis]
    P --> D[Dashboard at localhost:8501]
```

## 1. Configuration

The project's `.env` should contain:

```env
INGESTION_MODE=system
LLM_MODE=offline
```

`system` reads local journal events. `offline` keeps analysis local and avoids an LLM service or API.

## 2. Start the backend

Open a terminal and run:

```bash
cd "/home/kali/Documents/Default Project/ai-soc-analyst-assistant"
./venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Keep this terminal open. Check **http://127.0.0.1:8000/health**. The JSON should show `"ingestion_mode":"system"`.

## 3. Start the dashboard

Open a second terminal:

```bash
cd "/home/kali/Documents/Default Project/ai-soc-analyst-assistant"
./venv/bin/python -m streamlit run frontend/dashboard.py --server.address 127.0.0.1
```

Open **http://127.0.0.1:8501**. Keep this terminal open too.

## 4. Generate a safe local event

Open a third terminal. This makes `sudo` ask for your password again, then records one incorrect-password attempt locally:

```bash
sudo -k
sudo -v
```

At the password prompt, deliberately enter an incorrect password once. Do not repeat excessively; one event is enough for checking the log source. This does not attempt to access another account or machine.

## 5. Confirm the event was logged

Run:

```bash
journalctl --since "2 minutes ago" --no-pager | grep -i sudo
```

You should see a sudo/PAM authentication failure entry. The app polls the journal about every 10 seconds, so allow 10-20 seconds, then refresh the dashboard.

## 6. Confirm the alert

- Check the dashboard for a new alert with source `system` and a sudo/authentication-failure description.
- Open the alert to inspect severity, MITRE mapping, Sigma result, and offline analysis.
- Check backend logs if it does not appear.

## Troubleshooting

- If `/health` says `mock`, stop the backend and restart it after confirming `.env` has `INGESTION_MODE=system`.
- If `journalctl` shows no event, the failed-password test did not create a journal entry; try one incorrect attempt again.
- If `journalctl` reports permission errors or the app cannot read system events, run the backend from your normal terminal session and check local journal permissions. Do not run the whole dashboard as root.
- This implementation detects only the event patterns coded in `backend/app/system_logs.py`. A failed sudo password is the simplest test; SSH detection requires an SSH service and appropriate local auth logs, so it is intentionally not part of this minimal setup.
- `useradd` creates a real account and is unnecessary for this basic test.

## Presentation checklist

- [ ] `.env` has `INGESTION_MODE=system` and `LLM_MODE=offline`.
- [ ] Health endpoint reports system ingestion.
- [ ] Dashboard opens at `http://127.0.0.1:8501`.
- [ ] A sudo authentication failure is visible in `journalctl`.
- [ ] The resulting system alert appears in the dashboard.
- [ ] Capture screenshots of the health response, journal event, and alert detail.
- [ ] Explain that this is a local host-event test, not a test against an external machine.

## Safety

Keep both services bound to `127.0.0.1`. Generate test events only on your own laptop. This lab needs no external target, API, or attack utility.
