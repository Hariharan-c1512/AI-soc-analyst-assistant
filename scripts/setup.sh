#!/usr/bin/env bash
# One-command setup for the AI SOC Analyst Assistant (mock/offline mode).
set -e

cd "$(dirname "$0")"

echo "[1/4] Installing Python dependencies..."
pip install -r requirements.txt

echo "[2/4] Training ML severity model..."
python -m scripts.train_model --samples 2000

echo "[3/4] Seeding demo alerts..."
python -m scripts.seed_data --count 100

echo "[4/4] Starting backend and dashboard..."
echo "  Backend : http://localhost:8000/docs"
echo "  Dashboard: http://localhost:8501"

uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 &
sleep 3
streamlit run frontend/dashboard.py --server.port 8501
