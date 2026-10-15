"""Seed the database with sample alerts (runs the full pipeline).

Usage:
    python -m scripts.seed_data [--count 100] [--clear]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import settings  # noqa: E402
from backend.app.database import SessionLocal, init_db  # noqa: E402
from backend.app.ingester import process_alert  # noqa: E402
from backend.app.mock_data import build_mock_alert  # noqa: E402
from backend.app.models import Alert  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--clear", action="store_true", help="Delete existing alerts first")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        if args.clear:
            deleted = db.query(Alert).delete()
            db.commit()
            print(f"Cleared {deleted} existing alerts")

        start = 20000
        last = db.query(Alert).order_by(Alert.id.desc()).first()
        base = (last.alert_ref.split("-")[-1] if last else str(start)) or str(start)
        base_index = int(base)
        for i in range(args.count):
            raw = build_mock_alert(base_index + i)
            process_alert(db, raw)
        print(f"Seeded {args.count} alerts (pipeline + AI analysis complete).")
    finally:
        db.close()


if __name__ == "__main__":
    main()
