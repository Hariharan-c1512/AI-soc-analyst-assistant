"""Train the ML severity predictor.

Generates a synthetic labeled dataset from the alert templates, trains
a Random Forest (or XGBoost if installed), evaluates it, and saves the
model plus metadata to the database.

Usage:
    python -m scripts.train_model [--samples 2000]
"""
import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score, classification_report, confusion_matrix, f1_score,
)
from sklearn.model_selection import train_test_split  # noqa: E402

from backend.app.config import settings  # noqa: E402
from backend.app.database import SessionLocal, init_db  # noqa: E402
from backend.app.features import FEATURE_COLUMNS, SEVERITY_LABELS  # noqa: E402
from backend.app.mitre_mapper import MAP  # noqa: E402
from backend.app.models import ModelMetadata  # noqa: E402
from backend.app.mock_data import AGENTS, LEVEL_TO_SEVERITY, TEMPLATES  # noqa: E402


def generate_dataset(n_samples: int) -> pd.DataFrame:
    rows = []
    for _ in range(n_samples):
        tpl = random.choice(TEMPLATES)
        agent = random.choice(AGENTS)
        raw = f"{tpl.description} {tpl.raw_log_template.format(agent=agent['name'], path='/tmp/x', n=5, src='1.2.3.4', dst='5.6.7.8', b=100, proc='x', b64='', user='u', sql='x', md5='a'*32)}"
        sigma_id = tpl.sigma_rule_id
        level = tpl.level
        true_sev = LEVEL_TO_SEVERITY[level]

        # Slight noise: occasionally label boundary cases differently
        if random.random() < 0.03:
            true_sev = max(0, min(3, true_sev + random.choice([-1, 1])))

        rows.append({
            "wazuh_level": float(level),
            "sigma_severity": float({"MAL-001": 3, "RAN-001": 4, "CMD-014": 4, "PS-001": 2,
                                     "BRUTE-002": 2, "WEB-001": 2, "WEB-002": 2, "SCAN-001": 1,
                                     "MEDIA-001": 0, "FIM-001": 1, "PRIV-001": 2}.get(sigma_id, 1)),
            "agent_type": float({"Windows": 0, "Linux": 1}.get(agent["os"].split()[0], 1)),
            "hour_of_day": float(random.randint(0, 23)),
            "day_of_week": float(random.randint(0, 6)),
            "script_execution": float(1 if any(k in raw.lower() for k in ["powershell", "-enc", "python3", "cmd.exe"]) else 0),
            "log_volume": float(min(1.0, np.log1p(random.randint(1, 4000)) / 10.0)),
            "prev_alerts_24h": float(random.randint(0, 8)),
            "severity": int(true_sev),
        })
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=2000)
    args = parser.parse_args()

    df = generate_dataset(args.samples)
    X = df[FEATURE_COLUMNS]
    y = df["severity"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    use_xgb = False
    try:
        from xgboost import XGBClassifier

        clf = XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            objective="multi:softprob", num_class=4, random_state=42, n_jobs=1,
        )
        use_xgb = True
    except ImportError:
        clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=1)

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")

    print(f"Classifier: {'XGBoost' if use_xgb else 'RandomForest'}")
    print(f"Samples: {args.samples} (train {len(X_train)} / test {len(X_test)})")
    print(f"Accuracy: {acc:.4f}")
    print(f"Weighted F1: {f1:.4f}")
    print("\n" + classification_report(y_test, y_pred, target_names=SEVERITY_LABELS, labels=[0, 1, 2, 3]))

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1, 2, 3])
    print("\nConfusion Matrix:")
    print("                 Predicted")
    print("                 Low   Med   High  Crit")
    for i, label in enumerate(SEVERITY_LABELS):
        print(f"  Actual {label:<6} {cm[i][0]:>5} {cm[i][1]:>5} {cm[i][2]:>5} {cm[i][3]:>5}")

    # Feature Importance
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
        fi_pairs = sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: -x[1])
        print("\nFeature Importance:")
        for feat, imp in fi_pairs:
            print(f"  {feat:<20} {imp:.4f}")

    # Save full report to file
    report_dir = Path("data/results")
    report_dir.mkdir(parents=True, exist_ok=True)

    report_text = []
    report_text.append(f"Classifier: {'XGBoost' if use_xgb else 'RandomForest'}")
    report_text.append(f"Samples: {args.samples} (train {len(X_train)} / test {len(X_test)})")
    report_text.append(f"Accuracy: {acc:.4f}")
    report_text.append(f"Weighted F1: {f1:.4f}")
    report_text.append("")
    report_text.append("Classification Report:")
    report_text.append(classification_report(y_test, y_pred, target_names=SEVERITY_LABELS, labels=[0, 1, 2, 3]))
    report_text.append("Confusion Matrix:")
    report_text.append("                 Predicted")
    report_text.append("                 Low   Med   High  Crit")
    for i, label in enumerate(SEVERITY_LABELS):
        report_text.append(f"  Actual {label:<6} {cm[i][0]:>5} {cm[i][1]:>5} {cm[i][2]:>5} {cm[i][3]:>5}")
    if hasattr(clf, "feature_importances_"):
        report_text.append("")
        report_text.append("Feature Importance:")
        for feat, imp in fi_pairs:
            report_text.append(f"  {feat:<20} {imp:.4f}")

    report_path = report_dir / "training_report.txt"
    report_path.write_text("\n".join(report_text), encoding="utf-8")
    print(f"\nFull report saved -> {report_path}")

    # Save confusion matrix as JSON for programmatic access
    cm_data = {
        "labels": SEVERITY_LABELS,
        "matrix": cm.tolist(),
        "accuracy": round(acc, 4),
        "f1_weighted": round(f1, 4),
        "feature_importance": {feat: round(float(imp), 4) for feat, imp in fi_pairs} if hasattr(clf, "feature_importances_") else {},
    }
    cm_path = report_dir / "confusion_matrix.json"
    cm_path.write_text(json.dumps(cm_data, indent=2), encoding="utf-8")
    print(f"Confusion matrix JSON -> {cm_path}")

    import joblib

    model_path = Path(settings.MODEL_PATH)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"\nSaved model -> {model_path}")

    init_db()
    db = SessionLocal()
    try:
        db.add(ModelMetadata(
            model_name="XGBoost" if use_xgb else "RandomForest",
            version=f"v1.{args.samples // 1000}",
            accuracy=round(acc, 4),
            f1_score=round(f1, 4),
            training_samples=args.samples,
        ))
        db.commit()
    finally:
        db.close()
    print("Model metadata recorded in database.")


if __name__ == "__main__":
    main()
