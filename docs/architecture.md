# AI SOC Analyst Assistant - Architecture Diagram

For the implementation walkthrough, component responsibilities, and a
four-person mentor presentation script, see the
[mentor presentation guide](mentor-presentation.md). The flowchart is in
[project-flowchart.md](project-flowchart.md).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │   DATA       │    │   INGESTION  │    │   ENRICHMENT │                  │
│  │   SOURCES    │───▶│   LAYER      │───▶│   PIPELINE   │                  │
│  └──────────────┘    └──────────────┘    └──────────────┘                  │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │ • Wazuh SIEM │    │ • normalize  │    │ 1. Sigma     │                  │
│  │ • System logs│    │ • validate   │    │    Matching  │                  │
│  │ • Mock gen   │    │ • timestamp  │    │ 2. ML Pred   │                  │
│  └──────────────┘    └──────────────┘    │ 3. MITRE Map │                  │
│                                          │ 4. RAG Index │                  │
│                                          │ 5. LLM       │                  │
│                                          └──────────────┘                  │
│                                                  │                          │
│                                                  ▼                          │
│                    ┌─────────────────────────────────────────┐              │
│                    │              STORAGE                     │              │
│                    │  ┌─────────────┐  ┌─────────────────┐  │              │
│                    │  │  SQLite DB   │  │  Vector Store   │  │              │
│                    │  │  (alerts,    │  │  (TF-IDF /      │  │              │
│                    │  │   models)    │  │   ChromaDB)     │  │              │
│                    │  └─────────────┘  └─────────────────┘  │              │
│                    └─────────────────────────────────────────┘              │
│                                                  │                          │
│                                                  ▼                          │
│                    ┌─────────────────────────────────────────┐              │
│                    │              PRESENTATION               │              │
│                    │  ┌─────────────┐  ┌─────────────────┐  │              │
│                    │  │  Streamlit   │  │  FastAPI REST   │  │              │
│                    │  │  Dashboard   │  │  Endpoints      │  │              │
│                    │  └─────────────┘  └─────────────────┘  │              │
│                    └─────────────────────────────────────────┘              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    ENRICHMENT PIPELINE (5 STAGES)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Raw Alert ──▶ [1] Sigma ──▶ [2] ML ──▶ [3] MITRE ──▶ [4] RAG ──▶ [5] LLM│
│                  Match      Severity    ATT&CK Map     Retrieve   Analyze  │
│                  (22 rules) (RandomForest) (11 tech)   (top-3)   (summary) │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    ML SEVERITY CLASSIFIER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input Features (8):                                                        │
│  ┌─────────────────┬──────────────────────────────────────────────┐        │
│  │ wazuh_level     │ Wazuh alert level (1-15)                     │        │
│  │ sigma_severity  │ Sigma rule category (0-4)                    │        │
│  │ agent_type      │ OS type: Windows=0, Linux=1, Router=2        │        │
│  │ hour_of_day     │ Hour alert was generated (0-23)              │        │
│  │ day_of_week     │ Day of week (0-6)                            │        │
│  │ script_execution│ PowerShell/cmd.exe detected (0/1)            │        │
│  │ log_volume      │ Normalized log size (0-1)                    │        │
│  │ prev_alerts_24h │ Alert count in past 24h (0-8)                │        │
│  └─────────────────┴──────────────────────────────────────────────┘        │
│                          │                                                  │
│                          ▼                                                  │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │  Random Forest Classifier (200 trees, max_depth=12)             │      │
│  │  Training: 1400 samples | Test: 600 samples                     │      │
│  │  Accuracy: 96.50% | F1: 0.9651                                  │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│                          │                                                  │
│                          ▼                                                  │
│  Output: severity (low/medium/high/critical) + confidence + probabilities  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    SIGMA RULE ENGINE                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Hand-crafted Rules (11):                                                   │
│  ┌─────────────┬─────────────────────────────────────┬──────────────┐      │
│  │ Rule ID     │ Title                               │ MITRE Tech   │      │
│  ├─────────────┼─────────────────────────────────────┼──────────────┤      │
│  │ MAL-001     │ Malware Detected by AntiVirus       │ T1204.002    │      │
│  │ RAN-001     │ Ransomware File Encryption Pattern  │ T1486        │      │
│  │ CMD-014     │ Suspicious Outbound Connection      │ T1071.001    │      │
│  │ PS-001      │ Suspicious PowerShell Command Line  │ T1059.001    │      │
│  │ BRUTE-002   │ SSH Brute Force                     │ T1110        │      │
│  │ WEB-001     │ Web Shell Upload Attempt            │ T1505.003    │      │
│  │ WEB-002     │ SQL Injection Attempt               │ T1190        │      │
│  │ SCAN-001    │ Network Port Scan                   │ T1046        │      │
│  │ MEDIA-001   │ USB Device Connected                │ T1091        │      │
│  │ FIM-001     │ File Integrity Monitoring Change    │ T1070.001    │      │
│  │ PRIV-001    │ Sudo Privilege Escalation           │ T1068        │      │
│  └─────────────┴─────────────────────────────────────┴──────────────┘      │
│                                                                             │
│  Auto-generated Rules (11):                                                 │
│  • Generated from alert patterns in database                               │
│  • Uses keyword extraction from raw logs                                   │
│  • Prefixed with AUTO-* to avoid collisions                                │
│  • Stored in backend/sigma_rules/auto/                                     │
│                                                                             │
│  Total Rules: 22 | Match Rate: 100% (validated on 100 mock alerts)         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
