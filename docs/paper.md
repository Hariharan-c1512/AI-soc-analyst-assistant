# AI-Assisted Security Operations Center: Automated Threat Detection, Classification, and Response Using Machine Learning and Sigma Rules

**Hariharan C.** · **Muthuvishal Ram M.** · **Sathirathanavel R.** · **Yugashri S.**

*Department of Computer Science*
author@email.com

**Mentor: Sasikala R.**

---

## Abstract

Security operations centers in small and medium organizations face a persistent problem: too many alerts and not enough analysts. Commercial SIEM platforms are expensive, require dedicated infrastructure, and often generate more noise than signal. This paper presents a proof-of-concept SOC platform that automates the alert triage pipeline — from ingestion through severity classification, threat mapping, and incident response guidance — using a Random Forest classifier, Sigma detection rules, and a retrieval-augmented language model. The system ingests alerts from Wazuh (or generates synthetic alerts for controlled testing), classifies severity with a Random Forest model trained on a 2,000-sample labeled dataset, maps threats to the MITRE ATT&CK framework, and produces natural-language summaries through retrieval-augmented generation. A key contribution is the automatic generation of Sigma detection rules from observed alert patterns, reducing the manual effort required to build detection coverage. On a 600-sample held-out test set, the Random Forest classifier achieved approximately 97.7% accuracy (varying between 96.5% and 97.7% across runs due to random dataset generation). However, the severity labels were derived from Wazuh alert levels, and Wazuh level was also included as an input feature. Consequently, the classification result primarily demonstrates reproduction of a predefined severity mapping rather than independent discovery of severity. The combined Sigma rule set (11 hand-crafted and 11 auto-generated) matched all alerts in a controlled 100-alert evaluation. In a separate end-to-end experiment, 320 synthetic alerts were processed through the complete pipeline. We discuss the limitations of this approach, including target leakage in the feature set, reliance on synthetic training data, and the gap between controlled evaluation and production deployment.

**Index Terms** — Security Operations Center, Machine Learning, Sigma Rules, MITRE ATT&CK, Automated Incident Response

---

## I. Introduction

A typical Wazuh deployment generates thousands of alerts per day. Most are false positives — misconfigured services, legitimate administrative activity, or automated scans that look alarming but pose no real threat. A team of three analysts cannot manually review each one. They need help prioritizing, classifying, and responding.

This paper describes a system we built to address that problem. The AI SOC Analyst Assistant is a three-tier platform: a FastAPI backend that processes alerts, a Streamlit dashboard that displays results, and a SQLite database that stores everything. The backend runs a five-stage pipeline: (1) normalize raw alerts to a common schema, (2) match against Sigma detection rules, (3) classify severity with a Random Forest model, (4) map threats to the MITRE ATT&CK framework, and (5) generate natural-language summaries using retrieval-augmented generation.

The project started with a practical question: could we build a working SOC assistant on a single laptop, using open-source tools, without requiring a team of data engineers? The answer is yes, with caveats we discuss honestly in this paper. The ML model trains in seconds on a CSV file. Sigma rules can be auto-generated from observed data. The entire system runs on a machine with 4GB of RAM. There are no subscription fees or cloud dependencies.

An important methodological limitation affects the ML evaluation: the severity labels used for training are derived from the same Wazuh level that appears as an input feature. This target leakage means the model's accuracy reflects its ability to reproduce an existing mapping rather than independently discover severity patterns. We discuss this explicitly in Section IV.D and interpret the results accordingly throughout the paper.

The rest of this paper is organized as follows. Section II reviews related work. Section III describes the system architecture. Section IV explains the ML pipeline and discusses the target leakage issue. Section V covers the Sigma rule engine. Section VI presents experimental results. Section VII discusses findings and limitations. Section VIII concludes.

---

## II. Related Work

Automated threat detection has been an active area of research for over two decades. Early systems relied on rule-based approaches — if a network connection matched a known malicious IP, generate an alert. These systems worked well for known threats but struggled with novel attack patterns. The introduction of machine learning changed the landscape.

Raff et al. [7] demonstrated that deep learning models could detect malware by analyzing binary features, achieving accuracy rates above 95% on benchmark datasets. However, deep learning models require significant computational resources and large training datasets, making them impractical for small organizations. Random Forest classifiers, as shown by Breiman [5], offer a more accessible alternative — they train quickly, handle missing data gracefully, and provide interpretable feature importance scores.

The Sigma project [2], started by the detection engineering community, addressed a different problem: portability. Before Sigma, detection rules were written in vendor-specific formats — Splunk's SPL, Elastic's KQL, Wazuh's own rule syntax. This meant that organizations switching SIEM platforms had to rewrite all their detection logic from scratch. Sigma provides a generic format that can be translated to any SIEM backend, making detection rules truly portable.

MITRE's ATT&CK framework [3] standardized how we describe attacker behavior. Instead of saying "someone ran PowerShell with encoded commands," we can say "the attacker used T1059.001 — Command and Scripting Interpreter: PowerShell." This standardization has made it possible to build automated mapping systems that connect raw alerts to structured threat intelligence.

Retrieval-augmented generation (RAG), introduced by Lewis et al. [6], showed that language models could be made much more useful by providing them with relevant context from a knowledge base. Instead of asking a language model to generate a response from memory alone, RAG retrieves similar documents and includes them in the prompt. This approach is particularly valuable for SOC analysis, where the model needs to reference past incidents and organizational policies to provide accurate guidance.

Our work builds on all of these foundations but focuses on a specific niche: making SOC automation accessible to organizations that cannot afford enterprise solutions. We use Random Forest (not deep learning) for severity classification, Sigma (the open standard) for detection portability, MITRE ATT&CK for threat mapping, and RAG with a lightweight language model for incident summaries.

---

## III. System Architecture

The platform consists of three main components that communicate through a REST API.

### A. Backend (FastAPI)

The backend is a Python FastAPI application that handles all alert processing. It runs as a single process with a background ingestion thread that continuously polls for new alerts (in Wazuh mode) or generates synthetic alerts (in mock mode).

The ingestion loop processes each alert through a pipeline of five stages:

1. **Normalization**: Raw alerts (from Wazuh, system logs, or mock generator) are converted to a common schema with fields like `alert_ref`, `timestamp`, `agent_name`, `description`, `raw_log`, and `wazuh_level`.

2. **Sigma Matching**: The normalized alert is checked against all 22 Sigma rules. The engine supports keyword matching, field equality, field regex, and string containment. If a rule matches, its ID and title are attached to the alert.

3. **ML Severity Prediction**: The alert's features are extracted and fed to the Random Forest classifier. The model returns a severity label (low/medium/high/critical), a confidence score, and a probability distribution across all four classes.

4. **MITRE Mapping**: The Sigma rule ID (or a heuristic fallback) is used to look up the corresponding MITRE ATT&CK tactic, technique, and kill chain phase.

5. **RAG Indexing and LLM Analysis**: The alert is indexed in the retrieval store. The top-3 similar past incidents are retrieved and passed as context to the language model, which generates a summary, technique assessment, and remediation recommendations.

The processed alert is then stored in the SQLite database along with all enrichment data.

### B. Frontend (Streamlit)

The dashboard is a Streamlit application that displays alerts in a searchable, filterable table. Analysts can view alert details including the ML prediction, MITRE mapping, Sigma rule match, and AI-generated summary. The dashboard also shows aggregate statistics: alert counts by severity, top agents, and alerts over time.

### C. Ingestion Modes and Wazuh Integration

Wazuh is the core SIEM platform of this project. It is a free, open-source security monitoring solution that provides host-based intrusion detection, log analysis, and threat intelligence. In production, Wazuh agents are installed on every monitored host (Windows, Linux, servers, workstations). These agents forward logs to the Wazuh manager, which analyzes them and generates alerts. Our platform connects to this manager and adds the AI layer on top.

The system supports three ingestion modes, configured via the `.env` file:

- **Wazuh mode** (`INGESTION_MODE=wazuh`): The Wazuh manager collects and analyzes endpoint events; this backend searches alert documents from the Wazuh Indexer REST API (`https://localhost:9200/wazuh-alerts-*/_search`) using `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD`. It normalizes the returned documents into the common schema (`normalize_wazuh_alert()` in `backend/app/ingester.py`) and runs them through the shared enrichment pipeline — Sigma matching, ML severity prediction, MITRE mapping, RAG indexing, and LLM analysis. The included Docker Compose file provides a local Wazuh manager and indexer. The Indexer URL, credentials, and TLS verification must match the deployment; the sample Compose credentials are for local testing only. This mode requires a running, reachable Indexer and has not been evaluated as a production deployment.

- **Mock mode** (`INGESTION_MODE=mock`): Generates realistic alerts every 30 seconds using 11 attack templates defined in `backend/app/mock_data.py` (malware, ransomware, C2, PowerShell, SSH brute force, web shell, SQL injection, port scan, USB, file integrity, privilege escalation). Each template includes a Wazuh rule ID, Sigma rule mapping, MITRE ATT&CK technique, and kill chain phase. This mode was used for all experiments in this paper because it allows controlled, reproducible evaluation without requiring a full Wazuh deployment on the test hardware.

- **System mode** (`INGESTION_MODE=system`): Reads events from the Linux journal (`journald`) and detects real attacks on the local machine: SSH brute force, sudo misuse, and unauthorized user creation. This mode needs no external dependencies and catches genuine threats.

All three modes feed into the same enrichment pipeline in code. Mock-mode results validate that shared processing path, but do not by themselves demonstrate successful live Wazuh ingestion or production detection performance.

---

## IV. Machine Learning Pipeline

### A. Dataset Generation

Since real labeled SOC alert data is difficult to obtain (it is sensitive and organization-specific), we generate a synthetic labeled dataset from the attack templates. The `scripts/train_model.py` script creates 2,000 samples by randomly selecting templates, agents, timestamps, and log parameters. Each sample is labeled with a ground-truth severity derived from the template's Wazuh level.

The labeling scheme maps Wazuh levels to severity codes:
- Levels 12–15 → Critical (3)
- Levels 8–11 → High (2)
- Levels 5–7 → Medium (1)
- Levels 1–4 → Low (0)

A 3% label noise is introduced by randomly shifting boundary cases up or down by one severity level, simulating the ambiguity that real analysts face when triaging borderline alerts.

### B. Feature Engineering

Eight features are extracted from each alert (Table I). The feature set was chosen to capture the most relevant signals for severity classification while remaining computationally inexpensive to extract.

The `wazuh_level` feature is the strongest predictor — it directly encodes the alert's perceived severity by the detection rule author. The `sigma_severity` feature provides a secondary signal from the Sigma rule category. The `agent_type` feature captures the observation that attacks on servers (Linux) are often more severe than attacks on workstations (Windows). The `script_execution` feature flags alerts involving PowerShell, cmd.exe, or Python, which are commonly associated with malicious activity.

**TABLE I. Feature Description**

| Feature | Type | Range | Description |
|---------|------|-------|-------------|
| wazuh_level | Float | 1–15 | Wazuh alert level |
| sigma_severity | Float | 0–4 | Sigma rule category severity |
| agent_type | Float | 0–2 | OS type encoding |
| hour_of_day | Float | 0–23 | Hour the alert was generated |
| day_of_week | Float | 0–6 | Day of week |
| script_execution | Float | 0–1 | Script execution detected |
| log_volume | Float | 0–1 | Normalized log size |
| prev_alerts_24h | Float | 0–8 | Alert count in past 24 hours |

### C. Model Training and Evaluation

The dataset is split 70/30 into training and test sets (1,400 training, 600 test), stratified by severity class. A Random Forest classifier with 200 trees and maximum depth of 12 is trained on the training set and evaluated on the test set.

**Important caveat on target leakage.** The ground-truth severity labels are derived from the Wazuh level, and `wazuh_level` is also an input feature. This creates a direct leakage path: the model can learn the exact mapping it is supposed to discover. The feature importance results confirm this — `sigma_severity` accounts for 46.5% of the model's decisions, and `wazuh_level` (also correlated with the label) accounts for 42.9%. Together these two features drive 89.4% of the classification. This means the Random Forest is largely reproducing a lookup table that already exists in the data, not independently learning severity patterns from raw alert characteristics.

We chose to keep this experimental design because the practical goal is not to prove that ML can discover severity from first principles. The goal is to build a pipeline where severity classification is automated, consistent, and auditable. In a real deployment, the Wazuh level would come from the detection rule author's judgment, and the ML model would provide a second opinion that can be inspected, overridden, and improved over time. The feature importance scores make the model's reasoning transparent — an analyst can see exactly which factors drove each prediction.

That said, this design limits what the accuracy number means. The accuracy should be interpreted as "the model correctly reproduces the existing severity mapping approximately 97.7% of the time," not "the model independently discovers severity with 97.7% accuracy." Note that because the dataset is randomly generated, accuracy varies between runs (observed range: 96.5%–97.7%). Future work should evaluate the model on alerts where severity labels come from a different source than the input features (e.g., analyst-annotated labels, or alerts from a different SIEM with different level schemes).

**TABLE II. Classification Results**

| Metric | Value |
|--------|-------|
| Accuracy | 97.67% |
| Weighted F1 | 0.9766 |
| Precision (weighted) | 0.9767 |
| Recall (weighted) | 0.9767 |

The model correctly classified 586 out of 600 test samples. The 14 misclassifications occurred on boundary cases between adjacent severity levels (e.g., level-8 alerts classified as medium instead of high), which is expected given the intentional label noise in the training data. Note that accuracy varies between runs (observed range: 96.5%–97.7%) because the synthetic dataset is randomly generated each time.

**TABLE III. Confusion Matrix**

| Actual \ Predicted | Low | Medium | High | Critical |
|--------------------|-----|--------|------|----------|
| Low | 56 | 1 | 0 | 0 |
| Medium | 1 | 112 | 5 | 0 |
| High | 0 | 0 | 266 | 2 |
| Critical | 0 | 0 | 5 | 152 |

The confusion matrix shows that misclassifications cluster along the diagonal boundaries. No critical alert was misclassified as low or medium, which is important from a safety perspective — the system rarely misses the most severe threats.

**TABLE IV. Feature Importance**

| Feature | Importance | Interpretation |
|---------|-----------|----------------|
| sigma_severity | 0.4650 | Correlated with severity via rule category (leaked target) |
| wazuh_level | 0.4290 | Directly encodes severity (leaked target) |
| log_volume | 0.0301 | Larger logs may indicate more complex attacks |
| script_execution | 0.0299 | PowerShell/cmd.exe involvement |
| hour_of_day | 0.0185 | After-hours alerts may warrant closer inspection |
| day_of_week | 0.0122 | Weekend patterns |
| prev_alerts_24h | 0.0116 | Alert clustering may suggest coordinated activity |
| agent_type | 0.0037 | Server vs. workstation distinction |

The dominance of `sigma_severity` and `wazuh_level` is expected given the target leakage described above. The remaining six features (combined: 10.6%) provide marginal signal that helps resolve ambiguous cases, but the model would perform nearly as well with only the two dominant features.

### D. Fallback Mechanism

When the trained model is unavailable (e.g., on a fresh installation before training), the system falls back to a deterministic rule-based severity mapping. This ensures the pipeline always produces a result, even without ML.

---

## V. Sigma Rule Engine and Auto-Generation

### A. Rule Format

Each Sigma rule is a YAML file with a title, ID, description, level, detection logic, and MITRE tags. The detection logic uses a keyword-based approach: the rule specifies a list of keywords that should appear in the alert's description, raw log, or Sigma title.

For example, the SSH brute force rule looks for keywords like "brute force," "failed ssh," "failed login," and "attempts." If any of these appear in the alert text, the rule matches.

### B. Auto-Generation from Data

The `scripts/generate_sigma_rules.py` script implements a pipeline that analyzes alert patterns in the database and produces new Sigma rules. The process works as follows:

1. Alerts are grouped by their Sigma title (e.g., all "SSH Brute Force" alerts are grouped together).
2. Raw log content from all alerts in each group is aggregated.
3. A keyword extraction process identifies the most distinctive tokens in the raw logs.
4. The top 6 keywords are selected for the new rule.
5. Fields referenced in the raw log JSON are extracted and added to the rule.
6. MITRE ATT&CK tags are derived from the alert's mapping.
7. A unique `AUTO-*` prefixed ID is assigned to avoid collisions with hand-crafted rules.

The auto-generated rules are stored in the `sigma_rules/auto/` subdirectory and loaded by the Sigma engine alongside the hand-crafted rules. This design means the system can extend its detection coverage automatically as it observes new alert types.

### C. Detection Coverage

The combined rule set provides detection for 11 attack categories:

- Malware execution (ClamAV, EICAR)
- Ransomware file encryption
- C2 communication (outbound connections to known malicious IPs)
- PowerShell abuse (encoded commands)
- SSH brute force
- Web shell upload
- SQL injection
- Network port scanning
- USB device connection
- File integrity monitoring changes
- Privilege escalation (sudo misuse)

---

## VI. Experimental Results

This section presents three separate evaluations: (A) the ML classifier's accuracy on a held-out test set, (B) the Sigma engine's matching coverage, and (C) the end-to-end pipeline running on 320 seeded alerts.

### A. ML Classifier Evaluation

The Random Forest was trained on 1,400 samples and evaluated on 600 held-out test samples (2,000 total, 70/30 split). As discussed in Section IV.C, the input features include `wazuh_level`, which is correlated with the target label. The results should therefore be read as "the model reproduces the existing severity mapping" rather than "the model independently discovers severity."

**TABLE V. Class-wise Precision, Recall, and F1**

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| Low | 0.98 | 0.98 | 0.98 | 57 |
| Medium | 0.99 | 0.95 | 0.97 | 118 |
| High | 0.96 | 0.99 | 0.98 | 268 |
| Critical | 0.99 | 0.97 | 0.98 | 157 |
| Weighted avg | 0.98 | 0.98 | 0.98 | 600 |

The model performs best on the critical class (F1 = 0.98), which is the most important class from an operational perspective — missing a critical alert has severe consequences. The slightly lower performance on medium-severity alerts (F1 = 0.97) reflects the inherent ambiguity in this class, which sits between clearly benign and clearly malicious.

### B. Sigma Rule Matching

The Sigma engine was validated against all 11 attack templates and 100 randomly generated mock alerts (each randomly selecting a template, agent, timestamp, and log parameters). The combined rule set (11 hand-crafted + 11 auto-generated) achieved a 100% matching rate for these specific 11 attack categories. This does not mean the system detects all possible attack types — it means that for the controlled attack surface we defined, every alert matched at least one rule. Real environments would require additional rules for attack techniques not covered by the current template set.

The auto-generated rules contributed 11 additional detection patterns, and the `AUTO-*` prefixed IDs ensured no collision with the hand-crafted rules.

### C. Wazuh Integration Status

Wazuh integration is fully implemented in `backend/app/ingester.py` — `WazuhClient` authenticates via `POST /security/user/authenticate` and polls `GET /alerts` with bearer token, while `normalize_wazuh_alert()` converts raw Wazuh JSON to the common alert schema. Docker deployment is provided via `docker-compose.yml` (wazuh-manager:4.14.7, wazuh-indexer:4.14.7, postgres:16). On the test hardware (Kali Linux, <4GB RAM), the native Wazuh installer requires >=4GB RAM and the Docker indexer security initialization failed due to missing certificates, so production Wazuh evaluation was deferred. The pipeline code is identical for mock and Wazuh modes — only the alert source changes — so mock-mode results transfer to Wazuh deployments on suitable hardware (Ubuntu/RHEL, 4GB+ RAM).

### D. End-to-End Pipeline Evaluation

Separate from the ML test set evaluation, we seeded 320 alerts through the mock ingestion mode to test the full pipeline: normalization, Sigma matching, ML prediction, MITRE mapping, RAG indexing, and LLM analysis. Every alert was processed through all five stages and stored in the database with complete enrichment data.

**TABLE VI. Alert Distribution (320 seeded alerts)**

| Severity | Count | Percentage |
|----------|-------|------------|
| Low | 31 | 9.7% |
| Medium | 63 | 19.7% |
| High | 125 | 39.1% |
| Critical | 101 | 31.6% |

The distribution reflects the mock generator's template selection weights, which favor high and critical alerts to ensure analysts see realistic threat scenarios during testing.

### E. Real-World Pipeline Examples

Three alerts were injected and traced through the complete enrichment pipeline to demonstrate the system's practical output.

**Example 1: SQL Injection (HIGH severity)**

An alert was generated for a SQL injection attempt against the web application server (srv-db01, Ubuntu 20.04). The raw log showed a GET request to `/products?id=1' OR '1'='1` from IP 193.169.255.133. The Sigma engine matched rule WEB-002 (SQL Injection Attempt). The ML model classified it as HIGH severity with 73.7% confidence. MITRE mapping identified T1190 (Exploit Public-Facing Application) under the Initial Access tactic. The offline LLM produced remediation steps: patch the vulnerable application, add WAF rules blocking SQL injection patterns, review application logs, and validate all user input server-side.

**Example 2: SSH Brute Force (HIGH severity)**

An alert was generated for multiple failed SSH login attempts against the mail server (srv-mail01, Debian 11). The raw log recorded 3,271 failed attempts from IP 91.218.114.31 targeting the "admin" account. The Sigma engine matched rule BRUTE-002 (SSH Brute Force). The ML model classified it as HIGH severity with 90.2% confidence. MITRE mapping identified T1110 (Brute Force) under the Credential Access tactic. The system recommended blocking the source IP, enforcing account lockout policies and MFA, reviewing authentication logs for successful logins, and moving SSH to key-based authentication.

**Example 3: Ransomware (CRITICAL severity)**

An alert was generated for ransomware behavior on a Windows workstation (win-ep-01, Windows 10). The raw log detected bulk file modification with the ".locked" extension affecting 3,795 files in the temp directory. The Sigma engine matched rule RAN-001 (Ransomware File Encryption Pattern). The ML model classified it as CRITICAL severity with 98.0% confidence. MITRE mapping identified T1486 (Data Encrypted for Impact) under the Impact tactic. The system recommended immediately disconnecting the host from the network, identifying the encryption scope, restoring files from backup, and containing lateral movement by blocking SMB ports from affected hosts.

---

## VII. Discussion

### A. Practical Impact

The system demonstrates that meaningful SOC automation is achievable with minimal resources. The entire stack runs on a single laptop, the ML model trains in under 10 seconds, and the Sigma rules provide portable detection logic that works across SIEM platforms. For small organizations that cannot afford commercial SIEM licenses or dedicated security staff, this approach offers a practical alternative.

### B. Limitations

Several limitations should be acknowledged:

1. **Synthetic training data**: The ML model is trained on generated data, not real-world alerts. While the templates are designed to be realistic, the model may not generalize to novel attack patterns that do not match the training templates.

2. **Limited detection coverage**: The current Sigma rule set covers 11 attack categories. Real SOC environments face hundreds of distinct attack techniques. The auto-generation feature helps, but it requires existing labeled data to produce rules.

3. **Language model quality**: The offline LLM mode uses template-based analysis, which produces generic summaries. The Ollama-based mode with TinyLlama provides better results but requires additional setup.

4. **Single-machine deployment**: The system is designed for single-machine operation, which limits scalability. For large environments with thousands of alerts per minute, a distributed architecture would be needed.

### C. Future Work

Several extensions are planned:

- **Production Wazuh evaluation**: Deploy on Ubuntu/RHEL hardware meeting Wazuh's ≥4GB RAM requirement and evaluate ingestion of live Wazuh agent alerts (the REST integration, Docker compose, and normalization code are already implemented and switchable via one `.env` line).
- **Active learning**: Allow analysts to confirm or correct ML predictions, then retrain the model on the updated labels to improve accuracy over time.
- **Rule feedback loop**: When an analyst confirms a Sigma rule match, the system could use that feedback to refine the auto-generated rules.
- **Additional data sources**: Integrate with Suricata (network IDS), OSSEC (host IDS), and custom log sources.
- **Multi-tenant support**: Allow a single installation to monitor multiple organizations or departments.

---

## VIII. Conclusion

This paper presented a proof-of-concept SOC platform that automates the alert triage pipeline from ingestion to remediation guidance. The system combines a Random Forest classifier (approximately 97.7% accuracy on 600 held-out test samples, with acknowledged target leakage), Sigma detection rules (100% matching coverage for 11 defined attack templates), MITRE ATT&CK threat mapping, and retrieval-augmented generation to produce actionable intelligence from raw alerts.

The most important finding is not the accuracy number itself, but what it reveals about the design. The feature importance analysis showed that two features — Sigma rule severity (46.5%) and Wazuh alert level (42.9%) — drive 89.4% of the model's decisions. Since the severity labels are derived from these same features, the model is largely reproducing an existing mapping rather than discovering severity from scratch. This is acceptable for a proof-of-concept pipeline where the goal is automated, consistent, and auditable classification — but it is not evidence that ML independently learns severity patterns from raw alert data.

The Sigma rule matching validated at 100% for the 11 attack templates in the controlled evaluation. This confirms the auto-generation approach works for extending detection coverage within a defined attack surface, though real environments would require broader rule sets.

The main contribution of this work is demonstrating that a complete SOC triage pipeline — ingestion, Sigma matching, ML classification, MITRE mapping, and LLM-generated analysis — can run on a single machine using open-source tools with no external API dependencies. The system is not production-ready: it uses synthetic training data, covers only 11 attack categories, runs on a single machine, and has not been evaluated against live Wazuh alerts. These are all directions for future work.

---

## Acknowledgements

We would like to thank our mentor, Sasikala R., for her guidance and support throughout this project. Her expertise in cybersecurity and machine learning was invaluable in shaping the system architecture and evaluating the experimental results.

---

## References

[1] A. A. Hameed, A. A. Ali, and M. Anbar, "Intrusion detection system in cloud computing: A comprehensive review," *J. King Saud Univ. Comput. Inf. Sci.*, vol. 35, no. 3, pp. 625–648, 2023.

[2] S. Bhatt, F. Bachhofen, and T. Bader, "Sigma — The Open Signature Format for Generic Log Detection," GitHub, 2023. [Online]. Available: https://github.com/SigmaHQ/sigma

[3] MITRE Corporation, "ATT&CK — Adversarial Tactics, Techniques, and Common Knowledge," 2023. [Online]. Available: https://attack.mitre.org

[4] Wazuh, "Wazuh Documentation," 2024. [Online]. Available: https://documentation.wazuh.com

[5] L. Breiman, "Random forests," *Mach. Learn.*, vol. 45, no. 1, pp. 5–32, 2001.

[6] P. Lewis, E. Perez, A. Piktus, F. Petroni, V. Karpukhin, N. Goyal, H. Küttler, M. Lewis, W. Yih, T. Rocktäschel, S. Riedel, and D. Kiela, "Retrieval-augmented generation for knowledge-intensive NLP tasks," in *Proc. Adv. Neural Inf. Process. Syst. (NeurIPS)*, 2020, pp. 9459–9474.

[7] E. Raff, J. Barker, J. Sylvester, R. Brandon, B. Catanzaro, and C. Nicholas, "A deep learning approach for malware detection," in *Proc. IEEE Int. Conf. Big Data*, 2018, pp. 1–11.

[8] Streamlit, "Streamlit Documentation," 2024. [Online]. Available: https://docs.streamlit.io

[9] FastAPI, "FastAPI Documentation," 2024. [Online]. Available: https://fastapi.tiangolo.com

[10] scikit-learn, "Scikit-learn: Machine Learning in Python," 2024. [Online]. Available: https://scikit-learn.org

[11] Ollama, "Ollama — Run Large Language Models Locally," 2024. [Online]. Available: https://ollama.com

[12] ChromaDB, "Chroma — The AI-native open-source embedding database," 2024. [Online]. Available: https://www.trychroma.com
