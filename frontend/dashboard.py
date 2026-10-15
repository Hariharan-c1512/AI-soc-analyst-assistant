"""AI SOC Analyst Assistant — Enhanced Streamlit Dashboard.

Run:  streamlit run frontend/dashboard.py
Requires the FastAPI backend on localhost:8000.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils import (  # noqa: E402
    SEVERITY_COLORS, SEVERITY_ORDER, api, fetch_alerts, get_json,
    post_json,
)

st.set_page_config(
    page_title="AI SOC Analyst Assistant",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)

# ============================================================
# PREVENTION RULES DATABASE
# ============================================================
PREVENTION_RULES = {
    "T1110": {
        "name": "Brute Force Attack",
        "sigma_rules": [
            {
                "id": "BRUTE-002",
                "title": "SSH Brute Force Detection",
                "description": "Detects multiple failed SSH login attempts from a single source",
                "logic": "Authentication failures > 5 in 5 minutes from same source",
                "wazuh_level": 10
            }
        ],
        "prevention": [
            "Implement account lockout policies (5 failed attempts = 15min lockout)",
            "Enable Multi-Factor Authentication (MFA) on all SSH access",
            "Use key-based authentication instead of passwords",
            "Change SSH to non-standard port (e.g., 2222)",
            "Deploy fail2ban for automatic IP blocking",
            "Restrict SSH access via firewall rules (allow only specific IPs)"
        ],
        "sigma_yaml": """title: SSH Brute Force Detection
id: BRUTE-002
status: experimental
description: Detects multiple failed SSH login attempts
references:
  - https://attack.mitre.org/techniques/T1110/
author: AI SOC Analyst Assistant
logsource:
  category: authentication
  product: linux
detection:
  selection:
    event_id: 4625
    logon_type: 10
  condition: selection | count(target_user) by ip_address > 5 within 5m
level: high
tags:
  - attack.credential_access
  - attack.t1110"""
    },
    "T1486": {
        "name": "Ransomware Encryption",
        "sigma_rules": [
            {
                "id": "RAN-001",
                "title": "Ransomware File Encryption Pattern",
                "description": "Detects bulk file modification with ransomware extensions",
                "logic": "File extensions changed to .locked, .encrypted, .crypto",
                "wazuh_level": 15
            }
        ],
        "prevention": [
            "Maintain offline backups (3-2-1 rule: 3 copies, 2 media, 1 offsite)",
            "Enable Volume Shadow Copy for quick recovery",
            "Restrict write permissions on shared drives",
            "Deploy application whitelisting",
            "Disable PowerShell for standard users",
            "Keep all systems patched and updated"
        ],
        "sigma_yaml": """title: Ransomware File Encryption Pattern
id: RAN-001
status: experimental
description: Detects bulk file modification typical of ransomware
references:
  - https://attack.mitre.org/techniques/T1486/
author: AI SOC Analyst Assistant
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 11
    TargetFilename|endswith:
      - '.locked'
      - '.encrypted'
      - '.crypto'
      - '.wncry'
  condition: selection | count(TargetFilename) by Image > 50 within 1m
level: critical
tags:
  - attack.impact
  - attack.t1486"""
    },
    "T1071.001": {
        "name": "C2 Beaconing (Web Protocols)",
        "sigma_rules": [
            {
                "id": "CMD-014",
                "title": "Suspicious Outbound Connection to C2 IP",
                "description": "Detects connections to known malicious IPs over HTTP/HTTPS",
                "logic": "Outbound connection to threat intel listed IP",
                "wazuh_level": 14
            }
        ],
        "prevention": [
            "Deploy network proxy with threat intelligence feeds",
            "Block known malicious IPs at firewall",
            "Implement DNS filtering (Pi-hole, Cisco Umbrella)",
            "Enable TLS inspection on outbound traffic",
            "Monitor for unusual process-to-network connections",
            "Segment network to limit lateral movement"
        ],
        "sigma_yaml": """title: Suspicious Outbound Connection to C2 IP
id: CMD-014
status: experimental
description: Detects connections to known C2 infrastructure
references:
  - https://attack.mitre.org/techniques/T1071/001/
author: AI SOC Analyst Assistant
logsource:
  category: proxy
  product: windows
detection:
  selection:
    cs-host|re: '.*\\.(ru|cn|tk|pw|cc)'
    sc-bytes|gt: 100000
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001"""
    },
    "T1059.001": {
        "name": "PowerShell Execution",
        "sigma_rules": [
            {
                "id": "PS-001",
                "title": "Suspicious PowerShell Command Line",
                "description": "Detects encoded or obfuscated PowerShell commands",
                "logic": "PowerShell with -enc, -e, -EncodedCommand flags",
                "wazuh_level": 10
            }
        ],
        "prevention": [
            "Enable PowerShell Constrained Language Mode",
            "Deploy AppLocker/WDAC to restrict script execution",
            "Enable PowerShell Script Block Logging",
            "Enable AMSI (Antimalware Scan Interface)",
            "Disable PowerShell for non-admin users",
            "Monitor for Base64-encoded commands"
        ],
        "sigma_yaml": """title: Suspicious PowerShell Command Line
id: PS-001
status: experimental
description: Detects suspicious PowerShell execution patterns
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: AI SOC Analyst Assistant
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-e '
      - 'EncodedCommand'
      - 'bypass'
      - 'hidden'
      - 'Invoke-Expression'
      - 'IEX'
      - 'DownloadString'
      - 'Net.WebClient'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001"""
    },
    "T1505.003": {
        "name": "Web Shell Upload",
        "sigma_rules": [
            {
                "id": "WEB-001",
                "title": "Web Shell Upload Attempt",
                "description": "Detects web shell file uploads to web servers",
                "logic": "PHP/JSP/ASP files uploaded to upload directories",
                "wazuh_level": 9
            }
        ],
        "prevention": [
            "Disable script execution in upload directories",
            "Implement file type validation (allow only images)",
            "Use WAF to block shell upload patterns",
            "Scan uploaded files with antivirus",
            "Monitor web server access logs",
            "Deploy endpoint detection (EDR)"
        ],
        "sigma_yaml": """title: Web Shell Upload Attempt
id: WEB-001
status: experimental
description: Detects potential web shell uploads
references:
  - https://attack.mitre.org/techniques/T1505/003/
author: AI SOC Analyst Assistant
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/uploads/'
      - '/tmp/'
      - '/images/'
    cs-uri-stem|endswith:
      - '.php'
      - '.jsp'
      - '.asp'
      - '.aspx'
    sc-status: 200
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1505.003"""
    },
    "T1190": {
        "name": "SQL Injection",
        "sigma_rules": [
            {
                "id": "WEB-002",
                "title": "SQL Injection Attempt",
                "description": "Detects SQL injection patterns in HTTP requests",
                "logic": "UNION SELECT, OR 1=1, DROP TABLE in URI/parameters",
                "wazuh_level": 8
            }
        ],
        "prevention": [
            "Use parameterized queries/prepared statements",
            "Implement input validation and sanitization",
            "Deploy WAF with SQL injection rules",
            "Apply least privilege to database accounts",
            "Enable database query logging",
            "Regular security testing and code review"
        ],
        "sigma_yaml": """title: SQL Injection Attempt
id: WEB-002
status: experimental
description: Detects SQL injection patterns in web requests
references:
  - https://attack.mitre.org/techniques/T1190/
author: AI SOC Analyst Assistant
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: '(?i)(union\\s+select|or\\s+1=1|drop\\s+table|insert\\s+into|delete\\s+from)'
  condition: selection
level: medium
tags:
  - attack.initial_access
  - attack.t1190"""
    },
    "T1046": {
        "name": "Network Port Scan",
        "sigma_rules": [
            {
                "id": "SCAN-001",
                "title": "Network Port Scan",
                "description": "Detects network scanning activity",
                "logic": "Connection attempts to multiple ports in short time",
                "wazuh_level": 6
            }
        ],
        "prevention": [
            "Implement network segmentation",
            "Deploy IDS/IPS (Snort, Suricata)",
            "Rate-limit connections from single source",
            "Block scanning tools at firewall",
            "Monitor for SYN flood patterns",
            "Use honeypots for early detection"
        ],
        "sigma_yaml": """title: Network Port Scan
id: SCAN-001
status: experimental
description: Detects network port scanning activity
references:
  - https://attack.mitre.org/techniques/T1046/
author: AI SOC Analyst Assistant
logsource:
  category: firewall
detection:
  selection:
    action: denied
  condition: selection | count(dst_port) by src_ip > 20 within 1m
level: medium
tags:
  - attack.discovery
  - attack.t1046"""
    },
    "T1068": {
        "name": "Privilege Escalation",
        "sigma_rules": [
            {
                "id": "PRIV-001",
                "title": "Sudo Privilege Escalation",
                "description": "Detects sudo misuse or privilege escalation attempts",
                "logic": "Failed sudo attempts or suspicious sudo commands",
                "wazuh_level": 9
            }
        ],
        "prevention": [
            "Apply principle of least privilege",
            "Audit sudoers configuration regularly",
            "Require password for sudo (no NOPASSWD)",
            "Log all privileged commands",
            "Implement sudo command whitelisting",
            "Monitor for kernel exploit attempts"
        ],
        "sigma_yaml": """title: Sudo Privilege Escalation
id: PRIV-001
status: experimental
description: Detects sudo privilege escalation attempts
references:
  - https://attack.mitre.org/techniques/T1068/
author: AI SOC Analyst Assistant
logsource:
  category: auth
  product: linux
detection:
  selection:
    event_type: 'sudo'
    exit_code: 'failed'
  condition: selection | count() by user > 3 within 5m
level: high
tags:
  - attack.privilege_escalation
  - attack.t1068"""
    }
}

# ============================================================
# CUSTOM CSS STYLES (Works in both Light and Dark modes)
# ============================================================
st.markdown("""
<style>
    /* Main container */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    }
    [data-testid="stSidebar"] .stRadio > div {
        gap: 0.5rem;
    }
    [data-testid="stSidebar"] .stRadio > div > label {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        padding: 8px 12px;
        transition: all 0.3s ease;
        color: white !important;
    }
    [data-testid="stSidebar"] .stRadio > div > label:hover {
        background: rgba(255, 255, 255, 0.15);
    }
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span,
    [data-testid="stSidebar"] div {
        color: white !important;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 16px;
        color: white !important;
        text-align: center;
        box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        margin-bottom: 1rem;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 15px 40px rgba(102, 126, 234, 0.5);
    }
    .metric-card h3 {
        margin: 0;
        font-size: 2.5rem;
        font-weight: 700;
        color: white !important;
    }
    .metric-card p {
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
        font-size: 0.95rem;
        color: white !important;
    }

    .metric-critical {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        box-shadow: 0 10px 30px rgba(245, 87, 108, 0.4);
    }
    .metric-critical:hover {
        box-shadow: 0 15px 40px rgba(245, 87, 108, 0.5);
    }

    .metric-high {
        background: linear-gradient(135deg, #f5af19 0%, #f12711 100%);
        box-shadow: 0 10px 30px rgba(241, 39, 17, 0.4);
    }
    .metric-high:hover {
        box-shadow: 0 15px 40px rgba(241, 39, 17, 0.5);
    }

    .metric-success {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        box-shadow: 0 10px 30px rgba(56, 239, 125, 0.3);
    }
    .metric-success:hover {
        box-shadow: 0 15px 40px rgba(56, 239, 125, 0.4);
    }

    .metric-info {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        box-shadow: 0 10px 30px rgba(79, 172, 254, 0.4);
    }
    .metric-info:hover {
        box-shadow: 0 15px 40px rgba(79, 172, 254, 0.5);
    }

    /* Alert cards - works in both themes */
    .alert-card {
        background: var(--background-color, #ffffff);
        border: 1px solid var(--border-color, #e0e0e0);
        border-radius: 12px;
        padding: 1rem 1.5rem;
        margin-bottom: 0.8rem;
        border-left: 4px solid;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
        transition: all 0.3s ease;
        color: var(--text-color, #333333) !important;
    }
    .alert-card:hover {
        transform: translateX(5px);
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.12);
    }
    .alert-card p, .alert-card span, .alert-card div {
        color: var(--text-color, #333333) !important;
    }
    .alert-card.critical { border-left-color: #f5576c; }
    .alert-card.high { border-left-color: #f12711; }
    .alert-card.medium { border-left-color: #f5af19; }
    .alert-card.low { border-left-color: #38ef7d; }

    /* Section headers - gradient text works in both modes */
    .section-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 1.8rem;
        font-weight: 700;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #667eea;
    }

    /* Status badges */
    .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    .status-unacknowledged { background: #fff3cd; color: #856404; }
    .status-acknowledged { background: #d4edda; color: #155724; }
    .status-escalated { background: #f8d7da; color: #721c24; }
    .status-false_positive { background: #e2e3e5; color: #383d41; }

    /* Chat styling */
    .stChatMessage {
        border-radius: 16px;
        padding: 1rem;
        margin-bottom: 1rem;
    }

    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 10px 20px;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
    }

    /* DataFrame styling */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
    }

    /* Title styling */
    h1 {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    /* Glow effect for important elements */
    .glow {
        animation: glow 2s ease-in-out infinite alternate;
    }
    @keyframes glow {
        from { box-shadow: 0 0 5px rgba(102, 126, 234, 0.5); }
        to { box-shadow: 0 0 20px rgba(102, 126, 234, 0.8); }
    }

    /* Pulse animation for critical alerts */
    .pulse {
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }

    /* Card container - works in both themes */
    .card-container {
        background: var(--background-color, #ffffff);
        border: 1px solid var(--border-color, #e0e0e0);
        border-radius: 16px;
        padding: 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        margin-bottom: 1rem;
        color: var(--text-color, #333333) !important;
    }
    .card-container p, .card-container span, .card-container div, .card-container h3, .card-container h4 {
        color: var(--text-color, #333333) !important;
    }

    /* Sigma rule box */
    .sigma-box {
        background: #1e1e2e;
        color: #cdd6f4;
        border-radius: 8px;
        padding: 1rem;
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
        overflow-x: auto;
    }

    /* Prevention box - works in both themes */
    .prevention-box {
        background: linear-gradient(135deg, #667eea22 0%, #764ba222 100%);
        border: 1px solid #667eea;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        color: var(--text-color, #333333) !important;
    }
    .prevention-box p, .prevention-box h3, .prevention-box h4, .prevention-box li {
        color: var(--text-color, #333333) !important;
    }

    /* Info boxes */
    .stAlert > div {
        border-radius: 8px;
    }

    /* Make sure text in expanders is visible */
    .streamlit-expanderContent p,
    .streamlit-expanderContent span,
    .streamlit-expanderContent div {
        color: var(--text-color, #333333) !important;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("""
    <div style='text-align: center; padding: 1rem 0;'>
        <h1 style='color: white; font-size: 1.5rem; margin: 0;'>🛡️ AI SOC</h1>
        <p style='color: rgba(255,255,255,0.7); margin: 0;'>Analyst Assistant</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    page = st.selectbox(
        "Navigation",
        ["📊 Dashboard", "🔍 Alert Detail", "📋 Reports", "🛡️ Threat Intel", "🚨 Incident Response", "🎯 Attack Training", "📜 Compliance", "🤖 AI Assistant", "🔎 Search", "⚙️ Settings"],
        index=0,
    )

    st.markdown("---")

    try:
        health = get_json("/health")
        st.markdown(f"""
        <div style='background: rgba(255,255,255,0.1); border-radius: 10px; padding: 1rem; margin-top: 1rem;'>
            <p style='color: #38ef7d; margin: 0; font-weight: 600;'>● Backend Online</p>
            <p style='color: rgba(255,255,255,0.7); margin: 0.5rem 0 0 0; font-size: 0.9rem;'>
                {health['alerts_in_db']} alerts in database
            </p>
        </div>
        """, unsafe_allow_html=True)
    except Exception:
        st.markdown("""
        <div style='background: rgba(255,0,0,0.2); border-radius: 10px; padding: 1rem; margin-top: 1rem;'>
            <p style='color: #ff6b6b; margin: 0; font-weight: 600;'>● Backend Offline</p>
            <p style='color: rgba(255,255,255,0.7); margin: 0.5rem 0 0 0; font-size: 0.9rem;'>
                Start: uvicorn backend.app.main:app --port 8000
            </p>
        </div>
        """, unsafe_allow_html=True)

# ============================================================
# DASHBOARD PAGE
# ============================================================
if page == "📊 Dashboard":
    st.markdown('<p class="section-header">Security Operations Dashboard</p>', unsafe_allow_html=True)

    stats = get_json("/stats")
    s = stats["severity_counts"]
    alerts_df = fetch_alerts({"limit": 200})

    severity_filter = st.multiselect(
        "Filter by severity",
        options=["critical", "high", "medium", "low"],
        default=["critical", "high", "medium", "low"],
        help="Select the severities you want visible in the queue.",
    )

    if not alerts_df.empty:
        alerts_df = alerts_df[alerts_df["severity"].isin(severity_filter)].copy()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"<div class='metric-card'><h3>{stats['total_alerts']}</h3><p>Total Alerts</p><p style='font-size:0.8rem;opacity:0.8;'>+{stats['alerts_24h']} in 24h</p></div>", unsafe_allow_html=True)
    with col2:
        st.markdown(f"<div class='metric-card metric-critical'><h3>{s.get('critical', 0)}</h3><p>Critical</p></div>", unsafe_allow_html=True)
    with col3:
        st.markdown(f"<div class='metric-card metric-high'><h3>{s.get('high', 0)}</h3><p>High</p></div>", unsafe_allow_html=True)
    with col4:
        st.markdown(f"<div class='metric-card metric-success'><h3>{stats['avg_confidence']:.0%}</h3><p>AI Confidence</p></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    colA, colB = st.columns(2)
    with colA:
        st.markdown('<p class="section-header" style="font-size: 1.2rem;">Severity Distribution</p>', unsafe_allow_html=True)
        sev_df = pd.DataFrame({"Severity": list(s.keys()), "Count": list(s.values())})
        sev_df = sev_df[sev_df["Count"] > 0]
        if not sev_df.empty:
            fig = px.pie(sev_df, names="Severity", values="Count", color="Severity", color_discrete_map=SEVERITY_COLORS, hole=0.5)
            fig.update_layout(margin=dict(t=20, b=10, l=10, r=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert distribution data yet.")

    with colB:
        st.markdown('<p class="section-header" style="font-size: 1.2rem;">Alert Queue</p>', unsafe_allow_html=True)
        if not alerts_df.empty:
            queue_df = alerts_df[["alert_ref", "severity", "agent", "description", "timestamp"]].copy()
            queue_df["timestamp"] = pd.to_datetime(queue_df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
            st.dataframe(queue_df.head(10), use_container_width=True, hide_index=True)
        else:
            st.info("No alerts match the selected filter.")

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown('<p class="section-header">Quick Alert Actions</p>', unsafe_allow_html=True)
    if alerts_df.empty:
        st.info("There are no alerts to investigate with the current filter.")
    else:
        selected_alert = st.selectbox(
            "Jump to an alert",
            options=[f"{row.alert_ref} | {row.severity.upper()} | {row.agent} | {row.description[:60]}" for _, row in alerts_df.head(20).iterrows()],
            index=0,
            help="Select an alert to open in the detailed investigation panel.",
        )
        selected_id = alerts_df.loc[alerts_df["alert_ref"] == selected_alert.split(" | ")[0], "id"].iloc[0]
        if st.button("Open selected alert", use_container_width=True):
            st.session_state["focus_alert_id"] = selected_id
            st.session_state["current_page"] = "🔍 Alert Detail"
            st.rerun()

        st.markdown('<p class="section-header" style="font-size: 1.1rem;">Recent Priority Alerts</p>', unsafe_allow_html=True)
        recent = alerts_df.sort_values(by="severity", key=lambda c: c.map(SEVERITY_ORDER)).head(8)
        for _, row in recent.iterrows():
            st.markdown(f"""
            <div class="alert-card {row['severity']}">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem;">
                    <div>
                        <strong>{row['alert_ref']}</strong>
                        <div style="font-size:0.8rem; color:#666; margin-top:4px;">{row['agent']} · {row['timestamp']}</div>
                    </div>
                    <span style="color:{SEVERITY_COLORS.get(row['severity'], '#666')}; font-weight:700;">{row['severity'].upper()}</span>
                </div>
                <p style="margin:0.6rem 0 0 0;">{row['description']}</p>
            </div>
            """, unsafe_allow_html=True)

# ============================================================
# ALERT DETAIL PAGE
# ============================================================
elif page == "🔍 Alert Detail":
    st.markdown('<p class="section-header">Alert Investigation</p>', unsafe_allow_html=True)

    df = fetch_alerts({"limit": 200})
    if df.empty:
        st.info("No alerts available yet.")
        st.stop()

    options = {
        f"{r.alert_ref} | {r.severity.upper():<9} | {r.agent} | {r.description}": r.id
        for r in df.itertuples()
    }
    default_choice = None
    default_alert_id = st.session_state.get("focus_alert_id")
    if default_alert_id is not None:
        for label, alert_id_value in options.items():
            if alert_id_value == default_alert_id:
                default_choice = label
                break
    choice = st.selectbox(
        "Select an alert:",
        list(options.keys()),
        index=list(options.keys()).index(default_choice) if default_choice else 0,
    )
    alert_id = options[choice]
    st.session_state["focus_alert_id"] = alert_id
    alert = get_json(f"/alerts/{alert_id}")

    # Alert header with severity badge and download buttons
    sev_color = SEVERITY_COLORS.get(alert["ml_severity"], "#666")
    
    col_header1, col_header2 = st.columns([3, 1])
    with col_header1:
        st.markdown(f"""
        <div class="card-container" style="border-left: 5px solid {sev_color};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h2 style="margin: 0;">{alert['alert_ref']}</h2>
                    <p style="margin: 0.5rem 0 0 0;">
                        Confidence: {alert['ml_confidence']:.0%} | Status: {alert['status']} | AI mode: {alert['ai_model']}
                    </p>
                </div>
                <div style="background: {sev_color}; color: white; padding: 8px 20px; border-radius: 20px; font-weight: bold;">
                    {alert['ml_severity'].upper()}
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col_header2:
        # Generate detailed report content
        detailed_report = f"""# Alert Report: {alert['alert_ref']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Alert Summary
- **Alert ID:** {alert['alert_ref']}
- **Severity:** {alert['ml_severity'].upper()}
- **Confidence:** {alert['ml_confidence']:.0%}
- **Status:** {alert['status']}

## Alert Information
- **Agent:** {alert['agent_name']}
- **IP Address:** {alert['agent_ip']}
- **Operating System:** {alert['os_type']}
- **Timestamp:** {alert['timestamp']}
- **Source:** {alert['source']}

## Detection Details
- **Wazuh Rule ID:** {alert['wazuh_rule_id']}
- **Wazuh Level:** {alert['wazuh_level']}
- **Sigma Rule:** {alert['sigma_rule_id']} — {alert['sigma_title']}
- **Description:** {alert['description']}

## MITRE ATT&CK Mapping
- **Tactic:** {alert['mitre_tactic']} ({alert['mitre_tactic_id']})
- **Technique:** {alert['mitre_technique']} ({alert['mitre_technique_id']})
- **Kill Chain Phase:** {alert['kill_chain_phase']}

## AI Analysis
### Summary
{alert.get('ai_summary') or 'No summary generated.'}

### Technique Explanation
{alert.get('ai_technique') or 'Not generated (offline mode).'}

### Remediation Steps
{alert.get('ai_remediation') or 'No remediation generated.'}

## Raw Log Data
```json
{alert.get('raw_log') or 'No raw log available'}
```
"""
        
        # Download buttons in the right corner
        st.download_button(
            label="📥 Download Report",
            data=detailed_report,
            file_name=f"alert_{alert['alert_ref']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        
        json_report = {
            "alert_id": alert['alert_ref'],
            "timestamp": alert['timestamp'],
            "severity": alert['ml_severity'],
            "confidence": alert['ml_confidence'],
            "status": alert['status'],
            "agent": {
                "name": alert['agent_name'],
                "ip": alert['agent_ip'],
                "os": alert['os_type'],
            },
            "detection": {
                "wazuh_rule_id": alert['wazuh_rule_id'],
                "wazuh_level": alert['wazuh_level'],
                "sigma_rule_id": alert['sigma_rule_id'],
                "sigma_title": alert['sigma_title'],
                "description": alert['description'],
            },
            "mitre": {
                "tactic": alert['mitre_tactic'],
                "tactic_id": alert['mitre_tactic_id'],
                "technique": alert['mitre_technique'],
                "technique_id": alert['mitre_technique_id'],
                "kill_chain": alert['kill_chain_phase'],
            },
            "ai_analysis": {
                "summary": alert.get('ai_summary'),
                "technique": alert.get('ai_technique'),
                "remediation": alert.get('ai_remediation'),
            },
            "raw_log": alert.get('raw_log'),
        }
        
        st.download_button(
            label="📥 Download JSON",
            data=json.dumps(json_report, indent=2),
            file_name=f"alert_{alert['alert_ref']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    t1, t2 = st.tabs(["📋 Raw Alert", "🤖 AI Analysis"])

    with t1:
        col1, col2 = st.columns(2)

        with col1:
            st.markdown('<p class="section-header" style="font-size: 1.1rem;">Alert Metadata</p>', unsafe_allow_html=True)
            meta = {
                "🖥️ Agent": alert["agent_name"],
                "🌐 IP": alert["agent_ip"],
                "💻 OS": alert["os_type"],
                "📅 Timestamp": alert["timestamp"],
                "📡 Source": alert["source"],
                "🆔 Wazuh Rule ID": alert["wazuh_rule_id"],
                "📊 Wazuh Level": alert["wazuh_level"],
            }
            for k, v in meta.items():
                st.markdown(f"**{k}:** {v}")

        with col2:
            st.markdown('<p class="section-header" style="font-size: 1.1rem;">MITRE ATT&CK</p>', unsafe_allow_html=True)
            st.markdown(f"""
            <div class="card-container">
                <p><strong>🎯 Tactic:</strong> {alert['mitre_tactic']} ({alert['mitre_tactic_id']})</p>
                <p><strong>⚡ Technique:</strong> {alert['mitre_technique']} ({alert['mitre_technique_id']})</p>
                <p><strong>🔗 Kill Chain:</strong> {alert['kill_chain_phase']}</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<p class="section-header" style="font-size: 1.1rem;">Sigma Rule</p>', unsafe_allow_html=True)
        st.markdown(f"**{alert['sigma_rule_id']}** — {alert['sigma_title']}")
        st.markdown(f"**Description:** {alert['description']}")

        if alert.get("ml_proba"):
            st.markdown('<p class="section-header" style="font-size: 1.1rem;">ML Prediction Probabilities</p>', unsafe_allow_html=True)
            proba_df = pd.DataFrame(alert["ml_proba"], index=["Probability"]).T
            fig = px.bar(
                proba_df,
                x=proba_df.index,
                y="Probability",
                color=proba_df.index,
                color_discrete_map=SEVERITY_COLORS,
            )
            fig.update_layout(
                showlegend=False,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
            )
            st.plotly_chart(fig, use_container_width=True)

        st.markdown('<p class="section-header" style="font-size: 1.1rem;">Raw Log</p>', unsafe_allow_html=True)
        st.code(alert.get("raw_log") or "-", language="json")

    # AI Analysis tabs
    tabs = st.tabs(["📝 Summary", "🎯 Technique", "🔧 Remediation", "🔗 Related"])
    with tabs[0]:
        st.markdown(f"""
        <div class="card-container">
            {alert.get('ai_summary') or 'No summary generated.'}
        </div>
        """, unsafe_allow_html=True)
    with tabs[1]:
        st.markdown(f"""
        <div class="card-container">
            {alert.get('ai_technique') or 'Not generated (offline mode).'}
        </div>
        """, unsafe_allow_html=True)
    with tabs[2]:
        st.markdown(f"""
        <div class="card-container">
            {alert.get('ai_remediation') or 'No remediation generated.'}
        </div>
        """, unsafe_allow_html=True)
    with tabs[3]:
        rag_sources = alert.get("ai_rag_sources") or "[]"
        if isinstance(rag_sources, list):
            sources = rag_sources
        else:
            sources = json.loads(rag_sources)
        if sources:
            st.markdown('<div class="card-container">', unsafe_allow_html=True)
            st.write("Retrieved similar incidents (RAG):")
            for s in sources:
                st.markdown(f"- `{s}`")
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("No related incidents retrieved yet.")

    st.markdown("<br>", unsafe_allow_html=True)

    # Actions section
    st.markdown('<p class="section-header">Actions</p>', unsafe_allow_html=True)
    ca, cb, cc, cd = st.columns(4)
    if ca.button("✅ Acknowledge", use_container_width=True):
        api("PATCH", f"/alerts/{alert_id}/status", params={"status": "acknowledged"})
        st.success("Alert acknowledged")
    if cb.button("🚨 Escalate", use_container_width=True):
        api("PATCH", f"/alerts/{alert_id}/status", params={"status": "escalated"})
        st.success("Alert escalated")
    if cc.button("❌ Mark False Positive", use_container_width=True):
        api("PATCH", f"/alerts/{alert_id}/status", params={"status": "false_positive"})
        st.success("Marked false positive")
    if cd.button("🔄 Refresh", use_container_width=True):
        st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Prevention Recommendations Section
    st.markdown('<p class="section-header">🛡️ Prevention Recommendations</p>', unsafe_allow_html=True)

    mitre_tid = alert.get("mitre_technique_id", "")
    if mitre_tid in PREVENTION_RULES:
        rule_data = PREVENTION_RULES[mitre_tid]

        st.markdown(f"""
        <div class="prevention-box">
            <h3 style="margin-top: 0;">{rule_data['name']}</h3>
            <p>MITRE ATT&CK: {mitre_tid}</p>
        </div>
        """, unsafe_allow_html=True)

        # Prevention steps
        st.markdown("**Prevention Measures:**")
        for i, step in enumerate(rule_data['prevention'], 1):
            st.markdown(f"{i}. {step}")

        # Sigma rules
        st.markdown("**Detection Sigma Rules:**")
        for sigma in rule_data['sigma_rules']:
            st.markdown(f"""
            <div class="card-container">
                <strong>{sigma['id']}</strong> — {sigma['title']}<br>
                <em>{sigma['description']}</em><br>
                <small>Detection Logic: {sigma['logic']}</small>
            </div>
            """, unsafe_allow_html=True)

        # Sigma YAML code
        with st.expander("📄 View Sigma Rule YAML", expanded=False):
            st.code(rule_data['sigma_yaml'], language="yaml")
    else:
        st.info("No prevention rules available for this MITRE technique.")

    st.markdown("<br>", unsafe_allow_html=True)

    # Feedback section
    st.markdown('<p class="section-header">Analyst Feedback</p>', unsafe_allow_html=True)
    with st.form("feedback_form"):
        col1, col2 = st.columns(2)
        with col1:
            sev_correct = st.checkbox("✅ Severity prediction was correct", value=True)
            is_fp = st.checkbox("❌ This is a false positive", value=False)
        with col2:
            analyst_sev = st.selectbox("If wrong, correct severity:", ["low", "medium", "high", "critical"])
            name = st.text_input("👤 Analyst name:", value="analyst")

        notes = st.text_area("📝 Analyst notes:")
        submitted = st.form_submit_button("📤 Submit Feedback", use_container_width=True)
        if submitted:
            post_json("/feedback", {
                "alert_id": alert_id,
                "severity_correct": sev_correct,
                "analyst_severity": analyst_sev,
                "is_false_positive": is_fp,
                "analyst_notes": notes,
                "analyst_name": name,
            })
            st.success("✅ Feedback recorded — will be used for retraining.")

# ============================================================
# REPORTS PAGE
# ============================================================
elif page == "📋 Reports":
    st.markdown('<p class="section-header">Detailed Reports & Downloads</p>', unsafe_allow_html=True)

    # Report type selection
    report_type = st.selectbox(
        "Select Report Type:",
        ["Full Alert Summary", "SSH Brute Force Report", "Ransomware Report", "C2 Beaconing Report", "Custom Report"]
    )

    df = fetch_alerts({"limit": 500})

    if df.empty:
        st.info("No alerts available to generate reports.")
        st.stop()

    # Generate report content
    if report_type == "Full Alert Summary":
        report_content = f"""# AI SOC Analyst Assistant - Full Alert Summary Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
- Total Alerts: {len(df)}
- Critical: {len(df[df['severity'] == 'critical'])}
- High: {len(df[df['severity'] == 'high'])}
- Medium: {len(df[df['severity'] == 'medium'])}
- Low: {len(df[df['severity'] == 'low'])}

## Alert Details
"""
        for _, row in df.head(50).iterrows():
            report_content += f"""
### {row['alert_ref']}
- Severity: {row['severity'].upper()}
- Agent: {row['agent']}
- Description: {row['description']}
- MITRE: {row['mitre']}
- Confidence: {row['confidence']:.0%}
- Status: {row['status']}
"""

    elif "SSH" in report_type:
        ssh_df = df[df['mitre'] == 'T1110']
        report_content = f"""# SSH Brute Force Attack Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Attack Overview
- Attack Type: SSH Brute Force (Dictionary Attack)
- MITRE ATT&CK: T1110 — Brute Force
- Total Incidents: {len(ssh_df)}

## Detection Rule
- Sigma Rule: BRUTE-002
- Rule Title: SSH Brute Force Detection
- Wazuh Level: 10

## Affected Systems
"""
        for _, row in ssh_df.iterrows():
            report_content += f"""
- {row['agent']} ({row['alert_ref']}) — {row['severity'].upper()}
"""

        report_content += """
## Prevention Measures
1. Implement account lockout policies (5 failed attempts = 15min lockout)
2. Enable Multi-Factor Authentication (MFA) on all SSH access
3. Use key-based authentication instead of passwords
4. Change SSH to non-standard port (e.g., 2222)
5. Deploy fail2ban for automatic IP blocking
6. Restrict SSH access via firewall rules

## Sigma Detection Rule
```yaml
title: SSH Brute Force Detection
id: BRUTE-002
status: experimental
description: Detects multiple failed SSH login attempts
logsource:
  category: authentication
  product: linux
detection:
  selection:
    event_id: 4625
    logon_type: 10
  condition: selection | count(target_user) by ip_address > 5 within 5m
level: high
tags:
  - attack.credential_access
  - attack.t1110
```
"""

    elif "Ransomware" in report_type:
        ran_df = df[df['mitre'] == 'T1486']
        report_content = f"""# Ransomware Attack Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Attack Overview
- Attack Type: Ransomware File Encryption
- MITRE ATT&CK: T1486 — Data Encrypted for Impact
- Total Incidents: {len(ran_df)}

## Detection Rule
- Sigma Rule: RAN-001
- Rule Title: Ransomware File Encryption Pattern
- Wazuh Level: 15

## Affected Systems
"""
        for _, row in ran_df.iterrows():
            report_content += f"""
- {row['agent']} ({row['alert_ref']}) — {row['severity'].upper()}
"""

        report_content += """
## Prevention Measures
1. Maintain offline backups (3-2-1 rule: 3 copies, 2 media, 1 offsite)
2. Enable Volume Shadow Copy for quick recovery
3. Restrict write permissions on shared drives
4. Deploy application whitelisting
5. Disable PowerShell for standard users
6. Keep all systems patched and updated

## Sigma Detection Rule
```yaml
title: Ransomware File Encryption Pattern
id: RAN-001
status: experimental
description: Detects bulk file modification typical of ransomware
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 11
    TargetFilename|endswith:
      - '.locked'
      - '.encrypted'
      - '.crypto'
  condition: selection | count(TargetFilename) by Image > 50 within 1m
level: critical
tags:
  - attack.impact
  - attack.t1486
```
"""

    elif "C2" in report_type:
        c2_df = df[df['mitre'] == 'T1071.001']
        report_content = f"""# C2 Beaconing Attack Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Attack Overview
- Attack Type: Command and Control (C2) Beaconing
- MITRE ATT&CK: T1071.001 — Application Layer Protocol: Web Protocols
- Total Incidents: {len(c2_df)}

## Detection Rule
- Sigma Rule: CMD-014
- Rule Title: Suspicious Outbound Connection to C2 IP
- Wazuh Level: 14

## Affected Systems
"""
        for _, row in c2_df.iterrows():
            report_content += f"""
- {row['agent']} ({row['alert_ref']}) — {row['severity'].upper()}
"""

        report_content += """
## Prevention Measures
1. Deploy network proxy with threat intelligence feeds
2. Block known malicious IPs at firewall
3. Implement DNS filtering (Pi-hole, Cisco Umbrella)
4. Enable TLS inspection on outbound traffic
5. Monitor for unusual process-to-network connections
6. Segment network to limit lateral movement

## Sigma Detection Rule
```yaml
title: Suspicious Outbound Connection to C2 IP
id: CMD-014
status: experimental
description: Detects connections to known C2 infrastructure
logsource:
  category: proxy
  product: windows
detection:
  selection:
    cs-host|re: '.*\\.(ru|cn|tk|pw|cc)'
    sc-bytes|gt: 100000
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1071.001
```
"""

    else:
        # Custom report
        report_content = f"""# AI SOC Analyst Assistant - Custom Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Filtered Alerts
"""
        for _, row in df.iterrows():
            report_content += f"""
### {row['alert_ref']}
- Severity: {row['severity'].upper()}
- Agent: {row['agent']}
- Description: {row['description']}
- MITRE: {row['mitre']}
- Confidence: {row['confidence']:.0%}
"""

    # Display report preview
    st.markdown('<p class="section-header" style="font-size: 1.2rem;">Report Preview</p>', unsafe_allow_html=True)
    st.code(report_content, language="markdown")

    # Download buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button(
            label="📥 Download Markdown Report",
            data=report_content,
            file_name=f"soc_report_{report_type.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    with col2:
        # Convert to JSON for download
        json_data = {
            "report_type": report_type,
            "generated_at": datetime.now().isoformat(),
            "total_alerts": len(df),
            "severity_counts": df['severity'].value_counts().to_dict(),
            "alerts": df.to_dict(orient='records')
        }
        st.download_button(
            label="📥 Download JSON Data",
            data=json.dumps(json_data, indent=2),
            file_name=f"soc_data_{report_type.replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col3:
        # CSV download
        csv_data = df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV Export",
            data=csv_data,
            file_name=f"soc_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Prevention Rules Summary
    st.markdown('<p class="section-header">🛡️ Prevention Rules Database</p>', unsafe_allow_html=True)

    for tid, rule_data in PREVENTION_RULES.items():
        with st.expander(f"📌 {rule_data['name']} ({tid})", expanded=False):
            st.markdown("**Prevention Measures:**")
            for i, step in enumerate(rule_data['prevention'], 1):
                st.markdown(f"{i}. {step}")

            st.markdown("**Sigma Rule:**")
            st.code(rule_data['sigma_yaml'], language="yaml")

# ============================================================
# THREAT INTELLIGENCE PAGE
# ============================================================
elif page == "🛡️ Threat Intel":
    st.markdown('<p class="section-header">Threat Intelligence</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown('<p class="section-header" style="font-size: 1.1rem;">IP Lookup</p>', unsafe_allow_html=True)
        ip_to_lookup = st.text_input("Enter IP address to lookup:")
        if st.button("🔍 Lookup IP", use_container_width=True):
            if ip_to_lookup:
                with st.spinner("Querying threat intelligence..."):
                    try:
                        ti = post_json("/threat-intel/lookup", {"ip": ip_to_lookup})
                        st.session_state.ti_result = ti
                    except Exception as e:
                        st.error(f"Lookup failed: {e}")

    with col2:
        st.markdown('<p class="section-header" style="font-size: 1.1rem;">Results</p>', unsafe_allow_html=True)
        if "ti_result" in st.session_state:
            ti = st.session_state.ti_result
            if ti.get("is_malicious"):
                st.error(f"🚨 MALICIOUS IP DETECTED")
            else:
                st.success(f"✅ IP appears clean")

            col_a, col_b = st.columns(2)
            with col_a:
                st.metric("Threat Score", f"{ti.get('threat_score', 0):.0%}")
                st.metric("Country", ti.get("country", "Unknown"))
            with col_b:
                st.metric("Reports", ti.get("reports", 0))
                st.metric("Source", ti.get("source", "Unknown"))

            st.markdown(f"**ISP:** {ti.get('isp', 'Unknown')}")
            st.markdown(f"**Details:** {ti.get('details', 'N/A')}")
        else:
            st.info("Enter an IP address to check threat intelligence")

    st.markdown("<br>", unsafe_allow_html=True)

    # Known Threats from Alerts
    st.markdown('<p class="section-header">Known Threats from Alerts</p>', unsafe_allow_html=True)
    df = fetch_alerts({"limit": 50})
    if not df.empty:
        # Extract unique IPs from descriptions
        for _, row in df.head(10).iterrows():
            st.markdown(f"""
            <div class="alert-card {row['severity']}">
                <strong>{row['alert_ref']}</strong> — {row['description'][:60]}...
                <br><small>🎯 {row['mitre']} | 🖥️ {row['agent']}</small>
            </div>
            """, unsafe_allow_html=True)

# ============================================================
# INCIDENT RESPONSE PAGE
# ============================================================
elif page == "🚨 Incident Response":
    st.markdown('<p class="section-header">Incident Response Actions</p>', unsafe_allow_html=True)

    df = fetch_alerts({"limit": 50})
    if df.empty:
        st.info("No alerts available for incident response.")
        st.stop()

    # Select alert
    options = {
        f"{r.alert_ref} | {r.severity.upper()} | {r.agent} | {r.description[:50]}": r.id
        for r in df.itertuples()
    }
    choice = st.selectbox("Select alert for IR actions:", list(options.keys()))
    alert_id = options[choice]
    alert = get_json(f"/alerts/{alert_id}")

    # Display alert info
    st.markdown(f"""
    <div class="card-container" style="border-left: 5px solid {SEVERITY_COLORS.get(alert['ml_severity'], '#666')};">
        <h3 style="margin: 0;">{alert['alert_ref']} — {alert['ml_severity'].upper()}</h3>
        <p style="margin: 0.5rem 0; color: #666;">{alert['description']}</p>
    </div>
    """, unsafe_allow_html=True)

    # IR Actions
    st.markdown('<p class="section-header">Available Actions</p>', unsafe_allow_html=True)

    # Action buttons based on alert type
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🔍 Collect Evidence", use_container_width=True):
            with st.spinner("Collecting evidence..."):
                result = post_json("/ir/action", {"action": "collect_evidence", "target": alert["agent_name"]})
                st.success(f"✅ {result.get('message', 'Action completed')}")

    with col2:
        if st.button("🚫 Block Source IP", use_container_width=True):
            with st.spinner("Blocking IP..."):
                result = post_json("/ir/action", {"action": "block_ip", "target": "attacker_ip"})
                st.success(f"✅ {result.get('message', 'Action completed')}")

    with col3:
        if st.button("🔌 Isolate Host", use_container_width=True):
            st.warning("⚠️ Host isolation requires approval")
            result = post_json("/ir/action", {"action": "isolate_host", "target": alert["agent_name"]})
            st.info(f"📋 {result.get('message', 'Pending approval')}")

    with col4:
        if st.button("🔑 Reset Password", use_container_width=True):
            st.warning("⚠️ Password reset requires approval")
            result = post_json("/ir/action", {"action": "reset_password", "target": "affected_user"})
            st.info(f"📋 {result.get('message', 'Pending approval')}")

    st.markdown("<br>", unsafe_allow_html=True)

    # Action Log
    st.markdown('<p class="section-header">Action Log</p>', unsafe_allow_html=True)
    try:
        log = get_json("/ir/log")
        if log:
            for entry in log:
                status_color = "green" if entry["status"] == "success" else "orange" if "pending" in entry["status"] else "red"
                st.markdown(f"""
                <div class="card-container">
                    <span style="color: {status_color}; font-weight: bold;">{entry['status'].upper()}</span>
                    — <strong>{entry['action']}</strong> on {entry['target']}
                    <br><small>{entry['message']}</small>
                    <br><small>🕐 {entry['timestamp']}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No actions logged yet")
    except Exception:
        st.info("No actions logged yet")

# ============================================================
# ATTACK TRAINING PAGE
# ============================================================
elif page == "🎯 Attack Training":
    st.markdown('<p class="section-header">Attack Simulation Training</p>', unsafe_allow_html=True)

    st.markdown("""
    <div class="card-container">
        <p>Learn how different attacks work through interactive simulations.
        Each scenario includes step-by-step explanations, detection tips, and Sigma rules.</p>
    </div>
    """, unsafe_allow_html=True)

    # Get scenarios from backend
    try:
        scenarios = get_json("/training/scenarios")
    except Exception:
        scenarios = [
            {"id": "ssh_bruteforce", "name": "SSH Brute Force Attack", "difficulty": "beginner", "mitre_tid": "T1110"},
            {"id": "ransomware", "name": "Ransomware Encryption Attack", "difficulty": "intermediate", "mitre_tid": "T1486"},
            {"id": "c2_beaconing", "name": "C2 Beaconing Attack", "difficulty": "advanced", "mitre_tid": "T1071.001"},
            {"id": "sql_injection", "name": "SQL Injection Attack", "difficulty": "intermediate", "mitre_tid": "T1190"},
            {"id": "privilege_escalation", "name": "Privilege Escalation Attack", "difficulty": "advanced", "mitre_tid": "T1068"},
        ]

    # Display scenarios
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown('<p class="section-header" style="font-size: 1.1rem;">Select Scenario</p>', unsafe_allow_html=True)
        scenario_options = {f"{s['name']} ({s['difficulty']})": s['id'] for s in scenarios}
        selected = st.selectbox("Choose attack scenario:", list(scenario_options.keys()))
        scenario_id = scenario_options[selected]

        if st.button("🚀 Start Simulation", use_container_width=True):
            st.session_state.active_scenario = scenario_id
            st.session_state.step_index = 0
            st.rerun()

    with col2:
        if "active_scenario" in st.session_state:
            try:
                scenario_detail = get_json(f"/training/scenario/{st.session_state.active_scenario}")
            except Exception:
                scenario_detail = {
                    "scenario": {
                        "name": selected.split(" (")[0],
                        "description": "Interactive attack simulation",
                        "mitre_tid": "T1110",
                    },
                    "learning_objectives": ["Understand attack patterns", "Learn detection techniques"],
                    "current_step": {"phase": "Start", "action": "Begin the simulation"},
                    "total_steps": 5,
                }

            st.markdown(f"""
            <div class="card-container">
                <h3 style="margin: 0;">{scenario_detail['scenario']['name']}</h3>
                <p style="color: #666;">{scenario_detail['scenario']['description']}</p>
                <p><strong>MITRE:</strong> {scenario_detail['scenario']['mitre_tid']}</p>
            </div>
            """, unsafe_allow_html=True)

            # Learning objectives
            st.markdown("**Learning Objectives:**")
            for obj in scenario_detail.get("learning_objectives", []):
                st.markdown(f"- ✅ {obj}")

            # Current step
            if "current_step" in scenario_detail:
                step = scenario_detail["current_step"]
                st.markdown(f"""
                <div class="prevention-box">
                    <h4 style="margin: 0;">Step {step.get('step_number', 1)}: {step.get('phase', 'Unknown')}</h4>
                    <p><strong>Action:</strong> {step.get('action', 'N/A')}</p>
                    <p><strong>Command:</strong> <code>{step.get('command', 'N/A')}</code></p>
                    <p><strong>What to look for:</strong> {step.get('what_to_look', 'N/A')}</p>
                    <p><strong>Detection:</strong> {step.get('sigma_detection', 'N/A')}</p>
                </div>
                """, unsafe_allow_html=True)

            # Navigation buttons
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("⏭️ Next Step", use_container_width=True):
                    try:
                        result = post_json("/training/advance", {"scenario_id": st.session_state.active_scenario})
                        if result.get("completed"):
                            st.success("🎉 Scenario completed!")
                            st.markdown(f"<div class='card-container'><b>Detection Tips:</b><br>{'<br>'.join('• ' + t for t in result.get('detection_tips', []))}</div>", unsafe_allow_html=True)
                            if st.button("🔄 Start New Scenario", key="completed_restart"):
                                del st.session_state.active_scenario
                                st.rerun()
                        else:
                            st.rerun()
                    except Exception as e:
                        st.error(f"Advance failed: {e}")

            with col_b:
                if st.button("🔄 Restart", use_container_width=True):
                    del st.session_state.active_scenario
                    st.rerun()
        else:
            st.info("Select a scenario and click 'Start Simulation' to begin")

# ============================================================
# COMPLIANCE PAGE
# ============================================================
elif page == "📜 Compliance":
    st.markdown('<p class="section-header">Compliance Reports</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown('<p class="section-header" style="font-size: 1.1rem;">Select Standard</p>', unsafe_allow_html=True)
        standard = st.selectbox("Compliance Standard:", ["GDPR", "HIPAA", "SOC2", "PCI_DSS"])

        if st.button("📊 Generate Report", use_container_width=True):
            with st.spinner("Generating compliance report..."):
                try:
                    stats = get_json("/stats")
                    report = post_json("/compliance/generate", {
                        "standard": standard,
                        "stats": stats,
                    })
                    st.session_state.compliance_report = report
                except Exception as e:
                    st.error(f"Failed to generate report: {e}")

    with col2:
        if "compliance_report" in st.session_state:
            report = st.session_state.compliance_report

            # Score display
            score = report.get("score", 0)
            status = report.get("status", "unknown")
            status_color = "green" if status == "compliant" else "red"

            st.markdown(f"""
            <div class="metric-card" style="background: linear-gradient(135deg, {'#11998e' if score >= 80 else '#f5576c'} 0%, {'#38ef7d' if score >= 80 else '#f093fb'} 100%);">
                <h3>{score:.0f}%</h3>
                <p>Compliance Score</p>
                <p style="font-size: 1.2rem; font-weight: bold;">{status.upper()}</p>
            </div>
            """, unsafe_allow_html=True)

            # Summary
            summary = report.get("summary", {})
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Compliant", summary.get("compliant", 0))
            with col_b:
                st.metric("Partial", summary.get("partial", 0))
            with col_c:
                st.metric("Non-Compliant", summary.get("non_compliant", 0))

            # Findings
            st.markdown('<p class="section-header" style="font-size: 1.1rem;">Findings</p>', unsafe_allow_html=True)
            for finding in report.get("findings", []):
                status_icon = "✅" if finding["status"] == "compliant" else "⚠️" if finding["status"] == "partial" else "❌"
                st.markdown(f"""
                <div class="card-container">
                    {status_icon} <strong>{finding['control']}</strong>
                    <br>Status: {finding['status'].upper()} | Risk: {finding['risk'].upper()}
                    <br><small>{finding['evidence']}</small>
                </div>
                """, unsafe_allow_html=True)

            # Recommendations
            st.markdown('<p class="section-header" style="font-size: 1.1rem;">Recommendations</p>', unsafe_allow_html=True)
            for rec in report.get("recommendations", []):
                priority_color = "red" if rec["priority"] == "high" else "orange" if rec["priority"] == "medium" else "green"
                st.markdown(f"""
                <div class="card-container">
                    <span style="color: {priority_color}; font-weight: bold;">{rec['priority'].upper()}</span>
                    — <strong>{rec['control']}</strong>
                    <br>{rec['recommendation']}
                </div>
                """, unsafe_allow_html=True)

            # Download report
            st.download_button(
                label="📥 Download Compliance Report",
                data=json.dumps(report, indent=2),
                file_name=f"compliance_{standard}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )
        else:
            st.info("Select a compliance standard and click 'Generate Report'")

# ============================================================
# AI ASSISTANT PAGE
# ============================================================
elif page == "🤖 AI Assistant":
    st.markdown('<p class="section-header">AI SOC Assistant Chat</p>', unsafe_allow_html=True)

    if "history" not in st.session_state:
        st.session_state.history = []

    # Chat container
    for role, msg in st.session_state.history:
        with st.chat_message(role, avatar="🤖" if role == "assistant" else "👤"):
            st.write(msg)

    if prompt := st.chat_input("Ask about alerts, techniques, remediation..."):
        st.session_state.history.append(("user", prompt))
        with st.chat_message("user", avatar="👤"):
            st.write(prompt)
        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("🤔 Analyzing..."):
                resp = post_json("/chat", {"message": prompt})
                st.write(resp["answer"])
                st.caption(f"Mode: {resp['mode']}")
        st.session_state.history.append(("assistant", resp["answer"]))

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🗑️ Clear chat", use_container_width=True):
        st.session_state.history = []
        st.rerun()

# ============================================================
# SEARCH PAGE
# ============================================================
elif page == "🔎 Search":
    st.markdown('<p class="section-header">Alert Search</p>', unsafe_allow_html=True)

    with st.form("search_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            q = st.text_input("🔍 Keyword / description")
            severity = st.selectbox("⚠️ Severity", ["All", "critical", "high", "medium", "low"])
        with col2:
            status = st.selectbox("📋 Status", ["All", "unacknowledged", "acknowledged", "escalated", "false_positive"])
            agent = st.text_input("🖥️ Agent name")
        with col3:
            mitre = st.text_input("🎯 MITRE TID (e.g. T1059.001)")
            limit = st.slider("📊 Max results", 10, 200, 50)

        submitted = st.form_submit_button("🔎 Search", use_container_width=True)

    if submitted:
        params = {
            "q": q or None, "severity": severity if severity != "All" else None,
            "status": status if status != "All" else None,
            "agent": agent or None, "mitre": mitre or None, "limit": limit,
        }
        df = fetch_alerts(params)
        st.markdown(f"**Found {len(df)} results**")

        if not df.empty:
            for _, row in df.iterrows():
                sev_class = row['severity']
                st.markdown(f"""
                <div class="alert-card {sev_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong>{row['alert_ref']}</strong>
                            <span style="margin-left: 10px;">{row['agent']}</span>
                        </div>
                        <span style="color: {SEVERITY_COLORS.get(row['severity'], '#666')}; font-weight: bold;">
                            {row['severity'].upper()}
                        </span>
                    </div>
                    <p style="margin: 0.5rem 0; color: #333;">{row['description']}</p>
                    <div style="font-size: 0.85rem; color: #666;">
                        🎯 {row['mitre']} | 📊 {row['confidence']:.0%} | 📋 {row['status'].replace('_', ' ').title()}
                    </div>
                </div>
                """, unsafe_allow_html=True)

# ============================================================
# SETTINGS PAGE
# ============================================================
elif page == "⚙️ Settings":
    st.markdown('<p class="section-header">System Settings & Status</p>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<p class="section-header" style="font-size: 1.1rem;">🏥 Health Status</p>', unsafe_allow_html=True)
        try:
            h = get_json("/health")
            st.json(h)
        except Exception as e:
            st.error(str(e))

        st.markdown('<p class="section-header" style="font-size: 1.1rem;">⚙️ Pipeline Mode</p>', unsafe_allow_html=True)
        try:
            st.json(get_json("/stats")["pipeline_mode"])
        except Exception:
            pass

    with col2:
        st.markdown('<p class="section-header" style="font-size: 1.1rem;">🤖 Trained Model</p>', unsafe_allow_html=True)
        try:
            info = get_json("/model-info")
            st.json(info)
        except Exception as e:
            st.warning(f"Model info unavailable: {e}")

        st.markdown('<p class="section-header" style="font-size: 1.1rem;">🔄 Retrain Model</p>', unsafe_allow_html=True)
        st.caption("Trains on synthetic dataset; in production, uses analyst feedback.")
        if st.button("🔄 Retrain now", use_container_width=True):
            import subprocess

            r = subprocess.run(
                [sys.executable, "-m", "scripts.train_model", "--samples", "2000"],
                cwd=str(Path(__file__).resolve().parent.parent),
                capture_output=True, text=True,
            )
            st.code(r.stdout[-2000:], language="text")
            if r.returncode != 0:
                st.error(r.stderr[-2000:])
            else:
                st.success("✅ Model retrained and saved.")
