"""
Suspicious Login Detection System (CyberShield)
==============================================
A modern, interactive Cybersecurity Dashboard built with Python, Streamlit, Pandas, and Plotly.
Analyzes authentication and login logs to detect abnormal login patterns, credential attacks,
and unauthorized access attempts, and generates actionable security alerts.

Author: Cybersecurity AI Assistant
Version: 1.0.0
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import io

# -----------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & CUSTOM CYBERSECURITY THEME CSS
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield | Suspicious Login Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark-themed SOC (Security Operations Center) dashboard
st.markdown("""
<style>
    /* Dark Navy & Slate Cyber Theme */
    .stApp {
        background-color: #0B1120;
        color: #E2E8F0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0F172A;
        border-right: 1px solid #1E293B;
    }
    
    /* Top Header Banner */
    .cyber-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #0F172A 100%);
        border: 1px solid #334155;
        border-left: 6px solid #38BDF8;
        padding: 20px 24px;
        border-radius: 10px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    
    .cyber-header h1 {
        margin: 0;
        font-size: 26px;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.5px;
    }
    
    .cyber-header p {
        margin: 6px 0 0 0;
        color: #94A3B8;
        font-size: 14px;
    }

    /* Metric Cards Grid */
    .metric-card {
        background: #131D31;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 16px 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #38BDF8;
    }
    .metric-title {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #94A3B8;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 28px;
        font-weight: 800;
        color: #F8FAFC;
        line-height: 1.1;
    }
    .metric-subtext {
        font-size: 12px;
        margin-top: 6px;
        color: #64748B;
    }

    /* Risk Badges */
    .badge-high {
        background-color: rgba(239, 68, 68, 0.2);
        color: #FCA5A5;
        border: 1px solid #EF4444;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        display: inline-block;
    }
    .badge-med {
        background-color: rgba(245, 158, 11, 0.2);
        color: #FCD34D;
        border: 1px solid #F59E0B;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        display: inline-block;
    }
    .badge-low {
        background-color: rgba(56, 189, 248, 0.2);
        color: #BAE6FD;
        border: 1px solid #38BDF8;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        display: inline-block;
    }

    /* Alert Detail Card */
    .alert-card {
        background: #111B2E;
        border: 1px solid #1E293B;
        border-left: 5px solid #38BDF8;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .alert-card.high {
        border-left-color: #EF4444;
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.08) 0%, #111B2E 35%);
    }
    .alert-card.medium {
        border-left-color: #F59E0B;
        background: linear-gradient(90deg, rgba(245, 158, 11, 0.08) 0%, #111B2E 35%);
    }
    .alert-card.low {
        border-left-color: #38BDF8;
        background: linear-gradient(90deg, rgba(56, 189, 248, 0.08) 0%, #111B2E 35%);
    }

    /* Disclaimer box */
    .soc-disclaimer {
        background-color: rgba(30, 41, 59, 0.7);
        border: 1px dashed #475569;
        border-radius: 8px;
        padding: 14px 18px;
        font-size: 13px;
        color: #94A3B8;
        margin-top: 20px;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 2. FICTIONAL SAMPLE DATA GENERATOR MODULE
# -----------------------------------------------------------------------------
@st.cache_data
def generate_sample_dataset(scenario="mixed"):
    """
    Generates realistic fictional authentication logs containing both normal traffic
    and targeted cybersecurity attack patterns.
    """
    base_time = datetime(2026, 10, 19, 8, 0, 0)
    records = []
    
    normal_users = ["alice.smith", "bob.jones", "carol.security", "david.miller", "emma.watson", "frank.castle"]
    trusted_ips = ["192.168.1.100", "192.168.1.101", "10.0.1.50", "10.0.1.51", "10.0.1.52"]
    
    # 1. Normal Corporate Traffic Baseline (Business hours, trusted IPs, successful logins)
    for i in range(40):
        t = base_time + timedelta(minutes=int(i * 12 + (i % 5) * 4))
        u = normal_users[i % len(normal_users)]
        ip = trusted_ips[i % len(trusted_ips)]
        records.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "username": u,
            "ip_address": ip,
            "status": "Success",
            "location": "New York, US",
            "device": "Windows 11 / Chrome"
        })
        
    # Occasional normal user password typo (1 failure followed immediately by success)
    records.append({
        "timestamp": (base_time + timedelta(hours=1, minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
        "username": "emma.watson",
        "ip_address": "10.0.1.52",
        "status": "Failure",
        "location": "New York, US",
        "device": "macOS / Safari"
    })
    records.append({
        "timestamp": (base_time + timedelta(hours=1, minutes=16)).strftime("%Y-%m-%d %H:%M:%S"),
        "username": "emma.watson",
        "ip_address": "10.0.1.52",
        "status": "Success",
        "location": "New York, US",
        "device": "macOS / Safari"
    })

    if scenario in ["mixed", "brute_force"]:
        # Attack Pattern 1: High-frequency Brute Force on alice.smith (7 failed attempts in 4 mins)
        bf_time = base_time + timedelta(hours=1, minutes=10)
        for i in range(7):
            records.append({
                "timestamp": (bf_time + timedelta(seconds=i * 35)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": "alice.smith",
                "ip_address": "198.51.100.42",
                "status": "Failure",
                "location": "Frankfurt, DE",
                "device": "Python-requests / 2.31"
            })

    if scenario in ["mixed", "compromise"]:
        # Attack Pattern 2: Successful Login After Repeated Failures (dev_admin compromise)
        # 5 failures in 3 mins followed by a SUCCESS!
        comp_time = base_time + timedelta(hours=6, minutes=2)
        for i in range(5):
            records.append({
                "timestamp": (comp_time + timedelta(seconds=i * 45)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": "dev_admin",
                "ip_address": "203.0.113.19",
                "status": "Failure",
                "location": "Bucharest, RO",
                "device": "Hydra / v9.5"
            })
        records.append({
            "timestamp": (comp_time + timedelta(minutes=4, seconds=30)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "dev_admin",
            "ip_address": "203.0.113.19",
            "status": "Success",
            "location": "Bucharest, RO",
            "device": "Hydra / v9.5"
        })

    if scenario in ["mixed", "password_spray"]:
        # Attack Pattern 3: Multiple-User Targeting (Password Spraying)
        # Attacker 185.220.101.5 tests 1 password across 5 distinct usernames within 7 minutes
        spray_time = base_time + timedelta(hours=3, minutes=20)
        spray_targets = ["admin", "root", "john.doe", "sarah.connor", "finance_lead"]
        for i, target in enumerate(spray_targets):
            records.append({
                "timestamp": (spray_time + timedelta(minutes=i * 1.3)).strftime("%Y-%m-%d %H:%M:%S"),
                "username": target,
                "ip_address": "185.220.101.5",
                "status": "Failure",
                "location": "Amsterdam, NL",
                "device": "Go-http-client / 1.1"
            })

    if scenario in ["mixed"]:
        # Attack Pattern 4: Unusual Login Times (Off-Hours: 02:35 AM & 03:40 AM)
        records.append({
            "timestamp": "2026-10-19 02:35:12",
            "username": "bob.jones",
            "ip_address": "203.0.113.88",
            "status": "Success",
            "location": "New York, US",
            "device": "Windows 11 / Chrome"
        })
        records.append({
            "timestamp": "2026-10-19 03:40:05",
            "username": "david.miller",
            "ip_address": "192.168.1.105",
            "status": "Failure",
            "location": "New York, US",
            "device": "iOS / Mobile Safari"
        })

        # Attack Pattern 5: Unfamiliar / Untrusted IP
        records.append({
            "timestamp": (base_time + timedelta(hours=4, minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "carol.security",
            "ip_address": "194.26.29.112",
            "status": "Success",
            "location": "Reykjavik, IS",
            "device": "Ubuntu / Firefox"
        })

        # Attack Pattern 6: Velocity Anomaly / Impossible Travel (New York to Tokyo in 14 mins)
        records.append({
            "timestamp": "2026-10-19 10:00:00",
            "username": "john.doe",
            "ip_address": "198.51.100.20",
            "status": "Success",
            "location": "New York, US",
            "device": "macOS / Chrome"
        })
        records.append({
            "timestamp": "2026-10-19 10:14:00",
            "username": "john.doe",
            "ip_address": "103.245.12.55",
            "status": "Success",
            "location": "Tokyo, JP",
            "device": "Windows 10 / Edge"
        })

        # Rapid IP Switching within 35 seconds
        records.append({
            "timestamp": "2026-10-19 11:05:00",
            "username": "sarah.connor",
            "ip_address": "10.0.2.14",
            "status": "Success",
            "location": "London, UK",
            "device": "Ubuntu / Firefox"
        })
        records.append({
            "timestamp": "2026-10-19 11:05:35",
            "username": "sarah.connor",
            "ip_address": "198.51.100.99",
            "status": "Failure",
            "location": "London, UK",
            "device": "Android / Mobile App"
        })

    df = pd.DataFrame(records)
    df['dt_temp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('dt_temp').drop(columns=['dt_temp']).reset_index(drop=True)
    return df


# -----------------------------------------------------------------------------
# 3. DETECTION ENGINE & HEURISTIC RULES
# -----------------------------------------------------------------------------
def run_suspicious_activity_detection(df, config):
    """
    Applies configurable heuristic cybersecurity detection rules to authentication logs.
    Returns:
        alerts_df: DataFrame with detected security alerts.
        work_df: Cleaned and normalized login logs.
    """
    work_df = df.copy()
    work_df['dt'] = pd.to_datetime(work_df['timestamp'])
    work_df['username'] = work_df['username'].astype(str).str.strip()
    work_df['ip_address'] = work_df['ip_address'].astype(str).str.strip()
    
    # Normalize status
    status_str = work_df['status'].astype(str).str.strip().str.capitalize()
    work_df['is_success'] = status_str.str.startswith('Succ') | status_str.isin(['Pass', 'Succeeded', 'True', '1'])
    work_df['is_failure'] = ~work_df['is_success']
    work_df['status_display'] = np.where(work_df['is_success'], 'Success', 'Failure')

    if 'location' not in work_df.columns:
        work_df['location'] = 'Unknown'
    else:
        work_df['location'] = work_df['location'].fillna('Unknown').astype(str)

    if 'device' not in work_df.columns:
        work_df['device'] = 'Unknown'
    else:
        work_df['device'] = work_df['device'].fillna('Unknown').astype(str)

    work_df = work_df.sort_values('dt').reset_index(drop=True)
    alerts = []

    # -------------------------------------------------------------------------
    # RULE 1: Repeated Failed Logins (Brute Force on Account & Source IP)
    # -------------------------------------------------------------------------
    failed_win = timedelta(minutes=config["failed_window_minutes"])
    n_fail = config["failed_attempts_threshold"]

    # Rule 1A: Target Account Brute Force
    for user, u_df in work_df[work_df['is_failure']].groupby('username'):
        times = u_df['dt'].tolist()
        ips = u_df['ip_address'].tolist()
        i = 0
        while i < len(times):
            window_start = times[i]
            j = i
            while j < len(times) and (times[j] - window_start) <= failed_win:
                j += 1
            count = j - i
            if count >= n_fail:
                window_ips = list(set(ips[i:j]))
                risk = "High" if count >= (n_fail * 2) else "Medium"
                alerts.append({
                    "timestamp": times[j-1].strftime("%Y-%m-%d %H:%M:%S"),
                    "dt": times[j-1],
                    "username": user,
                    "ip_address": ", ".join(window_ips),
                    "rule_id": "RULE-01A",
                    "rule_name": "Repeated Failed Logins (Account Target)",
                    "risk_level": risk,
                    "explanation": f"{count} failed logins targeted account '{user}' within {config['failed_window_minutes']} minutes (Source IP: {', '.join(window_ips)}).",
                    "action": f"Temporarily lock account '{user}', enforce re-authentication challenge, verify employee status out-of-band.",
                    "evidence_count": count
                })
                i = j
            else:
                i += 1

    # Rule 1B: Source IP Brute Force Attack
    for ip, ip_df in work_df[work_df['is_failure']].groupby('ip_address'):
        times = ip_df['dt'].tolist()
        users = ip_df['username'].tolist()
        i = 0
        while i < len(times):
            window_start = times[i]
            j = i
            while j < len(times) and (times[j] - window_start) <= failed_win:
                j += 1
            count = j - i
            if count >= n_fail:
                window_users = list(set(users[i:j]))
                risk = "High" if count >= (n_fail * 2) else "Medium"
                alerts.append({
                    "timestamp": times[j-1].strftime("%Y-%m-%d %H:%M:%S"),
                    "dt": times[j-1],
                    "username": ", ".join(window_users[:4]),
                    "ip_address": ip,
                    "rule_id": "RULE-01B",
                    "rule_name": "Repeated Failed Logins (Source IP)",
                    "risk_level": risk,
                    "explanation": f"Source IP {ip} initiated {count} failed attempts within {config['failed_window_minutes']} minutes across accounts ({', '.join(window_users[:4])}).",
                    "action": f"Add IP {ip} to perimeter firewall blocklist, enable rate limiting, and review auth gateway logs.",
                    "evidence_count": count
                })
                i = j
            else:
                i += 1

    # -------------------------------------------------------------------------
    # RULE 2: Unusual Login Times (Off-Hours & Weekend Logins)
    # -------------------------------------------------------------------------
    start_h = config["work_hours_start"]
    end_h = config["work_hours_end"]
    trusted_set = set(config.get("trusted_ips", []))

    for idx, row in work_df.iterrows():
        event_dt = row['dt']
        h = event_dt.hour
        is_weekend = (event_dt.weekday() >= 5) and config.get("check_weekends", True)
        is_off_hour = (h < start_h or h >= end_h)

        if is_off_hour or is_weekend:
            reasons = []
            if is_off_hour:
                reasons.append(f"outside normal working hours ({start_h:02d}:00 - {end_h:02d}:00)")
            if is_weekend:
                reasons.append(f"occurred on weekend ({event_dt.strftime('%A')})")
            
            is_trusted = row['ip_address'] in trusted_set
            risk = "Medium" if not is_trusted else "Low"

            alerts.append({
                "timestamp": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "dt": event_dt,
                "username": row['username'],
                "ip_address": row['ip_address'],
                "rule_id": "RULE-02",
                "rule_name": "Unusual Login Time",
                "risk_level": risk,
                "explanation": f"Login event ({row['status_display']}) for '{row['username']}' detected {' and '.join(reasons)} from IP {row['ip_address']} ({'Untrusted IP' if not is_trusted else 'Trusted IP'}).",
                "action": "Verify user work schedule and dispatch out-of-band push confirmation to validate authorization.",
                "evidence_count": 1
            })

    # -------------------------------------------------------------------------
    # RULE 3: Successful Login After Repeated Failures (Credential Compromise)
    # -------------------------------------------------------------------------
    succ_win = timedelta(minutes=config["succ_after_fail_window_minutes"])
    succ_thresh = config["succ_after_fail_threshold"]

    for idx, row in work_df[work_df['is_success']].iterrows():
        succ_time = row['dt']
        succ_user = row['username']
        succ_ip = row['ip_address']

        prior_fails = work_df[
            (work_df['is_failure']) &
            (work_df['dt'] >= succ_time - succ_win) &
            (work_df['dt'] < succ_time) &
            ((work_df['username'] == succ_user) | (work_df['ip_address'] == succ_ip))
        ]

        if len(prior_fails) >= succ_thresh:
            alerts.append({
                "timestamp": succ_time.strftime("%Y-%m-%d %H:%M:%S"),
                "dt": succ_time,
                "username": succ_user,
                "ip_address": succ_ip,
                "rule_id": "RULE-03",
                "rule_name": "Successful Login After Repeated Failures",
                "risk_level": "High",
                "explanation": f"CRITICAL: Successful login for '{succ_user}' immediately preceded by {len(prior_fails)} failed attempts within {config['succ_after_fail_window_minutes']} minutes. Strong indicator of brute-force breach or credential guessing.",
                "action": "Immediate containment: terminate active user sessions, invalidate API/OAuth tokens, reset password, inspect post-login API/database activity.",
                "evidence_count": len(prior_fails)
            })

    # -------------------------------------------------------------------------
    # RULE 4: Unfamiliar / Untrusted IP Addresses
    # -------------------------------------------------------------------------
    untrusted_mode = config.get("untrusted_ip_mode", "success_only")
    for idx, row in work_df.iterrows():
        ip = row['ip_address']
        if ip not in trusted_set:
            if untrusted_mode == "success_only" and not row['is_success']:
                continue  # Skip failed logins if configured to reduce noise
            
            risk = "Medium" if row['is_success'] else "Low"
            alerts.append({
                "timestamp": row['dt'].strftime("%Y-%m-%d %H:%M:%S"),
                "dt": row['dt'],
                "username": row['username'],
                "ip_address": ip,
                "rule_id": "RULE-04",
                "rule_name": "Unfamiliar / Untrusted IP Address",
                "risk_level": risk,
                "explanation": f"Authentication attempt ({row['status_display']}) from IP {ip} ({row['location']}), which is not on the trusted IP whitelist.",
                "action": "Check IP reputation on threat intelligence feeds (AbuseIPDB/VirusTotal). If authorized remote worker, add to trusted baseline or enforce conditional access.",
                "evidence_count": 1
            })

    # -------------------------------------------------------------------------
    # RULE 5: Multiple-User Targeting (Password Spraying)
    # -------------------------------------------------------------------------
    spray_win = timedelta(minutes=config["spray_window_minutes"])
    spray_thresh = config["spray_users_threshold"]

    for ip, ip_df in work_df.groupby('ip_address'):
        ip_df = ip_df.sort_values('dt')
        times = ip_df['dt'].tolist()
        users = ip_df['username'].tolist()

        i = 0
        while i < len(times):
            window_start = times[i]
            j = i
            while j < len(times) and (times[j] - window_start) <= spray_win:
                j += 1
            unique_targets = list(set(users[i:j]))
            if len(unique_targets) >= spray_thresh:
                alerts.append({
                    "timestamp": times[j-1].strftime("%Y-%m-%d %H:%M:%S"),
                    "dt": times[j-1],
                    "username": ", ".join(unique_targets[:4]) + (f" (+{len(unique_targets)-4} more)" if len(unique_targets) > 4 else ""),
                    "ip_address": ip,
                    "rule_id": "RULE-05",
                    "rule_name": "Multiple-User Targeting (Password Spraying)",
                    "risk_level": "High",
                    "explanation": f"Source IP {ip} targeted {len(unique_targets)} unique user accounts ({', '.join(unique_targets)}) within {config['spray_window_minutes']} minutes. Matches automated password spraying.",
                    "action": "Drop traffic from IP {ip} at WAF/perimeter edge, notify targeted account holders, enforce CAPTCHA or proof-of-work on login endpoints.",
                    "evidence_count": len(unique_targets)
                })
                i = j
            else:
                i += 1

    # -------------------------------------------------------------------------
    # RULE 6: Unusual Access Patterns (Velocity / Impossible Travel)
    # -------------------------------------------------------------------------
    vel_win = timedelta(minutes=config["velocity_window_minutes"])
    for user, u_df in work_df.groupby('username'):
        u_df = u_df.sort_values('dt').reset_index(drop=True)
        for i in range(len(u_df) - 1):
            e1 = u_df.iloc[i]
            e2 = u_df.iloc[i+1]
            delta = e2['dt'] - e1['dt']

            loc1, loc2 = e1['location'], e2['location']
            ip1, ip2 = e1['ip_address'], e2['ip_address']

            if delta <= vel_win and delta > timedelta(seconds=0):
                # Anomaly A: Impossible geographic travel
                if loc1 != 'Unknown' and loc2 != 'Unknown' and loc1 != loc2:
                    delta_mins = max(1, int(delta.total_seconds() / 60))
                    alerts.append({
                        "timestamp": e2['dt'].strftime("%Y-%m-%d %H:%M:%S"),
                        "dt": e2['dt'],
                        "username": user,
                        "ip_address": f"{ip1} -> {ip2}",
                        "rule_id": "RULE-06A",
                        "rule_name": "Impossible Travel / Velocity Anomaly",
                        "risk_level": "High",
                        "explanation": f"Impossible physical travel detected for user '{user}': logged in from {loc1} ({ip1}) and then from {loc2} ({ip2}) within {delta_mins} minutes.",
                        "action": "Revoke active sessions, prompt hardware security key (FIDO2) or biometric challenge, isolate user machine pending forensic validation.",
                        "evidence_count": delta_mins
                    })
                # Anomaly B: Rapid IP change (under 2 minutes)
                elif ip1 != ip2 and delta <= timedelta(minutes=2):
                    sec_delta = int(delta.total_seconds())
                    alerts.append({
                        "timestamp": e2['dt'].strftime("%Y-%m-%d %H:%M:%S"),
                        "dt": e2['dt'],
                        "username": user,
                        "ip_address": f"{ip1} -> {ip2}",
                        "rule_id": "RULE-06B",
                        "rule_name": "Rapid Infrastructure Hopping",
                        "risk_level": "Medium",
                        "explanation": f"User '{user}' switched network endpoints in {sec_delta}s ({ip1} -> {ip2}). Possible proxy/TOR rotation or session hijacking.",
                        "action": "Review session cookies and IP subnets. Require step-up MFA if risk score remains elevated.",
                        "evidence_count": sec_delta
                    })

    alerts_df = pd.DataFrame(alerts)
    if not alerts_df.empty:
        alerts_df = alerts_df.sort_values('dt', ascending=False).reset_index(drop=True)
    else:
        alerts_df = pd.DataFrame(columns=[
            "timestamp", "dt", "username", "ip_address", "rule_id",
            "rule_name", "risk_level", "explanation", "action", "evidence_count"
        ])

    return alerts_df, work_df


# -----------------------------------------------------------------------------
# 4. SIDEBAR CONTROLS & CONFIGURATION
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ CyberShield Control")
    st.markdown("*Intrusion & Anomaly Detection Engine*")
    st.markdown("---")

    # Data Source Selection
    st.markdown("### 📂 Data Source")
    data_source_mode = st.radio(
        "Select Log Feed:",
        ["🎯 Realistic Attack Simulation", "📁 Upload Custom CSV File"],
        index=0
    )

    uploaded_file = None
    sample_scenario = "mixed"

    if data_source_mode == "🎯 Realistic Attack Simulation":
        sample_scenario = st.selectbox(
            "Select Attack Scenario:",
            [
                ("mixed", "All Rules Simulation (Brute Force + Spray + Anomaly)"),
                ("brute_force", "Targeted Brute-Force Wave"),
                ("compromise", "Credential Guessing with Successful Breach"),
                ("password_spray", "Stealth Password Spraying Campaign"),
            ],
            format_func=lambda x: x[1]
        )[0]
    else:
        uploaded_file = st.file_uploader("Upload Login Logs (CSV)", type=["csv"])
        st.markdown("""
        **Required Columns:**  
        `timestamp`, `username`, `ip_address`, `status`  
        *(Optional: `location`, `device`)*
        """)

    st.markdown("---")
    st.markdown("### ⚙️ Detection Thresholds")

    with st.expander("🔨 Rule 1: Repeated Failures", expanded=False):
        failed_attempts_threshold = st.slider("Failed Attempts Threshold", 2, 15, 5, help="Number of failed logins to trigger an alert.")
        failed_window_minutes = st.slider("Time Window (Minutes)", 1, 60, 10, help="Window duration for failed login counting.")

    with st.expander("⏰ Rule 2: Working Hours", expanded=False):
        work_hours_start = st.slider("Business Hours Start (Hour 0-23)", 0, 23, 8)
        work_hours_end = st.slider("Business Hours End (Hour 0-23)", 0, 23, 19)
        check_weekends = st.checkbox("Flag Weekend Logins", value=True)

    with st.expander("💥 Rule 3: Success After Failures", expanded=False):
        succ_after_fail_threshold = st.slider("Prior Failures Count", 1, 10, 3, help="Failures immediately before a successful login.")
        succ_after_fail_window_minutes = st.slider("Lookback Window (Minutes)", 2, 60, 15)

    with st.expander("🌐 Rule 4: Trusted IP Whitelist", expanded=False):
        trusted_ips_input = st.text_area(
            "Trusted Corporate IPs (comma or newline separated):",
            "192.168.1.100\n192.168.1.101\n10.0.1.50\n10.0.1.51\n10.0.1.52",
            height=100
        )
        untrusted_ip_mode = st.selectbox(
            "Untrusted IP Alert Mode:",
            [("success_only", "Flag only SUCCESSFUL logins (Low Noise)"), ("all", "Flag ALL attempts (Verbose)")],
            format_func=lambda x: x[1]
        )

    with st.expander("🎯 Rule 5: Password Spraying", expanded=False):
        spray_users_threshold = st.slider("Unique Accounts Targeted", 2, 10, 3, help="Minimum unique accounts targeted by one IP.")
        spray_window_minutes = st.slider("Spray Window (Minutes)", 2, 60, 15)

    with st.expander("🚀 Rule 6: Velocity & Travel", expanded=False):
        velocity_window_minutes = st.slider("Impossible Travel Threshold (Mins)", 5, 120, 30)

    # Parse trusted IPs
    trusted_ips_list = [ip.strip() for ip in trusted_ips_input.replace(',', '\n').split('\n') if ip.strip()]

    config = {
        "failed_attempts_threshold": failed_attempts_threshold,
        "failed_window_minutes": failed_window_minutes,
        "work_hours_start": work_hours_start,
        "work_hours_end": work_hours_end,
        "check_weekends": check_weekends,
        "succ_after_fail_threshold": succ_after_fail_threshold,
        "succ_after_fail_window_minutes": succ_after_fail_window_minutes,
        "trusted_ips": trusted_ips_list,
        "untrusted_ip_mode": untrusted_ip_mode,
        "spray_users_threshold": spray_users_threshold,
        "spray_window_minutes": spray_window_minutes,
        "velocity_window_minutes": velocity_window_minutes
    }

    st.markdown("---")
    # Download sample template
    sample_csv_data = generate_sample_dataset("mixed").to_csv(index=False)
    st.download_button(
        label="📥 Download Sample CSV Template",
        data=sample_csv_data,
        file_name="sample_login_logs.csv",
        mime="text/csv",
        use_container_width=True
    )


# -----------------------------------------------------------------------------
# 5. DATA INGESTION & VALIDATION
# -----------------------------------------------------------------------------
raw_df = None

if data_source_mode == "🎯 Realistic Attack Simulation":
    raw_df = generate_sample_dataset(sample_scenario)
    st.sidebar.success(f"Loaded simulation scenario: **{sample_scenario.upper()}** ({len(raw_df)} logs).")
else:
    if uploaded_file is not None:
        try:
            user_df = pd.read_csv(uploaded_file)
            required_cols = {"timestamp", "username", "ip_address", "status"}
            missing = required_cols - set(user_df.columns)
            if missing:
                st.error(f"❌ Upload Error: Missing required columns: `{', '.join(missing)}`. Please verify your CSV header.")
                st.stop()
            else:
                # Validate timestamp parsing
                try:
                    pd.to_datetime(user_df['timestamp'])
                except Exception as parse_err:
                    st.error(f"❌ Timestamp Error: Could not parse timestamps in CSV: {parse_err}")
                    st.stop()
                raw_df = user_df
                st.sidebar.success(f"Successfully loaded `{uploaded_file.name}` ({len(raw_df)} records).")
        except Exception as e:
            st.error(f"❌ Failed to parse uploaded file: {e}")
            st.stop()
    else:
        st.info("👆 Please upload a login log CSV file from the sidebar, or switch to the **Realistic Attack Simulation**.")
        # Fallback to sample data for preview
        raw_df = generate_sample_dataset("mixed")

# Execute detection engine
alerts_df, logs_df = run_suspicious_activity_detection(raw_df, config)


# -----------------------------------------------------------------------------
# 6. HEADER & EXECUTIVE METRICS
# -----------------------------------------------------------------------------
st.markdown("""
<div class="cyber-header">
    <h1>🛡️ CyberShield | Suspicious Login Detection System</h1>
    <p>Autonomous Identity Threat Detection, Credential Abuse Defense, and Abnormal Access Analytics</p>
</div>
""", unsafe_allow_html=True)

# Calculate Core Metrics
total_attempts = len(logs_df)
successful_logins = int(logs_df['is_success'].sum())
failed_logins = int(logs_df['is_failure'].sum())
failure_rate = (failed_logins / total_attempts * 100) if total_attempts > 0 else 0

total_alerts = len(alerts_df)
high_risk_count = int((alerts_df['risk_level'] == 'High').sum()) if total_alerts > 0 else 0
med_risk_count = int((alerts_df['risk_level'] == 'Medium').sum()) if total_alerts > 0 else 0
low_risk_count = int((alerts_df['risk_level'] == 'Low').sum()) if total_alerts > 0 else 0

# Metric Cards Layout
c1, c2, c3, c4, c5, c6 = st.columns(6)

with c1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Total Logins</div>
        <div class="metric-value">{total_attempts:,}</div>
        <div class="metric-subtext">Auth requests scanned</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Successful Logins</div>
        <div class="metric-value" style="color: #34D399;">{successful_logins:,}</div>
        <div class="metric-subtext">{(successful_logins/total_attempts*100):.1f}% success rate</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Failed Logins</div>
        <div class="metric-value" style="color: #F87171;">{failed_logins:,}</div>
        <div class="metric-subtext">{failure_rate:.1f}% failure rate</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="metric-card" style="border-left: 4px solid #EF4444;">
        <div class="metric-title">High Risk Alerts</div>
        <div class="metric-value" style="color: #EF4444;">{high_risk_count}</div>
        <div class="metric-subtext">Immediate triage required</div>
    </div>
    """, unsafe_allow_html=True)

with c5:
    st.markdown(f"""
    <div class="metric-card" style="border-left: 4px solid #F59E0B;">
        <div class="metric-title">Medium Risk Alerts</div>
        <div class="metric-value" style="color: #F59E0B;">{med_risk_count}</div>
        <div class="metric-subtext">Suspicious anomalies</div>
    </div>
    """, unsafe_allow_html=True)

with c6:
    st.markdown(f"""
    <div class="metric-card" style="border-left: 4px solid #38BDF8;">
        <div class="metric-title">Low Risk / Policy</div>
        <div class="metric-value" style="color: #38BDF8;">{low_risk_count}</div>
        <div class="metric-subtext">Policy deviations</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# 7. MAIN INTERFACE TABS
# -----------------------------------------------------------------------------
tab_exec, tab_alerts, tab_analytics, tab_logs, tab_playbook = st.tabs([
    "📊 Executive Dashboard",
    "🚨 Alert Investigation & Triage",
    "📈 Deep-Dive Threat Analytics",
    "📜 Raw Log Explorer",
    "🛡️ Incident Playbook & Architecture"
])

# -----------------------------------------------------------------------------
# TAB 1: EXECUTIVE DASHBOARD
# -----------------------------------------------------------------------------
with tab_exec:
    col_chart_left, col_chart_right = st.columns([1.6, 1.0])

    with col_chart_left:
        st.markdown("#### ⏱️ Authentication Activity Timeline")
        timeline_df = logs_df.copy()
        timeline_df['time_interval'] = timeline_df['dt'].dt.floor('15min')
        agg_timeline = timeline_df.groupby(['time_interval', 'status_display']).size().reset_index(name='count')
        
        fig_time = px.bar(
            agg_timeline,
            x='time_interval',
            y='count',
            color='status_display',
            color_discrete_map={'Success': '#10B981', 'Failure': '#EF4444'},
            barmode='stack',
            labels={'time_interval': 'Time (15-min Intervals)', 'count': 'Login Attempts', 'status_display': 'Status'},
            template='plotly_dark'
        )
        fig_time.update_layout(
            paper_bgcolor='rgba(15, 23, 42, 0.6)',
            plot_bgcolor='rgba(15, 23, 42, 0.4)',
            margin=dict(l=20, r=20, t=25, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            height=320
        )
        st.plotly_chart(fig_time, use_container_width=True)

    with col_chart_right:
        st.markdown("#### 🎯 Alert Severity Distribution")
        if total_alerts > 0:
            severity_counts = alerts_df['risk_level'].value_counts().reset_index()
            severity_counts.columns = ['Risk Level', 'Alert Count']
            
            fig_pie = px.pie(
                severity_counts,
                names='Risk Level',
                values='Alert Count',
                color='Risk Level',
                color_discrete_map={'High': '#EF4444', 'Medium': '#F59E0B', 'Low': '#38BDF8'},
                hole=0.55,
                template='plotly_dark'
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(15, 23, 42, 0.6)',
                plot_bgcolor='rgba(15, 23, 42, 0.4)',
                margin=dict(l=20, r=20, t=25, b=20),
                height=320,
                legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.success("✅ No security alerts detected! All logs conform to baseline security policies.")

    # Second row of overview charts
    col_threats, col_top_users, col_top_ips = st.columns([1.2, 0.9, 0.9])

    with col_threats:
        st.markdown("#### 📋 Detected Threat Categories")
        if total_alerts > 0:
            rule_counts = alerts_df['rule_name'].value_counts().reset_index()
            rule_counts.columns = ['Detection Rule', 'Events Flagged']
            fig_rules = px.bar(
                rule_counts.sort_values('Events Flagged', ascending=True),
                x='Events Flagged',
                y='Detection Rule',
                orientation='h',
                color='Events Flagged',
                color_continuous_scale='Blues',
                template='plotly_dark'
            )
            fig_rules.update_layout(
                paper_bgcolor='rgba(15, 23, 42, 0.6)',
                plot_bgcolor='rgba(15, 23, 42, 0.4)',
                margin=dict(l=20, r=20, t=10, b=20),
                height=260,
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_rules, use_container_width=True)
        else:
            st.info("No threat categories triggered.")

    with col_top_users:
        st.markdown("#### 👤 Top Targeted Accounts")
        fails_per_user = logs_df[logs_df['is_failure']]['username'].value_counts().head(5).reset_index()
        fails_per_user.columns = ['Username', 'Failed Attempts']
        if not fails_per_user.empty:
            fig_users = px.bar(
                fails_per_user,
                x='Username',
                y='Failed Attempts',
                color_discrete_sequence=['#F43F5E'],
                template='plotly_dark'
            )
            fig_users.update_layout(
                paper_bgcolor='rgba(15, 23, 42, 0.6)',
                plot_bgcolor='rgba(15, 23, 42, 0.4)',
                margin=dict(l=20, r=20, t=10, b=20),
                height=260
            )
            st.plotly_chart(fig_users, use_container_width=True)
        else:
            st.write("No failed login attempts recorded.")

    with col_top_ips:
        st.markdown("#### 🌐 Top Offending IPs")
        fails_per_ip = logs_df[logs_df['is_failure']]['ip_address'].value_counts().head(5).reset_index()
        fails_per_ip.columns = ['IP Address', 'Failed Attempts']
        if not fails_per_ip.empty:
            fig_ips = px.bar(
                fails_per_ip,
                x='IP Address',
                y='Failed Attempts',
                color_discrete_sequence=['#F59E0B'],
                template='plotly_dark'
            )
            fig_ips.update_layout(
                paper_bgcolor='rgba(15, 23, 42, 0.6)',
                plot_bgcolor='rgba(15, 23, 42, 0.4)',
                margin=dict(l=20, r=20, t=10, b=20),
                height=260
            )
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.write("No IP failure activity recorded.")


# -----------------------------------------------------------------------------
# TAB 2: ALERT INVESTIGATION & TRIAGE
# -----------------------------------------------------------------------------
with tab_alerts:
    st.markdown("### 🚨 Security Incident Triage Queue")
    st.markdown("Filter, inspect, and analyze detected security events to determine appropriate containment and remediation actions.")

    # Filter Controls
    f_c1, f_c2, f_c3, f_c4 = st.columns([1, 1.2, 1.2, 1.2])

    with f_c1:
        risk_filter = st.multiselect("Filter Severity:", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
    with f_c2:
        rule_options = sorted(alerts_df['rule_name'].unique().tolist()) if not alerts_df.empty else []
        rule_filter = st.multiselect("Filter Threat Rule:", rule_options, default=rule_options)
    with f_c3:
        user_search = st.text_input("Search Username:", placeholder="e.g. dev_admin, alice")
    with f_c4:
        ip_search = st.text_input("Search IP Address:", placeholder="e.g. 198.51, 203.0")

    # Apply Filters
    filtered_alerts = alerts_df.copy()
    if not filtered_alerts.empty:
        if risk_filter:
            filtered_alerts = filtered_alerts[filtered_alerts['risk_level'].isin(risk_filter)]
        if rule_filter:
            filtered_alerts = filtered_alerts[filtered_alerts['rule_name'].isin(rule_filter)]
        if user_search.strip():
            filtered_alerts = filtered_alerts[filtered_alerts['username'].str.contains(user_search.strip(), case=False, na=False)]
        if ip_search.strip():
            filtered_alerts = filtered_alerts[filtered_alerts['ip_address'].str.contains(ip_search.strip(), case=False, na=False)]

    st.markdown(f"**Showing {len(filtered_alerts)} of {total_alerts} security alerts**")

    # Alerts List with Rich Details
    if not filtered_alerts.empty:
        # Export Alerts Button
        csv_alerts = filtered_alerts.drop(columns=['dt'], errors='ignore').to_csv(index=False)
        st.download_button(
            label="📥 Export Filtered Alerts (CSV)",
            data=csv_alerts,
            file_name=f"cyber_security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        for idx, alert in filtered_alerts.iterrows():
            severity = alert['risk_level'].lower()
            badge_class = f"badge-{severity}"
            badge_icon = "🔴" if severity == "high" else ("🟠" if severity == "medium" else "🔵")

            with st.expander(f"{badge_icon} [{alert['risk_level'].upper()}] {alert['rule_name']} — Target: {alert['username']} | IP: {alert['ip_address']} @ {alert['timestamp']}", expanded=(severity == "high")):
                ac1, ac2 = st.columns([1.8, 1.2])
                with ac1:
                    st.markdown(f"**🔍 Event Explanation & Threat Context:**")
                    st.write(alert['explanation'])
                    
                    st.markdown(f"**🛡️ Recommended Security Action:**")
                    st.info(f"**Action Plan:** {alert['action']}")

                with ac2:
                    st.markdown(f"**📑 Incident Details:**")
                    st.markdown(f"- **Rule ID:** `{alert['rule_id']}`")
                    st.markdown(f"- **Severity:** <span class='{badge_class}'>{alert['risk_level'].upper()}</span>", unsafe_allow_html=True)
                    st.markdown(f"- **Detection Timestamp:** `{alert['timestamp']}`")
                    st.markdown(f"- **Impacted User(s):** `{alert['username']}`")
                    st.markdown(f"- **Source IP(s):** `{alert['ip_address']}`")
                    st.markdown(f"- **Evidence Weight:** `{alert['evidence_count']}` correlated events")

                # Correlated log entries from raw logs
                target_user = alert['username'].split(',')[0].strip()
                target_ip = alert['ip_address'].split(',')[0].split('->')[0].strip()
                correlated_logs = logs_df[
                    (logs_df['username'] == target_user) | 
                    (logs_df['ip_address'] == target_ip)
                ].sort_values('dt', ascending=False).head(5)

                if not correlated_logs.empty:
                    st.markdown("**🔬 Correlated Authentication Logs:**")
                    display_cols = ['timestamp', 'username', 'ip_address', 'status_display', 'location', 'device']
                    st.dataframe(correlated_logs[display_cols].rename(columns={'status_display': 'status'}), use_container_width=True)
    else:
        st.success("No alerts match the selected criteria.")


# -----------------------------------------------------------------------------
# TAB 3: DEEP-DIVE THREAT ANALYTICS
# -----------------------------------------------------------------------------
with tab_analytics:
    st.markdown("### 📈 Deep-Dive Behavioral & Access Pattern Analytics")

    an_c1, an_c2 = st.columns(2)

    with an_c1:
        st.markdown("#### 🕒 Hourly Authentication Distribution vs. Business Hours")
        logs_df_h = logs_df.copy()
        logs_df_h['hour'] = logs_df_h['dt'].dt.hour
        hourly_counts = logs_df_h.groupby(['hour', 'status_display']).size().reset_index(name='count')

        fig_hour = px.bar(
            hourly_counts,
            x='hour',
            y='count',
            color='status_display',
            color_discrete_map={'Success': '#10B981', 'Failure': '#EF4444'},
            labels={'hour': 'Hour of Day (0-23)', 'count': 'Attempts', 'status_display': 'Status'},
            template='plotly_dark'
        )
        # Add normal working hours shaded region
        fig_hour.add_vrect(
            x0=config['work_hours_start'],
            x1=config['work_hours_end'],
            fillcolor="#38BDF8",
            opacity=0.12,
            layer="below",
            line_width=1,
            annotation_text="Configured Working Hours",
            annotation_position="top left"
        )
        fig_hour.update_layout(
            paper_bgcolor='rgba(15, 23, 42, 0.6)',
            plot_bgcolor='rgba(15, 23, 42, 0.4)',
            height=340,
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig_hour, use_container_width=True)

    with an_c2:
        st.markdown("#### 🌍 Geographic Origins of Login Attempts")
        loc_df = logs_df.groupby(['location', 'status_display']).size().reset_index(name='count')
        fig_loc = px.bar(
            loc_df,
            x='location',
            y='count',
            color='status_display',
            color_discrete_map={'Success': '#10B981', 'Failure': '#EF4444'},
            labels={'location': 'Reported Location', 'count': 'Attempts'},
            template='plotly_dark'
        )
        fig_loc.update_layout(
            paper_bgcolor='rgba(15, 23, 42, 0.6)',
            plot_bgcolor='rgba(15, 23, 42, 0.4)',
            height=340,
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig_loc, use_container_width=True)

    st.markdown("---")
    an_c3, an_c4 = st.columns(2)

    with an_c3:
        st.markdown("#### 💻 Client Device & User-Agent Breakdown")
        device_df = logs_df.groupby(['device', 'status_display']).size().reset_index(name='count')
        fig_dev = px.bar(
            device_df.sort_values('count', ascending=True),
            x='count',
            y='device',
            orientation='h',
            color='status_display',
            color_discrete_map={'Success': '#10B981', 'Failure': '#EF4444'},
            template='plotly_dark'
        )
        fig_dev.update_layout(
            paper_bgcolor='rgba(15, 23, 42, 0.6)',
            plot_bgcolor='rgba(15, 23, 42, 0.4)',
            height=320,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        st.plotly_chart(fig_dev, use_container_width=True)

    with an_c4:
        st.markdown("#### 🕸️ IP vs User Attack Concentration Matrix")
        # Identify suspicious IPs attempting multiple users
        pivot_df = logs_df[logs_df['is_failure']].groupby(['ip_address', 'username']).size().reset_index(name='failed_count')
        if not pivot_df.empty:
            fig_scatter = px.scatter(
                pivot_df,
                x='ip_address',
                y='username',
                size='failed_count',
                color='failed_count',
                color_continuous_scale='Reds',
                labels={'failed_count': 'Failures'},
                template='plotly_dark'
            )
            fig_scatter.update_layout(
                paper_bgcolor='rgba(15, 23, 42, 0.6)',
                plot_bgcolor='rgba(15, 23, 42, 0.4)',
                height=320,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
        else:
            st.info("No failure correlations available to display.")


# -----------------------------------------------------------------------------
# TAB 4: RAW LOG EXPLORER
# -----------------------------------------------------------------------------
with tab_logs:
    st.markdown("### 📜 Raw Authentication Log Records")
    st.markdown("Inspect, filter, and audit the full dataset of authentication events.")

    rl_c1, rl_c2, rl_c3 = st.columns([1.5, 1, 1])
    with rl_c1:
        log_search = st.text_input("Filter raw logs by keyword:", placeholder="Filter by username, IP, device, location...")
    with rl_c2:
        status_filter = st.selectbox("Status Filter:", ["All", "Success Only", "Failure Only"])
    with rl_c3:
        sort_order = st.selectbox("Sort by Timestamp:", ["Newest First", "Oldest First"])

    view_logs = logs_df.copy()
    if status_filter == "Success Only":
        view_logs = view_logs[view_logs['is_success']]
    elif status_filter == "Failure Only":
        view_logs = view_logs[view_logs['is_failure']]

    if log_search.strip():
        term = log_search.strip().lower()
        mask = (
            view_logs['username'].str.lower().str.contains(term, na=False) |
            view_logs['ip_address'].str.lower().str.contains(term, na=False) |
            view_logs['location'].str.lower().str.contains(term, na=False) |
            view_logs['device'].str.lower().str.contains(term, na=False)
        )
        view_logs = view_logs[mask]

    view_logs = view_logs.sort_values('dt', ascending=(sort_order == "Oldest First"))

    st.markdown(f"**Showing {len(view_logs)} records**")
    display_table = view_logs[['timestamp', 'username', 'ip_address', 'status_display', 'location', 'device']].rename(
        columns={'status_display': 'status'}
    )
    st.dataframe(display_table, use_container_width=True, height=450)

    # Download raw filtered logs
    csv_raw = display_table.to_csv(index=False)
    st.download_button(
        label="📥 Download Displayed Logs (CSV)",
        data=csv_raw,
        file_name="filtered_login_logs.csv",
        mime="text/csv"
    )


# -----------------------------------------------------------------------------
# TAB 5: INCIDENT PLAYBOOK & SIEM ARCHITECTURE
# -----------------------------------------------------------------------------
with tab_playbook:
    st.markdown("### 🛡️ Cybersecurity Defense Playbook & Architecture")
    
    pb_col1, pb_col2 = st.columns(2)

    with pb_col1:
        st.markdown("""
        #### 🔒 Practical Security Recommendations
        
        1. **Enforce Phishing-Resistant MFA (Multi-Factor Authentication)**
           - Mandate FIDO2/WebAuthn hardware security keys or authenticator apps (TOTP).
           - Eliminate SMS-based or voice verification to prevent SIM-swapping attacks.
           - Implement step-up MFA whenever unusual locations or devices are detected.
        
        2. **Implement Adaptive Rate Limiting & Account Lockout Policies**
           - Enforce exponential backoff and progressive CAPTCHA challenges after 3 failed attempts.
           - Apply temporary lockouts (e.g., 15 minutes) on consecutive password failures.
           - Rate-limit per IP address to throttle distributed password spraying bots.
        
        3. **Enforce Conditional Access & IP Baselining**
           - Require trusted corporate VPN gateways (`10.0.0.0/8`, `192.168.0.0/16`) for privileged admin roles (`dev_admin`, `root`).
           - Geoblock or flag connections originating from non-business regions or anonymizing VPNs/TOR exit nodes.
        
        4. **Eliminate Password Reuse & Enforce Password Hygiene**
           - Validate passwords against HaveIBeenPwned / breached password databases at signup.
           - Enforce minimum length (14+ characters) over arbitrary complexity rules.
        
        5. **Deploy Continuous Session Validation & Token Revocation**
           - Ensure session tokens expire quickly and bind sessions to device fingerprint / TLS certificates.
           - Invalidate active refresh tokens immediately upon password reset or breach detection.
        """)

    with pb_col2:
        st.markdown("""
        #### 🚨 SOC Incident Response Triage Checklist
        
        When a **High-Risk Alert** fires (e.g., *Successful Login After Repeated Failures* or *Impossible Travel*):
        
        - [ ] **Step 1: Immediate Session Invalidation**  
          Terminate all active sessions for the compromised account via the IdP (Identity Provider) admin console.
        - [ ] **Step 2: Credential Invalidation**  
          Force an immediate password reset and revoke all API keys, OAuth consent tokens, and app passwords.
        - [ ] **Step 3: Perimeter Firewall Drop**  
          Block the offending attacker IP address at the perimeter firewall / WAF level.
        - [ ] **Step 4: Out-of-Band User Verification**  
          Contact the employee via phone or secure corporate chat to verify their physical location and device.
        - [ ] **Step 5: Forensic Audit (Post-Exploitation Investigation)**  
          Inspect cloud audit logs (CloudTrail, M365 Unified Audit Log, Okta System Log) for data exfiltration, privilege escalation, or persistence mechanisms created within 2 hours of the breach.
        """)

    st.markdown("""
    <div class="soc-disclaimer">
        <strong>⚠️ Security Demonstration Disclaimer & SIEM Context:</strong><br>
        This tool demonstrates fundamental rule-based anomaly detection heuristics for cybersecurity learning and prototype monitoring. 
        In production enterprise environments, heuristic rules must be balanced against operational baselines to prevent alert fatigue (false positives) and blind spots (false negatives). 
        Production security architectures rely on comprehensive SIEM (Security Information and Event Management), UEBA (User and Entity Behavior Analytics), and SOAR (Security Orchestration, Automation, and Response) platforms (such as Splunk, Microsoft Sentinel, or Elastic Security) that correlate multi-source telemetry including EDR process trees, network NetFlow, and threat intelligence feeds.
    </div>
    """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# FOOTER
# -----------------------------------------------------------------------------
st.markdown("<hr style='border-color: #1E293B; margin-top: 40px;'>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align: center; color: #64748B; font-size: 12px; padding-bottom: 20px;">
    CyberShield Suspicious Login Detection System • Built with Python & Streamlit • Pair Programming with Antigravity AI
</div>
""", unsafe_allow_html=True)