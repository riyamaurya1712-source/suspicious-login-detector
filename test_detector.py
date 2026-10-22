import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def run_detection_rules(df, config=None):
    if config is None:
        config = {
            "failed_attempts_threshold": 5,
            "failed_window_minutes": 10,
            "work_hours_start": 8,
            "work_hours_end": 19,
            "check_weekends": True,
            "succ_after_fail_threshold": 3,
            "succ_after_fail_window_minutes": 15,
            "trusted_ips": ["192.168.1.100", "192.168.1.101", "10.0.1.50", "10.0.1.51", "10.0.1.52"],
            "spray_users_threshold": 3,
            "spray_window_minutes": 15,
            "velocity_window_minutes": 15,
        }

    work_df = df.copy()
    work_df['dt'] = pd.to_datetime(work_df['timestamp'])
    work_df['status_norm'] = work_df['status'].astype(str).str.strip().str.capitalize()
    work_df['is_success'] = work_df['status_norm'].str.startswith('Succ') | work_df['status_norm'].isin(['Pass', 'Succeeded', 'True', '1'])
    work_df['is_failure'] = ~work_df['is_success']
    work_df['username'] = work_df['username'].astype(str).str.strip()
    work_df['ip_address'] = work_df['ip_address'].astype(str).str.strip()
    
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

    # RULE 1: Repeated Failed Logins
    failed_win = timedelta(minutes=config["failed_window_minutes"])
    n_fail = config["failed_attempts_threshold"]

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
                    "rule_id": "RULE-01",
                    "rule_name": "Repeated Failed Logins (User Target)",
                    "risk_level": risk,
                    "explanation": f"{count} failed login attempts targeted user '{user}' within {config['failed_window_minutes']} minutes (source IP: {', '.join(window_ips)}).",
                    "action": f"Temporarily lock account '{user}', mandate password reset & MFA.",
                    "evidence_count": count
                })
                i = j
            else:
                i += 1

    # RULE 2: Unusual Login Times
    start_h = config["work_hours_start"]
    end_h = config["work_hours_end"]
    trusted_set = set(config.get("trusted_ips", []))

    for idx, row in work_df.iterrows():
        event_dt = row['dt']
        h = event_dt.hour
        is_weekend = (event_dt.weekday() >= 5) and config["check_weekends"]
        is_off_hour = (h < start_h or h >= end_h)
        if is_off_hour or is_weekend:
            is_untrusted = row['ip_address'] not in trusted_set
            risk = "Medium" if is_untrusted else "Low"
            alerts.append({
                "timestamp": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "dt": event_dt,
                "username": row['username'],
                "ip_address": row['ip_address'],
                "rule_id": "RULE-02",
                "rule_name": "Unusual Login Time",
                "risk_level": risk,
                "explanation": f"Login event ({row['status']}) for '{row['username']}' outside working hours.",
                "action": "Verify user work schedule and dispatch push validation.",
                "evidence_count": 1
            })

    # RULE 3: Successful Login After Repeated Failures
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
                "explanation": f"CRITICAL: Successful login for '{succ_user}' after {len(prior_fails)} failures.",
                "action": "Immediate containment: invalidate active sessions, force password reset.",
                "evidence_count": len(prior_fails)
            })

    # RULE 4: Untrusted IP Address
    for idx, row in work_df.iterrows():
        ip = row['ip_address']
        if ip not in trusted_set:
            risk = "Medium" if row['is_success'] else "Low"
            alerts.append({
                "timestamp": row['dt'].strftime("%Y-%m-%d %H:%M:%S"),
                "dt": row['dt'],
                "username": row['username'],
                "ip_address": ip,
                "rule_id": "RULE-04",
                "rule_name": "Unfamiliar / Untrusted IP Address",
                "risk_level": risk,
                "explanation": f"Login attempt from IP {ip} not found in whitelist.",
                "action": "Inspect IP reputation on threat feeds.",
                "evidence_count": 1
            })

    # RULE 5: Password Spraying
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
                    "username": ", ".join(unique_targets[:4]),
                    "ip_address": ip,
                    "rule_id": "RULE-05",
                    "rule_name": "Multiple-User Targeting (Password Spraying)",
                    "risk_level": "High",
                    "explanation": f"IP {ip} targeted {len(unique_targets)} accounts within {config['spray_window_minutes']}m.",
                    "action": "Block IP at edge firewall, reset credentials.",
                    "evidence_count": len(unique_targets)
                })
                i = j
            else:
                i += 1

    # RULE 6: Velocity Anomaly
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
                if loc1 != 'Unknown' and loc2 != 'Unknown' and loc1 != loc2:
                    delta_mins = max(1, int(delta.total_seconds() / 60))
                    alerts.append({
                        "timestamp": e2['dt'].strftime("%Y-%m-%d %H:%M:%S"),
                        "dt": e2['dt'],
                        "username": user,
                        "ip_address": f"{ip1} -> {ip2}",
                        "rule_id": "RULE-06",
                        "rule_name": "Impossible Travel / Velocity Anomaly",
                        "risk_level": "High",
                        "explanation": f"Impossible travel for '{user}' ({loc1} to {loc2} in {delta_mins}m).",
                        "action": "Revoke active session tokens, challenge with hardware key.",
                        "evidence_count": delta_mins
                    })

    alerts_df = pd.DataFrame(alerts)
    return alerts_df

if __name__ == "__main__":
    df = pd.read_csv("sample_login_logs.csv")
    alerts = run_detection_rules(df)
    print(f"Total alerts detected: {len(alerts)}")
    print(alerts['risk_level'].value_counts())