import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def generate_sample_data():
    base_time = datetime(2026, 10, 19, 8, 0, 0)
    records = []

    # 1. Normal corporate logins (Baseline)
    normal_users = ["alice.smith", "bob.jones", "carol.security", "david.miller", "emma.watson", "frank.castle"]
    trusted_ips = ["192.168.1.100", "192.168.1.101", "10.0.1.50", "10.0.1.51", "10.0.1.52"]
    
    for i in range(35):
        t = base_time + timedelta(minutes=int(i * 14 + (i % 7) * 3))
        user = normal_users[i % len(normal_users)]
        ip = trusted_ips[i % len(trusted_ips)]
        records.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "username": user,
            "ip_address": ip,
            "status": "Success",
            "location": "New York, US",
            "device": "Windows 11 / Chrome"
        })

    # Occasional normal user typo (single failure then success)
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

    # 2. Attack Scenario 1: Repeated Failed Logins (Brute Force against alice.smith)
    bf_start = base_time + timedelta(hours=1, minutes=10)
    for i in range(7):
        records.append({
            "timestamp": (bf_start + timedelta(seconds=i * 35)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "alice.smith",
            "ip_address": "198.51.100.42",
            "status": "Failure",
            "location": "Frankfurt, DE",
            "device": "Python-requests / 2.31"
        })

    # 3. Attack Scenario 2: Successful Login After Repeated Failures (dev_admin compromise)
    comp_start = base_time + timedelta(hours=6, minutes=2)
    for i in range(5):
        records.append({
            "timestamp": (comp_start + timedelta(seconds=i * 45)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "dev_admin",
            "ip_address": "203.0.113.19",
            "status": "Failure",
            "location": "Bucharest, RO",
            "device": "Hydra / v9.5"
        })
    records.append({
        "timestamp": (comp_start + timedelta(minutes=4, seconds=30)).strftime("%Y-%m-%d %H:%M:%S"),
        "username": "dev_admin",
        "ip_address": "203.0.113.19",
        "status": "Success",
        "location": "Bucharest, RO",
        "device": "Hydra / v9.5"
    })

    # 4. Attack Scenario 3: Multiple-User Targeting (Password Spraying)
    spray_start = base_time + timedelta(hours=3, minutes=20)
    spray_targets = ["admin", "root", "john.doe", "sarah.connor", "finance_lead"]
    for i, target in enumerate(spray_targets):
        records.append({
            "timestamp": (spray_start + timedelta(minutes=i * 1.2)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": target,
            "ip_address": "185.220.101.5",
            "status": "Failure",
            "location": "Amsterdam, NL",
            "device": "Go-http-client / 1.1"
        })

    # 5. Scenario 4: Unusual Login Times (Off-hours: 02:35 AM)
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

    # 6. Scenario 5: Unfamiliar / Untrusted IP
    records.append({
        "timestamp": (base_time + timedelta(hours=4, minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
        "username": "carol.security",
        "ip_address": "194.26.29.112",
        "status": "Success",
        "location": "Reykjavik, IS",
        "device": "Ubuntu / Firefox"
    })

    # 7. Scenario 6: Unusual Access Pattern - Velocity / Impossible Travel
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

    # 8. Scenario 6b: Rapid IP switching
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
    df['dt'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('dt').drop(columns=['dt']).reset_index(drop=True)
    return df

if __name__ == "__main__":
    df = generate_sample_data()
    print(f"Generated {len(df)} sample log entries.")
    df.to_csv("sample_login_logs.csv", index=False)
    print("Saved to sample_login_logs.csv successfully!")