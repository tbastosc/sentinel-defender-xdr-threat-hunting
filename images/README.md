# 📷 Repository Screenshots & Evidence Assets Catalog

This directory contains the visual evidence captured during the Microsoft Sentinel & Defender XDR threat hunting investigation.

## 🖼️ Image Assets

| Filename | Data Source / Interface | Investigation Context |
| :--- | :--- | :--- |
| `img1_crowdstrike.png` | Defender XDR Advanced Hunting (`CrowdStrikeAlerts`) | Endpoint alert aggregation identifying host `win11a` as a heavily targeted pivot host with 112 alerts. |
| `img2_paloalto.png` | Microsoft Sentinel (`CommonSecurityLog`) | Palo Alto firewall blocked traffic query identifying internal port scanning from `10.0.1.50` across 124 ports. |
| `img3_paloalto.png` | Microsoft Sentinel (`CommonSecurityLog`) | Outbound HTTPS session analysis proving C2 communication and ~183 MB data exfiltration. |
| `img4_security_eventlog.png` | Sentinel Incidents Dashboard (`SecurityEvent`) | Detection of Windows Event ID 1102 (Security Log Cleared) under incident "NRT Security Event log cleared". |
| `img5_automation_standart_rule.png` | Sentinel Automation Rules Engine | Configuration of "Escalate Log Cleared Events" rule to auto-tag (`defense-evasion`) and elevate severity to High. |
