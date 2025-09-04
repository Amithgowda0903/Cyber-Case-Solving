
# **1. Artifact Analysis Walkthrough**

### A) SIEM Logs (`black_swan_siem_logs.csv`)

**Timeline Reconstruction:**

1. Time Unknown - Phish opened (initial access to SaaS, T1566.002 spearphishing link).
2. 10:00:10 - VPN login from `vendor-vpn-1` - `10.0.3.15` (Initial access, T1078 valid accounts). 
3. 10:01:22 - `rundll32.exe` executing suspicious DLL (Execution, T1218.011 LOLBin).  
4. 10:02:44 - PowerShell command, encrypted HTTPS domain fronting (T1059.001 + T1090.004).    
5. 10:03:55 - RDP from `10.0.3.15` - `10.0.3.20` (T1021.001).    
6. 10:04:30 - Kerberos anomaly, forged Golden Ticket, 10y lifetime (Privilege escalation + Persistence, T1558.001).    
7. 10:05:10 - DNS over HTTPS traffic to `8.8.8.8` (Exfiltration, T1071.004).     
8. 10:06:00 - IoT QR scanner beaconing to `203.0.113.200` (Persistence, T1108).    
9. 10:07:15 - DB query on `db-oracle-1` - settlement data access (Collection, T1005).    
10. 10:08:45 - POS broker(QR scanner) - `203.0.113.210` through MQTT exfil (Exfiltration, T1074.002). 
11. 10:09:30 - ICS relay OFF through Modbus command (configuration,DS0017).
    

**Expected Findings:**
- VPN initial entry(Attacker) from vendor connection.    
- Domain compromise through Kerberos manipulation.    
- Exfiltrated data from DB and POS broker.    
- Persistence through IoT node.    
- ICS relay toggled.

---
### B) VPN Authentication & Phishing Email 
Indicators:
- Vendor credentials successfully authenticated without MFA.    
- Unusual login geo/time anomalies not flagged.    

- Sender domain `vendor-update-secure.example.com` not legitimate
- Link `http://vendor-update-secure.example.com/login` (insecure HTTP + suspicious domain).
- Urgency + compliance scare tactic.
- No DKIM/DMARC/SPF alignment.

**Expected Conclusion:**
- Weak vendor VPN  - direct attacker entry point. 
- Block/quarantine, domain takedown request.
- Search other inboxes for campaign distribution.

---

### C) Database Logs (`black_swan_siem_logs.csv`)

- Query: `SELECT UTR, Amount FROM settlements`.    
- Access from `10.0.3.20`, impersonating DB admin account.    

**Expected Conclusion:**
- Financial data reconnaissance + staging for exfil.

---
### D) IoT Logs (`black_swan_iot_logs`)

- Beacon to `203.0.113.200` every 30s.    
- Persistence mechanism tied to IoT QR scanner device.

---
### E) ICS Logs (`black_swan_ics_logs`)

- Modbus relay state changed → OFF.    
- Command origin: `10.0.3.20`.    
- Severity High

**Expected Conclusion:**
- Attack pivoted into OT - ICS relay tempered which leads to high business impact.

---
# **2. MITRE ATT&CK Mapping**

| Stage                  | Technique ID         | Technique Name                         |
| ---------------------- | -------------------- | -------------------------------------- |
| initial access to SaaS | T1566.002            | spearphishing link                     |
| Initial Access         | T1078                | Valid Accounts (Vendor VPN login)      |
| Execution              | T1218.011            | Rundll32 (LOLBin execution of DLL)     |
| Execution and C2       | T1059.001, T1090.004 | PowerShell & domain Fonting            |
| Lateral Movement       | T1021.001            | RDP                                    |
| Persistence(server)    | T1558.001            | Kerberos Golden Ticket                 |
| Persistence (IoT)      | T1108                | Redundant Access (IoT beacon)          |
| Privilege Escal.       | T1558.001            | Kerberos Ticket Forging                |
| C2 (HTTPS)             | T1071.001            | Application Layer Protocol: Web        |
| C2 (DoH)               | T1071.004            | Application Layer Protocol: DNS        |
| Collection             | T1005                | Data from Local System (Settlement DB) |
| Exfiltration           | T1071.004            | Exfiltration through MQTT/DNS          |
| Impact (ICS)           | T0829                | Manipulation of Control (Modbus relay) |
| Defense Evasion        | T1140                | Obfuscated Files or Information        |

---
# **3. Expected Detection Queries**

### Splunk
```spl
source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" details="Billing SaaS vendor connected" event="Vendor VPN login"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" event="LOLBin execution" src_ip="10.0.3.15"

source="black_swan_siem_logs.csv" host="amith" index="summary" sourcetype="csv" event="PowerShell command" details="Encrypted HTTPS with domain fronting"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" details="Jump host lateral move" dst_ip="10.0.3.20" event="RDP connection"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" details="Golden Ticket forged, lifetime=10y"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" event="DNS over HTTPS" details="Suspicious exfil traffic" src_ip="10.0.3.20"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" details="QR scanner beacon every 60s" dst_ip=2"203.0.113.200" event="IoT firmware beacon"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" details="SELECT UTR, Amount FROM settlements" event="DB query"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" details="POS telemetry data siphoned" event="MQTT exfil" dst_ip="203.0.113.210" src_ip="pos-broker"

source="black_swan_siem_logs.csv" index="summary" sourcetype="csv" src_ip="pos-broker" dst_ip="203.0.113.210" event="MQTT exfil"
```

---
# **4. Business Impact Assessment**

- **Financial Data:** Settlement DB queries - leakage of sensitive transaction records.    
- **Merchants:** POS broker exfiltration - exposure of payment telemetry logs.    
- **IoT Subnet:** Weak link exploited - persistence - staging point.    
- **ICS:** Relay toggled OFF - operational disruption 
- **Overall:**  IT and OT compromise which directly indicates systemic risk to payments and operations.    

---
# **5. Executive Summary Template**

> **Summary:**  
> On 26-8-2025, the enterprise was compromised through a **vendor VPN connection**.  
> The attacker used **LOLBin execution (rundll32)**, **PowerShell C2**, and lateral RDP movement to pivot into the core domain server (`10.0.3.20`).  
> From there, they forged a **Kerberos Golden Ticket**, granting full domain persistence.  
> They exfiltrated **financial settlement data** and **POS telemetry** through DNS over HTTPS and MQTT.  
> Persistence was maintained through an **IoT QR scanner implant**.  
> Finally, the attacker issued **unauthorized ICS relay commands**, threatening operational continuity.
> 
> **Impact:**  
> High severity - compromise of financial and operational systems.  
> 
> **Next Steps:**
> - Enforce MFA for the vendor VPN and also Reset the credentials.    
> - Kerberos key change (reset).    
> - Segment IoT and ICS networks. 
> - Enhance SIEM with DNS over HTTPS and MQTT anomaly detection.