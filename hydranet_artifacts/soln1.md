## 1. Artifact Analysis Walkthrough

### A) SIEM Logs (hydranet_siem_logs.csv)
**Timeline Reconstruction:**
1. 09:00:12 — Phish opened (initial access, T1566.002 spearphishing link).
2. 09:01:05 — PowerShell obfuscated command executed (`-nop -w hidden -enc`) → execution (T1059.001).
3. 09:02:45 — RDP from bastion → app node (`10.0.2.20`) → lateral movement (T1021.001).
4. 09:05:22 — Suspicious DNS query to 8.8.8.8 → C2 over DNS (T1071.004).
5. 09:06:00 — HTTP beacon to `203.0.113.55` → web C2 (T1071.001).
6. 09:06:30 — IoT CCTV device beaconing to `203.0.113.99` → persistence channel (T1108).
7. 09:07:22 — Webhook callback signature failure on `/upi/callback` → indicates tampering attempt.
8. 09:08:10 — Access to `finance.xlsx` (collection, T1005).
9. 09:09:45 — ICS Modbus write (impact, T0829 manipulatio-n of control).

**Expected Findings:**
- Multi-host compromise (bastion + app node + IoT cam + ICS node).
- Recon and exfil attempt through C2 channels.
- Tampering with UPI webhook flow integrity.

---

### B) Phishing Email (hydranet_phishing_email.eml)
**Indicators:**
- Sender domain `npci-gov.in` not legitimate (`npci.org.in` would be).
- Link `http://npcicompliance-reset.example.com/login` (insecure HTTP + suspicious domain).
- Urgency + compliance scare tactic.
- No DKIM/DMARC/SPF alignment.

**Expected Actions:**
- Block/quarantine, domain takedown request.
- Search other inboxes for campaign distribution.

---

### C) ICS Logs (hydranet_ics_logs.txt)
- Modbus WRITE to register 40001 → power controller changed state.
- Alert from ICS node: unexpected command from `10.0.2.20`.

**Expected Conclusion:**
- Attackers pivoted into ICS from IT core.
- High business impact if power to payments infra disrupted.

---

### D) IoT Logs (hydranet_iot_logs.txt)
- CCTV device beaconing every 30s to `203.0.113.99`.
- Persistence channel: likely malware implant on IoT device.

**Expected Conclusion:**
- IoT subnet is a weak link.
- Requires segmentation + NAC + patching/monitoring.

---

### E) PCAP (hydranet_attack.pcap)
- Contains DNS query/response and HTTP SYN to attacker IP.
- Confirms network-level evidence of DNS spoofing and beaconing.

---

## 2. MITRE ATT&CK Mapping

| Stage              | Technique ID     | Technique Name                               |
|--------------------|-----------------|----------------------------------------------|
| Initial Access     | T1566.002       | Spearphishing Link                          |
| Execution          | T1059.001       | PowerShell                                  |
| Persistence        | T1108           | Redundant Access (IoT beacon channel)       |
| Privilege Escal.   | T1078           | Valid Accounts (stolen creds via RDP)       |
| Lateral Movement   | T1021.001       | Remote Desktop Protocol                     |
| C2 (DNS)           | T1071.004       | Application Layer Protocol: DNS             |
| C2 (HTTP)          | T1071.001       | Application Layer Protocol: Web             |
| Collection         | T1005           | Data from Local System (finance.xlsx)       |
| Exfil/Impact       | T0829 (ICS)     | Manipulation of Control (Modbus commands)   |
| Defense Evasion    | T1140           | Obfuscated Files or Information             |

---

## 3. Expected Detection Queries

### Splunk
```spl
index=siem sourcetype=hydranet event="PowerShell execution" details="* -enc *"
index=siem sourcetype=hydranet event="RDP connection"
index=siem sourcetype=hydranet event="DNS request" (details="*encoded*" OR details="*suspicious*")
index=siem sourcetype=hydranet event="Webhook callback failure"
index=siem sourcetype=hydranet event="IoT beacon" dst_ip!=approved_list
index=ics sourcetype=modbus action=WRITE
```

### ELK (Kibana Lucene Query)
```
event:"PowerShell execution" AND event.original:* -enc *
event:"RDP connection"
event:"DNS request" AND (event.original:*encoded* OR event.original:*suspicious*)
event:"Webhook callback failure"
event:"IoT beacon" AND NOT destination.ip:(PSP_IP_ALLOWLIST)
protocol:Modbus AND action:WRITE
```

### K8s/Falco (IoC Example)
```yaml
- rule: Unexpected Container Exec
  desc: Detects exec into UPI Switch containers
  condition: container.name=upi-switch and evt.type=execve and not user=root
  output: "Exec into UPI container by non-root user (user=%user.name)"
```

---

## 4. Business Impact Assessment

- **Merchants:** No double-debits confirmed; reconciliation integrity at risk due to DB tampering.
- **PSPs:** Webhook callbacks tampered; SLA breaches possible.
- **NPCI:** Must notify if reconciliation mismatches cross thresholds.
- **ICS:** Simulated outage → could cascade into downtime for payment infra.


---

## 5. Executive Summary Template

> **Summary:**
> On 26-Aug-2025, UPI Switch infra was targeted by a phishing-led APT campaign.
> Attackers leveraged PowerShell execution, lateral RDP, DNS + HTTP C2, and IoT persistence.
> They attempted to tamper with webhook callbacks and reconciliation DBs, and issued unauthorized ICS commands.
> Impact contained with no confirmed merchant double-debits; reconciliation re-run; IoT node isolated.
> Next steps: PSP key rotation, IoT subnet hardening, DNSSEC/mTLS enforcement.

---

# End

#spi 