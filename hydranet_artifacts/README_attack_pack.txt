Sample Attack Traffic Pack
===========================
Files:
- sample_attack_traffic.pcap : DNS query/response (spoofed) for malicious-domain.com and a TCP SYN to 203.0.113.55:80 (simulated C2).
- mock_phishing_email.eml : Phishing email template (password reset lure).
- sample_siem_logs.csv : SIEM-like log events (PowerShell, RDP lateral movement, DNS tunneling, C2).

Suggested Candidate Tasks:
1) Open the PCAP in Wireshark. Identify the fake DNS response and destination IP.
2) Explain why the TCP SYN might indicate beaconing and propose next steps.
3) Correlate with CSV logs to reconstruct the timeline.
4) Analyze the .eml email headers/body and list phishing indicators.
