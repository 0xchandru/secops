# Sample Alert-Generating Logs

Raw log samples for each detection rule. **23 files** covering all parser formats — original (syslog, Windows EventLog, firewall, CEF, CloudTrail) plus new parsers (Apache/Nginx, VPC Flow, DNS). Each file can be sent via the ingestion API or pasted into the Raw Log Paste panel.

## Usage

### Single log
```bash
curl -X POST http://localhost:3000/api/ingest-log \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"source": "<source_type>", "message": "<raw_log_line>"}'
```

### Bulk (for threshold rules)
```bash
curl -X POST http://localhost:3000/api/ingest/bulk \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"logs": [{"source":"<source_type>","message":"<line1>"}, ...]}'
```

### Raw text (paste / pipe entire file)
```bash
curl -X POST http://localhost:3000/api/ingest/raw?source=<source_type> \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"text": "<paste entire file contents>"}'
```

## Rules Index

| # | File | Rule | Type | Severity | MITRE |
|---|------|------|------|----------|-------|
| 1 | `01-brute-force-login.jsonl` | Brute Force Login Attempt | threshold | high | T1110 |
| 2 | `02-suspicious-powershell.jsonl` | Suspicious PowerShell Execution | simple | high | T1059.001 |
| 3 | `03-psexec-lateral-movement.jsonl` | PsExec-style Lateral Movement | simple | critical | T1021.002 |
| 4 | `04-ssh-brute-force.txt` | SSH Brute Force | threshold | medium | T1110 |
| 5 | `05-firewall-blocked-repeated.txt` | Firewall Connection Blocked – Repeated | threshold | medium | T1046 |
| 6 | `06-dns-c2-domain.txt` | DNS Query to Known C2 Domain | simple | critical | T1071.004 |
| 7 | `07-rdp-external-logon.jsonl` | RDP Logon from External IP | simple | high | T1021.001 |
| 8 | `08-new-user-created.jsonl` | New User Account Created | simple | medium | T1136.001 |
| 9 | `09-http-post-external.txt` | Suspicious HTTP POST to External IP | simple | high | T1041 |
| 10 | `10-registry-run-key.jsonl` | Windows Registry Run Key Modification | simple | high | T1547.001 |
| 11 | `11-kerberoasting-spn.jsonl` | Kerberoasting – SPN Request Spike | threshold | high | T1558.003 |
| 12 | `12-cloudtrail-root.json` | CloudTrail – Root Account Usage | simple | critical | T1078.004 |
| 13 | `13-credential-dumping.jsonl` | Credential Dumping Tool Detected | simple | critical | T1003 |
| 14 | `14-login-after-creation.jsonl` | Login After Account Creation | sequence | high | T1136.001 |
| 15 | `15-dns-tunneling.txt` | Excessive DNS Queries – Possible Tunneling | threshold | high | T1071.004 |
| 16 | `16-apache-access-scan.log` | Web Scanner/Crawler Detection | threshold | high | T1595.002 |
| 17 | `17-nginx-500-errors.log` | Web Server Error Spike (500s) | threshold | medium | T1190 |
| 18 | `18-vpc-flow-portscan.txt` | Port Scan Detected (VPC Flow) | threshold | high | T1046 |
| 19 | `19-vpc-flow-ssh-brute.txt` | SSH Brute Force via VPC Flow | threshold | high | T1110 |
| 20 | `20-dns-tunneling-bind.txt` | DNS Tunneling – BIND Encoded Subdomains | threshold | critical | T1071.004 |
| 21 | `21-dns-suspicious-domains.txt` | Suspicious Domain Lookups (DGA/Malicious TLD) | simple | high | T1071.004 |
| 22 | `22-vpc-flow-exfiltration.txt` | Data Exfiltration via Large Outbound Transfer | threshold | critical | T1048 |
| 23 | `23-nginx-sqli-attempt.log` | SQL Injection Attempt (Web Logs) | simple | critical | T1190 |

## Notes

- **Threshold rules** require sending enough events to exceed the count threshold (send all lines in the file).
- **Sequence rules** require sending Step 1 first, then Step 2 within the configured time window.
- `.jsonl` files: each line is a Windows EventLog JSON — use `source: "windows_eventlog"`.
- `.txt` files: each line is a syslog/firewall/CEF/VPC Flow/DNS raw line — use the `source` noted in the file header comment.
- `.log` files: each line is an Apache or Nginx access log — use `source: "apache"` or `source: "nginx"`.
- `.json` files: the entire file is a single CloudTrail JSON event — use `source: "cloudtrail"`.

### New Parser Formats (Files 16–23)

Files 16–23 cover the three new parser types added to the detection pipeline:

- **Apache/Nginx** (`16`, `17`, `23`): Combined Log Format access logs. Parser extracts HTTP method, URL, status code, user-agent, referrer, and source IP. Use `source: "apache"` or `source: "nginx"`.
- **VPC Flow Logs** (`18`, `19`, `22`): AWS VPC Flow Log v2 (space-delimited, 14 fields). Parser extracts src/dst IP/port, protocol, action, bytes, and well-known service names. Use `source: "vpc_flow"`.
- **DNS Query Logs** (`20`, `21`): BIND/named and dnsmasq formats. Parser detects DNS tunneling (high-entropy subdomains), DGA patterns, and suspicious TLDs. Use `source: "dns"`.
