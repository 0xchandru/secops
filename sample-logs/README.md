# Sample Logs — Alert Trigger Samples

Each file in this directory contains real log events crafted to trigger one or more of the 15 seeded detection rules. Send them via the ingest API or paste them in the Log Explorer raw ingest panel.

---

## Quick Ingest (all files)

Replace `<token>` with your bearer token (login first via `/api/auth/login`).

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123"}' | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4)
echo "Token: $TOKEN"
```

### Send a JSONL file (Windows EventLog)
```bash
# Read each line and send as individual events
while IFS= read -r line; do
  curl -s -X POST http://localhost:8080/api/ingest-log \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"source\":\"windows_eventlog\",\"message\":$(echo $line | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}"
done < sample-logs/02-powershell-execution.jsonl
```

### Send a raw text file (syslog, firewall, CEF)
```bash
curl -s -X POST "http://localhost:8080/api/ingest/raw?source=syslog" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"text\":\"$(cat sample-logs/04-ssh-brute-force.txt | tr '\n' '|' | sed 's/|/\\n/g')\"}"
```

### Send a CloudTrail JSON file
```bash
curl -s -X POST http://localhost:8080/api/ingest-log \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"source\":\"cloudtrail\",\"message\":$(cat sample-logs/12-cloudtrail-root.json | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}"
```

---

## Files and Alert Mapping

| File | Source Type | Rule Triggered | Severity | MITRE |
|---|---|---|---|---|
| `01-brute-force-windows.jsonl` | `windows_eventlog` | Brute Force Login Attempt | HIGH | T1110 |
| `02-powershell-execution.jsonl` | `windows_eventlog` | Suspicious PowerShell Execution | HIGH | T1059.001 |
| `03-psexec-lateral-movement.jsonl` | `windows_eventlog` | PsExec-style Lateral Movement | CRITICAL | T1021.002 |
| `04-ssh-brute-force.txt` | `syslog` | SSH Brute Force | MEDIUM | T1110 |
| `05-firewall-port-scan.txt` | `syslog` | Firewall Connection Blocked – Repeated | MEDIUM | T1046 |
| `06-dns-c2-beaconing.jsonl` | `windows_eventlog` | DNS Query to Known C2 Domain | CRITICAL | T1071.004 |
| `07-rdp-external-login.jsonl` | `windows_eventlog` | RDP Logon from External IP | HIGH | T1021.001 |
| `08-new-user-created.jsonl` | `windows_eventlog` | New User Account Created | MEDIUM | T1136.001 |
| `09-http-exfiltration.txt` | `cef` | Suspicious HTTP POST to External IP | HIGH | T1041 |
| `10-registry-persistence.jsonl` | `windows_eventlog` | Windows Registry Run Key Modification | HIGH | T1547.001 |
| `11-kerberoasting.jsonl` | `windows_eventlog` | Kerberoasting – SPN Request Spike | HIGH | T1558.003 |
| `12-cloudtrail-root.json` | `cloudtrail` | CloudTrail – Root Account Usage | CRITICAL | T1078.004 |
| `13-credential-dumping.jsonl` | `windows_eventlog` | Credential Dumping Tool Detected | CRITICAL | T1003 |
| `14-account-creation-login.jsonl` | `windows_eventlog` | Login After Account Creation (sequence) | HIGH | T1136.001 |
| `15-dns-tunneling.txt` | `syslog` | Excessive DNS Queries – Possible Tunneling | HIGH | T1071.004 |

---

## Notes

- **Threshold rules** (brute force, SSH, firewall, kerberoasting, DNS tunneling): each file contains enough events (6–12) to cross the configured threshold within one ingest call.
- **Simple rules** (PowerShell, PsExec, RDP, registry, credential dumping, C2 DNS): one matching event is enough to fire the alert.
- **Sequence rule** (file 14): the file contains both Step 1 (user creation) and Step 2 (login) with the same `TargetUserName`. Send all lines together — the detection engine processes them sequentially.
- `.jsonl` files: send each line separately with `source: "windows_eventlog"`, or use the bulk ingest endpoint.
- `.txt` files: send the entire file contents as `source: "syslog"` or `source: "cef"` using the raw ingest endpoint.
- `.json` files: send the whole JSON object as `source: "cloudtrail"`.
