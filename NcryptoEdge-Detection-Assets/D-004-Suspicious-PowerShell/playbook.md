# P-004 — Suspicious PowerShell: Response Playbook

**Playbook ID:** P-004
**Linked Detection:** D-004 — Suspicious PowerShell
**Technique:** T1059.001
**Trigger:** D-004 alert fires and investigation indicates malicious PowerShell execution
**Author:** Esla Kwanza — NCryptoEdge

---

## Phase 1 — Contain the host

### If malicious execution is confirmed
- Remove the host from untrusted networks
- Disable remote access and stop the suspicious process if possible
- Preserve the process command line, parent PID, and event logs

### If suspicious but not confirmed
- Monitor the host closely for follow-on commands
- Restrict access to the host to trusted administrators only

---

## Phase 2 — Collect evidence

Capture:
- Sysmon event ID 1 with PowerShell command line
- Process creation trees and parent process details
- Scheduled tasks, services, and autoruns added around the event

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=(Get-Date).AddHours(-6)}
```

---

## Phase 3 — Remove persistence

Check for and remove persistence created by the attacker:
- Scheduled tasks
- Services
- Registry autoruns
- Startup folder entries

---

## Phase 4 — Recover

### If no compromise found
- Document the alert and findings
- Allow legitimate automation to continue after validation
- Tune detection for known safe PowerShell usage

### If compromise found
- Rebuild the host if persistence or credential theft is suspected
- Reset credentials for affected accounts
- Review all PowerShell activity in the incident window

---

## Phase 5 — Hardening

Recommended improvements:
- Restrict PowerShell execution via AppLocker or transcription policies
- Enable PowerShell logging and script block logging
- Block `powershell.exe` and `pwsh.exe` for non-administrative users
- Monitor for encoded PowerShell commands and downloader patterns
