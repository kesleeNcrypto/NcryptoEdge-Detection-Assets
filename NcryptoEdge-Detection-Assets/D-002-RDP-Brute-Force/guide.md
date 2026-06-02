# D-002 — RDP Brute Force: Investigation Guide

**Asset ID:** D-002
**Author:** Esla Kwanza — NCryptoEdge
**Last Updated:** 2026-06-01
**MITRE Technique:** T1110.001 — Brute Force: Password Guessing
**Log Source:** Windows Security Event Log (Event ID 4625, LogonType 10) / Wazuh agent
**Paired Files:** rule.yml | playbook.md | report-language.md

---

## Asset Metadata

```yaml
Asset Category: Authentication

Severity:
  Default: Medium
  Escalated: High

ATT&CK:
  - T1110.001

Client Services:
  - Managed Detection
  - Security Monitoring
  - Incident Response

Platforms:
  - Windows Server
  - Windows Workstation
```

---


## Purpose

This guide walks through the complete triage process when an RDP brute force alert
fires. The goal is to answer one question first: **did the attacker get in?**
Everything else follows from that answer.

---

## Investigation Variables

Populate these fields during triage. These variables are standardized across all NCryptoEdge Detection Assets.

| Variable       | Value |
| -------------- | ----- |
| SOURCE_IP      |       |
| HOSTNAME       |       |
| TARGET_USER    |       |
| ATTEMPT_COUNT  |       |
| FIRST_SEEN     |       |
| LAST_SEEN      |       |
| DETECTION_TIME |       |
| ANALYST        |       |
| TICKET_ID      |       |

---


## Step 1 — Validate the Alert

Confirm the alert is real before escalating.

**Wazuh query (Discover / KQL):**
```
rule.id:100002 AND data.win.eventdata.ipAddress:<SOURCE_IP>
```

**Splunk equivalent:**
```
index=wazuh sourcetype=wazuh EventCode=4625 LogonType=10 IpAddress=<SOURCE_IP>
| table _time, IpAddress, TargetUserName, WorkstationName, host
```

**Confirm:**
- [ ] Alert fired on 5+ Event ID 4625 (LogonType 10) within 60 seconds from a single IP
- [ ] Log timestamps are consistent (not a replay or duplicate alert)
- [ ] Source IP is external (not an internal helpdesk or IT support address)

**False positive checks:**
- Is this IP a known IT support or remote management tool for this client?
- Has the client notified you of a scheduled penetration test?
- Is the targeted username an admin account with known scripted access?

If any of the above is true → close as false positive, document reason.

---

## Step 2 — Determine if Access Was Gained

This is the critical question. Run this immediately.

**Wazuh — check for successful RDP login from same IP:**
```
data.win.system.eventID:4624 AND data.win.eventdata.logonType:10
AND data.win.eventdata.ipAddress:<SOURCE_IP>
```

**Windows Event Log — check directly on the host:**
```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  Id=4624
} | Where-Object {
  $_.Properties[18].Value -eq '<SOURCE_IP>' -and
  $_.Properties[8].Value -eq '10'
} | Select-Object TimeCreated, Message | Format-List
```

**Check for active RDP sessions at time of alert:**
```powershell
query session
qwinsta
```

**If no successful login found:** proceed to Step 3 (impact = low).
**If successful login confirmed:** skip to Step 5 (treat as incident).

---

## Severity Determination

Use the following criteria to determine incident severity.

### Medium

* Failed RDP login attempts only
* No successful authentication observed
* No suspicious activity detected on host

### High

* Successful RDP authentication detected (Event ID 4624, LogonType 10)
* Source IP associated with malicious activity
* Multiple user accounts targeted

### Critical

* Successful authentication followed by privilege escalation
* Successful authentication followed by malware execution
* Successful authentication followed by lateral movement
* Successful authentication followed by persistence creation
* Evidence of data access, exfiltration, or ransomware activity

---

## Step 3 — Profile the Source

Gather context on the attacker to assess threat level and inform the client report.

**Information to collect:**
- Source IP geolocation (use: https://otx.alienvault.com or https://ipinfo.io)
- Is the IP listed on threat intel feeds? Check OTX, AbuseIPDB
- How many total attempts? Over what timeframe?
- Which usernames were targeted? (Administrator, admin, user = automated scan)
- Single IP or multiple IPs targeting the same host?

**Wazuh — username enumeration check:**
```
data.win.eventdata.ipAddress:<SOURCE_IP> AND data.win.system.eventID:4625
| stats count by data.win.eventdata.targetUserName
```

**Assessment logic:**
- Administrator targeted + single IP + rapid timing = automated scanner (low sophistication)
- Specific valid domain usernames targeted = higher concern (possible credential stuffing)
- Multiple IPs same pattern = coordinated campaign or botnet

---

## Step 4 — Check for Persistence (No Breach Confirmed)

Even without a confirmed login, check for indicators of earlier or parallel access.

```powershell
# New local user accounts
Get-LocalUser | Select Name, Enabled, LastLogon

# Recent changes to local admin group
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732} |
  Select-Object TimeCreated, Message | Format-List

# Scheduled tasks (look for unusual entries)
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
  Select TaskName, TaskPath, State

# Active listening ports (unexpected services)
netstat -ano | findstr LISTENING

# RDP-specific: check if NLA is enforced
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
# Expected: 1 (NLA enforced). If 0, flag for hardening.
```

If nothing anomalous found → classify as **Blocked, No Impact**. Move to reporting.

---

## Step 5 — Confirmed Breach Protocol

Only reach this step if Step 2 confirmed a successful RDP login (Event ID 4624, LogonType 10).

**Immediately:**
1. Note the exact time of successful authentication (from Event ID 4624)
2. Check what the attacker did after login:

```powershell
# PowerShell command history
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104} |
  Select-Object TimeCreated, Message | Format-List

# Process creation events during session window (requires Sysmon or audit policy)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object {$_.TimeCreated -ge '<BREACH_TIME>'} |
  Select-Object TimeCreated, Message | Format-List

# Files created or modified during session
# (Use Sysmon Event ID 11 if deployed)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} |
  Where-Object {$_.TimeCreated -ge '<BREACH_TIME>'} |
  Select-Object TimeCreated, Message

# Network connections made during session
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object {$_.TimeCreated -ge '<BREACH_TIME>'} |
  Select-Object TimeCreated, Message
```

3. Determine: was anything exfiltrated, modified, or installed?
4. Document timeline: first attempt → successful login → detection → containment
5. Move immediately to playbook.md — Incident Path

---

## Recommended Hardening Actions

Whether or not a compromise occurred, evaluate the following controls and provide recommendations to the client where appropriate.

### Remote Access Security

* Enable Network Level Authentication (NLA)
* Restrict RDP access to trusted IP addresses
* Require VPN access before RDP access
* Disable direct Internet exposure of RDP services
* Review firewall rules protecting RDP services

### Account Security

* Implement Multi-Factor Authentication (MFA)
* Review account lockout policy settings
* Disable unused accounts
* Remove unnecessary local administrator accounts
* Enforce strong password policies

### Monitoring and Logging

* Enable PowerShell logging (4103, 4104)
* Enable Process Creation auditing (4688)
* Deploy Sysmon for enhanced visibility
* Forward Windows Security Logs to Wazuh
* Configure alerting for repeated failed RDP logons

### Validation

* Confirm NLA status
* Confirm account lockout policy
* Confirm remote access restrictions
* Confirm monitoring coverage for RDP events

```
```

## Step 6 — Close and Document

**For blocked/no-breach:**
- [ ] Alert validated as real
- [ ] No successful login confirmed
- [ ] Source IP profiled
- [ ] No persistence found
- [ ] Source IP blocked (confirm with playbook.md)
- [ ] Report language selected from report-language.md

**For confirmed breach:**
- [ ] Timeline documented
- [ ] Post-login activity captured
- [ ] Playbook.md incident path initiated
- [ ] Client notification drafted using report-language.md (Incident version)

---

## Classification Reference

| Finding | Classification | Report Template |
|---------|---------------|-----------------|
| No successful login, low volume | Informational | Monthly — Blocked version |
| No successful login, high volume / sustained | Low | Monthly — High Volume version |
| Successful login confirmed | High | Incident Report version |

---

*NCryptoEdge Detection Asset — D-002 Investigation Guide | Last updated: 2026-06-02*
