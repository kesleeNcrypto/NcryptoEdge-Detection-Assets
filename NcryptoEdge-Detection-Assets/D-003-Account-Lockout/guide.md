# D-003 — Account Lockout: Investigation Guide

**Asset ID:** D-003
**Author:** Esla Kwanza — NCryptoEdge
**Last Updated:** 2026-06-01
**MITRE Technique:** T1110.001 — Brute Force: Password Guessing
**Log Source:** Windows Security / Wazuh agent

---

## Purpose

This guide helps determine whether a Windows account lockout is caused by
malicious authentication attempts, legitimate user error, or a misconfigured
system.

---

## Step 1 — Validate the event

Confirm the lockout is from a real account and not a known administrative action.

**Wazuh query:**
```
rule.id:100003 AND user.name:<TARGET_USERNAME>
```

**Checks:**
- Lockout event is EventID 4740
- Target account is valid and in scope
- Source IP or computer name is known
- Lockout was not caused by password resets or account provisioning

---

## Step 2 — Identify the source

Capture the lockout source and related events.

**Windows event log:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740; StartTime=(Get-Date).AddHours(-6)} |
  Where-Object { $_.Properties[0].Value -eq '<TARGET_USERNAME>' }
```

**Look for:**
- Source computer name or IP address
- Caller account that initiated the lockout
- Time window of repeated failures

---

## Step 3 — Determine whether it is malicious

**Indicators of malicious lockout:**
- Lockout from an external or unknown source
- Multiple account names targeted from the same source
- Lockout on high-value accounts or admin users
- Repeated lockouts across many systems in a short window

**Possible benign causes:**
- Users typing the wrong password repeatedly
- Legacy services using cached credentials
- Password change synchronization issues

---

## Step 4 — Follow-on activity

If malicious activity is suspected, look for surrounding events.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4625,4624,4768,4769); StartTime=(Get-Date).AddHours(-6)}
```

Check for:
- Failed authentication bursts before the lockout
- Any successful authentications from the same source
- Other lockouts or failed logons on related accounts

---

## Step 5 — Escalation

If this lockout is suspicious:
- Treat as a potential credential stuffing or brute force event
- Block the source if it is external and malicious
- Review related hosts for the same source or account activity
- Move to P-003 incident playbook if successful access or persistence is found
