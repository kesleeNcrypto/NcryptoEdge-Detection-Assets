# D-004 — Suspicious PowerShell: Investigation Guide

**Asset ID:** D-004
**Author:** Esla Kwanza — NCryptoEdge
**Last Updated:** 2026-06-01
**MITRE Technique:** T1059.001 — PowerShell
**Log Source:** Windows Sysmon / Wazuh agent

---

## Purpose

This guide helps investigators determine whether suspicious PowerShell activity
represents malicious execution, administrative automation, or a benign process.

---

## Step 1 — Validate the alert

Confirm the process and command line details.

**Wazuh query:**
```
rule.id:100004 AND data.process_path:*powershell.exe*
```

**Key checks:**
- Process is PowerShell or pwsh
- Command line contains encoded or suspicious parameters
- Execution occurred on a host that should not be running automation scripts

---

## Step 2 — Identify the user and context

Capture the account that launched PowerShell and the parent process.

**Look for:**
- Service accounts or scheduled task credentials
- Parent process that may indicate legitimate automation
- Whether the command line was launched from a remote session

---

## Step 3 — Determine if execution is malicious

**High-risk indicators:**
- Use of `-EncodedCommand` or `IEX`
- Inline downloaders such as `DownloadString` or `Invoke-WebRequest`
- Commands that create persistence or modify security settings

**Lower-risk indicators:**
- Managed deployment tools such as SCCM or Intune
- Known backup or patching systems using PowerShell
- Security agents scanning with PowerShell

---

## Step 4 — Search for follow-on activity

If this appears malicious, search for additional activity on the host.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4688,4697,7045); StartTime=(Get-Date).AddHours(-6)}
```

Also review:
- newly created scheduled tasks
- changes to startup or service configurations
- suspicious network connections from the host

---

## Step 5 — Escalation

If malicious PowerShell execution is confirmed:
- Isolate the host if necessary
- Collect the full PowerShell command line and process tree
- Check for persistence mechanisms
- Move to the incident response playbook
