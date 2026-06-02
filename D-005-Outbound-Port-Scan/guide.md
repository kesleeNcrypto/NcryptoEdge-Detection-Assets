# D-005 — Outbound Port Scan: Investigation Guide

**Asset ID:** D-005
**Author:** Esla Kwanza — NCryptoEdge
**Last Updated:** 2026-06-01
**MITRE Technique:** T1046 — Network Service Scanning
**Log Source:** Suricata / Wazuh agent

---

## Purpose

This guide helps analysts investigate outbound port scanning activity sourced
from an internal host. The goal is to determine whether the scan is malicious,
misconfigured, or part of authorised reconnaissance.

---

## Step 1 — Validate the alert

Confirm the scan is coming from a monitored host and not a known security/tool
scanner.

**Wazuh query:**
```
rule.id:100005 AND src.ip:<SOURCE_IP>
```

**Key checks:**
- Alert originates from a host on the monitored network
- Signature indicates outbound scanning or port sweep activity
- Destination ports are broad or sequential

---

## Step 2 — Identify the source host

Collect context on the host generating the scan.

**Look for:**
- Hostname and asset owner
- Process or user responsible for scan generation
- Whether the scan is part of an authorised exercise

---

## Step 3 — Determine if scan is benign

**Benign indicators:**
- Known vulnerability assessment or discovery tools
- Security team activity with approved scope
- Cloud platform health checks or monitoring probes

**Malicious indicators:**
- Unexpected scan from a server with no scanning role
- Scan targeting many hosts or ports rapidly
- Scan source not matching asset owner or business need

---

## Step 4 — Search for related activity

Scan activity can precede lateral movement or data collection.

**Review:**
- Other suspicious outbound connections from the same host
- Local process execution around the scan time
- Any connections to known malicious infrastructure

---

## Step 5 — Escalation

If the scan is malicious:
- Isolate or restrict the host immediately
- Block outbound scanning at the network boundary
- Investigate the host for compromise or misuse
- Notify the asset owner and security operations team
