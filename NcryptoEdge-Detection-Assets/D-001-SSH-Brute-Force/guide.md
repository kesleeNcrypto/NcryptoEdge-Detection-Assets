# D-001 — SSH Brute Force: Investigation Guide

**Asset ID:** D-001
**Author:** Esla Kwanza — NcryptoEdge
**Last Updated:** 2026-06-01
**MITRE Technique:** T1110.001 — Brute Force: Password Guessing
**Log Source:** Linux auth logs / Wazuh agent
**Paired Files:** rule.yml | playbook.md | report-language.md

---

## Purpose

This guide walks through the complete triage process when an SSH brute force
alert fires. The goal is to answer one question first: **did the attacker get in?**
Everything else follows from that answer.

---

## Step 1 — Validate the Alert

Confirm the alert is real before escalating.

**Wazuh query (Discover / KQL):**
```
rule.id:100001 AND data.srcip:<SOURCE_IP>
```

**Splunk equivalent:**
```
index=wazuh sourcetype=wazuh rule_id=100001 src_ip=<SOURCE_IP>
| table _time, src_ip, dstuser, hostname, rule_description
```

**Confirm:**
- [ ] Alert fired on 5+ failures within 60 seconds from a single source IP
- [ ] Log timestamps are consistent (not a replay or duplicate alert)
- [ ] Source IP is external (not an internal monitoring tool or jump server)

**False positive checks:**
- Is this IP a known monitoring or automation system for this client?
- Has the client notified you of a scheduled penetration test?
- Is the targeted username a service account with known scripted access?

If any of the above is true → close as false positive, document reason.

---

## Step 2 — Determine if Access Was Gained

This is the critical question. Run this immediately.

**Wazuh — check for successful login from same IP:**
```
rule.groups:authentication_success AND data.srcip:<SOURCE_IP>
```

**Linux — check auth log directly on the host:**
```bash
grep "Accepted password\|Accepted publickey" /var/log/auth.log | grep <SOURCE_IP>
```

**Check active sessions at time of alert:**
```bash
last | grep <SOURCE_IP>
who
w
```

**If no successful login found:** proceed to Step 3 (impact = low).
**If successful login confirmed:** skip to Step 5 (treat as incident).

---

## Step 3 — Profile the Source

Gather context on the attacker to assess threat level and inform the client report.

**Information to collect:**
- Source IP geolocation (use: https://otx.alienvault.com or https://ipinfo.io)
- Is the IP listed on threat intel feeds? Check OTX, AbuseIPDB
- How many total attempts? Over what timeframe?
- Which usernames were targeted? (root, admin, common names = automated scan)
- Single IP or multiple IPs targeting the same host?

**Wazuh — username enumeration check:**
```
data.srcip:<SOURCE_IP> AND rule.groups:authentication_failures
| stats count by data.dstuser
```

**Assessment logic:**
- Root/admin targeted + single IP + rapid timing = automated scanner (low sophistication)
- Specific valid usernames targeted = higher concern (possible credential stuffing)
- Multiple IPs same pattern = coordinated campaign

---

## Step 4 — Check for Persistence (No Breach Confirmed)

Even without a confirmed login, check for indicators of earlier or parallel access.

```bash
# New user accounts
cat /etc/passwd | grep -v nologin | grep -v false

# Recent sudo usage
grep sudo /var/log/auth.log | tail -50

# Scheduled tasks
crontab -l
ls -la /etc/cron*

# Listening services (unexpected ports)
ss -tulnp

# New SSH keys
find /home -name "authorized_keys" -exec cat {} \;
find /root -name "authorized_keys" -exec cat {} \;
```

If nothing anomalous found → classify as **Blocked, No Impact**. Move to reporting.

---

## Step 5 — Confirmed Breach Protocol

Only reach this step if Step 2 confirmed a successful login.

**Immediately:**
1. Note the exact time of successful authentication
2. Check what the attacker did after login:

```bash
# Shell history for the compromised account
cat /home/<USERNAME>/.bash_history
cat /root/.bash_history

# All commands run in the session window
last -F | grep <SOURCE_IP>
journalctl _COMM=sshd --since="<BREACH_TIME>" --until="<DETECTION_TIME>"

# Files created or modified during the session
find / -newer /tmp/reference_time -type f 2>/dev/null
# (set reference_time to a file timestamped just before the breach)
```

3. Determine: was anything exfiltrated, modified, or installed?
4. Document timeline: first attempt → successful login → detection → containment
5. Move immediately to playbook.md — Incident Path

---

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

*NCryptoEdge Detection Asset — D-001 Investigation Guide | Last updated: 2026-06-01*
