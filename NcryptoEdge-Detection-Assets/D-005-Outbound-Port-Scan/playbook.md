# P-005 — Outbound Port Scan: Response Playbook

**Playbook ID:** P-005
**Linked Detection:** D-005 — Outbound Port Scan
**Technique:** T1046
**Trigger:** D-005 alert fires and outbound scanning activity is confirmed or suspicious
**Author:** Esla Kwanza — NCryptoEdge

---

## Phase 1 — Contain the source

### If the scan is malicious
- Restrict outbound network access for the host
- Apply firewall rules to block scanning traffic
- Temporarily quarantine the host from sensitive networks

### If the scan is unknown
- Verify whether the host is authorised to perform network discovery
- Engage the asset owner or security team for confirmation

---

## Phase 2 — Investigate the host

Capture:
- Source host identity and ownership
- Running processes during the scan
- Local user accounts or scheduled jobs that may have launched the scan

```bash
# Example commands on the host
ps -eo pid,user,cmd | grep -i scan
netstat -tulpen
```

---

## Phase 3 — Determine remediation

### Legitimate scanning
- Document the scanning activity as authorised
- Tune detection rules to reduce alerts from approved tools
- Ensure scanning occurs on a controlled schedule

### Malicious scanning
- Remove the host from production networks
- Conduct a deeper compromise assessment
- Review the host for persistence or unauthorized tooling

---

## Phase 4 — Recover and harden

Recommended actions:
- Limit outbound scanning to approved assets only
- Block high-risk scanning at the perimeter
- Review host security controls and monitoring
- Ensure proper change control for network discovery tools
