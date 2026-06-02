# NCryptoEdge Detection Assets

**Maintained by:** Esla Kwanza — NCryptoEdge
**Last Updated:** 2026-06-01

---

## What This Repository Is

This is the detection engineering asset library for NCryptoEdge Security Operations.

Every asset in this library is production-ready and built to the NCryptoEdge Detection Standard. Each asset covers a specific threat and ships with four files that take it from raw alert to client report.

This library serves two purposes simultaneously:
1. **Operational** — deployed across NCryptoEdge client environments for active monitoring
2. **Portfolio** — evidence of detection engineering depth and methodology

---

## The NCryptoEdge Detection Standard

Every asset in this library contains:

| File | Purpose |
|------|---------|
| `rule.yml` | Sigma detection rule with Wazuh equivalent |
| `guide.md` | Step-by-step investigation and triage process |
| `playbook.md` | Containment and response actions (two paths: blocked vs breach) |
| `report-language.md` | Plain-English client report templates |

---

## Detection Asset Library

| ID | Threat | MITRE Technique | Log Source | Status |
|----|--------|----------------|------------|--------|
| [D-001](./D-001-SSH-Brute-Force/) | SSH Brute Force | T1110.001 | Linux auth / Wazuh | ✅ Production |
| [D-002](./D-002-RDP-Brute-Force/) | RDP Brute Force | T1110.001 | Windows Security / Wazuh | ✅ Production |
| [D-003](./D-003-Account-Lockout/) | Account Lockout — Credential Attack | T1110.001 | Windows Security / Wazuh | ✅ Production |
| [D-004](./D-004-Suspicious-PowerShell/) | Suspicious PowerShell Execution | T1059.001 | Sysmon / Windows / Wazuh | ✅ Production |
| [D-005](./D-005-Outbound-Port-Scan/) | Outbound Port Scan | T1046 | Suricata / Wazuh | ✅ Production |

---

## How These Assets Are Used

### During Monitoring
Detection rules (rule.yml) are deployed in Wazuh on client endpoints and servers.
Alerts that fire are triaged using the corresponding investigation guide (guide.md).

### During Incidents
The response playbook (playbook.md) guides containment and recovery.
All playbooks include two paths: blocked/no breach, and confirmed breach.

### In Client Reports
The report-language.md file provides pre-written, plain-English paragraphs for monthly security reports and incident reports. No technical jargon reaches the client.

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Asset |
|--------|-----------|-------|
| Credential Access | T1110.001 Brute Force: Password Guessing | D-001, D-002, D-003 |
| Execution | T1059.001 PowerShell | D-004 |
| Discovery | T1046 Network Service Scanning | D-005 |

---

## Related Repositories

| Repository | Description |
|-----------|-------------|
| [Full-Detection-Pipeline-Lab](https://github.com/kesleeNcrypto/Full-Detection-Pipeline-Lab) | Cross-layer detection pipeline: Suricata, Sysmon, Wazuh, Splunk, TheHive |
| [Blue-Team-Detection-Lab](https://github.com/kesleeNcrypto/Blue-Team-Detection-Lab) | SOC lab: threat detection, alert correlation, incident response |
| [Zero-Trust-NGO-Security-Architecture](https://github.com/kesleeNcrypto/Zero-Trust-NGO-Security-Architecture) | Zero Trust architecture design for NGO environments |

---

## About NCryptoEdge

NCryptoEdge is building Africa's leading SME-focused Security Operations service —
delivering enterprise-grade detection and response to hotels, clinics, schools, and
NGOs that face real threats without enterprise budgets.

*This repository is not a collection of projects. It is the operating system behind NCryptoEdge.*

---

*NCryptoEdge Detection Assets | github.com/kesleeNcrypto/NCryptoEdge-Detection-Assets*
