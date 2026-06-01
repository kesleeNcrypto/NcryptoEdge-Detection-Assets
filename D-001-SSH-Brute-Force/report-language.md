# D-001 — SSH Brute Force: Client Report Language

**Asset ID:** D-001  
**Use in:** Monthly Security Report (R-001), Incident Report (R-002)  
**Author:** Esla Kwanza — NCryptoEdge  

---

## Monthly Report — "Nothing Bad Happened" Version

Use when the attack was detected and blocked with no successful access:

> **SSH Brute Force Attempt — Blocked**
>
> On [DATE], our monitoring system detected an automated brute-force attack
> against your server's SSH service originating from IP address [X.X.X.X]
> ([COUNTRY]). The attacker made [N] login attempts over [TIMEFRAME] minutes,
> targeting the [USERNAME] account.
>
> The attack was detected and blocked automatically. No successful access was
> gained. Your systems and data were not affected.
>
> **What we did:** The attacking IP was blocked at the firewall level within
> [N] minutes of detection. We confirmed no successful logins occurred before
> or after the attack window.
>
> **What this means for you:** Automated SSH scanning is common on
> internet-facing servers. This detection is normal and expected. Our monitoring
> caught it early. No action is required from your side.
>
> **Recommendation:** [Choose one or more as applicable]
> - Consider restricting SSH access to known IP addresses only
> - Ensure all accounts use strong passwords or key-based authentication
> - We will continue monitoring for repeat attempts from this source

---

## Monthly Report — "High Volume / Ongoing" Version

Use when attack volume was significant or attack persisted:

> **Elevated SSH Brute Force Activity**
>
> Between [START DATE] and [END DATE], we observed sustained brute-force
> activity targeting your SSH service. A total of [N] failed login attempts
> were recorded from [NUMBER] distinct source IPs. No successful access was
> achieved during this period.
>
> **What we did:** Attacking IP addresses were blocked progressively as
> thresholds were exceeded. We reviewed login history to confirm no access
> was granted prior to detection. SSH hardening recommendations have been
> prepared (see Recommendations section).
>
> **Recommendation:** We recommend scheduling a brief call to review SSH
> hardening options including IP allowlisting and key-based authentication
> enforcement.

---

## Incident Report — "Successful Login Found" Version

Use when investigation confirmed a successful login after brute force:

> **Security Incident: Unauthorised SSH Access Following Brute Force**
>
> **Incident Date:** [DATE]  
> **Severity:** High  
> **Status:** [Contained / Under Investigation / Resolved]
>
> **Summary:**
> On [DATE] at [TIME], our monitoring detected a brute-force attack against
> your SSH service. Subsequent investigation confirmed that the attacker
> successfully authenticated to the [USERNAME] account at [TIME] using a
> valid password.
>
> **What happened:**
> An attacker from IP [X.X.X.X] ([COUNTRY/ISP]) made [N] failed login
> attempts before gaining access. Once detected, we [took the following
> actions: isolated the host / locked the account / blocked the IP].
>
> **Impact:**
> The attacker had access to the [USERNAME] account for approximately
> [DURATION]. [Describe any observed activity or state "No destructive
> activity was observed during this window."]
>
> **Actions taken:**
> 1. Source IP blocked at firewall
> 2. Compromised account locked and password reset
> 3. Login history and active sessions reviewed
> 4. [Additional actions if applicable]
>
> **Recommendations:**
> 1. Disable SSH password authentication — require key-based login only
> 2. Restrict SSH access to authorised IP addresses
> 3. Enable multi-factor authentication where possible
> 4. Review all user account activity from the incident window
>
> We will follow up with a full post-incident report within [48 hours /
> agreed SLA].

---

## Executive Risk Summary — One-Liner Versions

For the risk summary table in the monthly report:

| Scenario | Risk Summary Text |
|---|---|
| Blocked, no success | SSH brute force detected and blocked — no impact |
| High volume, blocked | Elevated scanning activity observed — contained, no breach |
| Successful login | **Unauthorised access confirmed — incident response initiated** |

---

## Tone Notes

- Never use technical jargon in client-facing text (no "T1110.001", no "MITRE")
- Lead with outcome, not process ("The attack was blocked" before "Here is what we did")
- Be specific about numbers — clients trust concrete data (N attempts, N minutes)
- Always end with a clear next step or recommendation
- For incidents: be calm, factual, and action-oriented — avoid alarm language

---

*NCryptoEdge Detection Asset — D-001 Report Language | Last updated: 2026-06-01*
