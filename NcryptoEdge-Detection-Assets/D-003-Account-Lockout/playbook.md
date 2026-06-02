# P-003 — Account Lockout: Response Playbook

**Playbook ID:** P-003
**Linked Detection:** D-003 — Account Lockout
**Technique:** T1110.001
**Trigger:** D-003 alert fires and lockout appears suspicious or part of credential attack activity
**Author:** Esla Kwanza — NCryptoEdge

---

## Phase 1 — Validate and contain

### Confirm lockout source
- Identify the source device or IP
- Confirm whether the lockout originated from a legitimate domain controller or workstation

### Mitigate if malicious
- Block attacker source in network or endpoint firewall
- Disable remote access from the offending source
- If the lockout is generating repeated alerts, escalate to a broader containment action

---

## Phase 2 — Protect impacted accounts

### Reset or verify credentials
- Confirm the locked account is not under active use for critical services
- Force password reset if the account is user-facing
- Verify service accounts are using valid credentials and are not expired

### Review account lockout policy
- Confirm lockout threshold and duration are appropriate
- Ensure account lockout does not create a denial of service for legitimate users

---

## Phase 3 — Investigate for compromise

If the lockout is part of a broader threat:
- Review failed logon events for patterns across targets
- Check for successful logons from the same source
- Search for account usage from unusual locations or devices

---

## Phase 4 — Recover

### If no compromise found
- Document the event and findings
- Continue monitoring the impacted account and source
- Communicate findings to the appropriate team

### If compromise found
- Isolate affected systems
- Reset credentials for impacted accounts
- Review and remove any unauthorized account changes
- Consider a password expiration policy review across the environment

---

## Phase 5 — Hardening

Recommended improvements:
- Enforce strong account lockout policies with balanced thresholds
- Monitor account lockouts as a credential attack signal
- Limit interactive logon rights for service and administrative accounts
- Use MFA to reduce the impact of credential abuse
