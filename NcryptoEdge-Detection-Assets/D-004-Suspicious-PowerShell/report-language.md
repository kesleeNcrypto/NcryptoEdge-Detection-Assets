# D-004 — Suspicious PowerShell Report Language

## Detection summary
A detection alert identified suspicious PowerShell execution on a Windows host.
This includes encoded commands or inline downloader patterns that are commonly
used by attackers.

## Impact statement
At this stage, the activity is under investigation. Suspicious PowerShell
execution is a common attack vector and requires validation to determine whether
it was legitimate or malicious.

## Recommended actions
- Investigate the PowerShell command and execution context
- Restrict PowerShell use to approved administrative workflows
- Enable enhanced PowerShell logging and monitoring
- Review the host for related malicious activity

## Client wording — standard version
> Our security monitoring detected suspicious PowerShell execution on a server.
> We are investigating to determine whether this was legitimate administration
> or an attempted attack.

## Client wording — incident version
> We identified suspicious attacker-style PowerShell activity on a server.
> The host is being isolated and investigated for potential compromise.
