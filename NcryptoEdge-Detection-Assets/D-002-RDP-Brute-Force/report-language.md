# D-002 — RDP Brute Force Report Language

## Detection summary
An alert was triggered for repeated failed RDP login attempts from a single
source IP on a Windows host. This behavior is consistent with brute force
credential guessing against Remote Desktop.

## Impact statement
No confirmed unauthorized access has been observed at this stage. The activity
represents a high-risk scanning attempt and warrants continued monitoring.

## Recommended actions
- Block the attacker IP address at the network or host firewall
- Restrict RDP access to trusted IP addresses only
- Enforce strong authentication, including MFA where possible
- Review any failed login attempts for patterns across other hosts

## Client wording — blocked version
> Our security monitoring detected an automated brute-force attack targeting
> remote desktop access on one of your Windows servers. The source IP was
> blocked and no successful login was observed.

## Client wording — confirmed breach version
> Our monitoring detected repeated RDP login attempts followed by a successful
> authentication attempt from the same source. The affected host was isolated
> and we are investigating the timeline and scope of the access.
