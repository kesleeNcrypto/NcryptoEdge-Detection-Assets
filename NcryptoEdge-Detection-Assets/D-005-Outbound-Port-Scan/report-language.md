# D-005 — Outbound Port Scan Report Language

## Detection summary
An outbound port scan was detected from a monitored host. This activity can be
part of internal reconnaissance or a sign of an attacker probing the network.

## Impact statement
If the scan is authorised, it represents planned discovery activity. If it is
unauthorised, it may indicate compromised infrastructure or misuse of the host.

## Recommended actions
- Confirm whether the scan was authorised by the security or IT team
- Restrict outbound scanning to approved systems and schedules
- Investigate the host if the scan is unexpected
- Tune detection rules to reduce noise from known scanning tools

## Client wording — authorised scan
> A host in your environment generated network discovery traffic. We are
> verifying whether this scan was part of an approved assessment or a security
> tool.

## Client wording — suspicious scan
> We detected outbound port scanning activity from a server. We are treating
> this as suspicious and investigating the source to determine whether the
> host has been compromised or is being misused.
