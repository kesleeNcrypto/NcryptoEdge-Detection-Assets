# D-003 — Account Lockout Report Language

## Detection summary
An account lockout was detected on a Windows system. Account lockouts are often
triggered by repeated incorrect password attempts and can indicate a credential
attack.

## Impact statement
At this time, no confirmed account takeover has been observed. The event is a
strong signal that authentication attempts are being made against user
credentials.

## Recommended actions
- Review the lockout source and block any malicious IPs or devices
- Verify the affected account was not locked out by legitimate user activity
- Confirm account lockout policies are tuned to balance security and usability
- Monitor for additional lockouts or suspicious login attempts

## Client wording — standard version
> Our detection system observed a Windows account lockout on [DATE]. This may
> have been caused by repeated incorrect login attempts. We are reviewing the
> source and confirm no unauthorized access has been established.

## Client wording — incident version
> A Windows user account was locked out due to repeated authentication failures
> from an unknown source. We are treating this as a potential credential attack
> and are investigating for any follow-on compromise.
