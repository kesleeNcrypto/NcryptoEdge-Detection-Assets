# P-001 — SSH Brute Force: Response Playbook

**Playbook ID:** P-001  
**Linked Detection:** D-001 — SSH Brute Force  
**Technique:** T1110.001  
**Trigger:** D-001 alert fires AND investigation confirms active or successful attack  
**Author:** Esla Kwanza — NCryptoEdge  

---

## Playbook Decision Tree

```
D-001 alert fires
       │
       ▼
Run Investigation Guide (guide.md)
       │
       ├─── No successful login + external IP ──► TRACK (Phase 1 only)
       │
       ├─── Ongoing high-volume + no success ───► CONTAIN (Phase 1 + 2)
       │
       └─── Successful login found ─────────────► FULL RESPONSE (All phases)
```

---

## Phase 1 — Contain the Source

### Block the attacking IP (Linux host)

```bash
# Immediate block with iptables
sudo iptables -I INPUT -s <ATTACKER_IP> -p tcp --dport 22 -j DROP

# Make it persistent (Ubuntu/Debian)
sudo apt install iptables-persistent -y
sudo netfilter-persistent save

# Verify block is in place
sudo iptables -L INPUT -n | grep <ATTACKER_IP>
```

### Block with UFW (if in use)

```bash
sudo ufw deny from <ATTACKER_IP> to any port 22
sudo ufw status
```

### Block with Fail2ban (preferred for automation)

```bash
# Manual ban
sudo fail2ban-client set sshd banip <ATTACKER_IP>

# Verify
sudo fail2ban-client status sshd

# Check ban duration (default 600s — increase for persistent attackers)
# Edit /etc/fail2ban/jail.local:
# [sshd]
# bantime = 86400    # 24 hours
# findtime = 60
# maxretry = 5
```

### Wazuh Active Response (automated)

If Wazuh active response is configured, it will block automatically.
Verify it triggered:

```bash
cat /var/ossec/logs/active-responses.log | grep <ATTACKER_IP>
```

---

## Phase 2 — Protect the Target Account

### Lock the targeted account (if attack is ongoing)

```bash
# Temporarily lock account
sudo passwd -l <USERNAME>

# Verify
sudo passwd -S <USERNAME>    # should show 'L' for locked

# Unlock when safe
sudo passwd -u <USERNAME>
```

### Force password reset on next login

```bash
sudo chage -d 0 <USERNAME>
```

### Disable password authentication for SSH (harden)

```bash
# Edit /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH service
sudo systemctl restart sshd

# Verify
grep "PasswordAuthentication" /etc/ssh/sshd_config
```

> ⚠️ Only disable password auth if key-based auth is already set up and confirmed working. Test in a second terminal before closing your current session.

---

## Phase 3 — Investigate for Compromise (if login succeeded)

Work through this checklist in order:

```bash
# 1. Who is currently logged in?
who
w

# 2. Recent login history
last -20
lastb -10   # failed attempts

# 3. Check for new user accounts
awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd
grep "useradd\|adduser" /var/log/auth.log | tail -20

# 4. Check for new SSH keys (backdoor persistence)
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
  echo "=== $user ===" 
  cat /home/$user/.ssh/authorized_keys 2>/dev/null
done

# 5. Check for cron jobs added
crontab -l
ls -la /etc/cron* /var/spool/cron/

# 6. Check for suspicious processes
ps aux --sort=-pcpu | head -20
netstat -tulnp   # or: ss -tulnp

# 7. Check recently modified files
find / -mtime -1 -type f 2>/dev/null | grep -v "/proc\|/sys\|/run" | head -30

# 8. Check bash history of compromised account
cat /home/<USERNAME>/.bash_history
```

---

## Phase 4 — Recover

### If no compromise confirmed

```bash
# Unblock IP after 24–48 hours (or leave permanent for repeat offenders)
sudo iptables -D INPUT -s <ATTACKER_IP> -p tcp --dport 22 -j DROP

# Document and close case
```

### If compromise confirmed

1. **Isolate the host** — remove from network or apply strict firewall rules
2. **Preserve evidence** — copy logs before any remediation
   ```bash
   cp /var/log/auth.log /tmp/incident-$(date +%Y%m%d)-auth.log
   cp /var/log/syslog /tmp/incident-$(date +%Y%m%d)-syslog.log
   ```
3. **Reset all credentials** on the affected host
4. **Rotate SSH keys** for all users on the host
5. **Rebuild if root was compromised** — do not trust the host; rebuild from clean image
6. **Notify** client contact per agreed communication plan

---

## Phase 5 — Harden (Post-Incident)

Apply these if not already in place:

```bash
# Change SSH to non-standard port (reduces automated scanning noise)
# /etc/ssh/sshd_config → Port 2222

# Restrict SSH to specific IPs
# /etc/ssh/sshd_config → AllowUsers user@trusted_ip

# Enable Fail2ban if not running
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Disable root SSH login
# /etc/ssh/sshd_config → PermitRootLogin no
```

---

## Incident Documentation Checklist

Before closing the case, confirm all fields are recorded:

- [ ] Alert first seen (timestamp)
- [ ] Source IP and reputation score
- [ ] Target host and username(s)
- [ ] Total failure count
- [ ] Successful login: Yes / No
- [ ] Containment action taken (block method used)
- [ ] Compromise indicators found: Yes / No (list if yes)
- [ ] Recovery actions taken
- [ ] Hardening recommendations made
- [ ] Case closed timestamp
- [ ] Client notified: Yes / No

---

## Escalation Contacts

| Scenario | Escalate To |
|---|---|
| Successful login confirmed | Senior analyst / client contact |
| Root compromise | Immediate client notification + host isolation |
| Multiple hosts affected | Incident Commander |
| Ransomware indicators | P-003 Ransomware Playbook |

---

*NCryptoEdge Detection Asset — P-001 | Last updated: 2026-06-01*
