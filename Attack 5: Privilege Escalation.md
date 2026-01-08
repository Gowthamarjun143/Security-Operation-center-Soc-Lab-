# Attack 5: Privilege Escalation (Local User to Administrator / Root)

---

## Attack Objective

To escalate privileges from a low-privileged user account to an administrator or root context by abusing legitimate privilege assignment mechanisms on Windows and Linux systems.

---

## Environment

### Attacker Platform
- Kali Linux

### Victim Systems
- Windows VM (RDP enabled, Splunk Universal Forwarder installed)
- Ubuntu VM (OpenSSH + sudo enabled, Splunk Universal Forwarder installed)

---

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                      |
|---------------------|--------------|----------------------------------------------------|
| Privilege Escalation| T1078        | Valid Accounts                                     |
| Privilege Escalation| T1548.003    | Abuse Elevation Control Mechanism: Sudo            |
| Execution           | T1059        | Command and Scripting Interpreter                  |

---

## Attack Execution

### Windows – Privilege Escalation via `runas`

The attacker logged in as a **low-privileged user** (`lowuser`) via RDP and escalated privileges locally to an **administrative user** (`Gowtham`) using the Windows `runas` mechanism. This resulted in execution of an elevated `cmd.exe` process.

#### Command Used
 
    xfreerdp3 /u:lowuser /p:password@123 /v:10.178.180.234

Privilege escalation occurred after successful authentication, entirely within the target system.

### Ubuntu – Privilege Escalation via sudo

The attacker logged in as a standard user (lucy) via SSH and escalated privileges to root by spawning a root shell using sudo.

#### Commands Used

    ssh lucy@10.178.180.79
    sudo /bin/bash

## Logs Generated
### Windows – Raw Log Output

    Event ID 4624 – Successful Logon
    EventCode=4624
    Logon Type: 2
    Account Name: lowuser
    Elevated Token: No
    Source Network Address: ::1
    Linked Logon ID: 0x637BE1

    Event ID 4672 – Special Privileges Assigned
    EventCode=4672
    Account Name: Gowtham
    Privileges:
    SeSecurityPrivilege
    SeTakeOwnershipPrivilege
    SeLoadDriverPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeDebugPrivilege
    SeSystemEnvironmentPrivilege
    SeImpersonatePrivilege
    SeDelegateSessionUserImpersonatePrivilege

    Event ID 4688 – Process Creation (Elevated)
    EventCode=4688
    New Process Name: C:\Windows\System32\cmd.exe
    Creator Process Name: C:\Windows\System32\runas.exe
    Token Elevation Type: %%1938
    Mandatory Label: S-1-16-8192

### Ubuntu – Raw Log Output
    2025-12-25T11:33:20.912649+05:30 lucifer-VirtualBox sudo:
    lucy : TTY=pts/0 ; PWD=/home/lucy ; USER=root ; COMMAND=/bin/bash

    2025-12-25T11:33:20.914699+05:30 lucifer-VirtualBox sudo:
    pam_unix(sudo:session): session opened for user root(uid=0) by lucy(uid=1002)

## Log Explanation
### Windows

- Event ID 4624
 - Confirms successful interactive logon (Logon Type 2)
 - User lowuser logged in with no elevated token
- Event ID 4672
 - Indicates assignment of high-risk administrative privileges
 - Strong indicator of privilege escalation
- Event ID 4688
 - Confirms execution of an elevated process
 - cmd.exe spawned via runas.exe
 - Correlation of 4624 → 4672 → 4688 clearly confirms successful privilege escalation.

### Ubuntu

- Log File: /var/log/auth.log
- Service: sudo
- User: lucy (UID 1002)
- Action: sudo /bin/bash
- Result: Root shell spawned (UID 0)

These logs confirm:

- Successful sudo authentication
- Root session creation
- Privilege escalation from normal user to root

## Detection Logic (Splunk SPL)
### Windows – Privilege Escalation Detection

    index=windows_index sourcetype="WinEventLog:Security"
    (EventCode=4672 OR EventCode=4688)
    | stats count by Account_Name, New_Process_Name, Creator_Process_Name, host

### Ubuntu – Sudo Privilege Escalation Detection

    index=ubuntu_index sourcetype=linux_secure "session opened for user root"
    | stats count by user, host, src_ip

## Alert Logic (SOC Use Case)
### Trigger Conditions

- Assignment of special privileges (Event ID 4672)
- Elevated process creation (Event ID 4688)
- Root session creation via sudo
- Privilege escalation shortly after user authentication

### Alert Classification
- Privilege Escalation / Post-Exploitation Activity

### Escalation Criteria
- Privilege escalation from non-admin users
- Root shell execution
- Privilege escalation followed by lateral movement or persistence

## Severity Assessment

| Metric               | Value  |
| -------------------- | ------ |
| Severity             | High   |
| Attack Complexity    | Medium |
| Impact Potential     | High   |
| Privilege Required   | Low    |
| Detection Confidence | High   |

## Analysis

- Privilege escalation represents a critical post-compromise phase.
- Windows escalation is clearly visible through privilege assignment and elevated process creation
- Linux sudo activity is explicitly logged and auditable
- Although legitimate mechanisms were used, the behavior is high-risk
- Attackers commonly exploit: 
  - Excessive Windows group memberships
  - Misconfigured sudoers rules

## SOC Conclusion

This simulation demonstrates successful privilege escalation on both Windows and Ubuntu systems. The generated logs provide high-confidence indicators that can be reliably detected using SIEM correlation. Detecting privilege escalation early is critical, as it often precedes lateral movement, persistence, and data exfiltration.

## Mitigation & Response
### Windows

- Enforce least-privilege access models
- Monitor and alert on Event IDs 4672 and 4688
- Restrict usage of runas
- Enforce strict UAC policies

### Ubuntu

- Audit sudoers file regularly
- Restrict password-based sudo
- Enable detailed sudo command logging
- Alert on interactive root shell creation
























