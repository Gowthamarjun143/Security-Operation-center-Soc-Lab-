# Attack 07: Lateral Movement (Credential-Based Remote Access)

---

## Attack Objective

To simulate lateral movement by leveraging valid credentials to access remote systems over network services (SSH on Linux and SMB/WMI on Windows), validating SOC visibility into remote authentication, privilege assignment, and post-access command execution.

---

## Environment

### Attacker Machine
- Kali Linux (Bare Metal)
- Tools: OpenSSH, Impacket (smbclient, wmiexec)
- Splunk Enterprise

### Victim Machines
- Ubuntu 24.04.3 LTS
  - Splunk Universal Forwarder installed
- Windows 10 (Build 19044)
  - Advanced Auditing enabled
  - Splunk Universal Forwarder installed

---

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                                  |
|----------------------|--------------|-----------------------------------------------|
| Lateral Movement     | T1021.004    | Remote Services: SSH                           |
| Lateral Movement     | T1021.002    | Remote Services: SMB/Windows Admin Shares     |
| Lateral Movement     | T1047        | Windows Management Instrumentation (WMI)      |
| Credential Access    | T1078        | Valid Accounts                                 |

---

## Attack Execution

### Ubuntu – Remote SSH Lateral Movement

The attacker initiated an SSH connection from Kali to the Ubuntu host using valid credentials (`lucifer`) and executed a remote command (`uname -a`) to validate lateral access.

#### Command Executed

    ssh lucifer@10.178.180.79 "uname -a"
Observed Behavior:
- Successful remote authentication
- Session creation
- Remote command execution validated lateral access

### Windows – SMB/WMI Lateral Movement

The attacker used valid credentials to access the Windows host via SMB and WMI using Impacket utilities (smbclient, wmiexec).
Post-authentication, a test command created a file to confirm remote execution.

#### Commands Executed
    impacket-smbclient Gowtham:7774@10.178.180.234
    impacket-wmiexec Gowtham:7774@10.178.180.234
    cmd.exe /c echo LATERAL_MOVEMENT_TEST > C:\Windows\Temp\lm_test.txt


Observed Behavior:
- SMB share enumeration
- Remote command execution
- Privileged access confirmed

## Logs Generated
### Ubuntu – Raw Logs
2025-12-30T10:54:34.074555+05:30 lucifer-VirtualBox sshd[5224]: 
Connection from 10.178.180.19 port 47014 on 10.178.180.79 port 22

2025-12-30T10:54:36.451469+05:30 lucifer-VirtualBox sshd[5224]: 
Accepted password for lucifer from 10.178.180.19 port 47014 ssh2

type=USER_AUTH msg=audit(1767072276.421:427): 
exe="/usr/sbin/sshd" acct="lucifer" addr=10.178.180.19 res=success

type=USER_START msg=audit(1767072276.809:431): 
op=PAM:session_open acct="lucifer" exe="/usr/sbin/sshd" res=success

### Windows – Raw Logs
EventCode=4624
Logon Type: 3
Authentication Package: NTLM
Account Name: Gowtham
Source Network Address: 10.178.180.19
Elevated Token: Yes

EventCode=4672
Message: Special privileges assigned to new logon
Privileges: SeDebugPrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege

EventCode=4688
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: cmd.exe /c echo LATERAL_MOVEMENT_TEST
Creator Process Name: C:\Windows\System32\cmd.exe

## Log Explanation
### Ubuntu

- Log Files: /var/log/auth.log, /var/log/audit/audit.log
- User: lucifer
- Service: sshd
- Source IP: 10.178.180.19
- Result: Successful authentication
- Session: Remote SSH
- Confirms lateral movement using valid credentials with successful command execution.

## Windows

- Event ID 4624: Successful network logon (Logon Type 3)
- Event ID 4672: High-risk privileges assigned after logon (SeDebugPrivilege, SeImpersonatePrivilege)
- Event ID 4688: Post-authentication remote command execution
- Confirms credential-based lateral movement and elevated access.

## Detection Logic (Splunk SPL)
### Ubuntu – SSH Lateral Movement
index=linux_index sourcetype=linux_secure OR sourcetype=linux_audit
| search exe="/usr/sbin/sshd" AND res=success
| stats count by host, acct, addr

### Windows – SMB/WMI Lateral Movement
index=windows_index (EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| search Source_Network_Address=10.178.180.19
| table _time EventCode Account_Name Source_Network_Address New_Process_Name

## Alert Logic (SOC Use Case)
### Trigger Conditions

- Network logon (Type 3) from non-admin endpoints
- Immediate assignment of high-risk privileges (Event 4672)
- Remote command execution post-authentication
- Correlation with multiple remote hosts accessed by the same account
### Alert Classification
- Credential-Based Lateral Movement
### Escalation Criteria
- Elevated privileges obtained on remote host
- Multiple remote logons within short time window
- Remote execution of sensitive commands

## Severity Assessment

| Metric               | Value             |
| -------------------- | ----------------- |
| Severity             | High              |
| Attack Complexity    | Medium            |
| Impact Potential     | High              |
| Privilege Required   | Valid credentials |
| Detection Confidence | High              |

## Analysis

- Demonstrates credential-based lateral movement using SSH (Linux) and SMB/WMI (Windows)
- Key indicators:
  - Remote authentication from peer system
  - Network logon (Type 3) with elevated token
  - Post-authentication remote command execution
- Mapped MITRE ATT&CK techniques:
  - T1021.004 – Remote Services: SSH
  - T1021.002 – SMB/Windows Admin Shares
  - T1047 – Windows Management Instrumentation
  - T1078 – Valid Accounts

## SOC Conclusion

Attack 07 successfully validated SOC detection of lateral movement across Linux and Windows systems.
Authentication, privilege escalation, and post-access activity were captured and correlated in Splunk, providing actionable indicators for analyst investigation.

## Mitigation & Response

- Enforce least-privilege access for all users
- Disable NTLM where possible; enforce Kerberos
- Implement MFA for SSH and administrative access
- Monitor Logon Type 3 events correlated with Event 4672
- Restrict WMI and SMB access via network segmentation
- Alert on remote administrative logons from non-admin endpoints


















