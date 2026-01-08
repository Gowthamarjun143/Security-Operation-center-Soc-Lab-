# Attack 03: Compromised Account (Valid Credential Abuse)

---

## Attack Objective

To simulate the use of valid credentials by an attacker to gain unauthorized access to systems and observe post-authentication activity, including session creation, privilege usage, and command execution across Linux and Windows environments.

---

## Environment

### Attacker / SOC Platform
- Kali Linux (Bare Metal)
- Splunk Enterprise (Indexer + Search Head)

### Victim Systems
- Ubuntu VM with OpenSSH and Splunk Universal Forwarder
- Windows VM with RDP enabled and Splunk Universal Forwarder

---

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                         |
|---------------------|--------------|---------------------------------------|
| Initial Access      | T1078        | Valid Accounts                        |
| Credential Access   | T1078.004    | Valid Accounts: Cloud/Local Accounts  |
| Lateral Movement    | T1021.001    | Remote Services: RDP                  |
| Lateral Movement    | T1021.004    | Remote Services: SSH                  |
| Privilege Escalation| T1068        | Exploitation for Privilege Escalation |
| Execution           | T1059        | Command and Scripting Interpreter     |

---

## Attack Execution

### Ubuntu (SSH – Valid Credentials)

An SSH login was performed from the Kali attacker machine using **valid credentials** for the user `lucifer`.

#### Command Used

    ssh lucifer@10.178.180.79

The authentication succeeded, establishing an interactive shell session on the Ubuntu system.

### Windows (RDP – Valid Credentials)

A Remote Desktop session was initiated from Kali using valid credentials for the user gowtham via FreeRDP.

#### Command Used

    xfreerdp3 /u:gowtham /p:Deena@123 /v:10.178.180.234

The authentication succeeded, resulting in remote desktop access, privilege usage, and process creation on the Windows host.

--- 

## Logs Generated
### Ubuntu – Raw Log Output

    2025-12-24T14:29:55.845797+05:30 lucifer-VirtualBox sshd[3737]:
    Connection from 10.178.180.19 port 33960 on 10.178.180.79 port 22

    2025-12-24T14:29:58.197710+05:30 lucifer-VirtualBox sshd[3737]:
    Accepted password for lucifer from 10.178.180.19 port 33960 ssh2

    2025-12-24T14:29:58.200150+05:30 lucifer-VirtualBox sshd[3737]:
    pam_unix(sshd:session): session opened for user lucifer(uid=1000)

    2025-12-24T14:30:01.148302+05:30 lucifer-VirtualBox CRON[3792]:
    pam_unix(cron:session): session opened for user root(uid=0)

    2025-12-24T14:30:01.160131+05:30 lucifer-VirtualBox CRON[3792]:
    pam_unix(cron:session): session closed for user root

### Ubuntu – Log Explanation

- Log Files: /var/log/auth.log, /var/log/syslog
- Services: sshd, cron
- User Logged In: lucifer
- Source IP Address: 10.178.180.19 (Kali attacker)
- Authentication Result: Successful SSH login
- Post-Login Activity: Root-level cron session execution

These logs confirm successful remote authentication using valid credentials, followed by system-level activity, indicating potential account compromise.

--- 

### Windows – Raw Log Output

    EventCode=4624   (Successful Logon)
    EventCode=4672   (Special Privileges Assigned)
    EventCode=4673   (Sensitive Privilege Use)
EventCode=4688   (New Process Created)

Multiple privilege usage and process creation events were recorded shortly after successful authentication.

### Windows – Log Explanation

- Event ID 4624: Successful logon
- Event ID 4672: Special privileges assigned to new logon
- Event ID 4673: Privileged service usage detected
- Event ID 4688: New processes spawned
- Log Source: WinEventLog:Security
- Access Method: RDP
- Source System: Kali attacker

These events indicate that a valid user account logged in remotely and executed privileged operations, consistent with compromised account behavior.

--- 

## Detection Logic (Splunk SPL)
### Ubuntu – Successful SSH Login Detection

    index=ubuntu_index sourcetype=linux_secure "Accepted password"
    | stats count by user, src_ip, host

## Windows – Privileged Login and Activity Detection

    index=windows_index sourcetype="WinEventLog:Security"
    (EventCode=4624 OR EventCode=4672 OR EventCode=4673 OR EventCode=4688)
    | stats count by Account_Name, EventCode, host

--- 

## Alert Logic (SOC Use Case)

### Trigger Conditions:
- Successful authentication from an external or unusual source IP
- Followed by privileged events (4672 / 4673) or process creation (4688)
- Occurring within a short time window (≤ 10 minutes)

### Alert Classification:
- Compromised Account / Valid Credential Abuse
- Escalate if root-level or administrator-level actions are detected

--- 

## Severity Assessment

| Metric             | Value             |
| ------------------ | ----------------- |
| Severity           | High              |
| Attack Complexity  | Low               |
| Impact Potential   | Very High         |
| Privilege Required | Valid Credentials |

--- 

## Detection Confidence

High

### Reason:

- Authentication succeeded using valid credentials
- External source access
- Immediate privileged and system-level activity
- Strong behavioral indicators beyond simple login success

--- 

## Analysis

- Unlike brute-force attacks, this activity involved successful authentication, making it more dangerous.
- SSH logs confirm valid credentials were used from an external source.
- Immediate cron execution and root-level activity increase suspicion.
- On Windows, privilege assignment and sensitive operations followed the successful logon.
- Such behavior strongly indicates stolen, reused, or compromised credentials.

--- 

## SOC Conclusion

This simulation demonstrates how compromised accounts manifest in logs through successful authentication followed by privileged actions. Although credentials were valid, contextual indicators such as source IP, timing, and post-login behavior enable SOC analysts to detect anomalous activity consistent with account compromise.

--- 

## Mitigation & Response

- Enforce multi-factor authentication (MFA) for all remote access.
- Monitor logins from unusual IP addresses, devices, or locations.
- Implement strict least-privilege access controls.
- Rotate and invalidate compromised credentials immediately.
- Review and restrict cron jobs and scheduled task usage.
- Enable behavioral analytics and UEBA capabilities in Splunk.




































































