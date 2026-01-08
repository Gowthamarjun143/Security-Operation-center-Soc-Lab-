# Attack 4: Account Enumeration (Invalid User Discovery)

---

## Attack Objective

To identify valid or invalid user accounts by attempting authentication with non-existent usernames and analyzing system responses and log artifacts on Windows and Linux systems.

---

## Environment

### Attacker / SOC Platform
- Kali Linux (Bare Metal)
- Splunk Enterprise (Indexer + Search Head)

### Victim Systems
- Windows VM with RDP enabled and Splunk Universal Forwarder
- Ubuntu VM with OpenSSH and Splunk Universal Forwarder

---

## MITRE ATT&CK Mapping

| Tactic            | Technique ID | Technique Name                     |
|-------------------|--------------|-----------------------------------|
| Credential Access | T1087        | Account Discovery                 |
| Credential Access | T1110.003    | Password Guessing (Enumeration)   |
| Initial Access    | T1078        | Valid Accounts (Preparation)      |

---

## Attack Execution

### Windows (RDP – Invalid Username)

The attacker attempted to authenticate via RDP using a **non-existent username** (`admin_test`) from Kali using FreeRDP.

#### Command Used

    xfreerdp3 /u:admin_test /v:10.178.180.234

The authentication failed, but Windows processed the username and attempted credential validation, exposing enumeration indicators.

### Ubuntu (SSH – Invalid Username)

The attacker attempted to authenticate via SSH using an invalid user (invaliduser) from Kali.

#### Command Used

    ssh invaliduser@10.178.180.79

Multiple authentication attempts were made, resulting in SSH rejecting the user during the pre-authentication phase.

--- 

## Logs Generated
### Windows – Raw Log Output

    EventCode=4625
    Logon Type: 3
    Account Name: admin_test
    Source Network Address: 10.178.180.19
    Workstation Name: kali
    Failure Reason: Unknown user name or bad password
    Sub Status: 0xC0000064

    EventCode=4776
    Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
    Logon Account: admin_test
    Source Workstation: kali
    Error Code: 0xC0000064

#### Windows – Log Explanation

- Event ID: 4625 – Failed logon attempt
- Logon Type: 3 (Network logon – RDP)
- Target Account: admin_test (non-existent user)
- Failure Substatus: 0xC0000064 (User does not exist)
- Source IP Address: 10.178.180.19 (Kali attacker)
- Event ID: 4776 – Credential validation failure via NTLM
- Error Code: 0xC0000064 (Invalid username)

These events confirm that Windows attempted to validate a non-existent username, clearly indicating account enumeration activity.

--- 

### Ubuntu – Raw Log Output

    2025-12-24T15:11:06.543550+05:30 lucifer-VirtualBox sshd[4178]:
    Connection from 10.178.180.19 port 40488 on 10.178.180.79 port 22

    2025-12-24T15:11:06.657213+05:30 lucifer-VirtualBox sshd[4178]:
    Invalid user invaliduser from 10.178.180.19 port 40488

    2025-12-24T15:11:09.116328+05:30 lucifer-VirtualBox sshd[4178]:
    Failed none for invalid user invaliduser from 10.178.180.19 port 40488 ssh2

    2025-12-24T15:11:10.183079+05:30 lucifer-VirtualBox sshd[4178]:
    Failed password for invalid user invaliduser from 10.178.180.19 port 40488 ssh2

    2025-12-24T15:11:10.778125+05:30 lucifer-VirtualBox sshd[4178]:
    Connection closed by invalid user invaliduser 10.178.180.19 port 40488 [preauth]

#### Ubuntu – Log Explanation

- Log File: /var/log/auth.log
- Service: sshd
- Attempted User: invaliduser (non-existent account)
- Source IP Address: 10.178.180.19
- Stage: Pre-authentication
- Result: User rejected before authentication

These logs clearly indicate SSH-based account enumeration by testing invalid usernames.

--- 

## Detection Logic (Splunk SPL)
### Windows – Account Enumeration Detection

    index=windows_index sourcetype="WinEventLog:Security"
    (EventCode=4625 OR EventCode=4776)
    | where Sub_Status="0xC0000064" OR Error_Code="0xC0000064"
    | stats count by Account_Name, Source_Network_Address, host

### Ubuntu – SSH Invalid User Detection

    index=ubuntu_index sourcetype=linux_secure "Invalid user"
    | stats count by user, src_ip, host

--- 

## Alert Logic (SOC Use Case)

### Trigger Conditions:

- Multiple authentication attempts with non-existent usernames
- Same source IP within a short time window (≤ 5 minutes)
- Presence of explicit enumeration indicators (Invalid user, 0xC0000064)
- Alert Classification:
- Account Enumeration / Reconnaissance
- Escalate if followed by brute-force or credential-stuffing attempts

--- 

### Severity Assessment

| Metric             | Value  |
| ------------------ | ------ |
| Severity           | Medium |
| Attack Complexity  | Low    |
| Impact Potential   | Medium |
| Privilege Required | None   |

--- 

## Detection Confidence

Very High

### Reason:

- Explicit invalid-user indicators
- Clear protocol-level responses
- Low false-positive rate for Invalid user and 0xC0000064 patterns

--- 

## Analysis

- Account enumeration focuses on discovering valid usernames rather than guessing passwords.
- Windows NTLM responses expose enumeration via specific failure substatus codes.
- Ubuntu SSH logs explicitly log invalid usernames during pre-authentication.
- Enumeration significantly lowers attacker effort for subsequent brute-force or credential-stuffing attacks.
- The activity originated externally from Kali, increasing overall risk.

--- 

## SOC Conclusion

This simulation successfully demonstrates account enumeration techniques against both Windows and Linux systems. The logs provide clear indicators that attackers can leverage to discover valid users. Early detection enables SOC teams to block reconnaissance activity before credential-based attacks escalate.

--- 

## Mitigation & Response

- Configure Windows policies to reduce detailed authentication error responses.
- Disable NTLM where possible and enforce Kerberos authentication.
- Implement Fail2Ban or SSH rate limiting on Linux systems.
- Monitor repeated invalid-user attempts from single source IPs.
- Block offending IP addresses at firewall or perimeter security controls.
- Configure Splunk alerts specifically for enumeration thresholds.








