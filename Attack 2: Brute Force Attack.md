# Attack 2: Brute Force Attack (Credential Guessing)

---

## Attack Objective

To simulate a brute-force authentication attack using automated password guessing tools and analyze how repeated failed login attempts are logged, detected, and correlated in Splunk across Linux (SSH) and Windows (RDP/NTLM) systems.

---

## Environment

### Attacker / SOC Platform
- Kali Linux (Bare Metal)
- Splunk Enterprise (Indexer + Search Head)

### Victim Systems
- Ubuntu VM with OpenSSH and Splunk Universal Forwarder
- Windows VM with RDP enabled and Splunk Universal Forwarder

---

## Tools Used

- THC Hydra
- Custom password wordlist (`Brute.txt`)

---

## MITRE ATT&CK Mapping

| Tactic            | Technique ID | Technique Name        |
|-------------------|--------------|----------------------|
| Credential Access | T1110        | Brute Force          |
| Credential Access | T1110.001    | Password Guessing    |
| Lateral Movement  | T1021.001    | Remote Services: RDP |
| Lateral Movement  | T1021.004    | Remote Services: SSH |

---

## Attack Execution

### Ubuntu (SSH)

A brute-force SSH attack was launched from the Kali attacker machine targeting the Ubuntu VM using THC Hydra.

#### Command Used

    hydra -l lucifer -P ~/Documents/Brute.txt ssh://10.164.231.79 -t 4

The attack attempted multiple password combinations in rapid succession against the SSH service.

### Windows (RDP / NTLM)

A brute-force RDP authentication attempt was launched from Kali targeting the Windows VM.

#### Command Used

    hydra -l gowtham -P ~/Documents/Brute.txt rdp://10.178.180.234 -t 4

Although a full RDP session was not established, multiple credential validation attempts were logged on the Windows system.

## Logs Generated
## Ubuntu – Raw Log Output

    2025-12-24T12:11:03.859709+05:30 lucifer-VirtualBox sshd[4169]:
    Failed password for lucifer from 10.164.231.19 port 57208 ssh2

    2025-12-24T12:11:05.531843+05:30 lucifer-VirtualBox sshd[4169]:
    PAM 1 more authentication failure; rhost=10.164.231.19 user=lucifer

    2025-12-24T12:10:57.869375+05:30 lucifer-VirtualBox sshd[4169]: 
    pam_unix(sshd:auth): authentication failure; rhost=10.164.231.19 user=lucifer

    2025-12-24T12:10:57.786048+05:30 lucifer-VirtualBox sshd[4169]:
    Connection from 10.164.231.19 port 57208 on 10.164.231.79 port 22

### Ubuntu – Log Explanation

- Log File: /var/log/auth.log
- Service: sshd
- User Targeted: lucifer
- Source IP Address: 10.164.231.19 (Kali attacker)
- Authentication Method: SSH (password-based)
- Result: Multiple authentication failures

These logs confirm repeated failed SSH login attempts originating from a single external IP address, a strong indicator of brute-force behavior.

## Windows – Raw Log Output

    EventCode=4625
    Logon Type: 3
    Account Name: gowtham
    Failure Reason: Unknown user name or bad password
    Source Network Address: 10.178.180.19
    Authentication Package: NTLM
    Keywords: Audit Failure

    EventCode=4776
    Logon Account: gowtham
    Source Workstation: kali
    Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
    Error Code: 0xC000006A

### Windows – Log Explanation

- Event ID: 4625
- Log Source: WinEventLog:Security
- Logon Type: 3 (Network)
- Failure Reason: Bad password
- Authentication Package: NTLM
- Source IP / Workstation: Kali (external attacker)
- Event ID: 4776
- Task Category: Credential Validation
- Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
- Error Code: 0xC000006A (Invalid credentials)

These events confirm repeated remote credential validation failures typical of brute-force attacks against Windows network services.

## Detection Logic (Splunk SPL)
### Ubuntu – SSH Brute Force Detection

    index=ubuntu_index sourcetype=linux_secure "Failed password"
    | stats count by src_ip, user, host
    | where count > 5

### Windows – Network Brute Force Detection

    index=windows_index sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4776)
    | stats count by Account_Name, Source_Network_Address, EventCode
    | where count > 5

## Alert Logic (SOC Use Case)

### Trigger Conditions:
More than 5 failed authentication attempts
Same user and same source IP
Within a short time window (≤ 5 minutes)

### Alert Classification:

- Credential Access – Brute Force
- Escalate severity if multiple accounts or hosts are targeted

## Severity Assessment

| Metric             | Value |
| ------------------ | ----- |
| Severity           | High  |
| Attack Complexity  | Low   |
| Impact Potential   | High  |
| Privilege Required | None  |

## Detection Confidence

Very High

## Reason:

- High-frequency failures
- Single-source IP
- Consistent user targeting
- Well-known brute-force log patterns on both Linux and Windows

## Analysis

- Multiple failed authentication attempts occurred within seconds from the same source IP.
- On Ubuntu, SSH logs clearly show repeated password failures and PAM authentication errors.
- On Windows, NTLM credential validation failures and network logon failures were recorded.
- The attack pattern matches known brute-force behavior: high frequency, single user, single source.
- Splunk successfully centralized and correlated authentication telemetry across platforms.

## SOC Conclusion

This simulation demonstrates how brute-force attacks are detected through authentication failure patterns in both Linux and Windows environments. Event frequency, source consistency, and failure reasons provide strong indicators for SOC analysts to identify, validate, and escalate brute-force activity effectively.

## Mitigation & Response

- Enforce account lockout policies after repeated authentication failures.
- Implement SSH protection mechanisms such as Fail2Ban.
- Restrict RDP access using firewall rules, IP allowlists, and VPNs.
- Enable multi-factor authentication (MFA) for all remote access services.
- Configure Splunk alerts for excessive failed authentication attempts.
- Monitor, block, and blacklist offending IP addresses at the network level.












