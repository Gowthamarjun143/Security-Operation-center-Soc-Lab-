# Attack 1: Failed Authentication Attempts (Credential Validation Failure)

---

## Attack Objective

To simulate failed login attempts using incorrect credentials and analyze how authentication failures are logged, detected, and correlated in a SOC environment using Splunk across Windows and Ubuntu systems.

---

## Environment

### SOC Platform
- Kali Linux (Bare Metal)
- Splunk Enterprise (Indexer + Search Head)

### Endpoints
- Windows VM with Splunk Universal Forwarder
- Ubuntu VM with Splunk Universal Forwarder

---

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                    |
|---------------------|--------------|----------------------------------|
| Credential Access   | T1110        | Brute Force                      |
| Credential Access   | T1110.001    | Password Guessing                |

---

## Attack Execution

### Windows

The attack was performed by:
- Locking the Windows system using **Win + L**
- Attempting to log in multiple times using an incorrect password for the user **Gowtham**

This simulates local interactive authentication failures that may occur during password guessing or brute-force attempts.

---

### Ubuntu

The attack was performed by:
- Powering on the Ubuntu VM
- Entering incorrect passwords multiple times at the GDM login screen for the user **lucifer**

This simulates failed graphical authentication attempts handled by PAM modules.

---

## Logs Generated
### Windows – Raw Log Output
LogName=Security
EventCode=4625
SourceName=Microsoft Windows security auditing.
ComputerName=DESKTOP-HFGS62A
Keywords=Audit Failure
TaskCategory=Logon
Message=An account failed to log on.

Subject:
Security ID: S-1-5-18
Account Name: DESKTOP-HFGS62A$
Account Domain: WORKGROUP

Logon Type: 2

Account For Which Logon Failed:
Account Name: Gowtham

Failure Information:
Failure Reason: Unknown user name or bad password.
Status: 0xC000006D
Sub Status: 0xC000006A

Process Information:
Caller Process Name: C:\Windows\System32\svchost.exe

Network Information:
Source Network Address: 127.0.0.1


---

### Windows – Log Explanation

- **Event ID:** 4625  
- **Log Source:** WinEventLog:Security  
- **Failure Reason:** Unknown user name or bad password  
- **Logon Type:** 2 (Interactive)  
- **Authentication Package:** Negotiate (NTLM)  
- **Source IP Address:** 127.0.0.1  
- **Process Name:** C:\Windows\System32\svchost.exe  
- **Keywords:** Audit Failure  

This event confirms failed interactive authentication attempts on a local Windows system.

---

### Ubuntu – Raw Log Output

2025-12-24T11:56:41.971945+05:30 lucifer-VirtualBox gdm-password]:
pam_unix(gdm-password:auth): authentication failure;
logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost= user=lucifer


---

### Ubuntu – Log Explanation

- **Log File:** /var/log/auth.log  
- **Process:** gdm-password  
- **PAM Module:** pam_unix  
- **User:** lucifer  
- **TTY:** /dev/tty1  
- **Result:** authentication failure  

This log confirms failed graphical login attempts processed through PAM authentication on Ubuntu.

---

## Detection Logic (Splunk SPL)

### Windows – Failed Interactive Logons
        
    index=* sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=2
    | stats count by Account_Name, Failure_Reason, host

### Ubuntu – PAM Authentication Failures

    index=ubuntu_index sourcetype=linux_secure "authentication failure"
    | stats count by user, process, host

## Alert Logic (SOC Use Case)

### Trigger Condition:

- More than 5 failed authentication attempts for the same user within 5 minutes

### Recommended Splunk Alert Type:

- Scheduled search
- Trigger on threshold breach
- Severity escalated if attempts originate from multiple hosts

## Severity Assessment

| Metric                | Value  |
| --------------------- | ------ |
| Severity              | Medium |
| Attack Complexity     | Low    |
| Impact Potential      | Medium |
| Privilege Requirement | None   |

## Detection Confidence

High

### Reason:

- Event ID 4625 (Windows) and PAM authentication failures (Linux) are high-fidelity indicators.
- Low false-positive rate when correlated by frequency and user context.

## Analysis

- Event ID 4625 is the primary Windows indicator for failed authentication attempts.
- Interactive logon failures may indicate user error, password guessing, or early-stage brute-force activity.
- PAM authentication failures on Ubuntu provide equivalent visibility for Linux endpoints.
- Centralized log ingestion into Splunk enables correlation and cross-platform visibility.
- This attack validates authentication monitoring, alerting logic, and SOC detection readiness.

## SOC Conclusion

The simulation successfully demonstrates how failed authentication attempts are detected, analyzed, and correlated in a SOC environment using Splunk. Although the activity originated locally, identical indicators are critical for identifying brute-force attacks, credential abuse, and potential account compromise in enterprise environments.

## Mitigation & Response

- Enforce account lockout policies after multiple failed authentication attempts.
- Configure Splunk alerts for repeated Event ID 4625 and PAM authentication failures.
- Implement strong password policies and multi-factor authentication (MFA).
- Monitor authentication trends to distinguish user error from malicious behavior.
- Conduct periodic reviews of authentication logs to identify anomalies and attack patterns.

