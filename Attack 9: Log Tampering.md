#  Attack 09: Log Tampering (Defense Evasion)

---

## Attack Objective

To evade detection and hinder forensic investigation by deleting or manipulating system and security logs after attacker activity.

---

## Environment

### Attacker Machine
- Kali Linux (Bare Metal)
- Tools: OpenSSH, Impacket (wmiexec)
- Splunk Enterprise

### Victim Machines
- Ubuntu 24.04.3 LTS
  - Splunk Universal Forwarder installed
- Windows 10
  - Advanced Auditing enabled
  - Splunk Universal Forwarder installed

---

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                     |
|----------------------|--------------|-----------------------------------|
| Defense Evasion      | T1070.002    | Clear Linux Logs                  |
| Defense Evasion      | T1070.001    | Clear Windows Event Logs          |

---

## Attack Execution

### Ubuntu – Log Tampering via Truncate

Attacker accessed Ubuntu via previously established SSH persistence and truncated the authentication log. Rsyslog was restarted to resume logging and obscure evidence.

#### Commands Executed

    ssh -i kali_persist_key lucifer@10.242.253.79
    sudo truncate -s 0 /var/log/auth.log
    sudo systemctl restart rsyslog

### Windows – Log Tampering via Wevtutil

Attacker authenticated remotely using administrative credentials and cleared Security and System logs with native Windows utilities.

#### Commands Executed
    impacket-wmiexec Gowtham:7774@10.242.253.234
    wevtutil cl Security
    wevtutil cl System

--- 

## Raw Logs
### Ubuntu – Raw Logs
    type=USER_CMD msg=audit(1767183111.412:367):
    cmd=7472756E63617465202D732030202F7661722F6C6F672F617574682E6C6F67
    exe="/usr/bin/sudo" res=success
    UID="lucifer" AUID="lucifer"

    type=SERVICE_STOP msg=audit(1767183125.229:376):
    unit=rsyslog comm="systemd" res=success
    UID="root"

    2025-12-31T17:42:05.226419+05:30 lucifer-VirtualBox rsyslogd:
    exiting on signal 15

    2025-12-31T17:42:05.225324+05:30 lucifer-VirtualBox systemd[1]:
    Stopping rsyslog.service - System Logging Service...

    2025-12-31T17:42:05.562552+05:30 lucifer-VirtualBox systemd[1]:
    Started rsyslog.service - System Logging Service.

    type=SERVICE_START msg=audit(1767183125.562:378):
    unit=rsyslog comm="systemd" res=success
    UID="root"
    sudo:  lucifer : USER=root ; COMMAND=/usr/bin/systemctl restart rsyslog

### Windows – Raw Logs
    EventCode=1102
    LogName=Security
    Message=The audit log was cleared.
    Account Name: Gowtham

    EventCode=104
    LogName=System
    Message=The System log file was cleared.

    EventCode=4688
    New Process Name: C:\Windows\System32\wevtutil.exe
    Process Command Line: wevtutil cl System
    Creator Process Name: C:\Windows\System32\cmd.exe

--- 

## Log Explanation
### Ubuntu

- Log Files: /var/log/audit/audit.log, /var/log/auth.log, /var/log/syslog
- Key Observations:
  - USER_CMD confirms execution of truncate -s 0 /var/log/auth.log
  - Hex-decoded command verifies log truncation
  - SERVICE_STOP and SERVICE_START confirm rsyslog restart
- Conclusion: Logs show intentional deletion of authentication records and restarting of logging services to conceal attacker activity.

### Windows

- Event ID 1102: Security log cleared (high-severity audit success)
- Event ID 104: System log cleared
- Event ID 4688: wevtutil.exe executed from cmd.exe with arguments confirming log clearing
- Conclusion: Logs confirm tampering using native Windows utilities with administrative privileges, erasing audit trails.

--- 

## Splunk Detection Queries
### Ubuntu
    index=linux_index sourcetype=linux_audit
    | search ("truncate" OR "SERVICE_STOP" OR "SERVICE_START")
    | table _time host uid cmd res

### Windows
    index=windows_index EventCode IN (1102,104)
    | table _time host Account_Name EventCode Message

--- 

## Alert Logic (SOC Use Case)
### Trigger Conditions
- Detection of truncate commands targeting system or auth logs
- Rsyslog or audit service stop/start events
- Windows Event IDs 1102 or 104 indicating log clearing
- Elevated privilege execution context
### Alert Classification
- Defense Evasion / Log Tampering
### Escalation Criteria
- Multiple hosts affected
- Repeated log clearing within short timeframes
- Occurrence immediately following sensitive activity (e.g., privilege escalation, lateral movement)

--- 

## Severity Assessment

| Metric               | Value              |
| -------------------- | ------------------ |
| Severity             | High               |
| Attack Complexity    | Medium             |
| Impact Potential     | High               |
| Privilege Required   | Root/Administrator |
| Detection Confidence | High               |

--- 

## Analysis

- Post-exploitation log tampering to evade detection
- Both Linux and Windows attackers leveraged native tools (truncate, systemctl, wevtutil)
- Actions performed under administrative privileges
- Evidence captured despite tampering, allowing forensic reconstruction
- MITRE ATT&CK Techniques:
  - T1070.002 – Clear Linux Logs
  - T1070.001 – Clear Windows Event Logs

--- 

## SOC Conclusion

Attack 09 successfully demonstrates log tampering on both Ubuntu and Windows systems.
Audit and system-level logs still provide actionable evidence despite attempts to erase traces, allowing SOC teams to detect defense-evasion techniques and reconstruct attack sequences.

---

## Mitigation & Response

- Forward logs in real time to a remote SIEM (e.g., Splunk)
- Enable immutable or append-only logging (WORM storage)
- Monitor for truncate, wevtutil, and logging service restart commands
- Alert on Event IDs 1102 (Security log cleared) and 104 (System log cleared)
- Restrict sudo and administrative privileges to trusted users
- Implement host-based intrusion detection with auditd rules












