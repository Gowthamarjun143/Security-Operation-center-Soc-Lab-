# Attack 06: Suspicious Process Execution (Process Masquerading)

---

## Attack Objective

To execute attacker-controlled binaries disguised as legitimate system processes on Linux and Windows systems and observe how suspicious process execution is logged and detected through audit and security telemetry.

---

## Environment

### Attacker Machine
- Kali Linux (Bare Metal)
- Role: Attack execution & Splunk Enterprise

### Victim Machines
- Ubuntu 24.04.3 LTS (Splunk Universal Forwarder)
- Windows 10 (Build 19044)
  - Advanced Auditing enabled
  - Splunk Universal Forwarder installed

---

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                              |
|----------------------|--------------|---------------------------------------------|
| Defense Evasion      | T1036        | Masquerading                                |
| Execution            | T1059        | Command and Scripting Interpreter           |
| Privilege Escalation | T1548.003    | Abuse Elevation Control Mechanism: Sudo     |

---

## Attack Execution

### Ubuntu – Masqueraded Binary Execution

The attacker accessed the Ubuntu system via SSH and escalated privileges using sudo.  
A legitimate system binary (`/bin/bash`) was copied to a deceptive filename (`/tmp/systemd-update`) to impersonate a system process and executed manually under root context.

#### Commands Executed

    ssh lucy@10.178.180.79
    sudo /bin/bash
    cp /bin/bash /tmp/systemd-update

Cron and audit logs captured the execution of the masqueraded binary under elevated privileges.

### Windows – Masqueraded Process Execution

Advanced auditing for process creation and command-line logging was enabled.
A legitimate binary (cmd.exe) was copied to a deceptive filename (svchost-update.exe) in a public directory and executed manually.

#### Commands Executed

    auditpol /set /subcategory:"Process Creation" /success:enable
    reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit ^
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    copy C:\Windows\System32\cmd.exe C:\Users\Public\svchost-update.exe
    C:\Users\Public\svchost-update.exe

Windows Security Event ID 4688 recorded the suspicious process execution.

## Logs Generated
### Ubuntu – Raw Logs

    2025-12-25T18:15:01.963694+05:30 lucifer-VirtualBox CRON[4961]:
    pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)

    type=SYSCALL msg=audit(1766666701.961:400):
    arch=c000003e syscall=1 success=yes exit=1
    ppid=744 pid=4961 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0
    comm="cron" exe="/usr/sbin/cron" subj=unconfined

    2025-12-25T18:11:49.130170+05:30 lucifer-VirtualBox sudo:
    lucy : TTY=pts/0 ; PWD=/home/lucy ; USER=root ; COMMAND=/bin/bash

### Windows – Raw Logs
    EventCode=4688
    LogName=Security
    ComputerName=DESKTOP-HFGS62A
    Account Name: Gowtham
    Creator Process Name: C:\Windows\System32\cmd.exe
    New Process Name: C:\Users\Public\svchost-update.exe
    Process Command Line: C:\Users\Public\svchost-update.exe
    Token Elevation Type: %%1937
    Mandatory Label: S-1-16-12288 
    Keywords: Audit Success
    Time: 2025-12-25T20:54:42.711+05:30

## Log Explanation
### Ubuntu

- Log Files: /var/log/auth.log, /var/log/audit/audit.log
- User Context: root (uid=0)
- Execution Path: /tmp/systemd-update
- Observed Behavior:
   - Root shell spawned via sudo
   - Execution of renamed binary from /tmp
   - Audit syscall activity confirms process execution

Execution of binaries from /tmp under root context strongly indicates suspicious or malicious activity.

### Windows
- Event ID: 4688
- Log Source: WinEventLog:Security
- Process Name: svchost-update.exe
- Execution Path: C:\Users\Public\
- Creator Process: cmd.exe
- Token Elevation: Elevated

This event confirms execution of a masqueraded binary using a deceptive system-like name from a non-standard directory.

## Detection Logic (Splunk SPL)
### Ubuntu – Suspicious Binary Execution

    index=linux_index sourcetype=linux_audit OR sourcetype=linux_secure
    | search exe="/tmp/*" OR exe="/usr/bin/*"
    | stats count by host, user, exe, comm

### Windows – Masqueraded Process Detection

    index=windows_index EventCode=4688
    | search New_Process_Name="*svchost*" AND NOT New_Process_Name="*System32*"
    | table _time Account_Name New_Process_Name Creator_Process_Name Process_Command_Line

## Alert Logic (SOC Use Case)
### Trigger Conditions
- Execution of binaries from non-standard directories
- Process names mimicking system binaries
- Elevated token execution outside trusted paths
- Command-line execution enabled with suspicious filenames
### Alert Classification
- Suspicious Process Execution / Masquerading
### Escalation Criteria
- Execution under elevated privileges
- Repeated executions from public or world-writable paths
- Correlation with prior privilege escalation events

## Severity Assessment

| Metric               | Value  |
| -------------------- | ------ |
| Severity             | High   |
| Attack Complexity    | Medium |
| Impact Potential     | High   |
| Privilege Required   | Medium |
| Detection Confidence | High   |

## Analysis

Both Linux and Windows systems exhibited process masquerading, a common post-exploitation technique.

Key indicators include:
- Execution from non-standard directories
- Legitimate binaries renamed to impersonate system processes
- Elevated privilege context during execution
- Absence of trusted or signed execution paths
- These behaviors align with MITRE ATT&CK T1036 (Masquerading) and T1059 (Command Execution).

## SOC Conclusion

Attack 06 successfully demonstrated suspicious process execution on both Linux and Windows platforms.
Audit logs and Windows Security logs provided clear visibility into masqueraded binary execution with elevated privileges. Proper SIEM correlation enables high-confidence detection of this post-exploitation behavior.

## Mitigation & Response

- Enforce application allowlisting (AppArmor, Windows Defender Application Control)
- Monitor execution from /tmp, public, and world-writable directories
- Alert on system-like process names outside trusted paths
- Enable full command-line logging and auditd rules
- Isolate affected endpoints immediately upon detection
- Perform hash-based IOC validation and memory inspection
chmod +x /tmp/systemd-update
/tmp/systemd-update
