# Azuki Series Pt.1 
## Port of Entry  Threat Hunt Report: Unauthorized Access and Data Exfiltration (Case: Azuki-SL)  

**Date:** March 28, 2026 

**Investigator:** Jacob Vasquez 

**Subject:** Detection and Analysis of Multi-Stage Compromise on Endpoint azuki-sl  

---
## Scenario
A competitor undercut a 6-year shipping contract by exactly 3%.  Supplier contracts and pricing data appeared on underground forums.  

### Company 
Azuki Import/Export trading Co. - 23 employees, shipping logistics Japan/SE Asia  

## Executive Summary
On November 19, 2025, a sophisticated multi-stage attack was detected targeting the endpoint azuki-sl. The adversary gained initial access via a successful brute-force attack on a legitimate user account, followed by defense evasion, credential theft, and data exfiltration. The attack culminated in lateral movement to secondary internal assets. This report details the chronological events, the KQL queries used for discovery, and the recommended response actions.  

---

## Platforms and Languages Leveraged
- **Platforms:** Windows 10 Pro, Azure Log Analytics, Azure VM, Microsoft Defender for Endpoint (MDE), MITRE ATT&CK
- **Languages & Tools:** PowerShell, Kusto Query Language (KQL), Regular Expressions (Regex) specifically used within KQL, and basic scripting utilities.     

## **High-Level Indicators of Compromise (IoCs) Discovery Plan**
The following Microsoft Defender for Endpoint (MDE) log table types were utilized to identify specific IoCs:

### **DeviceLogonEvents**
This table was used to isolate remote interactive sessions and identify the initial point of entry.
* **IoCs Found:**
    * **Successful External Logon:** Account `kenji.sato`
    * **Attacker Source IP:** `88.97.178.12`
    * **Brute Force Origin IP:** `115.247.157.74` (associated with a series of failed `administrator` logon attempts)

### **DeviceProcessEvents**
[cite_start]This table was extensively used to track malicious commands, reconnaissance, and persistence mechanisms.
* **IoCs Found:**
    * **Network Reconnaissance:** Use of `ARP.EXE -a` to enumerate local network devices.
    * **Defense Evasion (Hidden Staging):** Use of `attrib.exe +h +s` on the directory `C:\ProgramData\WindowsCache`.
    * **Ingress Tool Transfer:** Use of `certutil.exe -urlcache` to download malicious executables from `http://78.141.196.6:8080`.
    * **Persistence (Scheduled Tasks):** Creation of a task named "Windows Update Check" to run `C:\ProgramData\WindowsCache\svchost.exe`.
    * **Credential Dumping:** Execution of a renamed Mimikatz binary (`mm.exe`) using the module `sekurlsa::logonpasswords`.
    * **Anti-Forensics:** Use of `wevtutil.exe cl Security` to clear the Security event logs.
    * *Persistence (Backdoor Account):** Use of `net.exe` to create a local administrator account named `support`.
    * *Lateral Movement:** Use of `cmdkey.exe` and `mstsc.exe` to target internal IP `10.1.0.188` using `fileadmin` credentials.

### **DeviceRegistryEvents**
This table was used to identify modifications to system security settings.
* **IoCs Found:**
    * **Impair Defenses (Exclusions):** Addition of three unique file extensions (`.exe`, `.ps1`, `.bat`) to Windows Defender exclusions.
    * **Impair Defenses (Path Exclusion):** Exclusion of the path `C:\Users\KENJI~1.SAT\AppData\Local\Temp` from Windows Defender scanning.

### **DeviceNetworkEvents**
This table was used to identify Command and Control (C2) communication and data exfiltration.
* **IoCs Found:**
    * **C2 Communication:** Outbound connections from the malicious `svchost.exe` process to the public IP `78.141.196.6` via port `443`.
    * **Exfiltration Channel:** Use of `curl.exe` to upload a staged archive (`export-data.zip`) to a Discord webhook.

### **DeviceFileEvents**
This table was used to identify the creation of malicious scripts and tools in temporary or staging directories.
* **IoCs Found:**
    * **Malicious Executable Creation:** Creation of `mm.exe` (confirmed as Mimikatz) in `C:\ProgramData\WindowsCache`.
    * **Malicious Script Execution:** Download and creation of a PowerShell script `wupdate.ps1` from the external IP `78.141.196.6`.
