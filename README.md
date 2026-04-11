# Azuki Series Pt.1 - Port of Entry   
  <img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/2cde9ee0-e8f2-454d-a08e-42a5e6b9346a" />


## Threat Hunt Report: Unauthorized Access and Data Exfiltration (Case: Azuki-SL)  

**Date:** March 28, 2026 

**Investigator:** Jacob Vasquez 

**Subject:** Detection and Analysis of Multi-Stage Compromise on Endpoint azuki-sl  

---
## Scenario
A competitor undercut a 6-year shipping contract by exactly 3%.  Supplier contracts and pricing data appeared on underground forums.  

### Company  
Azuki Import/Export trading Co. - 23 employees, shipping logistics Japan/SE Asia  

## Executive Summary 
On November 19, 2025, a sophisticated multi-stage attack was detected targeting the endpoint `azuki-sl`. The adversary gained initial access via a successful brute-force attack on a legitimate user account, followed by defense evasion, credential theft, and data exfiltration. The attack culminated in lateral movement to secondary internal assets. This report details the chronological events, the KQL queries used for discovery, and the recommended response actions.  

---

## Platforms and Languages Leveraged 
- **Platforms:** Windows 10 Pro, Azure Log Analytics, Azure VM, Microsoft Defender for Endpoint (MDE), MITRE ATT&CK
- **Languages & Tools:** PowerShell, Kusto Query Language (KQL), Regular Expressions (Regex) specifically used within KQL, and basic scripting utilities.     

## **Indicators of Compromise (IoCs) Discovery Plan** :warning:
The following Microsoft Defender for Endpoint (MDE) log table types were utilized to identify specific IoCs:

### **DeviceLogonEvents**
This table was used to isolate remote interactive sessions and identify the initial point of entry.
* **IoCs Found:**
    * **Successful External Logon:** Account `kenji.sato`
    * **Attacker Source IP:** `88.97.178.12`
    * **Brute Force Origin IP:** `115.247.157.74` (associated with a series of failed `administrator` logon attempts)

### **DeviceProcessEvents**
This table was extensively used to track malicious commands, reconnaissance, and persistence mechanisms.
* **IoCs Found:**
    * **Network Reconnaissance:** Use of `ARP.EXE -a` to enumerate local network devices.
    * **Defense Evasion (Hidden Staging):** Use of `attrib.exe +h +s` on the directory `C:\ProgramData\WindowsCache`.
    * **Ingress Tool Transfer:** Use of `certutil.exe -urlcache` to download malicious executables from `http://78.141.196.6:8080`.
    * **Persistence (Scheduled Tasks):** Creation of a task named "Windows Update Check" to run `C:\ProgramData\WindowsCache\svchost.exe`.
    * **Credential Dumping:** Execution of a renamed Mimikatz binary (`mm.exe`) using the module `sekurlsa::logonpasswords`.
    * **Anti-Forensics:** Use of `wevtutil.exe cl Security` to clear the Security event logs.
    * **Persistence (Backdoor Account):** Use of `net.exe` to create a local administrator account named `support`.
    * **Lateral Movement:** Use of `cmdkey.exe` and `mstsc.exe` to target internal IP `10.1.0.188` using `fileadmin` credentials.

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
---- 


## Investigation & Discovery :chart_with_downwards_trend:
This section details the chronological progression of the intrusion on device azuki-sl, mapped to the MITRE ATT&CK framework.   

### :triangular_flag_on_post: **Phase 1: Initial Access & Reconnaissance**
The attacker established a foothold by targeting administrative accounts via remote services. 

- **Initial Access (RDP Brute Force):** <img width="777" height="181" alt="image" src="https://github.com/user-attachments/assets/e324bd4a-dfe3-4607-a9ea-dc0362c97655" />


  **Attacker Action:** After a high-volume brute-force campaign from `115.247.157.74` against the `administrator` account, a successful logon was achieved by account `kenji.sato` from remote `IP 88.97.178.12`. <img width="740" height="195" alt="image" src="https://github.com/user-attachments/assets/72c12c66-ff5a-40f8-9632-bb8d066ef449" />


- **Network Discovery:** <img width="898" height="156" alt="image" src="https://github.com/user-attachments/assets/15c42a67-3832-4758-929b-8bb209a5799f" />

  **Attacker Action:** The attacker executed `ARP.EXE -a` to enumerate local network devices and hardware addresses to identify potential targets for lateral movement. <img width="807" height="273" alt="image" src="https://github.com/user-attachments/assets/de1c83d1-d3b2-4ca1-8946-259c234b9419" />
---  


### :triangular_flag_on_post: **Phase 2: Execution & Tool Ingress**  
Following successful access, the attacker leveraged native Windows binaries to download a malicious toolkit.  
- **Ingress Tool Transfer (Living off the Land):**<img width="898" height="203" alt="image" src="https://github.com/user-attachments/assets/9c406656-da31-4e27-9958-1cf4ebf7a267" />
 
  **Attacker Action:** Used `certutil.exe` to download two malicious executables, `svchost.exe` and `mm.exe`, from `http://78.141.196.6:8080` into a custom staging directory. <img width="825" height="307" alt="image" src="https://github.com/user-attachments/assets/88135e92-2d0a-4ea8-9522-e4bb789069df" />
---  

### :triangular_flag_on_post: **Phase 3: Persistence & Defense Evasion**
The attacker implemented multiple layers of persistence and disabled security features to maintain long-term access.  
- **Hidden Staging & Directory Creation:** <img width="937" height="175" alt="image" src="https://github.com/user-attachments/assets/fb188d8f-5e6e-42e2-9908-d74d70c64252" />  
  **Attacker Action:** Created `C:\ProgramData\WindowsCache` and used `attrib.exe +h +s` to hide the staging folder from standard user interfaces. <img width="925" height="338" alt="image" src="https://github.com/user-attachments/assets/9fe3e3f7-96a6-49f3-b528-7f1afc53db16" />  
- **Disabling Security Defenses (Defender Exclusions):** <img width="838" height="188" alt="image" src="https://github.com/user-attachments/assets/b8e3aa7d-02b1-48b1-9a5a-654c1dfdbf12" />  
  **Attacker Action:** Modified the registry to add three unique file extensions (`.exe`, `.ps1`, `.bat`) and the specific staging path to Windows Defender's exclusion list. <img width="880" height="163" alt="image" src="https://github.com/user-attachments/assets/f4d40c9e-05f2-440f-9e58-d45108039d3c" />

- **Scheduled Task Persistence:** <img width="857" height="127" alt="image" src="https://github.com/user-attachments/assets/f62602e9-6bf2-461e-bd82-5dce2a39b700" />

  **Attacker Action:** Created a persistent scheduled task named "Windows Update Check" configured to run the malicious `svchost.exe` from the hidden staging directory. <img width="946" height="321" alt="image" src="https://github.com/user-attachments/assets/c74eda5a-b25d-4b50-bc23-24b04697267a" /> <img width="865" height="195" alt="image" src="https://github.com/user-attachments/assets/3bfc1d1f-abbf-4401-b3b2-3f8e9b07d3fd" />
---  

### :triangular_flag_on_post: **Phase 4: Credential Access & Lateral Movement**  
The attacker extracted authentication secrets to pivot toward high-value internal assets.   
- **OS Credential Dumping:** <img width="816" height="95" alt="image" src="https://github.com/user-attachments/assets/d6576ed9-f399-4362-804f-239e6261615d" />  
  **Attacker Action:** Executed the renamed Mimikatz binary (`mm.exe`) using the `sekurlsa::logonpasswords` module to extract plaintext credentials from system memory.
    <img width="895" height="442" alt="image" src="https://github.com/user-attachments/assets/305b02a1-f7e6-4b30-b143-881c198461ff" />  
- **Lateral Movement:**   
  <img width="542" height="123" alt="image" src="https://github.com/user-attachments/assets/a7e7f2b7-2a00-4e48-8858-b8b410229d68" />  
  **Attacker Action:** Leveraged cmdkey.exe to store stolen fileadmin credentials and initiated an RDP session (mstsc.exe) to target internal host 10.1.0.188. <img width="902" height="303" alt="image" src="https://github.com/user-attachments/assets/e87eb025-2018-4915-b2a1-35f358b5a72b" />
  <img width="938" height="342" alt="image" src="https://github.com/user-attachments/assets/44b435c7-2bb1-45a7-9a79-f2e75c49c9e7" />
---

### :triangular_flag_on_post: **Phase 5: Exfiltration & Anti-Forensics**  
In the final phase, the attacker staged collected data, exfiltrated it to a cloud service, and attempted to wipe evidence of the intrusion.
- **Data Staging & Exfiltration:** <img width="881" height="122" alt="image" src="https://github.com/user-attachments/assets/eec21154-345c-4bcf-82a0-85e015bfd13b" />  
  **Attacker Action:** Compressed stolen data into `export-data.zip` and used `curl.exe` to exfiltrate the archive to a Discord webhook over HTTPS. <img width="937" height="196" alt="image" src="https://github.com/user-attachments/assets/acc2821d-ce3d-447a-98ca-04e61fa291d4" />  
- **Backdoor Account Creation:**  
  <img width="583" height="121" alt="image" src="https://github.com/user-attachments/assets/35e17009-8da7-44ed-abe5-9ba98b1ea0ba" />    
  **Attacker Action:** Created a local administrator account named `support` as a secondary backdoor for future access. <img width="860" height="212" alt="image" src="https://github.com/user-attachments/assets/6f077c6a-e621-4f19-93e1-4754b08bf160" />    
- **Anti-Forensics (Log Tampering):** <img width="876" height="198" alt="image" src="https://github.com/user-attachments/assets/e986f85d-5cc1-4727-9b8c-61da304d96d8" />  
  **Attacker Action:** Executed `wevtutil.exe cl Security` to clear the Security event logs and destroy forensic evidence of the intrusion. <img width="936" height="101" alt="image" src="https://github.com/user-attachments/assets/3aa53c78-01a7-443c-b270-f6c3589fe0c4" />

---

# Summary of Findings  :books:

### **Chronological timeline summarizing the activity on `azuki-sl` from initial access to anti-forensic cleanup.**

* **2025-11-19 18:36:18** – **Initial Access:** Successful RDP logon for account `kenji.sato` from external IP `88.97.178.12` following a brute-force campaign.
* **2025-11-19 18:42:05** – **Directory Staging:** The directory `C:\ProgramData\WindowsCache` is created to store malicious tools.
* **2025-11-19 18:44:12** – **Defense Evasion:** Execution of `attrib.exe +h +s` on the staging directory to hide it from the file system.
* **2025-11-19 18:48:30** – **Tool Ingress:** `certutil.exe` is used to download `svchost.exe` and `mm.exe` from `http://78.141.196.6:8080`.
* **2025-11-19 18:52:15** – **Impair Defenses:** Registry modifications add `.exe`, `.ps1`, and `.bat` extensions to Windows Defender exclusions.
* **2025-11-19 18:55:40** – **Reconnaissance:** Execution of `ARP.EXE -a` to enumerate local network devices and map internal hardware addresses.
* **2025-11-19 18:58:10** – **Persistence:** A scheduled task named "Windows Update Check" is created to execute the malicious `svchost.exe` payload.
* **2025-11-19 19:02:22** – **Credential Access:** The renamed Mimikatz binary (`mm.exe`) is executed to dump plaintext passwords from memory.
* **2025-11-19 19:05:45** – **Account Creation:** A local administrator account named `support` is created via `net.exe` for backdoor access.
* **2025-11-19 19:10:37** – **Lateral Movement:** Stolen `fileadmin` credentials are used with `mstsc.exe` to RDP into the internal server `10.1.0.188`.
* **2025-11-19 19:15:20** – **Data Exfiltration:** `curl.exe` is used to upload the archived `export-data.zip` to a Discord webhook.
* **2025-11-19 19:18:55** – **Anti-Forensics:** The Security event log is cleared using `wevtutil.exe cl Security` to destroy the audit trail.
Based on the findings in the **Azuki Series Pt.1** investigation, here is the organized summary of the intrusion mapped to the 5 distinct phases and the corresponding MITRE ATT&CK techniques.
--- 

### **Organized intrusion summary mapped to the 5 distinct phases and the corresponding MITRE ATT&CK techniques.**
###  :collision:**MITRE ATT&CK Mapping**:collision:

| Phase | Tactic | Technique Name | ID | Description of Activity |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Initial Access** | Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | External RDP logon to `kenji.sato` from IP `88.97.178.12`. |
| **1** | **Reconnaissance** | System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | Use of `ARP.EXE -a` to map the internal network. |
| **2** | **Execution** | Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Using `certutil.exe -urlcache` to download `mm.exe` and `svchost.exe`. |
| **3** | **Persistence** | Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Creation of the "Windows Update Check" task for the malicious payload. |
| **3** | **Defense Evasion** | Impair Defenses: Disable or Modify Tools | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Adding `.exe`, `.ps1`, and folder paths to Defender Exclusions. |
| **3** | **Defense Evasion** | Hide Artifacts: Hidden Files and Directories | [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | Using `attrib.exe +h +s` on the `WindowsCache` directory. |
| **4** | **Credential Access** | OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Execution of `mm.exe` (Mimikatz) `sekurlsa::logonpasswords`. |
| **4** | **Lateral Movement** | Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Using `mstsc.exe` to move from `azuki-sl` to internal host `10.1.0.188`. |
| **5** | **Exfiltration** | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Using `curl.exe` to post `export-data.zip` to a Discord Webhook. |
| **5** | **Impact** | Indicator Removal: Clear Windows Event Logs | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Execution of `wevtutil.exe cl Security` to wipe the audit trail. |

---

# Response & Remediation  :ambulance:
### **Recommended Actions: Azuki Series Pt.1**

Based on the vulnerabilities and attacker activities identified, the following recommendations provide a roadmap for immediate remediation, broader eviction, and long-term security hardening.

---

#### **1. Immediate Incident Response & Eviction**

* **Terminate Compromised Sessions and Reset Credentials:**
    * Immediately terminate all active RDP and network sessions for the `kenji.sato` and `fileadmin` accounts.
    * Perform a mandatory password reset for all compromised users and any accounts that may have been cached in memory during the Mimikatz (`mm.exe`) execution.
* **Remove Persistence Mechanisms:**
    * Delete the unauthorized local administrator account named `support`.
    * Deactivate and delete the **"Windows Update Check"** scheduled task and its associated payload located at `C:\ProgramData\WindowsCache\svchost.exe`.
* **Sanitize Host Artifacts:**
    * Delete the hidden staging directory `C:\ProgramData\WindowsCache`.
    * Restore the Windows Defender registry configuration by removing all unauthorized exclusions for the `.exe`, `.ps1`, and `.bat` extensions, as well as the specific folder path exclusions.

---

#### **2. Network and Infrastructure Hardening**

* **Secure Remote Access:**
    * Disable RDP (`mstsc.exe`) access from public IP addresses.
    * Implement a Virtual Private Network (VPN) or a secure gateway (e.g., Azure Bastion) for all remote administrative tasks to prevent external brute-force attempts.
    * Enforce **Multi-Factor Authentication (MFA)** for all remote interactive logons.
* **Implement Network Egress Filtering:**
    * Block outbound traffic to the identified C2 IP address `78.141.196.6` at the perimeter firewall.
    * Restrict or monitor the use of common web services like **Discord** for data transfer in production environments to mitigate exfiltration risks.

---

#### **3. Detection and Monitoring Enhancements**

* **Deploy Living-off-the-Land (LotL) Monitoring:**
    * Create custom detection rules for high-risk uses of `certutil.exe`, `attrib.exe`, and `wevtutil.exe` when used with arguments related to downloading files, hiding directories, or clearing logs.
* **Monitor for Lateral Movement:**
    * Configure alerts for the use of `cmdkey.exe` followed immediately by `mstsc.exe`, especially when targeting high-value internal assets like `10.1.0.188`.
    * Audit for **Event ID 4624 (Successful Logon)** on critical servers to correlate with remote process executions identified on source workstations.










 








