# Threat-Huntung-Scenario-Port-Of-Entry

Azuki Import/Export Trading Co., a small logistics firm operating across Japan and Southeast Asia, recently discovered that confidential supplier contracts and pricing data were leaked and later found circulating on underground forums. The timing coincided with a competitor undercutting their six-year shipping agreement by precisely 3%, strongly suggesting targeted corporate espionage rather than opportunistic data theft. Initial investigation indicates that the breach originated from **AZUKI-SL**, the company’s IT administrator workstation, pointing to a high-value compromise with privileged access likely used to exfiltrate sensitive contract information. The situation demands immediate threat hunting to determine attacker entry point, persistence mechanisms, and the scope of potential insider activity or external intrusion.

## Environment & Data Sources
- **Host:** `azuki-sl` (Windows endpoint)
- **Telemetry:** Microsoft Defender For Endpoint:
  - `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`
- **Timeframe:** 2025-11-19 → 2025-11-20 (UTC)

---

### Flag 1 - INITIAL ACCESS - Remote Access Source

**Objective :**  
Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**Flag Value :**  
`88.97.178.12`

**KQL Query :**
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, ActionType, RemoteDeviceName, RemoteIP
| order by Timestamp asc
```

<img width="1207" height="187" alt="Flag 1" src="https://github.com/user-attachments/assets/fba952d8-7e50-4214-bca1-089467b218b6" />

---

### Flag 2 - INITIAL ACCESS - Compromised User Account

**Objective :**  
Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

**Flag Value :**  
`kenji.sato`

**KQL Query :**
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, ActionType, RemoteDeviceName, RemoteIP
| order by Timestamp asc
```

<img width="650" height="200" alt="Flag 2" src="https://github.com/user-attachments/assets/59a9c03b-a5b8-4d53-8924-2b75c530e6d5" />

---

### Flag 3: DISCOVERY - Network Reconnaissance

**Objective :**  
Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

**Flag Value :**  
`"ARP.EXE" -a`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("arp", "ipconfig", "nbtstat")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath, AccountName
| order by Timestamp asc 
```

<img width="1197" height="127" alt="Flag 3" src="https://github.com/user-attachments/assets/672df639-a24b-4d50-a6ec-296e0c4eaf11" />

---

### Flag 4: DEFENCE EVASION - Malware Staging Directory

**Objective :**  
Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**Flag Value :**  
`C:\ProgramData\WindowsCache`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "attrib"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="660" height="190" alt="Flag 4" src="https://github.com/user-attachments/assets/b3bb6d77-5afc-4edb-a967-b16b4faa3914" />

---

### Flag 5: DEFENCE EVASION - File Extension Exclusions

**Objective :**  
Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

**Flag Value :**  
`3`

**KQL Query :**
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_any ("\\Exclusions\\Extensions")
| project Timestamp, DeviceName, ActionType, RegistryValueName, RegistryKey
| order by Timestamp asc 
```

<img width="1481" height="173" alt="Flag 5" src="https://github.com/user-attachments/assets/d99cc4d8-f7d1-49eb-a3e0-441d577832fd" />

---

### Flag 6: DEFENCE EVASION - Temporary Folder Exclusion

**Objective :**  
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**Flag Value :**  
`C:\Users\KENJI~1.SAT\AppData\Local\Temp`

**KQL Query :**
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_any ("Paths")
| project Timestamp, DeviceName, ActionType, RegistryValueName, RegistryKey, InitiatingProcessFolderPath
| order by Timestamp asc
```

<img width="720" height="220" alt="Flag 6" src="https://github.com/user-attachments/assets/fb1f194a-595d-4f21-8306-c81fb5b491b6" />

---

### Flag 7: DEFENCE EVASION - Download Utility Abuse

**Objective :**  
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**Flag Value :**  
`certutil.exe`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("appinstaller.exe", "bitsadmin.exe", "certoc.exe", "certreq.exe", "certutil.exe", "cmd.exe")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1377" height="92" alt="Flag 7" src="https://github.com/user-attachments/assets/34b51065-1cfa-41e3-9bde-781468f98051" />

---

### Flag 8: PERSISTENCE - Scheduled Task Name

**Objective :**  
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Flag Value :**  
`Windows Update Check`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("schtasks")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc 
```

<img width="1278" height="136" alt="Flag 8" src="https://github.com/user-attachments/assets/6f1a2e11-bf7f-4cda-a4fd-c5dace672a29" />

---

### Flag 9: PERSISTENCE - Scheduled Task Target

**Objective :**  
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Flag Value :**  
`C:\ProgramData\WindowsCache\svchost.exe`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("schtasks")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1247" height="243" alt="Flag 9" src="https://github.com/user-attachments/assets/83cecf0e-bd68-43c4-a2b5-f29a3fb7c6f1" />

---

### Flag 10: COMMAND & CONTROL - C2 Server Address

**Objective :**  
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**Flag Value :**  
`78.141.196.6`

**KQL Query :**
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by Timestamp asc 
```

<img width="650" height="190" alt="Flag 10" src="https://github.com/user-attachments/assets/047d4dc6-c1c5-464f-88f0-2bdad377abc7" />

---

### Flag 11: COMMAND & CONTROL - C2 Communication Port

**Objective :**  
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**Flag Value :**  
`2025-11-19T19:10:37.2912992Z`

**KQL Query :**
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

<img width="1317" height="92" alt="Flag 11" src="https://github.com/user-attachments/assets/0652014c-42c4-4bf3-827d-133466fc1c60" />

---

### Flag 12: CREDENTIAL ACCESS - Credential Theft Tool

**Objective :**  
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**Flag Value :**  
`mm.exe`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".exe")
| where ProcessVersionInfoProductName has_any ("Mimikatz", "LaZagne", "lsassy", "nanodump", "ProcDump")
| project Timestamp, DeviceName, FileName, ProcessVersionInfoProductName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="820" height="190" alt="Flag 12" src="https://github.com/user-attachments/assets/f67f27ab-d79b-4ab4-887d-46615978bd63" />

---

### Flag 13: CREDENTIAL ACCESS - Memory Extraction Module

**Objective :**  
Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

**Flag Value :**  
`sekurlsa::logonpasswords`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".exe")
| where ProcessVersionInfoProductName has_any ("Mimikatz", "LaZagne", "lsassy", "nanodump", "ProcDump")
| project Timestamp, DeviceName, FileName, ProcessVersionInfoProductName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="820" height="190" alt="Flag 13" src="https://github.com/user-attachments/assets/0a9e01b6-c5c7-4951-88b5-d0d76f2d8ae9" />

---

### Flag 14: COLLECTION - Data Staging Archive

**Objective :**  
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**Flag Value :**  
`export-data.zip`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".zip")
| project Timestamp, DeviceName, FileName, ProcessVersionInfoProductName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="820" height="190" alt="Flag 14" src="https://github.com/user-attachments/assets/fc3718b6-8440-4c97-8558-69095ea8802b" />

---

### Flag 15: EXFILTRATION - Exfiltration Channel

**Objective :**  
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**Flag Value :**  
`discord`

**KQL Query :**
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessAccountName == "kenji.sato"
| where RemotePort == "443"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

<img width="1368" height="132" alt="image" src="https://github.com/user-attachments/assets/44ebc1bf-10ec-4d37-9dcc-4881e86ee900" />

---

### Flag 16: ANTI-FORENSICS - Log Tampering

**Objective :**  
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**Flag Value :**  
`Security`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine
| order by Timestamp asc 
```

<img width="950" height="150" alt="Flag 16" src="https://github.com/user-attachments/assets/22001f03-dbfc-4be7-9e4c-c0bdfcc35820" />

---

### Flag 17: IMPACT - Persistence Account

**Objective :**  
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**Flag Value :**  
`support`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("add")
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine
| order by Timestamp asc 
```

<img width="1242" height="221" alt="Flag 17" src="https://github.com/user-attachments/assets/35f3a6c6-073b-49d8-9fbd-9e4ee54bbd5b" />

---

### Flag 18: EXECUTION - Malicious Script

**Objective :**  
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**Flag Value :**  
`wupdate.ps1`

**KQL Query :**
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath has_any ("temp", "Temp")
| where FileName !startswith "__PSScriptPolicyTest"
| where FileName has_any (".ps1")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp asc  
```

<img width="980" height="260" alt="image" src="https://github.com/user-attachments/assets/1c205549-2aaf-472b-9e13-e57de1aba089" />

---

### Flag 19: LATERAL MOVEMENT - Secondary Target

**Objective :**  
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**Flag Value :**  
`10.1.0.188`

**KQL Query :**
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc 
```

<img width="700" height="130" alt="Flag 19" src="https://github.com/user-attachments/assets/cf46f30a-2f31-4291-9a41-ced4687182f9" />

---

### LATERAL MOVEMENT - Remote Access Tool

**Objective :**  
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

**Flag Value :**  
`mstsc.exe`

**KQL Query :**
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc 
```

<img width="700" height="130" alt="Flag 20" src="https://github.com/user-attachments/assets/ae741527-1481-4793-b551-ec38c7368ef4" />

---
