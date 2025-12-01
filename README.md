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
