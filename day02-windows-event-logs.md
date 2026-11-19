# Day 2: Windows Event Logs (4625 and 4624)

Date: Nov 19, 2026

## Goal
Learn to read Windows Security logs and tell normal activity from suspicious activity.

## Tools used
Windows Event Log, PowerShell (run as Administrator)

## Command 1: failed logons (Event ID 4625)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10
```
- `Get-WinEvent` reads Windows event logs.
- `-FilterHashtable @{...}` filters by the conditions inside.
- `LogName='Security'` picks the Security log, which records logins.
- `Id=4625` picks failed logons only.
- `-MaxEvents 10` returns at most 10 results.

![4625 results](screenshots/day02/day02-4625-error.png)
I first mistyped the log name (`Securtiy`) and PowerShell returned an error saying no such log exists. I fixed the spelling and it returned 10 failed-logon events.

## Command 2: full detail of one event

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 4 | Format-List TimeCreated, Message
```
- `|` (pipe) sends the results into the next command.
- `Format-List TimeCreated, Message` prints each event as a list with the full message, instead of a cut-off table.

![4625 detail](screenshots/day02/day02-4625-detail.png)

### Investigation of a 4625 event

| Field | Value | Meaning |
|---|---|---|
| Logon Type | 2 | Interactive, at the keyboard |
| Source Network Address | - | No remote source |
| Sub Status | 0xC000006A | Correct username, wrong password |
| Caller Process | msedgewebview2.exe | Legitimate Microsoft component |

**Conclusion:** benign. A mistyped password in a local sign-in prompt, not a brute-force attack.

**What I would escalate:** many failures in a short time from a remote IP (Logon Type 3 or 10), or an unexpected process as the caller.

## Command 3: successful logons (Event ID 4624)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 5 | Format-List TimeCreated, Message
```
Same as above, but `Id=4624` picks successful logons.

![4624 type 5](screenshots/day02/day02-4624-type5.png)

### Investigation of a 4624 event

| Field | Value | Meaning |
|---|---|---|
| Logon Type | 5 | Service logon, a background service starting |
| Account | SYSTEM (NT AUTHORITY) | Built-in Windows account |
| Process | C:\Windows\System32\services.exe | Correct location |
| Source Network Address | - | Local only |

**Conclusion:** benign. Windows starting a background service.

**It would be suspicious if:** services.exe ran from a user folder, a normal user account showed up with this logon type, or a remote IP appeared.

## Logon types I learned
- 2: interactive (keyboard)
- 3: network
- 5: service
- 7: unlock
- 10: remote desktop (RDP)

## What I learned
- 4625 is a failed logon and 4624 is a successful one. Read together, they tell the story.
- The key pattern: many 4625s followed by a 4624 from the same IP can mean a brute force succeeded.
- Logon Type, source address and the process matter more than the event ID alone.
- Knowing what normal looks like (type 5, SYSTEM, services.exe) makes abnormal easier to spot.

## What confused me
- At first I was confused about how to differentiate logon types but after a few research, I was able to decipher it accurately

## Why this matters in a SOC
Analysts use these events to confirm brute-force attempts, find compromised accounts, and separate real threats from false positives.

