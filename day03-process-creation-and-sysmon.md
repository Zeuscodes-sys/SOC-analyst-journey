# Day 3: Process Creation (4688) and Sysmon

Date: Nov 19, 2026

## Goal
Learn to see which programs start on a Windows machine (Event ID 4688), then install Sysmon for richer logging (process, network, hashes).

## Tools used
Windows Security log, auditpol, PowerShell (Administrator), Sysmon v15.22, SwiftOnSecurity sysmon-config

## Part 1: Event ID 4688 (process creation)

### Turn on process auditing
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```
- `auditpol` manages Windows audit policy.
- `/set /subcategory:"Process Creation"` selects the process-start category.
- `/success:enable` logs every successful process start.

### Check that it is on
```powershell
auditpol /get /subcategory:"Process Creation"
```
- `/get` reads the current setting without changing it.

![auditpol enabled](screenshots/day03/day03-auditpol-enabled_png.png)
The Setting column shows **Success**, so process creation is being logged.

### Read the events
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5 | Format-List TimeCreated, Message
```
- `Get-WinEvent` reads Windows event logs.
- `-FilterHashtable @{LogName='Security'; Id=4688}` selects process-creation events in the Security log.
- `-MaxEvents 5` returns the 5 most recent.
- `| Format-List TimeCreated, Message` prints the time and full details as a list.

![4688 event 1](screenshots/day03/day03-4688-event_png.png)
![4688 event 2](screenshots/day03/day03-4688-event2_png.png)

### Investigation of two 4688 events

| Field | Event 1 (9:55 AM) | Event 2 (9:54 AM) |
|---|---|---|
| New Process | C:\Windows\System32\svchost.exe | C:\Windows\System32\svchost.exe |
| Command line | svchost.exe -k netsvcs -p -s gpsvc | svchost.exe -k Camera -s FrameServer |
| Creator process | services.exe | services.exe |
| Runs as | SYSTEM | LOCAL SERVICE |
| Token elevation | Default (1) | Default (1) |

- `gpsvc` is the Group Policy Client service. `FrameServer` belongs to the Windows Camera service.
- Both started from `System32`, were launched by `services.exe`, and ran under built-in service accounts.

**Conclusion:** benign. These are normal Windows services starting.

**What would make it suspicious:**
- svchost.exe running outside `System32`
- a parent other than services.exe
- Word/Excel/browser spawning cmd.exe or powershell.exe
- PowerShell with `-enc` or `-w hidden`
- programs running from Temp, Downloads or AppData

The **Process Command Line** field is filled in, so I can see exactly how each program was started.

## Part 2: Sysmon

### Install
```powershell
cd "C:\path\to\Sysmon"
```
- `cd` moves into the folder. Quotes are required when the path has a space.

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig-export.xml"
```
- `Invoke-WebRequest` downloads a file from a web address.
- `-Uri` is the file's address, and `-OutFile` is the name it is saved as.

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
- `.\Sysmon64.exe` runs the 64-bit Sysmon in this folder.
- `-accepteula` accepts the license automatically.
- `-i sysmonconfig-export.xml` installs Sysmon as a service using that config.

Output showed "Configuration file validated", "Sysmon64 installed", "SysmonDrv installed" and "Sysmon64 started".

```powershell
Get-Service Sysmon64
```
- Checks the service status. It shows **Running**.

### Read the Sysmon log
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List TimeCreated, Id, Message
```
- `-LogName "Microsoft-Windows-Sysmon/Operational"` reads Sysmon's own log.

![Sysmon Event 3](screenshots/day03/day03-sysmon-event3-discord_png.png)

### Investigation of a Sysmon Event ID 3 (network connection)

| Field | Value | Meaning |
|---|---|---|
| Image | ...\AppData\Local\Discord\app-1.0.9268\Discord.exe | Discord made the connection |
| Protocol | UDP | Connectionless, typical for voice/video |
| Initiated | true | My laptop started it (outbound) |
| Destination port | 443 (https) | Normal encrypted web port |
| Destination IP | 64:ff9b::a29f:88e8 | NAT64 address; the last 32 bits decode to 162.159.136.232 |
| Second event | private 10.x to private 10.x | Stays inside the local network |

**Conclusion:** most likely benign. It is Discord making outbound connections on a normal port. I would still confirm with a lookup of the destination IP and a check of the file's signature, because AppData is a common place for malware to hide.

```powershell
Get-AuthenticodeSignature "$env:LOCALAPPDATA\Discord\app-1.0.9268\Discord.exe" | Select-Object Status, SignerCertificate
```
- `Get-AuthenticodeSignature` checks a file's digital signature.
- `$env:LOCALAPPDATA` is a shortcut to the user's AppData\Local folder.
- `Select-Object Status, SignerCertificate` shows whether it is valid and who signed it.

## Sysmon Event IDs I learned
- 1: process created
- 3: network connection
- 11: file created
- 13: registry value set
- 22: DNS query

## Setup problems and how I fixed them
1. **`cd` failed** ("A positional parameter cannot be found"). Cause: my folder path had a space and no quotes. Fix: wrapped the path in quotes.
2. **`auditpol` failed** ("A required privilege is not held"). Cause: PowerShell was not running as Administrator. Fix: reopened it with Run as administrator.
3. **`auditpol /get` failed** with "The parameter is incorrect". Cause: I typed a space after `/subcategory:`. Fix: removed the space.
4. **Sysmon install failed** ("Failed to open xml configuration"). Cause: sysmonconfig-export.xml was not in the Sysmon folder. Fix: downloaded it with Invoke-WebRequest, checked with `dir`, and reran the install.

## What I learned
- 4688 shows what started and which process launched it. Sysmon adds hashes, network connections and more.
- Normal system processes follow a pattern: right path, right parent, right account. Abnormal is anything that breaks it.
- Most errors came from small things: typos, spaces, missing admin rights, wrong folder.

## What confused me
Most of my errors came from small details, not the concepts:
- A typo in the log name ("Securtiy") made PowerShell say the log didn't exist.
- A space after `/subcategory:` made auditpol return "The parameter is incorrect".
- My folder path had a space, so `cd` failed until I put quotes around it.
- Sysmon wouldn't install until the config file was in the same folder.

I also found the destination IP in the Sysmon network event confusing
at first. It started with `64:ff9b::`, which turned out to be an address
format that carries an IPv4 address inside it.

Lesson: read the error message carefully, then check spelling, spaces,
quotes, admin rights and the current folder before assuming the tool is broken.

## Why this matters in a SOC
Process creation and network events are how analysts trace what an attacker ran and where it connected, for example Word spawning PowerShell.

