# Day 1: Wireshark Setup and First Capture

Date: 19th November 2026

## What I did
I installed Wireshark, Npcap and Nmap on my laptop.
I started a capture, then ran an Nmap scan and looked at the packets.

## Setup problems and how I fixed them

**Problem:** I tried to install Nmap from the command line using
winget (the Windows package manager, a tool that installs programs
from the terminal), but winget was not installed on my laptop.

**What I did:** I installed winget manually, then used it to
install Nmap.

**Command I used:**
`winget install Insecure.Nmap`
This tells winget to download and install Nmap.

**How I checked it worked:**
`nmap --version`
This prints the Nmap version, which proves it installed.

**What I learned:**
Tools can fail
to install, and checking with a version command confirms it worked.


## What I saw
- DNS packets: my laptop looking up website names.
- SYN packets: Nmap knocking on many ports.
- RST packets: closed ports saying "no".

## Filters I used
- `tcp.flags.syn == 1 && tcp.flags.ack == 0`
  Shows only SYN packets, the first step of a connection. Lots of these from one machine means a port scan.
- `tcp.flags.reset == 1`
  Shows RST packets. These come back from closed ports.
- `dns`
  Shows DNS lookups only.





## Why this matters in a SOC
A SOC analyst can use Wireshark to check whether a port scan alert is real by looking for many SYN packets from one source.
