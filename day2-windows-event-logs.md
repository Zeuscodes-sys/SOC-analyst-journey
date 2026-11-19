## Investigation: failed logons (Event ID 4625)

I queried the Security log for failed logons and examined one event.

Findings:
- Logon Type 2 (interactive), so a local attempt
- No source IP, so no remote source
- Sub Status 0xC000006A: correct username, wrong password
- Caller process: msedgewebview2.exe (legitimate Microsoft component)

Conclusion: benign. A mistyped password in a local sign-in prompt.
Not a brute-force attack, which would show Logon Type 3/10 and a
source IP.
I also found out these from my mentor, Logon type 2 means that its from the local keyboard
a logon type 3 means that it is over the network
a logon type 10 means that its from a remote desktop

What I'd escalate: many failures in a short time from a remote IP,
or an unexpected process as the caller.
