# CyberDefenders: Lockdown Lab — Walkthrough

## Scenario

TechNova Systems' SOC detected suspicious outbound traffic from a public-facing IIS server in its cloud platform — activity suggestive of a web shell drop and covert connections to an unknown host. Three artifacts were provided for investigation:

- A **PCAP** capturing the initial intrusion traffic
- A **full memory image** of the compromised server
- A **malware sample** recovered from disk

**Category:** Network Forensics
**Tactics covered:** Execution, Persistence, Privilege Escalation, Stealth, Discovery, Lateral Movement, Command and Control
**Tools used:** Wireshark, Volatility 3, FLOSS/strings, VirusTotal (Threat Intel)

---

## Phase 1 — PCAP Analysis (Wireshark)

### Q1 — Attacker's IP Address

**Method:** `Statistics → Conversations → IPv4 tab`, sorted by Packets descending.

One conversation stood out with **6,007 packets** (4 MB) — over 100x higher than any other conversation involving the IIS host. Every other row involving the server (`10.0.2.15`) showed normal background traffic volumes (52 packets, 35 packets, etc. — DNS, multicast, routine outbound connections). The lone host responsible for that entire flood, and appearing in *no other* conversation in the capture, was the attacker.

**Answer:** `10.0.2.4`

### Q2 — First/Enumeration Tool (HTTP)

**Method:** Filtered to the attacker's traffic and inspected HTTP request headers for identifying tool signatures.

```
http and ip.src == 10.0.2.4
```
The initial reconnaissance sweep — a rapid-fire TCP SYN scan across dozens of ports (113, 135, 5900, 143, 587, 8080, 445, 3306, 22, 3389, etc.), each immediately met with a `RST, ACK` for closed ports — was consistent with an Nmap-style port scan. The tool's signature carried through into the subsequent HTTP-layer probing against the discovered web service.

**Answer:** `nmap`

### Q3 — SMB Tree Connect Requests

**Method:**
```
smb2.cmd == 3 and ip.addr == 10.0.2.4
```
(SMB2 command code `3` = Tree Connect)

Sorted chronologically, the first two Tree Connect Request/Response pairs showed:
```
Tree Connect Request, Tree: '\\10.0.2.15\IPC$'
Tree Connect Response, Tree: '\\10.0.2.15\IPC$'
Tree Connect Request, Tree: '\\10.0.2.15\Documents'
Tree Connect Response, Tree: '\\10.0.2.15\Documents'
```
`IPC$` is the standard hidden administrative share Windows uses for inter-process communication — commonly the first share probed to confirm SMB is responsive. `Documents` was the actual content share probed next, and turned out to overlap with the IIS web root.

**Answer:** `\\10.0.2.15\Documents`, `\\10.0.2.15\IPC$`

### Q4 — Malicious Uploaded File

**Method:** Having confirmed SMB write access to the `Documents` share, filtered for SMB Create/Write operations from the attacker to locate the planted file.
```
smb2.cmd == 5 and ip.addr == 10.0.2.4    # Create
smb2.cmd == 9 and ip.addr == 10.0.2.4    # Write
```
The `Documents` share was found to be mapped to (or overlapping with) the IIS web root, making any file dropped there web-accessible — explaining how a `.aspx` web shell became remotely executable simply by being written into the share.

**Answer:** `shell.aspx`

### Q5 — Reverse Shell Callback Port

**Method:** Filtered for the server initiating a *new* outbound connection back to the attacker (the defining signature of a reverse shell, versus a bind shell where the attacker connects in):
```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == 10.0.2.15 and ip.dst == 10.0.2.4
```
This isolates the first SYN packet from server → attacker on a fresh session, occurring after the shell upload. The port chosen was not one already seen in normal service traffic and fits the "uncommon but firewall-friendly" description — a port frequently permitted outbound through corporate egress filtering without raising alarms.

**Answer:** `4443`

---

## Phase 2 — Memory Forensics (Volatility 3)

### Setup
```bash
pip install volatility3 --break-system-packages
vol -f memdump.mem windows.info
```
Volatility auto-detects the OS (Windows Server, build 10.0.17763) and auto-downloads the matching kernel symbol table on first run — no manual symbol prep needed for a Windows image.

### Q6 — Kernel Base Address

**Method:** `windows.info` output, top of the field list.

```
Kernel Base     0xf80079213000
```
The `SystemTime` field in the same output (`2024-09-10 06:14:13 UTC`) anchors when this snapshot was taken relative to the PCAP timeline.

**Answer:** `0xf80079213000`

### Q7 — Persistence Executable's Full Path

**Method:** `windows.pstree` — walked the process tree looking for anything spawned outside the normal IIS/System32 stack.

```bash
vol -f memdump.mem windows.pstree > pstree.txt
```
Traced the branch:
```
svchost.exe (PID 2452, -k iissvcs)
  └── w3wp.exe (PID 4332)          — IIS worker process, exited 06:10:48 UTC
        └── updatenow.exe (PID 900) — spawned 06:08:23 UTC, Wow64: True
```
`updatenow.exe`'s **Path** field pointed to the Windows Startup folder — a classic persistence technique that guarantees automatic relaunch on every user logon without needing a scheduled task or registry Run key.

**Answer:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe`

### Q8 — Process Handling the Reverse Shell / Spawning the Implant

**Method:** Same `pstree` branch as Q7 — the parent of the persistence implant.

`w3wp.exe` (PID `4332`) is IIS's legitimate worker process, responsible for executing web requests — including whatever code ran through the uploaded web shell. Its abuse to spawn `updatenow.exe` is what let the attacker's payload masquerade as activity from a fully trusted, built-in Windows/IIS process.

**Answer:** `w3wp.exe`, PID `4332`

---

## Phase 3 — Malware Analysis (updatenow.exe)

### Q9 — Packer Used

**Method:** Static string/PE inspection.
```bash
strings -n 8 updatenow.exe
```
Output was unusually thin — mostly binary fragments and a sparse import table (only a handful of `kernel32.dll` imports like `LoadLibraryA`/`GetProcAddress`, consistent with runtime import resolution after unpacking). PE section headers showed the classic pair `UPX0` (empty placeholder) and `UPX1` (compressed payload), plus the `UPX!` magic marker near the file's end.

Unpacking confirmed it: `602,112` bytes packed → `1,084,928` bytes unpacked (~44% size reduction), matching UPX's typical compression signature.

**Answer:** `UPX`

### Q10 — C2 FQDN

**Method:** The unpacked binary's C2 configuration remained **encrypted** inside its .NET assembly (a known AgentTesla trait — config is never stored as plaintext even post-unpacking). Static string extraction (`strings`, FLOSS) on the unpacked binary returned no usable C2 indicators.

Pivoted to threat intelligence:
1. `sha256sum updatenow.exe` → submitted hash to VirusTotal
2. **Relations tab → Contacted Domains** — surfaced the C2 domain directly, sourced from VT's own sandbox detonation and prior analyst submissions
3. Cross-validated independently against the PCAP's own DNS traffic:
```bash
tshark -r capture.pcapng -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
```
The IIS host's DNS query for the same domain in the capture corroborated the VT finding with direct wire evidence.

**Answer:** `cp8nl.hyperhost.ua`

### Q11 — Malware Family

**Method:** VirusTotal **Community** tab and **Popular threat label** (Details tab) attributed the sample by name, corroborated against independently observed indicators from earlier phases:

| Indicator | Source | Significance |
|---|---|---|
| UPX packing | Q9 | AgentTesla builders near-universally ship UPX-packed samples |
| Sparse import table, runtime-resolved APIs | Static analysis | Consistent with a packed/obfuscated .NET loader |
| WinINET-based HTTP imports | Import table | Matches AgentTesla's HTTP(S) exfiltration method |
| Startup folder persistence | Q7 | AgentTesla's default/common persistence mechanism |
| Spawned from `w3wp.exe` | Q8 | Consistent with a web shell dropping/executing the implant |
| Wow64: True (32-bit on 64-bit OS) | Q7 | Typical of AgentTesla's compiled builds |

AgentTesla is a widely-circulated commodity .NET RAT/infostealer (keylogging, credential theft from browsers/email/FTP/VPN clients, screenshot capture) sold and cracked across underground forums — this combination of packing, persistence method, and beaconing style is a well-documented signature.

**Answer:** `AgentTesla`

---

## Attack Timeline

| Stage | Action | Evidence |
|---|---|---|
| Recon | Nmap scan against IIS host, `10.0.2.4 → 10.0.2.15` | 6,007-packet flood, port scan pattern (SYN → immediate RST,ACK) |
| Enumeration | HTTP-based service enumeration | HTTP requests from `10.0.2.4`, nmap tool signature |
| Discovery | SMB share probing | `\\10.0.2.15\IPC$` then `\\10.0.2.15\Documents` |
| Initial Access | Web shell dropped into `Documents` share (= IIS web root) | `shell.aspx` written via SMB |
| Execution | Reverse shell established | Callback from `10.0.2.15 → 10.0.2.4` on port `4443` |
| Execution/Privilege Escalation | `w3wp.exe` (PID 4332) spawns implant | `updatenow.exe` (PID 900), 06:08:23 UTC |
| Persistence | Implant dropped into Startup folder | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |
| Stealth | Binary packed with UPX | `UPX0`/`UPX1` sections, `UPX!` marker |
| Command and Control | Beaconing to attacker infrastructure | `cp8nl.hyperhost.ua` (VT + PCAP DNS corroboration) |
| Attribution | Malware family confirmed | AgentTesla (commodity .NET RAT/infostealer) |

## Answers Recap

| # | Question | Answer |
|---|---|---|
| Q1 | Attacker's IP | `10.0.2.4` |
| Q2 | Enumeration tool | `nmap` |
| Q3 | First two SMB Tree Connects | `\\10.0.2.15\Documents`, `\\10.0.2.15\IPC$` |
| Q4 | Uploaded malicious file | `shell.aspx` |
| Q5 | Reverse shell port | `4443` |
| Q6 | Kernel base address | `0xf80079213000` |
| Q7 | Persistence executable path | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |
| Q8 | Process spawning implant + PID | `w3wp.exe`, `4332` |
| Q9 | Packer | `UPX` |
| Q10 | C2 FQDN | `cp8nl.hyperhost.ua` |
| Q11 | Malware family | `AgentTesla` |

---

## Methodology Notes (for future investigations)

- **Volume-based pivoting works fast in noisy captures:** `Statistics → Conversations` sorted by packet count is often the single fastest way to surface a scanning/flooding source in a PCAP.
- **TCP flag filters isolate connection direction cleanly:** `tcp.flags.syn==1 and tcp.flags.ack==0` finds *initiators*, not responders — critical for telling a bind shell from a reverse shell.
- **SMB2 command codes are worth memorizing for investigations:** `3` = Tree Connect, `5` = Create, `9` = Write. These three alone cover most "what did the attacker access/plant" questions.
- **Volatility's `pstree` is the fastest way to spot a persistence implant:** look for any process spawned by a trusted parent (`w3wp.exe`, `svchost.exe`, `wmiprvse.exe`) that doesn't belong to the normal software stack, especially one running from an unusual path (Startup folder, `ProgramData`, `AppData`, `Temp`).
- **Packed malware rarely hides its packer:** UPX in particular leaves clear fingerprints (`UPX0`/`UPX1` section names, `UPX!` magic string) — no need to guess, just look at the section table.
- **When static analysis hits an encrypted config, pivot to threat intel:** VirusTotal's Relations (contacted domains/URLs) and Community (analyst tagging) tabs frequently recover what static string extraction cannot, especially for well-known commodity malware families whose configs are deliberately encrypted.
- **Cross-artifact corroboration strengthens findings:** confirming a VT-sourced C2 domain against the PCAP's own DNS queries turns a single-source claim into independently verified evidence — good practice for any real IR report.