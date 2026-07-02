# OSCP / OSCP+ Cheatsheet

[**The Compendium for this repo**](https://mystichackers.com/story/Njk)

Penetration-testing reference for the **2026 OSCP+ exam**: 3 standalone machines (20 pts each = 60) + one Active Directory set of 3 machines (40 pts) — **70 to pass**. No buffer-overflow machine, no bonus points.

**How to use it.** Each file below is a self-contained phase of the attack — open the one you need and `Ctrl+F` the keyword (a port like `445`, a technique like `kerberoast`, a tool like `chisel`). During the exam, **clone this repo locally first** (`git clone`) and/or keep an offline copy so you're never depending on the network staying up for 24h. Remember: AI assistants are **not** permitted during the exam or report phase — this is offline notes.

## Repository map

| Phase | File |
|------|------|
| Recon & enumeration (nmap, per-port, web) | [01-recon.md](01-recon.md) |
| Foothold — shells, file transfer, web exploitation, public exploits | [02-foothold.md](02-foothold.md) |
| Linux privilege escalation | [03-linux-privesc.md](03-linux-privesc.md) |
| Windows privilege escalation | [04-windows-privesc.md](04-windows-privesc.md) |
| Active Directory (the 40-point set) | [05-active-directory.md](05-active-directory.md) |
| Pivoting & tunneling | [06-pivoting.md](06-pivoting.md) |
| Password attacks & cracking | [07-password-attacks.md](07-password-attacks.md) |

The strategy, exam rules, report guidance, and a quick-reference appendix live below on this page.

---

## EXAM RULES & STRATEGY (read first)

### Hard rules (don't get flagged)
- **No AI / LLM chatbots during the exam OR the report phase.** This file is prep — you reference it offline. KAI included. Don't even have a chatbot tab open.
- **Metasploit: ONE target only.** Full MSF (exploit/auxiliary/post + one meterpreter) on a single machine of your choice. **Not** usable for pivoting (that would touch >1 target). `msfvenom`, `searchsploit`, `pattern_create`, `nasm_shell` are NOT counted as "using Metasploit."
- **Responder poisoning/spoofing is BANNED on the exam.** LLMNR/NBT-NS poisoning won't be the path. (Responder is "allowed" only in analyze mode; don't run `-w`/poisoning.)
- **Automatic exploitation tools are BANNED: SQLMap, SQLNinja, db_autopwn, browser_autopwn,** and anything that auto-discovers-and-exploits. Mass scanners (Nessus, OpenVAS, Nexpose) are banned too. Do SQLi and all exploitation **manually**. (Single-target tools like Nikto, dirb, nmap NSE are fine.)
- **PowerShell Core / PSSession counts as a valid interactive shell.**
- Everything happens on the proctored host. Don't discuss the exam anywhere (Discord, forums) — instant policy violation.

### Allowed tools (non-exhaustive, per OffSec)
BloodHound (Legacy + CE), SharpHound, PowerShell Empire, Covenant, PowerView, Rubeus, evil-winrm, Responder (analyze only), CrackMapExec / NetExec, Mimikatz, Impacket, PrintSpoofer. Standard non-MSF exploits are fine.

### How the points pass
You need 70. Realistic winning lines:
- **AD (40) + 3 local.txt (30) = 70** ← most common pass
- AD (40) + 2 local + 1 proof = 70
- AD (20, partial) + all 3 standalones fully = 70
- AD (10) + 3 standalones fully = 70

**Takeaway:** the AD set is the single biggest decider. Land AD first or early. Partial credit exists (foothold = 10, root = 10 on standalones; 10/10/20 on AD).

### Time plan (24h, no pause)
1. **First 20–30 min:** kick off nmap on every target, screenshot as scans run.
2. **Triage:** note quick wins (obvious CVE, anon SMB, default creds).
3. **AD set early** — it's 40 pts and chained; sinking those points first de-risks the day.
4. **Standalones:** grab every foothold (10 pts each) before grinding any single privesc. Partial points stack.
5. **Rotate.** Hard rule: if stuck 1.5–2h with zero progress, switch boxes. Come back fresh.
6. **Stop hacking ~2h before the window ends.** Verify every flag, re-take any missing screenshot, confirm proof.txt contents.

### Proof discipline (you lose points without this)
- Screenshot `local.txt` / `proof.txt` **with** `whoami` / `id` / `ipconfig` / `hostname` in the SAME frame.
- Screenshot the IP of the target in the shell.
- Log everything: `script` or just keep a per-box markdown with every command + output.
- Take MORE screenshots than you think you need. You cannot re-enter after the window closes.

### Per-box note template (copy for each target)
```
## <IP> - <hostname>
Ports:
Foothold: <how> | cred: <user:pass> | local.txt: <hash>
Privesc: <how> | proof.txt: <hash>
Screenshots: [ ] foothold+id  [ ] root+id  [ ] local.txt  [ ] proof.txt
```

---

---

## EXAM REPORT (no points without it — don't fumble the deliverable)
- Use the **official OffSec OSCP/OSCP+ report template** (.docx). Download and fill it offline.
- **One section per machine:** ports/services → foothold (exact request/exploit + URL/CVE) → `local.txt` proof → privesc steps → `proof.txt` proof.
- Every claim needs a **screenshot showing the command, its output, and `whoami`/`id`/`ipconfig` + the target IP in frame**.
- Write commands verbatim so a grader can **reproduce** each step. Note any exploit you modified.
- **AD set:** document the full chain host-by-host — how you got each credential and each hop to the DC.
- Workflow: keep per-box markdown notes during the exam → paste into the template afterward. (No AI for writing the report either.)
- Export to a **single PDF**, submit to the OffSec portal **within 24h** of the window closing.
- Unproven flags / missing screenshots = lost points. **When unsure, screenshot it.**

---

---

## QUICK-REFERENCE APPENDIX

### Common ports (memorize the cluster)
```
21 FTP | 22 SSH | 23 Telnet | 25 SMTP | 53 DNS | 80/443 HTTP(S) | 88 Kerberos(DC)
110 POP3 | 111 RPC/NFS | 135/139/445 SMB-RPC | 143 IMAP | 161 SNMP(UDP) | 389/636 LDAP
1433 MSSQL | 3306 MySQL | 3389 RDP | 5432 Postgres | 5985/5986 WinRM | 6379 Redis
```
Seeing 88 + 389 + 445 + 5985 together = **Domain Controller**. 53+88 too.

### Decision flow (per box)
```
nmap -> /etc/hosts -> per-port enum -> web dirbust -> identify version/CVE/default creds
  -> FOOTHOLD (web exploit / public exploit / creds) -> stabilize shell -> screenshot local.txt
  -> linpeas/winpeas + manual -> sudo -l / whoami /priv FIRST
  -> PRIVESC -> screenshot proof.txt -> document + move on
AD: given creds -> bloodhound -> roast/ACL/spray -> lateral (PtH) -> secretsdump -> DCSync -> DA
```

### When stuck (run the checklist before switching)
- Re-read ALL nmap output + every script line. Did you scan UDP? all 65535 TCP?
- Did you check **every** SMB share / web vhost / user `description`?
- Did you try found creds **everywhere** (SSH, SMB, RDP, WinRM, web, su)?
- `sudo -l` / `whoami /priv` done? GTFOBins/LOLBAS the binary?
- Any internal-only port in `ss -tlnp` / `netstat -ano` you haven't forwarded out?
- Backup/config/history files read? `.git`? source via php filter?
- For AD: re-collect BloodHound as the NEW user after each cred — paths change.
- Version too obscure for searchsploit? Search the exact `name + version + "exploit"` (cached refs).

### Reverse shell stabilize (one-liner recap)
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  ; Ctrl+Z ; stty raw -echo; fg ; export TERM=xterm
```

### secretsdump / PtH recap
```
impacket-secretsdump 'dom/user:pass@IP'      # dump
impacket-wmiexec dom/user@IP -hashes :NThash # use the hash
evil-winrm -i IP -u user -H NThash
```

### Offline reference stash to prepare BEFORE exam (no AI/internet-AI allowed)
HackTricks (book.hacktricks.xyz), GTFOBins, LOLBAS, PayloadsAllTheThings, revshells.com cheats,
hashcat mode table, Impacket/nxc help dumps, your own per-box notes. Keep binaries staged:
linpeas, winPEASany, pspy64, chisel (lin+win), ligolo (proxy+agent), PrintSpoofer64, GodPotato,
JuicyPotatoNG, PowerView, SharpHound, mimikatz, PwnKit, bloodyAD (sealed LDAP / ACL abuse),
certipy-ad (ADCS ESC1/ESC8), RunasCs (run-as with creds), Invoke-ConPtyShell (interactive Win TTY),
impacket owneredit/dacledit (WriteOwner/WriteDACL abuse).

---

*Personal prep notes. Coverage cross-checked against public OSCP checklists (crtvrffnrt, BlessedRebuS, fatalxs), HackTricks, GTFOBins and PayloadsAllTheThings, plus the official OSCP+ 2026 exam rules.*

---

## Further resources & credits

This cheatsheet is original notes, but its coverage was cross-checked against these community references — all worth reading directly:

- [crtvrffnrt/OSCP-Checklist-Cheatsheet2024](https://github.com/crtvrffnrt/OSCP-Checklist-Cheatsheet2024) — phase-by-phase checklists
- [0xsyr0/OSCP](https://github.com/0xsyr0/OSCP) — large command/tool/payload index
- [BlessedRebuS/OSCP-Pentesting-Cheatsheet](https://github.com/BlessedRebuS/OSCP-Pentesting-Cheatsheet) — methodology + payloads
- [HackTricks](https://book.hacktricks.xyz/) · [The Hacker Recipes](https://www.thehacker.recipes/) — deep technique references
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — payloads for every web vuln
- [GTFOBins](https://gtfobins.github.io/) · [LOLBAS](https://lolbas-project.github.io/) — living-off-the-land binaries (Linux / Windows)
- [WADComs](https://wadcoms.github.io/) — interactive Windows/AD command picker
- [Orange Cyberdefense AD mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/) — the AD attack flow on one page
- [revshells.com](https://www.revshells.com/) — reverse-shell generator (cache it offline)
- Official: [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) · [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ)

> Always confirm the current exam rules on the official guide before sitting — restricted-tool lists change.
