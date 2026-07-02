# 01 · Recon & Enumeration

> Part of the **OSCP/OSCP+ cheatsheet** — [← back to index](README.md)

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
- **AutoRecon** / nmapAutomator fan out per-service enum (enumeration only, so exam-safe). Read the output yourself.
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
