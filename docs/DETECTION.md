# EnumGod — detection & noise map

What each part of the toolkit looks like to a defender, so you can choose how loud to
be and so blue teams can build detections. EnumGod is **read-only enumeration**; the
loudest parts are the opt-in network/host sweeps and any exploitation *you* run from
`NEXT_STEPS`. Nothing here is designed to evade detection — this map exists to make the
tradeoffs explicit and to help the defensive side.

Legend: **Quiet** = local or normal-looking traffic · **Loud** = fans out to other hosts
/ generates security events.

| Module / action | Noise | What it touches | Likely telemetry |
|---|---|---|---|
| `Invoke-RTEnum` local triage (default) | Quiet | Local WMI/CIM/registry/files | Minimal; PowerShell 4104 script-block logs if enabled |
| CVE matching (`--only cve`) | Quiet | Local version/changelog/registry reads | None notable |
| `rt-linenum.sh` / extended checks | Quiet | Local files, `find`, `getcap` | Local auditd `execve` if configured |
| LDAP enumeration (AD / `ldap-enum.sh`) | Quiet-ish | LDAP(389/636) to DC/dir | Normal LDAP; heavy queries → 1644 (if AD field-engineering logging on) |
| `Invoke-RTEnum -HostSweep` / `-Target` | **Loud** | SMB/WMI to many hosts | 4624/4672 logons on targets; mass-SMB pattern |
| `net-sweep.sh` / `Invoke-RTNetScan` | **Loud** | TCP connect scan of subnet | IDS/NetFlow fan-out; many short-lived connections |
| `net-sweep.sh --db` | **Loud** | DB auth attempts | DB auth-failure logs; SQL Server 18456 |
| `Invoke-RTShareHunt` / `share-hunt.sh` | **Loud** | SMB to many hosts; `-TestWrite` writes a marker | 5140/5145 share access, 4663 object access, file-create events |
| `rt-adenum.sh --userenum` | **Loud** | Kerberos AS-REQ per user | 4768 with failure codes; kerbrute signature |
| `rt-adenum.sh --spray` | **Loud** | Kerberos/SMB auth per user | 4771/4625 bursts; lockouts if careless |
| `-Roast` / kerberoast (next-step) | **Loud** | TGS requests | 4769 for service accounts (RC4 esp.) |
| `rt-cloudenum.sh` token fetch | Medium | IMDS 169.254.169.254 | Cloud audit logs (token issuance); IMDS access anomaly |
| `Invoke-RTCloudEnum` | Quiet | Local reads + IMDS presence probe | Minimal |

## Reducing noise
- Default to quiet: local + LDAP only. Add sweeps only when you accept the fan-out.
- Scope sweeps with `-Target` / `-t <cidr>` instead of domain-wide.
- `net-sweep.sh` (no `--loud`) uses a curated port list and randomize host order where possible.
- `--spray` is lockout-aware — check the password policy (`--pass-pol` via netexec, or the
  policy section) and keep to **one attempt per observation window**.
- Cloud: `--no-token` identifies the environment without issuing a Managed-Identity token.

## For defenders (blue-team value)
Each finding in the HTML report carries a **MITRE ATT&CK** tag and a **remediation** note.
Prioritise: LSASS/credential-store hardening (LSA PPL + Credential Guard, WDigest=0),
patch currency (EnumGod only confirms genuinely-missing fixes), delegation/ACL hygiene,
Point-and-Print + Spooler state, SMB signing + share ACLs, and IMDSv2 enforcement.
