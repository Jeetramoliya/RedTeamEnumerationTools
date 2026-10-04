# Companion tools

The scripts are **self-contained** and work with native OS primitives. The tools
below are **optional** — when present they add depth or speed; when absent the
scripts degrade gracefully (and print the exact command to run elsewhere).

## Windows (`Invoke-RTEnum.ps1`, `Invoke-RTNetScan.ps1`, `Invoke-RTCloudEnum.ps1`)
| Tool | Adds |
|---|---|
| RSAT ActiveDirectory module / standalone `Microsoft.ActiveDirectory.Management.dll` | Faster/native AD queries (otherwise raw LDAP) |
| PowerView | Richer ACL / delegation / session enumeration |
| PowerUp | Local privesc checks + cached GPP |
| Rubeus, Certify/Certipy, mimikatz/SafetyKatz | Named in `NEXT_STEPS.txt` for exploitation (you run them) |
| Az / AzureAD / Microsoft.Graph modules, `az` CLI | Authenticated Entra/Azure enumeration |

## Linux (`rt-linenum.sh`, `rt-adenum.sh`, `ldap-enum.sh`, `net-sweep.sh`, `scan-secrets.sh`)
| Tool | Adds |
|---|---|
| `ldapsearch` (openldap-clients) | LDAP binds for AD + non-AD directories |
| netexec / crackmapexec | Rich SMB/LDAP enumeration, spraying, roasting |
| impacket (GetUserSPNs.py, GetNPUsers.py, secretsdump.py, getST.py) | Kerberos roasting, DCSync, delegation abuse |
| certipy | AD CS ESC analysis |
| bloodhound-python | Graph collection for path-finding |
| nmap | Faster/better network sweep (otherwise bash `/dev/tcp`) |
| mysql / psql / redis-cli / mongosh | DB default-credential checks (`net-sweep.sh --db`) |
| jq or python3 | CVE DB updater JSON parsing |
| getcap, sudo | Fuller local-privesc coverage |

## Suggested external references the scripts point you to
- GTFOBins (SUID/sudo abuse), LOLBAS (Windows), loldrivers.io (BYOVD)
- gtfobins.github.io, lolbas-project.github.io, www.loldrivers.io
- linux-exploit-suggester-2 / wesng / Watson (kernel/patch privesc breadth)
- The CISA KEV feed powers `tools/update-cve-db.*` (latest actively-exploited CVEs)
