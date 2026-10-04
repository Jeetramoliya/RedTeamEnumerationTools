#!/usr/bin/env python3
# ============================================================================
# eg-report.py  -  EnumGod report / merge / diff / playbook   |  Jeet Ramoliya
#
# Merges any number of EnumGod findings.json files (any module / host / platform)
# into ONE self-contained HTML report with:
#   * ranked HIGH/MED/INFO findings, de-duplicated
#   * MITRE ATT&CK technique tags per finding
#   * a phase-ordered PLAYBOOK (Local privesc -> Credential access -> Lateral ->
#     AD/domain -> Cloud) built from each module's NEXT_STEPS
#   * REMEDIATION notes per finding category (blue-team / report value)
#   * --diff: marks findings NEW since a previous run (what a hop unlocked)
#
# USAGE
#   python3 eg-report.py <run-dir|findings.json> [more...] [options]
#   python3 eg-report.py ./loot -o report.html --save-merged merged.json
#   python3 eg-report.py ./loot2 --diff merged.json -o report2.html
#
# Pure standard library. Operator-side tool (run where you triage, not the target).
# ============================================================================
import argparse, glob, html, json, os, re, sys, datetime

SEV_ORDER = {"HIGH": 0, "MED": 1, "INFO": 2}

# finding-text -> (ATT&CK id, technique name)
ATTACK = [
    (r"kerberoast",                      ("T1558.003", "Kerberoasting")),
    (r"AS-REP|asrep|DONT_REQUIRE_PREAUTH",("T1558.004", "AS-REP Roasting")),
    (r"delegation|RBCD|AllowedToAct",    ("T1558/T1134", "Delegation abuse")),
    (r"DCSync|replicat",                 ("T1003.006", "DCSync")),
    (r"LAPS|gMSA",                       ("T1555",     "Credentials from stores")),
    (r"cpassword|GPP",                   ("T1552.006", "Group Policy Preferences")),
    (r"LSASS|WDigest|Credential Guard",  ("T1003.001", "LSASS memory")),
    (r"\bSAM\b|HiveNightmare|secretsdump",("T1003.002", "SAM")),
    (r"/etc/shadow|gshadow|unshadow",    ("T1003.008", "/etc/passwd & /etc/shadow")),
    (r"unquoted service",                ("T1574.009", "Unquoted path hijack")),
    (r"DLL hijack|writable PATH|writable service dir",("T1574.001", "DLL hijack")),
    (r"service (binary|registry)|ImagePath|weak service",("T1543.003", "Windows Service")),
    (r"AlwaysInstallElevated|\.msi",     ("T1548.002", "Bypass UAC / elevated install")),
    (r"SUID|SGID|setuid",                ("T1548.001", "Setuid/Setgid")),
    (r"sudo|doas|NOPASSWD|GTFOBins",     ("T1548.003", "Sudo abuse")),
    (r"scheduled task|cron|systemd timer",("T1053",    "Scheduled task/job")),
    (r"SeImpersonate|potato|token priv", ("T1134.001", "Token impersonation")),
    (r"IMDS|managed identity|instance metadata|role credentials",("T1552.005", "Cloud instance metadata")),
    (r"secret|private key|api[_-]?key|token in|conn.?string|password", ("T1552.001", "Credentials in files")),
    (r"WRITABLE share|readable .*share|SMB share",("T1135", "Network share discovery")),
    (r"WinRM|evil-winrm|RDP|psexec|wmiexec",("T1021", "Remote services")),
    (r"password spray|spray",            ("T1110.003", "Password spraying")),
    (r"no_root_squash|container|docker\.sock|CAP_SYS_ADMIN|privileged",("T1611", "Escape to host")),
    (r"kernel .*built|Dirty Pipe|Dirty COW|OverlayFS|PwnKit|nf_tables|CVE-|CLFS|win32k", ("T1068", "Exploit for privilege escalation")),
    (r"ESC[0-9]|AD CS|certipy|certificate template",("T1649", "Steal/forge certificates")),
    (r"unattend|autologon|WiFi key",     ("T1552.001", "Credentials in files")),
    (r"trust|foreign principal|SID history",("T1134.005", "SID-History injection")),
]

# finding-text -> remediation note
REMED = [
    (r"kerberoast",            "Use (g)MSAs / 25+ char service-account passwords; AES-only; monitor 4769."),
    (r"AS-REP|asrep",          "Remove DONT_REQUIRE_PREAUTH; require Kerberos pre-auth for all accounts."),
    (r"delegation|RBCD",       "Remove unneeded delegation; set sensitive accounts 'not delegated'; audit msDS-AllowedToActOnBehalfOfOtherIdentity."),
    (r"DCSync",                "Restrict DS-Replication-Get-Changes* to DCs; audit non-default principals."),
    (r"LAPS",                  "Restrict ms-Mcs-AdmPwd read to admins; rotate; prefer Windows LAPS."),
    (r"gMSA",                  "Restrict PrincipalsAllowedToRetrieveManagedPassword to required hosts only."),
    (r"cpassword|GPP",         "Remove GPP passwords from SYSVOL; rotate affected local-admin passwords."),
    (r"LSASS|WDigest",         "Enable LSA PPL + Credential Guard; set WDigest UseLogonCredential=0."),
    (r"\bSAM\b|HiveNightmare", "Apply the fixing update; fix config\\SAM ACLs; delete VSS copies exposing hives."),
    (r"/etc/shadow|gshadow",   "Restore 640 root:shadow on /etc/shadow; rotate exposed hashes."),
    (r"unquoted service",      "Quote service ImagePath values; restrict write on the path."),
    (r"DLL hijack|writable PATH|writable service",  "Remove write for non-admins on service dirs / PATH entries."),
    (r"service registry|ImagePath",  "Restrict write on HKLM\\...\\Services keys to admins/SYSTEM."),
    (r"AlwaysInstallElevated", "Set AlwaysInstallElevated=0 in HKLM and HKCU policy."),
    (r"SUID|SGID",             "Remove needless setuid bits; mount user-writable fs nosuid."),
    (r"sudo|doas|NOPASSWD",    "Tighten sudoers; avoid NOPASSWD + GTFOBins binaries; patch sudo."),
    (r"cron|scheduled task|timer",  "Restrict write on scheduled scripts; run as least-privilege."),
    (r"SeImpersonate|potato",  "Remove SeImpersonate from service accounts where possible; patch potato vectors."),
    (r"IMDS|managed identity", "Enforce IMDSv2 / hop-limit 1; least-privilege the instance role; block 169.254.169.254 egress from apps."),
    (r"secret|private key|api[_-]?key|conn.?string|password", "Rotate exposed secrets; move to a vault; remove from disk/history/repos."),
    (r"WRITABLE share|SMB share",  "Remove write/Everyone ACLs; enable SMB signing; least-privilege shares."),
    (r"password spray",        "Enforce lockout + strong passwords + MFA; alert on 4625 bursts."),
    (r"no_root_squash|docker\.sock|container|privileged",  "Set root_squash; don't expose docker.sock; drop CAP_SYS_ADMIN; use userns."),
    (r"kernel .*built|Dirty|OverlayFS|PwnKit|nf_tables|CVE-|CLFS|win32k",  "Patch to the fixed package/kernel; disable unprivileged user namespaces if unused."),
    (r"ESC[0-9]|AD CS|certificate template",  "Fix template flags (no ENROLLEE_SUPPLIES_SUBJECT); require manager approval; restrict enroll."),
]

# phase ordering for the playbook
PHASES = [
    ("Local privilege escalation", r"privesc|suid|sudo|service|dll|ImagePath|AlwaysInstall|cron|task|token|potato|kernel|CVE|writable|capabilit|polkit|pkexec|library|ld\.so|wildcard"),
    ("Credential access",          r"lsass|wdigest|\bsam\b|dpapi|cmdkey|secret|private key|gpp|cpassword|laps|gmsa|dcsync|kerberoast|asrep|hash|shadow|vault|browser|token"),
    ("Lateral movement",           r"share|winrm|rdp|psexec|wmiexec|smb|spray|evil-winrm"),
    ("AD / domain escalation",     r"delegation|rbcd|acl|adcs|esc[0-9]|dnsadmin|trust|sid history|certipy"),
    ("Cloud / pivot",              r"imds|managed identity|azure|aws|gcp|kube|graph|entra|s3|role credential"),
]

def find_json(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += glob.glob(os.path.join(p, "**", "findings.json"), recursive=True)
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"[!] skip (not found): {p}", file=sys.stderr)
    return sorted(set(files))

def module_from_path(path):
    d = os.path.basename(os.path.dirname(os.path.abspath(path)))
    return d.split("_")[0] if "_" in d else (d or "run")

def norm(path):
    """-> (findings[list(sev,text,host,module)], nextsteps[list(title,cmd,module)])"""
    try:
        data = json.load(open(path, encoding="utf-8-sig"))
    except Exception as e:
        print(f"[!] bad json {path}: {e}", file=sys.stderr)
        return [], []
    host = data.get("host") or data.get("identity") or data.get("domain") or "?"
    module = data.get("module") or module_from_path(path)
    src = data.get("findings", data)
    finds = []
    for sev in ("high", "med", "info"):
        for item in (src.get(sev) or []):
            text = item if isinstance(item, str) else json.dumps(item)
            for tag in ("[HIGH] ", "[MED ] ", "[MED] ", "[INFO] "):
                if text.startswith(tag):
                    text = text[len(tag):]
            finds.append((sev.upper(), text.strip(), str(host), str(module)))
    nexts = []
    for ns in (data.get("next_steps") or []):
        if isinstance(ns, dict):
            title, cmd = ns.get("Title", ns.get("title", "")), ns.get("Cmd", ns.get("cmd", ""))
        else:
            parts = str(ns).split("::", 1)
            title, cmd = parts[0].strip(), (parts[1].strip() if len(parts) > 1 else "")
        if title or cmd:
            nexts.append((title, cmd, str(module)))
    return finds, nexts

def attack_tag(text):
    for rx, tid in ATTACK:
        if re.search(rx, text, re.I):
            return tid
    return ("", "")

def remediation(text):
    for rx, note in REMED:
        if re.search(rx, text, re.I):
            return note
    return ""

def phase_of(text):
    for i, (name, rx) in enumerate(PHASES):
        if re.search(rx, text, re.I):
            return i, name
    return len(PHASES), "Other"

def key(f):
    return (f[0], f[1])

def build_html(findings, nexts, title, diff_keys, sources):
    counts = {"HIGH": 0, "MED": 0, "INFO": 0}
    for sev, *_ in findings:
        counts[sev] = counts.get(sev, 0) + 1
    new_n = sum(1 for f in findings if diff_keys is not None and key(f) not in diff_keys)
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    # findings table
    rows = []
    for sev, text, host, module in sorted(findings, key=lambda f: (SEV_ORDER.get(f[0], 9), f[3], f[1])):
        tid, tname = attack_tag(text)
        att = f'<span class="att" title="{html.escape(tname)}">{tid}</span>' if tid else ""
        is_new = diff_keys is not None and key((sev, text)) not in diff_keys
        badge = '<span class="new">NEW</span>' if is_new else ""
        rows.append(
            f'<tr class="s-{sev.lower()}{" row-new" if is_new else ""}">'
            f'<td class="sev">{sev}</td><td class="mod">{html.escape(module)}</td>'
            f'<td class="host">{html.escape(host)}</td>'
            f'<td class="txt">{html.escape(text)} {att} {badge}</td></tr>')

    # playbook (phase-ordered, de-duplicated next steps)
    seen_ns, pb = set(), {}
    for title_, cmd, module in nexts:
        k = (title_, cmd)
        if k in seen_ns:
            continue
        seen_ns.add(k)
        pi, pname = phase_of(title_ + " " + cmd)
        pb.setdefault((pi, pname), []).append((title_, cmd, module))
    pb_html = []
    for (pi, pname) in sorted(pb):
        items = "".join(
            f'<li><b>{html.escape(t)}</b> <span class="mod">[{html.escape(m)}]</span>'
            + (f'<pre>{html.escape(c)}</pre>' if c else "") + "</li>"
            for t, c, m in pb[(pi, pname)])
        pb_html.append(f'<div class="phase"><h3>{pi+1}. {html.escape(pname)}</h3><ol>{items}</ol></div>')
    pb_section = ("".join(pb_html) if pb_html
                  else '<p class="sub">No scripted next-steps in these runs.</p>')

    # remediation (unique notes for present categories)
    rem = []
    seen_r = set()
    for _, text, _, _ in sorted(findings, key=lambda f: SEV_ORDER.get(f[0], 9)):
        note = remediation(text)
        if note and note not in seen_r:
            seen_r.add(note)
            rem.append(f'<li><b>{html.escape(text[:70])}{"…" if len(text)>70 else ""}</b><br><span class="rem">{html.escape(note)}</span></li>')
    rem_section = "".join(rem) if rem else "<li>No mapped remediations.</li>"

    srclist = "".join(f"<li>{html.escape(s)}</li>" for s in sources)
    diffline = (f'<span class="pill pill-new">{new_n} new</span>' if diff_keys is not None else "")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>
:root{{--bg:#0f1419;--card:#171d26;--fg:#e6edf3;--mut:#8b98a5;--line:#2a3340;
--high:#ff5c5c;--med:#ffb454;--info:#6b7684;--new:#3fb950;--accent:#58a6ff;}}
@media (prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--mut:#656d76;--line:#d0d7de;--info:#8b949e;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:24px 16px}}
.wrap{{max-width:1120px;margin:0 auto}}h1{{font-size:20px;margin:0 0 2px}}h2{{font-size:15px;margin:26px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}}
h3{{font-size:13px;margin:14px 0 6px;color:var(--accent)}}.sub{{color:var(--mut);margin:0 0 16px;font-size:12px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:6px}}.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:92px}}
.card .n{{font-size:26px;font-weight:700}}.card .l{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.c-high .n{{color:var(--high)}}.c-med .n{{color:var(--med)}}.c-info .n{{color:var(--info)}}.c-new .n{{color:var(--new)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
td.sev{{font-weight:700;white-space:nowrap}}.s-high td.sev{{color:var(--high)}}.s-med td.sev{{color:var(--med)}}.s-info td.sev{{color:var(--info)}}
td.mod,td.host{{color:var(--mut);white-space:nowrap}}td.txt{{width:99%}}
.row-new{{background:color-mix(in srgb,var(--new) 10%,transparent)}}
.new{{color:#021;background:var(--new);border-radius:4px;padding:0 6px;font-size:10px;font-weight:700}}
.att{{color:var(--accent);border:1px solid var(--line);border-radius:4px;padding:0 5px;font-size:10px;white-space:nowrap}}
.pill{{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:11px;color:var(--mut);margin-left:8px}}.pill-new{{color:var(--new);border-color:var(--new)}}
.phase{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 16px 12px;margin-bottom:12px}}
.phase ol{{margin:0;padding-left:22px}}.phase li{{margin:8px 0}}
pre{{white-space:pre-wrap;color:var(--accent);margin:4px 0 0;font-size:12px}}
ul.rem{{list-style:none;padding:0}}ul.rem li{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}}
.rem{{color:var(--mut)}}details summary{{cursor:pointer;color:var(--mut)}}
footer{{color:var(--mut);font-size:11px;margin-top:24px;text-align:center}}
</style></head><body><div class="wrap">
<h1>{html.escape(title)}</h1>
<p class="sub">EnumGod &middot; generated {gen} &middot; {len(sources)} run(s) {diffline} &middot; author Jeet Ramoliya</p>
<div class="cards">
<div class="card c-high"><div class="n">{counts['HIGH']}</div><div class="l">High</div></div>
<div class="card c-med"><div class="n">{counts['MED']}</div><div class="l">Medium</div></div>
<div class="card c-info"><div class="n">{counts['INFO']}</div><div class="l">Info</div></div>
{'<div class="card c-new"><div class="n">'+str(new_n)+'</div><div class="l">New</div></div>' if diff_keys is not None else ''}
</div>
<h2>Attack playbook (by phase)</h2>{pb_section}
<h2>Findings</h2>
<table><thead><tr><th>Sev</th><th>Module</th><th>Host</th><th>Finding &amp; ATT&amp;CK</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan=4>No findings.</td></tr>'}</tbody></table>
<h2>Remediation</h2><ul class="rem">{rem_section}</ul>
<details><summary>Source runs ({len(sources)})</summary><ul>{srclist}</ul></details>
<footer>EnumGod &middot; author Jeet Ramoliya &middot; authorized use only</footer>
</div></body></html>"""

def main():
    ap = argparse.ArgumentParser(description="EnumGod report / merge / diff / playbook")
    ap.add_argument("paths", nargs="+", help="run dir(s) or findings.json file(s)")
    ap.add_argument("-o", "--out", default="enumgod-report.html")
    ap.add_argument("--diff", help="prior merged JSON; marks findings not present in it as NEW")
    ap.add_argument("--save-merged", help="write normalised merged findings to this JSON")
    ap.add_argument("--title", default="EnumGod Report")
    a = ap.parse_args()

    files = find_json(a.paths)
    if not files:
        print("[-] no findings.json found under the given paths", file=sys.stderr); sys.exit(1)

    seen, merged, nexts = set(), [], []
    for f in files:
        fi, ns = norm(f)
        for item in fi:
            if key(item) in seen: continue
            seen.add(key(item)); merged.append(item)
        nexts += ns

    diff_keys = None
    if a.diff and os.path.isfile(a.diff):
        try:
            prev = json.load(open(a.diff, encoding="utf-8-sig"))
            diff_keys = {(x[0], x[1]) for x in prev.get("findings", [])}
        except Exception as e:
            print(f"[!] could not read --diff file: {e}", file=sys.stderr)

    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(build_html(merged, nexts, a.title, diff_keys, files))
    if a.save_merged:
        json.dump({"generated": datetime.datetime.now().isoformat(), "sources": files, "findings": merged},
                  open(a.save_merged, "w", encoding="utf-8"), indent=2)

    c = {"HIGH": 0, "MED": 0, "INFO": 0}
    for s, *_ in merged: c[s] = c.get(s, 0) + 1
    newc = 0 if diff_keys is None else sum(1 for m in merged if key(m) not in diff_keys)
    print(f"[+] {len(files)} run(s) -> {len(merged)} findings "
          f"(HIGH={c['HIGH']} MED={c['MED']} INFO={c['INFO']}"
          f"{'' if diff_keys is None else f' NEW={newc}'}), {len(set((t,c2) for t,c2,_ in nexts))} playbook step(s)")
    print(f"[+] report: {a.out}" + (f"   merged: {a.save_merged}" if a.save_merged else ""))

if __name__ == "__main__":
    main()
