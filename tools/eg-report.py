#!/usr/bin/env python3
# ============================================================================
# eg-report.py  -  EnumGod report / merge / diff / playbook   |  Jeet Ramoliya
#
# Normalizes every module's findings.json (any shape, any platform) into ONE
# CANONICAL finding schema, then renders a self-contained HTML report with:
#   * stable finding IDs (same issue -> same id; per-host rows stay separate assets)
#   * severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) + independent confidence
#     (CONFIRMED/LIKELY/POTENTIAL)
#   * category, MITRE ATT&CK tag, remediation, active-check flag, port
#   * a phase-ordered PLAYBOOK built from each module's NEXT_STEPS
#   * --diff: marks findings NEW since a previous run (what a hop unlocked)
#
# --save-merged writes the canonical findings as JSON (the schema below). This is
# the normalization layer: shell/PowerShell modules keep emitting their simple
# JSON; this tool makes them all schema-compatible.
#
# CANONICAL FINDING:
#   {id,title,severity,confidence,category,host,port,source,description,
#    evidence,impact,remediation,next_steps,active_check,attack,timestamp}
#
# USAGE
#   python3 eg-report.py <run-dir|findings.json> [more...] [-o out.html]
#                        [--save-merged merged.json] [--diff prev.json] [--title T]
# Pure standard library. Operator-side tool. Exit: 0 none, 1 findings, 2 error, 3 args.
# ============================================================================
import argparse, glob, hashlib, html, json, os, re, sys, datetime

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MED": 2, "LOW": 3, "INFO": 4}
SEV_CANON = {"HIGH": "HIGH", "MED": "MEDIUM", "MEDIUM": "MEDIUM", "INFO": "INFO",
             "CRITICAL": "CRITICAL", "LOW": "LOW"}

# (regex, (ATT&CK id, name))
ATTACK = [
    (r"kerberoast", ("T1558.003", "Kerberoasting")),
    (r"AS-REP|asrep|DONT_REQUIRE_PREAUTH", ("T1558.004", "AS-REP Roasting")),
    (r"delegation|RBCD|AllowedToAct", ("T1558/T1134", "Delegation abuse")),
    (r"DCSync|replicat", ("T1003.006", "DCSync")),
    (r"LAPS|gMSA", ("T1555", "Credentials from stores")),
    (r"cpassword|GPP", ("T1552.006", "Group Policy Preferences")),
    (r"LSASS|WDigest|Credential Guard", ("T1003.001", "LSASS memory")),
    (r"\bSAM\b|HiveNightmare|secretsdump", ("T1003.002", "SAM")),
    (r"/etc/shadow|gshadow|unshadow", ("T1003.008", "/etc/passwd & /etc/shadow")),
    (r"unquoted service", ("T1574.009", "Unquoted path hijack")),
    (r"DLL hijack|writable PATH|writable service dir", ("T1574.001", "DLL hijack")),
    (r"service (binary|registry)|ImagePath|weak service", ("T1543.003", "Windows Service")),
    (r"AlwaysInstallElevated|\.msi", ("T1548.002", "Bypass UAC / elevated install")),
    (r"SUID|SGID|setuid", ("T1548.001", "Setuid/Setgid")),
    (r"sudo|doas|NOPASSWD|GTFOBins", ("T1548.003", "Sudo abuse")),
    (r"scheduled task|cron|systemd timer", ("T1053", "Scheduled task/job")),
    (r"SeImpersonate|potato|token priv", ("T1134.001", "Token impersonation")),
    (r"IMDS|managed identity|instance metadata|role credentials", ("T1552.005", "Cloud instance metadata")),
    (r"secret|private key|api[_-]?key|token in|conn.?string|password", ("T1552.001", "Credentials in files")),
    (r"WRITABLE share|readable .*share|SMB share", ("T1135", "Network share discovery")),
    (r"WinRM|evil-winrm|RDP|psexec|wmiexec", ("T1021", "Remote services")),
    (r"password spray|spray", ("T1110.003", "Password spraying")),
    (r"no_root_squash|container|docker\.sock|CAP_SYS_ADMIN|privileged", ("T1611", "Escape to host")),
    (r"kernel .*built|Dirty Pipe|Dirty COW|OverlayFS|PwnKit|nf_tables|CVE-|CLFS|win32k", ("T1068", "Exploit for privilege escalation")),
    (r"ESC[0-9]|AD CS|certipy|certificate template", ("T1649", "Steal/forge certificates")),
    (r"trust|foreign principal|SID history", ("T1134.005", "SID-History injection")),
]
REMED = [
    (r"kerberoast", "Use (g)MSAs / 25+ char service-account passwords; AES-only; monitor 4769."),
    (r"AS-REP|asrep", "Remove DONT_REQUIRE_PREAUTH; require Kerberos pre-auth."),
    (r"delegation|RBCD", "Remove unneeded delegation; mark sensitive accounts 'not delegated'."),
    (r"DCSync", "Restrict DS-Replication-Get-Changes* to DCs; audit non-default principals."),
    (r"LAPS", "Restrict ms-Mcs-AdmPwd read to admins; rotate; prefer Windows LAPS."),
    (r"gMSA", "Restrict PrincipalsAllowedToRetrieveManagedPassword to required hosts."),
    (r"cpassword|GPP", "Remove GPP passwords from SYSVOL; rotate affected local-admin passwords."),
    (r"LSASS|WDigest", "Enable LSA PPL + Credential Guard; set WDigest UseLogonCredential=0."),
    (r"\bSAM\b|HiveNightmare", "Apply the fixing update; fix config\\SAM ACLs; delete exposing VSS copies."),
    (r"/etc/shadow|gshadow", "Restore 640 root:shadow on /etc/shadow; rotate exposed hashes."),
    (r"unquoted service", "Quote service ImagePath values; restrict write on the path."),
    (r"DLL hijack|writable PATH|writable service", "Remove non-admin write on service dirs / PATH."),
    (r"service registry|ImagePath", "Restrict write on HKLM\\...\\Services keys to admins/SYSTEM."),
    (r"AlwaysInstallElevated", "Set AlwaysInstallElevated=0 in HKLM and HKCU policy."),
    (r"SUID|SGID", "Remove needless setuid bits; mount user-writable fs nosuid."),
    (r"sudo|doas|NOPASSWD", "Tighten sudoers; avoid NOPASSWD + GTFOBins binaries; patch sudo."),
    (r"cron|scheduled task|timer", "Restrict write on scheduled scripts; least-privilege."),
    (r"SeImpersonate|potato", "Remove SeImpersonate from service accounts; patch potato vectors."),
    (r"IMDS|managed identity", "Enforce IMDSv2 / hop-limit 1; least-privilege the instance role."),
    (r"secret|private key|api[_-]?key|conn.?string|password", "Rotate exposed secrets; move to a vault; purge from disk/history/repos."),
    (r"WRITABLE share|SMB share", "Remove write/Everyone ACLs; enable SMB signing."),
    (r"password spray", "Enforce lockout + strong passwords + MFA; alert on 4625 bursts."),
    (r"no_root_squash|docker\.sock|container|privileged", "Set root_squash; don't expose docker.sock; drop CAP_SYS_ADMIN."),
    (r"kernel .*built|Dirty|OverlayFS|PwnKit|nf_tables|CVE-|CLFS|win32k", "Patch to the fixed package/kernel; disable unprivileged user namespaces if unused."),
    (r"ESC[0-9]|AD CS|certificate template", "Fix template flags; require manager approval; restrict enroll."),
]
# category code + matcher (first match wins); used for both display and the stable ID prefix
CATEGORY = [
    ("ADCS",  r"ESC[0-9]|AD CS|certificate template|certipy"),
    ("AD",    r"kerberoast|asrep|AS-REP|delegation|RBCD|DCSync|gMSA|LAPS|cpassword|trust|SID history|MachineAccountQuota|domain admin|privileged group"),
    ("CRED",  r"LSASS|WDigest|\bSAM\b|secret|private key|api[_-]?key|password|token|credential|vault|dpapi|keychain|shadow|hash"),
    ("CLOUD", r"IMDS|managed identity|azure|aws|gcp|entra|kube|s3|role credential|graph"),
    ("CVE",   r"CVE-|Dirty Pipe|Dirty COW|PwnKit|OverlayFS|nf_tables|CLFS|win32k|kernel .*built"),
    ("PRIV",  r"SUID|SGID|sudo|doas|service|ImagePath|DLL|AlwaysInstall|cron|task|token priv|SeImpersonate|potato|capabilit|polkit|library|wildcard|writable"),
    ("NET",   r"share|SMB|redis|docker|nfs|winrm|rdp|ldap|mssql|mysql|postgres|mongo|elastic|snmp|ipv6|llmnr|exposed|port"),
    ("DISC",  r"discover|neighbour|mdns|netbios|interface|route"),
]
PHASES = [
    ("Local privilege escalation", r"privesc|suid|sudo|service|dll|ImagePath|AlwaysInstall|cron|task|token|potato|kernel|CVE|writable|capabilit|polkit|pkexec|library|ld\.so|wildcard"),
    ("Credential access", r"lsass|wdigest|\bsam\b|dpapi|cmdkey|secret|private key|gpp|cpassword|laps|gmsa|dcsync|kerberoast|asrep|hash|shadow|vault|browser|token"),
    ("Lateral movement", r"share|winrm|rdp|psexec|wmiexec|smb|spray|evil-winrm"),
    ("AD / domain escalation", r"delegation|rbcd|acl|adcs|esc[0-9]|dnsadmin|trust|sid history|certipy"),
    ("Cloud / pivot", r"imds|managed identity|azure|aws|gcp|kube|graph|entra|s3|role credential"),
]
ACTIVE_HINT = r"writable share|WRITE|test-write|spray|OPENQUERY|xp_cmdshell|collect-token|retrieved .*token|unauthenticated .*(confirmed|answers)|BLANK password|default/blank"

def first(table, text, default=("", "")):
    for rx, val in table:
        if re.search(rx, text, re.I):
            return val
    return default

def category(text):
    for code, rx in CATEGORY:
        if re.search(rx, text, re.I):
            return code
    return "INFO"

def confidence(text):
    t = text.lower()
    if "confirmed" in t:
        return "CONFIRMED"
    if ("[potential]" in t or "potential" in t or "may apply" in t or "candidate" in t
            or "verify" in t or "possible" in t or "often unauth" in t or "unconfirm" in t):
        return "POTENTIAL"
    return "LIKELY"

def port_of(text):
    m = re.search(r"\((\d{2,5})\)|(?:^|\s)(\d{2,5})/(?:tcp|udp)|:(\d{2,5})\b", text)
    if m:
        for g in m.groups():
            if g:
                return int(g)
    return None

def finding_id(cat, title):
    norm = re.sub(r"\s+", " ", re.sub(r"[0-9A-Fa-f:.]{4,}", "", title)).strip().lower()
    h = hashlib.md5(norm.encode("utf-8", "ignore")).hexdigest()[:4]
    return f"RT-{cat}-{h}"

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
    """-> (findings[canonical dicts], nextsteps[(title,cmd,module)])"""
    try:
        data = json.load(open(path, encoding="utf-8-sig"))
    except Exception as e:
        print(f"[!] bad json {path}: {e}", file=sys.stderr)
        return [], [], False
    host = str(data.get("host") or data.get("identity") or data.get("domain") or "?")
    module = str(data.get("source") or data.get("module") or module_from_path(path))
    mod_active = bool(data.get("active_check", False))
    ts = str(data.get("ts") or data.get("timestamp") or "")
    src = data.get("findings", data)
    finds = []
    for sevkey in ("high", "med", "info"):
        for item in (src.get(sevkey) or []):
            text = item if isinstance(item, str) else json.dumps(item)
            for tag in ("[HIGH] ", "[MED ] ", "[MED] ", "[INFO] "):
                if text.startswith(tag):
                    text = text[len(tag):]
            text = text.strip()
            sev = SEV_CANON.get(sevkey.upper(), "INFO")
            cat = category(text)
            tid, tname = first(ATTACK, text)
            active = mod_active or bool(re.search(ACTIVE_HINT, text, re.I))
            finds.append({
                "id": finding_id(cat, text),
                "title": text[:120],
                "severity": sev,
                "confidence": confidence(text),
                "category": cat,
                "host": host,
                "port": port_of(text),
                "source": module,
                "description": text,
                "evidence": text,
                "impact": tname,
                "remediation": first(REMED, text, ("",))[0] if isinstance(first(REMED, text, ("",)), tuple) else first(REMED, text, ""),
                "attack": tid,
                "active_check": active,
                "timestamp": ts,
            })
    nexts = []
    for ns in (data.get("next_steps") or []):
        if isinstance(ns, dict):
            title, cmd = ns.get("Title", ns.get("title", "")), ns.get("Cmd", ns.get("cmd", ""))
        else:
            parts = str(ns).split("::", 1)
            title, cmd = parts[0].strip(), (parts[1].strip() if len(parts) > 1 else "")
        if title or cmd:
            nexts.append((title, cmd, module))
    return finds, nexts, mod_active

def remediation_text(text):
    for rx, note in REMED:
        if re.search(rx, text, re.I):
            return note
    return ""

def phase_of(text):
    for i, (name, rx) in enumerate(PHASES):
        if re.search(rx, text, re.I):
            return i, name
    return len(PHASES), "Other"

def ident(f):           # finding identity for dedup/diff: stable id + host (per-asset)
    return (f["id"], f["host"])

def build_html(finds, nexts, title, diff_set, sources):
    sevc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    confc = {"CONFIRMED": 0, "LIKELY": 0, "POTENTIAL": 0}
    for f in finds:
        sevc[f["severity"]] = sevc.get(f["severity"], 0) + 1
        confc[f["confidence"]] = confc.get(f["confidence"], 0) + 1
    new_n = sum(1 for f in finds if diff_set is not None and ident(f) not in diff_set)
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = []
    for f in sorted(finds, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["source"], x["title"])):
        att = f'<span class="att" title="{html.escape(f["impact"])}">{f["attack"]}</span>' if f["attack"] else ""
        is_new = diff_set is not None and ident(f) not in diff_set
        new = '<span class="new">NEW</span>' if is_new else ""
        act = '<span class="act">ACTIVE</span>' if f["active_check"] else ""
        port = html.escape(str(f["port"])) if f["port"] else ""
        rows.append(
            f'<tr class="s-{f["severity"].lower()}{" row-new" if is_new else ""}">'
            f'<td class="fid">{html.escape(f["id"])}</td>'
            f'<td class="sev">{f["severity"]}</td>'
            f'<td class="conf c-{f["confidence"].lower()}">{f["confidence"]}</td>'
            f'<td class="mod">{html.escape(f["source"])}</td>'
            f'<td class="host">{html.escape(f["host"])}</td><td class="port">{port}</td>'
            f'<td class="txt">{html.escape(f["description"])} {att} {act} {new}</td></tr>')

    seen, pb = set(), {}
    for t_, c_, m_ in nexts:
        if (t_, c_) in seen:
            continue
        seen.add((t_, c_))
        pi, pname = phase_of(t_ + " " + c_)
        pb.setdefault((pi, pname), []).append((t_, c_, m_))
    pbh = []
    for k in sorted(pb):
        items = "".join(f'<li><b>{html.escape(t)}</b> <span class="mod">[{html.escape(m)}]</span>'
                        + (f'<pre>{html.escape(c)}</pre>' if c else "") + "</li>" for t, c, m in pb[k])
        pbh.append(f'<div class="phase"><h3>{k[0]+1}. {html.escape(k[1])}</h3><ol>{items}</ol></div>')
    pb_section = "".join(pbh) if pbh else '<p class="sub">No scripted next-steps.</p>'

    rem, seenr = [], set()
    for f in sorted(finds, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        note = remediation_text(f["description"])
        if note and note not in seenr:
            seenr.add(note)
            rem.append(f'<li><b>{html.escape(f["title"][:70])}</b><br><span class="rem">{html.escape(note)}</span></li>')
    rem_section = "".join(rem) if rem else "<li>No mapped remediations.</li>"

    srclist = "".join(f"<li>{html.escape(s)}</li>" for s in sources)
    diffline = f'<span class="pill pill-new">{new_n} new</span>' if diff_set is not None else ""

    def card(cls, n, l):
        return f'<div class="card {cls}"><div class="n">{n}</div><div class="l">{l}</div></div>'
    cards = (card("c-crit", sevc["CRITICAL"], "Critical") + card("c-high", sevc["HIGH"], "High")
             + card("c-med", sevc["MEDIUM"], "Medium") + card("c-low", sevc["LOW"], "Low")
             + card("c-info", sevc["INFO"], "Info")
             + (card("c-new", new_n, "New") if diff_set is not None else ""))

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>
:root{{--bg:#0f1419;--card:#171d26;--fg:#e6edf3;--mut:#8b98a5;--line:#2a3340;
--crit:#ff3860;--high:#ff5c5c;--med:#ffb454;--low:#6cb6ff;--info:#6b7684;--new:#3fb950;--accent:#58a6ff;}}
@media (prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--mut:#656d76;--line:#d0d7de;--info:#8b949e;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:24px 16px}}
.wrap{{max-width:1180px;margin:0 auto}}h1{{font-size:20px;margin:0 0 2px}}h2{{font-size:15px;margin:26px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}}
h3{{font-size:13px;margin:14px 0 6px;color:var(--accent)}}.sub{{color:var(--mut);margin:0 0 14px;font-size:12px}}
.cards{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}}.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:84px}}
.card .n{{font-size:24px;font-weight:700}}.card .l{{color:var(--mut);font-size:11px;text-transform:uppercase}}
.c-crit .n{{color:var(--crit)}}.c-high .n{{color:var(--high)}}.c-med .n{{color:var(--med)}}.c-low .n{{color:var(--low)}}.c-info .n{{color:var(--info)}}.c-new .n{{color:var(--new)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-size:11px;text-transform:uppercase}}
td.fid{{color:var(--mut);white-space:nowrap;font-size:11px}}td.sev{{font-weight:700;white-space:nowrap}}
.s-critical td.sev{{color:var(--crit)}}.s-high td.sev{{color:var(--high)}}.s-medium td.sev{{color:var(--med)}}.s-low td.sev{{color:var(--low)}}.s-info td.sev{{color:var(--info)}}
td.conf{{font-size:10px;font-weight:700}}.c-confirmed{{color:var(--high)}}.c-likely{{color:var(--med)}}.c-potential{{color:var(--mut)}}
td.mod,td.host,td.port{{color:var(--mut);white-space:nowrap}}td.txt{{width:99%}}
.row-new{{background:color-mix(in srgb,var(--new) 10%,transparent)}}
.new{{color:#021;background:var(--new);border-radius:4px;padding:0 6px;font-size:10px;font-weight:700}}
.act{{color:#210;background:var(--med);border-radius:4px;padding:0 5px;font-size:10px;font-weight:700}}
.att{{color:var(--accent);border:1px solid var(--line);border-radius:4px;padding:0 5px;font-size:10px}}
.pill{{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:11px;color:var(--mut);margin-left:8px}}.pill-new{{color:var(--new);border-color:var(--new)}}
.phase{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 16px 12px;margin-bottom:12px}}.phase ol{{margin:0;padding-left:22px}}.phase li{{margin:8px 0}}
pre{{white-space:pre-wrap;color:var(--accent);margin:4px 0 0;font-size:12px}}
ul.rem{{list-style:none;padding:0}}ul.rem li{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}}.rem{{color:var(--mut)}}
details summary{{cursor:pointer;color:var(--mut)}}footer{{color:var(--mut);font-size:11px;margin-top:24px;text-align:center}}
</style></head><body><div class="wrap">
<h1>{html.escape(title)}</h1>
<p class="sub">EnumGod &middot; generated {gen} &middot; {len(sources)} run(s) {diffline} &middot; author Jeet Ramoliya</p>
<div class="cards">{cards}</div>
<p class="sub">Confidence &mdash; CONFIRMED {confc['CONFIRMED']} &middot; LIKELY {confc['LIKELY']} &middot; POTENTIAL {confc['POTENTIAL']}</p>
<h2>Attack playbook (by phase)</h2>{pb_section}
<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Sev</th><th>Conf</th><th>Module</th><th>Host</th><th>Port</th><th>Finding &amp; ATT&amp;CK</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan=7>No findings.</td></tr>'}</tbody></table>
<h2>Remediation</h2><ul class="rem">{rem_section}</ul>
<details><summary>Source runs ({len(sources)})</summary><ul>{srclist}</ul></details>
<footer>EnumGod &middot; author Jeet Ramoliya &middot; authorized use only</footer>
</div></body></html>"""

def main():
    ap = argparse.ArgumentParser(description="EnumGod report / merge / diff / playbook")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--out", default="enumgod-report.html")
    ap.add_argument("--diff", help="prior merged JSON; marks findings not in it as NEW")
    ap.add_argument("--save-merged", help="write canonical merged findings JSON")
    ap.add_argument("--title", default="EnumGod Report")
    a = ap.parse_args()

    files = find_json(a.paths)
    if not files:
        print("[-] no findings.json found under the given paths", file=sys.stderr)
        sys.exit(3)

    seen, merged, nexts = set(), [], []
    for f in files:
        fi, ns, _ = norm(f)
        for item in fi:
            k = ident(item)
            if k in seen:
                continue
            seen.add(k)
            merged.append(item)
        nexts += ns

    diff_set = None
    if a.diff and os.path.isfile(a.diff):
        try:
            prev = json.load(open(a.diff, encoding="utf-8-sig"))
            pf = prev.get("findings", [])
            diff_set = set()
            for x in pf:
                if isinstance(x, dict):
                    diff_set.add((x.get("id", "?"), x.get("host", "?")))
                elif isinstance(x, (list, tuple)):   # legacy tuple format
                    diff_set.add((x[0], x[2] if len(x) > 2 else "?"))
        except Exception as e:
            print(f"[!] could not read --diff file: {e}", file=sys.stderr)

    try:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(build_html(merged, nexts, a.title, diff_set, files))
        if a.save_merged:
            json.dump({"schema": "enumgod/1", "generated": datetime.datetime.now().isoformat(),
                       "sources": files, "findings": merged},
                      open(a.save_merged, "w", encoding="utf-8"), indent=2)
    except Exception as e:
        print(f"[-] report write failed: {e}", file=sys.stderr)
        sys.exit(2)

    c = {}
    for f in merged:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    newc = 0 if diff_set is None else sum(1 for m in merged if ident(m) not in diff_set)
    print(f"[+] {len(files)} run(s) -> {len(merged)} findings "
          f"(CRIT={c.get('CRITICAL',0)} HIGH={c.get('HIGH',0)} MED={c.get('MEDIUM',0)} "
          f"LOW={c.get('LOW',0)} INFO={c.get('INFO',0)}"
          f"{'' if diff_set is None else f' NEW={newc}'}), "
          f"{len(set((t,c2) for t,c2,_ in nexts))} playbook step(s)")
    print(f"[+] report: {a.out}" + (f"   merged: {a.save_merged}" if a.save_merged else ""))
    # exit: 1 = findings present, 0 = none
    sys.exit(1 if merged else 0)

if __name__ == "__main__":
    main()
