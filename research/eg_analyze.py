#!/usr/bin/env python3
# ============================================================================
# eg_analyze.py  -  EnumGod analysis pipeline        |  Author: Jeet Ramoliya
#
# Turns raw module output into analysed intelligence, end to end:
#   findings.json (any module) -> normalize -> asset/permission GRAPH ->
#   correlation RULES -> ATTACK-PATH analysis -> ANOMALY detection ->
#   NOVELTY classification (CVE/known-pattern cross-check) -> research candidates
#   -> HTML / JSON / SARIF / CSV reports (+ baseline diff).
#
# Consumes the canonical findings every EnumGod module already writes - existing
# modules are NOT modified. Pure Python standard library (no new dependencies).
# Read-only analysis of already-collected data; it never touches a target.
#
# USAGE
#   python3 research/eg_analyze.py <run-dir|findings.json> [more...] [options]
#     --graph FILE          also ingest a structured graph (nodes/edges JSON)
#     --baseline FILE       compare against a prior merged findings JSON (--diff)
#     --out PREFIX          output path prefix (default: enumgod-analysis)
#     --output-format LIST  comma list of: html,json,sarif,csv  (default html,json)
#     --attack-paths        include attack-path analysis (default on)
#     --anomalies           include anomaly detection (default on)
#     --research            include the research/novelty engine (default on)
#     --rules DIR           rules directory (default: research/rules)
#   Exit: 0 clean, 1 findings present, 2 error, 3 bad args.
#
# TERMINOLOGY: this tool never claims a confirmed zero-day. The strongest label is
# POTENTIALLY_NOVEL meaning "no matching known vulnerability identified by the local
# knowledge base; manual research and validation required."
# ============================================================================
import argparse, csv, datetime, glob, hashlib, html, importlib.util, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ---- reuse the canonical normalizer from tools/eg-report.py (single source of truth) ----
def _load_egreport():
    p = os.path.join(ROOT, "tools", "eg-report.py")
    spec = importlib.util.spec_from_file_location("egreport", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
EGR = _load_egreport()

NOVELTY = ["KNOWN_PATTERN", "CORRELATED_PATTERN", "UNUSUAL_PATTERN", "RESEARCH_CANDIDATE", "POTENTIALLY_NOVEL"]
HIGH_VALUE = re.compile(r"domain admin|enterprise admin|administrator|SYSTEM|\broot\b|cluster.?admin|"
                        r"global admin|owner|sa\b|krbtgt|sensitive|secret", re.I)

# ---------------------------- centralized redaction ----------------------------
REDACT = [
    (re.compile(r"(A(?:KIA|SIA)[0-9A-Z]{6})[0-9A-Z]{10}"), r"\1...REDACTED"),
    (re.compile(r"(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), r"\1...REDACTED.JWT"),
    (re.compile(r"(?i)(bearer\s+[A-Za-z0-9._-]{6})[A-Za-z0-9._-]{6,}"), r"\1...REDACTED"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY----- ...REDACTED"),
    (re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}"), r"\1...REDACTED"),
    (re.compile(r"(?i)(xox[baprs]-[0-9A-Za-z-]{4})[0-9A-Za-z-]{6,}"), r"\1...REDACTED"),
]
_KV = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|client_secret|token|access[_-]?key)\b(\s*[:=]\s*)(\S+)")
_CONN = re.compile(r"(?i)\b([a-z]+://[^:/\s]+:)[^@/\s]+(@)")

def redact(text):
    if not isinstance(text, str):
        text = str(text)
    for rx, repl in REDACT:
        text = rx.sub(repl, text)
    text = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}REDACTED", text)
    text = _CONN.sub(lambda m: f"{m.group(1)}REDACTED{m.group(2)}", text)
    return text

# ---------------------------- ingest findings ----------------------------
def ingest(paths):
    files = EGR.find_json(paths)
    finds, nexts = [], []
    seen = set()
    for f in files:
        fi, ns, _ = EGR.norm(f)
        for it in fi:
            it["evidence"] = redact(it.get("evidence", ""))
            it["description"] = redact(it.get("description", ""))
            it["title"] = redact(it.get("title", ""))
            it.setdefault("novelty", "KNOWN_PATTERN")
            k = (it["id"], it["host"])
            if k in seen:
                continue
            seen.add(k)
            finds.append(it)
        nexts += [(redact(t), redact(c), m) for t, c, m in ns]
    return files, finds, nexts

# ---------------------------- asset inventory ----------------------------
def asset_inventory(finds):
    hosts = {}
    for f in finds:
        h = f["host"]
        if h in ("?", "", None):
            continue
        a = hosts.setdefault(h, {"host": h, "findings": 0, "sources": set(), "max_sev": "INFO"})
        a["findings"] += 1
        a["sources"].add(f["source"])
        if EGR.SEV_ORDER.get(f["severity"], 9) < EGR.SEV_ORDER.get(a["max_sev"], 9):
            a["max_sev"] = f["severity"]
    for a in hosts.values():
        a["sources"] = sorted(a["sources"])
    return list(hosts.values())

# ---------------------------- graph ----------------------------
def new_graph():
    return {"nodes": {}, "edges": []}

def add_node(g, nid, ntype, label, **props):
    g["nodes"].setdefault(nid, {"id": nid, "type": ntype, "label": label, "props": props})
    return nid

def add_edge(g, src, dst, etype, **props):
    g["edges"].append({"src": src, "dst": dst, "type": etype, "props": props})

# derive graph edges from findings (heuristic, per category) so real runs yield paths
EDGE_SYNTH = [
    # (regex, node_type, node_label, edge_type, target_type, target_label)
    (r"writable service (binary|dir|registry)|unquoted service|ImagePath", "Service", "service", "CAN_WRITE", "Account", "SYSTEM"),
    (r"AlwaysInstallElevated", "Installer", "MSI installer", "CAN_EXECUTE", "Account", "SYSTEM"),
    (r"SeImpersonate|potato", "Token", "impersonation", "CAN_IMPERSONATE", "Account", "SYSTEM"),
    (r"sudo|NOPASSWD|GTFOBins|SUID|SGID|setuid|writable.*ld\.so|LD_PRELOAD", "Binary", "privileged binary", "CAN_EXECUTE", "Account", "root"),
    (r"docker\.sock|privileged container|CAP_SYS_ADMIN|no_root_squash|/host", "Container", "container", "CAN_MODIFY", "Account", "root"),
    (r"kerberoast|AS-REP|asrep", "Credential", "service ticket", "CAN_READ", "Account", "service account"),
    (r"DCSync", "Domain", "domain", "CAN_READ", "Account", "Domain Admin"),
    (r"delegation|RBCD|AllowedToAct", "Computer", "computer", "DELEGATES_TO", "Account", "Domain Admin"),
    (r"LAPS|gMSA|cpassword|GPP", "Credential", "stored secret", "CAN_READ", "Account", "Local Administrator"),
    (r"managed identity|IMDS|role credential", "CloudIdentity", "cloud identity", "HAS_ACCESS", "CloudResource", "Cloud Administrator"),
    (r"Can CREATE pods|clusterrolebinding|can .* secrets", "KubernetesService", "k8s api", "CAN_MODIFY", "Account", "Cluster Administrator"),
]

def graph_from_findings(finds):
    g = new_graph()
    you = add_node(g, "you", "Identity", "current principal")
    for f in finds:
        t = f["description"]
        for rx, ntype, nlabel, etype, ttype, tlabel in EDGE_SYNTH:
            if re.search(rx, t, re.I):
                host = f["host"] if f["host"] not in ("?", "", None) else "localhost"
                mid = add_node(g, f"{ntype}:{host}:{f['id']}", ntype, f"{nlabel} on {host}", host=host, finding=f["id"])
                tgt = add_node(g, f"{ttype}:{tlabel}", ttype, tlabel, privileged=True)
                add_edge(g, you, mid, etype, finding=f["id"], confidence=f["confidence"])
                add_edge(g, mid, tgt, "RUNS_AS" if ntype == "Service" else "GRANTS", finding=f["id"])
    return g

def merge_graph(g, ext):
    # ext: {"nodes":[{id,type,label,...}], "edges":[{src,dst,type,...}]}
    for n in ext.get("nodes", []):
        g["nodes"].setdefault(n["id"], {"id": n["id"], "type": n.get("type", "Node"),
                                        "label": n.get("label", n["id"]), "props": {k: v for k, v in n.items() if k not in ("id", "type", "label")}})
    for e in ext.get("edges", []):
        g["edges"].append({"src": e["src"], "dst": e["dst"], "type": e.get("type", "CONNECTS_TO"),
                           "props": {k: v for k, v in e.items() if k not in ("src", "dst", "type")}})
    return g

# ---------------------------- attack-path analysis (BFS) ----------------------------
def is_high_value(node):
    if node.get("props", {}).get("privileged"):
        return True
    return bool(HIGH_VALUE.search(node.get("label", "") + " " + node.get("id", "")))

def attack_paths(g, max_paths=40, max_depth=8):
    adj = {}
    for e in g["edges"]:
        adj.setdefault(e["src"], []).append((e["dst"], e["type"]))
    nodes = g["nodes"]
    targets = {nid for nid, n in nodes.items() if is_high_value(n)}
    starts = [nid for nid, n in nodes.items()
              if nid not in targets and (n["type"] in ("Identity", "User") or nid == "you")]
    if not starts:
        starts = [nid for nid in nodes if nid not in targets]
    paths = []
    for s in starts:
        # BFS shortest path to any target
        from collections import deque
        q = deque([(s, [s], [])])
        seen = {s}
        while q:
            cur, pnodes, pedges = q.popleft()
            if len(pnodes) > max_depth:
                continue
            for dst, et in adj.get(cur, []):
                if dst in seen:
                    continue
                npn, npe = pnodes + [dst], pedges + [et]
                if dst in targets:
                    paths.append({"start": s, "target": dst, "nodes": npn, "edges": npe, "hops": len(npe)})
                    break
                seen.add(dst)
                q.append((dst, npn, npe))
            if len(paths) >= max_paths:
                break
        if len(paths) >= max_paths:
            break
    # describe
    out = []
    for p in sorted(paths, key=lambda x: x["hops"]):
        steps = []
        for i, nid in enumerate(p["nodes"]):
            lbl = nodes.get(nid, {}).get("label", nid)
            if i < len(p["edges"]):
                steps.append(f"{lbl} --[{p['edges'][i]}]-->")
            else:
                steps.append(lbl)
        out.append({
            "id": f"RT-PATH-{hashlib.md5(('>'.join(p['nodes'])).encode()).hexdigest()[:4]}",
            "start": nodes.get(p["start"], {}).get("label", p["start"]),
            "target": nodes.get(p["target"], {}).get("label", p["target"]),
            "hops": p["hops"], "chain": " ".join(steps),
            "confidence": "LIKELY" if p["hops"] <= 2 else "POTENTIAL",
        })
    return out

# ---------------------------- rule engine ----------------------------
def load_rules(rules_dir):
    rules = []
    for fp in sorted(glob.glob(os.path.join(rules_dir, "**", "*.json"), recursive=True)):
        try:
            data = json.load(open(fp, encoding="utf-8-sig"))
            for r in (data if isinstance(data, list) else [data]):
                r["_file"] = os.path.relpath(fp, ROOT)
                rules.append(r)
        except Exception as e:
            print(f"[!] bad rule {fp}: {e}", file=sys.stderr)
    return rules

def _match_terms(terms, blob, mode="all"):
    if not terms:
        return True
    res = [re.search(t, blob, re.I) for t in terms]
    return all(res) if mode == "all" else any(res)

def run_rules(rules, finds):
    """Correlation: a rule fires per-host when all its 'requires' regexes match some finding on that host."""
    by_host = {}
    for f in finds:
        by_host.setdefault(f["host"], []).append(f)
    out = []
    for host, hf in by_host.items():
        blob = "\n".join(f["description"] for f in hf)
        for r in rules:
            req = r.get("requires", [])
            any_terms = r.get("any", [])
            if req and not _match_terms(req, blob, "all"):
                continue
            if any_terms and not _match_terms(any_terms, blob, "any"):
                continue
            if not req and not any_terms:
                continue
            ev = [f["id"] for f in hf if any(re.search(t, f["description"], re.I) for t in (req + any_terms))]
            out.append({
                "id": f"{r.get('id','RT-RULE')}-{hashlib.md5((host+r.get('id','')).encode()).hexdigest()[:3]}",
                "rule_id": r.get("id", "RT-RULE"),
                "title": r.get("title", "Correlated condition"),
                "severity": r.get("severity", "MEDIUM"),
                "confidence": r.get("confidence", "POTENTIAL"),
                "novelty": r.get("novelty", "CORRELATED_PATTERN"),
                "category": r.get("category", "Correlation"),
                "host": host,
                "source": "correlation:" + os.path.basename(r.get("_file", "rule")),
                "description": r.get("description", r.get("title", "")),
                "impact": r.get("impact", ""),
                "remediation": r.get("remediation", ""),
                "evidence": ev,
                "attack_path": r.get("attack_path", []),
                "active_check": False,
                "timestamp": "",
            })
    return out

# ---------------------------- anomaly detection ----------------------------
def anomalies(finds, baseline_cats):
    """Deterministic, explainable: a finding category/host unseen in the baseline is unusual."""
    out = []
    for f in finds:
        cat = f["category"]
        if baseline_cats is not None and cat not in baseline_cats and f["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
            out.append({
                "id": f"RT-ANOM-{hashlib.md5((f['id']+f['host']).encode()).hexdigest()[:4]}",
                "title": f"Unusual finding category for this environment: {cat}",
                "severity": f["severity"], "confidence": "POTENTIAL", "novelty": "UNUSUAL_PATTERN",
                "category": "Anomaly", "host": f["host"], "source": "anomaly-detector",
                "baseline": "category absent from baseline", "observed": f["title"],
                "reason": f"category '{cat}' did not appear in the baseline run; review.",
                "description": f"Anomaly: {f['title']}", "evidence": [f["id"]],
                "impact": "", "remediation": "", "active_check": False, "timestamp": "",
            })
    return out

# ---------------------------- novelty classification ----------------------------
def load_cve_terms():
    terms = set()
    p = os.path.join(ROOT, "data", "cve-db.txt")
    if os.path.isfile(p):
        for line in open(p, encoding="utf-8-sig"):
            m = re.findall(r"CVE-\d{4}-\d+", line)
            terms.update(m)
            parts = line.split("|")
            if len(parts) > 2 and parts[0] in ("linux", "windows", "glibc", "sudo", "polkit"):
                terms.add(parts[2].strip().lower())
    return terms

def classify_novelty(item, cve_terms, known_attack):
    text = (item.get("description", "") + " " + item.get("title", "")).lower()
    # 1) local CVE knowledge base
    if any(c.lower() in text for c in cve_terms):
        item["novelty"] = "KNOWN_PATTERN"
        item["known_cve"] = next((c for c in cve_terms if c.lower() in text), "")
        return item
    # 2) known attack pattern (ATT&CK mapping present)
    tid, _ = EGR.first(EGR.ATTACK, item.get("description", ""))
    if tid:
        item.setdefault("novelty", "KNOWN_PATTERN")
        item["attack"] = tid
        return item
    # 3) correlation/research rules keep their declared novelty
    if item.get("novelty") in ("CORRELATED_PATTERN", "RESEARCH_CANDIDATE", "POTENTIALLY_NOVEL", "UNUSUAL_PATTERN"):
        item["known_cve"] = ""
        item["novelty_note"] = "No matching known vulnerability identified by the local knowledge base; manual research/validation required."
        return item
    item["novelty"] = "KNOWN_PATTERN"
    return item

# ---------------------------- baseline diff ----------------------------
def diff_baseline(finds, baseline_path):
    prev = {}
    try:
        data = json.load(open(baseline_path, encoding="utf-8-sig"))
        for x in data.get("findings", []):
            if isinstance(x, dict):
                prev[(x.get("id"), x.get("host"))] = x
            elif isinstance(x, (list, tuple)):
                prev[(x[0], x[2] if len(x) > 2 else "?")] = {}
    except Exception as e:
        print(f"[!] baseline read failed: {e}", file=sys.stderr)
        return [], [], set()
    cur = {(f["id"], f["host"]) for f in finds}
    new = [f for f in finds if (f["id"], f["host"]) not in prev]
    resolved = [k for k in prev if k not in cur]
    return new, resolved, set(prev.keys())

# ---------------------------- outputs ----------------------------
def esc(s):
    return html.escape(str(s))

def write_json(path, payload):
    json.dump(payload, open(path, "w", encoding="utf-8"), indent=2, default=list)

def write_csv(path, finds):
    cols = ["id", "severity", "confidence", "novelty", "category", "host", "source", "title"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for f in finds:
            w.writerow({c: f.get(c, "") for c in cols})

def write_sarif(path, finds):
    rules_seen, results = {}, []
    for f in finds:
        rid = f["id"].rsplit("-", 1)[0] if "-" in f["id"] else f["id"]
        rules_seen.setdefault(rid, {"id": rid, "name": f.get("category", "finding"),
                                    "shortDescription": {"text": f.get("title", "")[:120]}})
        lvl = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(f["severity"], "note")
        results.append({
            "ruleId": rid, "level": lvl,
            "message": {"text": f"{f.get('title','')} [{f['severity']}/{f['confidence']}/{f.get('novelty','')}]"},
            "properties": {"confidence": f["confidence"], "novelty": f.get("novelty", ""),
                           "host": f.get("host", ""), "source": f.get("source", "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("host", "unknown")}}}],
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "EnumGod", "informationUri": "https://github.com/Jeetramoliya/RedTeamEnumerationTools",
                                           "rules": list(rules_seen.values())}}, "results": results}]}
    write_json(path, sarif)

def write_html(path, title, finds, assets, paths, research, anoms, newf, resolved, sources, modes):
    sev_order = EGR.SEV_ORDER
    sevc = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in finds:
        sevc[f["severity"]] = sevc.get(f["severity"], 0) + 1
    def frow(f):
        nov = f.get("novelty", "")
        novcls = "nv-res" if nov in ("RESEARCH_CANDIDATE", "POTENTIALLY_NOVEL") else ("nv-cor" if nov == "CORRELATED_PATTERN" else "nv-known")
        return (f'<tr class="s-{f["severity"].lower()}"><td class="fid">{esc(f["id"])}</td>'
                f'<td class="sev">{esc(f["severity"])}</td><td class="conf">{esc(f["confidence"])}</td>'
                f'<td class="{novcls}">{esc(nov)}</td><td class="mod">{esc(f.get("source",""))}</td>'
                f'<td class="host">{esc(f.get("host",""))}</td><td>{esc(f.get("description",""))}</td></tr>')
    def sec_rows(items):
        return "".join(frow(f) for f in sorted(items, key=lambda x: sev_order.get(x["severity"], 9)))
    pr = "".join(f'<li><b>{esc(p["start"])}</b> &rarr; <b>{esc(p["target"])}</b> '
                 f'<span class="pill">{p["hops"]} hop(s) &middot; {esc(p["confidence"])}</span>'
                 f'<pre>{esc(p["chain"])}</pre></li>' for p in paths) or "<li>No attack paths derived.</li>"
    rc = ""
    for r in research:
        rc += (f'<div class="rc"><h3>{esc(r["id"])} &middot; {esc(r.get("title",""))} '
               f'<span class="pill nv-res">{esc(r.get("novelty",""))}</span></h3>'
               f'<p><b>Severity/Confidence:</b> {esc(r["severity"])} / {esc(r["confidence"])}</p>'
               f'<p><b>Observed:</b> {esc(r.get("description",""))}</p>'
               f'<p><b>Why unusual:</b> {esc(r.get("impact","") or "see correlated evidence")}</p>'
               f'<p><b>Known-pattern comparison:</b> {esc(r.get("novelty_note","Matches a known pattern."))}</p>'
               f'<p><b>Evidence:</b> {esc(", ".join(r.get("evidence",[])) or "-")}</p>'
               f'<p><b>Validation required:</b> {esc(r.get("remediation","") or "Manually verify the correlated conditions before acting.")}</p></div>')
    rc = rc or "<p class='sub'>No research candidates in this run.</p>"
    ai = "".join(f'<tr><td>{esc(a["host"])}</td><td class="sev">{esc(a["max_sev"])}</td>'
                 f'<td>{a["findings"]}</td><td class="mod">{esc(", ".join(a["sources"]))}</td></tr>' for a in assets) or "<tr><td colspan=4>No hosts.</td></tr>"
    an = "".join(f'<li><b>{esc(a["title"])}</b> <span class="pill">{esc(a["host"])}</span><br>'
                 f'<span class="sub">baseline: {esc(a.get("baseline",""))} &middot; {esc(a.get("reason",""))}</span></li>' for a in anoms) or "<li>No anomalies (or no baseline supplied).</li>"
    newrows = sec_rows(newf) if newf else "<tr><td colspan=7>(no baseline / none new)</td></tr>"
    resv = "".join(f"<li>{esc(k[0])} on {esc(k[1])}</li>" for k in resolved) or "<li>-</li>"
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)}</title>
<style>
:root{{--bg:#0f1419;--card:#171d26;--fg:#e6edf3;--mut:#8b98a5;--line:#2a3340;--crit:#ff3860;--high:#ff5c5c;--med:#ffb454;--low:#6cb6ff;--info:#6b7684;--res:#c77dff;--cor:#58a6ff;--accent:#3fb950;}}
@media (prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--mut:#656d76;--line:#d0d7de;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;padding:22px 16px}}
.wrap{{max-width:1180px;margin:0 auto}}h1{{font-size:20px;margin:0 0 2px}}h2{{font-size:15px;margin:24px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}}h3{{font-size:13px;margin:6px 0}}
.sub{{color:var(--mut);font-size:12px}}.cards{{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:80px}}.card .n{{font-size:22px;font-weight:700}}.card .l{{color:var(--mut);font-size:11px;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:8px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--mut);font-size:11px;text-transform:uppercase}}
td.sev{{font-weight:700}}.s-critical td.sev{{color:var(--crit)}}.s-high td.sev{{color:var(--high)}}.s-medium td.sev{{color:var(--med)}}.s-low td.sev{{color:var(--low)}}
td.fid,td.mod,td.host,td.conf{{color:var(--mut);white-space:nowrap;font-size:11px}}
.nv-res{{color:var(--res);font-weight:700}}.nv-cor{{color:var(--cor)}}.nv-known{{color:var(--mut)}}
.pill{{border:1px solid var(--line);border-radius:20px;padding:1px 8px;font-size:11px;color:var(--mut)}}
ol,ul{{padding-left:20px}}li{{margin:6px 0}}pre{{white-space:pre-wrap;color:var(--accent);margin:3px 0 0;font-size:12px}}
.rc{{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--res);border-radius:8px;padding:8px 14px;margin:8px 0}}
footer{{color:var(--mut);font-size:11px;margin-top:20px;text-align:center}}
</style></head><body><div class="wrap">
<h1>{esc(title)}</h1>
<p class="sub">EnumGod analysis &middot; {gen} &middot; modes: {esc(modes)} &middot; {len(sources)} run(s) &middot; author Jeet Ramoliya</p>
<div class="cards">
<div class="card"><div class="n">{sevc['CRITICAL']}</div><div class="l">Critical</div></div>
<div class="card"><div class="n">{sevc['HIGH']}</div><div class="l">High</div></div>
<div class="card"><div class="n">{sevc['MEDIUM']}</div><div class="l">Medium</div></div>
<div class="card"><div class="n">{len(paths)}</div><div class="l">Attack paths</div></div>
<div class="card"><div class="n">{len(research)}</div><div class="l">Research cand.</div></div>
<div class="card"><div class="n">{len(anoms)}</div><div class="l">Anomalies</div></div>
</div>
<h2>Asset inventory</h2><table><thead><tr><th>Host</th><th>Max sev</th><th>Findings</th><th>Modules</th></tr></thead><tbody>{ai}</tbody></table>
<h2>Attack paths</h2><ul>{pr}</ul>
<h2>Research candidates</h2>{rc}
<h2>Anomalies vs baseline</h2><ul>{an}</ul>
<h2>New since baseline</h2><table><thead><tr><th>ID</th><th>Sev</th><th>Conf</th><th>Novelty</th><th>Module</th><th>Host</th><th>Finding</th></tr></thead><tbody>{newrows}</tbody></table>
<h2>Resolved since baseline</h2><ul>{resv}</ul>
<h2>All findings ({len(finds)})</h2><table><thead><tr><th>ID</th><th>Sev</th><th>Conf</th><th>Novelty</th><th>Module</th><th>Host</th><th>Finding</th></tr></thead><tbody>{sec_rows(finds)}</tbody></table>
<footer>EnumGod &middot; novelty labels are research leads, never confirmed zero-days &middot; authorized use only</footer>
</div></body></html>"""
    open(path, "w", encoding="utf-8").write(doc)

# ---------------------------- main ----------------------------
def main():
    ap = argparse.ArgumentParser(description="EnumGod analysis pipeline")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--graph")
    ap.add_argument("--baseline")
    ap.add_argument("--out", default="enumgod-analysis")
    ap.add_argument("--output-format", default="html,json")
    ap.add_argument("--rules", default=os.path.join(HERE, "rules"))
    ap.add_argument("--attack-paths", action="store_true")
    ap.add_argument("--anomalies", action="store_true")
    ap.add_argument("--research", action="store_true")
    ap.add_argument("--title", default="EnumGod Analysis")
    a = ap.parse_args()
    # default: everything on unless the user selected specific stages
    all_on = not (a.attack_paths or a.anomalies or a.research)
    do_paths = all_on or a.attack_paths
    do_anom = all_on or a.anomalies
    do_res = all_on or a.research

    files, finds, nexts = ingest(a.paths)
    if not files:
        print("[-] no findings.json found", file=sys.stderr)
        sys.exit(3)

    cve_terms = load_cve_terms()
    rules = load_rules(a.rules)
    correlations = run_rules(rules, finds) if do_res else []

    g = graph_from_findings(finds)
    if a.graph and os.path.isfile(a.graph):
        try:
            merge_graph(g, json.load(open(a.graph, encoding="utf-8-sig")))
        except Exception as e:
            print(f"[!] graph ingest failed: {e}", file=sys.stderr)
    paths = attack_paths(g) if do_paths else []

    baseline_cats = None
    newf, resolved = [], []
    if a.baseline and os.path.isfile(a.baseline):
        try:
            bdata = json.load(open(a.baseline, encoding="utf-8-sig"))
            baseline_cats = {x.get("category") for x in bdata.get("findings", []) if isinstance(x, dict)}
        except Exception:
            baseline_cats = None
        newf, resolved, _ = diff_baseline(finds, a.baseline)
    anoms = anomalies(finds, baseline_cats) if do_anom else []

    # classify novelty on everything; research candidates = correlations/anoms not explained by known patterns
    for item in finds + correlations + anoms:
        classify_novelty(item, cve_terms, EGR.ATTACK)
    research = [x for x in (correlations + anoms)
               if x.get("novelty") in ("CORRELATED_PATTERN", "UNUSUAL_PATTERN", "RESEARCH_CANDIDATE", "POTENTIALLY_NOVEL")]

    assets = asset_inventory(finds)
    all_items = finds + correlations + anoms

    fmts = [x.strip() for x in a.output_format.split(",") if x.strip()]
    modes = ",".join([m for m, on in (("attack-paths", do_paths), ("anomalies", do_anom), ("research", do_res)) if on])
    try:
        if "json" in fmts:
            write_json(a.out + ".json", {"schema": "enumgod-analysis/1", "generated": datetime.datetime.now().isoformat(),
                       "sources": files, "assets": assets, "findings": all_items, "graph": g,
                       "attack_paths": paths, "research_candidates": research, "anomalies": anoms,
                       "new_since_baseline": [f["id"] for f in newf], "resolved_since_baseline": [list(k) for k in resolved]})
        if "html" in fmts:
            write_html(a.out + ".html", a.title, all_items, assets, paths, research, anoms, newf, resolved, files, modes)
        if "sarif" in fmts:
            write_sarif(a.out + ".sarif", all_items)
        if "csv" in fmts:
            write_csv(a.out + ".csv", all_items)
    except Exception as e:
        print(f"[-] report write failed: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"[+] {len(files)} run(s): {len(finds)} findings, {len(correlations)} correlations, "
          f"{len(paths)} attack paths, {len(research)} research candidates, {len(anoms)} anomalies")
    print(f"[+] outputs: {a.out}.({'/'.join(fmts)})")
    sys.exit(1 if all_items else 0)

if __name__ == "__main__":
    main()
