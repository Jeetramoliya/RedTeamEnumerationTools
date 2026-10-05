#!/usr/bin/env python3
# EnumGod analysis-engine tests (no live domain needed). Run: python3 research/tests/test_engine.py
import json, os, sys, tempfile, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
spec = importlib.util.spec_from_file_location("eg_analyze", os.path.join(ROOT, "research", "eg_analyze.py"))
EG = importlib.util.module_from_spec(spec); spec.loader.exec_module(EG)

PASS = 0; FAIL = 0
def check(name, cond):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS {name}")
    else: FAIL += 1; print(f"  FAIL {name}")

def mkrun(tmp, name, findings):
    d = os.path.join(tmp, f"{name}_HOST_x"); os.makedirs(d, exist_ok=True)
    json.dump(findings, open(os.path.join(d, "findings.json"), "w"))
    return d

print("[*] attack-path over synthetic graph (USER_A -> ... -> ADMIN_A)")
g = EG.new_graph()
EG.merge_graph(g, json.load(open(os.path.join(HERE, "synthetic_graph.json"))))
paths = EG.attack_paths(g)
check("found a path to the privileged target", any("ADMIN_A" in p["target"] for p in paths))
check("path is multi-hop (4 hops)", any(p["hops"] == 4 for p in paths))

print("[*] correlation -> research candidate (RBCD + MAQ)")
with tempfile.TemporaryDirectory() as tmp:
    mkrun(tmp, "rt-adenum", {"host": "DC01", "source": "rt-adenum",
          "high": ["RBCD configured on SRV (msDS-AllowedToActOnBehalfOfOtherIdentity set)",
                   "ms-DS-MachineAccountQuota=10 - any user can add machine accounts"], "med": [], "info": []})
    files, finds, nexts = EG.ingest([tmp])
    rules = EG.load_rules(os.path.join(ROOT, "research", "rules"))
    corr = EG.run_rules(rules, finds)
    check("RBCD correlation rule fired", any(c["rule_id"] == "RT-AD-RBCD" for c in corr))

print("[*] novelty: known CVE text -> KNOWN_PATTERN, not novel")
item = {"description": "CVE-2022-0847 Dirty Pipe kernel built before fix", "title": "x", "novelty": "RESEARCH_CANDIDATE"}
EG.classify_novelty(item, EG.load_cve_terms(), EG.EGR.ATTACK)
check("known CVE reclassified to KNOWN_PATTERN", item["novelty"] == "KNOWN_PATTERN")

print("[*] redaction: secrets masked")
r = EG.redact("password=Sup3rSecret! and AKIAIOSFODNN7EXAMPLE and Authorization: Bearer abcdef123456789")
check("password masked", "Sup3rSecret" not in r)
check("aws key masked", "IOSFODNN7EXAMPLE" not in r)
check("bearer masked", "abcdef123456789" not in r)

print("[*] HTML escaping of hostile evidence")
with tempfile.TemporaryDirectory() as tmp:
    mkrun(tmp, "net-sweep", {"host": "<img src=x onerror=alert(1)>", "source": "net",
          "high": ["<script>alert('xss')</script> finding"], "med": [], "info": []})
    files, finds, nexts = EG.ingest([tmp])
    out = os.path.join(tmp, "rep")
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        try: EG.write_html(out + ".html", "t", finds, EG.asset_inventory(finds), [], [], [], [], [], files, "x")
        except SystemExit: pass
    htmltxt = open(out + ".html", encoding="utf-8").read()
    check("no raw <script> in HTML", "<script>alert('xss')</script>" not in htmltxt)
    check("escaped entity present", "&lt;script&gt;" in htmltxt)

print("[*] SARIF + JSON validity")
with tempfile.TemporaryDirectory() as tmp:
    mkrun(tmp, "rt-linenum", {"host": "lin01", "source": "rt-linenum",
          "high": ["Writable service binary FooSvc"], "med": [], "info": []})
    files, finds, nexts = EG.ingest([tmp])
    EG.write_sarif(os.path.join(tmp, "o.sarif"), finds)
    s = json.load(open(os.path.join(tmp, "o.sarif")))
    check("SARIF version 2.1.0", s.get("version") == "2.1.0")
    check("SARIF has results", len(s["runs"][0]["results"]) >= 1)

print("[*] baseline diff (new vs resolved)")
with tempfile.TemporaryDirectory() as tmp:
    mkrun(tmp, "m", {"host": "h1", "source": "m", "high": ["New thing here"], "med": [], "info": []})
    files, finds, nexts = EG.ingest([tmp])
    base = os.path.join(tmp, "base.json")
    json.dump({"findings": [{"id": "RT-OLD-0000", "host": "h1"}]}, open(base, "w"))
    newf, resolved, _ = EG.diff_baseline(finds, base)
    check("new finding detected", len(newf) >= 1)
    check("resolved finding detected", ("RT-OLD-0000", "h1") in resolved)

print(f"\n=== {PASS} passed, {FAIL} failed ===")
sys.exit(1 if FAIL else 0)
