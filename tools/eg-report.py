#!/usr/bin/env python3
# ============================================================================
# eg-report.py  -  EnumGod report & merge/diff tool   |   Author: Jeet Ramoliya
#
# Merges any number of EnumGod findings.json files (from any module / host /
# platform) into one ranked, self-contained HTML report. With --diff it marks
# findings that are NEW since a previous run - so after you re-run as a captured
# identity you instantly see what fresh access the hop unlocked.
#
# USAGE
#   python3 eg-report.py <run-dir|findings.json> [more...] [options]
#   python3 eg-report.py ./loot -o report.html --save-merged merged.json
#   python3 eg-report.py ./loot2 --diff merged.json -o report2.html
#
# OPTIONS
#   -o, --out FILE         HTML output (default: enumgod-report.html)
#   --diff PREV.json       mark findings not present in this prior merged JSON
#   --save-merged FILE     write the normalised merged findings as JSON
#   --title TEXT           report title
#
# Pure standard library. Operator-side tool (run where you triage, not the target).
# ============================================================================
import argparse, glob, html, json, os, sys, datetime

SEV_ORDER = {"HIGH": 0, "MED": 1, "INFO": 2}

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
    # .../<kind>_<target>_<ts>/findings.json  ->  <kind>
    d = os.path.basename(os.path.dirname(os.path.abspath(path)))
    for sep in ("_",):
        if sep in d:
            return d.split(sep)[0]
    return d or "run"

def norm(path):
    """Return list of (sev, text, host, module) from one findings.json (any EnumGod shape)."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"[!] bad json {path}: {e}", file=sys.stderr)
        return []
    host = data.get("host") or data.get("identity") or data.get("domain") or "?"
    module = data.get("module") or module_from_path(path)
    # findings live either flat (high/med/info) or nested under "findings"
    src = data.get("findings", data)
    out = []
    for sev in ("high", "med", "info"):
        for item in (src.get(sev) or []):
            text = item if isinstance(item, str) else json.dumps(item)
            # strip a leading "[HIGH] " style tag if present
            for tag in ("[HIGH] ", "[MED ] ", "[MED] ", "[INFO] "):
                if text.startswith(tag):
                    text = text[len(tag):]
            out.append((sev.upper(), text.strip(), str(host), str(module)))
    return out

def key(f):
    return (f[0], f[1])  # dedupe/diff on severity+text

def build_html(findings, title, diff_keys, sources):
    counts = {"HIGH": 0, "MED": 0, "INFO": 0}
    for sev, *_ in findings:
        counts[sev] = counts.get(sev, 0) + 1
    new_n = sum(1 for f in findings if diff_keys is not None and key(f) not in diff_keys)
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = []
    for sev, text, host, module in sorted(findings, key=lambda f: (SEV_ORDER.get(f[0], 9), f[3], f[1])):
        is_new = diff_keys is not None and key((sev, text)) not in diff_keys
        badge = '<span class="new">NEW</span>' if is_new else ""
        rows.append(
            f'<tr class="s-{sev.lower()}{" row-new" if is_new else ""}">'
            f'<td class="sev">{sev}</td>'
            f'<td class="mod">{html.escape(module)}</td>'
            f'<td class="host">{html.escape(host)}</td>'
            f'<td class="txt">{html.escape(text)} {badge}</td></tr>'
        )
    srclist = "".join(f"<li>{html.escape(s)}</li>" for s in sources)
    diffline = (f'<span class="pill pill-new">{new_n} new</span>' if diff_keys is not None else "")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{--bg:#0f1419;--card:#171d26;--fg:#e6edf3;--mut:#8b98a5;--line:#2a3340;
--high:#ff5c5c;--med:#ffb454;--info:#6b7684;--new:#3fb950;--accent:#58a6ff;}}
@media (prefers-color-scheme:light){{:root:not([data-theme=dark]){{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--mut:#656d76;--line:#d0d7de;--info:#8b949e;}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:24px 16px}}
.wrap{{max-width:1100px;margin:0 auto}}
h1{{font-size:20px;margin:0 0 2px}}.sub{{color:var(--mut);margin:0 0 16px;font-size:12px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:96px}}
.card .n{{font-size:26px;font-weight:700}}.card .l{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.c-high .n{{color:var(--high)}}.c-med .n{{color:var(--med)}}.c-info .n{{color:var(--info)}}.c-new .n{{color:var(--new)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;position:sticky;top:0;background:var(--card)}}
td.sev{{font-weight:700;white-space:nowrap}}
.s-high td.sev{{color:var(--high)}}.s-med td.sev{{color:var(--med)}}.s-info td.sev{{color:var(--info)}}
td.mod,td.host{{color:var(--mut);white-space:nowrap}}td.txt{{width:99%}}
.row-new{{background:color-mix(in srgb,var(--new) 10%,transparent)}}
.new{{color:#021;background:var(--new);border-radius:4px;padding:0 6px;font-size:10px;font-weight:700;margin-left:6px}}
.pill{{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:11px;color:var(--mut);margin-left:8px}}
.pill-new{{color:var(--new);border-color:var(--new)}}
details{{margin-top:18px}}summary{{cursor:pointer;color:var(--mut)}}
footer{{color:var(--mut);font-size:11px;margin-top:22px;text-align:center}}
pre{{white-space:pre-wrap;color:var(--accent);margin:4px 0 0}}
</style></head><body><div class="wrap">
<h1>{html.escape(title)}</h1>
<p class="sub">EnumGod consolidated report &middot; generated {gen} &middot; {len(sources)} source run(s) {diffline}</p>
<div class="cards">
<div class="card c-high"><div class="n">{counts['HIGH']}</div><div class="l">High</div></div>
<div class="card c-med"><div class="n">{counts['MED']}</div><div class="l">Medium</div></div>
<div class="card c-info"><div class="n">{counts['INFO']}</div><div class="l">Info</div></div>
{'<div class="card c-new"><div class="n">'+str(new_n)+'</div><div class="l">New</div></div>' if diff_keys is not None else ''}
</div>
<table><thead><tr><th>Sev</th><th>Module</th><th>Host</th><th>Finding</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan=4>No findings.</td></tr>'}</tbody></table>
<details><summary>Source runs ({len(sources)})</summary><ul>{srclist}</ul></details>
<footer>EnumGod &middot; author Jeet Ramoliya &middot; authorized use only</footer>
</div></body></html>"""

def main():
    ap = argparse.ArgumentParser(description="EnumGod report & merge/diff")
    ap.add_argument("paths", nargs="+", help="run dir(s) or findings.json file(s)")
    ap.add_argument("-o", "--out", default="enumgod-report.html")
    ap.add_argument("--diff", help="prior merged JSON; marks findings not present in it as NEW")
    ap.add_argument("--save-merged", help="write normalised merged findings to this JSON")
    ap.add_argument("--title", default="EnumGod Report")
    a = ap.parse_args()

    files = find_json(a.paths)
    if not files:
        print("[-] no findings.json found under the given paths", file=sys.stderr)
        sys.exit(1)

    seen, merged = set(), []
    for f in files:
        for item in norm(f):
            k = key(item)
            if k in seen:
                continue
            seen.add(k)
            merged.append(item)

    diff_keys = None
    if a.diff and os.path.isfile(a.diff):
        try:
            prev = json.load(open(a.diff, encoding="utf-8-sig"))
            diff_keys = {(x[0], x[1]) for x in prev.get("findings", [])}
        except Exception as e:
            print(f"[!] could not read --diff file: {e}", file=sys.stderr)

    htmltxt = build_html(merged, a.title, diff_keys, files)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(htmltxt)

    if a.save_merged:
        with open(a.save_merged, "w", encoding="utf-8") as fh:
            json.dump({"generated": datetime.datetime.now().isoformat(),
                       "sources": files, "findings": merged}, fh, indent=2)

    c = {"HIGH": 0, "MED": 0, "INFO": 0}
    for s, *_ in merged:
        c[s] = c.get(s, 0) + 1
    newc = 0 if diff_keys is None else sum(1 for m in merged if key(m) not in diff_keys)
    print(f"[+] {len(files)} run(s) -> {len(merged)} unique findings "
          f"(HIGH={c['HIGH']} MED={c['MED']} INFO={c['INFO']}"
          f"{'' if diff_keys is None else f' NEW={newc}'})")
    print(f"[+] report: {a.out}" + (f"   merged: {a.save_merged}" if a.save_merged else ""))

if __name__ == "__main__":
    main()
