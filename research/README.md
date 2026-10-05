# EnumGod analysis engine (`research/`)

Turns raw module output into analysed intelligence — **without changing any enumeration
module**. It consumes the `findings.json` every EnumGod module already writes.

```
findings.json (any module/OS)
   -> normalize (canonical schema + redaction)
   -> asset/permission GRAPH (lightweight JSON nodes+edges)
   -> correlation RULES (research/rules/*.json)
   -> ATTACK-PATH analysis (BFS to Domain Admin / SYSTEM / root / cluster-admin ...)
   -> ANOMALY detection (baseline-relative, deterministic)
   -> NOVELTY classification (CVE + known-pattern cross-check)
   -> research candidates
   -> HTML / JSON / SARIF / CSV  (+ baseline diff)
```

Pure Python standard library (no new dependencies). Read-only analysis of already-collected
data — it never touches a target.

## Usage
```bash
python3 research/eg_analyze.py <run-dir|findings.json> [more...] \
    [--graph nodes_edges.json] [--baseline prev-merged.json] \
    [--out PREFIX] [--output-format html,json,sarif,csv] \
    [--attack-paths] [--anomalies] [--research]
```
With no stage flags, all stages run. `run-all.sh` invokes it automatically.

## Novelty terminology (important)
Never "zero-day confirmed". Labels: `KNOWN_PATTERN`, `CORRELATED_PATTERN`, `UNUSUAL_PATTERN`,
`RESEARCH_CANDIDATE`, `POTENTIALLY_NOVEL`. The strongest means *"no matching known vulnerability
identified by the local knowledge base; manual research and validation required."*

## Rules
`research/rules/*.json` — readable, version-controlled correlation rules:
`{id,title,severity,confidence,novelty,category,requires:[regex],any:[regex],impact,remediation}`.
A rule fires per-host when its `requires` regexes all match some finding on that host.

## Tests
`python3 research/tests/test_engine.py` — synthetic graph attack-path, RBCD correlation,
CVE novelty cross-check, redaction, HTML escaping, SARIF validity, baseline diff. No live
environment required.
