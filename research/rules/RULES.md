# EnumGod correlation rules

Rules are plain JSON. The engine loads **every `*.json` under this directory (recursively)**,
so community packs just drop into `research/rules/community/`. No code change needed.

## Schema
```json
{
  "id": "RT-AREA-NAME",            // stable prefix; becomes the finding id prefix
  "title": "Short human title",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "CONFIRMED|LIKELY|POTENTIAL",   // keep POTENTIAL for correlation-only
  "novelty": "KNOWN_PATTERN|CORRELATED_PATTERN|RESEARCH_CANDIDATE",
  "category": "Active Directory|Cloud|Windows Privilege Escalation|...",
  "requires": ["regex1", "regex2"], // ALL must match some finding on the same host
  "any":      ["regexA", "regexB"], // at least one must match (optional)
  "impact": "What the chain yields.",
  "remediation": "How to fix it.",
  "description": "What was observed and the chain."
}
```

## How matching works
A rule fires **per host** when every `requires` regex (and ≥1 `any`, if present) matches the
text of some finding on that host. Match against the strings the enum modules actually emit —
grep the modules for the exact wording (e.g. `"Unconstrained delegation"`, `"AD CS enterprise CA"`).

## Rules of the road
- **Correlation only.** Rules never execute anything. Keep confidence `POTENTIAL` unless the
  co-occurrence is genuinely conclusive.
- **Multi-signal.** Don't restate a single finding — a rule should combine signals a single
  detector misses. One-condition rules are usually noise.
- **No secrets, no version-only "vulnerable".** Follow the `VERSION_MATCH` discipline.
- **Test it:** add your pack, run `python3 research/eg_analyze.py <a run dir> --output-format json`
  and confirm your rule id appears in `research_candidates`.

## Contributing a pack
1. Create `research/rules/community/<your-pack>.json` (a JSON array of rule objects).
2. Prefix ids with your area, e.g. `RT-WEB-...`, `RT-K8S-...`.
3. PR it. Include one line in the PR naming the module finding(s) your rule correlates.
