# Contributing

Thanks for improving the toolkit. A few conventions keep it consistent and safe.

## Ground rules
- **Read-only.** Enumeration scripts must not change the target. They *find* and
  *rank* and print the next command; the operator runs exploitation steps.
- **Self-contained + graceful degradation.** No hard dependencies. If an optional
  tool is missing, detect it and fall back (or print the command to run elsewhere).
- **Authorized use only.** Don't add features whose only purpose is evading
  detection for malicious use. Detection *awareness* (noise/event-ID notes) is fine.

## The shared findings model (keep it identical across scripts)
Every script writes a timestamped dir with:
- `00_SUMMARY.txt` — ranked `[HIGH]/[MED ]/[INFO]`, de-duplicated
- `NEXT_STEPS.txt` — pre-filled command per actionable finding
- `NN_*.txt` — per-section raw dumps
- `findings.json` — with `-j`/`-Json`

Reuse the existing `flag` / `Flag`, `sect` / `Sect`, `save` / `Save`, `nextstep`
helpers rather than inventing new output shapes.

## Style & gotchas (learned the hard way)
- **Shell:** `#!/usr/bin/env bash`, `set -u`, LF endings (enforced by `.gitattributes`).
  Guard heavy `find /` / `getcap -r /` with the `TG` (`timeout`) helper. Keep awk
  POSIX — **no gawk `and()`**; use `int(x/BIT)%2==1`. Pass regexes starting with `-`
  to grep via `-e`.
- **PowerShell:** must parse on **Windows PowerShell 5.1** *and* `pwsh`. No ternary
  (`? :`), no `??`. Avoid `@()` around a `New-Object List[object]` (5.1 bug) — use
  `.ToArray()`. Force arrays with `@(...)` before indexing `[0]` on possibly-scalar
  pipeline output. Don't name a param `-Db` (collides with `-Debug`).
- Syntax-check before pushing:
  ```bash
  bash -n path/to/script.sh
  ```
  ```powershell
  [System.Management.Automation.Language.Parser]::ParseFile('path\to.ps1',[ref]$null,[ref]$null)
  ```

## CVE knowledge base (`data/cve-db.txt`)
Pipe-delimited `os|cve|name|type|min|max|severity|exploited|note`. Curated rows have
real version ranges; feed-sourced rows (from `tools/update-cve-db.*`) use `min=max=kev`
and surface as awareness only. Add new curated CVEs with verified ranges + a one-line note.

## CI
`.github/workflows/lint.yml` runs shellcheck (`-S error`) on `*.sh` and
PSScriptAnalyzer (Error severity) on `*.ps1`. Please run them locally first.
