#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# watch.sh  -  continuous posture mode. Re-runs the toolkit on an interval,
#              diffs against the previous run, and pushes NEW findings to a
#              webhook (Slack/Discord/generic). Turns a one-shot pentest sweep
#              into continuous monitoring. Read-only unless you pass run-all's
#              own active flags through after `--`.
#
# USAGE
#   ./run/watch.sh --interval 3600 --out /var/eg --webhook https://hooks.slack.com/...
#   ./run/watch.sh --once                      # single run + diff (for cron)
#   ./run/watch.sh --interval 1800 -- --net 10.0.0.0/24 --ad -d corp.local --dc 10.0.0.1 -u u
# Everything after `--` is passed verbatim to run-all.sh.
# ============================================================================
set -u
umask 077
SELF=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$SELF/.." && pwd)
INTERVAL=3600; OUT="./enumgod-watch"; WEBHOOK=""; ONCE=0; PASS=()
while [ $# -gt 0 ]; do case "$1" in
  --interval) INTERVAL="$2"; shift 2;;
  --out) OUT="$2"; shift 2;;
  --webhook) WEBHOOK="$2"; shift 2;;
  --once) ONCE=1; shift;;
  --) shift; PASS=("$@"); break;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 3;;
esac; done
mkdir -p "$OUT"; chmod 700 "$OUT" 2>/dev/null
command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python
BASELINE="$OUT/baseline.json"

notify(){ # $1 = message
  [ -z "$WEBHOOK" ] && return 0
  curl -s --max-time 10 -H 'Content-Type: application/json' \
    -d "$(printf '{"text":%s,"content":%s}' "\"$1\"" "\"$1\"")" "$WEBHOOK" >/dev/null 2>&1
}

one_cycle(){
  ts=$(date +%Y%m%d_%H%M%S); run="$OUT/run_$ts"; mkdir -p "$run"
  bash "$ROOT/run/run-all.sh" -o "$run" "${PASS[@]}" >"$run/run.log" 2>&1 || true
  # analyse this run, diff against the rolling baseline
  args=(--out "$OUT/latest" --output-format json,html)
  [ -f "$BASELINE" ] && args+=(--baseline "$BASELINE")
  "$PY" "$ROOT/research/eg_analyze.py" "$run" "${args[@]}" >/dev/null 2>&1 || true
  newc=0
  [ -f "$OUT/latest.json" ] && newc=$("$PY" - "$OUT/latest.json" <<'PY' 2>/dev/null
import json,sys
d=json.load(open(sys.argv[1]))
print(len(d.get("new_since_baseline",[])))
PY
)
  echo "[$(date)] cycle done: ${newc:-0} new finding(s)  ($OUT/latest.html)"
  if [ "${newc:-0}" -gt 0 ] && [ -n "$WEBHOOK" ]; then
    notify "EnumGod: ${newc} NEW finding(s) on $(hostname) - see latest report."
  fi
  cp "$OUT/latest.json" "$BASELINE" 2>/dev/null   # this run becomes next run's baseline
}

if [ "$ONCE" = 1 ]; then one_cycle; exit 0; fi
echo "[*] EnumGod watch: every ${INTERVAL}s -> $OUT  (webhook: ${WEBHOOK:+set})"
while true; do one_cycle; sleep "$INTERVAL"; done
