#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# run-all.sh  -  orchestrator: run the EnumGod Linux modules into ONE master
#                directory, then build a consolidated HTML report (eg-report.py).
#
# USAGE
#   ./run/run-all.sh                         # local triage + secrets + cloud(no-token)
#   ./run/run-all.sh --net 10.0.0.0/24       # also sweep a subnet
#   ./run/run-all.sh --ad -d corp.local --dc 10.0.0.10 -u user -p pass
#   ./run/run-all.sh --all --loud -o /dev/shm/loot
# ============================================================================
set -u
umask 077  # loot dirs/files not world-readable
SELFDIR=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$SELFDIR/.." && pwd)
OUTBASE="."; QUICK=""; LOUD=""; DONET=0; NETT=""; DOAD=0; DOCLOUD=1; DOSEC=1
DOKUBE=0; DODISC=0; DOCAUTH=0; ACTIVE=0; DOM=""; DC=""; USER=""; PASS=""
while [ $# -gt 0 ]; do case "$1" in
  -o) OUTBASE="$2"; shift 2;;
  -q|--fast) QUICK="-q"; shift;;
  --safe) ACTIVE=0; shift;;                 # default: read-only/discovery across all modules
  --active) ACTIVE=1; shift;;               # enable active checks (DB creds, token collection)
  --loud) LOUD="--loud"; shift;;
  --net) DONET=1; case "${2:-}" in -*|"") NETT="";; *) NETT="$2"; shift;; esac; shift;;
  --ad) DOAD=1; shift;;
  --cloud) DOCLOUD=1; shift;;
  --no-cloud) DOCLOUD=0; shift;;
  --secrets) DOSEC=1; shift;;
  --no-secrets) DOSEC=0; shift;;
  --kube) DOKUBE=1; shift;;
  --discover) DODISC=1; shift;;
  --cloudauth) DOCAUTH=1; shift;;
  --all) DONET=1; DOAD=1; DOCLOUD=1; DOSEC=1; DOKUBE=1; DODISC=1; DOCAUTH=1; shift;;
  -d) DOM="$2"; DOAD=1; shift 2;;
  --dc) DC="$2"; shift 2;;
  -u) USER="$2"; shift 2;;
  -p) PASS="$2"; PW_CLI=1; shift 2;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 3;;
esac; done
: "${PW_CLI:=0}"
[ "$PW_CLI" = 1 ] && echo "[!] WARNING: -p on the command line is visible in ps/history; prefer -k or the module prompt." >&2
# active checks that run only with --active (safe by default)
DB_FLAG=""; TOKEN_FLAG=""
[ "$ACTIVE" = 1 ] && { DB_FLAG="--db"; TOKEN_FLAG="--collect-tokens"; echo "[!] --active: DB default-cred tests and cloud token collection are ENABLED." >&2; }

TS=$(date +%Y%m%d_%H%M%S); MASTER="${OUTBASE%/}/EnumGod_$(hostname 2>/dev/null)_${TS}"
mkdir -p "$MASTER" || { echo "cannot create $MASTER"; exit 1; }
chmod 700 "$MASTER" 2>/dev/null
RUNID="EG-$(date +%s)-$$"
echo "[*] EnumGod run-all -> $MASTER  (run id $RUNID)"

MODRUN=0; declare -a MODOK=() MODFAIL=()
# run a module in its own output subdir; capture exit code; validate its JSON; never abort the whole run
run(){
  name="$1"; shift
  echo "[>] $name"
  MODRUN=$((MODRUN+1))
  sub="$MASTER/mod_${name}"; mkdir -p "$sub" 2>/dev/null; chmod 700 "$sub" 2>/dev/null
  if "$@" -o "$sub" -j >"$sub/.stdout" 2>"$sub/.stderr"; then rc=0; else rc=$?; fi
  jf=$(find "$sub" -name findings.json 2>/dev/null | head -1)
  if [ -n "$jf" ] && { command -v python3 >/dev/null 2>&1 && python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$jf" 2>/dev/null || command -v jq >/dev/null 2>&1 && jq -e . "$jf" >/dev/null 2>&1; }; then
    MODOK+=("$name (rc=$rc)")
  elif [ -n "$jf" ]; then
    MODFAIL+=("$name (invalid JSON)")
  else
    # rc 0/1 with no JSON can be legitimate (nothing to emit); only treat >=2 as failure
    [ "${rc:-0}" -ge 2 ] && MODFAIL+=("$name (rc=$rc)") || MODOK+=("$name (rc=$rc, no json)")
  fi
}

[ -f "$ROOT/linux/rt-linenum.sh" ]  && run rt-linenum bash "$ROOT/linux/rt-linenum.sh" $QUICK
[ "$DOSEC" = 1 ]  && [ -f "$ROOT/secrets/scan-secrets.sh" ] && run scan-secrets bash "$ROOT/secrets/scan-secrets.sh" -p "$HOME"
[ "$DOCLOUD" = 1 ] && [ -f "$ROOT/cloud/rt-cloudenum.sh" ]   && run rt-cloudenum bash "$ROOT/cloud/rt-cloudenum.sh" $TOKEN_FLAG
if [ "$DONET" = 1 ] && [ -f "$ROOT/network/net-sweep.sh" ]; then
  if [ -n "$NETT" ]; then run net-sweep bash "$ROOT/network/net-sweep.sh" -t "$NETT" $LOUD $DB_FLAG; else run net-sweep bash "$ROOT/network/net-sweep.sh" --self; fi
fi
if [ "$DOAD" = 1 ] && [ -n "$DOM" ] && [ -f "$ROOT/linux/rt-adenum.sh" ]; then
  A=(-d "$DOM"); [ -n "$DC" ] && A+=(--dc "$DC"); [ -n "$USER" ] && A+=(-u "$USER"); [ -n "$PASS" ] && A+=(-p "$PASS")
  run rt-adenum bash "$ROOT/linux/rt-adenum.sh" "${A[@]}"
fi
[ "$DOKUBE" = 1 ]  && [ -f "$ROOT/cloud/kube-enum.sh" ]      && run kube-enum bash "$ROOT/cloud/kube-enum.sh"
[ "$DOCAUTH" = 1 ] && [ -f "$ROOT/cloud/cloud-authenum.sh" ] && run cloud-authenum bash "$ROOT/cloud/cloud-authenum.sh"
if [ "$DODISC" = 1 ] && [ -f "$ROOT/network/discover.sh" ]; then
  if [ -n "$NETT" ]; then run discover bash "$ROOT/network/discover.sh" -t "$NETT"; else run discover bash "$ROOT/network/discover.sh"; fi
fi

echo "[*] modules run=$MODRUN ok=${#MODOK[@]} failed=${#MODFAIL[@]}"
[ "${#MODFAIL[@]}" -gt 0 ] && { echo "[!] failed modules:"; printf '    - %s\n' "${MODFAIL[@]}"; }
{ echo "run id: $RUNID"; echo "modules_run: $MODRUN"; echo "modules_ok: ${MODOK[*]}"; echo "modules_failed: ${MODFAIL[*]:-none}"; } > "$MASTER/RUN_SUMMARY.txt"

# ---- ONE merged raw-output file (every module's summary + dumps) for manual review / script tuning ----
MERGED="$MASTER/EnumGod_MERGED.txt"
{
  echo "######################################################################"
  echo "# EnumGod merged output  -  run $RUNID  -  $(date)"
  echo "# Modules ok: ${MODOK[*]:-none}    failed: ${MODFAIL[*]:-none}"
  echo "######################################################################"
  find "$MASTER" -mindepth 2 -type f \( -name '0*_*.txt' -o -name 'NEXT_STEPS.txt' -o -name '*_matches.txt' \) 2>/dev/null | sort | while IFS= read -r f; do
    echo; echo "==================== ${f#"$MASTER"/} ===================="; cat "$f" 2>/dev/null
  done
} > "$MERGED" 2>/dev/null
chmod 600 "$MERGED" 2>/dev/null
echo "[+] merged raw output: $MERGED"

echo "[*] building consolidated report + analysis..."
PY=""; command -v python3 >/dev/null 2>&1 && PY=python3; [ -z "$PY" ] && command -v python >/dev/null 2>&1 && PY=python
if [ -n "$PY" ] && [ -f "$ROOT/tools/eg-report.py" ]; then
  "$PY" "$ROOT/tools/eg-report.py" "$MASTER" -o "$MASTER/EnumGod-report.html" --save-merged "$MASTER/merged.json" --title "EnumGod - $(hostname 2>/dev/null) - $TS" || true
  echo "[+] report: $MASTER/EnumGod-report.html"
fi
# full analysis pipeline (graph / attack-paths / anomalies / research / SARIF)
if [ -n "$PY" ] && [ -f "$ROOT/research/eg_analyze.py" ]; then
  RARGS=""; [ "$ACTIVE" = 1 ] && RARGS="$RARGS"   # research is read-only; active handled per-module above
  "$PY" "$ROOT/research/eg_analyze.py" "$MASTER" --out "$MASTER/EnumGod-analysis" --output-format html,json,sarif,csv $RARGS || true
  echo "[+] analysis: $MASTER/EnumGod-analysis.html (+ .json/.sarif/.csv)"
  echo "[i] next hop: re-run, then  $PY research/eg_analyze.py <new-master> --baseline $MASTER/merged.json  for the diff."
elif [ -z "$PY" ]; then
  echo "[i] python not found - see per-module 00_SUMMARY.txt and $MERGED"
fi
