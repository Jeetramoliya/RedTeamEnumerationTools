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
SELFDIR=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$SELFDIR/.." && pwd)
OUTBASE="."; QUICK=""; LOUD=""; DONET=0; NETT=""; DOAD=0; DOCLOUD=1; DOSEC=1
DOM=""; DC=""; USER=""; PASS=""
while [ $# -gt 0 ]; do case "$1" in
  -o) OUTBASE="$2"; shift 2;;
  -q|--fast) QUICK="-q"; shift;;
  --loud) LOUD="--loud"; shift;;
  --net) DONET=1; case "${2:-}" in -*|"") NETT="";; *) NETT="$2"; shift;; esac; shift;;
  --ad) DOAD=1; shift;;
  --cloud) DOCLOUD=1; shift;;
  --no-cloud) DOCLOUD=0; shift;;
  --secrets) DOSEC=1; shift;;
  --no-secrets) DOSEC=0; shift;;
  --all) DONET=1; DOAD=1; DOCLOUD=1; DOSEC=1; shift;;
  -d) DOM="$2"; DOAD=1; shift 2;;
  --dc) DC="$2"; shift 2;;
  -u) USER="$2"; shift 2;;
  -p) PASS="$2"; shift 2;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done

TS=$(date +%Y%m%d_%H%M%S); MASTER="${OUTBASE%/}/EnumGod_$(hostname 2>/dev/null)_${TS}"
mkdir -p "$MASTER" || { echo "cannot create $MASTER"; exit 1; }
echo "[*] EnumGod run-all -> $MASTER"

run(){ echo "[>] $*"; "$@" -o "$MASTER" -j >/dev/null 2>&1 || echo "    (module returned non-zero)"; }

[ -f "$ROOT/linux/rt-linenum.sh" ]  && run bash "$ROOT/linux/rt-linenum.sh" $QUICK
[ "$DOSEC" = 1 ]  && [ -f "$ROOT/secrets/scan-secrets.sh" ] && run bash "$ROOT/secrets/scan-secrets.sh" -p "$HOME"
[ "$DOCLOUD" = 1 ] && [ -f "$ROOT/cloud/rt-cloudenum.sh" ]   && run bash "$ROOT/cloud/rt-cloudenum.sh" --no-token
if [ "$DONET" = 1 ] && [ -f "$ROOT/network/net-sweep.sh" ]; then
  if [ -n "$NETT" ]; then run bash "$ROOT/network/net-sweep.sh" -t "$NETT" $LOUD; else run bash "$ROOT/network/net-sweep.sh" --self; fi
fi
if [ "$DOAD" = 1 ] && [ -n "$DOM" ] && [ -f "$ROOT/linux/rt-adenum.sh" ]; then
  A="-d $DOM"; [ -n "$DC" ] && A="$A --dc $DC"; [ -n "$USER" ] && A="$A -u $USER"; [ -n "$PASS" ] && A="$A -p $PASS"
  run bash "$ROOT/linux/rt-adenum.sh" $A
fi

echo "[*] building consolidated report..."
if command -v python3 >/dev/null 2>&1 && [ -f "$ROOT/tools/eg-report.py" ]; then
  python3 "$ROOT/tools/eg-report.py" "$MASTER" -o "$MASTER/EnumGod-report.html" --save-merged "$MASTER/merged.json" --title "EnumGod - $(hostname 2>/dev/null) - $TS"
  echo "[+] report: $MASTER/EnumGod-report.html"
  echo "[i] next hop: re-run, then  python3 tools/eg-report.py <new-master> --diff $MASTER/merged.json  to see NEW access."
else
  echo "[i] python3 not found - per-module 00_SUMMARY.txt files are under $MASTER"
fi
