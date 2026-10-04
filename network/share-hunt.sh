#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# share-hunt.sh  -  SMB share enumeration & loot hunting from Linux.
#                   Lists shares across targets, flags readable/writable, and
#                   greps readable shares for interesting files.
#
# ENGINE   netexec/cme (best) -> smbclient + rpcclient fallback. Degrades to
#          printing the exact commands if none are installed.
#
# NOISE    Active - touches other hosts over SMB.
#
# USAGE
#   ./share-hunt.sh -t 10.0.0.0/24
#   ./share-hunt.sh -t 10.0.0.5 -u user -p pass -j
#   ./share-hunt.sh -t hosts.txt -u user -H <NTLM>
# ============================================================================
set -u
umask 077  # loot dirs/files not world-readable
TARGET=""; USER=""; PASS=""; HASH=""; DOM="."; OUTBASE="."; JSON=0
while [ $# -gt 0 ]; do case "$1" in
  -t|--target) TARGET="$2"; shift 2;;
  -u|--user) USER="$2"; shift 2;;
  -p|--pass) PASS="$2"; PW_CLI=1; shift 2;;
  -H|--hash) HASH="$2"; shift 2;;
  -d|--domain) DOM="$2"; shift 2;;
  -o) OUTBASE="$2"; shift 2;;
  -j|--json) JSON=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 3;;
esac; done
[ -z "$TARGET" ] && { echo "[-] need -t <cidr|host|hosts.txt>"; exit 1; }

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/sharehunt_${HOST}_${TS}"; mkdir -p "$RUN" || { echo "cannot create $RUN"; exit 1; }
chmod 700 "$RUN" 2>/dev/null
if [ -t 1 ]; then R=$'\e[31m';Y=$'\e[33m';C=$'\e[36m';G=$'\e[32m';D=$'\e[90m';N=$'\e[0m'; else R=;Y=;C=;G=;D=;N=; fi
SUMMARY="$RUN/00_SUMMARY.txt"; JFILE="$RUN/findings.json"; : > "$SUMMARY"; HIGHN=0;MEDN=0;INFON=0
declare -a J_HIGH=() J_MED=() J_INFO=()
flag(){ sev="$1";shift;txt="$*";case "$sev" in
  HIGH)col=$R;tag="[HIGH]";HIGHN=$((HIGHN+1));J_HIGH+=("$txt");;
  MED)col=$Y;tag="[MED ]";MEDN=$((MEDN+1));J_MED+=("$txt");;
  *)col=$D;tag="[INFO]";INFON=$((INFON+1));J_INFO+=("$txt");;esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"; printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"; }
has(){ command -v "$1" >/dev/null 2>&1; }
enumgod_banner(){ printf '%s' "${C:-}"; cat <<'ART'
 _____                        ____           _
| ____|_ __  _   _ _ __ ___  / ___| ___   __| |
|  _| | '_ \| | | | '_ ` _ \| |  _ / _ \ / _` |
| |___| | | | |_| | | | | | | |_| | (_) | (_| |
|_____|_| |_|\__,_|_| |_| |_|\____|\___/ \__,_|
ART
  printf '%s   EnumGod  Red Team Enumeration Toolkit%s\n' "${G:-}" "${N:-}"
  printf '%s   author : Jeet Ramoliya   module : SMB share hunt%s\n\n' "${D:-}" "${N:-}"; }
enumgod_banner
echo "${G}[*] share-hunt  ->  $RUN${N}"

NXC=""; has netexec && NXC=netexec; has nxc && NXC=nxc; has crackmapexec && [ -z "$NXC" ] && NXC=crackmapexec
# credential hygiene + array-based auth (no eval)
: "${PW_CLI:=0}"
[ "$PW_CLI" = 1 ] && echo "[!] WARNING: -p on the command line is visible in ps/shell history; prefer -H <hash> or a null session." >&2
if [ -n "$NXC" ]; then
  AUTH=(-u "${USER:-}"); if [ -n "$HASH" ]; then AUTH+=(-H "$HASH"); elif [ -n "$PASS" ]; then AUTH+=(-p "$PASS"); else AUTH=(-u '' -p ''); fi
  echo "[*] engine: $NXC"
  "$NXC" smb "$TARGET" "${AUTH[@]}" --shares 2>&1 | tee "$RUN/01_shares.txt" >/dev/null
  # flag writable / readable-interesting
  grep -iE 'READ,WRITE|WRITE' "$RUN/01_shares.txt" 2>/dev/null | grep -viq 'NETLOGON\|SYSVOL' && flag HIGH "Writable SMB share(s) found (see 01_shares.txt) -> drop payload / capture hashes."
  grep -iE 'READ' "$RUN/01_shares.txt" 2>/dev/null | grep -viqE 'IPC\$|print\$|ADMIN\$|C\$' && flag MED "Readable non-default share(s) found (see 01_shares.txt)."
  # spider interesting files if nxc module available
  if "$NXC" smb "$TARGET" "${AUTH[@]}" -M spider_plus >/dev/null 2>&1; then flag INFO "Ran spider_plus - check ~/.nxc/modules/nxc_spider_plus for indexed files."; fi
elif has smbclient; then
  echo "[*] engine: smbclient"
  # expand simple target list (single host / file); smbclient doesn't do CIDR
  HOSTS="$TARGET"; [ -f "$TARGET" ] && HOSTS=$(cat "$TARGET")
  for h in $HOSTS; do
    echo "== $h ==" >> "$RUN/01_shares.txt"
    if [ -n "$PASS" ]; then smbclient -L "//$h" -U "${DOM}/${USER}%${PASS}" 2>/dev/null >> "$RUN/01_shares.txt"
    else smbclient -L "//$h" -N 2>/dev/null >> "$RUN/01_shares.txt"; fi
  done
  grep -qiE 'Disk' "$RUN/01_shares.txt" && flag MED "Shares listed via smbclient (see 01_shares.txt); test access per share (smbclient //host/share)."
else
  flag INFO "No SMB tooling (netexec/smbclient) - install one. Commands:"
  echo "   netexec smb $TARGET -u USER -p PASS --shares" | tee -a "$SUMMARY"
  echo "   smbclient -L //HOST -U DOM/USER%PASS" | tee -a "$SUMMARY"
fi

# summary tail
{ echo; echo "share-hunt - $(date) - target $TARGET"; } >> "$SUMMARY"
if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","target":"%s","ts":"%s",\n' "$HOST" "$TARGET" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"

# EnumGod exit code: 0=no findings, 1=findings, 2=runtime error, 3=bad args
if [ $(( ${HIGHN:-0} + ${MEDN:-0} )) -gt 0 ]; then exit 1; else exit 0; fi
