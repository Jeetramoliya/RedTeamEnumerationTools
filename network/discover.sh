#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# discover.sh  -  layer-2/3 discovery protocols: SNMP, NetBIOS/LLMNR/mDNS, IPv6.
#                 Finds hosts, service names and MITM/poisoning opportunities that
#                 a plain TCP port scan misses.
#
# ENGINE   uses snmpwalk/onesixtyone, nmblookup, avahi-browse, ip when present;
#          degrades to notes + ready commands otherwise.
#
# NOISE    Active-ish (SNMP queries, NetBIOS/mDNS probes). LLMNR/NBT-NS/mDNS also
#          present a *poisoning* opportunity (Responder/mitm6) - flagged, not run.
#
# USAGE
#   ./discover.sh                      # local subnet
#   ./discover.sh -t 10.0.0.0/24 -j
#   ./discover.sh -t 10.0.0.5 --community public
# ============================================================================
set -u
umask 077  # loot dirs/files not world-readable
TARGET=""; OUTBASE="."; JSON=0; COMMUNITY="public private community"
while [ $# -gt 0 ]; do case "$1" in
  -t|--target) TARGET="$2"; shift 2;;
  --community) COMMUNITY="$2"; shift 2;;
  -o) OUTBASE="$2"; shift 2;;
  -j|--json) JSON=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 3;;
esac; done

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/discover_${HOST}_${TS}"; mkdir -p "$RUN" || { echo "cannot create $RUN"; exit 1; }
chmod 700 "$RUN" 2>/dev/null
if [ -t 1 ]; then R=$'\e[31m';Y=$'\e[33m';C=$'\e[36m';G=$'\e[32m';D=$'\e[90m';N=$'\e[0m'; else R=;Y=;C=;G=;D=;N=; fi
SUMMARY="$RUN/00_SUMMARY.txt"; NEXT="$RUN/NEXT_STEPS.txt"; JFILE="$RUN/findings.json"; : > "$SUMMARY"; : > "$NEXT"
HIGHN=0;MEDN=0;INFON=0; declare -a J_HIGH=() J_MED=() J_INFO=() J_NEXT=()
sect(){ printf '\n%s[==== %s ====]%s\n' "$C" "$1" "$N"; }
flag(){ sev="$1";shift;txt="$*";case "$sev" in HIGH)col=$R;tag="[HIGH]";HIGHN=$((HIGHN+1));J_HIGH+=("$txt");; MED)col=$Y;tag="[MED ]";MEDN=$((MEDN+1));J_MED+=("$txt");; *)col=$D;tag="[INFO]";INFON=$((INFON+1));J_INFO+=("$txt");;esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"; printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"; }
nextstep(){ printf '[*] %s\n    %s\n\n' "$1" "$2" >> "$NEXT"; J_NEXT+=("$1 :: $2"); }
save(){ cat > "$RUN/$1"; }
has(){ command -v "$1" >/dev/null 2>&1; }
enumgod_banner(){ printf '%s' "${C:-}"; cat <<'ART'
 _____                        ____           _
| ____|_ __  _   _ _ __ ___  / ___| ___   __| |
|  _| | '_ \| | | | '_ ` _ \| |  _ / _ \ / _` |
| |___| | | | |_| | | | | | | |_| | (_) | (_| |
|_____|_| |_|\__,_|_| |_| |_|\____|\___/ \__,_|
ART
  printf '%s   EnumGod  Red Team Enumeration Toolkit%s\n' "${G:-}" "${N:-}"
  printf '%s   author : Jeet Ramoliya   module : discovery protocols%s\n\n' "${D:-}" "${N:-}"; }
enumgod_banner
echo "${G}[*] discover  ->  $RUN${N}"

# derive local subnet(s) if no target
CIDRS=$(ip -o -4 addr 2>/dev/null | awk '{print $4}' | grep -v '^127\.')
[ -z "$TARGET" ] && TARGET=$(echo "$CIDRS" | while read -r c; do b=${c%/*}; echo "${b%.*}.0/24"; done | sort -u | head -1)
flag INFO "Target: ${TARGET:-<none>}  local nets: $(echo "$CIDRS" | tr '\n' ' ')"

# ---------------- SNMP ----------------
sect "SNMP (udp/161)"
if has onesixtyone && [ -n "$TARGET" ]; then
  printf '%s\n' $COMMUNITY | tr ' ' '\n' > "$RUN/.comm"
  onesixtyone -c "$RUN/.comm" "$TARGET" 2>/dev/null | save 01_snmp.txt
  [ -s "$RUN/01_snmp.txt" ] && flag HIGH "SNMP responders found with a guessable community (see 01_snmp.txt) -> snmpwalk for config/creds."
elif has snmpwalk && echo "$TARGET" | grep -qv '/'; then
  for cm in $COMMUNITY; do
    snmpwalk -v2c -c "$cm" -t 2 -r 1 "$TARGET" 2>/dev/null | head -40 >> "$RUN/01_snmp.txt" && grep -q . "$RUN/01_snmp.txt" && { flag HIGH "SNMP community '$cm' works on $TARGET -> dump system/route/process/user info."; nextstep "SNMP walk" "snmpwalk -v2c -c $cm $TARGET"; break; }
  done
else
  flag INFO "No snmpwalk/onesixtyone - install net-snmp. Try: onesixtyone $TARGET public ; snmpwalk -v2c -c public <ip>"
fi

# ---------------- NetBIOS ----------------
sect "NetBIOS (udp/137)"
if has nmblookup; then
  if echo "$TARGET" | grep -qv '/'; then nmblookup -A "$TARGET" 2>/dev/null | save 02_netbios.txt
    grep -q '<' "$RUN/02_netbios.txt" 2>/dev/null && flag INFO "NetBIOS names resolved for $TARGET (see 02_netbios.txt)."
  else flag INFO "nmblookup present - run per host: nmblookup -A <ip>"; fi
else flag INFO "No nmblookup (samba-common-bin)."; fi

# ---------------- mDNS / service discovery ----------------
sect "mDNS / DNS-SD (udp/5353)"
if has avahi-browse; then
  timeout 8 avahi-browse -atrp 2>/dev/null | save 03_mdns.txt
  [ -s "$RUN/03_mdns.txt" ] && flag INFO "mDNS services advertised on the LAN (see 03_mdns.txt) - printers/Apple/IoT often leak info."
elif has dns-sd; then
  flag INFO "dns-sd present - dns-sd -B _services._dns-sd._udp"
else flag INFO "No avahi-browse/dns-sd for mDNS enumeration."; fi

# ---------------- name-resolution poisoning opportunity ----------------
sect "LLMNR / NBT-NS / mDNS poisoning surface"
# If these protocols are in use on the segment, Responder can capture NetNTLM hashes.
flag MED "LLMNR(5355)/NBT-NS(137)/mDNS(5353) are typically enabled on Windows LANs -> NetNTLMv2 capture/relay opportunity (Responder / ntlmrelayx). Verify before running."
nextstep "Capture NetNTLM (poisoning)" "sudo responder -I <iface>    # then crack NetNTLMv2 (hashcat -m 5600) or relay with ntlmrelayx"

# ---------------- IPv6 ----------------
sect "IPv6"
{
  echo "== addresses =="; ip -6 addr 2>/dev/null
  echo; echo "== neighbours =="; ip -6 neigh 2>/dev/null
} | save 04_ipv6.txt
if ip -6 addr 2>/dev/null | grep -q 'inet6 .*global\|inet6 fe80'; then
  flag MED "IPv6 is active on this host -> mitm6 (rogue DHCPv6/DNS) is often viable even in 'IPv4' networks; pair with ntlmrelayx."
  nextstep "IPv6 takeover" "mitm6 -d <domain>   +   ntlmrelayx.py -6 -t ldaps://<DC> --delegate-access"
fi

rm -f "$RUN/.comm" 2>/dev/null
# summary
sect "Writing ranked summary"
{
  echo "discover summary - $HOST - $(date)"; echo "target=$TARGET"; echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="; if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Install net-snmp/samba/avahi for deeper discovery."; fi
} > "$SUMMARY"
if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","target":"%s","ts":"%s",\n' "$HOST" "$TARGET" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"

# EnumGod exit code: 0=no findings, 1=findings, 2=runtime error, 3=bad args
if [ $(( ${HIGHN:-0} + ${MEDN:-0} )) -gt 0 ]; then exit 1; else exit 0; fi
