#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# cloud-authenum.sh  -  AUTHENTICATED cloud enumeration (post-access).
#                       Given an existing CLI session or token, enumerate identity,
#                       permissions and privesc surface in AWS / Azure(Entra) / GCP.
#
# Companion to rt-cloudenum.sh (which *obtains* access). This one *uses* it.
# Read-only: lists identities, roles/policies, resources. No changes made.
#
# USAGE
#   ./cloud-authenum.sh              # autodetect & enumerate every logged-in CLI
#   ./cloud-authenum.sh --aws --azure --gcp -j
#   GRAPH_TOKEN=eyJ... ./cloud-authenum.sh --entra      # Entra via a Graph token
# ============================================================================
set -u
umask 077  # loot dirs/files not world-readable
OUTBASE="."; JSON=0; DOAWS=0; DOAZ=0; DOGCP=0; DOENTRA=0; AUTO=1
while [ $# -gt 0 ]; do case "$1" in
  --aws) DOAWS=1; AUTO=0; shift;;
  --azure) DOAZ=1; AUTO=0; shift;;
  --gcp) DOGCP=1; AUTO=0; shift;;
  --entra) DOENTRA=1; AUTO=0; shift;;
  -o) OUTBASE="$2"; shift 2;;
  -j|--json) JSON=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/cloudauth_${HOST}_${TS}"; mkdir -p "$RUN" || { echo "cannot create $RUN"; exit 1; }
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
  printf '%s   author : Jeet Ramoliya   module : authenticated cloud%s\n\n' "${D:-}" "${N:-}"; }
enumgod_banner
echo "${G}[*] cloud-authenum  ->  $RUN${N}"

# ---------------- AWS ----------------
if [ "$AUTO" = 1 ] || [ "$DOAWS" = 1 ]; then
  if has aws && aws sts get-caller-identity >/dev/null 2>&1; then
    sect "AWS (authenticated)"
    aws sts get-caller-identity 2>/dev/null | save 01_aws_identity.json
    ARN=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
    flag HIGH "AWS authenticated as $ARN."
    aws iam list-attached-user-policies --user-name "$(basename "$ARN")" 2>/dev/null | save 01_aws_user_policies.json
    aws iam get-account-authorization-details 2>/dev/null | save 01_aws_authz.json
    aws s3 ls 2>/dev/null | save 01_aws_s3.txt
    [ -s "$RUN/01_aws_s3.txt" ] && flag MED "S3 buckets listed (see 01_aws_s3.txt)."
    # privesc-prone policy hints
    grep -Eqi '"Action": *"\*"|AdministratorAccess|iam:PassRole|iam:CreateAccessKey|iam:AttachUserPolicy|sts:AssumeRole' "$RUN/01_aws_authz.json" 2>/dev/null && { flag HIGH "AWS privesc-prone permissions present (*, PassRole, CreateAccessKey, AttachUserPolicy, AssumeRole) - see 01_aws_authz.json."; nextstep "AWS privesc" "# analyse with pmapper / cloudsplaining / enumerate-iam"; }
  elif [ "$DOAWS" = 1 ]; then flag INFO "aws CLI not authenticated (aws sts get-caller-identity failed)."; fi
fi

# ---------------- Azure (ARM) ----------------
if [ "$AUTO" = 1 ] || [ "$DOAZ" = 1 ]; then
  if has az && az account show >/dev/null 2>&1; then
    sect "Azure (authenticated)"
    az account show 2>/dev/null | save 02_az_account.json
    flag HIGH "az CLI authenticated: $(az account show --query user.name -o tsv 2>/dev/null)."
    az role assignment list --all 2>/dev/null | save 02_az_roles.json
    az resource list 2>/dev/null | save 02_az_resources.json
    az keyvault list 2>/dev/null | save 02_az_keyvaults.json
    grep -Eqi '"roleDefinitionName": *"(Owner|Contributor|User Access Administrator)"' "$RUN/02_az_roles.json" 2>/dev/null && { flag HIGH "High Azure RBAC role (Owner/Contributor/UAA) assigned - see 02_az_roles.json."; nextstep "Azure privesc" "# Contributor on a VM -> run-command RCE; UAA -> grant self Owner"; }
    grep -q '"name"' "$RUN/02_az_keyvaults.json" 2>/dev/null && flag MED "Key Vaults present - check access policies / secrets (az keyvault secret list)."
  elif [ "$DOAZ" = 1 ]; then flag INFO "az CLI not authenticated."; fi
fi

# ---------------- Entra (Graph token) ----------------
if [ "$AUTO" = 1 ] || [ "$DOENTRA" = 1 ]; then
  GT="${GRAPH_TOKEN:-}"
  if [ -z "$GT" ] && has az; then GT=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>/dev/null); fi
  if [ -n "$GT" ]; then
    sect "Entra ID (Microsoft Graph)"
    gq(){ curl -s --max-time 10 -H "Authorization: Bearer $GT" "https://graph.microsoft.com/v1.0$1" 2>/dev/null; }
    gq "/me" | save 03_entra_me.json
    gq "/users?\$top=50&\$select=userPrincipalName,displayName" | save 03_entra_users.json
    gq "/directoryRoles" | save 03_entra_roles.json
    gq "/applications?\$top=50&\$select=displayName,appId" | save 03_entra_apps.json
    grep -q '"userPrincipalName"' "$RUN/03_entra_users.json" 2>/dev/null && flag HIGH "Entra directory is readable via Graph token (users/roles/apps enumerated)."
    grep -qi 'Global Administrator\|Privileged Role Administrator' "$RUN/03_entra_roles.json" 2>/dev/null && flag MED "Privileged Entra roles present - map members (/directoryRoles/{id}/members)."
  elif [ "$DOENTRA" = 1 ]; then flag INFO "No Graph token (set GRAPH_TOKEN or login with az)."; fi
fi

# ---------------- GCP ----------------
if [ "$AUTO" = 1 ] || [ "$DOGCP" = 1 ]; then
  if has gcloud && gcloud auth list 2>/dev/null | grep -q '\*'; then
    sect "GCP (authenticated)"
    gcloud auth list 2>/dev/null | save 04_gcp_auth.txt
    gcloud projects list 2>/dev/null | save 04_gcp_projects.txt
    gcloud projects get-iam-policy "$(gcloud config get-value project 2>/dev/null)" 2>/dev/null | save 04_gcp_iam.txt
    flag HIGH "gcloud authenticated: $(gcloud config get-value account 2>/dev/null)."
    grep -Eqi 'roles/owner|roles/editor|iam.serviceAccountTokenCreator|setIamPolicy' "$RUN/04_gcp_iam.txt" 2>/dev/null && { flag HIGH "GCP privesc-prone role (owner/editor/tokenCreator/setIamPolicy) - see 04_gcp_iam.txt."; }
  elif [ "$DOGCP" = 1 ]; then flag INFO "gcloud not authenticated."; fi
fi

[ "$HIGHN" = 0 ] && [ "$MEDN" = 0 ] && flag INFO "No authenticated cloud sessions found - run rt-cloudenum.sh first to obtain access."

# summary
sect "Writing ranked summary"
{
  echo "cloud-authenum summary - $HOST - $(date)"; echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="; if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Obtain cloud access (rt-cloudenum.sh), then re-run."; fi
} > "$SUMMARY"
if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","ts":"%s",\n' "$HOST" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
echo "${Y}[!] Credential/identity data may be in $RUN - handle per rules of engagement.${N}"
