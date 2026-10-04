#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# scan-secrets.sh  -  Red Team filesystem SECRETS scanner (trufflehog-lite).
#                     Same ranked findings model as the rest of the toolkit.
#
# WHAT IT DOES  (read-only)
#   Greps a path for high-value secrets: private keys, cloud keys (AWS/GCP/
#   Azure), SaaS tokens (GitHub/Slack/Stripe), JWTs, DB connection strings,
#   and generic password/api_key assignments in configs. Also scans .git
#   history when --git is set. Values are MASKED in the summary.
#
# USAGE
#   ./scan-secrets.sh                      # scan $HOME + common app dirs
#   ./scan-secrets.sh -p /var/www -j       # scan a path, write findings.json
#   ./scan-secrets.sh -p /opt --git        # also scan git history under -p
#   ./scan-secrets.sh -p / --max 5         # whole FS, skip files > 5 MB
# ============================================================================
set -u
umask 077  # loot dirs/files not world-readable
SCANPATH=""; OUTBASE="."; JSON=0; GITSCAN=0; MAXMB=5
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--path) SCANPATH="$2"; shift 2;;
    --git) GITSCAN=1; shift;;
    --max) MAXMB="$2"; shift 2;;
    -o) OUTBASE="$2"; shift 2;;
    -j|--json) JSON=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done
# default scan set
if [ -z "$SCANPATH" ]; then SCANPATH="$HOME /etc /opt /srv /var/www /home"; fi

HOST=$(hostname 2>/dev/null || echo host); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/secrets_${HOST}_${TS}"; mkdir -p "$RUN" 2>/dev/null || { echo "[-] cannot create $RUN"; exit 1; }
chmod 700 "$RUN" 2>/dev/null
if [ -t 1 ]; then R=$'\e[31m';Y=$'\e[33m';C=$'\e[36m';G=$'\e[32m';D=$'\e[90m';N=$'\e[0m'; else R=;Y=;C=;G=;D=;N=; fi
SUMMARY="$RUN/00_SUMMARY.txt"; MATCHES="$RUN/01_matches.txt"; JFILE="$RUN/findings.json"
: > "$SUMMARY"; : > "$MATCHES"; HIGHN=0;MEDN=0;INFON=0
declare -a J_HIGH=() J_MED=() J_INFO=()
sect(){ printf '\n%s[==== %s ====]%s\n' "$C" "$1" "$N"; }
flag(){ sev="$1";shift;txt="$*";case "$sev" in
  HIGH)col=$R;tag="[HIGH]";HIGHN=$((HIGHN+1));J_HIGH+=("$txt");;
  MED)col=$Y;tag="[MED ]";MEDN=$((MEDN+1));J_MED+=("$txt");;
  *)col=$D;tag="[INFO]";INFON=$((INFON+1));J_INFO+=("$txt");;esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"; printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"; }
has(){ command -v "$1" >/dev/null 2>&1; }
if has timeout; then TG(){ timeout 120 "$@"; }; else TG(){ "$@"; }; fi

# mask a secret-ish token: keep first 3 + last 2 chars
mask(){ echo "$1" | sed -E 's/([A-Za-z0-9+/_-]{3})[A-Za-z0-9+/_=.-]{4,}([A-Za-z0-9+/_-]{2})/\1***\2/g'; }

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
enumgod_banner "secrets scanner"
echo "${G}[*] scan-secrets  ->  $RUN${N}"
echo "${D}[*] path: $SCANPATH   git-history: $GITSCAN   max: ${MAXMB}MB${N}"

# pattern table:  name | severity | ERE
PATTERNS='
privatekey|HIGH|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----
aws-akia|HIGH|A(KIA|SIA)[0-9A-Z]{16}
gcp-sa-key|HIGH|"private_key_id"|"type": ?"service_account"
github-token|HIGH|gh[pousr]_[A-Za-z0-9]{36,}
slack-token|HIGH|xox[baprs]-[0-9A-Za-z-]{10,}
google-api|HIGH|AIza[0-9A-Za-z_-]{35}
stripe-live|HIGH|sk_live_[0-9a-zA-Z]{20,}
npm-token|HIGH|_authToken=[A-Za-z0-9._-]{10,}
jwt|MED|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}
db-connstring|HIGH|(mongodb|postgres|postgresql|mysql|redis|amqp|ftp)://[^:@/ ]+:[^@/ ]+@
bearer|MED|[Bb]earer [A-Za-z0-9._-]{20,}
azure-secret|HIGH|(client_secret|CLIENT_SECRET)["'"'"']? ?[:=] ?["'"'"']?[A-Za-z0-9._~-]{20,}
generic-pass|MED|(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)["'"'"']? ?[:=] ?["'"'"']?[^"'"'"' ]{4,}
'

# find candidate files (text, under size cap), excluding heavy noise dirs
sect "Scanning for secrets"
FILELIST="$RUN/.files"
TG find $SCANPATH -type f -size -"${MAXMB}"M 2>/dev/null \
  | grep -Ev '/(node_modules|\.git/|/proc/|/sys/|\.cache/|site-packages|dist-packages)/' \
  | grep -Ev '\.(png|jpg|jpeg|gif|ico|pdf|zip|gz|tar|xz|7z|exe|dll|so|o|a|class|jar|mp4|mp3|woff2?|ttf)$' \
  > "$FILELIST" 2>/dev/null
NF=$(wc -l < "$FILELIST" 2>/dev/null)
flag INFO "Candidate files to scan: ${NF:-0}"

echo "$PATTERNS" | while IFS='|' read -r pname psev pre; do
  [ -z "$pname" ] && continue
  # grep across the file list (binary-safe, with line numbers)
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    TG grep -IEn -e "$pre" "$f" 2>/dev/null | head -5 | while IFS= read -r m; do
      ln=$(echo "$m" | cut -d: -f1); snippet=$(echo "$m" | cut -d: -f2- | cut -c1-120)
      echo "${psev}|${pname}|${f}:${ln}|$(mask "$snippet")"
    done
  done < "$FILELIST"
done | sort -u > "$RUN/.hits"

# summarise hits by pattern
cp "$RUN/.hits" "$MATCHES" 2>/dev/null
if [ -s "$RUN/.hits" ]; then
  # confidence: structured-format secrets are HIGH_CONFIDENCE; generic keyword matches are POSSIBLE
  conf_for(){ case "$1" in
    privatekey|aws-akia|gcp-sa-key|github-token|slack-token|google-api|stripe-live|npm-token|db-connstring) echo HIGH_CONFIDENCE;;
    *) echo POSSIBLE;; esac; }
  for pn in privatekey aws-akia gcp-sa-key github-token slack-token google-api stripe-live npm-token db-connstring azure-secret jwt bearer generic-pass; do
    c=$(grep -c "|${pn}|" "$RUN/.hits" 2>/dev/null)
    [ "${c:-0}" -gt 0 ] || continue
    sev=$(grep "|${pn}|" "$RUN/.hits" | head -1 | cut -d'|' -f1)
    ex=$(grep "|${pn}|" "$RUN/.hits" | head -1 | cut -d'|' -f3)
    flag "$sev" "[$(conf_for "$pn")] $c x ${pn} (e.g. ${ex}) - see 01_matches.txt (values masked)."
  done
else
  flag INFO "No secrets matched in the scanned path."
fi
rm -f "$RUN/.files" "$RUN/.hits" 2>/dev/null

# git history scan (committed-then-removed secrets) - matched lines are MASKED before writing
if [ "$GITSCAN" = "1" ]; then
  sect "Git history secrets"
  for p in $SCANPATH; do
    [ -d "$p/.git" ] || continue
    gf="$RUN/02_git_$(echo "$p"|tr '/' '_').txt"
    TG git -C "$p" log -p --all 2>/dev/null \
      | grep -aIE '(-----BEGIN [A-Z ]*PRIVATE KEY-----|A(KIA|SIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9a-zA-Z]{20,}|AIza[0-9A-Za-z_-]{35}|password *[:=]|secret *[:=]|api[_-]?key *[:=])' \
      | head -60 | while IFS= read -r line; do mask "${line:0:160}"; done > "$gf" 2>/dev/null
    [ -s "$gf" ] && flag HIGH "Secret-shaped lines in git history of $p (MASKED in 02_git_*.txt) -> review with: git -C $p log -p."
  done
fi

# summary
sect "Writing ranked summary"
{
  echo "scan-secrets summary - $HOST - $(date)"
  echo "Path: $SCANPATH"
  echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
} > "$SUMMARY"

if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","ts":"%s",\n' "$HOST" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON  (matches: $MATCHES)${N}"
