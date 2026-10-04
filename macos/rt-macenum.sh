#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# rt-macenum.sh  -  macOS local enumeration & privilege-escalation triage.
#                   SIP/TCC/Gatekeeper posture, admin & sudo, writable Launch
#                   Agents/Daemons (persistence+privesc), SUID, keychains, creds.
#
# Read-only. Native tools only (sw_vers, dscl, csrutil, launchctl, system_profiler).
#
# USAGE
#   ./rt-macenum.sh           # -> ./macenum_<host>_<ts>/
#   ./rt-macenum.sh -o /tmp -j
# ============================================================================
set -u
OUTBASE="."; JSON=0
while [ $# -gt 0 ]; do case "$1" in
  -o) OUTBASE="$2"; shift 2;;
  -j|--json) JSON=1; shift;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done

HOST=$(hostname 2>/dev/null || echo mac); TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/macenum_${HOST}_${TS}"; mkdir -p "$RUN" || { echo "cannot create $RUN"; exit 1; }
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
  printf '%s   author : Jeet Ramoliya   module : macOS local%s\n\n' "${D:-}" "${N:-}"; }
enumgod_banner
echo "${G}[*] rt-macenum  ->  $RUN${N}"
[ "$(uname 2>/dev/null)" = "Darwin" ] || flag INFO "Not running on macOS (uname != Darwin) - checks will be mostly empty."

# ---------------- system & security posture ----------------
sect "System & security posture"
{
  sw_vers 2>/dev/null; echo; uname -a 2>/dev/null
  echo; echo "== SIP =="; csrutil status 2>/dev/null
  echo "== Gatekeeper =="; spctl --status 2>/dev/null
  echo "== FileVault =="; fdesetup status 2>/dev/null
} | save 01_system.txt
csrutil status 2>/dev/null | grep -qi 'disabled' && flag HIGH "System Integrity Protection (SIP) is DISABLED -> far wider privesc/persistence surface."
spctl --status 2>/dev/null | grep -qi 'disabled' && flag MED "Gatekeeper disabled -> unsigned binaries run freely."
fdesetup status 2>/dev/null | grep -qi 'Off' && flag MED "FileVault is OFF -> disk at rest is unencrypted."

# ---------------- identity ----------------
sect "Users, admin & sudo"
{
  id 2>/dev/null
  echo; echo "== admin group =="; dscl . -read /Groups/admin GroupMembership 2>/dev/null
  echo; echo "== local users =="; dscl . -list /Users 2>/dev/null | grep -v '^_'
  echo; echo "== sudo -l =="; sudo -n -l 2>/dev/null
} | save 02_identity.txt
id -Gn 2>/dev/null | grep -qw admin && flag MED "Current user is in the 'admin' group (can sudo / authorize installs)."
sudo -n -l 2>/dev/null | grep -qi 'NOPASSWD' && flag HIGH "sudo NOPASSWD entries present -> root via sudo (check GTFOBins for the binary)."

# ---------------- LaunchAgents/Daemons (persistence + privesc) ----------------
sect "LaunchAgents / LaunchDaemons (writable = root persistence/privesc)"
for d in /Library/LaunchDaemons /Library/LaunchAgents /System/Library/LaunchDaemons; do
  [ -d "$d" ] || continue
  find "$d" -type f -perm -002 2>/dev/null | while read -r f; do flag HIGH "World-writable launchd plist: $f -> edit Program/ProgramArguments -> code exec as its (often root) user."; done
  # writable ProgramArguments target
  find "$d" -name '*.plist' -type f 2>/dev/null | while read -r f; do
    prog=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$f" 2>/dev/null || defaults read "$f" Program 2>/dev/null)
    [ -n "$prog" ] && [ -w "$prog" ] 2>/dev/null && flag HIGH "launchd $f runs a WRITABLE binary: $prog -> replace for code exec."
  done
done
ls -la /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null | save 03_launchd.txt

# ---------------- SUID / writable ----------------
sect "SUID binaries & writable sensitive paths"
find /usr/bin /usr/local/bin /Applications /opt -perm -4000 -type f 2>/dev/null | save 04_suid.txt
echo "$(cat "$RUN/04_suid.txt" 2>/dev/null)" | grep -E 'bash|sh|python|perl|ruby|vim|nano|find|cp|tar' | grep -q . && flag HIGH "GTFOBins-abusable SUID binary present (see 04_suid.txt)."
[ -w /etc/sudoers ] && flag HIGH "/etc/sudoers writable -> grant NOPASSWD ALL."
[ -w /etc/pam.d/sudo ] && flag HIGH "/etc/pam.d/sudo writable -> pam_tid/pam bypass -> sudo without password."
# Homebrew prefix writable (very common macOS privesc via root-run brew paths)
for bp in /opt/homebrew /usr/local/Homebrew /usr/local/bin; do [ -d "$bp" ] && [ -w "$bp" ] && flag MED "Writable Homebrew/bin path: $bp -> hijack a binary a privileged user runs."; done

# ---------------- credentials ----------------
sect "Credentials & secrets"
{
  echo "== keychains =="; security list-keychains 2>/dev/null
  echo; echo "== wifi/known =="; ls -la "$HOME/Library/Preferences/" 2>/dev/null | grep -i wifi
} | save 05_creds.txt
security list-keychains 2>/dev/null | grep -q '.keychain' && flag INFO "Keychains present -> if you can unlock (user password), dump with: security dump-keychain -d login.keychain."
for f in "$HOME/.aws/credentials" "$HOME/.azure" "$HOME/.config/gcloud" "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519"; do [ -e "$f" ] && flag MED "Credential material present: $f"; done
# shell history creds
for h in "$HOME/.zsh_history" "$HOME/.bash_history"; do [ -r "$h" ] && grep -Eiq 'pass|secret|token|security add-generic-password' "$h" 2>/dev/null && flag MED "Credential-shaped lines in history: $h"; done

# summary
sect "Writing ranked summary"
{
  echo "rt-macenum summary - $HOST - $(date)"; echo "user=$(id -un 2>/dev/null)"; echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###"; printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="; if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> Review HIGH items; check TCC/keychain access as the logged-in user."; fi
} > "$SUMMARY"
if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  { printf '{\n  "host":"%s","ts":"%s",\n' "$HOST" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n  "med":'; jarr x "${J_MED[@]:-}"; printf ',\n  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n}\n'; } > "$JFILE"
fi
echo; echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
