<#
    EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
    ============================================================================
    Invoke-RTShareHunt.ps1 - SMB share enumeration & loot hunting (PowerHuntShares
    style, native). Lists shares across targets, classifies readable / writable,
    and greps readable shares for interesting files (creds, keys, configs, backups).

    NOISE  Active - touches other hosts over SMB (the classic share-hunt pattern a
           blue team alerts on). Scope with -Target; -TestWrite also probes write
           access by creating+deleting a tiny marker file on each share.

    USAGE
        . .\network\Invoke-RTShareHunt.ps1
        Invoke-RTShareHunt                         # ARP-known + domain computers
        Invoke-RTShareHunt -Target 10.0.0.0/24 -TestWrite -Json
        Invoke-RTShareHunt -Target srv01,srv02 -Depth 3
    ============================================================================
#>
[CmdletBinding()]
param([string]$Target,[string]$OutDir="$PWD",[int]$Depth=2,[switch]$TestWrite,[switch]$Json)

function Invoke-RTShareHunt {
    [CmdletBinding()]
    param([string]$Target,[string]$OutDir="$PWD",[int]$Depth=2,[switch]$TestWrite,[switch]$Json)
    $ErrorActionPreference='SilentlyContinue'
    $summary=New-Object System.Collections.Generic.List[string]
    $loot=New-Object System.Collections.Generic.List[string]
    function Log($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
    function Sect($n){ Log "`n[==== $n ====]" 'Cyan' }
    function Flag($sev,$txt){ $tag=switch($sev){'HIGH'{'[HIGH]'}'MED'{'[MED ]'}default{'[INFO]'}}; $line="$tag $txt"; if($summary.Contains($line)){return}; $summary.Add($line); $col=switch($sev){'HIGH'{'Red'}'MED'{'Yellow'}default{'DarkGray'}}; Log $line $col }
    function Banner($m){ @(' _____                        ____           _','| ____|_ __  _   _ _ __ ___  / ___| ___   __| |','|  _| | ''_ \| | | | ''_ ` _ \| |  _ / _ \ / _` |','| |___| | | | |_| | | | | | | |_| | (_) | (_| |','|_____|_| |_|\__,_|_| |_| |_|\____|\___/ \__,_|') | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
        Write-Host '   EnumGod  Red Team Enumeration Toolkit' -ForegroundColor Green
        Write-Host "   author : Jeet Ramoliya   module : $m" -ForegroundColor DarkGray; Write-Host '' }
    $stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
    $run=Join-Path $OutDir ("ShareHunt_{0}_{1}" -f $env:COMPUTERNAME,$stamp)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    function Save($f,$d){ $d | Out-File -FilePath (Join-Path $run $f) -Encoding UTF8 -Width 4096 }
    Banner 'SMB share hunt'
    Log "[*] Invoke-RTShareHunt  ->  $run" 'Green'

    # build target list
    $hosts=New-Object System.Collections.Generic.List[string]
    if ($Target){
        foreach($t in ($Target -split ',')){ $t=$t.Trim()
            if ($t -match '/24$'){ $p=($t -replace '\.0/24$',''); 1..254 | ForEach-Object { $hosts.Add("$p.$_") } }
            else { $hosts.Add($t) } }
    } else {
        Get-NetNeighbor -AddressFamily IPv4 2>$null | Where-Object { $_.State -in 'Reachable','Stale' -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '224.*' } | ForEach-Object { $hosts.Add($_.IPAddress) }
        # domain computers if reachable
        try { $d=([ADSI]'LDAP://RootDSE').defaultNamingContext; if ($d){ $s=New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$d"); $s.Filter='(objectCategory=computer)'; [void]$s.PropertiesToLoad.Add('dnshostname'); $s.PageSize=500; $s.FindAll() | ForEach-Object { $n="$($_.Properties['dnshostname'])"; if ($n){ $hosts.Add($n) } } } } catch {}
        Flag 'INFO' "No -Target; using $($hosts.Count) ARP-known + domain computer(s)."
    }
    $hosts=$hosts | Select-Object -Unique | Where-Object { $_ }

    $interesting='pass|secret|cred|unattend|sysprep|web\.config|\.kdbx$|id_rsa|\.ppk$|\.pem$|\.vmdk$|\.bak$|\.config$|\.ps1$|\.vbs$|\.ini$|\.xlsx$|backup|confidential'
    $skipShares='IPC\$|print\$'

    Sect "Enumerating shares over $($hosts.Count) host(s) [ACTIVE]"
    $rows=New-Object System.Collections.Generic.List[string]
    foreach($h in $hosts){
        if (-not $h){ continue }
        $view = net view "\\$h" /all 2>$null
        if (-not $view){ continue }
        $shares = $view | Select-String '\s+Disk\s*' | ForEach-Object { ($_ -split '\s{2,}')[0].Trim() } | Where-Object { $_ -and $_ -notmatch $skipShares }
        foreach($sh in $shares){
            $unc="\\$h\$sh"; $canRead=Test-Path $unc
            $acc = if ($canRead){'READ'} else {'denied'}
            $canWrite=$false
            if ($canRead -and $TestWrite){
                $mk=Join-Path $unc ".__eg_$([guid]::NewGuid().ToString('N').Substring(0,8))"
                try { Set-Content -LiteralPath $mk -Value '' -ErrorAction Stop; $canWrite=$true; Remove-Item -LiteralPath $mk -Force -ErrorAction SilentlyContinue } catch {}
            }
            if ($canWrite){ $acc='READ,WRITE' }
            $rows.Add("$unc`t$acc")
            if ($canWrite){ Flag 'HIGH' "WRITABLE share: $unc -> drop payloads / SCF/LNK capture / replace binaries." }
            elseif ($canRead -and $sh -notmatch '^(ADMIN|C|D|E)\$$'){ Flag 'MED' "Readable non-default share: $unc" }
            if ($canRead){
                try {
                    Get-ChildItem -LiteralPath $unc -Recurse -Depth $Depth -File -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -match $interesting } | Select-Object -First 40 | ForEach-Object {
                        $loot.Add("$($_.FullName)")
                      }
                } catch {}
            }
        }
    }
    Save '01_shares.txt' ($rows -join "`r`n")
    if ($loot.Count){
        Save '02_loot_files.txt' ($loot -join "`r`n")
        Flag 'HIGH' "$($loot.Count) interesting file(s) found on readable shares -> 02_loot_files.txt (creds/keys/configs/backups)."
    }

    Sect "Writing ranked summary"
    $high=$summary|Where-Object{$_ -like '`[HIGH`]*'}; $med=$summary|Where-Object{$_ -like '`[MED *'}; $info=$summary|Where-Object{$_ -like '`[INFO`]*'}
    $sf=New-Object System.Collections.Generic.List[string]
    $sf.Add("RTShareHunt summary - $env:COMPUTERNAME - $(Get-Date)"); $sf.Add("")
    $sf.Add("### HIGH ($($high.Count)) ###"); $high | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### MED ($($med.Count)) ###"); $med | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### INFO ($($info.Count)) ###"); $info | ForEach-Object { $sf.Add($_) }
    Save '00_SUMMARY.txt' ($sf -join "`r`n")
    if ($Json){ $jb=[ordered]@{ host=$env:COMPUTERNAME; ts=$stamp; high=@($high); med=@($med); info=@($info) }; ($jb|ConvertTo-Json -Depth 5)|Out-File (Join-Path $run 'findings.json') -Encoding UTF8 }
    Log "`n[+] Done. HIGH=$($high.Count) MED=$($med.Count) INFO=$($info.Count)" 'Green'
    return $run
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-RTShareHunt @PSBoundParameters }
