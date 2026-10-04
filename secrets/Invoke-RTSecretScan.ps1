<#
    EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
    Invoke-RTSecretScan.ps1
    ============================================================================
    Red Team filesystem SECRETS scanner for Windows. Windows companion to
    secrets/scan-secrets.sh - same ranked findings model, values MASKED.

    Finds private keys, cloud keys (AWS/GCP/Azure), SaaS tokens (GitHub/Slack/
    Stripe), JWTs, DB connection strings, and password/api_key assignments in
    configs / scripts / .env / registry-exported files.

    USAGE
        . .\Invoke-RTSecretScan.ps1
        Invoke-RTSecretScan                              # scan common user/app dirs
        Invoke-RTSecretScan -Path C:\inetpub,C:\Apps -Json
        Invoke-RTSecretScan -Path C:\ -MaxMB 5           # whole drive, skip >5MB
    ============================================================================
#>
[CmdletBinding()]
param([string[]]$Path,[string]$OutDir="$PWD",[int]$MaxMB=5,[switch]$Json)

function Invoke-RTSecretScan {
    [CmdletBinding()]
    param([string[]]$Path,[string]$OutDir="$PWD",[int]$MaxMB=5,[switch]$Json)
    $ErrorActionPreference='SilentlyContinue'
    if (-not $Path){ $Path = @("$env:USERPROFILE","$env:ProgramData","C:\inetpub","C:\xampp","C:\Apps","C:\Users\Public") }

    $summary=New-Object System.Collections.Generic.List[string]
    function Log($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
    function Sect($n){ Log "`n[==== $n ====]" 'Cyan' }
    function Flag($sev,$txt){ $tag=switch($sev){'HIGH'{'[HIGH]'}'MED'{'[MED ]'}default{'[INFO]'}}; $line="$tag $txt"; if($summary.Contains($line)){return}; $summary.Add($line); $col=switch($sev){'HIGH'{'Red'}'MED'{'Yellow'}default{'DarkGray'}}; Log $line $col }
    $stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
    $run=Join-Path $OutDir ("Secrets_{0}_{1}" -f $env:COMPUTERNAME,$stamp)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    function Banner($m){
        @(
            ' _____                        ____           _',
            '| ____|_ __  _   _ _ __ ___  / ___| ___   __| |',
            '|  _| | ''_ \| | | | ''_ ` _ \| |  _ / _ \ / _` |',
            '| |___| | | | |_| | | | | | | |_| | (_) | (_| |',
            '|_____|_| |_|\__,_|_| |_| |_|\____|\___/ \__,_|'
        ) | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
        Write-Host '   EnumGod  Red Team Enumeration Toolkit' -ForegroundColor Green
        Write-Host "   author : Jeet Ramoliya   module : $m" -ForegroundColor DarkGray
        Write-Host ''
    }
    Banner 'secrets scanner'
    Log "[*] Invoke-RTSecretScan  ->  $run" 'Green'

    $patterns=@(
        @{n='privatekey';  s='HIGH'; re='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'},
        @{n='aws-akia';    s='HIGH'; re='A(KIA|SIA)[0-9A-Z]{16}'},
        @{n='gcp-sa-key';  s='HIGH'; re='"type":\s*"service_account"|"private_key_id"'},
        @{n='github-token';s='HIGH'; re='gh[pousr]_[A-Za-z0-9]{36,}'},
        @{n='slack-token'; s='HIGH'; re='xox[baprs]-[0-9A-Za-z-]{10,}'},
        @{n='google-api';  s='HIGH'; re='AIza[0-9A-Za-z_-]{35}'},
        @{n='stripe-live'; s='HIGH'; re='sk_live_[0-9a-zA-Z]{20,}'},
        @{n='db-connstring';s='HIGH';re='(mongodb|postgres|postgresql|mysql|redis|amqp|ftp)://[^:@/ ]+:[^@/ ]+@'},
        @{n='azure-secret';s='HIGH'; re='(client_secret|CLIENT_SECRET)["'']?\s*[:=]\s*["'']?[A-Za-z0-9._~-]{20,}'},
        @{n='jwt';         s='MED';  re='eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'},
        @{n='generic-pass';s='MED';  re='(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)["'']?\s*[:=]\s*["'']?[^"'' ]{4,}'}
    )
    $extOK='\.(txt|ini|cfg|conf|config|env|xml|json|yml|yaml|ps1|psm1|bat|cmd|vbs|js|py|php|java|cs|sql|properties|pem|key|log|md|sh)$'
    function Mask($s){ [regex]::Replace($s,'([A-Za-z0-9+/_-]{3})[A-Za-z0-9+/_=.-]{4,}([A-Za-z0-9+/_-]{2})','$1***$2') }

    Sect "Scanning for secrets"
    $files = foreach($p in $Path){ if (Test-Path $p){ Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt ($MaxMB*1MB) -and ($_.Name -match 'id_rsa|id_ed25519|\.npmrc|\.git-credentials' -or $_.Extension -match '\.(txt|ini|cfg|conf|config|env|xml|json|yml|yaml|ps1|psm1|bat|cmd|vbs|js|py|php|java|cs|sql|properties|pem|key|log|md|sh)') -and $_.FullName -notmatch '\\(node_modules|\.git|AppData\\Local\\Microsoft|WinSxS)\\' } } }
    $files = $files | Select-Object -Unique
    Flag 'INFO' "Candidate files to scan: $($files.Count)."

    $hits=New-Object System.Collections.Generic.List[string]
    foreach($f in $files){
        $content = Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue
        if (-not $content){ continue }
        $ln=0
        foreach($line in $content){
            $ln++
            foreach($pat in $patterns){
                if ($line -match $pat.re){
                    $snip = if ($line.Length -gt 120){ $line.Substring(0,120) } else { $line }
                    $hits.Add(("{0}|{1}|{2}:{3}|{4}" -f $pat.s,$pat.n,$f.FullName,$ln,(Mask $snip.Trim())))
                    break
                }
            }
        }
    }
    $hits = $hits | Select-Object -Unique
    $hits | Out-File (Join-Path $run '01_matches.txt') -Encoding UTF8
    if ($hits.Count){
        foreach($pn in ($patterns.n)){
            $grp = @($hits | Where-Object { $_ -match "\|$pn\|" })
            if ($grp.Count){ $parts=$grp[0] -split '\|'; Flag $parts[0] "$($grp.Count) x $pn (e.g. $($parts[2])) - see 01_matches.txt (values masked)." }
        }
    } else { Flag 'INFO' "No secrets matched in the scanned paths." }

    Sect "Writing ranked summary"
    $high=$summary|Where-Object{$_ -like '`[HIGH`]*'}; $med=$summary|Where-Object{$_ -like '`[MED *'}; $info=$summary|Where-Object{$_ -like '`[INFO`]*'}
    $sf=New-Object System.Collections.Generic.List[string]
    $sf.Add("RTSecretScan summary - $env:COMPUTERNAME - $(Get-Date)"); $sf.Add("Paths: $($Path -join '; ')"); $sf.Add("")
    $sf.Add("### HIGH ($($high.Count)) ###"); $high | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### MED ($($med.Count)) ###"); $med | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### INFO ($($info.Count)) ###"); $info | ForEach-Object { $sf.Add($_) }
    ($sf -join "`r`n") | Out-File (Join-Path $run '00_SUMMARY.txt') -Encoding UTF8
    if ($Json){ $jb=[ordered]@{ host=$env:COMPUTERNAME; ts=$stamp; high=@($high); med=@($med); info=@($info) }; ($jb|ConvertTo-Json -Depth 5)|Out-File (Join-Path $run 'findings.json') -Encoding UTF8 }

    Log "`n[+] Done. HIGH=$($high.Count) MED=$($med.Count) INFO=$($info.Count)  (matches: $run\01_matches.txt)" 'Green'
    return $run
}

if ($MyInvocation.InvocationName -ne '.') {
    # exit: 0 = success, 2 = runtime error (orchestrator treats >=2 as module failure)
    try { Invoke-RTSecretScan @PSBoundParameters | Out-Null; exit 0 } catch { Write-Error $_; exit 2 }
}
