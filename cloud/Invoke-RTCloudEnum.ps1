<#
    Invoke-RTCloudEnum.ps1
    ============================================================================
    Red Team ENTRA ID / AZURE posture enumeration from a Windows host.
    Cloud companion to Invoke-RTEnum.ps1 - same ranked findings model.

    SCOPE: DETECTION & PRIORITISATION (read-only). It reports what cloud-identity
    exposure exists on this host and ranks it HIGH/MED/INFO. It does NOT perform
    credential theft; where a finding implies a follow-up, it names the public
    tool/technique by reference so you can decide and act deliberately.

    WHAT IT CHECKS
      - Azure IMDS: is this an Azure VM? is a Managed Identity attached?
      - Device join posture via dsregcmd (Azure AD joined / hybrid / PRT present)
      - Live local sessions: az CLI, Az PowerShell, Graph/AzureAD modules
      - On-disk Azure token/profile caches
      - Hybrid: Azure AD Connect (sync server) presence

    USAGE
        . .\Invoke-RTCloudEnum.ps1
        Invoke-RTCloudEnum
        Invoke-RTCloudEnum -OutDir C:\loot -Json
    ============================================================================
#>
[CmdletBinding()]
param([string]$OutDir="$PWD",[switch]$Json)

function Invoke-RTCloudEnum {
    [CmdletBinding()]
    param([string]$OutDir="$PWD",[switch]$Json)
    $ErrorActionPreference='SilentlyContinue'; $WarningPreference='SilentlyContinue'

    $summary=New-Object System.Collections.Generic.List[string]
    function Log($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
    function Sect($n){ Log "`n[==== $n ====]" 'Cyan' }
    function Flag($sev,$txt){ $tag=switch($sev){'HIGH'{'[HIGH]'}'MED'{'[MED ]'}default{'[INFO]'}}; $line="$tag $txt"; if($summary.Contains($line)){return}; $summary.Add($line); $col=switch($sev){'HIGH'{'Red'}'MED'{'Yellow'}default{'DarkGray'}}; Log $line $col }

    $stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
    $run=Join-Path $OutDir ("CloudEnum_{0}_{1}" -f $env:COMPUTERNAME,$stamp)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    function Save($f,$d){ $d | Out-File -FilePath (Join-Path $run $f) -Encoding UTF8 -Width 4096 }
    Log "[*] Invoke-RTCloudEnum  ->  $run" 'Green'

    $imds='169.254.169.254'

    # ---------------- Azure IMDS (identify VM + whether an MI is attached) ----------------
    Sect "Azure IMDS / Managed Identity (presence)"
    $azMeta=$null
    try { $azMeta=Invoke-RestMethod -Headers @{Metadata='true'} -Uri "http://$imds/metadata/instance?api-version=2021-02-01" -TimeoutSec 3 } catch {}
    if ($azMeta) {
        Flag 'INFO' "Azure VM reachable via IMDS (vmId $($azMeta.compute.vmId))."
        Flag 'INFO' "Subscription $($azMeta.compute.subscriptionId) / RG $($azMeta.compute.resourceGroupName) / $($azMeta.compute.location)."
        Save '01_azure_meta.json' ($azMeta | ConvertTo-Json -Depth 6)
        $mi=$null
        try { $mi=Invoke-RestMethod -Headers @{Metadata='true'} -Uri "http://$imds/metadata/identity/info?api-version=2018-02-01" -TimeoutSec 3 } catch {}
        if ($mi) { Flag 'HIGH' "A Managed Identity is attached to this VM (IMDS identity endpoint responds). This host can obtain ARM/Graph tokens for that identity - scope its role assignments and treat it as reachable cloud access." }
        else     { Flag 'INFO' "No managed-identity info returned (none attached, or endpoint restricted)." }
    } else { Flag 'INFO' "No Azure IMDS reachable (not an Azure VM, or IMDS blocked)." }

    # ---------------- device join posture ----------------
    Sect "Device join posture (dsregcmd)"
    $ds = dsregcmd /status 2>$null
    if ($ds){
        Save '02_dsregcmd.txt' ($ds | Out-String)
        $aadj = ($ds | Select-String 'AzureAdJoined\s*:\s*YES')
        $prt  = ($ds | Select-String 'AzureAdPrt\s*:\s*YES')
        $drj  = ($ds | Select-String 'DomainJoined\s*:\s*YES')
        if ($aadj){ Flag 'MED' "Host is Azure AD joined." }
        if ($drj -and $aadj){ Flag 'INFO' "Hybrid-joined (on-prem AD + Entra) - an on-prem compromise may bridge to cloud identity." }
        if ($prt){ Flag 'HIGH' "A Primary Refresh Token (PRT) is present for the signed-in user - a high-value SSO artifact to Entra. Factor it into the access model." }
    } else { Flag 'INFO' "dsregcmd not available or returned nothing." }

    # ---------------- local session reuse ----------------
    Sect "Local Azure sessions & token caches"
    $s=New-Object System.Collections.Generic.List[string]
    if (Get-Command az -EA SilentlyContinue){
        $acct = az account show 2>$null
        if ($acct){ Flag 'HIGH' "az CLI is already authenticated - the engagement identity can act as that principal. Enumerate: az ad user list / az role assignment list --all."; $s.Add("az account show:"); $s.Add(($acct | Out-String)) }
    }
    foreach($p in @("$env:USERPROFILE\.azure\msal_token_cache.bin","$env:USERPROFILE\.azure\accessTokens.json","$env:USERPROFILE\.azure\azureProfile.json")){
        if (Test-Path $p){ Flag 'HIGH' "Azure CLI token/profile cache on disk: $p"; $s.Add("FOUND: $p") }
    }
    if (Get-Module -ListAvailable Az.Accounts){
        $ctx = try { Get-AzContext 2>$null } catch {}
        if ($ctx.Account){ Flag 'HIGH' "Az PowerShell has a live context: $($ctx.Account.Id) ($($ctx.Subscription.Name)). Enumerate: Get-AzADUser / Get-AzRoleAssignment." }
        else { Flag 'INFO' "Az.Accounts module installed (no live context)." }
    }
    if (Get-Module -ListAvailable Microsoft.Graph){ Flag 'INFO' "Microsoft.Graph module installed - Connect-MgGraph enables Entra enumeration." }
    if (Get-Module -ListAvailable AzureAD){ Flag 'INFO' "AzureAD module installed (legacy) - Connect-AzureAD; Get-AzureADUser." }
    Save '03_sessions.txt' ($s -join "`r`n")

    # ---------------- hybrid hints ----------------
    Sect "Hybrid identity hints"
    if (Get-Service ADSync -EA SilentlyContinue){ Flag 'HIGH' "Azure AD Connect (ADSync) service present on THIS host - this is a directory-sync server, a known high-value pivot between on-prem AD and Entra. Treat it as tier-0." }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Azure AD Connect'){ Flag 'MED' "Azure AD Connect registry key present." }

    # ---------------- summary ----------------
    Sect "Writing ranked summary"
    $high=$summary|Where-Object{$_ -like '`[HIGH`]*'}; $med=$summary|Where-Object{$_ -like '`[MED *'}; $info=$summary|Where-Object{$_ -like '`[INFO`]*'}
    $sf=New-Object System.Collections.Generic.List[string]
    $sf.Add("RTCloudEnum summary - $env:COMPUTERNAME - $(Get-Date)")
    $sf.Add(""); $sf.Add("### HIGH ($($high.Count)) ###"); $high | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### MED ($($med.Count)) ###"); $med | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### INFO ($($info.Count)) ###"); $info | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("=== NOTE ===")
    $sf.Add("Each HIGH above marks reachable cloud identity/access. Scope the associated role")
    $sf.Add("assignments (least-privilege check) and record it in the engagement access model.")
    Save '00_SUMMARY.txt' ($sf -join "`r`n")

    if ($Json){
        $jb=[ordered]@{ host=$env:COMPUTERNAME; ts=$stamp; high=@($high); med=@($med); info=@($info) }
        ($jb | ConvertTo-Json -Depth 5) | Out-File (Join-Path $run 'findings.json') -Encoding UTF8
    }

    Log "`n[+] Done. HIGH=$($high.Count) MED=$($med.Count) INFO=$($info.Count)" 'Green'
    Log "[+] Read: $run\00_SUMMARY.txt" 'Green'
    return $run
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-RTCloudEnum @PSBoundParameters }
