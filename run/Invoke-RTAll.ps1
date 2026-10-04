<#
    EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
    ============================================================================
    Invoke-RTAll.ps1 - orchestrator: run the EnumGod Windows modules into ONE
    master directory, then build a consolidated HTML report (eg-report.py if
    python is present).

    USAGE
        . .\run\Invoke-RTAll.ps1
        Invoke-RTAll                                  # local+AD + secrets + cloud + netscan(ARP)
        Invoke-RTAll -Net 10.0.0.0/24 -OutDir C:\loot
        Invoke-RTAll -Quick -NoCloud
    ============================================================================
#>
[CmdletBinding()]
param([string]$OutDir="$PWD",[switch]$Quick,[string]$Net,[switch]$NoCloud,[switch]$NoSecrets,[string]$Domain)

function Invoke-RTAll {
    [CmdletBinding()]
    param([string]$OutDir="$PWD",[switch]$Quick,[string]$Net,[switch]$NoCloud,[switch]$NoSecrets,[string]$Domain)
    $root = Split-Path $PSScriptRoot -Parent
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $master = Join-Path $OutDir ("EnumGod_{0}_{1}" -f $env:COMPUTERNAME,$ts)
    New-Item -ItemType Directory -Path $master -Force | Out-Null
    Write-Host "[*] EnumGod Invoke-RTAll -> $master" -ForegroundColor Green

    function RunMod($file,$fn,$args){
        $p = Join-Path $root $file
        if (-not (Test-Path $p)){ return }
        Write-Host "[>] $fn" -ForegroundColor Cyan
        . $p
        try { & $fn @args -OutDir $master -Json 3>$null 6>$null | Out-Null } catch { Write-Host "    ($fn failed: $($_.Exception.Message))" -ForegroundColor DarkGray }
    }

    $enumArgs = @{}; if ($Quick){ $enumArgs.Quick = $true }; if ($Domain){ $enumArgs.Domain = $Domain }
    RunMod 'windows\Invoke-RTEnum.ps1' 'Invoke-RTEnum' $enumArgs
    if (-not $NoSecrets){ RunMod 'secrets\Invoke-RTSecretScan.ps1' 'Invoke-RTSecretScan' @{} }
    if (-not $NoCloud){   RunMod 'cloud\Invoke-RTCloudEnum.ps1'   'Invoke-RTCloudEnum'  @{} }
    if ($Net){ RunMod 'network\Invoke-RTNetScan.ps1' 'Invoke-RTNetScan' @{ Target = $Net } }
    else {     RunMod 'network\Invoke-RTNetScan.ps1' 'Invoke-RTNetScan' @{} }

    Write-Host "[*] building consolidated report..." -ForegroundColor Green
    $py = Get-Command python,python3 -ErrorAction SilentlyContinue | Select-Object -First 1
    $rep = Join-Path $root 'tools\eg-report.py'
    if ($py -and (Test-Path $rep)){
        & $py.Source $rep $master -o (Join-Path $master 'EnumGod-report.html') --save-merged (Join-Path $master 'merged.json') --title "EnumGod - $env:COMPUTERNAME - $ts"
        Write-Host "[+] report: $master\EnumGod-report.html" -ForegroundColor Green
        Write-Host "[i] next hop: re-run, then python eg-report.py <new-master> --diff $master\merged.json" -ForegroundColor DarkGray
    } else {
        Write-Host "[i] python not found - per-module 00_SUMMARY.txt files are under $master" -ForegroundColor DarkGray
    }
    return $master
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-RTAll @PSBoundParameters }
