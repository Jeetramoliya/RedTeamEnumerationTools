<#
    EnumGod - Red Team Enumeration Toolkit   |   Author: Jeet Ramoliya
    Invoke-RTNetScan.ps1
    ============================================================================
    Red Team NETWORK discovery & service fingerprint from a Windows foothold.
    Windows companion to network/net-sweep.sh - same ranked findings model.

    WHAT IT DOES  (ACTIVE - touches other hosts)
      - Discover live hosts (ARP cache + optional ping sweep of the local /24).
      - TCP-connect scan a curated red-team port list (native .NET, fast).
      - Fingerprint & flag SMB/LDAP/RDP/WinRM/web/DBs and pivot targets.

    NOISE  Port scanning is detectable. Default targets ARP-known live hosts
           (quiet-ish). -Target sweeps a CIDR/host/list. -Loud = full port set.

    USAGE
        . .\Invoke-RTNetScan.ps1
        Invoke-RTNetScan                         # scan live (ARP) hosts
        Invoke-RTNetScan -Target 10.0.0.0/24 -Loud -Json
        Invoke-RTNetScan -Target srv01,10.0.0.5 -OutDir C:\loot
    ============================================================================
#>
[CmdletBinding()]
param([string]$Target,[string]$OutDir="$PWD",[switch]$Loud,[switch]$Self,[switch]$Json,[int]$TimeoutMs=400)

function Invoke-RTNetScan {
    [CmdletBinding()]
    param([string]$Target,[string]$OutDir="$PWD",[switch]$Loud,[switch]$Self,[switch]$Json,[int]$TimeoutMs=400)
    $ErrorActionPreference='SilentlyContinue'

    $summary=New-Object System.Collections.Generic.List[string]
    $nextList=New-Object System.Collections.Generic.List[object]
    function Log($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }
    function Sect($n){ Log "`n[==== $n ====]" 'Cyan' }
    function Flag($sev,$txt){ $tag=switch($sev){'HIGH'{'[HIGH]'}'MED'{'[MED ]'}default{'[INFO]'}}; $line="$tag $txt"; if($summary.Contains($line)){return}; $summary.Add($line); $col=switch($sev){'HIGH'{'Red'}'MED'{'Yellow'}default{'DarkGray'}}; Log $line $col }
    function AddNext($t,$c){ $nextList.Add([pscustomobject]@{Title=$t;Cmd=$c}) }
    $stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
    $run=Join-Path $OutDir ("NetScan_{0}_{1}" -f $env:COMPUTERNAME,$stamp)
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    function Save($f,$d){ $d | Out-File -FilePath (Join-Path $run $f) -Encoding UTF8 -Width 4096 }
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
    Banner 'network discovery & services'
    Log "[*] Invoke-RTNetScan  ->  $run" 'Green'

    $portMap=@{ 21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';80='HTTP';110='POP3';111='RPCbind';135='MSRPC';139='SMB';143='IMAP';389='LDAP';443='HTTPS';445='SMB';636='LDAPS';993='IMAPS';1433='MSSQL';1521='Oracle-TNS';2049='NFS';2375='Docker-API';3306='MySQL';3389='RDP';5432='PostgreSQL';5900='VNC';5985='WinRM-HTTP';5986='WinRM-HTTPS';6379='Redis';8080='HTTP-alt';8443='HTTPS-alt';9200='Elasticsearch';11211='Memcached';27017='MongoDB' }
    $portsQuick=@(21,22,23,25,53,80,110,111,135,139,143,389,443,445,636,993,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,9200,11211,27017)
    $portsLoud=$portsQuick + @(88,123,161,465,587,623,873,2375,2376,3000,5000,5601,6443,7001,8000,8089,8888,9000,9090,10000)
    $ports = if ($Loud){ $portsLoud } else { $portsQuick }

    function Test-Port($h,$p,$toMs){
        $c=New-Object System.Net.Sockets.TcpClient
        try { $iar=$c.BeginConnect($h,$p,$null,$null); if ($iar.AsyncWaitHandle.WaitOne($toMs,$false) -and $c.Connected){ $c.Close(); return $true } } catch {}
        finally { $c.Close() }
        return $false
    }

    # local inventory
    Sect "Local interfaces & ARP neighbours"
    $li=New-Object System.Collections.Generic.List[string]
    $li.Add((Get-NetIPAddress -AddressFamily IPv4 2>$null | Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object IPAddress,PrefixLength,InterfaceAlias | Format-Table -Auto | Out-String))
    $arp = Get-NetNeighbor -AddressFamily IPv4 2>$null | Where-Object { $_.State -in 'Reachable','Stale' -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '224.*' -and $_.IPAddress -ne '255.255.255.255' }
    $li.Add("== ARP neighbours =="); $li.Add(($arp | Select-Object IPAddress,LinkLayerAddress | Format-Table -Auto | Out-String))
    Save '01_local.txt' ($li -join "`r`n")
    $myNet = Get-NetIPAddress -AddressFamily IPv4 2>$null | Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixLength -ge 24 } | Select-Object -First 1
    if ($myNet){ Flag 'INFO' "Local network: $($myNet.IPAddress)/$($myNet.PrefixLength) on $($myNet.InterfaceAlias)." }

    if ($Self){ Flag 'INFO' "-Self: local inventory only, no scanning."; }
    else {
        # build target list
        $hosts=New-Object System.Collections.Generic.List[string]
        if ($Target){
            foreach($t in ($Target -split ',')){
                $t=$t.Trim()
                if ($t -match '/24$'){ $p=($t -replace '\.0/24$',''); 1..254 | ForEach-Object { $hosts.Add("$p.$_") } }
                elseif ($t -match '/\d+$'){ Flag 'INFO' "Only /24 CIDR auto-expands in PS; scanning network base of $t."; $p=($t -split '/')[0]; $hosts.Add($p) }
                else { $hosts.Add($t) }
            }
        } else {
            # default: ARP-known live hosts + gateway
            $arp | ForEach-Object { $hosts.Add($_.IPAddress) }
            (Get-NetRoute -DestinationPrefix '0.0.0.0/0' 2>$null).NextHop | Where-Object { $_ -and $_ -ne '0.0.0.0' } | ForEach-Object { $hosts.Add($_) }
            Flag 'INFO' "No -Target; scanning $($hosts.Count) ARP-known live host(s). Use -Target <cidr> to sweep."
        }
        $hosts = $hosts | Select-Object -Unique | Where-Object { $_ }

        Sect "Port sweep ($(if($Loud){'loud'}else{'quick'})) over $($hosts.Count) host(s) [ACTIVE]"
        $svc=New-Object System.Collections.Generic.List[string]
        foreach($h in $hosts){
            foreach($p in $ports){
                if (Test-Port $h $p $TimeoutMs){
                    $lbl = if ($portMap[$p]){ $portMap[$p] } else { "tcp/$p" }
                    $svc.Add("$h $p $lbl"); Log "  $h`:$p ($lbl)" 'DarkGray'
                }
            }
        }
        Save '03_services.txt' ($svc -join "`r`n")
        if ($svc.Count){
            $openH = ($svc | ForEach-Object { ($_ -split ' ')[0] } | Select-Object -Unique).Count
            Flag 'INFO' "Live hosts with open ports: $openH (see 03_services.txt)."
            $flat = $svc -join "`n"
            if ($flat -match '(^|\n)\S+ 6379 ')  { Flag 'HIGH' "Redis (6379) exposed - often unauthenticated -> RCE."; AddNext "Redis unauth" "redis-cli -h <ip> ping; config get dir" }
            if ($flat -match '(^|\n)\S+ 2375 ')  { Flag 'HIGH' "Docker API (2375) exposed -> host root via container." }
            if ($flat -match '(^|\n)\S+ 2049 ')  { Flag 'HIGH' "NFS (2049) exposed - check exports (showmount -e)." }
            if ($flat -match '(^|\n)\S+ 445 ')   { Flag 'MED'  "SMB hosts present - test null/guest & signing (netexec smb <ip> -u '' -p '' --shares)."; AddNext "SMB triage" "netexec smb <ip> -u '' -p '' --shares" }
            if ($flat -match '(^|\n)\S+ 389 ')   { Flag 'MED'  "LDAP hosts present - run ldap-enum.sh / Invoke-RTEnum against them." }
            if ($flat -match '(^|\n)\S+ 1433 ')  { Flag 'MED'  "MSSQL (1433) present - try default/weak creds; PowerUpSQL." }
            if ($flat -match '(^|\n)\S+ 3306 ')  { Flag 'MED'  "MySQL (3306) present - test root/blank & weak creds." }
            if ($flat -match '(^|\n)\S+ 5985 ')  { Flag 'MED'  "WinRM present - creds -> evil-winrm." }
            if ($flat -match '(^|\n)\S+ 3389 ')  { Flag 'INFO' "RDP hosts present (lateral target with creds)." }
            if ($flat -match '(^|\n)\S+ 1521 ')  { Flag 'MED'  "Oracle TNS (1521) present - SID brute / odat." }
            if ($flat -match '(HTTP|HTTPS)')     { Flag 'INFO' "Web services present - screenshot & dirbust." }
        } else { Flag 'INFO' "No open ports found." }
    }

    # summary
    Sect "Writing ranked summary"
    $high=$summary|Where-Object{$_ -like '`[HIGH`]*'}; $med=$summary|Where-Object{$_ -like '`[MED *'}; $info=$summary|Where-Object{$_ -like '`[INFO`]*'}
    $sf=New-Object System.Collections.Generic.List[string]
    $sf.Add("RTNetScan summary - $env:COMPUTERNAME - $(Get-Date)")
    $sf.Add(""); $sf.Add("### HIGH ($($high.Count)) ###"); $high | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### MED ($($med.Count)) ###"); $med | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("### INFO ($($info.Count)) ###"); $info | ForEach-Object { $sf.Add($_) }
    $sf.Add(""); $sf.Add("=== RECOMMENDED NEXT MOVE ===")
    $rec=$nextList|Select-Object -First 1
    if ($rec){ $sf.Add("-> $($rec.Title)"); $sf.Add("   $($rec.Cmd)") } else { $sf.Add("-> Review 03_services.txt and pivot to a service.") }
    Save '00_SUMMARY.txt' ($sf -join "`r`n")
    if ($nextList.Count){ $ns=New-Object System.Collections.Generic.List[string]; $ns.Add("# Pre-filled next-steps`r`n"); $i=1; foreach($n in $nextList){ $ns.Add("[$i] $($n.Title)"); $ns.Add("    $($n.Cmd)"); $ns.Add(""); $i++ }; Save 'NEXT_STEPS.txt' ($ns -join "`r`n") }
    if ($Json){ $jb=[ordered]@{ host=$env:COMPUTERNAME; target="$Target"; ts=$stamp; high=@($high); med=@($med); info=@($info); next_steps=$nextList.ToArray() }; ($jb|ConvertTo-Json -Depth 5)|Out-File (Join-Path $run 'findings.json') -Encoding UTF8 }

    Log "`n[+] Done. HIGH=$($high.Count) MED=$($med.Count) INFO=$($info.Count)" 'Green'
    Log "[+] Read: $run\00_SUMMARY.txt" 'Green'
    return $run
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-RTNetScan @PSBoundParameters }
