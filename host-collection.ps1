# Script to collect simple baseline information for comparison

# example command: host-collection.ps1 -targets ./targs.txt -files filelist.txt -registry reglist.txt
# targs.txt contains IP addresses, one per line
# filelist.txt contains file paths to hash
# reglist.txt contains registry keys to collect in the following formats:
#       HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run
#    or Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Run
# default file names are show below if not provided on the command line

param (
    [string]$targets = "./targs.txt",
    [string]$files = "./filelist.txt",
    [string]$registry = "./registrylist.txt",
    [switch]$help = $false
)

if ($help) {
    Write-Output "Script to collect simple baseline information for comparison`n"
    Write-Output "Options:"
    Write-Output "  -t, -targets    - target file contain IP addresses, one per line"
    Write-Output "  -f, -files      - file containing file paths to hash"
    Write-Output "  -r, -registry   - file containing registry keys to collect in the following formats:"
    Write-Output "                        HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run"
    Write-Output "                     or Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Run`n"
    Write-Output "Example command: "
    Write-Output "  host-collection.ps1 -targets ./targs.txt -files filelist.txt -registry reglist.txt`n"
    
    return
}

$timestamp = Get-Date -f yyyy-MM-ddThhmmss

Write-Progress -Activity "Gathering host data..." -Status "Getting Credentials"
$cred = Get-Credential

Write-Progress -Activity "Gathering host data..." -Status "Reading Targets List"
$targ_ips = Get-Content $targets
$files_to_hash = Get-Content $files
$registry_keys = Get-Content $registry

foreach ($ip in $targ_ips){
    Write-Progress -id 0 -Activity "Collecting Host Data..." -status "Collecting from $ip..." -PercentComplete ($targ_ips.indexof($ip)/$targ_ips.count*100)
    
    Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Adding $ip as a trusted host"
    Set-Item wsman:\localhost\client\trustedhosts -value $ip.tostring() -force

    $ipsession = New-PSSession -ComputerName $ip -Credential $cred

    if($ipsession){
        # Gather and analyze hashes from identified systems within the DAL via 275 COS TTPs (automated tools/scripts, crew-aids, etc)
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting file hashes..." -status "Progress:" -PercentComplete 8.33
        $host_hashes = Invoke-Command -Session $ipsession -ScriptBlock {Get-FileHash -Path $Using:files_to_hash} | select-object Algorithm, Hash, Path 
        $host_hashes | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_hashes.txt")

        # Gather and analyze active and listening IP src & dest from identified systems within the DAL via 275 COS TTPs (automated tools/scripts, crew-aids, etc)
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting netstat info..." -status "Progress:" -PercentComplete 16.66
        $host_netstat = Invoke-Command -Session $ipsession -ScriptBlock {
            Get-NetTCPConnection -ErrorAction ignore
            Get-NetUDPEndpoint -ErrorAction ignore
        }
        $host_netstat | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_netstat.txt")

        # Gather and analyze process list from identified systems within the DAL via 275 COS TTPs (automated tools/scripts, crew-aids, etc)
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting processes..." -status "Progress:" -PercentComplete 25
        $host_process = Invoke-Command -Session $ipsession -ScriptBlock {Get-Process}
        $host_process | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_process.txt")

        # Gather and analyze registry hive from identified systems within the DAL via 275 COS TTPs (automated tools/scripts, crew-aids, etc)
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting registry info..." -status "Progress:" -PercentComplete 33.33
        $host_registry = Invoke-Command -Session $ipsession -ScriptBlock {Get-ItemProperty $Using:registry_keys}
        $host_registry | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_registry.txt")

        # Gather and analyze host/server firewall rules/status from identified systems within the DAL via 275 COS TTPs (automated tools/scripts, crew-aids, etc)
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting firewall rules..." -status "Progress:" -PercentComplete 41.65
        $host_firewall = Invoke-Command -Session $ipsession -ScriptBlock {Get-NetFirewallRule -all}
        $host_firewall | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_firewall.txt")

        # Gather and analyze host/server network shares from identified systems within the DAL via 275 COS TTPs (automated tools/scripts, crew-aids, etc)
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting smb shares..." -status "Progress:" -PercentComplete 50
        $host_smbshare = Invoke-Command -Session $ipsession -ScriptBlock {Get-SmbShare}
        $host_smbshare | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_smbshare.txt")

        # Get systeminfo
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting system info..." -status "Progress:" -PercentComplete 58.33
        $host_sysinfo = Invoke-Command -Session $ipsession -ScriptBlock {Get-CimInstance Win32_Operatingsystem | Format-List *}
        $host_sysinfo | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_sysinfo.txt")

        # Get Services
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting services..." -status "Progress:" -PercentComplete 66.64
        $host_services = Invoke-Command -Session $ipsession -ScriptBlock {Get-Service}
        $host_services | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_servies.txt")

        # Get IP Configuration
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting IP configuration..." -status "Progress:" -PercentComplete 75
        $host_netconfig = Invoke-Command -Session $ipsession -ScriptBlock {Get-NetIPConfiguration; Get-NetRoute}
        $host_netconfig | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_netconfig.txt")

        # Get Scheduled Tasks
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting scheduled tasks..." -status "Progress:" -PercentComplete 83.30
        $host_schedtasks = Invoke-Command -Session $ipsession -ScriptBlock {Get-ScheduledTask}
        $host_schedtasks | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_schedtasks.txt")

        # Get Users
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Collecting users..." -status "Progress:" -PercentComplete 91.63
        $host_users = Invoke-Command -Session $ipsession -ScriptBlock {Get-LocalUser}
        $host_users | ConvertTo-Json | out-file ($ip.tostring() + "_" + $timestamp + "_users.txt")

        # Close session
        Write-Progress -id (($targ_ips.indexof($ip))+1) -parentid 0 -Activity "Done Collecting from $ip" -status "Progress:" -PercentComplete 100 -Completed
        Remove-PSSession -Session $ipsession
        Clear-Variable host_*, ipsession
    }
    else {
        Write-Warning "Establishing session to $ip failed"
    }
}
