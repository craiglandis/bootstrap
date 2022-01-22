<#
(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/craiglandis/scripts/master/install-wmf.ps1', "$env:windir\temp\install-wmf.ps1"); set-executionpolicy unrestricted -force; invoke-expression -command "$env:windir\temp\install-wmf.ps1"
$imageName = 'MicrosoftWindowsServer.WindowsServer.2008-R2-SP1-smalldisk.2.127.20180613'
new -resourceGroupName test1 -name test1 -imageName 'MicrosoftWindowsServer.WindowsServer.2008-R2-SP1-smalldisk.2.127.20180613'
https://virtual-simon.co.uk/deploying-multiple-vms-arm-templates-use-copy-copyindex/
https://github.com/Azure/azure-quickstart-templates/tree/master/201-vm-copy-index-loops
https://github.com/Azure/azure-quickstart-templates/tree/master/201-vm-copy-managed-disks/
https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-multiple
https://stackoverflow.com/questions/50593595/arm-template-how-create-multiple-vms-with-private-ips-in-one-resource-group
#>

function out-log()
{
    param(
        [string]$text,
        [string]$prefix = 'timespan'
    )

    if ($prefix -eq 'timespan' -and $startTime)
    {
        $timespan = New-TimeSpan -Start $startTime -End (Get-Date)
        $timespanString = '[{0:mm}:{0:ss}]' -f $timespan
        Write-Host $timespanString -NoNewline -ForegroundColor Cyan
        Write-Host " $text"
        (($timespanString + " $text") | Out-String).Trim() | Out-File $logFile -Append
    }
    elseif ($prefix -eq 'both' -and $startTime)
    {
        $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
        $timespan = New-TimeSpan -Start $startTime -End (Get-Date)
        $timespanString = "$($timestamp) $('[{0:mm}:{0:ss}]' -f $timespan)"
        Write-Host $timespanString -NoNewline -ForegroundColor White
        Write-Host " $text"
        (($timespanString + " $text") | Out-String).Trim() | Out-File $logFile -Append
    }
    else
    {
        $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
        Write-Host $timestamp -NoNewline -ForegroundColor Cyan
        Write-Host " $text"
        (($timestamp + $text) | Out-String).Trim() | Out-File $logFile -Append
    }
}

Set-StrictMode -Version Latest

$startTime = Get-Date
$timestamp = Get-Date $startTime -Format yyyyMMddhhmmss
$scriptPath = $MyInvocation.MyCommand.Path
$scriptPathParent = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$scriptName = (Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).Split('.')[0]
#$logFile = "$scriptPathParent\$($scriptName)_$($timestamp).log"
$logFile = "$env:TEMP\$($scriptName)_$($timestamp).log"
out-log "scriptPath : $scriptPath"
out-log "scriptPathParent : $scriptPathParent"
out-log $logFile

# If this script is run from CSE, this makes it so I don't have to allows script later
# Obviously if I'm manually running the script I've typically already configured the execution policy in advance
Set-ExecutionPolicy -ExecutionPolicy ByPass -Force

$webClient = New-Object System.Net.WebClient

if ((Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -ge 461814)
{
    out-log 'NET Framework 4.72 already installed'
}
else
{
    out-log 'Installing NET Framework 4.72'
    $url = 'https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe'
    $fileName = $url -split '/' | Select-Object -Last 1
    $filePath = "$env:TEMP\$fileName"
    $webClient.DownloadFile($url, $filePath)
    Invoke-Expression -Command "$filePath /q /norestart"

    do
    {
        out-log 'Waiting for NET Framework 4.72 install to complete'
        Start-Sleep -Seconds 5
    } until ((Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -ge 461814)
    out-log 'NET Framework 4.72 install completed'
}

$osVersion = Get-WmiObject -Query 'Select Version from Win32_OperatingSystem'
$osVersion = $osVersion.Version
out-log "osVersion: $osVersion"
switch ($osVersion)
{
    '6.1.7601' {$hotfixId = 'KB3191566'}
    '6.2.9200' {$hotfixId = 'KB3191565'}
    '6.3.9600' {$hotfixId = 'KB3191564'}
}

$hotfixInstalled = Get-WmiObject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='$hotfixId'"
$psVersion = $PSVersionTable.PSVersion
out-log "PowerShell version: $psVersion"

if ($hotfixInstalled -and $psVersion -ge 5.1)
{
    out-log "WMF5.1 ($hotfixId) already installed and PowerShell version is $psVersion"
    exit
}
elseif ($hotfixInstalled -and $psVersion -lt 5.1)
{
    out-log "WMF5.1 ($hotfixId) already installed but PowerShell version is $psVersion, Windows restart still needed"
    exit
}
else
{
    out-log "$hotfixId not installed and PowerShell version is $psVersion, continuing with WMF 5.1 ($hotfixId) install"
}

switch ($osVersion)
{
    '6.1.7601' {$url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip'}
    '6.2.9200' {$url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu'}
    '6.3.9600' {$url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu'}
}

$fileName = $url -split '/' | Select-Object -Last 1
$filePath = "$env:TEMP\$fileName"
out-log "Downloading $url to $filepath"
$webClient.DownloadFile($url, $filePath)

if ($fileName.EndsWith('.zip'))
{
    $extractedFilePath = "$env:TEMP\$($fileName.Split('.')[0])"
    out-log "Extracting $fileName to $extractedFilePath"
    if (!(Test-Path $extractedFilePath))
    {
        New-Item -Path $extractedFilePath -ItemType Directory -Force | Out-Null
    }

    $shell = New-Object -com shell.application
    $zip = $shell.NameSpace($filePath)
    foreach ($item in $zip.items())
    {
        $shell.Namespace($extractedFilePath).copyhere($item)
    }

    while ((Get-ChildItem -Path $extractedFilePath -Recurse -Force).Count -lt $zip.Items().Count)
    {
        Start-Sleep -Seconds 1
    }
    $command = "$extractedFilePath\Install-WMF5.1.ps1 -AcceptEULA -AllowRestart"
    out-log $command
    Invoke-Expression -Command $command
    out-log "Windows will automatically restart after the WMF5.1 silent install completes"
    exit
}
else
{
    $wusa = "$env:windir\System32\wusa.exe"
    $command = "Start-Process -FilePath $wusa -ArgumentList $filePath, '/quiet', '/norestart' -Wait"
    out-log $command
    Invoke-Expression -Command $command
    exit
}

do
{
    Start-Sleep 5
    out-log 'Installing WMF 5.1...'
} until (Get-WmiObject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='$hotfixId'")
# I don't remember why I was scheduling the install-wmf5.1.ps1 to run AGAIN after restart on 2008R2
# out-log "Creating onstart scheduled task to run script again at startup:"
# schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr "powershell.exe -executionpolicy bypass -file $scriptPath" /f
if ($?)
{
    out-log 'Restarting to complete WMF 5.1 install'
    Restart-Computer -Force
    exit
}
else
{
    exit
}

<#
I think this got fixed in a WMF 5.1 re-release, regardless, it only caused a sysprep issue, and only on 2008R2/Win7
if (get-wmiobject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='KB3191566'")
{
    out-log "Setting LastFullPayloadTime reg value to workaround WMF 5.1 sysprep issue"
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\StreamProvider -Name LastFullPayloadTime -Value 0 -PropertyType DWord -Force | Out-Null
}
#>

if (Get-PackageProvider | Where-Object {$_.Name -eq 'NuGet'})
{
    out-log 'NuGet already installed'
}
else
{
    out-log 'Installing NuGet'
    Install-PackageProvider -Name NuGet -Force | Out-Null
}

if ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq 'Trusted')
{
    out-log 'PSGallery installation policy is already Trusted'
}
else
{
    out-log 'Setting PSGallery installation policy to Trusted'
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

<#
if (get-module -name PSWindowsUpdate -ListAvailable)
{
    out-log "PSWindowsUpdate module already installed"
}
else
{
    out-log "Installing PSWindowsUpdate module"
    install-module -name PSWindowsUpdate -Force
}
#>

<#
out-log "Installing Windows Updates"
get-windowsupdate -Install -AcceptAll -AutoReboot -IgnoreUserInput -RecurseCycle 5 -verbose
#>
