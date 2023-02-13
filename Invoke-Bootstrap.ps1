# [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;(New-Object Net.Webclient).DownloadFile('https://raw.githubusercontent.com/craiglandis/bootstrap/main/Invoke-Bootstrap.ps1', "$env:SystemDrive\Invoke-Bootstrap.ps1");Invoke-Expression -command $env:SystemDrive\Invoke-Bootstrap.ps1
# [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\src\bootstrap\Invoke-Bootstrap.ps1 -userName craig -password $password -bootstrapScriptUrl https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1
param(
    [string]$userName,
    [string]$password,
    [string]$bootstrapScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1'
)

function Out-Log
{
    param(
        [string]$text,
        [string]$prefix = 'timespan',
        [switch]$raw
    )
    if ($raw)
    {
        $text
    }
    elseif ($prefix -eq 'timespan' -and $scriptStartTime)
    {
        $timespan = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
        $prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
    }
    elseif ($prefix -eq 'both' -and $scriptStartTime)
    {
        $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
        $timespan = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
        $prefixString = "$($timestamp) $('{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan)"
    }
    else
    {
        $prefixString = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
    }
    Write-Host $prefixString -NoNewline -ForegroundColor Cyan
    Write-Host " $text"
    if ($logFilePath)
    {
        "$prefixString $text" | Out-File $logFilePath -Append
    }
}

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Out-Log $command
    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        Out-Log -Message "Failed: $command"
        Out-Log "$LASTEXITCODE : $LASTEXITCODE"
    }
}

function Invoke-Schtasks
{
    $taskRun = "powershell.exe -ExecutionPolicy Bypass -File $scriptPath -userName $userName -password $password -bootstrapScriptUrl $bootstrapScriptUrl"
    Invoke-ExpressionWithLogging -command "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"$taskRun`" /f"
    $task = Invoke-ExpressionWithLogging -command 'schtasks /Query /TN bootstrap'
    if ($task)
    {
        Out-Log 'Bootstrap scheduled task successfully created'
    }
    else
    {
        Out-Log 'Failed to create bootstrap scheduled task'
    }
}

function Enable-PSLogging
{
    Invoke-ExpressionWithLogging -command '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072'
    $getPSLoggingScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Get-PSLogging.ps1'
    $getPSLoggingScriptName = $getPSLoggingScriptUrl.Split('/')[-1]
    $getPSLoggingScriptFilePath = "$scriptsPath\$getPSLoggingScriptName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$getPSLoggingScriptUrl`', `'$getPSLoggingScriptFilePath`')"
    Invoke-ExpressionWithLogging -Command "& `'$getPSLoggingScriptFilePath`' -Enable"
}

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptPath = $MyInvocation.MyCommand.Path
$scriptName = Split-Path -Path $scriptPath -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$bootstrapPath = "$env:SystemDrive\bootstrap"
$logFilePath = "$bootstrapPath\$($scriptBaseName)_$(Get-Date -Format yyyyMMddhhmmss).log"
if ((Test-Path -Path (Split-Path -Path $logFilePath -Parent) -PathType Container) -eq $false)
{
    New-Item -Path (Split-Path -Path $logFilePath -Parent) -ItemType Directory -Force | Out-Null
}

$windowsIdentityName = Invoke-ExpressionWithLogging -command '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name'
$isSystem = Invoke-ExpressionWithLogging -command '[System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem'
Out-Log "Running as USER   : $windowsIdentityName"
Out-Log "Running as SYSTEM : $isSystem"

if (Test-Path -Path $bootstrapPath -PathType Container)
{
    Out-Log "$bootstrapPath already exists, don't need to create it"
}
else
{
    Out-Log "Creating $bootstrapPath"
    New-Item -Path $bootstrapPath -ItemType Directory -Force | Out-Null
}

$scriptsPath = "$bootstrapPath\scripts"
if (Test-Path -Path $scriptsPath -PathType Container)
{
    Out-Log "$scriptsPath already exists, don't need to create it"
}
else
{
    Out-Log "Creating $scriptsPath"
    New-Item -Path $scriptsPath -ItemType Directory -Force | Out-Null
}

$logsPath = "$bootstrapPath\logs"
if (Test-Path -Path $logsPath -PathType Container)
{
    Out-Log "$logsPath already exists, don't need to create it"
}
else
{
    Out-Log "Creating $logsPath"
    New-Item -Path $logsPath -ItemType Directory -Force | Out-Null
}

if ((Get-WmiObject -Class Win32_Baseboard -ErrorAction SilentlyContinue).Product -eq 'Virtual Machine')
{
    $isVM = $true
}
else
{
    $isVM = $false
}

if ($isVM)
{
    $dDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq 'D:'}
    if ($dDrive)
    {
        Out-Log "Drive $($dDrive.DeviceID) Name: $($dDrive.VolumeName) Type: $($dDrive.DriveType) Size: $([Math]::Round($dDrive.Size / 1GB, 2))GB Free: $([Math]::Round($dDrive.FreeSpace / 1GB, 2))GB"
    }

    $tempDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.VolumeName -eq 'Temporary Storage'}
    if ($tempDrive)
    {
        $tempDrive = $tempDrive.DeviceID
        $packagesPath = "$tempDrive\packages"

        # Delete CBS\*.log and DataStore.edb to free up space
        $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
        $systemDriveSizeGB = [Math]::Round($systemDrive.Size / 1GB, 2)
        $systemDriveFreeSpaceGBBefore = [Math]::Round($systemDrive.FreeSpace / 1GB, 2)
        Invoke-ExpressionWithLogging -command "Drive $env:SystemDrive Size: $systemDriveSizeGB GB, Free: $systemDriveFreeSpaceGBBefore GB"
        Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:SystemRoot\Logs\CBS\*.log -Force"
        Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:SystemRoot\SoftwareDistribution\DataStore\DataStore.edb -Force"
        $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}
        $systemDriveFreeSpaceGBAfter = [Math]::Round($systemDrive.FreeSpace / 1GB, 2)
        Invoke-ExpressionWithLogging -command "Drive $env:SystemDrive Size: $systemDriveSizeGB GB, Free: $systemDriveFreeSpaceGBAfter GB (deleting CBS logs and DataStore.edb freed $($systemDriveFreeSpaceGBAfter - $systemDriveFreeSpaceGBBefore) GB)"

        # Ephemeral OS disk VMs put the pagefile on C: for some reason, which takes up space, so putting it on the temp drive D:
        # Sets initial/maximum both to size of RAM + 1GB unless that is more than 50% of temp drive free space, in which case set it to 50% temp drive free space
        $currentPagingFilesValue = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' -Name PagingFiles).PagingFiles
        Out-Log "Current PagingFiles value: $currentPagingFilesValue"
        $tempDisk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.VolumeName -eq 'Temporary Storage'}
        $halfTempDiskFreeSpaceMB = [Math]::Round($tempDisk.FreeSpace / 1MB, 0) / 2
        Out-Log "$halfTempDiskFreeSpaceMB MB is half the free space on $($tempDisk.DeviceID)"
        $totalPhysicalMemoryMBPlus1MB = [Math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB) + 1
        Out-Log "$totalPhysicalMemoryMBPlus1MB total MB physical memory plus 1MB"
        if ($totalPhysicalMemoryMBPlus1MB -gt $halfTempDiskFreeSpaceMB)
        {
            $newPageFileSizeMB = $halfTempDiskFreeSpaceMB
        }
        else
        {
            $newPageFileSizeMB = $totalPhysicalMemoryMBPlus1MB
        }
        $newPagingFilesValue = "$($tempDisk.DeviceID)\pagefile.sys $newPageFileSizeMB $newPageFileSizeMB"
        Out-Log "New PagingFiles value: $newPagingFilesValue"
        Invoke-ExpressionWithLogging -command "reg add `"HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management`" /v PagingFiles /t REG_MULTI_SZ /d `"$newPagingFilesValue`" /f | Out-Null"
        # Saw hangs trying to use Set-WmiInstance, which I think tries to make the changes immediately, so just changing the registry since that takes effect at reboot which is fine for my needs
        # Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name = "$($tempDisk.DeviceID)\pagefile.sys"; InitialSize = $($newPageFileSizeGB * 1MB); MaximumSize = $($newPageFileSizeGB * 1MB)}
    }
    else
    {
        $packagesPath = "$bootstrapPath\packages"
    }
}
else
{
    $packagesPath = "$bootstrapPath\packages"
}

if (Test-Path -Path $packagesPath -PathType Container)
{
    Out-Log "Packages path $packagesPath already exists, don't need to create it"
}
else
{
    Out-Log "Creating $packagesPath"
    New-Item -Path $packagesPath -ItemType Directory -Force | Out-Null
}

$scriptPathNew = "$scriptsPath\$scriptName"
if ($scriptPath -ne $scriptPathNew)
{
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $scriptPath -Destination $scriptPathNew -Force"
    $scriptPath = $scriptPathNew
}

$productType = (Get-WmiObject -Class Win32_OperatingSystem).ProductType
$build = [environment]::OSVersion.Version.Build

$defaultUserHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
$defaultUserKeyPath = 'HKEY_USERS\DefaultUserHive'
Invoke-ExpressionWithLogging -command "reg load $defaultUserKeyPath $defaultUserHivePath"

# Set Windows sound scheme to "No sounds"
Invoke-Expression "reg add $defaultUserKeyPath\AppEvents\Schemes /VE /T REG_SZ /F /D `".None`""
Invoke-Expression "reg add HKCU\AppEvents\Schemes /VE /T REG_SZ /F /D `".None`""
# Disable Windows startup sound
Invoke-Expression "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation /T REG_DWORD /V DisableStartupSound /D 1 /F"
# Not sure this policy location is necessary
# reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /T REG_DWORD /V DisableStartupSound /D 1

if ($productType -ne 1)
{
    # Disable Server Manager from starting at Windows startup
    Invoke-ExpressionWithLogging -command "reg add $defaultUserKeyPath\SOFTWARE\Microsoft\ServerManager /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-ExpressionWithLogging -command "reg add $defaultUserKeyPath\SOFTWARE\Microsoft\ServerManager /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
}

if ($productType -eq 1)
{
    if ($build -ge 22000)
    {
        # Enable dark mode
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v SystemUsesLightTheme /t REG_DWORD /d 0 /f"
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v AppsUseLightTheme /t REG_DWORD /d 0 /f"
        # Win11: Disable the new context menu
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`' /f /ve | Out-Null"
        # Win11: Taskbar on left instead of center
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"
    }

    if ($build -lt 22000 -and $build -ge 10240)
    {
        # Win10: Enable "Always show all icons in the notification area"
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`' /f /ve | Out-Null"
    }
}

# Config for all Windows versions
# Always show all icons and notifications on the taskbar
# On Win11 to toggle this in the GUI run: explorer shell:::{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}
Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v EnableAutoTray /t REG_DWORD /d 0 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`' /v EnableAutoTray /t REG_DWORD /d 0 /f | Out-Null"
# Show file extensions
Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
# Show hidden files
Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
# Show protected operating system files
Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
# Explorer show compressed files color
Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"

Invoke-ExpressionWithLogging -command "reg unload $defaultUserKeyPath"

$logScriptFilePath = "$bootstrapPath\log.ps1"
if (Test-Path -Path $logScriptFilePath -PathType Leaf)
{
    Out-Log "$logScriptFilePath already exists, don't need to create it"
}
else
{
    $logCommand = "Import-Csv (Get-ChildItem -Path $logsPath\*.csv).FullName | Sort-Object -Property Timestamp | Format-Table Timestamp, @{Name = 'File'; Expression={`$_.File.Split('\')[-1]}}, Message -AutoSize"
    $logCommand | Out-File -FilePath $logScriptFilePath -Force
}

Invoke-ExpressionWithLogging -command 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force'

<#
# Since I'm using -SkipNetworkProfileCheck with Enable-PSRemoting, maybe setting the network profiles all to Private (1) isn't necessary?
if ((Get-WmiObject -Class Win32_Baseboard).Product -eq 'Virtual Machine')
{
    $currentBuild = [environment]::OSVersion.Version.Build
    Out-Log "Windows build: $currentBuild"
    # if ($currentBuild -lt 9600)
    # Get-NetConnectionProfile hangs for some reason, I think the direct reg edit way will work on all versions
    if ($true)
    {
        $profiles = Invoke-ExpressionWithLogging -command "Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'"
        $profiles | ForEach-Object {
            $currentKey = Get-ItemProperty -Path $_.PsPath
            if ($currentKey.ProfileName -eq $ProfileName)
            {
                # 0 is Public, 1 is Private, 2 is Domain
                Out-Log "Setting $ProfileName profile to Private"
                Set-ItemProperty -Path $_.PsPath -Name 'Category' -Value 1
            }
        }
    }
    else
    {
        # Get-NetConnectionProfile hangs for some reason, I think the direct reg edit way will work on all versions
        # Invoke-ExpressionWithLogging -command 'Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private'
    }
}
#>

if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
{
    if (!$userName)
    {
        Out-Log 'ERROR: Required parameter missing: -userName <userName>'
        exit
    }
    elseif (!$password)
    {
        Out-Log 'ERROR: Required parameter missing: -password <password>'
        exit
    }
    elseif (!$bootstrapScriptUrl)
    {
        Out-Log 'ERROR: Required parameter missing: -bootstrapScriptUrl <bootstrapScriptUrl>'
        exit
    }
}

if ($PSVersionTable.PSVersion -ge [Version]'5.1')
{
    Invoke-ExpressionWithLogging -command '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072'

    Invoke-ExpressionWithLogging -command 'Invoke-Schtasks'

    if ($isVM)
    {
        Invoke-ExpressionWithLogging -command 'Enable-PSLogging'
    }
    Out-Log "IsVM: $isVM"

    $bootstrapScriptFileName = $bootstrapScriptUrl.Split('/')[-1]
    $bootstrapScriptFilePath = "$scriptsPath\$bootstrapScriptFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$bootstrapScriptUrl`', `'$bootstrapScriptFilePath`')"

    Out-Log "Checking if path exists: $bootstrapScriptFilePath"
    if (Test-Path -Path $bootstrapScriptFilePath -PathType Leaf)
    {
        Out-Log "File does exist: $bootstrapScriptFilePath"
        Out-Log 'Checking if running as local system account'
        if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
        {
            Out-Log 'Running as local system account'
            Out-Log "Converting password: $password to secure string"
            $passwordSecureString = ConvertTo-SecureString -String $password -AsPlainText -Force
            if ($passwordSecureString)
            {
                Out-Log "Succesfully converted password: $password to secure string"
                $credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$userName", $passwordSecureString)
                Invoke-ExpressionWithLogging -command 'Enable-PSRemoting -SkipNetworkProfileCheck -Force'
                Invoke-Command -Credential $credential -ComputerName localhost -ScriptBlock {param($scriptPath) & $scriptPath} -ArgumentList $bootstrapScriptFilePath
            }
            else
            {
                Out-Log 'ERROR: Failed to convert password to secure string'
                Exit
            }
        }
        else
        {
            Out-Log 'Not running as local system account'
            Invoke-ExpressionWithLogging -command $bootstrapScriptFilePath
        }
    }
    else
    {
        Out-Log "ERROR: File not found: $bootstrapScriptFilePath"
        exit 2
    }

    Out-Log 'Done'
}
else
{
    $osVersion = Get-WmiObject -Query 'Select Version from Win32_OperatingSystem'
    $osVersion = $osVersion.Version
    $psVersion = $PSVersionTable.PSVersion
    Out-Log "OS version: $osVersion"
    Out-Log "PS version: $psVersion"
    switch ($osVersion)
    {
        '6.1.7601' {$hotfixId = 'KB3191566'}
        '6.2.9200' {$hotfixId = 'KB3191565'}
        '6.3.9600' {$hotfixId = 'KB3191564'}
    }
    Out-Log "WMF 5.1 hotfixId: $hotfixId"

    $hotfixInstalled = [bool](Get-WmiObject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='$hotfixId'")

    if ($hotfixInstalled -and $psVersion -lt [Version]'5.1')
    {
        Out-Log "WMF5.1 ($hotfixId) already installed but PowerShell version is $psVersion, Windows restart still needed"
        Invoke-ExpressionWithLogging -command 'Invoke-Schtasks'
    }
    else
    {
        Out-Log "$hotfixId not installed and PowerShell version is $psVersion, continuing with WMF 5.1 ($hotfixId) install"
        switch ($osVersion)
        {
            '6.1.7601' {$url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip'}
            '6.2.9200' {$url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu'}
            '6.3.9600' {$url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu'}
        }
        $fileName = $url.Split('/')[-1]
        $filePath = "$packagesPath\$fileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$url`', `'$filePath`')"

        if ($filePath.EndsWith('.zip'))
        {
            $extractedFilePath = $filePath.Replace('.zip', '')
            Out-Log "Extracting $filePath to $extractedFilePath"
            if (!(Test-Path $extractedFilePath))
            {
                Invoke-ExpressionWithLogging -command "New-Item -Path $extractedFilePath -ItemType Directory -Force | Out-Null"
            }

            $shell = New-Object -Com Shell.Application
            $zip = $shell.NameSpace($filePath)
            foreach ($item in $zip.Items())
            {
                $shell.Namespace($extractedFilePath).CopyHere($item, 0x14)
            }

            while ((Get-ChildItem -Path $extractedFilePath -Recurse -Force).Count -lt $zip.Items().Count)
            {
                Start-Sleep -Seconds 1
            }

            Invoke-ExpressionWithLogging -command 'Invoke-Schtasks'
            Out-Log 'Windows will restart automatically after WMF5.1 silent install completes'
            Invoke-ExpressionWithLogging -command "$extractedFilePath\Install-WMF5.1.ps1 -AcceptEULA -AllowRestart"
        }
        else
        {
            Invoke-ExpressionWithLogging -command 'Invoke-Schtasks'
            Out-Log 'Windows will restart automatically after WMF5.1 silent install completes'
            $wusa = "$env:windir\System32\wusa.exe"
            Invoke-ExpressionWithLogging -command "Start-Process -FilePath $wusa -ArgumentList $filePath, '/quiet', '/forcerestart' -Wait"
        }

        do
        {
            Start-Sleep 5
            Out-Log 'Installing WMF 5.1...'
            $hotfixInstalled = [bool](Get-WmiObject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='$hotfixId'")
        } until ($hotfixInstalled)
        Out-Log 'Done'
    }
}
