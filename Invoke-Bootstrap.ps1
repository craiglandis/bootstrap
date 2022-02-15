# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\onedrive\my\Invoke-Bootstrap.ps1 -userName craig -password $password -bootstrapScriptUrl https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1
param(
    [string]$userName,
    [string]$password,
    [string]$bootstrapScriptUrl
)

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Write-PSFMessage $command
    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        Write-PSFMessage -Level Error -Message "Failed: $command" -ErrorRecord $_
        Write-PSFMessage "`$LASTEXITCODE: $LASTEXITCODE"
    }
}

function Set-PSFramework
{
    Remove-Item Alias:Write-PSFMessage -Force -ErrorAction SilentlyContinue
    $PSDefaultParameterValues['Write-PSFMessage:Level'] = 'Output'
    $logFilePath = "$logsPath\$($scriptBaseName)-Run$($runCount)-$scriptStartTimeString.csv"
    $paramSetPSFLoggingProvider = @{
        Name     = 'logfile'
        FilePath = $logFilePath
        Enabled  = $true
        TimeFormat = 'yyyy-MM-dd HH:mm:ss.fff'
    }
    Set-PSFLoggingProvider @paramSetPSFLoggingProvider
    Write-PSFMessage "PSFramework $($psframework.Version)"
    Write-PSFMessage "Log path: $logsPath"
}

function Invoke-Schtasks
{
    $taskRun = "powershell.exe -ExecutionPolicy Bypass -File $scriptPath -userName $userName -password $password -bootstrapScriptUrl $bootstrapScriptUrl"
    Invoke-ExpressionWithLogging -command "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"$taskRun`" /f"
}

function Invoke-GetWindowsUpdate
{
    $ProgressPreference = 'SilentlyContinue'
    $getWindowsUpdateLogFilePath = "$logsPath\Get-WindowsUpdate-$(Get-Date -Format yyyyMMddHHmmssff).log"
    Invoke-ExpressionWithLogging -command "Get-WindowsUpdate -MicrosoftUpdate -UpdateType Software -NotCategory 'Language packs' -AcceptAll -Download -Install -IgnoreReboot -Verbose *>&1 | tee-object $getWindowsUpdateLogFilePath"
    $isRebootNeeded = Get-WURebootStatus -Silent
    Write-PSFMessage "`$isRebootNeeded: $isRebootNeeded"
    if ($isRebootNeeded)
    {
        Invoke-Schtasks
        Complete-ScriptExecution
        Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
    }
    else
    {
        Invoke-ExpressionWithLogging -command 'schtasks /delete /tn bootstrap /f'
    }
}

function Complete-ScriptExecution
{
    if (Get-Module -Name Defender -ListAvailable -ErrorAction SilentlyContinue)
    {
        Invoke-ExpressionWithLogging -command "Remove-MpPreference -ExclusionPath $env:temp -Force"
        Invoke-ExpressionWithLogging -command "Remove-MpPreference -ExclusionPath $bsPath -Force"
        Invoke-ExpressionWithLogging -command "Remove-MpPreference -ExclusionPath $toolsPath -Force"
    }

    $scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
    Write-PSFMessage "$scriptName duration: $scriptDuration"

    $psFrameworkLogPath = Get-PSFConfigValue -FullName PSFramework.Logging.FileSystem.LogPath
    $psFrameworkLogFile = Get-ChildItem -Path $psFrameworkLogPath | Sort-Object LastWriteTime -desc | Select-Object -First 1
    $psFrameworkLogFilePath = $psFrameworkLogFile.FullName
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $env:ProgramData\chocolatey\logs\chocolatey.log -Destination $logsPath"
    Write-PSFMessage "Log path: $psFrameworkLogFilePath"
    Invoke-ExpressionWithLogging -command "New-Item -Path $bsPath\ScriptRanToCompletion -ItemType File -Force | Out-Null"
}

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

Set-Alias -Name Write-PSFMessage -Value Write-Output

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptPath = $MyInvocation.MyCommand.Path
$scriptName = Split-Path -Path $scriptPath -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$bsPath = "$env:SystemDrive\bs"
if (Test-Path -Path $bsPath -PathType Container)
{
    Write-PSFMessage "$bsPath already exists, don't need to create it"
}
else
{
    Write-PSFMessage "Creating $bsPath"
    New-Item -Path $bsPath -ItemType Directory -Force | Out-Null
}

$scriptsPath = "$bsPath\scripts"
if (Test-Path -Path $scriptsPath -PathType Container)
{
    Write-PSFMessage "$scriptsPath already exists, don't need to create it"
}
else
{
    Write-PSFMessage "Creating $scriptsPath"
    New-Item -Path $scriptsPath -ItemType Directory -Force | Out-Null
}

$logsPath = "$bsPath\logs"
if (Test-Path -Path $logsPath -PathType Container)
{
    Write-PSFMessage "$logsPath already exists, don't need to create it"
}
else
{
    Write-PSFMessage "Creating $logsPath"
    New-Item -Path $logsPath -ItemType Directory -Force | Out-Null
}

if ($isVM)
{
    $tempDrive = (Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.VolumeName -eq 'Temporary Storage'}).DeviceID
    $packagesPath = "$tempDrive\Packages"
}
else
{
    $packagesPath = "$bsPath\Packages"
}
if (Test-Path -Path $packagesPath -PathType Container)
{
    Write-PSFMessage "Packages path $packagesPath already exists, don't need to create it"
}
else
{
    Write-PSFMessage "Creating $packagesPath"
    New-Item -Path $packagesPath -ItemType Directory -Force | Out-Null
}

$scriptPathNew = "$scriptsPath\$scriptName"
if ($scriptPath -ne $scriptPathNew)
{
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $scriptPath -Destination $scriptPathNew -Force"
    $scriptPath = $scriptPathNew
}

$systemDrive = Get-WmiObject -Class Win32_LogicalDisk | where-object {$_.DeviceID -eq $env:SystemDrive}
$systemDriveSizeGB = [Math]::Round($systemDrive.Size/1GB,2)
$systemDriveFreeSpaceGBBefore = [Math]::Round($systemDrive.FreeSpace/1GB,2)
Invoke-ExpressionWithLogging -command "Drive $env:SystemDrive Size: $systemDriveSizeGB GB, Free: $systemDriveFreeSpaceGBBefore GB"
Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:SystemRoot\Logs\CBS\*.log -Force"
Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:SystemRoot\SoftwareDistribution\DataStore\DataStore.edb -Force"
$systemDrive = Get-WmiObject -Class Win32_LogicalDisk | where-object {$_.DeviceID -eq $env:SystemDrive}
$systemDriveFreeSpaceGBAfter = [Math]::Round($systemDrive.FreeSpace/1GB,2)
Invoke-ExpressionWithLogging -command "Drive $env:SystemDrive Size: $systemDriveSizeGB GB, Free: $systemDriveFreeSpaceGBAfter GB (deleting CBS logs and DataStore.edb freed $($systemDriveFreeSpaceGBAfter - $systemDriveFreeSpaceGBBefore) GB)"

$productType = (Get-WmiObject -Class Win32_OperatingSystem).ProductType
$build = [environment]::OSVersion.Version.Build

$defaultUserHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
$defaultUserKeyPath = "HKEY_USERS\DefaultUserHive"
Invoke-ExpressionWithLogging -command "reg load $defaultUserKeyPath $defaultUserHivePath"

if ($productType -ne 1)
{
    # Disable Server Manager from starting at Windows startup
    Invoke-ExpressionWithLogging -command "reg add $defaultUserKeyPath\SOFTWARE\Microsoft\ServerManager /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-ExpressionWithLogging -command "reg add $defaultUserKeyPath\SOFTWARE\Microsoft\ServerManager /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
    #Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
    #Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
}

if ($productType -eq 1)
{
    if ($build -ge 22000)
    {
        # Win11
        #Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`' /f /ve | Out-Null"
    }

    if ($build -lt 22000 -and $build -ge 10240)
    {
        # Win10: Enable "Always show all icons in the notification area"
        #Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`' /f /ve | Out-Null"
    }
}

# Config for all Windows versions
# Show file extensions
#Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
# Show hidden files
#Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
# Show protected operating system files
#Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
# Explorer show compressed files color
#Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
# Taskbar on left instead of center
#Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"
Invoke-ExpressionWithLogging -command "reg add `'$defaultUserKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"

Invoke-ExpressionWithLogging -command "reg unload $defaultUserKeyPath"

$logScriptFilePath = "$bsPath\log.ps1"
if (Test-Path -Path $logScriptFilePath -PathType Leaf)
{
    Write-PSFMessage "$logScriptFilePath already exists, don't need to create it"
}
else
{
    $logCommand = "Import-Csv (Get-ChildItem -Path $logsPath\*.csv | Sort-Object -Property LastWriteTime -Descending)[0].FullName | Format-Table Timestamp, Message -AutoSize"
    Invoke-ExpressionWithLogging -command "New-Item -Path $logScriptFilePath -ItemType File -Force | Out-Null"
    Invoke-ExpressionWithLogging -command "Set-Content -Value `"$logCommand`" -Path $logScriptFilePath -Force"
}

Invoke-ExpressionWithLogging -command 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force'

if ((Get-WmiObject -Class Win32_Baseboard).Product -eq 'Virtual Machine')
{
    #$currentBuild = [int](Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion').CurrentBuild
    $currentBuild = [environment]::OSVersion.Version.Build
    if ($currentBuild -lt 9600)
    {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' | ForEach-Object {

            $currentKey = Get-ItemProperty -Path $_.PsPath
            if ($currentKey.ProfileName -eq $ProfileName)
            {
                # 0 is Public, 1 is Private, 2 is Domain
                Set-ItemProperty -Path $_.PsPath -Name 'Category' -Value 1
            }
        }
    }
    else
    {
        Invoke-ExpressionWithLogging -command 'Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private'
    }
}

if (!$userName)
{
    Write-Error 'Required parameter missing: -userName <userName>'
    exit
}
elseif (!$password)
{
    Write-Error 'Required parameter missing: -password <password>'
    exit
}
elseif (!$bootstrapScriptUrl)
{
    Write-Error 'Required parameter missing: -bootstrapScriptUrl <bootstrapScriptUrl>'
    exit
}

# https://psframework.org/
Import-Module -Name PSFramework -ErrorAction SilentlyContinue
$psframework = Get-Module -Name PSFramework -ErrorAction SilentlyContinue
if ($psframework)
{
    Set-PSFramework
}
else
{
    if ($PSVersionTable.PSVersion -ge [Version]'5.1')
    {
        Invoke-ExpressionWithLogging -command '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072'

        Write-PSFMessage 'Verifying Nuget 2.8.5.201+ is installed'
        $nuget = Get-PackageProvider -Name nuget -ErrorAction SilentlyContinue -Force
        if (!$nuget -or $nuget.Version -lt [Version]'2.8.5.201')
        {
            Invoke-ExpressionWithLogging -command 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force'
        }
        else
        {
            Write-PSFMessage "Nuget $($nuget.Version) already installed"
        }

        Invoke-ExpressionWithLogging -command 'Install-Module -Name PSFramework -Repository PSGallery -Scope AllUsers -Force -ErrorAction SilentlyContinue'
        Import-Module -Name PSFramework -ErrorAction SilentlyContinue
        $psframework = Get-Module -Name PSFramework -ErrorAction SilentlyContinue
        if ($psframework)
        {
            Set-PSFramework
        }
        else
        {
            Write-Error 'PSFramework module failed to install'
            exit
        }
    }
}

# Ephemeral OS disk VMs put the pagefile on C: for some reason, which takes up space, so putting it on the temp drive D:
# Sets initial/maximum both to size of RAM + 1GB unless that is more than 50% of temp drive free space, in which case set it to 50% temp drive free space
$currentPagingFilesValue = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name PagingFiles).PagingFiles
Write-PSFMessage "Current PagingFiles value: $currentPagingFilesValue"
$tempDisk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.VolumeName -eq 'Temporary Storage'}
$halfTempDiskFreeSpaceMB = [Math]::Round($tempDisk.FreeSpace / 1MB, 0) / 2
Write-PSFMessage "$halfTempDiskFreeSpaceMB MB is half the free space on $($tempDisk.DeviceID)"
$totalPhysicalMemoryMBPlus1MB = [Math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB) + 1
Write-PSFMessage "$totalPhysicalMemoryMBPlus1MB total MB physical memory plus 1MB"
if ($totalPhysicalMemoryMBPlus1MB -gt $halfTempDiskFreeSpaceMB)
{
    $newPageFileSizeMB = $halfTempDiskFreeSpaceMB
}
else
{
    $newPageFileSizeMB = $totalPhysicalMemoryMBPlus1MB
}
$newPagingFilesValue = "$($tempDisk.DeviceID)\pagefile.sys $newPageFileSizeMB $newPageFileSizeMB"
Write-PSFMessage "New PagingFiles value: $newPagingFilesValue"
Invoke-ExpressionWithLogging -command "reg add `"HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management`" /v PagingFiles /t REG_MULTI_SZ /d `"$newPagingFilesValue`" /f | Out-Null"
# Saw hangs trying to use Set-WmiInstance, which I think tries to make the changes immediately, so just changing the registry since that takes effect at reboot which is fine for my needs
# Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name = "$($tempDisk.DeviceID)\pagefile.sys"; InitialSize = $($newPageFileSizeGB * 1MB); MaximumSize = $($newPageFileSizeGB * 1MB)}

if ($PSVersionTable.PSVersion -ge [Version]'5.1')
{
    Invoke-ExpressionWithLogging -command '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072'

    $bootstrapScriptFileName = $bootstrapScriptUrl.Split('/')[-1]
    $bootstrapScriptFilePath = "$scriptsPath\$bootstrapScriptFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$bootstrapScriptUrl`', `'$bootstrapScriptFilePath`')"

    if (Test-Path -Path $bootstrapScriptFilePath -PathType Leaf)
    {
        if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
        {
            $passwordSecureString = ConvertTo-SecureString -String $password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$userName", $passwordSecureString)
            Enable-PSRemoting -SkipNetworkProfileCheck -Force
            Invoke-Command -Credential $credential -ComputerName localhost -ScriptBlock {param($scriptPath) & $scriptPath} -ArgumentList $bootstrapScriptFilePath
        }
        else
        {
            Invoke-ExpressionWithLogging -command $bootstrapScriptFilePath
        }
    }
    else
    {
        Write-Error "File not found: $bootstrapScriptFilePath"
        exit 2
    }
}
else
{
    $osVersion = Get-WmiObject -Query 'Select Version from Win32_OperatingSystem'
    $osVersion = $osVersion.Version
    $psVersion = $PSVersionTable.PSVersion
    Write-PSFMessage "OS version: $osVersion"
    Write-PSFMessage "PS version: $psVersion"
    switch ($osVersion)
    {
        '6.1.7601' {$hotfixId = 'KB3191566'}
        '6.2.9200' {$hotfixId = 'KB3191565'}
        '6.3.9600' {$hotfixId = 'KB3191564'}
    }
    Write-PSFMessage "WMF 5.1 hotfixId: $hotfixId"

    $hotfixInstalled = [bool](Get-WmiObject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='$hotfixId'")

    if ($hotfixInstalled -and $psVersion -lt [Version]'5.1')
    {
        Write-PSFMessage "WMF5.1 ($hotfixId) already installed but PowerShell version is $psVersion, Windows restart still needed"
        Invoke-Schtasks
    }
    else
    {
        Write-PSFMessage "$hotfixId not installed and PowerShell version is $psVersion, continuing with WMF 5.1 ($hotfixId) install"
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
            Write-PSFMessage "Extracting $filePath to $extractedFilePath"
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

            Invoke-Schtasks
            Write-PSFMessage 'Windows will restart automatically after WMF5.1 silent install completes'
            Invoke-ExpressionWithLogging -command "$extractedFilePath\Install-WMF5.1.ps1 -AcceptEULA -AllowRestart"
        }
        else
        {
            Invoke-Schtasks
            Write-PSFMessage 'Windows will restart automatically after WMF5.1 silent install completes'
            $wusa = "$env:windir\System32\wusa.exe"
            Invoke-ExpressionWithLogging -command "Start-Process -FilePath $wusa -ArgumentList $filePath, '/quiet', '/forcerestart' -Wait"
        }

        do
        {
            Start-Sleep 5
            Write-PSFMessage 'Installing WMF 5.1...'
            $hotfixInstalled = [bool](Get-WmiObject -Query "Select HotFixID from Win32_QuickFixEngineering where HotFixID='$hotfixId'")
        } until ($hotfixInstalled)
    }
}

Invoke-GetWindowsUpdate