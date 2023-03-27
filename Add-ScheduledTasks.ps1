<# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\onedrive\my\Add-ScheduledTasks.ps1
copy \\tsclient\c\OneDrive\My\AutoHotkey.ahk c:\OneDrive\My\AutoHotkey.ahk
copy \\tsclient\c\OneDrive\My\AutoHotkey_Not_Elevated.ahk c:\OneDrive\My\AutoHotkey_Not_Elevated.ahk
#>
param(
    [string]$toolsPath = 'C:\OneDrive\Tools',
    [string]$myPath = 'C:\OneDrive\My'
)

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Write-PSFMessage $command
    Invoke-Expression -Command $command
}

# TODO: 2008R2/WIN7 don't have the ScheduledTasks module even when PS5.1 is installed
# Need to uses schtasks.exe instead for 2008R2/WIN7
# Can import from XML - schtasks /create /xml "%UserProfile%\IMPORTED-FOLDER-PATH\TASK-INPORT-NAME.xml" /tn "\TASKSCHEDULER-FOLDER-PATH\TASK-INPORT-NAME" /ru "COMPUTER-NAME\USER-NAME"
# procmon driver can't load without this hotfix on Win7?
# https://download.microsoft.com/download/C/8/7/C87AE67E-A228-48FB-8F02-B2A9A1238099/Windows6.1-KB3033929-x64.msu
# No that didn't help
# WU - installed all updates - still doesn't work
# https://docs.microsoft.com/en-us/windows/win32/taskschd/triggercollection-create#parameters
function Add-ScheduledTask
{
    param(
        [string]$taskName,
        [int]$triggerType,
        [string]$execute,
        [string]$argument,
        [string]$runLevel
    )

    if (Get-Module -Name ScheduledTasks -ListAvailable)
    {
        Write-PSFMessage "Register-ScheduledTask -TaskName $taskName -InputObject (New-ScheduledTask -Action (New-ScheduledTaskAction -Execute $execute -Argument $argument) -Principal (New-ScheduledTaskPrincipal -UserId $env:userdomain\$env:username -RunLevel $runLevel -LogonType Interactive) -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8))"
        $userId = "$env:userdomain\$env:username"
        $action = New-ScheduledTaskAction -Execute $execute -Argument $argument
        if ($triggerType -eq $TASK_TRIGGER_BOOT)
        {
            $trigger = New-ScheduledTaskTrigger -AtStartup
        }
        elseif ($triggerType -eq $TASK_TRIGGER_LOGON)
        {
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
        }
        $principal = New-ScheduledTaskPrincipal -UserId $userId -RunLevel $runLevel -LogonType Interactive
        # 'Win8' is the highest compatibility level even in Win11, setting that makes "Configure for" show Windows 10 in the UI for the task
        # And in the export XMl for the task, version="1.4" is on the second line if the task was created as -Compatibility Win8
        $compatibility = 'Win8'
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility $compatibility
        $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null

        if ($triggerType -eq $TASK_TRIGGER_LOGON -and (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue))
        {
            Write-PSFMessage "Scheduled task succesfully created: $taskName"
            Write-PSFMessage "Starting scheduled task: $taskName"
            Start-ScheduledTask -TaskName $taskName
        }
    }
    else
    {
        if ($runLevel -eq 'Highest')
        {
            $runLevel = 1
        }
        else
        {
            $runLevel = 0
        }

        $user = [Security.Principal.WindowsIdentity]::GetCurrent()
        $scheduleService = New-Object -ComObject Schedule.Service
        $task = $scheduleService.NewTask(0)

        $registrationInfo = $task.RegistrationInfo
        $registrationInfo.Description = $taskName
        $registrationInfo.Author = $user.Name

        $settings = $task.Settings
        $settings.Enabled = $true
        $settings.StartWhenAvailable = $true
        $settings.Hidden = $false

        $action = $task.Actions.Create(0)
        $action.Path = $execute
        $action.Arguments = $argument

        $trigger = $task.Triggers.Create($triggerType)

        $task.Principal.RunLevel = $runLevel

        $scheduleService.Connect()
        $rootFolder = $scheduleService.GetFolder("\")
        $rootFolder.RegisterTaskDefinition($taskName, $task, 6, $null, $null, 0) | Out-Null

        if ($triggerType -eq $TASK_TRIGGER_LOGON)
        {
            $rootFolder.GetTask($taskName).Run(0) | Out-Null
        }
    }
}

$scriptStartTime = Get-Date
#$scriptName = Split-Path -Path $PSCommandPath -Leaf
$scriptName = Split-Path -Path $MyInvocation.MyCommand.Path -Leaf
Set-Alias -Name Write-PSFMessage -Value Write-Output
$PSDefaultParameterValues['Write-PSFMessage:Level'] = 'Output'
#[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Variable -Name TASK_TRIGGER_BOOT -Value 8 -Option Constant
New-Variable -Name TASK_TRIGGER_LOGON -Value 9 -Option Constant

if ($env:COMPUTERNAME.StartsWith('TDC'))
{
    $isSAW = $true
}
else
{
    $win32_Baseboard = Get-CimInstance -ClassName Win32_Baseboard
    if ($win32_Baseboard.Product -eq 'Virtual Machine')
    {
        $isVM = $true
    }
    else
    {
        $isPC = $true
    }
}
Write-PSFMessage "`$isPC: $isPC `$isVM: $isVM `$isSAW: $isSAW"

# Skip this on VSAW which already has > 2.8.5.201
if ($isVM -or $isPC)
{
    if ($PSEdition -eq 'Desktop')
    {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force
        if ($nuget)
        {
            if ($nuget.Version -lt [Version]'2.8.5.201')
            {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            }
        }
    }
}

Import-Module -Name PSFramework -ErrorAction SilentlyContinue
if (Get-Module -Name PSFramework)
{
    Write-PSFMessage "PSFramework module already loaded"
}
else
{
    Write-Output "PSFramework module not found, installing it"
    Install-Module -Name PSFramework -Repository PSGallery -Scope CurrentUser -AllowClobber -Force -ErrorAction SilentlyContinue
    Import-Module -Name PSFramework -ErrorAction SilentlyContinue
    if (Get-Module -Name PSFramework -ErrorAction SilentlyContinue)
    {
        Write-PSFMessage "PSFramework module install succeeded"
    }
    else
    {
        Write-Output "PSFramework module install failed"
        $command = "Set-Alias -Name Write-PSFMessage -Value Write-Output"
        Write-Output $command
        Invoke-Expression -Command $command
    }
}

Write-PSFMessage "Checking if $myPath exists"
if (Test-Path -Path $myPath -PathType Container)
{
    Write-PSFMessage "$myPath already exists, don't need to create it"
}
else
{
    Write-PSFMessage "$myPath does not exist, creating it"
    New-Item -Path $myPath -ItemType Directory | Out-Null
}

Write-PSFMessage "Checking if $toolsPath exists"
if (Test-Path -Path $toolsPath -PathType Container)
{
    Write-PSFMessage "$toolsPath already exists, don't need to create it"
}
else
{
    Write-PSFMessage "$toolsPath does not exist, creating it"
    New-Item -Path $toolsPath -ItemType Directory -Force | Out-Null
}

if ($isSAW)
{
    # For VSAW, need to make AutoHotkey work without admin rights
    # https://www.thenickmay.com/how-to-install-autohotkey-even-without-administrator-access/
    # It works - the .ahk file must be named AutoHotkeyU64.ahk, then you run AutoHotkeyU64.exe
    $ahkExeFolderPath = $toolsPath
    $ahkExeFilePath = "$ahkExeFolderPath\AutoHotkeyU64.exe"
}
else
{
    $ahkExeFolderPath = "$env:ProgramFiles\AutoHotkey"
    $ahkExeFilePath = "$ahkExeFolderPath\AutoHotkey.exe"
}

Write-PSFMessage "Checking if AutoHotkey is installed ($ahkExeFilePath)"
if (Test-Path -Path $ahkExeFilePath -PathType Leaf)
{
    Write-PSFMessage "AutoHotkey already installed"
}
else
{
    Write-PSFMessage "AutoHotkey not installed, installing it now"
    # autohotkey.portable - couldn't find a way to specify a patch for this package
    # (portable? https://www.autohotkey.com/download/ahk.zip)
    # https://www.thenickmay.com/how-to-install-autohotkey-even-without-administrator-access/
    # It works - the .ahk file must be named AutoHotkeyU64.ahk, then you run AutoHotkeyU64.exe
    # copy-item -Path \\tsclient\c\onedrive\ahk\AutoHotkey.ahk -Destination c:\my\ahk\AutoHotkeyU64.ahk
    if ($isSAW)
    {
        $ahkZipFileUrl = 'https://www.autohotkey.com/download/ahk.zip'
        $ahkZipFileName = $ahkZipFileUrl.Split('/')[-1]
        $ahkZipFilePath = "$env:TEMP\$ahkZipFileName"
        (New-Object System.Net.WebClient).DownloadFile($ahkZipFileUrl, $ahkZipFilePath)
        Get-Process | Where-Object {$_.Name -match 'AutoHotkey'} | Stop-Process -Force
        Expand-Archive -Path $ahkZipFilePath -DestinationPath $ahkExeFolderPath -Force
    }
    else
    {
        Invoke-Expression ((New-Object Net.Webclient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install autohotkey -y
        Write-PSFMessage "`$LASTEXITCODE: $LASTEXITCODE"
    }
}

$ahkFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/ahk.ahk'
$ahkFileName = $ahkFileUrl.Split('/')[-1]
$ahkFilePath = "$myPath\$ahkFileName"
$ahkNotElevatedFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/ahk_not_elevated.ahk'
$ahkNotElevatedFileName = $ahkNotElevatedFileUrl.Split('/')[-1]
$ahkNotElevatedFilePath = "$myPath\$ahkNotElevatedFileName"
$ahkU64FileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/AutoHotkeyU64.ahk'
$ahkU64FileName = $ahkU64FileUrl.Split('/')[-1]
$ahkU64FilePath = "$toolsPath\$ahkU64FileName"

if ($isSAW)
{
    Write-PSFMessage "Checking for $ahkU64FilePath"
    if (Test-Path -Path $ahkU64FilePath -PathType Leaf)
    {
        Write-PSFMessage "$ahkU64FilePath already present, no need to download it"
    }
    else
    {
        Write-PSFMessage "$ahkU64FilePath not present, downloading it"
        Write-PSFMessage "Downloading $ahkFileUrl"
        (New-Object Net.Webclient).DownloadFile($ahkU64FileUrl, $ahkU64FilePath)
    }
    Start-Process -FilePath $ahkExeFilePath
}
else
{
    Write-PSFMessage "Checking for $ahkFilePath"
    if (Test-Path -Path $ahkFilePath -PathType Leaf)
    {
        Write-PSFMessage "$ahkFilePath already present, no need to download it"
    }
    else
    {
        Write-PSFMessage "$ahkFilePath not present, downloading it"
        Write-PSFMessage "Downloading $ahkFileUrl"
        (New-Object Net.Webclient).DownloadFile($ahkFileUrl, $ahkFilePath)
    }

    Write-PSFMessage "Checking for $ahkNotElevatedFilePath"
    if (Test-Path -Path $ahkNotElevatedFilePath -PathType Leaf)
    {
        Write-PSFMessage "$ahkNotElevatedFilePath already present, no need to download it"
    }
    else
    {
        Write-PSFMessage "$ahkNotElevatedFilePath not present, downloading it"
        Write-PSFMessage "Downloading $ahkNotElevatedFileUrl"
        (New-Object Net.Webclient).DownloadFile($ahkNotElevatedFileUrl, $ahkNotElevatedFilePath)
    }
}

# Skip this on SAW and regular VMs, no need to keep them awake with caffeine
if ($isPC)
{
    $caffeineUrl = 'https://www.zhornsoftware.co.uk/caffeine/caffeine.zip'
    $caffeineFolderPath = $toolsPath
    $caffeineExeFilePath = "$caffeineFolderPath\caffeine64.exe"
    $caffeineZipFilePath = "$caffeineFolderPath\caffeine.zip"

    Write-PSFMessage "Checking for $caffeineExeFilePath"
    if (Test-Path -Path $caffeineExeFilePath -PathType Leaf)
    {
        Write-PSFMessage "$caffeineExeFilePath already present, no need to download it"
    }
    else
    {
        Write-PSFMessage "$caffeineExeFilePath not present, downloading it"
        (New-Object Net.Webclient).DownloadFile($caffeineUrl, $caffeineZipFilePath)
        Expand-Archive -Path $caffeineZipFilePath -DestinationPath $caffeineFolderPath
    }
}

$executeCmd = "$env:SystemRoot\System32\cmd.exe"
$executePowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

# Can't add scheduled tasks or import reg files on SAW
if ($isPC)
{
    $taskName = 'Caffeine'
    $argument = "/c Start $caffeineExeFilePath"
    Add-ScheduledTask -taskName $taskName -triggerType $TASK_TRIGGER_LOGON -execute $executeCmd -argument $argument -runLevel Highest
}

if ($isSAW)
{
    $taskName = 'AutoHotkey_Not_Elevated_SAW'
    $argument = "/c Start `"$ahkExeFilePath`" $ahkU64FilePath"
    Add-ScheduledTask -taskName $taskName -triggerType $TASK_TRIGGER_LOGON -execute $executeCmd -argument $argument -runLevel Limited
}

if ($isPC -or $isVM)
{
    $bootstrapFileUrl = 'https://raw.githubusercontent.com/craiglandis/ps/master/bootstrap.ps1'
    $bootstrapFileName = $bootstrapFileUrl.Split('/')[-1]
    $bootstrapFolderPath = "$env:SystemDrive\bootstrap"
    $bootstrapFilePath = "$bootstrapFolderPath\$bootstrapFileName"
    if (Test-Path -Path $bootstrapFolderPath -PathType Container)
    {
        Write-PSFMessage "$bootstrapFolderPath already exists, don't need to create it"
    }
    else
    {
        Write-PSFMessage "Creating folder $bootstrapFolderPath"
        New-Item -Path $bootstrapFolderPath -ItemType Directory -Force
    }
    (New-Object Net.Webclient).DownloadFile($bootstrapFileUrl, $bootstrapFilePath)

    if (Test-Path -Path $bootstrapFilePath -PathType Leaf)
    {
        $taskName = 'Bootstrap'
        $argument = "-NoLogo -NoProfile -File $bootstrapFilePath"
        Add-ScheduledTask -taskName $taskName -triggerType $TASK_TRIGGER_BOOT -execute $executePowerShell -argument $argument -runLevel Highest
    }

    $taskName = 'AutoHotkey'
    $argument = "/c Start `"$ahkExeFilePath`" $ahkFilePath"
    Add-ScheduledTask -taskName $taskName -triggerType $TASK_TRIGGER_LOGON -execute $executeCmd -argument $argument -runLevel Highest

    $taskName = 'AutoHotkey_Not_Elevated'
    $argument = "/c Start `"$ahkExeFilePath`" $ahkNotElevatedFilePath"
    Add-ScheduledTask -taskName $taskName -triggerType $TASK_TRIGGER_LOGON -execute $executeCmd -argument $argument -runLevel Limited

    Write-PSFMessage "Setting AutoHotkey Edit command to open AHK files in vscode instead of Notepad"
    $vscodeUserPath = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"
    $vscodeSystemPath = "$env:ProgramFiles\Microsoft VS Code\Code.exe"
    if (Test-Path -Path $vscodeUserPath -PathType Leaf)
    {
        $regFileUrl = 'AutoHotkeyScript_Edit_Command_VSCode_If_Installed_In_Users_username_AppData_Local_Programs_Microsoft_VS_Code.reg'

    }
    elseif (Test-Path -Path $vscodeSystemPath -PathType Leaf)
    {
        $regFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/AutoHotkeyScript_Edit_Command_VSCode_If_Installed_In_Program_Files_Microsoft_VS_Code.reg'
    }
    else
    {
        Write-PSFMessage "VSCode not installed. Skipping file association config."
    }

    if ($regFileUrl)
    {
        $regFileName = $regFileUrl.Split('/')[-1]
        $regFilePath = "$env:TEMP\$regFileName"
        Write-PSFMessage "Downloading $regFileUrl"
        (New-Object Net.Webclient).DownloadFile($regFileUrl, $regFilePath)
        if (Test-Path -Path $regFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging "reg import $regFilePath"
        }
        else
        {
            Write-PSFMessage "File not found: $regFilePath" -Level Error
        }
    }
}

$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
Write-PSFMessage "$scriptName duration: $scriptDuration"
