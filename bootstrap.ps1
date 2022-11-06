<#
# Run from RDP client:
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\src\bootstrap\bootstrap.ps1
# ipcsv (gci c:\bs\*.csv | sort lastwritetime -desc)[0].FullName | ft -a timestamp,message
TODO:
=== 2022-11-02 start ===
Why did PS 7.0 get installed instead of 7.2?
Why is the font not getting installed?
Why aren't 7-zip file associations getting updated?
Docker Desktop - supress subscription service agreement
Docker Desktop - throws error "WSL 2 installation is incomplete" - wants WSL2 kernel update - https://aka.ms/wsl2kernel (https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi)
Mouse cursor - setting cursor size/color isn't working - ends up huge and wrong color
Steam - steam logon prompt comes up, no obvious way to surpress without stopping Steam from starting at boot, so no big deal, leave as-is
PowerShell - profile is not created

=== 2022-11-02 end ===
Additional shell customizations
Install KE https://aka.ms/ke
Import KE connections
Install Visio https://www.office.com/?auth=2&home=1
wmic path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
Use fileUris to download the scripts instead of doing downloads from invoke-bootstrap.ps1/bootstrap.ps1
Log to a custom event log - PSFramework - and create a .log, .csv, or .xlsx export of the useful stuff from that at the end
Incorporate Helper module to minimize code redundancy
#>
[CmdletBinding()]
param(
    [ValidateSet('PC', 'VM', 'VSAW', 'All')]
    [string]$group,
    [switch]$show,
    [string]$toolsPath = 'C:\OneDrive\Tools',
    [string]$myPath = 'C:\OneDrive\My'
)
DynamicParam
{
    $ParameterName = 'app'
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $false
    $ParameterAttribute.Position = 1
    $AttributeCollection.Add($ParameterAttribute)
    $appsJsonFilePath = "$PSScriptRoot\apps.json"
    Remove-Item -Path $appsJsonFilePath -Force -ErrorAction SilentlyContinue
    $appsJsonFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/apps.json'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    (New-Object Net.WebClient).DownloadFile($appsJsonFileUrl, $appsJsonFilePath)
    $apps = Get-Content -Path $PSScriptRoot\apps.json | ConvertFrom-Json
    $appNames = $apps.Name
    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($appNames)
    $AttributeCollection.Add($ValidateSetAttribute)
    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
    return $RuntimeParameterDictionary
}
begin
{
    $app = $PsBoundParameters[$ParameterName]
}
process
{

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
            Out-Log -Level Error -Message "Failed: $command" -ErrorRecord $_
            Out-Log "`$LASTEXITCODE: $LASTEXITCODE"
        }
    }

    function Confirm-NugetInstalled
    {
        Out-Log 'Verifying Nuget 2.8.5.201+ is installed'
        $nuget = Get-PackageProvider -Name nuget -ErrorAction SilentlyContinue -Force
        if (!$nuget -or $nuget.Version -lt [Version]'2.8.5.201')
        {
            Invoke-ExpressionWithLogging -command 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force'
        }
        else
        {
            Out-Log "Nuget $($nuget.Version) already installed"
        }
    }
	<#
    function Set-PSFramework
    {
        Remove-Item Alias:Out-Log -Force -ErrorAction SilentlyContinue
        Import-Module -Name PSFramework -ErrorAction SilentlyContinue
        $PSDefaultParameterValues['Out-Log:Level'] = 'Output'
        $logFilePath = "$logsPath\$($scriptBaseName)-Run$($runCount)-$scriptStartTimeString.csv"
        $paramSetPSFLoggingProvider = @{
            Name     = 'logfile'
            FilePath = $logFilePath
            Enabled  = $true
            TimeFormat = 'yyyy-MM-dd HH:mm:ss.fff'
        }
        Set-PSFLoggingProvider @paramSetPSFLoggingProvider
        Out-Log "PSFramework $($psframework.Version)"
        Out-Log "Logs path: $logsPath"
    }
	#>

    function Get-AppList
    {
        $appsJsonFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/apps.json'
        $appsJsonFilePath = "$bootstrapPath\apps.json"
        Remove-Item -Path $appsJsonFilePath -Force -ErrorAction SilentlyContinue
        if ($isWin7 -or $isWS08R2 -or $isWS12)
        {
            Invoke-ExpressionWithLogging -command "Start-BitsTransfer -Source $appsJsonFileUrl -Destination $appsJsonFilePath"
        }
        else
        {
            Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$appsJsonFileUrl`', `'$appsJsonFilePath`')"
        }

        if (Test-Path -Path $appsJsonFilePath -PathType Leaf)
        {
            Get-Content -Path $appsJsonFilePath | ConvertFrom-Json
        }
    }

    function Expand-Zip
    {
        param
        (
            [CmdletBinding()]
            [Parameter(Mandatory = $true)]
            [System.IO.FileInfo]$Path,
            [Parameter(Mandatory = $true)]
            [System.IO.DirectoryInfo]$DestinationPath
        )

        $Path = $Path.FullName
        $DestinationPath = $DestinationPath.FullName

        $7z = 'C:\Program Files\7-Zip\7z.exe'
        if (Test-Path -Path $7z -PathType Leaf)
        {
            (& $7z x "$Path" -o"$DestinationPath" -aoa -r) | Out-Null
            $7zExitCode = $LASTEXITCODE
            if ($7zExitCode -ne 0)
            {
                throw "Error $7zExitCode extracting $Path to $DestinationPath"
            }
        }
        else
        {
            Add-Type -Assembly System.IO.Compression.Filesystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
        }
    }

    function Invoke-Schtasks
    {
        $taskRun = "powershell.exe -ExecutionPolicy Bypass -File $scriptPath"
        Invoke-ExpressionWithLogging -command "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"$taskRun`" /f"
    }

    function Invoke-GetWindowsUpdate
    {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-ExpressionWithLogging -command "Install-Module -Name PSWindowsUpdate -Repository PSGallery -Scope AllUsers -Force"
        Invoke-ExpressionWithLogging -command "Import-Module -Name PSWindowsUpdate -Force"
        $psWindowsUpdate = Get-Module -Name PSWindowsUpdate
        if ($psWindowsUpdate)
        {
            Out-Log "$($psWindowsUpdate.Name) $($psWindowsUpdate.Version)"
            $timestamp = Get-Date -Format yyyyMMddHHmmssff
            $invokeWUJobLogFilePath = "$logsPath\Invoke-WUJob-$($timestamp).log"
            # Couldn't find a way to get a variable to expand when include within -Script {}, so using a literal path for now
            # $getWindowsUpdateLogFilePath = "$logsPath\Get-WUList-$($timestamp).log"
            # This script is run via remoting so it runs under a specific user context for app installs and OS config purposes
            # But by design, the Windows Update APIs the PSWindowsUpdate module uses to install updates fail with access denied when run via remoting
            # Workaround is to use Invoke-WUJob, which creates a scheduled task to run Get-WUList as local system account
            $taskStartTime = Get-Date
            Invoke-WUJob -ComputerName localhost -Script {$ProgressPreference = 'SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; ipmo PSWindowsUpdate; Get-WUList -MicrosoftUpdate -UpdateType Software -NotCategory 'Language packs' -AcceptAll -Download -Install -IgnoreReboot -Verbose *>&1 | Tee-Object C:\bs\logs\Get-WUList.log} -RunNow -Confirm:$false -Verbose -ErrorAction Ignore *>&1 | Tee-Object $invokeWUJobLogFilePath
            do {
                Start-Sleep -Seconds 5
                $taskName = 'PSWindowsUpdate'
                $scheduleService = New-Object -ComObject Schedule.Service
                $scheduleService.Connect()
                $rootFolder = $scheduleService.GetFolder('\')
                $task = $rootFolder.GetTask($taskName)
            } until ($task.State -eq 3)
            $taskEndTime = Get-Date
            $taskDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $taskStartTime -End $taskEndTime)
            Out-Log "Name: $($task.Name) Duration: $taskDuration LastTaskResult: $($task.LastTaskResult) LastRunTime: $($task.LastRunTime)"
            $rootFolder.DeleteTask($taskName, 0)
            $isRebootNeeded = Get-WURebootStatus -Silent
            Out-Log "`$isRebootNeeded: $isRebootNeeded"
            if ($isRebootNeeded)
            {
                Invoke-Schtasks
                Complete-ScriptExecution
                Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
                #exit
            }
            else
            {
                Invoke-ExpressionWithLogging -command 'schtasks /delete /tn bootstrap /f'
                Complete-ScriptExecution
                Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
                #exit
            }
        }
        else
        {
            Out-Log "Failed to install PSWindowsUpdate module"
            Complete-ScriptExecution
            Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
            #exit
        }
    }

    function Complete-ScriptExecution
    {
        if (Get-Module -Name Defender -ListAvailable -ErrorAction SilentlyContinue)
        {
            Invoke-ExpressionWithLogging -command "Remove-MpPreference -ExclusionPath $env:temp -Force"
            Invoke-ExpressionWithLogging -command "Remove-MpPreference -ExclusionPath $bootstrapPath -Force"
            Invoke-ExpressionWithLogging -command "Remove-MpPreference -ExclusionPath $toolsPath -Force"
        }

        $scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
        Out-Log "$scriptName duration: $scriptDuration"

        <#
		$psFrameworkLogPath = Get-PSFConfigValue -FullName PSFramework.Logging.FileSystem.LogPath
        $psFrameworkLogFile = Get-ChildItem -Path $psFrameworkLogPath | Sort-Object LastWriteTime -desc | Select-Object -First 1
        $psFrameworkLogFilePath = $psFrameworkLogFile.FullName        
        Out-Log "Log path: $psFrameworkLogFilePath"
		#>
		Invoke-ExpressionWithLogging -command "Copy-Item -Path $env:ProgramData\chocolatey\logs\chocolatey.log -Destination $logsPath"
        Invoke-ExpressionWithLogging -command "New-Item -Path $bootstrapPath\ScriptRanToCompletion -ItemType File -Force | Out-Null"
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

    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    $PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    $scriptStartTime = Get-Date
    $scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss

    # Since this script will be called via psremoting using Invoke-Command so that it runs in the context of a specific user instead of system,
    # the $MyInvocation.MyCommand.Path, $PSScriptRoot, and $PSCommandPath automatic variables are not populated, because Invoke-Command is reading the script but executing it as a script block
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptName = Split-Path -Path $scriptPath -Leaf
    $scriptBaseName = $scriptName.Split('.')[0]

	<#
    $psframework = Get-Module -Name PSFramework -ErrorAction SilentlyContinue
    if ($psframework)
    {
        Set-PSFramework
    }
    else
    {
        # Alias Out-Log to Out-Log until PSFramework module is installed
        Set-Alias -Name Out-Log -Value Write-Output
        Confirm-NugetInstalled
        Invoke-ExpressionWithLogging -command 'Install-Module -Name PSFramework -Repository PSGallery -Scope AllUsers -Force -ErrorAction SilentlyContinue'
        Import-Module -Name PSFramework -Force
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
	#>

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
        Enable-PSLogging
    }    

    $bootstrapPath = "$env:SystemDrive\bootstrap"
    $logFilePath = "$bootstrapPath\$($scriptBaseName)_$(Get-Date -Format yyyyMMddhhmmss).log"
    if ((Test-Path -Path (Split-Path -Path $logFilePath -Parent) -PathType Container) -eq $false)
    {
        new-item -path (Split-Path -Path $logFilePath -Parent) -ItemType Directory -Force | Out-Null
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

    $regFilesPath = "$bootstrapPath\reg"
    if (Test-Path -Path $regFilesPath -PathType Container)
    {
        Out-Log "$regFilesPath already exists, don't need to create it"
    }
    else
    {
        Out-Log "Creating $regFilesPath"
        New-Item -Path $regFilesPath -ItemType Directory -Force | Out-Null
    }

    $tempDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.VolumeName -eq 'Temporary Storage'}
    if ($tempDrive)
    {
        $tempDrive = $tempDrive.DeviceID
        $packagesPath = "$tempDrive\packages"
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

    $logScriptFilePath = "$bootstrapPath\log.ps1"
    if (Test-Path -Path $logScriptFilePath -PathType Leaf)
    {
        Out-Log "$logScriptFilePath already exists, don't need to create it"
    }
    else
    {
        $logCommand = "Import-Csv (Get-ChildItem -Path `$logsPath\*.csv).FullName | Sort-Object -Property Timestamp | Format-Table Timestamp, @{Name = 'File'; Expression={`$_.File.Split('\')[-1]}}, Message -AutoSize"
        $logCommand | Out-File -FilePath $logScriptFilePath -Force
    }

    if (Get-Module -Name Defender -ListAvailable -ErrorAction SilentlyContinue)
    {
        # Temporary Defender exclusions to avoid perf issue
        # See also https://github.com/PowerShell/Microsoft.PowerShell.Archive/issues/32
        Invoke-ExpressionWithLogging -command "Add-MpPreference -ExclusionPath $env:temp -Force"
        Invoke-ExpressionWithLogging -command "Add-MpPreference -ExclusionPath $bootstrapPath -Force"
        Invoke-ExpressionWithLogging -command "Add-MpPreference -ExclusionPath $toolsPath -Force"
    }
    $runCount = (Get-ChildItem -Path "$logsPath\$scriptBaseName-Run*" -File | Measure-Object).Count
    $runCount++

    if (Test-Path -Path "$bootstrapPath\ScriptRanToCompletion" -PathType Leaf)
    {
        Invoke-GetWindowsUpdate
        Complete-ScriptExecution
        exit
    }

    if ($PSVersionTable.PSVersion -ge [Version]'5.1' -and $PSEdition -eq 'Desktop')
    {
        # https://devblogs.microsoft.com/powershell/when-powershellget-v1-fails-to-install-the-nuget-provider/
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    }

    if ([string]::IsNullOrEmpty($group))
    {
        if ($env:COMPUTERNAME.StartsWith('TDC'))
        {
            $group = 'VSAW'
            $isSAW = $true
            $installDir = "$env:SystemDrive:\ch"
            if (Test-Path -Path $installDir -PathType Container)
            {
                Out-Log "$installDir already exists, don't need to create it"
            }
            else
            {
                Out-Log "Creating $installDir folder for non-admin chocolatey installs"
                New-Item -Path $installDir -ItemType Directory | Out-Null
            }
            Invoke-ExpressionWithLogging -command "[Environment]::SetEnvironmentVariable('ChocolateyInstall', '$installDir', 'User')"
            $env:ChocolateyInstall = $installDir
            Out-Log "`$env:ChocolateyInstall : $env:ChocolateyInstall"
        }
        else
        {
            if ($isVM)
            {
                $group = 'VM'
            }
            else
            {
                $group = 'PC'
                $isPC = $true
            }
        }
        Out-Log "`$isPC: $isPC `$isVM: $isVM `$isSAW: $isSAW"
    }

    if ($show)
    {
        $apps = Get-AppList
        $apps = $apps | Where-Object {$_.Groups -contains $group}
        $appCount = ($apps | Measure-Object).Count
        Out-Log "`nGroup: $group, Count: $appCount"
        Out-Log $apps
        exit
    }

    if ($PSVersionTable.PSVersion -lt [Version]'5.1')
    {
        $win32_OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem
    }
    else
    {
        $win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    }
    $productType = $win32_OperatingSystem.ProductType
    $osVersion = ($win32_OperatingSystem | Select-Object @{Label = 'OSVersion'; Expression = {"$($_.Caption) $($_.Version)"}}).OSVersion

    # 1 = Workstation, 2 = Domain controller, 3 = Server
    switch ($productType)
    {
        1 {$isWindowsClient = $true}
        2 {$isWindowsServer = $true}
        3 {$isWindowsServer = $true}
    }

    # https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
    $build = [environment]::OSVersion.Version.Build # TODO: switch to using just build number and product type instead of caption+version
    switch -regex ($osVersion)
    {
        '7601' {if ($isWindowsServer) {$os = 'WS08R2'; $isWS08R2 = $true} else {$os = 'WIN7'; $isWin7 = $true}}
        '9200' {if ($isWindowsServer) {$os = 'WS12'; $isWS12 = $true} else {$os = 'WIN8'; $isWin8 = $true}}
        '9600' {if ($isWindowsServer) {$os = 'WS12R2'; $isWS12R2 = $true} else {$os = 'WIN81'; $isWin81 = $true}}
        '10240' {$os = 'WIN10'; $isWin10 = $true} # 1507 Threshold 2
        '10586' {$os = 'WIN10'; $isWin10 = $true} # 1511 Threshold 2
        '14393' {if ($isWindowsServer) {$os = 'WS16'; $isWS16 = $true} else {$os = 'WIN10'; $isWin10 = $true}} # 1607 Redstone 1
        '15063' {$os = 'WIN10'; $isWin10 = $true} # RS2 1703 Redstone 2
        '16299' {if ($isWindowsServer) {$os = 'WS1709'} else {$os = 'WIN10'; $isWin10 = $true}} # 1709 (Redstone 3)
        '17134' {if ($isWindowsServer) {$os = 'WS1803'} else {$os = 'WIN10'; $isWin10 = $true}} # 1803 (Redstone 4)
        '17763' {if ($isWindowsServer) {$os = 'WS19'; $isWS19 = $true} else {$os = 'WIN10'; $isWin10 = $true}} # 1809 October 2018 Update (Redstone 5)
        '18362' {if ($isWindowsServer) {$os = 'WS1909'} else {$os = 'WIN10'; $isWin10 = $true}} # 1903 19H1 November 2019 Update
        '18363' {if ($isWindowsServer) {$os = 'WS1909'} else {$os = 'WIN10'; $isWin10 = $true}} # 1909 19H2 November 2019 Update
        '19041' {if ($isWindowsServer) {$os = 'WS2004'} else {$os = 'WIN10'; $isWin10 = $true}} # 2004 20H1 May 2020 Update
        '19042' {if ($isWindowsServer) {$os = 'WS20H2'} else {$os = 'WIN10'; $isWin10 = $true}} # 20H2 October 2020 Update
        '19043' {$os = 'WIN10'; $isWin10 = $true} # 21H1 May 2021 Update
        '19044' {$os = 'WIN10'; $isWin10 = $true} # 21H2 November 2021 Update
        '20348' {$os = 'WS22'; $isWS22 = $true} # 21H2
        '22000' {$os = 'WIN11'; $isWin11 = $true} # 21H2
	'22621' {$os = 'WIN11'; $isWin11 = $true} # 22H2
        default {$os = 'Unknown'}
    }
    Out-Log "OS: $os ($osVersion)"

    if ($isWindowsServer)
    {
        # Disable Server Manager from starting at Windows startup
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
    }

    if ($isWin11)
    {
        # Win11
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
    }

    if ($isWin10)
    {
        # Win10: Enable "Always show all icons in the notification area"
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v EnableAutoTray /t REG_DWORD /d 0 /f | Out-Null"
    }

    # Config for all Windows versions
    # Show file extensions
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
    # Show hidden files
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
    # Show protected operating system files
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
    # Explorer show compressed files color
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
    # Taskbar on left instead of center
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"

    if ($isSAW)
    {
        Invoke-ExpressionWithLogging -command 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Scope CurrentUser'
    }
    else
    {
        Invoke-ExpressionWithLogging -command 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force'
    }

    if ($isVM)
    {
        if (Test-Path -Path $profile.AllUsersAllHosts -PathType Leaf)
        {
            Out-Log "$($profile.AllUsersAllHosts) already exists, don't need to create it"
        }
        else
        {
            Invoke-ExpressionWithLogging -command "New-Item -Path $($profile.AllUsersAllHosts) -Type File -Force | Out-Null"
            Set-Content -Value '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072' -Path $profile.AllUsersAllHosts -Force
        }
    }

    if (Test-Path -Path $profile.CurrentUserCurrentHost -PathType Leaf)
    {
        Out-Log "$($profile.CurrentUserCurrentHost) already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $($profile.CurrentUserCurrentHost) -Type File -Force | Out-Null"
    }

    $ErrorActionPreference = 'SilentlyContinue'
    $chocoVersion = choco -v
    $ErrorActionPreference = 'Continue'

    if ($chocoVersion)
    {
        Out-Log "Chocolatey $chocoVersion already installed"
    }
    else
    {
        # Chocolatey install requires at least PS3. 2008R2/Win7 by default only have PS 2.0, so need to manually get PS5.1 installed on those
        if ($PSVersionTable.PSVersion -lt [Version]'3.0')
        {
            $installWmfScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-WMF.ps1'
            $installWmfScriptFilePath = "$scriptsPath\$($installWmfScriptUrl.Split('/')[-1])"
            #Import-Module -Name BitsTransfer
            #Start-BitsTransfer -Source $installWmfScriptUrl -Destination $installWmfScriptFilePath
            (New-Object Net.WebClient).DownloadFile($installWmfScriptUrl, $installWmfScriptFilePath)
            Invoke-ExpressionWithLogging -command $installWmfScriptFilePath
            # The install WMF script will issue a retart on its own
            exit
        }
        else
        {
            Invoke-ExpressionWithLogging -command "Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"

            $ErrorActionPreference = 'SilentlyContinue'
            $chocoVersion = choco -v
            $ErrorActionPreference = 'Continue'
            if ($chocoVersion)
            {
                Out-Log "Chocolatey $chocoVersion already installed"
            }
            else
            {
                Out-Log 'Chocolatey failed to install'
                exit
            }
        }
    }

    if ($chocoVersion)
    {
        Out-Log "Chocolatey $chocoVersion successfully installed"
        Out-Log "Changing Chocolatey download cache to $packagesPath to save space on OS disk. See also https://docs.chocolatey.org/en-us/guides/usage/change-cache"
        Invoke-ExpressionWithLogging -command "choco config set cacheLocation $packagesPath"
    }
    else
    {
        Out-Log 'Chocolatey install failed'
        exit
    }

    if ($PSVersionTable.PSVersion -lt [Version]'5.1')
    {
        # 14393+ definitely have PS5.1, 10240 and 10586 may not, but nobody uses those early days Win10 builds anymore anyway.
        # The chocolatey package checks if PowerShell 5.1 is installed, if so, it does not try to install it
        $timestamp = Get-Date -Format yyyyMMddHHmmssff
        $packageName = 'powershell'
        $chocoInstallLogFilePath = "$logsPath\choco_install_$($packageName)_$($timestamp).log"
        Invoke-ExpressionWithLogging -command "choco install $packageName --limit-output --no-progress --no-color --confirm --log-file=$chocoInstallLogFilePath | Out-Null"
        if ($LASTEXITCODE -eq 3010)
        {
            Out-Log 'Creating onstart scheduled task to run script again at startup'
            if (Test-Path -Path $scriptPath -PathType Leaf)
            {
                Out-Log "Script already exists in $scriptPath"
            }
            else
            {
                $bootstrapScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1'
                $bootstrapScriptFileName = $bootstrapScriptUrl.Split('/')[-1]
                $bootstrapScriptFilePath = "$scriptsPath\$bootstrapScriptFileName"
                Out-Log "Downloading $bootstrapScriptUrl to $bootstrapScriptFilePath"
                (New-Object Net.Webclient).DownloadFile($bootstrapScriptUrl, $bootstrapScriptFilePath)
            }
            Invoke-ExpressionWithLogging -command "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"powershell.exe -executionpolicy bypass -file $bootstrapScriptFilePath`" /f"
            Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
        }
    }

    # This needs to be before Set-PSRepository, otherwise Set-PSRepository will prompt to install it
    if ($PSEdition -eq 'Desktop')
    {
        Confirm-NugetInstalled
        Invoke-ExpressionWithLogging -command 'Import-Module -Name Appx -ErrorAction SilentlyContinue'
    }
    else
    {
        Invoke-ExpressionWithLogging -command 'Import-Module -Name Appx -UseWindowsPowerShell -ErrorAction SilentlyContinue'
    }

    # https://psframework.org/
	<#
    Import-Module -Name PSFramework -ErrorAction SilentlyContinue
    $psframework = Get-Module -Name PSFramework -ErrorAction SilentlyContinue
    if ($psframework)
    {
        Set-PSFramework
    }
    else
    {
        Out-Log 'PSFramework module not found, installing it'
        Invoke-ExpressionWithLogging -command "Install-Module -Name PSFramework -Repository PSGallery -Scope AllUsers -Force -ErrorAction SilentlyContinue"
        Invoke-ExpressionWithLogging -command "Import-Module -Name PSFramework -ErrorAction SilentlyContinue"
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
	#>

    $ErrorActionPreference = 'SilentlyContinue'
    $chocoVersion = choco -v
    $ErrorActionPreference = 'Continue'

    if ($chocoVersion)
    {
        Out-Log "Chocolatey $chocoVersion already installed"
    }
    else
    {
        if ($isSAW)
        {
            $installDir = "$env:SystemDrive:\ch"
            Invoke-ExpressionWithLogging -command "[Environment]::SetEnvironmentVariable('ChocolateyInstall', '$installDir', 'System')"
            New-Item -Path $installDir -ItemType Directory | Out-Null
        }

        Invoke-ExpressionWithLogging -command "Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
        $ErrorActionPreference = 'SilentlyContinue'
        $chocoVersion = choco -v
        $ErrorActionPreference = 'Continue'
        if ($chocoVersion)
        {
            Out-Log "Chocolatey $chocoVersion already installed"
        }
        else
        {
            Out-Log 'Chocolatey failed to install'
            exit
        }
    }

    if ($chocoVersion)
    {
        Out-Log "Chocolatey $chocoVersion successfully installed"
    }
    else
    {
        Out-Log 'Chocolatey install failed'
        exit
    }

    # Install Windows Terminal and winget
    if ($isWS22 -or $isWS19 -or $isWin11 -or $isWin10)
    {
        # This alternate way to install Windows Terminal is only needed on WS22. For Win11/Win10, it's easier to use winget to install Windows Terminal
        # But using this same approach on WS22/Win11/Win10 simplifies the script
        # "choco install microsoft-windows-terminal -y" does work on WS22/Win11/Win10, but there's no Windows Terminal Preview chocolatey package, only that package for the release version
        # So use the "download msixbundle + run Add-AppxPackage" approach instead to install Windows Terminal Preview
        # $windowsTerminalPreviewMsixBundleUri = 'https://github.com/microsoft/terminal/releases/download/v1.12.3472.0/Microsoft.WindowsTerminalPreview_1.12.3472.0_8wekyb3d8bbwe.msixbundle'
        # v1.13.10336.0 below released 2022-02-03

        $windowsTerminalReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/microsoft/terminal/releases'
        $windowsTerminalPreviewRelease = $windowsTerminalReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $windowsTerminalPreviewMsixBundleUri = ($windowsTerminalPreviewRelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $windowsTerminalPreviewMsixBundleFileName = $windowsTerminalPreviewMsixBundleUri.Split('/')[-1]
        $windowsTerminalPreviewMsixBundleFilePath = "$packagesPath\$windowsTerminalPreviewMsixBundleFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$windowsTerminalPreviewMsixBundleUri`', `'$windowsTerminalPreviewMsixBundleFilePath`')"
        Invoke-ExpressionWithLogging -command "Add-AppxPackage -Path $windowsTerminalPreviewMsixBundleFilePath -ErrorAction SilentlyContinue | Out-Null"
        <# Release version
        $windowsTerminalRelease = $windowsTerminalReleases | Where-Object {$_.prerelease -eq $false} | Sort-Object -Property id -Descending | Select-Object -First 1
        $windowsTerminalMsixBundleUri = ($windowsTerminalRelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $windowsTerminalMsixBundleFileName = $windowsTerminalMsixBundleUri.Split('/')[-1]
        $windowsTerminalMsixBundleFilePath = "$packagesPath\$windowsTerminalMsixBundleFileName"
        (New-Object Net.WebClient).DownloadFile($windowsTerminalMsixBundleUri, $windowsTerminalMsixBundleFilePath)
        Add-AppxPackage -Path $windowsTerminalMsixBundleFilePath
        #>

        # Install winget since it is not installed by default. It is supported on Win10/Win11 but not WS22 although you can get it working on WS22
        # Preview version didn't work, said it needed Microsoft.UI.Xaml 2.7.0 even after I installed Microsoft.UI.Xaml 2.7.0
        # $wingetMsixBundleUrl = 'https://github.com/microsoft/winget-cli/releases/download/v1.2.3411-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        $vcLibsUrl = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
        $vcLibsFileName = $vcLibsUrl.Split('/')[-1]
        $vcLibsFilePath = "$packagesPath\$vcLibsFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$vcLibsUrl`', `'$vcLibsFilePath`')"
        if (Test-Path -Path $vcLibsFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging -command "Add-AppPackage -Path $vcLibsFilePath | Out-Null"
        }

        $microsoftUiXamlPackageUrl = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.0'
        $microsoftUiXamlPackageFileName = $microsoftUiXamlPackageUrl.Split('/')[-1]
        $microsoftUiXamlPackageFolderPath = "$packagesPath\$microsoftUiXamlPackageFileName"
        $microsoftUiXamlPackageFilePath = "$packagesPath\$microsoftUiXamlPackageFileName.zip"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$microsoftUiXamlPackageUrl`', `'$microsoftUiXamlPackageFilePath`')"
        Invoke-ExpressionWithLogging -command "Expand-Zip -Path $microsoftUiXamlPackageFilePath -DestinationPath $microsoftUiXamlPackageFolderPath"
        $microsoftUiXamlAppXFilePath = "$microsoftUiXamlPackageFolderPath\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx"
        Invoke-ExpressionWithLogging -command "Add-AppxPackage -Path $microsoftUiXamlAppXFilePath | Out-Null"

        $wingetReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases'
        $wingetPrerelease = $wingetReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleUrl = ($wingetPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleFileName = $wingetPrereleaseMsixBundleUrl.Split('/')[-1]
        $wingetPrereleaseMsixBundleFilePath = "$packagesPath\$wingetPrereleaseMsixBundleFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$wingetPrereleaseMsixBundleUrl`', `'$wingetPrereleaseMsixBundleFilePath`')"
        $wingetPrereleaseMsixBundleLicenseUrl = ($wingetPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('xml')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleLicenseFileName = $wingetPrereleaseMsixBundleLicenseUrl.Split('/')[-1]
        $wingetPrereleaseMsixBundleLicenseFilePath = "$packagesPath\$wingetPrereleaseMsixBundleLicenseFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$wingetPrereleaseMsixBundleLicenseUrl`', `'$wingetPrereleaseMsixBundleLicenseFilePath`')"
        if ((Test-Path -Path $wingetPrereleaseMsixBundleFilePath -PathType Leaf) -and (Test-Path -Path $wingetPrereleaseMsixBundleLicenseFilePath -PathType Leaf))
        {
            Invoke-ExpressionWithLogging -command "Add-AppxProvisionedPackage -Online -PackagePath $wingetPrereleaseMsixBundleFilePath -LicensePath $wingetPrereleaseMsixBundleLicenseFilePath | Out-Null"
        }
        <# Release version
        $wingetrelease = $wingetReleases | Where-Object prerelease -eq $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $wingetreleaseMsixBundleUrl = ($wingetrelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetreleaseMsixBundleFileName = $wingetreleaseMsixBundleUrl.Split('/')[-1]
        $wingetreleaseMsixBundleFilePath = "$packagesPath\$wingetreleaseMsixBundleFileName"
        (New-Object Net.WebClient).DownloadFile($wingetreleaseMsixBundleUrl, $wingetreleaseMsixBundleFilePath)
        $wingetreleaseMsixBundleLicenseUrl = ($wingetrelease.assets | Where-Object {$_.browser_download_url.EndsWith('xml')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetreleaseMsixBundleLicenseFileName = $wingetreleaseMsixBundleLicenseUrl.Split('/')[-1]
        $wingetreleaseMsixBundleLicenseFilePath = "$packagesPath\$wingetreleaseMsixBundleLicenseFileName"
        (New-Object Net.WebClient).DownloadFile($wingetreleaseMsixBundleLicenseUrl, $wingetreleaseMsixBundleLicenseFilePath)
        if ((Test-Path -Path $wingetreleaseMsixBundleFilePath -PathType Leaf) -and (Test-Path -Path $wingetreleaseMsixBundleLicenseFilePath -PathType Leaf))
        {
            Invoke-ExpressionWithLogging -command "Add-AppxProvisionedPackage -Online -PackagePath $wingetreleaseMsixBundleFilePath -LicensePath $wingetreleaseMsixBundleLicenseFilePath | Out-Null"
        }
        #>
    }

    $powershellReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases'
    # Install PS7 release version
    $powershellRelease = $powershellReleases | Where-Object prerelease -EQ $false | Sort-Object -Property id -Descending | Select-Object -First 1
    $powerShellx64MsiUrl = ($powershellRelease.assets | Where-Object {$_.browser_download_url.EndsWith('win-x64.msi')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
    $powerShellx64MsiFileName = $powerShellx64MsiUrl.Split('/')[-1]
    $powerShellx64MsiFilePath = "$packagesPath\$powerShellx64MsiFileName"
    $powerShellx64MsiLogFilePath = "$logsPath\$($powerShellx64MsiFileName).$(Get-Date -Format yyyyMMddHHmmssff).log"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$powerShellx64MsiUrl`', `'$powerShellx64MsiFilePath`')"
    Invoke-ExpressionWithLogging -command "msiexec.exe /package $powerShellx64MsiFilePath /quiet /L*v $powerShellx64MsiLogFilePath ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=0 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 | Out-Null"
    # Install PS7 preview version
    $powershellPrerelease = $powershellReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
    $powerShellPreviewx64MsiUrl = ($powershellPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('win-x64.msi')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
    $powerShellPreviewx64MsiFileName = $powerShellPreviewx64MsiUrl.Split('/')[-1]
    $powerShellPreviewx64MsiFilePath = "$packagesPath\$powerShellPreviewx64MsiFileName"
    $powerShellPreviewx64MsiLogFilePath = "$logsPath\$($powerShellPreviewx64MsiFileName).$(Get-Date -Format yyyyMMddHHmmssff).log"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$powerShellPreviewx64MsiUrl`', `'$powerShellPreviewx64MsiFilePath`')"
    Invoke-ExpressionWithLogging -command "msiexec.exe /package $powerShellPreviewx64MsiFilePath /quiet /L*v $powerShellPreviewx64MsiLogFilePath ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=0 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 | Out-Null"

    if (!$apps)
    {
        $apps = Get-AppList
        if (!$apps)
        {
            Out-Log -Level Error -Message 'Failed to get app list'
            exit
        }
    }

    if ($group -ne 'All')
    {
        $apps = $apps | Where-Object {$_.Groups -contains $group}
    }

    Out-Log 'Checking if winget is installed'
    $ErrorActionPreference = 'SilentlyContinue'
    $wingetVersion = winget -v
    $ErrorActionPreference = 'Continue'
    if ($wingetVersion)
    {
        $isWingetInstalled = $true
    }
    else
    {
        $isWingetInstalled = $false
    }
    Out-Log "`$isWingetInstalled: $isWingetInstalled"
    Out-Log "Mode: $group"
    Out-Log "$($apps.Count) apps to be installed"
    $apps | ForEach-Object {

        $app = $_

        if ($app.ChocolateyName -and ($app.WingetName -or !$app.WingetName))
        {
            $appName = $app.ChocolateyName
            $useChocolatey = $true
            if ($app.ChocolateyParams)
            {
                $chocolateyParams = $app.ChocolateyParams
            }
            else
            {
                $chocolateyParams = $null
            }
        }
        elseif ($app.WingetName)
        {
            $appName = $app.WingetName
        }
        else
        {
            $appName = ''
        }

        if ($appName -and $useChocolatey)
        {
            Remove-Variable useChocolatey -Force
            # https://docs.chocolatey.org/en-us/choco/commands/install
            $timestamp = Get-Date -Format yyyyMMddHHmmssff
            $chocoInstallLogFilePath = "$logsPath\choco_install_$($appName)_$($timestamp).log"
            $command = "choco install $appName --limit-output --no-progress --no-color --confirm --log-file=$chocoInstallLogFilePath"
            if ($chocolateyParams)
            {
                # EXAMPLE: choco install sysinternals --params "/InstallDir:C:\your\install\path"
                $command = "$command --params `"$chocolateyParams`""
                $command = $command.Replace('TOOLSPATH', $toolsPath)
                $command = $command.Replace('MYPATH', $myPath)
            }
            $command = "$command | Out-Null"
            Invoke-ExpressionWithLogging -command $command
        }
        elseif ($appName -and !$useChocolatey -and $isWingetInstalled)
        {
            # https://aka.ms/winget-command-install
            # winget log files will be in %temp%\AICLI\*.log unless redirected
            $timestamp = Get-Date -Format yyyyMMddHHmmssff
            $wingetInstallLogFilePath = "$logsPath\winget_install_$($appName)_$($timestamp).log"
            $command = "winget install --id $appName --exact --silent --accept-package-agreements --accept-source-agreements --log $wingetInstallLogFilePath | Out-Null"
            Invoke-ExpressionWithLogging -command $command
        }
    }

    <#
    The sysinternals package tries to create the specified InstallDir and fails if it already exists
    ERROR: Exception calling "CreateDirectory" with "1" argument(s): "Cannot create "C:\OneDrive\Tools" because a file or directory with the same name already exists."
    So don't precreate these, let the package create them, and if needed, make sure they are created after all package installs are done
    #>
    Out-Log "Checking if $toolsPath exists"
    if (Test-Path -Path $toolsPath -PathType Container)
    {
        Out-Log "$toolsPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $toolsPath -Type Directory -Force | Out-Null"
    }

    Out-Log "Checking if $myPath exists"
    if (Test-Path -Path $myPath -PathType Container)
    {
        Out-Log "$myPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $myPath -Type Directory -Force | Out-Null"
    }

    # https://stackoverflow.com/questions/714877/setting-windows-powershell-environment-variables
    Out-Log "Adding $toolsPath and $myPath to user Path environment variable"
    $newUserPath = "$env:Path;$toolsPath;$myPath"
    Invoke-ExpressionWithLogging -command "[Environment]::SetEnvironmentVariable('Path', '$newUserPath', 'User')"

    $userPathFromRegistry = (Get-ItemProperty -Path 'HKCU:\Environment' -Name Path).Path
    $separator = "`n$('='*160)`n"
    Out-Log "$separator`$userPathFromRegistry: $userPathFromRegistry$separator"

    Invoke-ExpressionWithLogging -command "Remove-Item $env:PUBLIC\Desktop\*.lnk -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging -command "Remove-Item $env:USERPROFILE\Desktop\*.lnk -Force -ErrorAction SilentlyContinue"

    $scriptFileUrls = @(
        # 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Cursor.ps1',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Console.ps1',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Add-ScheduledTasks.ps1'
    )

    $scriptFileUrls | ForEach-Object {
        $scriptFileUrl = $_
        $scriptFileName = $scriptFileUrl.Split('/')[-1]
        $scriptFilePath = "$scriptsPath\$scriptFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$scriptFileUrl`', `'$scriptFilePath`')"
        Invoke-ExpressionWithLogging -command $scriptFilePath
    }

    $regFileUrls = @(
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/7-zip_auto_extract_downloaded_zip.reg',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/7-zip_double-click_extract_to_folder.reg'
    )

    $regFileUrls | ForEach-Object {
        $regFileUrl = $_
        $regFileName = $regFileUrl.Split('/')[-1]
        $regFilePath = "$regFilesPath\$regFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$regFileUrl`', `'$regFilePath`')"
        if (Test-Path -Path $regFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging -command "reg import $regFilePath"
        }
    }

    $windowsTerminalSettingsUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/windows-terminal-settings.json'

    $windowsTerminalSettingsFilePaths = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
    )

    $windowsTerminalSettingsFilePaths | ForEach-Object {
        $windowsTerminalSettingsFilePath = $_
        if (Test-Path -Path $windowsTerminalSettingsFilePath -PathType Leaf)
        {
            Move-Item -Path $windowsTerminalSettingsFilePath -Destination "$windowsTerminalSettingsFilePath.original" -ErrorAction SilentlyContinue
        }
        else
        {
            Invoke-ExpressionWithLogging -command "New-Item -Path $windowsTerminalSettingsFilePath -ItemType File -Force"
        }
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$windowsTerminalSettingsUrl`', `'$windowsTerminalSettingsFilePath`')"
    }

    if ($isWin11 -and $group -eq 'PC')
    {
        Invoke-ExpressionWithLogging -command 'wsl --install'
        # /All enables all parent features of the specified feature
        Invoke-ExpressionWithLogging -command 'dism /Online /Enable-Feature /FeatureName:NetFx3 /All'
        Invoke-ExpressionWithLogging -command 'dism /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V /All'
    }

    $nppSettingsZipUrl = 'https://github.com/craiglandis/bootstrap/raw/main/npp-settings.zip'
    $nppSettingsZipFileName = $nppSettingsZipUrl.Split('/')[-1]
    $nppSettingsZipFilePath = "$packagesPath\$nppSettingsZipFileName"
    $nppSettingsTempFolderPath = "$packagesPath\$($nppSettingsZipFileName.Replace('.zip',''))"
    $nppSettingsFolderPath = 'C:\OneDrive\npp'
    $nppAppDataPath = "$env:APPDATA\Notepad++"
    $nppCloudFolderPath = "$nppAppDataPath\cloud"
    $nppCloudFilePath = "$nppCloudFolderPath\choice"

    if (Test-Path -Path $nppSettingsFolderPath -PathType Container)
    {
        Out-Log "$nppSettingsFolderPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $nppSettingsFolderPath -Type Directory -Force | Out-Null"
    }

    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$nppSettingsZipUrl`', `'$nppSettingsZipFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Zip -Path $nppSettingsZipFilePath -DestinationPath $nppSettingsTempFolderPath"
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $nppSettingsTempFolderPath\* -Destination $nppSettingsFolderPath"
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $nppSettingsTempFolderPath\* -Destination $nppAppDataPath"

    if (Test-Path -Path $nppCloudFolderPath -PathType Container)
    {
        Out-Log "$nppSettingsFolderPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $nppCloudFolderPath -Type Directory -Force | Out-Null"
    }
    Invoke-ExpressionWithLogging -command "Set-Content -Path $env:APPDATA\Notepad++\cloud\choice -Value $nppSettingsFolderPath -Force"

    # The chocolatey package for Everything includes an old version (1.1.0.9) of the es.exe CLI tool
    # Delete that one, then download the latest (1.1.0.23 ) from the voidtools site
    Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:ProgramData\chocolatey\bin\es.exe -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:ProgramData\chocolatey\lib\Everything\tools\es.exe -Force -ErrorAction SilentlyContinue"
    $esZipUrl = 'https://www.voidtools.com/ES-1.1.0.23.zip'
    $esZipFileName = $esZipUrl.Split('/')[-1]
    $esZipFolderPath = "$packagesPath\$($esZipFileName.Replace('.zip',''))"
    $esZipFilePath = "$packagesPath\$esZipFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$esZipUrl`', `'$esZipFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Zip -Path $esZipFilePath -DestinationPath $esZipFolderPath"
    Copy-Item -Path $esZipFolderPath\es.exe -Destination $toolsPath -Force

    $esIniUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/es.ini'
    $esIniFileName = $esIniUrl.Split('/')[-1]
    $esIniFilePath = "$toolsPath\$esIniFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$esIniUrl`', `'$esIniFilePath`')"

    if ($group -eq 'PC' -or $group -eq 'VM')
    {
        $getNirSoftToolsScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Get-NirsoftTools.ps1'
        $getNirSoftToolsScriptFileName = $getNirSoftToolsScriptUrl.Split('/')[-1]
        $getNirSoftToolsScriptFilePath = "$scriptsPath\$getNirSoftToolsScriptFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$getNirSoftToolsScriptUrl`', `'$getNirSoftToolsScriptFilePath`')"
        Invoke-ExpressionWithLogging -command $getNirSoftToolsScriptFilePath
    }

    # autohotkey.portable - couldn't find a way to specify a patch for this package
    # (portable? https://www.autohotkey.com/download/ahk.zip)

    # https://www.thenickmay.com/how-to-install-autohotkey-even-without-administrator-access/
    # It works - the .ahk file must be named AutoHotkeyU64.ahk, then you run AutoHotkeyU64.exe
    # copy-item -Path \\tsclient\c\onedrive\ahk\AutoHotkey.ahk -Destination c:\my\ahk\AutoHotkeyU64.ahk

    if ($group -eq 'VM' -or $group -eq 'PC' -or $group -eq 'LAPTOP')
    {
        $installVSCodeScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-VSCode.ps1'
        $installVSCodeScriptFileName = $installVSCodeScriptUrl.Split('/')[-1]
        $installVSCodeScriptFilePath = "$scriptsPath\$installVSCodeScriptFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$installVSCodeScriptUrl`', `'$installVSCodeScriptFilePath`')"
        Invoke-ExpressionWithLogging -command $installVSCodeScriptFilePath

        $installVSCodeExtensionsScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-VSCodeExtensions.ps1'
        $installVSCodeExtensionsScriptFileName = $installVSCodeExtensionsScriptUrl.Split('/')[-1]
        $installVSCodeExtensionsScriptFilePath = "$scriptsPath\$installVSCodeExtensionsScriptFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$installVSCodeExtensionsScriptUrl`', `'$installVSCodeExtensionsScriptFilePath`')"
        Invoke-ExpressionWithLogging -command $installVSCodeExtensionsScriptFilePath
    }

    $vsCodeSystemPath = "$env:ProgramFiles\Microsoft VS Code\Code.exe"
    $vsCodeUserPath = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"
    if (Test-Path -Path $vsCodeSystemPath -PathType Leaf)
    {
        $vsCodePath = $vsCodeSystemPath
    }
    if (Test-Path -Path $vsCodeUserPath -PathType Leaf)
    {
        $vsCodePath = $vsCodeUserPath
    }

    if ($vsCodePath)
    {
        $vsCodeSettingsJsonUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/vscode_settings.json'
        $vsCodeSettingsJsonPath = "$env:APPDATA\Code\User\settings.json"
        Invoke-ExpressionWithLogging -command "New-Item -Path $vsCodeSettingsJsonPath -Force"
        Out-Log "Downloading $vsCodeSettingsJsonUrl"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$vsCodeSettingsJsonUrl`', `'$vsCodeSettingsJsonPath`')"
    }
    else
    {
        Out-Log "VSCode not installed, skipping download of $vsCodeSettingsJsonUrl"
    }

    Invoke-ExpressionWithLogging -command 'Update-Help -Force -ErrorAction SilentlyContinue'
    $pwshFilePath = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (Test-Path -Path $pwshFilePath -PathType Leaf)
    {
        Invoke-ExpressionWithLogging -Command "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Update-Help -Force -ErrorAction SilentlyContinue"
    }

    if ($isPC -or $isVM)
    {
        Invoke-ExpressionWithLogging -command "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\od -Target $env:SystemDrive\OneDrive -ErrorAction SilentlyContinue | Out-Null"
        Invoke-ExpressionWithLogging -command "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\my -Target $env:SystemDrive\OneDrive\My -ErrorAction SilentlyContinue | Out-Null"
        Invoke-ExpressionWithLogging -command "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\bin -Target $env:SystemDrive\OneDrive\Tools -ErrorAction SilentlyContinue | Out-Null"

        # To remove the symbolic links (Remove-Item won't do it):
        #(Get-Item -Path "$env:SystemDrive\od").Delete()
        #(Get-Item -Path "$env:SystemDrive\my").Delete()
        #(Get-Item -Path "$env:SystemDrive\bin").Delete()
    }

    $installModulesFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-Modules.ps1'
    $installModulesFileName = $installModulesFileUrl.Split('/')[-1]
    $installModulesFilePath = "$scriptsPath\$installModulesFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$installModulesFileUrl`', `'$installModulesFilePath`')"

    if (Test-Path -Path $installModulesFilePath -PathType Leaf)
    {
        Invoke-ExpressionWithLogging -command 'powershell -nologo -noprofile -Command [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force'
        Invoke-ExpressionWithLogging -command 'powershell -nologo -noprofile -Command [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force -AllowPrerelease'
        Invoke-ExpressionWithLogging -command "powershell -nologo -noprofile -File $installModulesFilePath"

        if (Test-Path -Path $pwshFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging -command "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force"
            Invoke-ExpressionWithLogging -command "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force -AllowPrerelease"
            Invoke-ExpressionWithLogging -command "& `'$pwshFilePath`' -NoProfile -NoLogo -File $installModulesFilePath"
        }
    }
    else
    {
        Out-Log "File not found: $installModulesFilePath"
    }

    # "Choco find greenshot" - package is still on 1.2.10 from 2017, no high DPI scaling support so very small icons on 4K, no obvious way to use chocolatey to install the prerelease version, so doing it manually
    $greenshotReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/greenshot/greenshot/releases'
    $greenshotPrerelease = $greenshotReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
    $greenshotInstallerUrl = ($greenshotPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('.exe')}).browser_download_url
    $greenshotInstallerFileName = $greenshotInstallerUrl.Split('/')[-1]
    $greenshotInstallerFilePath = "$packagesPath\$greenshotInstallerFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$greenshotInstallerUrl`', `'$greenshotInstallerFilePath`')"
    Invoke-ExpressionWithLogging -command "$greenshotInstallerFilePath /VERYSILENT /NORESTART | Out-Null"

    if ($isPC)
    {
        $caption = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption
        if ($caption -eq 'Microsoft Windows 11 Enterprise')
        {
            c:\windows\system32\cscript.exe //H:cscript
            cscript //NoLogo c:\windows\system32\slmgr.vbs /skms RED-VL-VM.redmond.corp.microsoft.com
            cscript //NoLogo c:\windows\system32\slmgr.vbs /ipk NPPR9-FWDCX-D2C8J-H872K-2YT43
            cscript //NoLogo c:\windows\system32\slmgr.vbs /ato
            cscript //NoLogo c:\windows\system32\slmgr.vbs /dlv
        }
    }

    if ($isPC -or $isVM)
    {
        $taskName = 'bootstrap'
        $scheduleService = New-Object -ComObject Schedule.Service
        $scheduleService.Connect()
        $rootFolder = $scheduleService.GetFolder('\')
        $tasks = $rootFolder.GetTasks(1) | Select-Object Name, Path, State
        $bootstrapTask = $tasks | Where-Object {$_.Name -eq $taskName}
        if ($bootstrapTask)
        {
            Out-Log "Found $taskName scheduled task from previous script run, deleting it"
            $rootFolder.DeleteTask($taskName, 0)
        }
    }

    if ($isVM)
    {
        # Set file type associations (FTAs) with SetUserFTA, which works around how Win8+ protects certain FTAs from being configure the old way in the registry
        # https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/
        # HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\<extension>\OpenWithList
        # Browser
        Invoke-ExpressionWithLogging -command 'SetUserFTA http MSEdgeHTM'
        Invoke-ExpressionWithLogging -command 'SetUserFTA https MSEdgeHTM'
        Invoke-ExpressionWithLogging -command 'SetUserFTA microsoft-edge MSEdgeHTM'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .htm MSEdgeHTM'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .html MSEdgeHTM'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .pdf MSEdgeHTM'
        # Logs/config
        Invoke-ExpressionWithLogging -command 'SetUserFTA .bas Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .cfg Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .conf Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .config Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .csv Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .inf Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .ini Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .json Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .log Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .rdp Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .reg Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .settings Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .status Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .txt Applications\notepad++.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .xml Applications\notepad++.exe'
        # Code
        Invoke-ExpressionWithLogging -command 'SetUserFTA .bat Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .cmd Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .ps1 Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .ps1xml Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .psd1 Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .psm1 Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .py Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .sh Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .vbs Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .wsf Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .xaml Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .xls Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .xlsm Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .xsl Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .xslt Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .yaml Applications\code.exe'
        Invoke-ExpressionWithLogging -command 'SetUserFTA .yml Applications\code.exe'
    }

    $zimmermanToolsZipUrl = 'https://f001.backblazeb2.com/file/EricZimmermanTools/net6/All_6.zip'
    $zimmermanToolsZipFileName = $zimmermanToolsZipUrl.Split('/')[-1]
    $zimmermanToolsZipFilePath = "$packagesPath\$zimmermanToolsZipFileName"
    $zimmermanToolsZipFolderPath = $zimmermanToolsZipFilePath.Replace('.zip','')
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$zimmermanToolsZipUrl`', `'$zimmermanToolsZipFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Zip -Path $zimmermanToolsZipFilePath -DestinationPath $zimmermanToolsZipFolderPath"
    Get-ChildItem -Path $zimmermanToolsZipFolderPath | ForEach-Object {Expand-Zip -Path $_.FullName -DestinationPath $toolsPath}

    $tssUrl = 'https://aka.ms/getTSSv2'
    $tssFolderPath = "$toolsPath\TSSv2"
    $tssFilePath = "$packagesPath\TSSv2.zip"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$tssUrl`', `'$tssFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Zip -Path $tssFilePath -DestinationPath $tssFolderPath"

    Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:USERPROFILE\Desktop\desktop.ini -Force"
    Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:PUBLIC\Desktop\desktop.ini -Force"

    Invoke-ExpressionWithLogging -command "reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Discord /f"
    Invoke-ExpressionWithLogging -command "reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v BCClipboard /f"

    Invoke-ExpressionWithLogging -command "powercfg /hibernate off"

    Invoke-GetWindowsUpdate

    # es.exe and wt.exe don't work as expected without a reboot or maybe a logoff /logonCount
    # so try logoff first to see if that resolves things
    Invoke-ExpressionWithLogging -command "C:\Windows\system32\logoff.exe"
}
