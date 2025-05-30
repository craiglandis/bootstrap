<#
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; (New-Object Net.Webclient).DownloadFile('https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1', "$env:SystemDrive\bootstrap.ps1");.\bootstrap.ps1 -group VM
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; (New-Object Net.Webclient).DownloadFile('https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1', "$env:SystemDrive\bootstrap.ps1");.\bootstrap.ps1 -group HV
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; (New-Object Net.Webclient).DownloadFile('https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1', "$env:SystemDrive\bootstrap.ps1");.\bootstrap.ps1 -group QUICKVM
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; \\tsclient\c\src\bootstrap\bootstrap.ps1
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
ipcsv (gci c:\bs\*.csv | sort lastwritetime -desc)[0].FullName | ft -a timestamp,message

=======
# [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; (New-Object Net.Webclient).DownloadFile('https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1', "$env:SystemDrive\bootstrap.ps1"); Invoke-Expression -command $env:SystemDrive\bootstrap.ps1
# [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\src\bootstrap\bootstrap.ps1
TODO:
Update C:\Users\<user>\Documents\Default.rdp
Get-NetConnectionProfile hangs when run from Invoke-Bootstrap.ps1 - commented it out for now
Why aren't 7-zip file associations getting updated?
Mouse cursor - setting cursor size/color isn't working - ends up huge and wrong color
Steam - steam logon prompt comes up, no obvious way to surpress without stopping Steam from starting at boot, so no big deal, leave as-is
Additional shell customizations
Install KE https://aka.ms/ke
reg add HKLM\Software\Policies\Microsoft\Windows\Explorer /v DisableSearchBoxSuggestions
Import KE connections
Install Visio https://www.office.com/?auth=2&home=1
Use fileUris to download the scripts instead of doing downloads from invoke-bootstrap.ps1/bootstrap.ps1
Log to a custom event log - PSFramework - and create a .log, .csv, or .xlsx export of the useful stuff from that at the end
Incorporate Helper module
#>
[CmdletBinding()]
param(
    [ValidateSet('HV','PC', 'QUICKVM', 'VM', 'ALL')]
    [string]$group,
    [switch]$show,
    [string]$toolsPath = 'C:\OneDrive\Tools',
    [string]$myPath = 'C:\OneDrive\My',
    [switch]$installModules
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
            [string]$prefix,
            [switch]$raw,
            [switch]$logonly,
            [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
            [string]$color = 'White'
        )

        if ($raw)
        {
            if ($logonly)
            {
                if ($global:logFilePath)
                {
                    $text | Out-File $global:logFilePath -Append
                }
            }
            else
            {
                Write-Host $text -ForegroundColor $color
                if ($global:logFilePath)
                {
                    $text | Out-File $global:logFilePath -Append
                }
            }
        }
        else
        {
            if ($prefix -eq 'timespan' -and $global:scriptStartTime)
            {
                $timespan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
                $prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
            }
            elseif ($prefix -eq 'both' -and $global:scriptStartTime)
            {
                $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
                $timespan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
                $prefixString = "$($timestamp) $('{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan)"
            }
            else
            {
                $prefixString = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
            }

            if ($logonly)
            {
                if ($global:logFilePath)
                {
                    "$prefixString $text" | Out-File $global:logFilePath -Append
                }
            }
            else
            {
                Write-Host $prefixString -NoNewline -ForegroundColor Cyan
                Write-Host " $text" -ForegroundColor $color
                if ($global:logFilePath)
                {
                    "$prefixString $text" | Out-File $global:logFilePath -Append
                }
            }
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
            Out-Log "Failed: $command"
            Out-Log "`$LASTEXITCODE: $LASTEXITCODE"
        }
    }

    function Confirm-NugetInstalled
    {
        Out-Log 'Verifying Nuget 2.8.5.201+ is installed'
        $nuget = Get-PackageProvider -Name nuget -ErrorAction SilentlyContinue -Force
        if (!$nuget -or $nuget.Version -lt [Version]'2.8.5.201')
        {
            Invoke-ExpressionWithLogging 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force'
        }
        else
        {
            Out-Log "Nuget $($nuget.Version) already installed"
        }
    }

    function Get-AppList
    {
        $appsJsonFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/apps.json'
        $appsJsonFilePath = "$bootstrapPath\apps.json"
        Remove-Item -Path $appsJsonFilePath -Force -ErrorAction SilentlyContinue
        if ($isWin7 -or $isWS08R2 -or $isWS12)
        {
            Invoke-ExpressionWithLogging "Start-BitsTransfer -Source $appsJsonFileUrl -Destination $appsJsonFilePath"
        }
        else
        {
            Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$appsJsonFileUrl`', `'$appsJsonFilePath`')"
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
        Invoke-ExpressionWithLogging "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"$taskRun`" /f"
    }

    function Invoke-GetWindowsUpdate
    {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-ExpressionWithLogging 'Install-Module -Name PSWindowsUpdate -Repository PSGallery -Scope AllUsers -Force'
        Invoke-ExpressionWithLogging 'Import-Module -Name PSWindowsUpdate -Force'
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
            Invoke-WUJob -ComputerName localhost -Script {$ProgressPreference = 'SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Set-ExecutionPolicy Bypass -Force; Import-Module PSWindowsUpdate; Get-WUList -MicrosoftUpdate -UpdateType Software -NotCategory 'Language packs' -AcceptAll -Download -Install -IgnoreReboot -Verbose *>&1 | Tee-Object C:\bs\logs\Get-WUList.log} -RunNow -Confirm:$false -Verbose -ErrorAction Ignore *>&1 | Tee-Object $invokeWUJobLogFilePath
            do
            {
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
                Invoke-ExpressionWithLogging 'Restart-Computer -Force'
                #exit
            }
            else
            {
                Invoke-ExpressionWithLogging 'schtasks /delete /tn bootstrap /f'
                Complete-ScriptExecution
                Invoke-ExpressionWithLogging 'Restart-Computer -Force'
                #exit
            }
        }
        else
        {
            Out-Log 'Failed to install PSWindowsUpdate module'
            Complete-ScriptExecution
            Invoke-ExpressionWithLogging 'Restart-Computer -Force'
            #exit
        }
    }

    function Complete-ScriptExecution
    {
        if (Get-Module -Name Defender -ListAvailable -ErrorAction SilentlyContinue)
        {
            Invoke-ExpressionWithLogging "Remove-MpPreference -ExclusionPath $env:temp -Force"
            Invoke-ExpressionWithLogging "Remove-MpPreference -ExclusionPath $bootstrapPath -Force"
            Invoke-ExpressionWithLogging "Remove-MpPreference -ExclusionPath $toolsPath -Force"
        }

        <#
		$psFrameworkLogPath = Get-PSFConfigValue -FullName PSFramework.Logging.FileSystem.LogPath
        $psFrameworkLogFile = Get-ChildItem -Path $psFrameworkLogPath | Sort-Object LastWriteTime -desc | Select-Object -First 1
        $psFrameworkLogFilePath = $psFrameworkLogFile.FullName
        Out-Log "Log path: $psFrameworkLogFilePath"
		#>
        Invoke-ExpressionWithLogging "Copy-Item -Path $env:ProgramData\chocolatey\logs\chocolatey.log -Destination $logsPath"
        Invoke-ExpressionWithLogging "New-Item -Path $bootstrapPath\ScriptRanToCompletion -ItemType File -Force | Out-Null"

        Out-Log "Log file: $logFilePath"
        $scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
        Out-Log "$scriptName duration: $scriptDuration"
        Out-Log 'Script completed. Some things may not work as expected until you sign off and on again.'
        # es.exe and wt.exe don't work as expected without a reboot or maybe a logoff /logonCount
        # so try logoff first to see if that resolves things
        # Invoke-ExpressionWithLogging 'C:\Windows\system32\logoff.exe'
    }

    function Enable-PSLogging
    {
        Invoke-ExpressionWithLogging '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072'
        $getPSLoggingScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Get-PSLogging.ps1'
        $getPSLoggingScriptName = $getPSLoggingScriptUrl.Split('/')[-1]
        $getPSLoggingScriptFilePath = "$scriptsPath\$getPSLoggingScriptName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$getPSLoggingScriptUrl`', `'$getPSLoggingScriptFilePath`')"
        Invoke-ExpressionWithLogging "& `'$getPSLoggingScriptFilePath`' -Enable"
    }

    function Remove-NullProperties
    {
        param(
            [parameter(Mandatory, ValueFromPipeline)]
            [psobject] $InputObject
        )

        process
        {
            # Create the initially empty output object
            $obj = [pscustomobject]::new()
            # Loop over all input-object properties.
            foreach ($prop in $InputObject.psobject.properties)
            {
                # If a property is non-$null, add it to the output object.
                if ($null -ne $InputObject.$($prop.Name))
                {
                    Add-Member -InputObject $obj -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
                }
            }
            # Give the output object a type name that reflects the type of the input
            # object prefixed with 'NonNull.' - note that this is purely informational, unless
            # you define a custom output format for this type name.
            $obj.pstypenames.Insert(0, 'NonNull.' + $InputObject.GetType().FullName)
            # Output the output object.
            $obj
        }
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

    $bootstrapPath = "$env:SystemDrive\bootstrap"
    $logFilePath = "$bootstrapPath\$($scriptBaseName)_$(Get-Date -Format yyyyMMddhhmmss).log"
    if ((Test-Path -Path (Split-Path -Path $logFilePath -Parent) -PathType Container) -eq $false)
    {
        New-Item -Path (Split-Path -Path $logFilePath -Parent) -ItemType Directory -Force | Out-Null
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
        Enable-PSLogging
    }

    $windowsIdentityName = Invoke-ExpressionWithLogging '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name'
    $isSystem = Invoke-ExpressionWithLogging '[System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem'
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
        Invoke-ExpressionWithLogging "Add-MpPreference -ExclusionPath $env:temp -Force"
        Invoke-ExpressionWithLogging "Add-MpPreference -ExclusionPath $bootstrapPath -Force"
        Invoke-ExpressionWithLogging "Add-MpPreference -ExclusionPath $toolsPath -Force"
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
            Invoke-ExpressionWithLogging "[Environment]::SetEnvironmentVariable('ChocolateyInstall', '$installDir', 'User')"
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
    else
    {
        Out-Log "`$group: $group"
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
	'22631' {$os = 'WIN11'; $isWin11 = $true} # 23H2
        default {$os = 'Unknown'}
    }
    Out-Log "OS: $os ($osVersion)"
    if ($os -eq 'Unknown')
    {
    	Out-Log "Could not determine OS version for build number $build, exiting"
     	exit
    }

    if ($isWindowsServer)
    {
        # Disable Server Manager from starting at Windows startup
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\ServerManager' -Name 'DoNotOpenServerManagerAtLogon' -Value 1 -PropertyType 'DWord' -Force | Out-Null"
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\ServerManager' -Name 'DoNotPopWACConsoleAtSMLaunch' -Value 1 -PropertyType 'DWord' -Force | Out-Null"
    }

    if ($isWin11)
    {
        # Enable classic context menu
        Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        # Hide Search box on Taskbar
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -PropertyType 'DWord' -Value 0 -Force | Out-Null"
        # Hide Task view on Taskbar
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowTaskViewButton' -PropertyType 'DWord' -Value 0 -Force | Out-Null"
        # Hide Widgets on Taskbar
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarDa' -PropertyType 'DWord' -Value 0 -Force | Out-Null"
        # Hide Chat on Taskbar
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -PropertyType 'DWord' -Value 0 -Force | Out-Null"
	# Hide Desktop Icons
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideIcons' -PropertyType 'DWord' -Value 1 -Force | Out-Null"
    }

    if ($isWin10)
    {
        # Win10: Enable "Always show all icons in the notification area"
        Invoke-ExpressionWithLogging "New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'EnableAutoTray' -Value 0 -PropertyType 'DWord' -Force | Out-Null"
    }

    # Config for all Windows versions
    # Disable "Show account related notifications occasionally in Start"
    Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Start_AccountNotifications /t REG_DWORD /d 0 /f"
    # Disable "Enhance pointer precision"
    Invoke-ExpressionWithLogging "reg add 'HKCU\Control Panel\Mouse' /v MouseSpeed /t REG_SZ /d 0 /f"
    Invoke-ExpressionWithLogging "reg add 'HKCU\Control Panel\Mouse' /v MouseThreshold1 /t REG_SZ /d 0 /f"
    Invoke-ExpressionWithLogging "reg add 'HKCU\Control Panel\Mouse' /v MouseThreshold2 /t REG_SZ /d 0 /f"
    # Disable web search and recent search entries
    # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsExplorer::DisableSearchBoxSuggestions
    Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Policies\Microsoft\Windows\Explorer' /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f"
    # Configure New Tab page URL
    # https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::NewTabPageLocation
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Policies\Microsoft\Edge' /v NewTabPageLocation /t REG_SZ /d 'https://www.google.com' /f"
    # Enable dark mode
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v SystemUsesLightTheme /t REG_DWORD /d 0 /f"
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v AppsUseLightTheme /t REG_DWORD /d 0 /f"
    # Set it to have no wallpaper (so solid color)
    Invoke-ExpressionWithLogging "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value ''"
    # Show file extensions
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
    # Show hidden files
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
    # Display the full path in the title bar
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' /v FullPath /t REG_DWORD /d 1 /f | Out-Null"
    # Show encrypted or compressed NTFS files in color
    Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowEncryptCompressedColor /t REG_DWORD /d 1 /f | Out-Null"
    # Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowEncryptCompressedColor' -Type DWord -Value 1
    # Show protected operating system files
    Invoke-ExpressionWithLogging "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
    # Explorer show compressed files color
    Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
    # Taskbar on left instead of center
    Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"
    # Prevent "Your remote desktop session has ended" dialog when closing an RDP session
    Invoke-ExpressionWithLogging "reg add 'HKCU\Software\Microsoft\Terminal Server Client' /v DisableEndSessionDialog /t REG_DWORD /d 1 /f | Out-Null"

    if ($isSAW)
    {
        Invoke-ExpressionWithLogging 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Scope CurrentUser'
    }
    else
    {
        Invoke-ExpressionWithLogging 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force'
    }

    if ($isVM)
    {
        if (Test-Path -Path $profile.AllUsersAllHosts -PathType Leaf)
        {
            Out-Log "$($profile.AllUsersAllHosts) already exists, don't need to create it"
        }
        else
        {
            #Invoke-ExpressionWithLogging "New-Item -Path $($profile.AllUsersAllHosts) -Type File -Force | Out-Null"
            Invoke-ExpressionWithLogging "New-Item -Path $profile -Type File -Force | Out-Null"
            $profilePs7 = 'C:\Program Files\PowerShell\7\profile.ps1'
            if (Test-Path -Path (Split-Path -Path $profilePs7) -PathType Container)
            {
                Invoke-ExpressionWithLogging "New-Item -Path '$profilePs7' -Type File -Force | Out-Null"
            }

            #Set-Content -Value '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072' -Path $profile.AllUsersAllHosts -Force
            Set-Content -Value '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072' -Path $profile -Force
            if ($group -ne 'QUICKVM' -and (Test-Path -Path $profilePs7 -PathType Leaf) -eq $true)
            {
                Set-Content -Value '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072' -Path $profilePs7 -Force
            }
            if (Test-Path -Path 'C:\ProgramData\chocolatey\lib\es\tools\es.exe' -PathType Leaf)
            {
                $invokeEsScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Invoke-ES.ps1'
                $invokeEsScriptFilePath = "C:\onedrive\my\$($invokeEsScriptUrl.Split('/')[-1])"
                (New-Object Net.WebClient).DownloadFile($invokeEsScriptUrl, $invokeEsScriptFilePath)
                #Set-Content -Value 'Set-Alias e C:\onedrive\my\Invoke-ES.ps1' -Path $profile.AllUsersAllHosts -Force
                Set-Content -Value 'Set-Alias e C:\onedrive\my\Invoke-ES.ps1' -Path $profile -Force
                if ($group -ne 'QUICKVM')
                {
                    Set-Content -Value 'Set-Alias e C:\onedrive\my\Invoke-ES.ps1' -Path $profilePs7 -Force
                }
            }
        }
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
            Invoke-ExpressionWithLogging $installWmfScriptFilePath
            # The install WMF script will issue a retart on its own
            exit
        }
        else
        {
            Invoke-ExpressionWithLogging "Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"

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
        #Out-Log "Changing Chocolatey download cache to $packagesPath to save space on OS disk. See also https://docs.chocolatey.org/en-us/guides/usage/change-cache"
        #Invoke-ExpressionWithLogging "choco config set cacheLocation $packagesPath"
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
        Invoke-ExpressionWithLogging "choco install $packageName --limit-output --no-progress --no-color --confirm --log-file=$chocoInstallLogFilePath | Out-Null"
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
            Invoke-ExpressionWithLogging "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"powershell.exe -executionpolicy bypass -file $bootstrapScriptFilePath`" /f"
            Invoke-ExpressionWithLogging 'Restart-Computer -Force'
        }
    }

    # This needs to be before Set-PSRepository, otherwise Set-PSRepository will prompt to install it
    if ($PSEdition -eq 'Desktop')
    {
        Confirm-NugetInstalled
        Invoke-ExpressionWithLogging 'Import-Module -Name Appx -ErrorAction SilentlyContinue'
    }
    else
    {
        Invoke-ExpressionWithLogging 'Import-Module -Name Appx -UseWindowsPowerShell -ErrorAction SilentlyContinue'
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
        Invoke-ExpressionWithLogging "Install-Module -Name PSFramework -Repository PSGallery -Scope AllUsers -Force -ErrorAction SilentlyContinue"
        Invoke-ExpressionWithLogging "Import-Module -Name PSFramework -ErrorAction SilentlyContinue"
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
            Invoke-ExpressionWithLogging "[Environment]::SetEnvironmentVariable('ChocolateyInstall', '$installDir', 'System')"
            New-Item -Path $installDir -ItemType Directory | Out-Null
        }

        Invoke-ExpressionWithLogging "Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
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
    if (($isWS22 -or $isWS19 -or $isWin11 -or $isWin10) -and $group -ne 'QUICKVM')
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
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$windowsTerminalPreviewMsixBundleUri`', `'$windowsTerminalPreviewMsixBundleFilePath`')"
        Invoke-ExpressionWithLogging "Add-AppxPackage -Path $windowsTerminalPreviewMsixBundleFilePath -ErrorAction SilentlyContinue | Out-Null"
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
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$vcLibsUrl`', `'$vcLibsFilePath`')"
        if (Test-Path -Path $vcLibsFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging "Add-AppPackage -Path $vcLibsFilePath | Out-Null"
        }

        $microsoftUiXamlPackageUrl = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.0'
        $microsoftUiXamlPackageFileName = $microsoftUiXamlPackageUrl.Split('/')[-1]
        $microsoftUiXamlPackageFolderPath = "$packagesPath\$microsoftUiXamlPackageFileName"
        $microsoftUiXamlPackageFilePath = "$packagesPath\$microsoftUiXamlPackageFileName.zip"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$microsoftUiXamlPackageUrl`', `'$microsoftUiXamlPackageFilePath`')"
        Invoke-ExpressionWithLogging "Expand-Zip -Path $microsoftUiXamlPackageFilePath -DestinationPath $microsoftUiXamlPackageFolderPath"
        $microsoftUiXamlAppXFilePath = "$microsoftUiXamlPackageFolderPath\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx"
        Invoke-ExpressionWithLogging "Add-AppxPackage -Path $microsoftUiXamlAppXFilePath | Out-Null"

        $wingetReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases'
        $wingetPrerelease = $wingetReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleUrl = ($wingetPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleFileName = $wingetPrereleaseMsixBundleUrl.Split('/')[-1]
        $wingetPrereleaseMsixBundleFilePath = "$packagesPath\$wingetPrereleaseMsixBundleFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$wingetPrereleaseMsixBundleUrl`', `'$wingetPrereleaseMsixBundleFilePath`')"
        $wingetPrereleaseMsixBundleLicenseUrl = ($wingetPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('xml')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleLicenseFileName = $wingetPrereleaseMsixBundleLicenseUrl.Split('/')[-1]
        $wingetPrereleaseMsixBundleLicenseFilePath = "$packagesPath\$wingetPrereleaseMsixBundleLicenseFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$wingetPrereleaseMsixBundleLicenseUrl`', `'$wingetPrereleaseMsixBundleLicenseFilePath`')"
        if ((Test-Path -Path $wingetPrereleaseMsixBundleFilePath -PathType Leaf) -and (Test-Path -Path $wingetPrereleaseMsixBundleLicenseFilePath -PathType Leaf))
        {
            Invoke-ExpressionWithLogging "Add-AppxProvisionedPackage -Online -PackagePath $wingetPrereleaseMsixBundleFilePath -LicensePath $wingetPrereleaseMsixBundleLicenseFilePath | Out-Null"
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
            Invoke-ExpressionWithLogging "Add-AppxProvisionedPackage -Online -PackagePath $wingetreleaseMsixBundleFilePath -LicensePath $wingetreleaseMsixBundleLicenseFilePath | Out-Null"
        }
        #>
    }

    Out-Log "`$group: $group"
    if ($group -ne 'QUICKVM')
    {
        Out-Log "`$group: $group"
        $powershellReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases'
        # Install PS7 release version
        if ($build -ge 9600)
        {
            $powershellRelease = $powershellReleases | Where-Object prerelease -EQ $false | Sort-Object -Property id -Descending | Select-Object -First 1
        }
        else
        {
            # v7.1.7 is the last PS7 version supported on Win7/2008R2/Win8/2012, v7.2+ need WS12R2+ (9600+)
            # https://learn.microsoft.com/en-us/powershell/scripting/install/PowerShell-Support-Lifecycle?view=powershell-7.3#supported-platforms
            # Installing 7.2+ on Win7/2008R2/Win8/2012 - the MSI install succeeds, but running pwsh.exe fails with error:
            # "Unhandled exception. System.TypeInitializationException: The type initializer for 'System.Management.Automation.Tracing.PSEtwLog' threw an exception."
            # https://github.com/PowerShell/PowerShell/issues/18971
            $powershellRelease = $powershellReleases | Where-Object prerelease -EQ $false | Where-Object tag_name -eq 'v7.1.7'
        }
        $powerShellx64MsiUrl = ($powershellRelease.assets | Where-Object {$_.browser_download_url.EndsWith('win-x64.msi')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $powerShellx64MsiFileName = $powerShellx64MsiUrl.Split('/')[-1]
        $powerShellx64MsiFilePath = "$packagesPath\$powerShellx64MsiFileName"
        $powerShellx64MsiLogFilePath = "$logsPath\$($powerShellx64MsiFileName).$(Get-Date -Format yyyyMMddHHmmssff).log"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$powerShellx64MsiUrl`', `'$powerShellx64MsiFilePath`')"
        Invoke-ExpressionWithLogging "msiexec.exe /package $powerShellx64MsiFilePath /quiet /L*v $powerShellx64MsiLogFilePath ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=0 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 | Out-Null"

        if ($group -in 'HV','PC')
        {
            # Install PS7 preview version
            $powershellPrerelease = $powershellReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
            $powerShellPreviewx64MsiUrl = ($powershellPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('win-x64.msi')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
            $powerShellPreviewx64MsiFileName = $powerShellPreviewx64MsiUrl.Split('/')[-1]
            $powerShellPreviewx64MsiFilePath = "$packagesPath\$powerShellPreviewx64MsiFileName"
            $powerShellPreviewx64MsiLogFilePath = "$logsPath\$($powerShellPreviewx64MsiFileName).$(Get-Date -Format yyyyMMddHHmmssff).log"
            Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$powerShellPreviewx64MsiUrl`', `'$powerShellPreviewx64MsiFilePath`')"
            Invoke-ExpressionWithLogging "msiexec.exe /package $powerShellPreviewx64MsiFilePath /quiet /L*v $powerShellPreviewx64MsiLogFilePath ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=0 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 | Out-Null"
        }
    }
    #exit

    $pwshCurrentUserCurrentHostProfilePath = "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    if (Test-Path -Path $pwshCurrentUserCurrentHostProfilePath -PathType Leaf)
    {
        Out-Log "$pwshCurrentUserCurrentHostProfilePath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging "New-Item -Path $pwshCurrentUserCurrentHostProfilePath -Type File -Force | Out-Null"
    }
    $lineLoadingProfileFromOneDrive = '. C:\OneDrive\my\Profile.ps1'
    if (Get-Content -Path $pwshCurrentUserCurrentHostProfilePath | Select-String -SimpleMatch $lineLoadingProfileFromOneDrive)
    {
        Out-Log "Line to load profile from OneDrive ($lineLoadingProfileFromOneDrive) already exists in $pwshCurrentUserCurrentHostProfilePath"
    }
    else
    {
        Out-Log "Adding line to load profile from OneDrive ($lineLoadingProfileFromOneDrive) to $pwshCurrentUserCurrentHostProfilePath"
        Add-Content -Path $pwshCurrentUserCurrentHostProfilePath -Value "`nif (Test-Path -Path C:\OneDrive\my\Profile.ps1 -PathType Leaf) {$lineLoadingProfileFromOneDrive}"
    }

    $computer = Get-CimInstance -Query 'SELECT * FROM Win32_ComputerSystem' -ErrorAction SilentlyContinue
    if ($computer)
    {
        $manufacturer = $computer.Manufacturer
        $systemSkuNumber = $computer.SystemSKUNumber
        if ($manufacturer -match 'LENOVO')
        {
            $isLenovo = $true
        }
        else
        {
            $isLenovo = $false
        }
        if ($systemSkuNumber -match 'ThinkPad')
        {
            $isThinkPad = $true
        }
        else
        {
            $isThinkPad = $false
        }
        $computerString = $computer | Remove-NullProperties | Format-List ($computer | Get-Member -MemberType Property | Sort-Object -Property name).name | Out-String
        $computerString = $computerString.Trim()
        Out-Log $computerString -raw
    }

    $battery = Get-CimInstance -Query 'SELECT Availability,Caption,Description,Name,Status,DeviceID,PowerManagementSupported,BatteryStatus,Chemistry,DesignVoltage,EstimatedChargeRemaining,EstimatedRunTime FROM Win32_Battery' -ErrorAction SilentlyContinue
    if ($battery)
    {
        $isLaptop = $true
        $batteryString = $battery | Remove-NullProperties | Format-List ($battery | Get-Member -MemberType NoteProperty | Sort-Object -Property name).name | Out-String
        $batteryString = $batteryString.Trim()
        Out-Log $batteryString -raw
    }
    else
    {
        $isLaptop = $false
    }
    Out-Log "`$isLaptop:   $isLaptop"
    Out-Log "`$isLenovo:   $isLenovo"
    Out-Log "`$isThinkPad: $isThinkPad"

    if (!$apps)
    {
        $apps = Get-AppList
        if (!$apps)
        {
            Out-Log 'Failed to get app list'
            exit
        }
    }

    if ($group -ne 'All')
    {
        $apps = $apps | Where-Object {$_.Groups -contains $group}
    }

    $adapterCompatibility = Get-CimInstance -Query 'Select AdapterCompatibility From Win32_VideoController' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AdapterCompatibility
    if ($adapterCompatibility -eq 'NVIDIA')
    {
        $nvidiaGpu = $true
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
    $appsToInstallCount = $apps.Count
    $appsToInstall = ($apps.Name | Sort-Object) -join "`n" | Out-String
    Out-Log "$appsToInstallCount apps to be installed:`n"
    Out-Log $appsToInstall -raw
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

            if ($command -match 'geforce')
            {
                # The NVIDIA packages fail slowly if no NVIDIA GPU is present, so don't run that at all if there's no NVIDIA GPU
                if ($command -match 'geforce' -and $nvidiaGpu)
                {
                    $command = "$command | Out-Null"
                    Invoke-ExpressionWithLogging $command
                }
            }
            else
            {
                $command = "$command | Out-Null"
                Invoke-ExpressionWithLogging $command
            }
        }
        elseif ($appName -and !$useChocolatey -and $isWingetInstalled)
        {
            # https://aka.ms/winget-command-install
            # winget log files will be in %temp%\AICLI\*.log unless redirected
            $timestamp = Get-Date -Format yyyyMMddHHmmssff
            $wingetInstallLogFilePath = "$logsPath\winget_install_$($appName)_$($timestamp).log"
            $command = "winget install --id $appName --exact --silent --accept-package-agreements --accept-source-agreements --log $wingetInstallLogFilePath | Out-Null"

            if ($command -match 'vantage')
            {
                # Only install Lenovo Vantage if it's a Lenovo but not a ThinkPad
                if ($command -match 'BartoszCichecki.LenovoLegionToolkit' -and $isLenovo -eq $true -and $isThinkPad -eq $false)
                {
                    $command = "$command | Out-Null"
                    Invoke-ExpressionWithLogging $command
                }
                # Only install Lenovo Commercial Vantage if it's a ThinkPad
                if ($command -match 'Lenovo Commercial Vantage' -and $isThinkPad -eq $true)
                {
                    $command = "$command | Out-Null"
                    Invoke-ExpressionWithLogging $command
                }
            }
            else
            {
                Invoke-ExpressionWithLogging $command
            }
        }
    }

    $wingetListResult = Invoke-ExpressionWithLogging "winget list --id AutoHotkey.AutoHotkey --exact --source winget" -raw
    if ($LASTEXITCODE -eq 0)
    {
    	Out-Log "Winget installed AutoHotkey v1, pinning it to exclude it from 'winget upgrade --all --source winget' else it would be upgraded to V2, and I'm not ready to use V2 exclusively yet"
    	$wingetPinResult = Invoke-ExpressionWithLogging "winget pin add --exact --id AutoHotkey.AutoHotkey"
      	if ($LASTEXITCODE -eq 0)
       	{
           Out-Log "Pinned AutoHotkey.AutoHotkey, 'winget upgrade --all --source winget' will exclude it"
       	}
	else
 	{
  	   Out-Log "Failed to pin AutoHotkey.AutoHotkey, 'winget upgrade --all --source winget' will include it unless pinned"
 	}
    }
    else
    {
    	Out-Log "winget did not install AutoHotkey.AutoHotkey (which is V1), no need to pin it to exclude from 'winget upgrade --all --source winget' since it wasn't installed by winget"
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
        Invoke-ExpressionWithLogging "New-Item -Path $toolsPath -Type Directory -Force | Out-Null"
    }

    Out-Log "Checking if $myPath exists"
    if (Test-Path -Path $myPath -PathType Container)
    {
        Out-Log "$myPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging "New-Item -Path $myPath -Type Directory -Force | Out-Null"
    }

    # https://stackoverflow.com/questions/714877/setting-windows-powershell-environment-variables
    Out-Log "Adding $toolsPath and $myPath to user Path environment variable"
    $newUserPath = "$env:Path;$toolsPath;$myPath"
    Invoke-ExpressionWithLogging "[Environment]::SetEnvironmentVariable('Path', '$newUserPath', 'User')"

    $userPathFromRegistry = (Get-ItemProperty -Path 'HKCU:\Environment' -Name Path).Path
    $separator = "`n$('='*160)`n"
    Out-Log "$separator`$userPathFromRegistry: $userPathFromRegistry$separator"

    Invoke-ExpressionWithLogging "Remove-Item $env:PUBLIC\Desktop\*.lnk -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging "Remove-Item $env:USERPROFILE\Desktop\*.lnk -Force -ErrorAction SilentlyContinue"

    $scriptFileUrls = @(
        # 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Cursor.ps1',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Console.ps1',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Add-ScheduledTasks.ps1'
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Disable-StickyKeys.ps1'
	'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Show-TaskbarIcons.ps1'
    )

    $scriptFileUrls | ForEach-Object {
        $scriptFileUrl = $_
        $scriptFileName = $scriptFileUrl.Split('/')[-1]
        $scriptFilePath = "$scriptsPath\$scriptFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$scriptFileUrl`', `'$scriptFilePath`')"
        if ($scriptFileName -eq 'Show-TaskbarIcons.ps1')
        {
            Invoke-ExpressionWithLogging "& $scriptFilePath -addScheduledTask"
        }
        else
        {
            Invoke-ExpressionWithLogging $scriptFilePath
        }
    }

    $regFileUrls = @(
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/7-zip_auto_extract_downloaded_zip.reg',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/7-zip_double-click_extract_to_folder.reg'
    )

    $regFileUrls | ForEach-Object {
        $regFileUrl = $_
        $regFileName = $regFileUrl.Split('/')[-1]
        $regFilePath = "$regFilesPath\$regFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$regFileUrl`', `'$regFilePath`')"
        if (Test-Path -Path $regFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging "reg import $regFilePath"
        }
    }

    if ($isWS22 -or $isWS19 -or $isWin11 -or $isWin10)
    {
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
                Invoke-ExpressionWithLogging "New-Item -Path $windowsTerminalSettingsFilePath -ItemType File -Force | Out-Null"
            }
            Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$windowsTerminalSettingsUrl`', `'$windowsTerminalSettingsFilePath`')"
        }
    }

    if ($isWin11 -and $group -in 'HV','PC')
    {
        $wsl = Get-AppPackage -Name MicrosoftCorporationII.WindowsSubsystemForLinux -ErrorAction SilentlyContinue
        if ($wsl)
        {
    	    $wslVersion = [version]($wsl.Version)
	        $wslVersionString = $wslVersion.ToString()
	        if ($wslVersion.Major -ge 2)
	        {
		        Out-Log "WSL $wslVersionString already installed"
	        }
            else
	        {
                $installWsl2 = $true
            }
        }
        else
        {
            $installWsl2 = $true
        }

        if ($installWsl2)
        {
                # Still this open bug that results in wsl --install throwing a UAC prompt even though it's called from elevated PS
                # https://github.com/microsoft/WSL/issues/9032
                Invoke-ExpressionWithLogging 'wsl --install'
                # /All enables all parent features of the specified feature
                Invoke-ExpressionWithLogging 'dism /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart'
                Invoke-ExpressionWithLogging 'dism /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V /All /NoRestart'
        }
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
        Invoke-ExpressionWithLogging "New-Item -Path $nppSettingsFolderPath -Type Directory -Force | Out-Null"
    }

    Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$nppSettingsZipUrl`', `'$nppSettingsZipFilePath`')"
    Invoke-ExpressionWithLogging "Expand-Zip -Path $nppSettingsZipFilePath -DestinationPath $nppSettingsTempFolderPath"
    Invoke-ExpressionWithLogging "Copy-Item -Path $nppSettingsTempFolderPath\* -Destination $nppSettingsFolderPath"
    Invoke-ExpressionWithLogging "Copy-Item -Path $nppSettingsTempFolderPath\* -Destination $nppAppDataPath"

    if (Test-Path -Path $nppCloudFolderPath -PathType Container)
    {
        Out-Log "$nppSettingsFolderPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging "New-Item -Path $nppCloudFolderPath -Type Directory -Force | Out-Null"
    }
    Invoke-ExpressionWithLogging "Set-Content -Path $env:APPDATA\Notepad++\cloud\choice -Value $nppSettingsFolderPath -Force"

    # The chocolatey package for Everything includes an old version (1.1.0.9) of the es.exe CLI tool
    # Delete that one, then download the latest (1.1.0.23 ) from the voidtools site
    Invoke-ExpressionWithLogging "Remove-Item -Path $env:ProgramData\chocolatey\bin\es.exe -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging "Remove-Item -Path $env:ProgramData\chocolatey\lib\Everything\tools\es.exe -Force -ErrorAction SilentlyContinue"
    $esZipUrl = 'https://www.voidtools.com/ES-1.1.0.23.zip'
    $esZipFileName = $esZipUrl.Split('/')[-1]
    $esZipFolderPath = "$packagesPath\$($esZipFileName.Replace('.zip',''))"
    $esZipFilePath = "$packagesPath\$esZipFileName"
    Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$esZipUrl`', `'$esZipFilePath`')"
    Invoke-ExpressionWithLogging "Expand-Zip -Path $esZipFilePath -DestinationPath $esZipFolderPath"
    Copy-Item -Path $esZipFolderPath\es.exe -Destination $toolsPath -Force

    $esIniUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/es.ini'
    $esIniFileName = $esIniUrl.Split('/')[-1]
    $esIniFilePath = "$toolsPath\$esIniFileName"
    Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$esIniUrl`', `'$esIniFilePath`')"

    if ($group -eq 'VM')
    {
        if ($os -in 'WIN10','WIN11','WS19','WS22')
        {
            Invoke-ExpressionWithLogging "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
            Invoke-ExpressionWithLogging "Start-Service sshd"
            Invoke-ExpressionWithLogging "Set-Service -Name sshd -StartupType Automatic"
        }
        # This takes ~10 minutes so skip it for $group -eq 'PC', files will be there anyway
        <# Just skipping entirely for now, don't use them much
        $getNirSoftToolsScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Get-NirsoftTools.ps1'
        $getNirSoftToolsScriptFileName = $getNirSoftToolsScriptUrl.Split('/')[-1]
        $getNirSoftToolsScriptFilePath = "$scriptsPath\$getNirSoftToolsScriptFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$getNirSoftToolsScriptUrl`', `'$getNirSoftToolsScriptFilePath`')"
        Invoke-ExpressionWithLogging $getNirSoftToolsScriptFilePath
        #>
    }

    # autohotkey.portable - couldn't find a way to specify a patch for this package
    # (portable? https://www.autohotkey.com/download/ahk.zip)

    # https://www.thenickmay.com/how-to-install-autohotkey-even-without-administrator-access/
    # It works - the .ahk file must be named AutoHotkeyU64.ahk, then you run AutoHotkeyU64.exe
    # copy-item -Path \\tsclient\c\onedrive\ahk\AutoHotkey.ahk -Destination c:\my\ahk\AutoHotkeyU64.ahk

    if ($group -in 'HV','PC','VM')
    {
        $installVSCodeScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-VSCode.ps1'
        $installVSCodeScriptFileName = $installVSCodeScriptUrl.Split('/')[-1]
        $installVSCodeScriptFilePath = "$scriptsPath\$installVSCodeScriptFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$installVSCodeScriptUrl`', `'$installVSCodeScriptFilePath`')"
        Invoke-ExpressionWithLogging $installVSCodeScriptFilePath

        $installVSCodeExtensionsScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-VSCodeExtensions.ps1'
        $installVSCodeExtensionsScriptFileName = $installVSCodeExtensionsScriptUrl.Split('/')[-1]
        $installVSCodeExtensionsScriptFilePath = "$scriptsPath\$installVSCodeExtensionsScriptFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$installVSCodeExtensionsScriptUrl`', `'$installVSCodeExtensionsScriptFilePath`')"
        Invoke-ExpressionWithLogging $installVSCodeExtensionsScriptFilePath
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
        Invoke-ExpressionWithLogging "New-Item -Path $vsCodeSettingsJsonPath -Force | Out-Null"
        Out-Log "Downloading $vsCodeSettingsJsonUrl"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$vsCodeSettingsJsonUrl`', `'$vsCodeSettingsJsonPath`')"

        $vsCodeKeybindingsJsonUrl = "https://raw.githubusercontent.com/craiglandis/bootstrap/main/vscode_keybindings.json"
        $vsCodeKeybindingsJsonPath = "$env:APPDATA\Code\User\keybindings.json"
        Invoke-ExpressionWithLogging "New-Item -Path `"$env:APPDATA\Code\User`" -Force -ErrorAction SilentlyContinue | Out-Null"
        Out-Log "Downloading $vsCodeKeybindingsJsonUrl"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$vsCodeKeybindingsJsonUrl`', `'$vsCodeKeybindingsJsonPath`')"
    }
    else
    {
        Out-Log "VSCode not installed, skipping download of $vsCodeSettingsJsonUrl"
    }

    # Look at running these async since nothing needs to wait for the help to be updated
    Invoke-ExpressionWithLogging 'Update-Help -Force -ErrorAction SilentlyContinue'
    $pwshFilePath = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (Test-Path -Path $pwshFilePath -PathType Leaf)
    {
        Invoke-ExpressionWithLogging "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Set-ExecutionPolicy -ExecutionPolicy Bypass -Force"
        Invoke-ExpressionWithLogging "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Update-Help -Force -ErrorAction SilentlyContinue"
    }

    if ($installModules -eq $true -and ($isPC -or $isVM) -and $group -ne 'QUICKVM')
    {
        # These can't be run at this point, they need to be run after OneDrive is set to sync to C:\OneDrive, which is a step I have yet to find out how to automate
        #Invoke-ExpressionWithLogging "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\od -Target $env:SystemDrive\OneDrive -ErrorAction SilentlyContinue | Out-Null"
        #Invoke-ExpressionWithLogging "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\my -Target $env:SystemDrive\OneDrive\My -ErrorAction SilentlyContinue | Out-Null"
        #Invoke-ExpressionWithLogging "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\bin -Target $env:SystemDrive\OneDrive\Tools -ErrorAction SilentlyContinue | Out-Null"

        # To remove the symbolic links (Remove-Item won't do it):
        #(Get-Item -Path "$env:SystemDrive\od").Delete()
        #(Get-Item -Path "$env:SystemDrive\my").Delete()
        #(Get-Item -Path "$env:SystemDrive\bin").Delete()

        $installModulesFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-Modules.ps1'
        $installModulesFileName = $installModulesFileUrl.Split('/')[-1]
        $installModulesFilePath = "$scriptsPath\$installModulesFileName"
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$installModulesFileUrl`', `'$installModulesFilePath`')"

        if (Test-Path -Path $installModulesFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging 'powershell -nologo -noprofile -Command [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force'
            Invoke-ExpressionWithLogging 'powershell -nologo -noprofile -Command [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force -AllowPrerelease'
            Invoke-ExpressionWithLogging "powershell -nologo -noprofile -File $installModulesFilePath"

            if (Test-Path -Path $pwshFilePath -PathType Leaf)
            {
                Invoke-ExpressionWithLogging "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force"
                Invoke-ExpressionWithLogging "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force -AllowPrerelease"
                Invoke-ExpressionWithLogging "& `'$pwshFilePath`' -NoProfile -NoLogo -File $installModulesFilePath"
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
        Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$greenshotInstallerUrl`', `'$greenshotInstallerFilePath`')"
        # Was hanging script in the past, can't repro anymore. With /VERYSILENT it still opens browser to donate page but I can't repro that blocking script execution
        Invoke-ExpressionWithLogging "$greenshotInstallerFilePath /VERYSILENT /NORESTART | Out-Null"
    }

    if ($isPC)
    {
        $caption = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption
        if ($caption -eq 'Microsoft Windows 11 Enterprise')
        {
            Invoke-ExpressionWithLogging 'c:\windows\system32\cscript.exe //H:cscript'
            Invoke-ExpressionWithLogging 'cscript //NoLogo c:\windows\system32\slmgr.vbs /skms AZUSW2SLS-KMS01.redmond.corp.microsoft.com'
            # https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys
            Invoke-ExpressionWithLogging 'cscript //NoLogo c:\windows\system32\slmgr.vbs /ipk NPPR9-FWDCX-D2C8J-H872K-2YT43'
            # Skip since they only work if on VPN
            # Invoke-ExpressionWithLogging 'cscript //NoLogo c:\windows\system32\slmgr.vbs /ato'
            # Invoke-ExpressionWithLogging 'cscript //NoLogo c:\windows\system32\slmgr.vbs /dlv'
        }
    }

    if ($isPC -or $isVM)
    {
        Out-Log 'Checking if bootstrap task exists'
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
            $tasks = $rootFolder.GetTasks(1) | Select-Object Name, Path, State
            $bootstrapTask = $tasks | Where-Object {$_.Name -eq $taskName}
            if ($bootstrapTask)
            {
                Out-Log 'Failed to delete bootstrap scheduled task'
            }
        }
        else
        {
            Out-Log "Didn't find bootstrap scheduled task"
        }
    }

    if ($isVM)
    {
        # Set file type associations (FTAs) with SetUserFTA, which works around how Win8+ protects certain FTAs from being configure the old way in the registry
        # https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/
        # HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\<extension>\OpenWithList
        # Browser
        Invoke-ExpressionWithLogging 'SetUserFTA http MSEdgeHTM'
        Invoke-ExpressionWithLogging 'SetUserFTA https MSEdgeHTM'
        Invoke-ExpressionWithLogging 'SetUserFTA microsoft-edge MSEdgeHTM'
        Invoke-ExpressionWithLogging 'SetUserFTA .htm MSEdgeHTM'
        Invoke-ExpressionWithLogging 'SetUserFTA .html MSEdgeHTM'
        Invoke-ExpressionWithLogging 'SetUserFTA .pdf MSEdgeHTM'
        # Logs/config
        Invoke-ExpressionWithLogging 'SetUserFTA .bas Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .cfg Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .conf Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .config Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .csv Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .inf Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .ini Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .json Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .log Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .rdp Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .reg Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .settings Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .status Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .txt Applications\notepad++.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .xml Applications\notepad++.exe'
        # Code
        Invoke-ExpressionWithLogging 'SetUserFTA .bat Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .cmd Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .ps1 Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .ps1xml Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .psd1 Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .psm1 Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .py Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .sh Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .vbs Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .wsf Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .xaml Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .xls Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .xlsm Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .xsl Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .xslt Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .yaml Applications\code.exe'
        Invoke-ExpressionWithLogging 'SetUserFTA .yml Applications\code.exe'

        if ($group -eq 'VM')
        {
	<#  This URL is no longer valid and I can't find a new equivalent
            $zimmermanToolsZipUrl = 'https://f001.backblazeb2.com/file/EricZimmermanTools/net6/All_6.zip'
            $zimmermanToolsZipFileName = $zimmermanToolsZipUrl.Split('/')[-1]
            $zimmermanToolsZipFilePath = "$packagesPath\$zimmermanToolsZipFileName"
            $zimmermanToolsZipFolderPath = $zimmermanToolsZipFilePath.Replace('.zip', '')
            Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$zimmermanToolsZipUrl`', `'$zimmermanToolsZipFilePath`')"
            Invoke-ExpressionWithLogging "Expand-Zip -Path $zimmermanToolsZipFilePath -DestinationPath $zimmermanToolsZipFolderPath"
            Get-ChildItem -Path $zimmermanToolsZipFolderPath | ForEach-Object {Expand-Zip -Path $_.FullName -DestinationPath $toolsPath}
	#>
            $tssUrl = 'https://aka.ms/getTSSv2'
            $tssFolderPath = "$toolsPath\TSSv2"
            $tssFilePath = "$packagesPath\TSSv2.zip"
            Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$tssUrl`', `'$tssFilePath`')"
            Invoke-ExpressionWithLogging "Expand-Zip -Path $tssFilePath -DestinationPath $tssFolderPath"
        }
    }

    Invoke-ExpressionWithLogging "Remove-Item -Path $env:USERPROFILE\Desktop\desktop.ini -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging "Remove-Item -Path $env:PUBLIC\Desktop\desktop.ini -Force -ErrorAction SilentlyContinue"

    Invoke-ExpressionWithLogging "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Discord' -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'BCClipboard' -Force -ErrorAction SilentlyContinue"

    Invoke-ExpressionWithLogging 'powercfg /hibernate off'
    Invoke-ExpressionWithLogging 'powercfg /change /standby-timeout-ac 300'

    if ($isPC)
    {
        $packageProviderName = 'NuGet'
        $packageSourceName = 'nuget.org'
        $packageSourceLocation = 'https://www.nuget.org/api/v2'
        $packageName = 'Microsoft.Azure.Kusto.Tools'

        Invoke-ExpressionWithLogging "Register-PackageSource -Name $packageSourceName -ProviderName $packageProviderName -Location $packageSourceLocation"
        Invoke-ExpressionWithLogging "Install-PackageProvider -Name $packageProviderName -Force"
        Invoke-ExpressionWithLogging "Install-Package $packageName -Force"

        $removeTempOnedriveAndMyFoldersScriptContents = @'
Stop-Process -Name caffeine64 -Force -ErrorAction SilentlyContinue
Remove-Item -Path c:\my -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path c:\od -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path c:\bin -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path C:\OneDrive -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path C:\OneDrive -ItemType Directory -Force -ErrorAction SilentlyContinue
'@
        $removeTempOnedriveAndMyFoldersScriptContents | Out-File -FilePath "$env:USERPROFILE\Desktop\Remove-TempOnedriveAndMyFolders.ps1"

        # The non-elevated one starts successfully but isn't actually running?
        $setAutoHotKeyScheduledTasksScriptContents = @'
$userId = 'clandis@microsoft.com'

Stop-Process -Name AutoHotkey -Force -ErrorAction SilentlyContinue

if ((Test-path -Path 'C:\Program Files\AutoHotkey\AutoHotkey.exe' -PathType Leaf) -and (Test-path -Path 'C:\OneDrive\My\Autohotkey.ahk' -PathType Leaf) -and (Test-path -Path 'C:\OneDrive\My\AutoHotkey_Not_Elevated.ahk' -PathType Leaf))
{
    $autoHotKeyTaskName = 'AutoHotkey'
    $autoHotKeyTask = Get-ScheduledTask -TaskName $autoHotKeyTaskName
    $autoHotKeyTaskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' -Argument '/c Start "C:\Program Files\AutoHotkey\AutoHotkey.exe" C:\OneDrive\My\Autohotkey.ahk'
    $autoHotKeyTaskPrincipal = New-ScheduledTaskPrincipal -UserId $userId -RunLevel Highest -LogonType Interactive
    $autoHotKeyTaskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    Set-ScheduledTask -TaskName $autoHotKeyTaskName -Action $autoHotKeyTaskAction -Principal $autoHotKeyTaskPrincipal -Trigger $autoHotKeyTaskTrigger | select Actions -ExpandProperty Actions | select Execute,Arguments
    Start-ScheduledTask -TaskName $autoHotKeyTaskName

    $autoHotKeyNotElevatedTaskName = 'AutoHotkey_Not_Elevated'
    $autoHotKeyNotElevatedTask = Get-ScheduledTask -TaskName $autoHotKeyNotElevatedTaskName
    $autoHotKeyNotElevatedTaskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' -Argument '/c Start "C:\Program Files\AutoHotkey\AutoHotkey.exe" C:\OneDrive\My\AutoHotkey_Not_Elevated.ahk'
    $autoHotKeyNotElevatedTaskPrincipal = New-ScheduledTaskPrincipal -UserId $userId -RunLevel Limited -LogonType Interactive
    $autoHotKeyNotElevatedTaskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    Set-ScheduledTask -TaskName $autoHotKeyNotElevatedTaskName -Action $autoHotKeyNotElevatedTaskAction -Principal $autoHotKeyNotElevatedTaskPrincipal -Trigger $autoHotKeyNotElevatedTaskTrigger | select Actions -ExpandProperty Actions | select Execute,Arguments
    Start-ScheduledTask -TaskName $autoHotKeyNotElevatedTaskName
}
else
{
    Write-Host 'One or more of the following files was not found: C:\Program Files\AutoHotkey\AutoHotkey.exe, C:\OneDrive\My\Autohotkey.ahk, C:\OneDrive\My\AutoHotkey_Not_Elevated.ahk'
}
'@
        $setAutoHotKeyScheduledTasksScriptContents | Out-File -FilePath "$env:USERPROFILE\Desktop\Set-AutoHotKeyScheduledTasks.ps1"

        <# Couldn't actually get this to work, still had to right-click the folder and set it
$setAlwaysKeepOnThisDeviceScriptContents = @'
attrib "C:\OneDrive\My" -U +P /s
attrib "C:\OneDrive\npp" -U +P /s
attrib "C:\OneDrive\PDF" -U +P /s
attrib "C:\OneDrive\Screens" -U +P /s
attrib "C:\OneDrive\Tools" -U +P /s
'@
    $setAlwaysKeepOnThisDeviceScriptContents | Out-File -FilePath "$env:USERPROFILE\Desktop\Set-AlwaysKeepOnThisDevice.ps1"
    #>

        $registerWatchFilesScheduledTaskScriptContents = @'
if ((Test-path -Path 'C:\OneDrive\My\Watch-Files.ps1' -PathType Leaf) -and (Test-path -Path 'C:\OneDrive\My\Watch-Files.vbs' -PathType Leaf) -and (Test-path -Path 'C:\OneDrive\My\Watch-Files.xml' -PathType Leaf))
{
    Write-Host "Registering Watch-Files scheduled task"
    Register-ScheduledTask -Xml (Get-Content -Path C:\OneDrive\My\Watch-Files.xml | Out-String) -TaskName Watch-RDPFiles -TaskPath '\' -User 'clandis@microsoft.com' -Force # -Password $password -Force
    Start-ScheduledTask -TaskPath '\' -TaskName 'Watch-RDPFiles'
}
else
{
    Write-Host 'One or more of the following files was not found: C:\OneDrive\My\Watch-Files.ps1, C:\OneDrive\My\Watch-Files.vbs, C:\OneDrive\My\Watch-Files.xml'
}
'@
        $registerWatchFilesScheduledTaskScriptContents | Out-File -FilePath "$env:USERPROFILE\Desktop\Register-WatchFilesScheduledTask.ps1"

        <# Double-check this
    Out-Log "Disabling Windows startup sound"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableStartupSound' -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation' -Name 'DisableStartupSound' -Value 1

    Out-Log "Disabling Windows system sounds"
    Get-ChildItem -Path 'HKCU:\AppEvents\Schemes\Apps' | Get-ChildItem | Get-ChildItem | Where-Object {$_.PSChildName -eq '.Current'} | Set-ItemProperty -Name '(Default)' -Value ''
    #>

    }

    Out-Log "Disabling Beyond Compare BCClipboard from running on Windows startup"
    Remove-ItemProperty -Path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'BCClipboard' -ErrorAction SilentlyContinue

    # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies#searchinsidebarenabled
    Out-Log "Disabling search in sidebar which is supposed to disable 'Search Bing in sidebar' in the context menu"
    Invoke-ExpressionWithLogging "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SearchInSidebarEnabled' -Type DWord -Value 2 -ErrorAction SilentlyContinue"

    Out-Log "Deleting 'Send to OneNote' shortcut from Startup folder"
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -ErrorAction SilentlyContinue

    Out-Log 'Deleting Discord from Run keys, even though it seems to still startup automatically without them?'
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Discord' -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' -Name 'Discord' -ErrorAction SilentlyContinue

    Out-Log 'Enabling remote desktop'
    $win32TerminalServiceSettings = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TerminalServiceSetting
    $win32TerminalServiceSettings | Invoke-CimMethod -MethodName SetAllowTSConnections -Arguments @{AllowTSConnections = 1; ModifyFirewallException = 1}

    $pythonExePath = Get-ChildItem -Path 'C:\Python*\python.exe' -File -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -Last 1 | Select-Object -ExpandProperty FullName
    if ($pythonExePath)
    {
        Out-Log 'Upgrading pip'
        Invoke-ExpressionWithLogging "$pythonExePath -m pip install --upgrade pip"
    }

    $activePowerPlan = Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan -Filter "IsActive = $true"
    Out-Log "Active power plan: $($activePowerPlan.ElementName) $($activePowerPlan.InstanceID.Replace('Microsoft:PowerPlan\',''))"
    $ultimatePerformancePowerPlan = Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'Ultimate Performance'"
    Out-Log "Setting active power plan to $($ultimatePerformancePowerPlan.ElementName) $($ultimatePerformancePowerPlan.InstanceID.Replace('Microsoft:PowerPlan\',''))"
    $activateResult = Invoke-CimMethod -InputObject $ultimatePerformancePowerPlan -MethodName Activate
    $activePowerPlan = Get-CimInstance -Name root\cimv2\power -Class Win32_PowerPlan -Filter "IsActive = $true"
    Out-Log "Active power plan: $($activePowerPlan.ElementName) $($activePowerPlan.InstanceID.Replace('Microsoft:PowerPlan\',''))"

    $desiredMaximumSizeInBytes = 100MB
    'Application','System','Security' | ForEach-Object {
        $logName = $_
        $eventLog = Get-WinEvent -ListLog $logName
        $currentMaximumSizeInBytes = $eventLog.MaximumSizeInBytes
        $currentMaximumSizeInMB = [Math]::Round($currentMaximumSizeInBytes/1MB,0)
        if ($currentMaximumSizeInBytes -ne $desiredMaximumSizeInBytes)
        {
            $eventLog.MaximumSizeInBytes = $desiredMaximumSizeInBytes
            $eventLog.SaveChanges()
            $eventLog = Get-WinEvent -ListLog $logName
            $newMaximumSizeInBytes = $eventLog.MaximumSizeInBytes
            $newMaximumSizeInMB = [Math]::Round($newMaximumSizeInBytes/1MB,0)
            Out-Log "Changed $_ log size from $($currentMaximumSizeInMB)MB to $($newMaximumSizeInMB)MB"
        }
    }

    <#
    # Urban legend is that if Windows is installed on an SSD, disabling prefetch and superfetch can actually improve performance
    # Prefetch/Superfetch definitely help if the OS is on an HDD, but it's unclear if leaving them enabled if the OS is on an SSD actually makes any difference
    Out-Log 'Disabling prefetch'
    Invoke-ExpressionWithLogging "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher' -Type DWord -Value 0 -Force | Out-Null"
    Out-Log 'Disabling superfetch'
    Invoke-ExpressionWithLogging "Stop-Service -Name SysMain -Force"
    Invoke-ExpressionWithLogging "Set-Service -Name SysMain -StartupType Disabled -Force"
    #>

    <#
    $steamSetupUrl = 'https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe'
    $steamSetupFileName = $steamSetupUrl.Split('/')[-1]
    $steamSetupFilePath = "$packagesPath\$steamSetupFileName"
    $steamSetupFolderPath = $steamSetupFilePath.Replace('.exe', '')
    Invoke-ExpressionWithLogging "(New-Object Net.WebClient).DownloadFile(`'$steamSetupUrl`', `'$steamSetupFilePath`')"
    Invoke-ExpressionWithLogging "$steamSetupFilePath /s"
    #>

    <#
    Out-Log "Creating desktop shortcut for running 'choco upgrade all -y'"
    $objShell = New-Object -ComObject Wscript.Shell
    $shortcutPath = "$env:userprofile\Desktop\choco_upgrade_all.lnk"
    $shortCut = $objShell.CreateShortCut($shortcutPath)
    $shortCut.Description = 'choco upgrade all -y'
    $shortCut.TargetPath = '%ProgramFiles%\PowerShell\7\pwsh.exe'
    $shortCut.Arguments = '-NoLogo -NoProfile -NoExit -Command choco upgrade all -y'
    $shortCut.WindowStyle = 3 # 1 = Normal, 3 = Maximized, 7 = Minimized
    $shortCut.Save()
    $bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes($shortcutPath, $bytes)
    #>

    Invoke-ExpressionWithLogging "Remove-Item -Path '$env:ProgramFiles\AutoHotkey\Compiler' -Recurse -Force -ErrorAction SilentlyContinue"

    if ($isPC)
    {
        Out-Log 'Running Invoke-GetWindowsUpdate'
        Invoke-GetWindowsUpdate
        Out-Log 'Done running Invoke-GetWindowsUpdate'
    }

    Complete-ScriptExecution
}
