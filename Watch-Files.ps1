[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$restart
)

<#
function Out-Toast
{
    param(
        [string]$firstLine,
        [string]$secondLine
    )
    $builder = New-BTContentBuilder
    $builder | Add-BTText -Text $firstLine, $secondLine
    Show-BTNotification -ContentBuilder $builder
}
#>

<#
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
    elseif ($prefix -eq 'timespan' -and $startTime)
    {
        $timespan = New-TimeSpan -Start $startTime -End (Get-Date)
        $prefixString = '[{0:mm}:{0:ss}.{0:ff}]' -f $timespan
    }
    elseif ($prefix -eq 'both' -and $startTime)
    {
        $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
        $timespan = New-TimeSpan -Start $startTime -End (Get-Date)
        $prefixString = "$($timestamp) $('[{0:mm}:{0:ss}]' -f $timespan)"
    }
    else
    {
        $prefixString = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
    }
    Write-Host $prefixString -NoNewline -ForegroundColor Cyan
    Write-Host " $text"
    $logFilePath = "$scriptPath\$scriptBaseName.log"
    if ((Test-Path -Path $logFilePath -PathType Leaf) -eq $false)
    {
        New-Item -Path $logFilePath -ItemType File -Force | Out-Null
    }
    "$prefixString $text" | Out-File $logFilePath -Append
}
#>

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
    if (!$raw)
    {
        Write-Host $prefixString -NoNewline -ForegroundColor Cyan
        Write-Host " $text"
    }
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
        Out-Log "Failed: $command"
        Out-Log "`$LASTEXITCODE: $LASTEXITCODE"
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

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptFolderPath = Split-Path -Path $scriptFullName
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$logFolderPath = "C:\logs\$scriptBaseName"
$logFilePath = "$logFolderPath\$($scriptBaseName)_$(Get-Date -Format yyyyMMddhhmmss).log"
if ((Test-Path -Path "C:\logs\$scriptBaseName" -PathType Container) -eq $false)
{
    $logFolder = New-Item -Path $logFolderPath -ItemType Directory -Force
}
Out-Log "Log file: $logFilePath"

$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

Out-Log "Script started"

# Watch-Files.ps1 -restart
if ($restart)
{
    Invoke-ExpressionWithLogging "Get-Process pwsh -ea si | where CommandLine -match 'Export-Events.ps1' | Stop-Process -Force -ea si"
    Invoke-ExpressionWithLogging "Get-Process pwsh -ea si | where CommandLine -match 'flatten.ps1' | Stop-Process -Force -ea si"
    Invoke-ExpressionWithLogging "Get-Process pwsh -ea si | where CommandLine -match 'Update-RDPFile.ps1' | Stop-Process -Force -ea si"
    Invoke-ExpressionWithLogging "Get-Process pwsh -ea si | where CommandLine -match 'Watch-Files.ps1' | Stop-Process -Force -ea si"
    Invoke-ExpressionWithLogging "Get-Process powershell -ea si| where CommandLine -match 'WinGuestAnalyzer.ps1' | Stop-Process -Force -ea si"
    Invoke-ExpressionWithLogging "Get-ScheduledTask -TaskName Watch-Files | Start-ScheduledTask"
    exit
}
# specify the path to the folder you want to monitor:
$path = "$env:USERPROFILE\Downloads"

# specify which files you want to monitor
# https://docs.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher.filter
# Only supports a single filter
#$FileFilter = '*.rdp'
$FileFilter = '' # this has it watch for *.* in the specified path

# specify whether you want to monitor subfolders as well:
$IncludeSubfolders = $false

# specify the file or folder properties you want to monitor:
$AttributeFilter = [IO.NotifyFilters]::FileName, [IO.NotifyFilters]::LastWrite

# specify the type of changes you want to monitor:
$ChangeTypes = [System.IO.WatcherChangeTypes]::Created, [System.IO.WatcherChangeTypes]::Renamed

# specify the maximum time (in milliseconds) you want to wait for changes:
$Timeout = 1000

# define a function that gets called for every change:
function Invoke-SomeAction
{
    param
    (
        [Parameter(Mandatory)]
        [System.IO.WaitForChangedResult]
        $ChangeInformation
    )

    $changeType = $ChangeInformation.ChangeType
    $name = $ChangeInformation.Name
    $oldName = $ChangeInformation.OldName
    $timedOut = $ChangeInformation.OldName
    Out-Log "ChangeType: $changeType Name: $name OldName: $oldName TimedOut: $timedOut"

    $filePath = "$path\$name"

    if ($filePath.EndsWith('.rdp'))
    {
        Out-Log "Detected new RDP file: '$filePath'"
        # Out-Toast -firstLine "Detected new RDP file:" -secondLine $filePath
        $mstscCount = (Get-Process -Name mstsc -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($mstscCount -le 10)
        {
            Invoke-ExpressionWithLogging -command "Update-RDPFile.ps1 -path '$filePath'"
            # Update-RDPFile.ps1 -path $filePath
        }
    }
    #elseif ($filePath.EndsWith('.zip'))
    #elseif ($filePath -match '.*GuestVMLogs.*.zip' -or $filePath -match '.*InspectIaaSDisk.*.zip')
    elseif ($filePath.EndsWith('.zip'))
    {
        Out-Log "Detected new zip file: '$filePath'"
        $folderPath = $filepath.TrimEnd('.zip')
        #Out-Log "Detected new guest logs zip file: '$filePath'"
        # Out-Toast -firstLine "Detected new guest logs zip file:" -secondLine $filePath
        # I have msedge configured to automatically extract downloaded zip files, so loop up to 30 seconds waiting for that to finish
        # If it still isn't extracted after 30 seconds, handle the extraction here
        $loopStartTime = Get-Date
        $secondsInLoop = 0
        $loopTimeout = 30
        Out-Log "Waiting up to $loopTimeout sec for msedge to extract the zip"
        do {
            Start-Sleep -Seconds 1
            $secondsInLoop++
        } until ((Test-Path -Path $folderPath -PathType Container) -or $secondsInLoop -ge $loopTimeout)
        $loopEndTime = Get-Date
        if ($secondsInLoop -ge $loopTimeout)
        {
            Out-Log "Exited loop because $loopTimeout sec timeout was reached"
        }
        else
        {
            $loopDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $loopStartTime -End $loopEndTime)
            Out-Log "Loop duration: $loopDuration"
        }

        if (Test-Path -Path $folderPath -PathType Container)
        {
            Out-Log "Don't need to extract, '$folderPath' already exists"
        }
        else
        {
            Invoke-ExpressionWithLogging -command "Expand-Zip -Path '$filePath' -DestinationPath '$folderPath'"
        }

        # The .zip from hostgaplugin has a nested GALogs.zip with everything in it, so if there's a GALogs.zip in the extracted folder, extract that too
        $gaLogsZipFile = Get-ChildItem -Path $folderPath\GALogs.zip -Recurse
        #if ($filePath -match '.*GuestVMLogs.*.zip')
        if ($gaLogsZipFile)
        {
            $gaLogsZipFilePath = $gaLogsZipFile.FullName
            Invoke-ExpressionWithLogging -command "Expand-Zip -Path '$gaLogsZipFilePath' -DestinationPath '$folderPath'"
            Invoke-ExpressionWithLogging -command "Remove-Item -Path '$folderPath\Logs' -Recurse -Force"
        }
        #Invoke-ExpressionWithLogging -command "flatten.ps1 -Path '$folderPath'"

        # Run WGA, Export-Events, etc. if there are any EVTX files within the extracted folder
        $evtxFiles = Get-ChildItem -Path $folderPath -Filter *.evtx -Recurse
        if ($evtxFiles)
        {
            $date = Get-Date
            $culture = Get-Culture
            $dayOfWeek = $culture.DateTimeFormat.GetAbbreviatedDayName($date.DayOfWeek)
            $month = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($date.Month)
            $day = $date.Day
            $time = Get-Date -Date $date -Format HHmmss
            $timestamp = "$($dayOfWeek)_$($month)_$($day)_$($time)"
            $outputFilePath = "$folderPath\events_$($timestamp).xlsx"
            Out-Log "`$outputFilePath: $outputFilePath"

            #$folderPath = "$($folderPath)_Flattened"
            $startUtcTime = Get-Date -Date (Get-Date).AddDays(-7).ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ
            $endUtcTime = Get-Date -Date (Get-Date).ToUniversalTime() -Format yyyy-MM-ddTHH:mm:ssZ

            #Invoke-ExpressionWithLogging -command "Get-Insights.ps1 -Path '$folderPath' -StartUtcTime $startUtcTime -EndUtcTime $endUtcTime"

            Invoke-ExpressionWithLogging -command "Invoke-WGA.ps1 -logsPath '$folderPath' -outputPath '$folderPath' -startUtcTime $startUtcTime -endUtcTime $endUtcTime"
            #Invoke-ExpressionWithLogging -command "powershell -nologo -noprofile -command C:\OneDrive\My\WinGuestAnalyzer\WinGuestAnalyzer.ps1 -AutoRun -Verbose -WinEventsPath '$folderPath' -OutputPath '$folderPath' -StartUtcTime $startUtcTime -EndUtcTime $endUtcTime"
            Invoke-ExpressionWithLogging -command "Invoke-Item -Path '$folderPath' -ErrorAction SilentlyContinue"
            Invoke-ExpressionWithLogging -command "Invoke-Item -Path (Get-ChildItem -Path '$folderPath\WinGuestAnalyzer*\report.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -First 1 -ExpandProperty FullName) -ErrorAction SilentlyContinue"
            Invoke-ExpressionWithLogging -command "Export-Events.ps1 -evtxFolderPath '$folderPath' -outputFilePath '$outputFilePath' -show"
        }
    }
}
# use a try...finally construct to release the
# filesystemwatcher once the loop is aborted
# by pressing CTRL+C

try
{
    Write-Warning "FileSystemWatcher is monitoring $path"

    # create a filesystemwatcher object
    $watcher = New-Object -TypeName IO.FileSystemWatcher -ArgumentList $path, $FileFilter -Property @{
        IncludeSubdirectories = $IncludeSubfolders
        NotifyFilter          = $AttributeFilter
    }

    # start monitoring manually in a loop:
    do
    {
        # wait for changes for the specified timeout
        # IMPORTANT: while the watcher is active, PowerShell cannot be stopped
        # so it is recommended to use a timeout of 1000ms and repeat the
        # monitoring in a loop. This way, you have the chance to abort the
        # script every second.
        $result = $watcher.WaitForChanged($ChangeTypes, $Timeout)
        # if there was a timeout, continue monitoring:
        if ($result.TimedOut)
        {
            continue
        }
        $global:result = $result
        Invoke-SomeAction -Change $result
        # the loop runs forever until you hit CTRL+C
    } while ($true)
}
finally
{
    # release the watcher and free its memory:
    $watcher.Dispose()
    Write-Warning 'FileSystemWatcher removed.'
}