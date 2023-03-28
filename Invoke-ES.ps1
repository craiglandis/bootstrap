<#
.SYNOPSIS
    Runs voidtools Everything ES.EXE command-line tool and returns the results as PowerShell objects.
.NOTES
    Requirements:

    voidtools Everything must be installed and running - https://www.voidtools.com/ -

    To install Everything with Chocolatey:

    choco everything es -y

    ES.EXE command-line interface for Everything must be in your PATH.

    To install ES.EXE with Chocolatey:

    choco install es -y

    Depending on when the Everything and ES chocolatey packages were updated, one of them may have a newer version of ES.EXE:

    C:\ProgramData\chocolatey\lib\Everything\tools\es.exe - "choco install everything -y" default location for ES.EXE
    C:\ProgramData\chocolatey\lib\es\tools\es.exe - "choco install es -y" default location for ES.EXE

    To see which is newer:

    Get-ChildItem -Path C:\ProgramData\chocolatey -Include es.exe -Recurse | Sort-Object -Property CreationTime -Descending | Format-Table -Property CreationTime,FullName -AutoSize

.EXAMPLE
    Invoke-ES.ps1 *.bak
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string]$searchString,
    [string]$esPath = 'C:\ProgramData\chocolatey\lib\es\tools\es.exe',
    # Windows Terminal historySize max is SHORT_MAX (32767), so setting default slightly below that
    [int]$maxResults = 32750,
    [ValidateSet('Date-Created', 'Date-Modified', 'Size', 'Name','Path','Extension')]
    [string]$sortProperty = 'Date-Modified',
    [ValidateSet('Ascending', 'Descending')]
    [string]$sortDirection = 'Descending',
    [switch]$paging,
    [switch]$passThru,
    [switch]$resultCount,
    [switch]$totalSize,
    [switch]$version
)

function Format-Size
{
    param($size)

    $kb = [Math]::Round($size/1KB,2)
    $mb = [Math]::Round($size/1MB,2)
    $gb = [Math]::Round($size/1GB,2)
    $tb = [Math]::Round($size/1TB,2)
    $pb = [Math]::Round($size/1PB,2)

    if ($pb -ge 1) {"$($pb)PB"}
    elseif ($tb -ge 1) {"$($tb)TB"}
    elseif ($gb -ge 1) {"$($gb)GB"}
    elseif ($mb -ge 1) {"$($mb)MB"}
    elseif ($kb -ge 1) {"$($kb)KB"}
    elseif ($kb -lt 1) {"$($size)B"}
}

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
}

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )

    Write-Verbose $command

    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        Write-Verbose -Message "Failed: $command"
        Write-Verbose "`$LASTEXITCODE: $LASTEXITCODE"
    }
}

function Get-Version
{
    $esVersion = Invoke-ExpressionWithLogging -command "$esPath -version"
    $everythingVersion = Invoke-ExpressionWithLogging -command "$esPath -get-everything-version"
    Write-Verbose "ES: $esVersion Everything: $everythingVersion"
}

$scriptStartTime = Get-Date

if ($version)
{
    Get-Version
    exit
}

$brightBlack = 90
$brightRed = 91
$brightGreen = 92
$brightYellow = 93
$brightMagenta = 95
$brightCyan = 96
$brightWhite = 97

$clearSettingsCommand = "$esPath -clear-settings"
$clearSettingsResult = Invoke-ExpressionWithLogging -command $clearSettingsCommand
Write-Verbose $clearSettingsResult

$timestamp = Get-Date -Format yyyyMMddHHmmss
$csvPath = "$env:TEMP\es-$timestamp.csv"
Write-Verbose "CSV path: $csvPath"

$searchCommand = "$esPath `'$searchString`' -w -date-created -date-modified -date-accessed -size -attributes -full-path-and-name -date-format 1 -no-digit-grouping -size-format 0 -max-results $maxResults -export-csv $csvPath -sort-$($sortProperty.ToLower())-$($sortDirection.ToLower())"
if ($resultCount)
{
    $searchCommand = [System.String]::Concat($searchCommand, " -get-result-count")
}
$result = Invoke-ExpressionWithLogging -Command $searchCommand -ErrorAction Stop
$files = Invoke-ExpressionWithLogging -Command "Import-Csv -Path $csvPath"

if ($files)
{
    $lastWriteTime = @{Label = 'LastWriteTime'; Expression = {"`e[1;$($brightYellow)m$($_.'Date Modified')`e[0m"}}
    $created = @{Label = 'Created'; Expression = {"`e[1;$($brightWhite)m$($_.'Date Created')`e[0m"}}
    $size = @{Label = 'Size'; Expression = {"`e[1;$($brightGreen)m$($_.Size)`e[0m"}}
    $attributes = @{Label = 'Attributes'; Expression = {"`e[1;$($brightBlack)m$($_.Attributes)`e[0m"}}
    $fileName = @{Label = 'FullName'; Expression = {"`e[1;$($brightCyan)m$($_.FileName)`e[0m"}}

    if ($passThru)
    {
        return $files
    }
    else
    {
        if ($paging)
        {
            $files | Format-Table -Property $created, $lastWriteTime, $size, $attributes, $fileName -AutoSize | Out-Host -Paging
        }
        else
        {
            $files | Format-Table -Property $created, $lastWriteTime, $size, $attributes, $fileName -AutoSize
        }

        Write-Verbose "CSV path: $csvPath"
    }
}
else
{
    Write-Host "No results found for $searchString" -ForegroundColor Cyan
    exit 2
}

if (!$passThru)
{
    Get-Version
    Write-Verbose "Clear settings command run: $clearSettingsCommand"
    Write-Verbose "Search command run: $searchCommand"

    $scriptDuration = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
    $scriptDurationTotalSeconds = [Math]::Round($scriptDuration.TotalSeconds,2)
    Write-Output "$($scriptDurationTotalSeconds)s"
}