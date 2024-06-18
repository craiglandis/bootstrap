<# CmdletBinding allows -verbose/-debug to work so -verbose will make Write-Verbose Run, and -debug will make Write-Debug run

   But you want to do more than Write-Verbose when -Verbose is used, check if $PSBoundParameters['verbose'] is $true
   Unlike custom params, common params like -Verbose -Debug, etc. don't set a variable in their name, so no $Verbose to check for.

   SupportsShouldProcess = $true adds support for -Confirm and -WhatIf switches, which is used with $PSCmdlet.ShouldProcess
   if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Remove X'))
#>
[CmdletBinding(SupportsShouldProcess = $true)]

$verbose = [bool]$PSBoundParameters['verbose']
$debug = [bool]$PSBoundParameters['debug']

function Get-Ago
{
    param(
        $start,
        $end
    )

    $timespan = New-TimeSpan -Start $start -End $end
    $days = $timespan.Days
    $hours = $timespan.Hours
    $minutes = $timespan.Minutes
    $seconds = $timespan.Seconds

    if ($days -gt 1)
    {
        $ago = "$days days"
    }
    elseif ($days -eq 1)
    {
        $ago = "$days day"
    }
    elseif ($hours -gt 1)
    {
        $ago = "$hours hrs"
    }
    elseif ($hours -eq 1)
    {
        $ago = "$hours hr"
    }
    elseif ($minutes -gt 1)
    {
        $ago = "$minutes mins"
    }
    elseif ($minutes -eq 1)
    {
        $ago = "$minutes min"
    }
    elseif ($seconds -gt 1)
    {
        $ago = "$seconds secs"
    }
    elseif ($seconds -eq 1)
    {
        $ago = "$seconds sec"
    }
    $ago = "$ago ago"
    return $ago
}

$crashes = Get-WinEvent -FilterHashtable @{LogName = 'Application'; ProviderName = 'Application Error'; Level = 2; Id = 1000}
$signature = @{N = 'Signature'; E = {"$($_.properties[6].Value) $($_.properties[0].value) $($_.properties[1].value) $($_.properties[3].value) $($_.properties[4].value)"}}
#$signatureWithTime = @{N='SignatureWithTime';E={"$(Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss) $(Get-Ago -Start $_.TimeCreated -End (Get-Date)) $($_.properties[6].Value) $($_.properties[0].value) $($_.properties[1].value) $($_.properties[3].value) $($_.properties[4].value)"}}
$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Ago -Start $_.TimeCreated -End (Get-Date)): $($_.properties[6].Value) $($_.properties[0].value) $($_.properties[1].value) $($_.properties[3].value) $($_.properties[4].value)"}}
$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
$crashesLastHour = $crashes | Where-Object TimeCreated -GE (Get-Date).AddHours(-1) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastOneDay = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-1) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastTwoDays = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-2) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastThreeDays = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-3) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastFourDays = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-4) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastFiveDays = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-5) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastSixDays = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-6) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastWeek = $crashes | Where-Object TimeCreated -GE (Get-Date).AddDays(-7) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashesLastMonth = $crashes | Where-Object TimeCreated -GE (Get-Date).AddMonths(-1) | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$crashes = $crashes | Sort-Object TimeCreated -desc | Sort-Object TimeCreated -desc | Select-Object $timeCreated, $signature, $signatureWithTime
$global:dbgCrashes = $crashes

$countCrashesLastHour = $crashesLastHour | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastOneDay = $crashesLastOneDay | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastTwoDays = $crashesLastTwoDays | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastThreeDays = $crashesLastThreeDays | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastFourDays = $crashesLastFourDays | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastFiveDays = $crashesLastFiveDays | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastSixDays = $crashesLastSixDays | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastWeek = $crashesLastWeek | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesLastMonth = $crashesLastMonth | Measure-Object | Select-Object -ExpandProperty Count
$countCrashesTotal = $crashes | Measure-Object | Select-Object -ExpandProperty Count

$lastCrash = $crashes | Select-Object -First 1
Out-Log "`nLast crash: $cyan$($lastCrash.SignatureWithTime)$reset" -raw

$crashCount = [PSCustomObject]@{
    CrashesLastHour  = $countCrashesLastHour
    CrashesLastDay   = $countCrashesLastOneDay
    CrashesLastTwoDays   = $countCrashesLastTwoDays
    CrashesLastThreeDays = $countCrashesLastThreeDays
    CrashesLastFourDays  = $countCrashesLastFourDays
    CrashesLastFiveDays  = $countCrashesLastFiveDays
    CrashesLastSixDays   = $countCrashesLastSixDays
    CrashesLastWeek  = $countCrashesLastWeek
    CrashesLastMonth = $countCrashesLastMonth
    CrashesTotal     = $countCrashesTotal
}
$crashCount
Out-Log 'Top five crashes by number of occurrences:' -raw
$crashes | Group-Object Signature | Sort-Object Count -desc | Select-Object Count, Name -First 5 | Format-Table -AutoSize

if ($verbose)
{
    Out-Log "$countCrashesLastHour crashes in last hour" -raw -color Green
    $crashesLastHour | Format-Table -AutoSize TimeCreated, SignatureWithTime -HideTableHeaders
    Out-Log "$countCrashesLastOneDay crashes in last day" -raw -color Green
    $crashesLastOneDay | Format-Table -AutoSize TimeCreated, SignatureWithTime -HideTableHeaders
    Out-Log "$countCrashesLastWeek crashes in last week" -raw -color Green
    $crashesLastWeek | Format-Table -AutoSize TimeCreated, SignatureWithTime -HideTableHeaders
    Out-Log "$countCrashesLastMonth crashes in last month" -raw -color Green
    $crashesLastMonth | Format-Table -AutoSize TimeCreated, SignatureWithTime -HideTableHeaders
}
exit
$global:lastCrash = $crashes | Select-Object -First 1
$global:lastCrashString = $global:lastCrash | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
$lastCrashString = $lastCrashString.Trim()
$crashes | Group-Object Signature | Sort-Object Count -desc | Select-Object Count, Name -First 5
Write-Host $lastCrashString

#$newestAppLogEventTime = Get-WinEvent -LogName Application -MaxEvents 1 | Select-Object -ExpandProperty TimeCreated
$newestAppLogEventTime = Get-Date
$oldestAppLogEventTime = Get-WinEvent -LogName Application -MaxEvents 1 -Oldest | Select-Object -ExpandProperty TimeCreated
$appLogTimespan = New-TimeSpan -Start $oldestAppLogEventTime -End $newestAppLogEventTime
$appLogTimespanDays = $appLogTimespan.Days
$newestAppLogEventTimeString = Get-Date $newestAppLogEventTime -Format yyyy-MM-dd
$oldestAppLogEventTimeString = Get-Date $oldestAppLogEventTime -Format yyyy-MM-dd
$appLogTimeRangeString = "Application log goes back $appLogTimespanDays days ($oldestAppLogEventTimeString)"
Write-Host $appLogTimeRangeString

#$newestSystemLogEventTime = Get-WinEvent -LogName System -MaxEvents 1 | Select-Object -ExpandProperty TimeCreated
$newestSystemLogEventTime = Get-Date
$oldestSystemLogEventTime = Get-WinEvent -LogName System -MaxEvents 1 -Oldest | Select-Object -ExpandProperty TimeCreated
$systemLogTimespan = New-TimeSpan -Start $oldestSystemLogEventTime -End $newestSystemLogEventTime
$systemLogTimespanDays = $systemLogTimespan.Days
$newestSystemLogEventTimeString = Get-Date $newestSystemLogEventTime -Format yyyy-MM-dd
$oldestSystemLogEventTimeString = Get-Date $oldestSystemLogEventTime -Format yyyy-MM-dd
$systemLogTimeRangeString = "System log goes back $systemLogTimespanDays days ($oldestSystemLogEventTimeString)"
Write-Host $systemLogTimeRangeString

$appLog = Get-WinEvent -ListLog Application
$appLogMode = $appLog.LogMode.ToString().ToLower()
$appLogFileSizeMB = [Math]::Round($appLog.FileSize / 1MB, 0)
$appLogMaxSizeMB = [Math]::Round($appLog.MaximumSizeInBytes / 1MB, 0)
# $appLogProviderNames = $appLog.ProviderNames
$appLogRecordCount = $appLog.RecordCount.ToString('N0')
$appLogDetailsString = "$appLogRecordCount events $($appLogFileSizeMB)MB of $($appLogMaxSizeMB)MB max ($appLogMode)"
Write-Host $appLogDetailsString

$systemLog = Get-WinEvent -ListLog System
$systemLogMode = $systemLog.LogMode.ToString().ToLower()
$systemLogFileSizeMB = [Math]::Round($systemLog.FileSize / 1MB, 0)
$systemLogMaxSizeMB = [Math]::Round($systemLog.MaximumSizeInBytes / 1MB, 0)
# $systemLogProviderNames = $systemLog.ProviderNames
$systemLogRecordCount = $systemLog.RecordCount.ToString('N0')
$systemLogDetailsString = "$systemLogRecordCount events $($systemLogFileSizeMB)MB of $($systemLogMaxSizeMB)MB max ($systemLogMode)"
Write-Host $systemLogDetailsString