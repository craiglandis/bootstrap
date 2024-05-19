# Tested successfully on Win11 ENT 23H2 22631.3593
# Taskbar reflected changes immediately, don't have to call advapi32.dll to refresh it
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [switch]$addScheduledTask
)

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptFolderPath = Split-Path -Path $scriptFullName
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$verbose = [bool]$PSBoundParameters['verbose']
$debug = [bool]$PSBoundParameters['debug']

$notifyIconSettingsKeyPath = 'HKCU:\Control Panel\NotifyIconsettings'
$subKeys = Invoke-ExpressionWithLogging "Get-ChildItem -Path '$notifyIconSettingsKeyPath' -ErrorAction SilentlyContinue" -verboseOnly
$objects = New-Object System.Collections.Generic.List[Object]
foreach ($subKey in $subKeys)
{
    $subKeyName = $subKey.PSChildName
    $subKeyPath = "$($notifyIconSettingsKeyPath)\$($subKey.PSChildName)"
    $exePath = $subKey.GetValue('ExecutablePath')
    $exeName = Split-Path -Path $exePath -Leaf -ErrorAction SilentlyContinue
    $initialToolTip = $subKey.GetValue('InitialToolTip')
    $initialToolTip = $initialToolTip -creplace '\P{IsBasicLatin}'
    $initialToolTip = $initialToolTip -replace "`n","" -replace "`r","" -replace "  "," "
    $initialToolTip = $initialToolTip.Trim()
    $iconGuid = $subKey.GetValue('IconGuid')
    $iconSnapshot = $subKey.GetValue('IconSnapshot')
    $isPromoted = $subKey.GetValue('IsPromoted')
    $publisher = $subKey.GetValue('Publisher')
    $uid = $subKey.GetValue('UID')

    $object = [PSCustomObject]@{
        ExeName = $exeName
        ExePath = $exePath
        IconGuid = $iconGuid
        IconSnapshot = $iconSnapshot
        InitialToolTip = $initialToolTip
        IsPromoted = $isPromoted
        Publisher = $publisher
        SubKeyName = $subKeyName
        SubKeyPath = $subKeyPath
        UID = $uid
    }
    $objects.Add($object)
    Invoke-ExpressionWithLogging "Set-ItemProperty -Path '$subKeyPath' -Name IsPromoted -Value 1 -Type DWord -ErrorAction SilentlyContinue" -verboseOnly
}

if ($verbose -or $debug)
{
    $objects | Sort-Object ExeName | Format-Table ExeName,InitialToolTip,IsPromoted,UID,SubKeyPath -AutoSize
}

$count = $objects | Where-Object {$_.IsPromoted -eq 1} | Measure-Object | Select-Object -ExpandProperty Count
Out-Log "$count NotifyIconsettings subkeys updated (IsPromoted set to 1)" -raw

if ($addScheduledTask)
{
	Out-Log "Adding scheduled task"
	$taskName = (Get-Culture).TextInfo.ToTitleCase($scriptBaseName)
	Invoke-ExpressionWithLogging "Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false -ErrorAction SilentlyContinue" -verboseOnly
    Out-Log "Registering $taskName task without XML" -verboseonly
    $executePowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $argument = "-NoLogo -NoProfile -File $scriptFullName"
    $userId = "$env:userdomain\$env:username"
    $runLevel = 'Highest'
    $action = New-ScheduledTaskAction -Execute $executePowerShell -Argument $argument -WorkingDirectory $scriptFolderPath
    $principal = New-ScheduledTaskPrincipal -UserId $userId -RunLevel $runLevel -LogonType Interactive
    $settings = New-ScheduledTaskSettingsSet -Compatibility Win8
    $trigger1 = New-ScheduledTaskTrigger -AtLogOn
    $trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)
    $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Trigger $trigger1, $trigger2
    Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
    # Get-ScheduledTask -TaskName $taskName | Format-List *
    Export-ScheduledTask -TaskName $taskName
    # Start-ScheduledTask -TaskName $taskName
}
