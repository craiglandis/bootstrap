# Tested successfully on Win11 ENT 23H2 22631.3593
# Taskbar reflected changes immediately, don't have to call advapi32.dll to refresh it
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [System.IO.FileInfo]$path,
    [string]$someStringParam,
    [switch]$someSwitchParam,
    [ValidateSet('Red', 'Green', 'Blue')]
    [string]$color
)

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