# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\onedrive\my\Set-Cursor.ps1

if ($PSVersionTable.PSVersion -lt [Version]'6.0')
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
    '17763' {if ($isWindowsServer) {$os = 'WS19'} else {$os = 'WIN10'; $isWin10 = $true}} # 1809 October 2018 Update (Redstone 5)
    '18362' {if ($isWindowsServer) {$os = 'WS1909'} else {$os = 'WIN10'; $isWin10 = $true}} # 1903 19H1 November 2019 Update
    '18363' {if ($isWindowsServer) {$os = 'WS1909'} else {$os = 'WIN10'; $isWin10 = $true}} # 1909 19H2 November 2019 Update
    '19041' {if ($isWindowsServer) {$os = 'WS2004'} else {$os = 'WIN10'; $isWin10 = $true}} # 2004 20H1 May 2020 Update
    '19042' {if ($isWindowsServer) {$os = 'WS20H2'} else {$os = 'WIN10'; $isWin10 = $true}} # 20H2 October 2020 Update
    '19043' {$os = 'WIN10'; $isWin10 = $true} # 21H1 May 2021 Update
    '19044' {$os = 'WIN10'; $isWin10 = $true} # 21H2 November 2021 Update
    '20348' {$os = 'WS22'; $isWS22 = $true} # 21H2
    '22000' {$os = 'WIN11'; $isWin11 = $true} # 21H2
    default {$os = 'Unknown'}
}

if ($isWS22 -or $isWin11 -or $isWin10)
{
    $cursorsUrl = 'https://github.com/craiglandis/ps/raw/master/cursors.zip'
    $cursorsFile = $cursorsUrl.Split('/')[-1]
    $cursorsFilePath = "$env:temp\$cursorsFile"
    (New-Object System.Net.Webclient).DownloadFile($cursorsUrl, $cursorsFilePath)

    $cursorsFolder = "$env:LOCALAPPDATA\Microsoft\Windows\Cursors"
    $cursorsFolderBackup = "$($cursorsFolder).bak"
    Write-Output "Cursors folder: $cursorsFolder"

    if (Test-Path -Path $cursorsFolder -PathType Container)
    {
        Write-Output "Creating Cursors folder backup: $cursorsFolderBackup"
        $command = "New-Item -Path $cursorsFolderBackup -ItemType Directory -Force"
        Write-Output $command
        Invoke-Expression -Command $command

        Write-Output "Backing up cursors to $cursorsFolderBackup"
        $command = "Copy-Item -Path `"$cursorsFolder\*`" -Destination $cursorsFolderBackup -Force -ErrorAction SilentlyContinue"
        Write-Output $command
        Invoke-Expression -Command $command

        Write-Output "Removing contents of cursors folder $cursorsFolder"
        $command = "Remove-Item -Path `"$cursorsFolder\*`" -ErrorAction SilentlyContinue"
        Write-Output $command
        Invoke-Expression -Command $command
    }
    else
    {
        Write-Output "Cursors folder does not exist, creating it"
        $command = "New-Item -Path $cursorsFolder -ItemType Directory -Force"
        Write-Output $command
        Invoke-Expression -Command $command
    }

    Write-Output "Extracting $cursorsFilePath to cursors folder $cursorsFolder"
    $command = "Expand-Archive -Path $cursorsFilePath -DestinationPath $cursorsFolder"
    Write-Output $command
    Invoke-Expression -Command $command
}

New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

$accessibilityKeyPaths = @('HKU:\.DEFAULT\SOFTWARE\Microsoft\Accessibility','HKCU:\SOFTWARE\Microsoft\Accessibility')

$accessibilityKeyPaths | ForEach-Object {

    $accessibilityKeyPath = $_

    if ((Test-Path -LiteralPath $accessibilityKeyPath) -ne $true)
    {
        New-Item $accessibilityKeyPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    New-ItemProperty -LiteralPath $accessibilityKeyPath -Name 'CursorColor' -Value 12582656 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath $accessibilityKeyPath -Name 'TextScaleFactor' -Value 100 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath $accessibilityKeyPath -Name 'CursorType' -Value 6 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath $accessibilityKeyPath -Name 'CursorSize' -Value 3 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
}

$cursorsKeyPaths = @('HKU:\.DEFAULT\Control Panel\Cursors','HKCU:\Control Panel\Cursors')

$cursorsKeyPaths | ForEach-Object {

    $cursorsKeyPath = $_

    if ((Test-Path -LiteralPath $cursorsKeyPath) -ne $true)
    {
        New-Item $cursorsKeyPath -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if ($isWS22 -or $isWin11 -or $isWin10)
    {
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name '(default)' -Value 'Windows Aero' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'AppStarting' -Value "$cursorsFolder\busy_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Arrow' -Value "$cursorsFolder\arrow_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'ContactVisualization' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Crosshair' -Value "$cursorsFolder\cross_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'CursorBaseSize' -Value 80 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'GestureVisualization' -Value 31 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Hand' -Value "$cursorsFolder\link_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Help' -Value "$cursorsFolder\helpsel_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'IBeam' -Value "$cursorsFolder\ibeam_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'No' -Value "$cursorsFolder\unavail_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'NWPen' -Value "$cursorsFolder\pen_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Person' -Value "$cursorsFolder\person_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Pin' -Value "$cursorsFolder\pin_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Scheme Source' -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeAll' -Value "$cursorsFolder\move_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeNESW' -Value "$cursorsFolder\nesw_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeNS' -Value "$cursorsFolder\ns_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeNWSE' -Value "$cursorsFolder\nwse_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeWE' -Value "$cursorsFolder\ew_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'UpArrow' -Value "$cursorsFolder\up_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Wait' -Value "$cursorsFolder\wait_eoa.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
    }
    else
    {
        $cursorsFolder = '%SystemRoot%\cursors'
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name '(default)' -Value 'Windows Inverted (extra large)' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'AppStarting' -Value "$cursorsFolder\wait_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Arrow' -Value "$cursorsFolder\arrow_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'ContactVisualization' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Crosshair' -Value "$cursorsFolder\cross_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'CursorBaseSize' -Value 80 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'GestureVisualization' -Value 31 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Hand' -Value "$cursorsFolder\aero_link_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Help' -Value "$cursorsFolder\help_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'IBeam' -Value "$cursorsFolder\beam_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'No' -Value "$cursorsFolder\no_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'NWPen' -Value "$cursorsFolder\pen_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Scheme Source' -Value 2 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeAll' -Value "$cursorsFolder\move_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeNESW' -Value "$cursorsFolder\size1_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeNS' -Value "$cursorsFolder\size4_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeNWSE' -Value "$cursorsFolder\size2_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'SizeWE' -Value "$cursorsFolder\size3_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'UpArrow' -Value "$cursorsFolder\up_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath $cursorsKeyPath -Name 'Wait' -Value "$cursorsFolder\busy_il.cur" -PropertyType ExpandString -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

Write-Output "Refreshing mouse cursor"
$CSharpSig = @'
[DllImport("user32.dll", EntryPoint = "SystemParametersInfo")]
public static extern bool SystemParametersInfo(
    uint uiAction,
    uint uiParam,
    uint pvParam,
    uint fWinIni);
'@
$cursorRefresh = Add-Type -MemberDefinition $CSharpSig -Name WinAPICall -Namespace SystemParamInfo -PassThru
$cursorRefresh::SystemParametersInfo(0x0057, 0, $null, 0)

Remove-PSDrive -Name HKU
