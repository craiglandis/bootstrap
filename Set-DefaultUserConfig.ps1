$productType = Get-CimInstance -Query "SELECT ProductType FROM Win32_OperatingSystem" | Select-Object -ExpandProperty ProductType
$build = [environment]::OSVersion.Version.Build

$defaultUserHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
$defaultUserKeyPath = 'HKEY_USERS\DefaultUserHive'
Invoke-Expression -command "reg load $defaultUserKeyPath $defaultUserHivePath"

# Set Windows sound scheme to "No sounds"
Invoke-Expression "reg add $defaultUserKeyPath\AppEvents\Schemes /VE /T REG_SZ /F /D `".None`""
Invoke-Expression "reg add HKCU\AppEvents\Schemes /VE /T REG_SZ /F /D `".None`""
# Disable Windows startup sound
Invoke-Expression "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation /T REG_DWORD /V DisableStartupSound /D 1 /F"
# Not sure this policy location is necessary
# reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /T REG_DWORD /V DisableStartupSound /D 1

if ($productType -ne 1)
{
    # Disable Server Manager from starting at Windows startup
    Invoke-Expression -command "reg add $defaultUserKeyPath\SOFTWARE\Microsoft\ServerManager /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-Expression -command "reg add $defaultUserKeyPath\SOFTWARE\Microsoft\ServerManager /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
    Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
}

if ($productType -eq 1)
{
    if ($build -ge 22000)
    {
        # Enable dark mode
        Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v SystemUsesLightTheme /t REG_DWORD /d 0 /f"
        Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' /v AppsUseLightTheme /t REG_DWORD /d 0 /f"
        # Set it to have no wallpaper (so solid color)
        Invoke-Expression -command "Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value ''"
        # Win11: Disable the new context menu
        Invoke-Expression -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        Invoke-Expression -command "reg add `'$defaultUserKeyPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`' /f /ve | Out-Null"
        # Win11: Taskbar on left instead of center
        Invoke-Expression -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"
        Invoke-Expression -command "reg add `'$defaultUserKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"
    }

    if ($build -lt 22000 -and $build -ge 10240)
    {
        # Win10: Enable "Always show all icons in the notification area"
        Invoke-Expression -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
        Invoke-Expression -command "reg add `'$defaultUserKeyPath\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`' /f /ve | Out-Null"
    }
}

# Config for all Windows versions
# Always show all icons and notifications on the taskbar
# On Win11 to toggle this in the GUI run: explorer shell:::{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}
Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v EnableAutoTray /t REG_DWORD /d 0 /f | Out-Null"
Invoke-Expression -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`' /v EnableAutoTray /t REG_DWORD /d 0 /f | Out-Null"
# Show file extensions
Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
Invoke-Expression -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
# Show hidden files
Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
Invoke-Expression -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
# Show protected operating system files
Invoke-Expression -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
Invoke-Expression -command "reg add `'$defaultUserKeyPath\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v ShowSuperHidden /t REG_DWORD /d 1 /f | Out-Null"
# Explorer show compressed files color
Invoke-Expression -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
Invoke-Expression -command "reg add `'$defaultUserKeyPath\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"

Invoke-Expression -command "reg unload $defaultUserKeyPath"
