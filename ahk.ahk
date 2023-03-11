#SingleInstance force

Menu, TRAY, Icon, C:\Program Files\AutoHotkey\AutoHotkey.exe, 4 ; red "H" icon to denote this script runs elevated

+^P::
windowsTerminalPreview := "C:\Users\" A_UserName "\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\wt.exe"
windowsTerminal := "C:\Users\" A_UserName "\AppData\Local\Microsoft\WindowsApps\wt.exe"
pwshPreview := "C:\Program Files\PowerShell\7-preview\pwsh.exe"
pwsh := "C:\Program Files\PowerShell\7\pwsh.exe"
powershell := "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SetTitleMatchMode RegEx
if WinExist("ahk_exe WindowsTerminal.exe")
{
    WinActivate
}
else if FileExist(windowsTerminalPreview)
{
    Run, %windowsTerminalPreview%, , max
}
else if FileExist(windowsTerminal)
{
    Run, %windowsTerminal%, , max
}
else if WinExist("ahk_exe pwsh.exe")
{
    WinActivate
}
else if FileExist(pwshPreview)
{
    Run %pwshPreview% -NoLogo -WindowStyle Maximized -NoExit -WorkingDirectory C:\
}
else if FileExist(pwsh)
{
    Run %pwsh% -NoLogo -WindowStyle Maximized -NoExit -WorkingDirectory C:\
}
else if WinExist("ahk_exe powershell.exe")
{
    WinActivate
}
else
{
    Run %powershell% -NoLogo -WindowStyle Maximized -NoExit -Command Set-Location -Path C:\
}
Return

+^O:: ; *** CTRL+SHIFT+O for (old) PowerShell (PS5.1) ***
powershell := "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SetTitleMatchMode RegEx
if WinExist("ahk_exe powershell.exe")
{
    WinActivate
}
else
{
    Run %powershell% -NoLogo -WindowStyle Maximized -NoExit -Command Set-Location -Path C:\
}
Return

+^C:: ; *** CTRL+SHIFT+C for VSCODE ***
vscodeSystemShortcutPath := A_AppDataCommon "\Microsoft\Windows\Start Menu\Programs\Visual Studio Code\Visual Studio Code.lnk"
vscodeUserShortcutPath := A_AppData "\Microsoft\Windows\Start Menu\Programs\Visual Studio Code\Visual Studio Code.lnk"
SetTitleMatchMode RegEx
if WinExist("ahk_exe Code.exe")
{
    WinActivate
}
else if FileExist(vscodeSystemShortcutPath)
{
    Run %vscodeSystemShortcutPath%
}
else if FileExist(vscodeUserShortcutPath)
{
    Run %vscodeUserShortcutPath%
}
Return

+^N:: ; *** CTRL+SHIFT+N for Notepad++ ***
IfWinExist Notepad++
{
    WinActivate
}
Else
{
    Run Notepad++
}
Return

+^R:: ; *** CTRL+SHIFT+R to reload AHK file***
Run, c:\onedrive\my\ahk.ahk, , Hide
Return

; *** Auto-replace strings ***
::!utc::
FormatTime, utc, %A_NowUTC%, yyyy-MM-ddTHH:mm:ssZ
SendInput %utc%
return

::!z::
FormatTime, utc, %A_NowUTC%, yyyy-MM-ddTHH:mm:ssZ
SendInput %utc%
return

::!local::
FormatTime, local, , yyyy-MM-ddTHH:mm:ss
SendInput %local%
return

::!now::
FormatTime, local, , yyyy-MM-ddTHH:mm:ss
SendInput %local%
return