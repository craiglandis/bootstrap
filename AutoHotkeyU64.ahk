#SingleInstance force

+^P::
windowsTerminalPreview := "C:\Users\" A_UserName "\AppData\Local\Microsoft\WindowsApps\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\wt.exe"
windowsTerminal := "C:\Users\" A_UserName "\AppData\Local\Microsoft\WindowsApps\wt.exe"
pwshPreview := "C:\Program Files\PowerShell\7-preview\pwsh.exe"
pwsh := "C:\Program Files\PowerShell\7\pwsh.exe"
powershell := "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SetTitleMatchMode RegEx
if WinExist("ahk_exe WindowsTerminal.exe")
{
    WinActivate ; foo
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
SetTitleMatchMode RegEx
if WinExist("ahk_exe Code.exe")
{
    WinActivate
}
Else
{
    Run, "C:\Program Files\Microsoft VS Code\Code.exe"
    ;Run, "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio Code\Visual Studio Code.lnk"
    ;Run, "C:\Users\clandis\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Visual Studio Code\Visual Studio Code.lnk"
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

^+E:: ; *** CTRL+SHIFT+E for Edge ***
If WinExist("ahk_exe msedge.exe")
{
	WinActivate
	WinMaximize
    ;WinMove, , , 0, 0, 1280, 720
    SendInput ^t
}
Else
{
    Run, "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    WinActivate
    ;WinMove, , , 0, 0, 1280, 720
    WinMaximize
    SendInput ^t
}
Return

+^R:: ; *** CTRL+SHIFT+R to reload AHK file***
Run, C:\OneDrive\Tools\AutoHotkeyU64.ahk, , Hide
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
