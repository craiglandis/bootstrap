#SingleInstance force

^+G:: ; *** CTRL+SHIFT+G for Google ***
If WinExist("ahk_exe chrome.exe")
{
	WinActivate
	WinMaximize
    SendInput ^t
}
Else
{
    Run, "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    WinActivate
    WinMaximize
    SendInput ^t
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
