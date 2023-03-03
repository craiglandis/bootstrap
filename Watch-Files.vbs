Dim shell, command
command = """C:\Program Files\PowerShell\7-preview\pwsh.exe"" -NoProfile -NoLogo -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\OneDrive\My\Watch-Files.ps1"
Set shell = CreateObject("WScript.Shell")
shell.Run command,0