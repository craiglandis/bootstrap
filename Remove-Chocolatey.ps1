# \\tsclient\c\od\Remove-Chocolatey.ps1
# iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
# https://docs.chocolatey.org/en-us/choco/uninstallation/
# Get-Item 'C:\ProgramData\chocolatey\choco.exe'
# Remove-Item -Path $env:ChocolateyInstall -Recurse -Force -WhatIf

if (Test-Path -Path 'C:\ProgramData\chocolatey\choco.exe')
{
    & $env:ChocolateyInstall\choco.exe uninstall chocolatey -y
}

del 'C:\ProgramData\chocolatey' -Recurse -Force -ErrorAction SilentlyContinue
del 'C:\ProgramData\ChocolateyHttpCache' -Recurse -Force -ErrorAction SilentlyContinue
del "$env:TEMP\chocolatey" -Recurse -Force -ErrorAction SilentlyContinue
del "$env:TEMP\ChocolateyScratch" -Recurse -Force -ErrorAction SilentlyContinue
del "C:\Windows\Temp\chocolatey" -Recurse -Force -ErrorAction SilentlyContinue

<#
    Using the .NET registry calls is necessary here in order to preserve environment variables embedded in PATH values;
    Powershell's registry provider doesn't provide a method of preserving variable references, and we don't want to
    accidentally overwrite them with absolute path values. Where the registry allows us to see "%SystemRoot%" in a PATH
    entry, PowerShell's registry provider only sees "C:\Windows", for example.
#>
$userKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
$userPath = $userKey.GetValue('PATH', [string]::Empty, 'DoNotExpandEnvironmentNames').ToString()

$machineKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\ControlSet001\Control\Session Manager\Environment\', $true)
$machinePath = $machineKey.GetValue('PATH', [string]::Empty, 'DoNotExpandEnvironmentNames').ToString()

if ($userPath -like "*C:\ProgramData\chocolatey\bin*")
{
    $newUserPATH = @(
        $userPath -split [System.IO.Path]::PathSeparator |
        Where-Object { $_ -and $_ -ne 'C:\ProgramData\chocolatey\bin'}
    ) -join [System.IO.Path]::PathSeparator

    # NEVER use [Environment]::SetEnvironmentVariable() for PATH values; see https://github.com/dotnet/corefx/issues/36449
    # This issue exists in ALL released versions of .NET and .NET Core as of 12/19/2019
    $userKey.SetValue('PATH', $newUserPATH, 'ExpandString')
}

if ($machinePath -like "*C:\ProgramData\chocolatey\bin*")
{
    $newMachinePATH = @(
        $machinePath -split [System.IO.Path]::PathSeparator |
        Where-Object { $_ -and $_ -ne 'C:\ProgramData\chocolatey\bin'}
    ) -join [System.IO.Path]::PathSeparator

    # NEVER use [Environment]::SetEnvironmentVariable() for PATH values; see https://github.com/dotnet/corefx/issues/36449
    # This issue exists in ALL released versions of .NET and .NET Core as of 12/19/2019
    $machineKey.SetValue('PATH', $newMachinePATH, 'ExpandString')
}

$agentService = Get-Service -Name 'chocolatey-agent' -ErrorAction SilentlyContinue
if ($agentService -and $agentService.Status -eq 'Running')
{
    $agentService.Stop()
}

'ChocolateyInstall', 'ChocolateyLastPathUpdate' | ForEach-Object {
    foreach ($scope in 'User', 'Machine')
    {
        [Environment]::SetEnvironmentVariable($_, [string]::Empty, $scope)
    }
}

$machineKey.Close()
$userKey.Close()
