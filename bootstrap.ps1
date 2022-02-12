<#
TODO:

Additional shell customizations
Install KE https://aka.ms/ke
Import KE connections
Install Visio
s
# wmic path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"
# reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
# Run from RDP client
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\onedrive\my\bootstrap.ps1
# ipcsv (gci c:\bs\*.csv | sort lastwritetime -desc)[0].FullName | ft -a timestamp,message
#>
[CmdletBinding()]
param(
    [ValidateSet('PC', 'VM', 'VSAW', 'All')]
    [string]$group,
    [switch]$show,
    [string]$toolsPath = 'C:\OneDrive\Tools',
    [string]$myPath = 'C:\OneDrive\My'
)
DynamicParam
{
    $ParameterName = 'app'
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $false
    $ParameterAttribute.Position = 1
    $AttributeCollection.Add($ParameterAttribute)
    $appsJsonFilePath = "$PSScriptRoot\apps.json"
    Remove-Item -Path $appsJsonFilePath -Force -ErrorAction SilentlyContinue
    $appsJsonFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/apps.json'
    (New-Object Net.WebClient).DownloadFile($appsJsonFileUrl, $appsJsonFilePath)
    $apps = Get-Content -Path $PSScriptRoot\apps.json | ConvertFrom-Json
    $appNames = $apps.Name
    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($appNames)
    $AttributeCollection.Add($ValidateSetAttribute)
    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
    return $RuntimeParameterDictionary
}
begin
{
    $app = $PsBoundParameters[$ParameterName]
}
process
{
    function Invoke-ExpressionWithLogging
    {
        param(
            [string]$command
        )
        Write-PSFMessage $command
        try
        {
            Invoke-Expression -Command $command
        }
        catch
        {
            Write-PSFMessage -Level Warning -Message "Failed: $command" -ErrorRecord $_
        }
    }

    function Set-PSFramework
    {
        Remove-Item Alias:Write-PSFMessage -Force -ErrorAction SilentlyContinue
        $logFilePath = "$bsPath\$($scriptBaseName)-Run$($runCount)-$scriptStartTimeString.csv"
        $paramSetPSFLoggingProvider = @{
            Name = 'logfile'
            FilePath = $logFilePath
            Enabled = $true
        }
        Set-PSFLoggingProvider @paramSetPSFLoggingProvider
        Write-PSFMessage "PSFramework $($psframework.Version)"
        Write-PSFMessage "Log path: $bsPath"
    }

    function Get-AppList
    {
        $appsJsonFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/apps.json'
        $appsJsonFilePath = "$bsPath\apps.json"
        Remove-Item -Path $appsJsonFilePath -Force -ErrorAction SilentlyContinue
        if ($isWin7 -or $isWS08R2 -or $isWS12)
        {
            Invoke-ExpressionWithLogging -command "Start-BitsTransfer -Source $appsJsonFileUrl -Destination $appsJsonFilePath"
        }
        else
        {
            Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$appsJsonFileUrl`', `'$appsJsonFilePath`')"
        }

        if (Test-Path -Path $appsJsonFilePath -PathType Leaf)
        {
            Get-Content -Path $appsJsonFilePath | ConvertFrom-Json
        }
    }

    # Alias Write-PSFMessage to Write-PSFMessage until confirming PSFramework module is installed
    Set-Alias -Name Write-PSFMessage -Value Write-Output
    $PSDefaultParameterValues['Write-PSFMessage:Level'] = 'Output'
    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    $PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'

    $scriptStartTime = Get-Date
    $scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss

    # Since this script will be called via psremoting using Invoke-Command so that it runs in the context of a specific user instead of system,
    # the $MyInvocation.MyCommand.Path, $PSScriptRoot, and $PSCommandPath automatic variables are not populated, because Invoke-Command is reading the script but executing it as a script block
    $bsPath = "$env:SystemDrive\bs"
    $scriptName = 'bootstrap.ps1'
    $scriptBaseName = $scriptName.Split('.')[0]
    $scriptPath = "$bsPath\$scriptName"
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptName = Split-Path -Path $scriptPath -Leaf

    if (Test-Path -Path $bsPath -PathType Container)
    {
        Write-PSFMessage "Log path $bsPath already exists, don't need to create it"
    }
    else
    {
        Write-PSFMessage "Creating log path $bsPath"
        New-Item -Path $bsPath -ItemType Directory -Force | Out-Null
    }
    $runCount = (Get-ChildItem -Path "$bsPath\$scriptBaseName-Run*" -File | Measure-Object).Count
    $runCount++

    whoami | Out-File -FilePath "$bsPath\whoami.txt" -Force

    $ProgressPreference = 'SilentlyContinue'
    if ($PSVersionTable.PSVersion -ge [Version]'5.1')
    {
        <#
        Import-Module BitsTransfer
        $url = 'http://download.windowsupdate.com/c/msdownload/update/software/updt/2016/04/windows6.1-kb3140245-x64_5b067ffb69a94a6e5f9da89ce88c658e52a0dec0.msu'
        08R2 - http://download.windowsupdate.com/c/msdownload/update/software/updt/2016/04/windows6.1-kb3140245-x64_5b067ffb69a94a6e5f9da89ce88c658e52a0dec0.msu
               http://download.windowsupdate.com/c/msdownload/update/software/updt/2016/04/windows8-rt-kb3140245-x64_b589173ad4afdb12b18606b5f84861fcf20010d0.msu
               Start-BitsTransfer -source $url
               wusa $kb32 /log:install.log

               Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
               Name  = 'DefaultSecureProtocols'

                reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DefaultSecureProtocols = (DWORD): 0xAA0
    HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\
        DefaultSecureProtocols = (DWORD): 0xAA0
        #>
        # https://devblogs.microsoft.com/powershell/when-powershellget-v1-fails-to-install-the-nuget-provider/
        #[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        <# 2008R2/Win7 don't support TLS1.2 until PS5.1/WMF are installed, before then this will result in error:
        PS C:\> [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Exception setting "SecurityProtocol": "Cannot convert value "3312" to type "System.Net.SecurityProtocolType" due to invalid enumeration values. Specify one of the following enumeration values and try again. The possible enumeration values are "Ssl3, Tls"."
        #>
    }

    if ([string]::IsNullOrEmpty($group))
    {
        if ($env:COMPUTERNAME.StartsWith('TDC'))
        {
            $group = 'VSAW'
            $isSAW = $true
            $installDir = "$env:SystemDrive:\ch"
            if (Test-Path -Path $installDir -PathType Container)
            {
                Write-PSFMessage "$installDir already exists, don't need to create it"
            }
            else
            {
                Write-PSFMessage "Creating $installDir folder for non-admin chocolatey installs"
                New-Item -Path $installDir -ItemType Directory | Out-Null
            }
            Invoke-ExpressionWithLogging -command "[Environment]::SetEnvironmentVariable('ChocolateyInstall', '$installDir', 'User')"
            $env:ChocolateyInstall = $installDir
            Write-PSFMessage "`$env:ChocolateyInstall : $env:ChocolateyInstall"
        }
        else
        {
            if ($PSVersionTable.PSVersion -lt [Version]'5.1')
            {
                $win32_Baseboard = Get-WmiObject -Class Win32_Baseboard
            }
            else
            {
                $win32_Baseboard = Get-CimInstance -ClassName Win32_Baseboard
            }

            if ($win32_Baseboard.Product -eq 'Virtual Machine')
            {
                $group = 'VM'
                $isVM = $true
            }
            else
            {
                $group = 'PC'
                $isPC = $true
            }
        }
        Write-PSFMessage "`$isPC: $isPC `$isVM: $isVM `$isSAW: $isSAW"
    }

    if ($show)
    {
        $apps = Get-AppList
        $apps = $apps | Where-Object {$_.Groups -contains $group}
        $appCount = ($apps | Measure-Object).Count
        Write-PSFMessage "`nGroup: $group, Count: $appCount"
        Write-PSFMessage $apps
        exit
    }

    if ($PSVersionTable.PSVersion -lt [Version]'5.1')
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
    Write-PSFMessage "OS: $os ($osVersion)"

    if ($isWindowsServer)
    {
        # Disable Server Manager from starting at Windows startup
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null"
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\ServerManager' /v DoNotPopWACConsoleAtSMLaunch /t REG_DWORD /d 1 /f | Out-Null"
    }

    if ($isWin11)
    {
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' /f /ve | Out-Null"
    }

    if ($isWin10)
    {
        # Enable "Always show all icons in the notification area"
        Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v EnableAutoTray /t REG_DWORD /d 0 /f | Out-Null"
    }

    # Config for all Windows versions
    # Show file extensions
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null"
    # Show hidden files
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Hidden /t REG_DWORD /d 1 /f | Out-Null"
    # Show protected operating system files
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowSuperHidden /t REG_DWORD /d 0 /f | Out-Null"
    # Explorer show compressed files color
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowCompColor /t REG_DWORD /d 1 /f | Out-Null"
    # Taskbar on left instead of center
    Invoke-ExpressionWithLogging -command "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Null"

    if ($isSAW)
    {
        Invoke-ExpressionWithLogging -command 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Scope CurrentUser'
    }
    else
    {
        Invoke-ExpressionWithLogging -command 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Force'
    }

    if (Test-Path -Path $profile.CurrentUserCurrentHost -PathType Leaf)
    {
        Write-PSFMessage "$($profile.CurrentUserCurrentHost) already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $($profile.CurrentUserCurrentHost) -Type File -Force | Out-Null"
    }

    $ErrorActionPreference = 'SilentlyContinue'
    $chocoVersion = choco -v
    $ErrorActionPreference = 'Continue'

    if ($chocoVersion)
    {
        Write-PSFMessage "Chocolatey $chocoVersion already installed"
    }
    else
    {
        # Chocolatey install requires at least PS3. Clean install of 2008R2/Win7 only have PS2, so need to manually get PS5.1 installed on those
        if ($PSVersionTable.PSVersion -lt [Version]'3.0')
        {
            $installWmfScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-WMF.ps1'
            $installWmfScriptFilePath = "$env:TEMP\$($installWmfScriptUrl.Split('/')[-1])"
            Start-BitsTransfer -Source $installWmfScriptUrl -Destination $installWmfScriptFilePath
            (New-Object Net.WebClient).DownloadFile($installWmfScriptUrl, $installWmfScriptFilePath)
            Invoke-ExpressionWithLogging -command $installWmfScriptFilePath
            # The install WMF script will issue a retart on its own
            exit
        }
        else
        {
            Invoke-ExpressionWithLogging -command "Invoke-Expression -command ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"

            $ErrorActionPreference = 'SilentlyContinue'
            $chocoVersion = choco -v
            $ErrorActionPreference = 'Continue'
            if ($chocoVersion)
            {
                Write-PSFMessage "Chocolatey $chocoVersion already installed"
            }
            else
            {
                Write-PSFMessage 'Chocolatey failed to install'
                exit
            }
        }
    }

    if ($chocoVersion)
    {
        Write-PSFMessage "Chocolatey $chocoVersion successfully installed"
    }
    else
    {
        Write-PSFMessage 'Chocolatey install failed'
        exit
    }

    if ($PSVersionTable.PSVersion -lt [Version]'5.1')
    {
        # 14393+ definitely have PS5.1, 10240 and 10586 may not, but nobody uses those early days Win10 builds anymore anyway.
        # The chocolatey package checks if PowerShell 5.1 is installed, if so, it does not try to install it
        $timestamp = Get-Date -Format yyyyMMddHHmmssff
        $packageName = 'powershell'
        $chocoInstallLogFilePath = "$bsPath\choco_install_$($packageName)_$($timestamp).log"
        Invoke-ExpressionWithLogging -command "choco install $packageName --limit-output --no-progress --no-color --confirm --log-file=$chocoInstallLogFilePath | Out-Null"
        if ($LASTEXITCODE -eq 3010)
        {
            Write-PSFMessage 'Creating onstart scheduled task to run script again at startup'
            if (Test-Path -Path $scriptPath -PathType Leaf)
            {
                Write-PSFMessage "Script already exists in $scriptPath"
            }
            else
            {
                $bootstrapScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1'
                $bootstrapScriptFileName = $bootstrapScriptUrl.Split('/')[-1]
                Write-PSFMessage "Downloading $bootstrapScriptUrl to $scriptPath"
                (New-Object Net.Webclient).DownloadFile($bootstrapScriptUrl, $scriptPath)
            }
            Invoke-ExpressionWithLogging -command "schtasks /create /tn bootstrap /sc onstart /delay 0000:30 /rl highest /ru system /tr `"powershell.exe -executionpolicy bypass -file $scriptPath`" /f"
            Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
        }
    }

    # This needs to be before Set-PSRepository, otherwise Set-PSRepository will prompt to install it
    if ($PSEdition -eq 'Desktop')
    {
        Write-PSFMessage 'Verifying Nuget 2.8.5.201+ is installed'
        $nuget = Get-PackageProvider -Name nuget -ErrorAction SilentlyContinue -Force
        if (!$nuget -or $nuget.Version -lt [Version]'2.8.5.201')
        {
            Invoke-ExpressionWithLogging -command 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force'
        }
        else
        {
            Write-PSFMessage "Nuget $($nuget.Version) already installed"
        }

        Import-Module -Name Appx
    }
    else
    {
        Import-Module -Name Appx -UseWindowsPowerShell
    }

    # https://psframework.org/
    Import-Module -Name PSFramework -ErrorAction SilentlyContinue
    $psframework = Get-Module -Name PSFramework -ErrorAction SilentlyContinue
    if ($psframework)
    {
        Set-PSFramework
    }
    else
    {
        Write-PSFMessage 'PSFramework module not found, installing it'
        Install-Module -Name PSFramework -Repository PSGallery -Scope CurrentUser -AllowClobber -Force -ErrorAction SilentlyContinue
        Import-Module -Name PSFramework -ErrorAction SilentlyContinue
        $psframework = Get-Module -Name PSFramework -ErrorAction SilentlyContinue
        if ($psframework)
        {
            Set-PSFramework
        }
        else
        {
            Write-Error 'PSFramework module failed to install'
            exit
        }
    }

    $ErrorActionPreference = 'SilentlyContinue'
    $chocoVersion = choco -v
    $ErrorActionPreference = 'Continue'

    if ($chocoVersion)
    {
        Write-PSFMessage "Chocolatey $chocoVersion already installed"
    }
    else
    {
        if ($isSAW)
        {
            $installDir = "$env:SystemDrive:\ch"
            Invoke-ExpressionWithLogging -command "[Environment]::SetEnvironmentVariable('ChocolateyInstall', '$installDir', 'System')"
            New-Item -Path $installDir -ItemType Directory | Out-Null
        }

        Invoke-ExpressionWithLogging -command "Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
        $ErrorActionPreference = 'SilentlyContinue'
        $chocoVersion = choco -v
        $ErrorActionPreference = 'Continue'
        if ($chocoVersion)
        {
            Write-PSFMessage "Chocolatey $chocoVersion already installed"
        }
        else
        {
            Write-PSFMessage 'Chocolatey failed to install'
            exit
        }
    }

    if ($chocoVersion)
    {
        Write-PSFMessage "Chocolatey $chocoVersion successfully installed"
    }
    else
    {
        Write-PSFMessage 'Chocolatey install failed'
        exit
    }

    # Install Windows Terminal and winget
    if ($isWS22 -or $isWin11 -or $isWin10)
    {
        # This alternate way to install Windows Terminal is only needed on WS22. For Win11/Win10, it's easier to use winget to install Windows Terminal
        # But using this same approach on WS22/Win11/Win10 simplifies the script
        # "choco install microsoft-windows-terminal -y" does work on WS22/Win11/Win10, but there's no Windows Terminal Preview chocolatey package, only that package for the release version
        # So use the "download msixbundle + run Add-AppxPackage" approach instead to install Windows Terminal Preview
        # $windowsTerminalPreviewMsixBundleUri = 'https://github.com/microsoft/terminal/releases/download/v1.12.3472.0/Microsoft.WindowsTerminalPreview_1.12.3472.0_8wekyb3d8bbwe.msixbundle'
        # v1.13.10336.0 below released 2022-02-03

        $windowsTerminalReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/microsoft/terminal/releases'
        $windowsTerminalPreviewRelease = $windowsTerminalReleases | Where-Object prerelease -eq $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $windowsTerminalPreviewMsixBundleUri = ($windowsTerminalPreviewRelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $windowsTerminalPreviewMsixBundleFileName = $windowsTerminalPreviewMsixBundleUri.Split('/')[-1]
        $windowsTerminalPreviewMsixBundleFilePath = "$env:TEMP\$windowsTerminalPreviewMsixBundleFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$windowsTerminalPreviewMsixBundleUri`', `'$windowsTerminalPreviewMsixBundleFilePath`')"
        Invoke-ExpressionWithLogging -command "Add-AppxPackage -Path $windowsTerminalPreviewMsixBundleFilePath -ErrorAction SilentlyContinue | Out-Null"
        <# Release version
        $windowsTerminalRelease = $windowsTerminalReleases | Where-Object {$_.prerelease -eq $false} | Sort-Object -Property id -Descending | Select-Object -First 1
        $windowsTerminalMsixBundleUri = ($windowsTerminalRelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $windowsTerminalMsixBundleFileName = $windowsTerminalMsixBundleUri.Split('/')[-1]
        $windowsTerminalMsixBundleFilePath = "$env:TEMP\$windowsTerminalMsixBundleFileName"
        (New-Object Net.WebClient).DownloadFile($windowsTerminalMsixBundleUri, $windowsTerminalMsixBundleFilePath)
        Add-AppxPackage -Path $windowsTerminalMsixBundleFilePath
        #>

        # Install winget since it is not installed by default. It is supported on Win10/Win11 but not WS22 although you can get it working on WS22
        # Preview version didn't work, said it needed Microsoft.UI.Xaml 2.7.0 even after I installed Microsoft.UI.Xaml 2.7.0
        # $wingetMsixBundleUrl = 'https://github.com/microsoft/winget-cli/releases/download/v1.2.3411-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        $vcLibsUrl = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
        $vcLibsFileName = $vcLibsUrl.Split('/')[-1]
        $vcLibsFilePath = "$env:TEMP\$vcLibsFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$vcLibsUrl`', `'$vcLibsFilePath`')"
        if (Test-Path -Path $vcLibsFilePath -PathType Leaf)
        {
            Invoke-ExpressionWithLogging -command "Add-AppPackage -Path $vcLibsFilePath | Out-Null"
        }

        $microsoftUiXamlPackageUrl = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.0'
        $microsoftUiXamlPackageFileName = $microsoftUiXamlPackageUrl.Split('/')[-1]
        $microsoftUiXamlPackageFolderPath = "$env:TEMP\$microsoftUiXamlPackageFileName"
        $microsoftUiXamlPackageFilePath = "$env:TEMP\$microsoftUiXamlPackageFileName.zip"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$microsoftUiXamlPackageUrl`', `'$microsoftUiXamlPackageFilePath`')"
        Invoke-ExpressionWithLogging -command "Expand-Archive -Path $microsoftUiXamlPackageFilePath -DestinationPath $microsoftUiXamlPackageFolderPath -Force"
        $microsoftUiXamlAppXFilePath = "$microsoftUiXamlPackageFolderPath\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx"
        Invoke-ExpressionWithLogging -command "Add-AppxPackage -Path $microsoftUiXamlAppXFilePath | Out-Null"

        $wingetReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases'
        $wingetPrerelease = $wingetReleases | Where-Object prerelease -eq $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleUrl = ($wingetPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleFileName = $wingetPrereleaseMsixBundleUrl.Split('/')[-1]
        $wingetPrereleaseMsixBundleFilePath = "$env:TEMP\$wingetPrereleaseMsixBundleFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$wingetPrereleaseMsixBundleUrl`', `'$wingetPrereleaseMsixBundleFilePath`')"
        $wingetPrereleaseMsixBundleLicenseUrl = ($wingetPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('xml')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetPrereleaseMsixBundleLicenseFileName = $wingetPrereleaseMsixBundleLicenseUrl.Split('/')[-1]
        $wingetPrereleaseMsixBundleLicenseFilePath = "$env:TEMP\$wingetPrereleaseMsixBundleLicenseFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$wingetPrereleaseMsixBundleLicenseUrl`', `'$wingetPrereleaseMsixBundleLicenseFilePath`')"
        if ((Test-Path -Path $wingetPrereleaseMsixBundleFilePath -PathType Leaf) -and (Test-Path -Path $wingetPrereleaseMsixBundleLicenseFilePath -PathType Leaf))
        {
            Invoke-ExpressionWithLogging -command "Add-AppxProvisionedPackage -Online -PackagePath $wingetPrereleaseMsixBundleFilePath -LicensePath $wingetPrereleaseMsixBundleLicenseFilePath | Out-Null"
        }
        <# Release version
        $wingetrelease = $wingetReleases | Where-Object prerelease -eq $true | Sort-Object -Property id -Descending | Select-Object -First 1
        $wingetreleaseMsixBundleUrl = ($wingetrelease.assets | Where-Object {$_.browser_download_url.EndsWith('msixbundle')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetreleaseMsixBundleFileName = $wingetreleaseMsixBundleUrl.Split('/')[-1]
        $wingetreleaseMsixBundleFilePath = "$env:TEMP\$wingetreleaseMsixBundleFileName"
        (New-Object Net.WebClient).DownloadFile($wingetreleaseMsixBundleUrl, $wingetreleaseMsixBundleFilePath)
        $wingetreleaseMsixBundleLicenseUrl = ($wingetrelease.assets | Where-Object {$_.browser_download_url.EndsWith('xml')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
        $wingetreleaseMsixBundleLicenseFileName = $wingetreleaseMsixBundleLicenseUrl.Split('/')[-1]
        $wingetreleaseMsixBundleLicenseFilePath = "$env:TEMP\$wingetreleaseMsixBundleLicenseFileName"
        (New-Object Net.WebClient).DownloadFile($wingetreleaseMsixBundleLicenseUrl, $wingetreleaseMsixBundleLicenseFilePath)
        if ((Test-Path -Path $wingetreleaseMsixBundleFilePath -PathType Leaf) -and (Test-Path -Path $wingetreleaseMsixBundleLicenseFilePath -PathType Leaf))
        {
            Invoke-ExpressionWithLogging -command "Add-AppxProvisionedPackage -Online -PackagePath $wingetreleaseMsixBundleFilePath -LicensePath $wingetreleaseMsixBundleLicenseFilePath | Out-Null"
        }
        #>
    }

    $powershellReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases'
    # Install PS7 release version
    $powershellRelease = $powershellReleases | Where-Object prerelease -eq $false | Sort-Object -Property id -Descending | Select-Object -First 1
    $powerShellx64MsiUrl = ($powershellRelease.assets | Where-Object {$_.browser_download_url.EndsWith('win-x64.msi')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
    $powerShellx64MsiFileName = $powerShellx64MsiUrl.Split('/')[-1]
    $powerShellx64MsiFilePath = "$env:TEMP\$powerShellx64MsiFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$powerShellx64MsiUrl`', `'$powerShellx64MsiFilePath`')"
    Invoke-ExpressionWithLogging -command "msiexec.exe /package $powerShellx64MsiFilePath /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 | Out-Null"
    # Install PS7 preview version
    $powershellPrerelease = $powershellReleases | Where-Object prerelease -eq $true | Sort-Object -Property id -Descending | Select-Object -First 1
    $powerShellPreviewx64MsiUrl = ($powershellPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('win-x64.msi')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
    $powerShellPreviewx64MsiFileName = $powerShellPreviewx64MsiUrl.Split('/')[-1]
    $powerShellPreviewx64MsiFilePath = "$env:TEMP\$powerShellPreviewx64MsiFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$powerShellPreviewx64MsiUrl`', `'$powerShellPreviewx64MsiFilePath`')"
    Invoke-ExpressionWithLogging -command "msiexec.exe /package $powerShellPreviewx64MsiFilePath /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 | Out-Null"

    if (!$apps)
    {
        $apps = Get-AppList
        if (!$apps)
        {
            Write-Error "Failed to get app list"
            exit
        }
    }

    if ($group -ne 'All')
    {
        $apps = $apps | Where-Object {$_.Groups -contains $group}
    }

    Write-PSFMessage "Checking if winget is installed"
    if (Get-ChildItem -Path $env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller*\winget.exe -ErrorAction SilentlyContinue)
    {
        $isWingetInstalled = $true
    }
    else
    {
        $isWingetInstalled = $false
    }
    Write-PSFMessage "`$isWingetInstalled: $isWingetInstalled"
    Write-PSFMessage "Mode: $group"
    Write-PSFMessage "$($apps.Count) apps to be installed"
    $apps | ForEach-Object {

        $app = $_
        Write-PSFMessage "Installing: $($app.Name)"

        if ($app.ChocolateyName -and ($app.WingetName -or !$app.WingetName))
        {
            $appName = $app.ChocolateyName
            $useChocolatey = $true
            if ($app.ChocolateyParams)
            {
                $chocolateyParams = $app.ChocolateyParams
            }
            else
            {
                $chocolateyParams = $null
            }
        }
        elseif ($app.WingetName)
        {
            $appName = $app.WingetName
        }
        else
        {
            $appName = ''
        }

        if ($appName -and $useChocolatey)
        {
            Remove-Variable useChocolatey -Force
            # https://docs.chocolatey.org/en-us/choco/commands/install
            $timestamp = Get-Date -Format yyyyMMddHHmmssff
            $chocoInstallLogFilePath = "$bsPath\choco_install_$($appName)_$($timestamp).log"
            $command = "choco install $appName --limit-output --no-progress --no-color --confirm --log-file=$chocoInstallLogFilePath | Out-Null"
            if ($chocolateyParams)
            {
                # EXAMPLE: choco install sysinternals --params "/InstallDir:C:\your\install\path"
                $command = "$command --params `"$chocolateyParams`""
                $command = $command.Replace('TOOLSPATH', $toolsPath)
                $command = $command.Replace('MYPATH', $myPath)
            }
            Invoke-ExpressionWithLogging -command $command
        }
        elseif ($appName -and !$useChocolatey -and $isWingetInstalled)
        {
            # https://aka.ms/winget-command-install
            # winget log files will be in %temp%\AICLI\*.log unless redirected
            $timestamp = Get-Date -Format yyyyMMddHHmmssff
            $wingetInstallLogFilePath = "$bsPath\winget_install_$($appName)_$($timestamp).log"
            $command = "winget install --id $appName --exact --silent --accept-package-agreements --accept-source-agreements --log $wingetInstallLogFilePath | Out-Null"
            Invoke-ExpressionWithLogging -command $command
        }
    }

    <#
    The sysinternals package tries to create the specified InstallDir and fails if it already exists
    ERROR: Exception calling "CreateDirectory" with "1" argument(s): "Cannot create "C:\OneDrive\Tools" because a file or directory with the same name already exists."
    So don't precreate these, let the package create them, and if needed, make sure they are created after all package installs are done
    #>
    Write-PSFMessage "Checking if $toolsPath exists"
    if (Test-Path -Path $toolsPath -PathType Container)
    {
        Write-PSFMessage "$toolsPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $toolsPath -Type File -Force | Out-Null"
    }

    Write-PSFMessage "Checking if $myPath exists"
    if (Test-Path -Path $myPath -PathType Container)
    {
        Write-PSFMessage "$myPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $myPath -Type Directory -Force | Out-Null"
    }

    # https://stackoverflow.com/questions/714877/setting-windows-powershell-environment-variables
    Write-PSFMessage "Adding $toolsPath and $myPath to user Path environment variable"
    $newUserPath = "$env:Path;$toolsPath;$myPath"
    Invoke-ExpressionWithLogging -command "[Environment]::SetEnvironmentVariable('Path', '$newUserPath', 'User')"

    $userPathFromRegistry = (Get-ItemProperty -Path 'HKCU:\Environment' -Name Path).Path
    $separator = "`n$('='*160)`n"
    Write-PSFMessage "$separator`$userPathFromRegistry: $userPathFromRegistry$separator"

    Invoke-ExpressionWithLogging -command "Remove-Item $env:PUBLIC\Desktop\*.lnk -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging -command "Remove-Item $env:USERPROFILE\Desktop\*.lnk -Force -ErrorAction SilentlyContinue"

    $scriptFileUrls = @(
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Cursor.ps1',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Console.ps1',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Add-ScheduledTasks.ps1'
    )

    $scriptFileUrls | ForEach-Object {
        $scriptFileUrl = $_
        $scriptFileName = $scriptFileUrl.Split('/')[-1]
        $scriptFilePath = "$bsPath\$scriptFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$scriptFileUrl`', `'$scriptFilePath`')"
        Invoke-ExpressionWithLogging -command $scriptFilePath
    }

    $regFileUrls = @(
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/7-zip_auto_extract_downloaded_zip.reg',
        'https://raw.githubusercontent.com/craiglandis/bootstrap/main/7-zip_double-click_extract_to_folder.reg'
    )

    $regFileUrls | ForEach-Object {
        $regFileUrl = $_
        $regFileName = $regFileUrl.Split('/')[-1]
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$regFileUrl`', `'$regFileName`')"
        if (Test-Path -Path $regFileName -PathType Leaf)
        {
            Invoke-ExpressionWithLogging -command "reg import $regFileName"
        }
    }

    $windowsTerminalSettingsUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/windows-terminal-settings.json'

    $windowsTerminalSettingsFilePaths = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json"
    )

    $windowsTerminalSettingsFilePaths | ForEach-Object {
        $windowsTerminalSettingsFilePath = $_
        if (Test-Path -Path $windowsTerminalSettingsFilePath -PathType Leaf)
        {
            Move-Item -Path $windowsTerminalSettingsFilePath -Destination "$windowsTerminalSettingsFilePath.original" -ErrorAction SilentlyContinue
        }
        else
        {
            Invoke-ExpressionWithLogging -command "New-Item -Path $windowsTerminalSettingsFilePath -ItemType File -Force"
        }
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$windowsTerminalSettingsUrl`', `'$windowsTerminalSettingsFilePath`')"
    }

    if ($isWin11 -and $group -eq 'PC')
    {
        Invoke-ExpressionWithLogging -command 'wsl --install'
    }

    $nppSettingsZipUrl = 'https://github.com/craiglandis/bootstrap/raw/main/npp-settings.zip'
    $nppSettingsZipFileName = $nppSettingsZipUrl.Split('/')[-1]
    $nppSettingsZipFilePath = "$env:temp\$nppSettingsZipFileName"
    $nppSettingsTempFolderPath = "$env:TEMP\$($nppSettingsZipFileName.Replace('.zip',''))"
    $nppSettingsFolderPath = 'C:\OneDrive\npp'
    $nppAppDataPath = "$env:APPDATA\Notepad++"
    $nppCloudFolderPath = "$nppAppDataPath\cloud"
    $nppCloudFilePath = "$nppCloudFolderPath\choice"

    if (Test-Path -Path $nppSettingsFolderPath -PathType Container)
    {
        Write-PSFMessage "$nppSettingsFolderPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $nppSettingsFolderPath -Type Directory -Force | Out-Null"
    }

    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$nppSettingsZipUrl`', `'$nppSettingsZipFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Archive -Path $nppSettingsZipFilePath -DestinationPath $nppSettingsTempFolderPath -Force"
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $nppSettingsTempFolderPath\* -Destination $nppSettingsFolderPath"
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $nppSettingsTempFolderPath\* -Destination $nppAppDataPath"

    if (Test-Path -Path $nppCloudFolderPath -PathType Container)
    {
        Write-PSFMessage "$nppSettingsFolderPath already exists, don't need to create it"
    }
    else
    {
        Invoke-ExpressionWithLogging -command "New-Item -Path $nppCloudFolderPath -Type Directory -Force | Out-Null"
    }
    Invoke-ExpressionWithLogging -command "Set-Content -Path $env:APPDATA\Notepad++\cloud\choice -Value $nppSettingsFolderPath -Force"

    # The chocolatey package for Everything includes an old version (1.1.0.9) of the es.exe CLI tool
    # Delete that one, then download the latest (1.1.0.21) from the voidtools site
    Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:ProgramData\chocolatey\bin\es.exe -Force -ErrorAction SilentlyContinue"
    Invoke-ExpressionWithLogging -command "Remove-Item -Path $env:ProgramData\chocolatey\lib\Everything\tools\es.exe -Force -ErrorAction SilentlyContinue"
    $esZipUrl = 'https://www.voidtools.com/ES-1.1.0.21.zip'
    $esZipFileName = $esZipUrl.Split('/')[-1]
    $esZipFilePath = "$env:TEMP\$esZipFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$esZipUrl`', `'$esZipFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Archive -Path $esZipFilePath -DestinationPath $toolsPath -Force"

    $esIniUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/es.ini'
    $esIniFileName = $esIniUrl.Split('/')[-1]
    $esIniFilePath = "$toolsPath\$esIniFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$esIniUrl`', `'$esIniFilePath`')"

    if ($group -eq 'PC' -or $group -eq 'VM')
    {
        $getNirSoftToolsScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Get-NirsoftTools.ps1'
        $getNirSoftToolsScriptFileName = $getNirSoftToolsScriptUrl.Split('/')[-1]
        $getNirSoftToolsScriptFilePath = "$bsPath\$getNirSoftToolsScriptFileName"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$getNirSoftToolsScriptUrl`', `'$getNirSoftToolsScriptFilePath`')"
        Invoke-ExpressionWithLogging -command $getNirSoftToolsScriptFilePath
    }

    # autohotkey.portable - couldn't find a way to specify a patch for this package
    # (portable? https://www.autohotkey.com/download/ahk.zip)

    # https://www.thenickmay.com/how-to-install-autohotkey-even-without-administrator-access/
    # It works - the .ahk file must be named AutoHotkeyU64.ahk, then you run AutoHotkeyU64.exe
    # copy-item -Path \\tsclient\c\onedrive\ahk\AutoHotkey.ahk -Destination c:\my\ahk\AutoHotkeyU64.ahk
    $vsCodeSystemPath = "$env:ProgramFiles\Microsoft VS Code\Code.exe"
    $vsCodeUserPath = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"
    if ((Test-Path -Path $vsCodeSystemPath -PathType Leaf) -or (Test-Path -Path $vsCodeUserPath -PathType Leaf))
    {
        $vsCodeSettingsJsonUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/vscode_settings.json'
        $vsCodeSettingsJsonPath = "$env:APPDATA\Code\User\settings.json"
        Invoke-ExpressionWithLogging -command "New-Item -Path $vsCodeSettingsJsonPath -Force"
        Write-PSFMessage "Downloading $vsCodeSettingsJsonUrl"
        Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$vsCodeSettingsJsonUrl`', `'$vsCodeSettingsJsonPath`')"
    }
    else
    {
        Write-PSFMessage "VSCode not installed, skipping download of $vsCodeSettingsJsonUrl"
    }

    Invoke-ExpressionWithLogging -command 'Update-Help -Force -ErrorAction SilentlyContinue'
    $pwshFilePath = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
    if (Test-Path -Path $pwshFilePath -PathType Leaf)
    {
        Invoke-ExpressionWithLogging -Command "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Update-Help -Force -ErrorAction SilentlyContinue"
    }

    if ($isPC -or $isVM)
    {
        Invoke-ExpressionWithLogging -command "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\od -Target $env:SystemDrive\OneDrive -ErrorAction SilentlyContinue"
        Invoke-ExpressionWithLogging -command "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\my -Target $env:SystemDrive\OneDrive\My -ErrorAction SilentlyContinue"
        Invoke-ExpressionWithLogging -command "New-Item -ItemType SymbolicLink -Path $env:SystemDrive\bin -Target $env:SystemDrive\OneDrive\Tools -ErrorAction SilentlyContinue"

        # To remove the symbolic links (Remove-Item won't do it):
        #(Get-Item -Path "$env:SystemDrive\od").Delete()
        #(Get-Item -Path "$env:SystemDrive\my").Delete()
        #(Get-Item -Path "$env:SystemDrive\bin").Delete()
    }

    $installModulesFileUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Install-Modules.ps1'
    $installModulesFileName = $installModulesFileUrl.Split('/')[-1]
    $installModulesFilePath = "$env:TEMP\$installModulesFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$installModulesFileUrl`', `'$installModulesFilePath`')"

    if (Test-Path -Path $installModulesFilePath -PathType Leaf)
    {
        Invoke-Expression -Command 'powershell -nologo -noprofile -command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force'
        Invoke-Expression -Command 'powershell -nologo -noprofile -command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force -AllowPrerelease'
        Invoke-Expression -Command "powershell -nologo -noprofile -file $installModulesFilePath"

        if (Test-Path -Path $pwshFilePath -PathType Leaf)
        {
            Invoke-Expression -Command "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force"
            Invoke-Expression -Command "& `'$pwshFilePath`' -NoProfile -NoLogo -Command Install-Module -Name PowerShellGet -Scope CurrentUser -AllowClobber -Force -AllowPrerelease"
            Invoke-Expression -Command "& `'$pwshFilePath`' -NoProfile -NoLogo -File $installModulesFilePath"
        }
    }
    else
    {
        Write-PSFMessage "File not found: $installModulesFilePath"
    }

    # "Choco find greenshot" - package is still on 1.2.10 from 2017, no high DPI scaling support so very small icons on 4K, no obvious way to use chocolatey to install the prerelease version, so doing it manually
    $greenshotReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/greenshot/greenshot/releases'
    $greenshotPrerelease = $greenshotReleases | Where-Object prerelease -EQ $true | Sort-Object -Property id -Descending | Select-Object -First 1
    $greenshotInstallerUrl = ($greenshotPrerelease.assets | Where-Object {$_.browser_download_url.EndsWith('.exe')}).browser_download_url
    $greenshotInstallerFileName = $greenshotInstallerUrl.Split('/')[-1]
    $greenshotInstallerFilePath = "$env:TEMP\$greenshotInstallerFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$greenshotInstallerUrl`', `'$greenshotInstallerFilePath`')"
    Invoke-ExpressionWithLogging -command "$greenshotInstallerFilePath /VERYSILENT /NORESTART | Out-Null"

    if ($isPC -or $isVM)
    {
        $taskName = 'bootstrap'
        $scheduleService = New-Object -ComObject Schedule.Service
        $scheduleService.Connect()
        $rootFolder = $scheduleService.GetFolder('\')
        $tasks = $rootFolder.GetTasks(1) | Select-Object Name,Path,State
        $bootstrapTask = $tasks | Where-Object {$_.Name -eq $taskName}
        if ($bootstrapTask)
        {
            Write-PSFMessage "Found $taskName scheduled task from previous script run, deleting it"
            $rootFolder.DeleteTask($taskName, 0)
        }
    }

    if ($isVM)
    {
        # Set file type associations (FTAs) with SetUserFTA, which works around how Win8+ protects certain FTAs from being configure the old way in the registry
        # https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/
        # HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\<extension>\OpenWithList
        # Browser
        Invoke-ExpressionWithLogging -command "SetUserFTA http MSEdgeHTM"
        Invoke-ExpressionWithLogging -command "SetUserFTA https MSEdgeHTM"
        Invoke-ExpressionWithLogging -command "SetUserFTA microsoft-edge MSEdgeHTM"
        Invoke-ExpressionWithLogging -command "SetUserFTA .htm MSEdgeHTM"
        Invoke-ExpressionWithLogging -command "SetUserFTA .html MSEdgeHTM"
        Invoke-ExpressionWithLogging -command "SetUserFTA .pdf MSEdgeHTM"
        # Logs/config
        Invoke-ExpressionWithLogging -command "SetUserFTA .bas applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .cfg applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .conf applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .config applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .csv applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .inf applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .ini applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .json applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .log applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .rdp applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .reg applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .settings applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .status applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .txt applications\notepad++.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .xml applications\notepad++.exe"
        # Code
        Invoke-ExpressionWithLogging -command "SetUserFTA .bat applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .cmd applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .ps1 applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .ps1xml applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .psd1 applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .psm1 applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .py applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .sh applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .vbs applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .wsf applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .xaml applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .xls applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .xlsm applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .xsl applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .xslt applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .yaml applications\code.exe"
        Invoke-ExpressionWithLogging -command "SetUserFTA .yml applications\code.exe"
    }

    $tssUrl = 'https://aka.ms/getTSSv2'
    $tssFileName = $tssUrl.Split('/')[-1]
    $tssFolderPath = "$bsPath\$($tssFileName.Split('.')[0])"
    $tssFilePath = "$bsPath\$tssFileName"
    Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`'$tssUrl`', `'$tssFilePath`')"
    Invoke-ExpressionWithLogging -command "Expand-Archive -Path $tssFilePath -DestinationPath $tssFolderPath -Force"
    #Invoke-ExpressionWithLogging -command "$tssFolderPath\TSSv2.ps1 -SDP Perf"

    $timestamp = Get-Date -Format yyyyMMddHHmmssff
    $getWindowsUpdateLogFilePath = "$bsPath\Get-WindowsUpdate-$timestamp.log"
    Invoke-ExpressionWithLogging -command "Get-WindowsUpdate -AcceptAll -AutoReboot -Download -Install -Verbose | Out-File $getWindowsUpdateLogFilePath"

    $scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
    Write-PSFMessage "$scriptName duration: $scriptDuration"

    $psFrameworkLogPath = Get-PSFConfigValue -FullName PSFramework.Logging.FileSystem.LogPath
    $psFrameworkLogFile = Get-ChildItem -Path $psFrameworkLogPath | Sort-Object LastWriteTime -desc | Select-Object -First 1
    $psFrameworkLogFilePath = $psFrameworkLogFile.FullName
    Invoke-ExpressionWithLogging -command "Copy-Item -Path $env:ProgramData\chocolatey\logs\chocolatey.log -Destination $bsPath"
    Write-PSFMessage "Log path: $psFrameworkLogFilePath"

    Invoke-ExpressionWithLogging -command 'Restart-Computer -Force'
}
