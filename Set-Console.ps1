# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\onedrive\my\Set-Console.ps1
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\src\bootstrap\Set-Console.ps1
param(
	[switch]$UpdateShortcuts = $true, # Change to $true for shortcuts (.lnk) to be updated in addition to the registry changes. Creates backups (*.lnk.bak) before changing the existing shortcut.
	[switch]$KeepBackupShortcuts = $false # If $true, keeps the backup *.lnk.bak. If $false, removes the backup *.lnk.bak file.
)

function Out-Log
{
    param(
        [string]$text,
        [string]$prefix = 'timespan',
        [switch]$raw
    )
    if ($raw)
    {
        $text
    }
    elseif ($prefix -eq 'timespan' -and $scriptStartTime)
    {
        $timespan = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
        $prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
    }
    elseif ($prefix -eq 'both' -and $scriptStartTime)
    {
        $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
        $timespan = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
        $prefixString = "$($timestamp) $('{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan)"
    }
    else
    {
        $prefixString = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
    }
    Write-Host $prefixString -NoNewline -ForegroundColor Cyan
    Write-Host " $text"
    if ($logFilePath)
    {
        "$prefixString $text" | Out-File $logFilePath -Append
    }
}

function Set-DefaultTerminalApp
{
    if (Get-AppxPackage -Name Microsoft.WindowsTerminal -ErrorAction SilentlyContinue)
    {
        # https://support.microsoft.com/en-us/windows/command-prompt-and-windows-powershell-for-windows-11-6453ce98-da91-476f-8651-5c14d5777c20
        # Since the GUIDs are in the KB article and make no mention of them being different for different WT versions, I suspect they won't be changing and will always be the ones to use to specify WT
		New-Item -Path 'HKCU:\Console\%%Startup' -ErrorAction SilentlyContinue
		New-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationConsole' -PropertyType 'String' -Value '{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}' -Force
		New-ItemProperty -Path 'HKCU:\Console\%%Startup' -Name 'DelegationTerminal' -PropertyType 'String' -Value '{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}' -Force
		# & "$env:LOCALAPPDATA\Microsoft\WindowsApps\Microsoft.WindowsTerminal_8wekyb3d8bbwe\wt.exe" --maximized
	}
}

function Invoke-ExpressionWithLogging
{
	param(
		[string]$command
	)
	Out-Log$command
	try
	{
		Invoke-Expression -Command $command
	}
	catch
	{
		Out-Log-Level Error -Message "Failed: $command" -ErrorRecord $_
		Out-Log "`$LASTEXITCODE: $LASTEXITCODE"
	}
}

function Expand-Zip
{
	param
	(
		[CmdletBinding()]
		[Parameter(Mandatory = $true)]
		[System.IO.FileInfo]$Path,
		[Parameter(Mandatory = $true)]
		[System.IO.DirectoryInfo]$DestinationPath
	)

	$Path = $Path.FullName
	$DestinationPath = $DestinationPath.FullName

	$7z = 'C:\Program Files\7-Zip\7z.exe'
	if (Test-Path -Path $7z -PathType Leaf)
	{
		(& $7z x "$Path" -o"$DestinationPath" -aoa -r) | Out-Null
		$7zExitCode = $LASTEXITCODE
		if ($7zExitCode -ne 0)
		{
			throw "Error $7zExitCode extracting $Path to $DestinationPath"
		}
	}
	else
	{
		Add-Type -Assembly System.IO.Compression.Filesystem
		[System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
	}
}

$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptPath = Split-Path -Path $scriptFullName
#$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptName = Split-Path -Path $MyInvocation.MyCommand.Path -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$bootstrapPath = "$env:SystemDrive\bootstrap"
$logFilePath = "$bootstrapPath\$($scriptBaseName)_$(Get-Date -Format yyyyMMddhhmmss).log"
if ((Test-Path -Path (Split-Path -Path $logFilePath -Parent) -PathType Container) -eq $false)
{
    New-Item -Path (Split-Path -Path $logFilePath -Parent) -ItemType Directory -Force | Out-Null
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

Add-Type -Name Session -Namespace '' -member @'
[DllImport("gdi32.dll")]
public static extern int AddFontResource(string filePath);
'@

$bootstrapPath = "$env:SystemDrive\bootstrap"
$logsPath = "$bootstrapPath\logs"
if (Test-Path -Path $logsPath -PathType Container)
{
	Out-Log "$logsPath already exists, don't need to create it"
}
else
{
	Out-Log "Creating $logsPath"
	New-Item -Path $logsPath -ItemType Directory -Force | Out-Null
}

if ($env:COMPUTERNAME.StartsWith('TDC'))
{
	$isSAW = $true
	$fontSize = 24
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
		$isVM = $true
		$fontSize = 24
	}
	else
	{
		$isPC = $true
		$fontSize = 18
	}
}
Out-Log "`$isPC: $isPC `$isVM: $isVM `$isSAW: $isSAW"

# Skip this on VSAW which already has > 2.8.5.201
if ($isVM -or $isPC)
{
	if ($PSEdition -eq 'Desktop')
	{
		$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force
		if ($nuget)
		{
			if ($nuget.Version -lt [Version]'2.8.5.201')
			{
				Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
			}
		}
	}
}

if (Test-Path -Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\wt.exe" -PathType Leaf)
{
	Set-DefaultTerminalApp -WindowsTerminal
}

$faceName = 'Lucida Console'

$build = [environment]::OSVersion.Version.Build

if ($isPC -or $isVM)
{
	$systemFontsPath = "$env:SystemRoot\Fonts"
	$userFontsPath = "$env:LOCALAPPDATA\Microsoft\Windows\Fonts"
	$fontFileName = 'Caskaydia Cove Nerd Font Complete.ttf'
	if ((Test-Path -Path "$systemFontsPath\$fontFileName" -PathType Leaf) -or (Test-Path -Path "$userFontsPath\$fontFileName" -PathType Leaf))
	{
		Out-Log "$fontFileName already installed, don't need to install it"
	}
	else
	{
		Out-Log "$fontFileName not installed, installing it now"
		$ErrorActionPreference = 'SilentlyContinue'
		$chocoVersion = C:\ProgramData\chocolatey\choco.exe -v
		$ErrorActionPreference = 'Continue'
		if ($chocoVersion)
		{
            Out-Log "Chocolatey $chocoVersion"
			Out-Log'Using Chocolatey to install it since Chocolatey itself is already installed'
			$timestamp = Get-Date -Format yyyyMMddHHmmssff
			$packageName = 'cascadia-code-nerd-font'
			$chocoInstallLogFilePath = "$logsPath\choco_install_$($packageName)_$($timestamp).log"
			Invoke-ExpressionWithLogging -command "choco install $packageName --limit-output --no-progress --no-color --confirm --log-file=$chocoInstallLogFilePath | Out-Null"
		}
		else
		{
            Out-Log "Chocolatey not installed, downloading Cascadia Code Nerd Font from github"
			$cascadiaCoveNerdFontReleases = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/ryanoasis/nerd-fonts/releases'
			$cascadiaCoveNerdFontRelease = $cascadiaCoveNerdFontReleases | Where-Object prerelease -EQ $false | Sort-Object -Property id -Descending | Select-Object -First 1
			$cascadiaCodeNerdFontZipUrl = ($cascadiaCoveNerdFontRelease.assets | Where-Object {$_.browser_download_url.EndsWith('CascadiaCode.zip')}).browser_download_url | Sort-Object -Descending | Select-Object -First 1
			$cascadiaCodeNerdFontZipFileName = $cascadiaCodeNerdFontZipUrl.Split('/')[-1]
			$cascadiaCodeNerdFontZipFilePath = "$env:temp\$cascadiaCodeNerdFontZipFileName"
			$cascadiaCodeNerdFontExtractedFolderPath = "$env:temp\CascadiaCodeNerdFont"
			Invoke-ExpressionWithLogging -command "(New-Object Net.WebClient).DownloadFile(`"$cascadiaCodeNerdFontZipUrl`", `"$cascadiaCodeNerdFontZipFilePath`")"
			Invoke-ExpressionWithLogging -command "Expand-Zip -Path $cascadiaCodeNerdFontZipFilePath -DestinationPath $cascadiaCodeNerdFontExtractedFolderPath"

			# Installs  the fonts just for current user (C:\Users\<username>\AppData\Local\Microsoft\Windows\Fonts)
			$userFontsFolder = (New-Object -ComObject Shell.Application).Namespace(0x14)
			Get-ChildItem -Path $cascadiaCodeNerdFontExtractedFolderPath | ForEach-Object {
				$fontPath = $_.FullName
				if (Test-Path -Path $fontPath -PathType Leaf)
				{
					Out-Log "$fontPath already present"
				}
				else
				{
					$userFontsFolder.CopyHere($_.FullName, 16)
				}
			}
		}

        if ((Test-Path -Path "$systemFontsPath\$fontFileName" -PathType Leaf) -or (Test-Path -Path "$userFontsPath\$fontFileName" -PathType Leaf))
        {
            Out-Log "$fontFileName installed"
        }
        else
        {
            Out-Log "$fontFileName did not get installed because reasons"
        }
    }

	if ((Test-Path -Path "$systemFontsPath\$fontFileName" -PathType Leaf) -or (Test-Path -Path "$userFontsPath\$fontFileName" -PathType Leaf))
	{
		$faceName = 'CaskaydiaCove Nerd Font'
		# Calling AddFontResource makes a newly installed font available immediately without rebooting or logging in again
		$null = foreach ($font in Get-ChildItem -Path $systemFontsPath\*nerd*.ttf -ErrorAction SilentlyContinue)
		{
			[Session]::AddFontResource($font.FullName)
		}
		$null = foreach ($font in Get-ChildItem -Path $userFontsPath\*nerd*.ttf -ErrorAction SilentlyContinue)
		{
			[Session]::AddFontResource($font.FullName)
		}
	}

	<#
	# Installs the fonts for all users (C:\Windows\Fonts)
	$addFontScriptUrl = 'https://raw.githubusercontent.com/craiglandis/ps/master/Add-Font.ps1'
	$addFontScriptFileName = $addFontScriptUrl.Split('/')[-1]
	$addFontScriptFilePath = "$env:temp\$addFontScriptFileName"
	(New-Object System.Net.WebClient).DownloadFile($addFontScriptUrl, $addFontScriptFilePath)
	$command = "$addFontScriptFilePath -Path $cascadiaCodeExtractedFolderPath"
	Write-Output $command
	$result = Invoke-Expression -Command $command
	#>
}

if ($isPC -or $isVM)
{
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont' -Name '000' -Value $faceName
}

$fontSize = $fontSize * 65536

$settings = @{
	'3840x2160 windowsize' = 0x3700aa;
	'3840x2160 buffersize' = 0x270f00aa;
	#"3840x2160 windowsize" = 0x500118;
	#"3840x2160 buffersize" = 0x270f0118;
	'2560x1440 windowsize' = 0x4b00e6;
	'2560x1440 buffersize' = 0xbb800e6;
	'1920x1200 windowsize' = 0x3e00ab;
	'1920x1200 buffersize' = 0xbb800ab;
	'1920x1080 windowsize' = 0x280096; #0x3700ac;
	'1920x1080 buffersize' = 0x270f0096; #0xbb800ac;
	'1680x1050 windowsize' = 0x360096;
	'1680x1050 buffersize' = 0xbb80096;
	'1600x1200 windowsize' = 0x3e008f;
	'1600x1200 buffersize' = 0xbb8008f;
	'1600x900 windowsize'  = 0x2d008f;
	'1600x900 buffersize'  = 0xbb8008f;
	'1440x900 windowsize'  = 0x2d0080;
	'1440x900 buffersize'  = 0xbb80080;
	'1366x768 windowsize'  = 0x260079;
	'1366x768 buffersize'  = 0xbb80079;
	'1280x1024 windowsize' = 0x340071;
	'1280x1024 buffersize' = 0xbb80071;
	'1152x864 windowsize'  = 0x2b0066;
	'1152x864 buffersize'  = 0xbb80066;
	'1024x768 windowsize'  = 0x280096; #0x26005a;
	'1024x768 buffersize'  = 0x270f0096; #0xbb8005a;
	'800x600 windowsize'   = 0x1d0046;
	'800x600 buffersize'   = 0xbb80046;
	'FaceName'             = $faceName;
	'FontFamily'           = 0x36;
	'FontSize'             = $fontSize;
	'FontWeight'           = 0x190;
	'HistoryBufferSize'    = 0x32;
	'HistoryNoDup'         = 0x1;
	'InsertMode'           = 0x1;
	'QuickEdit'            = 0x1;
	'ScreenColors'         = 0x7;
	'WindowPosition'       = 0x0;
	'PSColorTable00'       = 0x562401;
	'PSColorTable07'       = 0xf0edee;
	'CMDColorTable00'      = 0x0;
	'CMDColorTable07'      = 0xc0c0c0;
}

# HKCU\Console has the default values, and HCKU\Console\<window title> has settings for a console window with that window title.
# These values are not used if a shortcut (.lnk) file itself has console settings defined in it.

$regPaths = @(`
		'HKCU:Console', `
		'HKCU:Console\Command Prompt', `
		'HKCU:Console\%SystemRoot%_system32_cmd.exe', `
		'HKCU:Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe', `
		'HKCU:Console\%SystemRoot%_SysWOW64_WindowsPowerShell_v1.0_powershell.exe', `
		'HKCU:Console\Windows PowerShell (x86)', `
		'HKCU:Console\Windows PowerShell', `
		'HKCU:Console\C:_Program Files_PowerShell_7-preview_pwsh.exe'
	    'HKCU:Console\C:_Program Files_PowerShell_7_pwsh.exe'
)

# Settings in a shortcut override settings in the registry
# Since there is no way to edit the console settings in an existing shortcut,
# the simplest way is to delete the existing one, create a new one, and it will use the registry settings
# By default, the script will first backup the existing shortcuts, if they exist, before creating a new one.

$shortcuts = @(`
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\PowerShell\PowerShell 7-preview (x64).lnk", `
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\PowerShell\PowerShell 7 (x64).lnk", `
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Windows PowerShell.lnk", `
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Windows PowerShell (x86).lnk", `
		"$ENV:ALLUSERSPROFILE\Start Menu\Programs\Accessories\Windows PowerShell\Windows PowerShell.lnk", `
		"$ENV:ALLUSERSPROFILE\Start Menu\Programs\Accessories\Windows PowerShell\Windows PowerShell (x86).lnk", `
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell\Windows PowerShell.lnk", `
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell\Windows PowerShell (x86).lnk", `
		"$ENV:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\System Tools\Windows PowerShell.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell (x86).lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\StartMenu\Windows PowerShell.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Windows PowerShell.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\StartMenu\Command Prompt.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Command Prompt.lnk", `
		"$ENV:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk", `
		"$ENV:SYSTEMDRIVE\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk", `
		"$ENV:SYSTEMDRIVE\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk", `
		"$ENV:SYSTEMDRIVE\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell (x86).lnk", `
		"$ENV:SYSTEMDRIVE\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk"
)

# Unlike some other methods, this method will get the correct screen resolution even in an RDP session.
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
$resolution = ([string][Windows.Forms.Screen]::PrimaryScreen.Bounds.Width + 'x' + [string][Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)

Write-Host "`nResolution:  $resolution"
If ($settings."$resolution windowsize" -eq $null)
{
	$defaultValue = '1920x1080'
	Write-Host "There are no settings defined for resolution $resolution. Defaulting to values for $defaultValue."
	$resolution = $defaultValue
}

# https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/dpi-related-apis-and-registry-settings?view=windows-11#table-6-hkcucontrol-paneldesktoplogpixels-values
# LogPixel values: 96 (100%), 120 (125%), 144 (150%), 192 (200%)
if ($resolution -eq '3840x2160')
{
	New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name LogPixels -Value 192 -PropertyType DWORD -Force | Out-Null
}

# Create the registry keys if they do not exist
$regPaths | ForEach-Object {
	$regPath = $_
	If (!(Test-Path -Path $regPath))
	{
		"`nCreating key $regPath"
		New-Item -Path $regPath -ItemType Registry -Force | Out-Null
	}
}

# Set console settings in the registry
$regPaths | ForEach-Object {

	$regPath = $_

	# Configure window size and buffer size registry values based on values defined earlier in the script
	Write-Host "`n$regPath"
	Write-Host ("`tWindowSize = " + $settings."$resolution windowsize")
	Write-Host ("`tScreenBufferSize = " + $settings."$resolution buffersize")

	New-ItemProperty -Path $regPath -Name WindowSize -Value $settings."$resolution windowsize" -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name ScreenBufferSize -Value $settings."$resolution buffersize" -PropertyType DWORD -Force | Out-Null

	if ($regPath -match 'PowerShell')
	{
		# Configure PowerShell windows to use default white text on blue background
		Write-Host "`n$regPath"
		Write-Host "`tColorTable00 =" $settings.PSColorTable00
		Write-Host "`tColorTable07 =" $settings.PSColorTable07

		New-ItemProperty -Path $regPath -Name ColorTable00 -Value $settings.PSColorTable00 -PropertyType DWORD -Force | Out-Null
		New-ItemProperty -Path $regPath -Name ColorTable07 -Value $settings.PSColorTable07 -PropertyType DWORD -Force | Out-Null
	}
	else
	{
		# Configures CMD windows to use default white text on black background
		Write-Host "`n$regPath"
		Write-Host "`tColorTable00 =" $settings.CMDColorTable00
		Write-Host "`tColorTable07 =" $settings.CMDColorTable07

		New-ItemProperty -Path $regPath -Name ColorTable00 -Value $settings.CMDColorTable00 -PropertyType DWORD -Force | Out-Null
		New-ItemProperty -Path $regPath -Name ColorTable07 -Value $settings.CMDColorTable07 -PropertyType DWORD -Force | Out-Null
	}

	# Configure font, window position, history buffer, insert mode, and quickedit
	Write-Host "`n$regPath"
	Write-Host "`tFaceName =" $settings.FaceName
	Write-Host "`tFontFamily =" $settings.FontFamily
	Write-Host "`tFontSize =" $settings.FontSize
	Write-Host "`tFontWeight =" $settings.FontWeight
	Write-Host "`tHistoryBufferSize =" $settings.HistoryBufferSize
	Write-Host "`tHistoryNoDup =" $settings.HistoryNoDup
	Write-Host "`tInsertMode =" $settings.InsertMode
	Write-Host "`tQuickEdit =" $settings.QuickEdit
	Write-Host "`tScreenColors =" $settings.ScreenColors
	Write-Host "`tWindowPosition =" $settings.WindowPosition

	New-ItemProperty -Path $regPath -Name FaceName -Value $settings.FaceName -Force | Out-Null
	New-ItemProperty -Path $regPath -Name FontFamily -Value $settings.FontFamily -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name FontSize -Value $settings.FontSize -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name FontWeight -Value $settings.FontWeight -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name HistoryBufferSize -Value $settings.HistoryBufferSize -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name HistoryNoDup -Value $settings.HistoryNoDup -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name InsertMode -Value $settings.InsertMode -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name QuickEdit -Value $settings.QuickEdit -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name ScreenColors -Value $settings.ScreenColors -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $regPath -Name WindowPosition -Value $settings.WindowPosition -PropertyType DWORD -Force | Out-Null
}

If ($UpdateShortcuts)
{
	$objShell = New-Object -ComObject Wscript.Shell
	$shortcuts | ForEach-Object {

		$shortcutPath = $_

		If ((Test-Path -Path $shortcutPath -PathType Leaf) -and (($isPC -or $isVM) -or ($isSAW -and $shortcutPath.StartsWith($env:USERPROFILE))))
		{
			# Copy instead of rename as renaming creates orphaned Start Menu/Taskbar links
			Write-Host "`nBackup: $shortcutPath.bak"
			Copy-Item -Path $shortcutPath -Destination "$shortcutPath.bak" -Force

			# If $BackupShortcuts is true, check that the backup was created before removing the existing one
			Write-Host "Remove: $shortcutPath"
			Remove-Item -Path $shortcutPath -Force -ErrorAction SilentlyContinue

			Write-Host "Create: $shortcutPath"
			$shortCut = $objShell.CreateShortCut($shortcutPath)

			if ($shortcutPath.EndsWith('PowerShell 7 (x64).lnk'))
			{
				$shortCut.Description = 'PowerShell 7 (x64)'
				$shortCut.TargetPath = '%ProgramFiles%\PowerShell\7\pwsh.exe'
				$shortCut.Arguments = '-NoLogo'
			}
			elseif ($shortcutPath.EndsWith('PowerShell 7-preview (x64).lnk'))
			{
				$shortCut.Description = 'PowerShell 7-preview (x64)'
				$shortCut.TargetPath = '%ProgramFiles%\PowerShell\7-preview\pwsh.exe'
				$shortCut.Arguments = '-NoLogo'
			}
			elseif ($shortcutPath.EndsWith('Windows PowerShell.lnk'))
			{
				$shortCut.Description = 'Windows PowerShell'
				$shortCut.TargetPath = '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe'
				$shortCut.Arguments = '-NoLogo'
			}
			elseif ($shortcutPath.EndsWith('Windows PowerShell (x86).lnk'))
			{
				$shortCut.Description = 'Windows PowerShell (x86)'
				$shortCut.TargetPath = '%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
				$shortCut.Arguments = '-NoLogo'
			}
			elseif ($shortcutPath.EndsWith('Command Prompt.lnk'))
			{
				$shortCut.Description = 'Command Prompt'
				$shortCut.TargetPath = '%windir%\system32\cmd.exe'
			}

			$shortCut.WindowStyle = 1 # 1 = Normal
			$shortCut.Save()

			If ($KeepBackupShortcuts -eq $false)
			{
				If (Test-Path -Path "$shortcutPath.bak")
				{
					Write-Host "Remove: $shortcutPath.bak"
					Remove-Item -Path "$shortcutPath.bak" -Force
				}
			}
		}
	}
}

$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
Out-Log "$scriptName duration: $scriptDuration"
