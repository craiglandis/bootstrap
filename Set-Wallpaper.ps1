# \\tsclient\c\onedrive\my\set-wallpaper.ps1
<#
    To prevent the wallpaper change roaming to other machines:

    Settings, Account, Sync your settings, set Theme to Off

    If Theme is On, Windows will automatically sync the wallpaper to other machines, the file will be here:

    C:\Users\<user>\AppData\Local\Microsoft\Windows\Themes\RoamedThemeFiles\DesktopBackground

    The wallpaper file created by this script is written to:

    c:\windows\web\wallpaper\<computername>_custom_wallpaper.jpg"
#>
param(
	[ValidateSet('left', 'right')]
	[string]
	$justify,
	[switch]$blank,
	[int]$fontSize = 22,
	[switch]$oemBackground
)

function GetRegKey($strKey)
{
	$arrOutput += ' '
	$arrOutput += $strkey.Replace(':', '\')
	if (Test-Path $strKey)
	{
		# Event empty keys have a value named "(default)". May need to improve this check later if anything actually uses the (default) value
		$objkey = Get-Item $strKey
		if ($objkey.ValueCount -gt 1)
		{
			$objkey | Select-Object * -ExpandProperty property | ForEach-Object {$arrOutput += (Pad $_ 25 $PADRIGHT) + ' ' + (Pad (GetRegValueType $objkey.GetValueKind($_)) 15 $PADRIGHT) + ' ' + (Get-ItemProperty $strkey).$_}
		}
		Else
		{
			$arrOutput += '<key exists but has no values>'
			# There is always a (default) value, but I'm not yet checking for anything that puts any value data in it that we care about reporting.
			# (get-itemproperty "HKLM:SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps")."(default)"
		}
	}
	Else
	{
		$arrOutput += '<key does not exist>'
	}
}

function GetRegValueType($strValueType)
{
	switch ($strValueType.ToString().ToUpper())
	{
		'STRING' {Return 'REG_SZ'}
		'BINARY' {Return 'REG_BINARY'}
		'DWORD' {Return 'REG_DWORD'}
		'QWORD' {Return 'REG_QWORD'}
		'EXPANDSTRING' {Return 'REG_EXPAND_SZ'}
		'MULTISTRING' {Return 'REG_MULTI_SZ'}
	}
}

function Add-Padding
{
	param(
		[string]$text,
		[int]$length,
		[string]$align
	)
	$numSpaces = $length - $text.Length
	if ($numSpaces -gt 0)
	{
		if ($align -eq 'left')
		{
			$text = ((' ' * $numSpaces) + $text)
		}
		else
		{
			$text = ($text + (' ' * $numSpaces))
		}
	}
	return $text
}

function get-osdetails
{
	$arrOutput = @()
	$win32_OperatingSystem = Get-CimInstance -Query 'SELECT * From Win32_OperatingSystem'
	$win32_ComputerSystem = Get-CimInstance -Query 'SELECT Name, Manufacturer, Model, SystemType, TotalPhysicalMemory, UserName, DaylightInEffect FROM Win32_ComputerSystem'
	$win32_PageFileUsage = Get-CimInstance -Query 'SELECT Caption FROM Win32_PageFileUsage'
	$win32_Processor = Get-CimInstance -Query 'SELECT * FROM Win32_Processor'
	$win32_BIOS = Get-CimInstance -Query 'SELECT Manufacturer, Version, SMBIOSPresent, SMBIOSBIOSVersion, ReleaseDate, SMBIOSMajorVersion, SMBIOSMinorVersion, BIOSVersion FROM Win32_BIOS'
	$win32_TimeZone = Get-CimInstance -Query 'SELECT StandardName FROM Win32_TimeZone'

	$processorName = $win32_Processor.name.Replace('Intel(R) Core(TM) ', '').Split(' ')[0]
	$maxClockSpeed = ('@ ' + [string][math]::Round($win32_Processor.MaxClockSpeed / 1000, 2) + 'Ghz')
	$cores = "$($win32_Processor.NumberOfCores) physical/$($win32_Processor.NumberOfLogicalProcessors) logical"
	$processor = "$processorName $maxClockSpeed $cores"

	$systemDrive = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $env:systemdrive + "'")
	$free = [math]::round($systemDrive.FreeSpace / 1GB, 0)
	$size = [math]::round($systemDrive.Size / 1GB, 0)
	#$used = $size-$free
	$letter = $systemDrive.DeviceID
	$systemDrive = "$letter $($size)GB ($($free)GB Free)"
	$version = $win32_OperatingSystem.Version
	$caption = $win32_OperatingSystem.Caption
	<#
    if ($caption -match 'Server')
    {
        $caption = 'Windows Server'
    }
    elseif ($caption -match 'Windows 10')
    {
        $caption = 'Windows 10'
    }
	#>

	$ErrorActionPreference = 'SilentlyContinue'
	$buildNumber = [environment]::osversion.version.build
	if ($buildNumber -ge 14393)
	{
		$releaseId = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseId -ErrorAction SilentlyContinue
		$displayVersion = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue
	}
	$ErrorActionPreference = 'Continue'

	if ($releaseId -and $displayVersion)
	{
		$osVersion = "$caption $displayVersion $releaseId $version"
	}
	else
	{
		$osVersion = "$caption $version"
	}

	$freePhysicalMemory = $win32_OperatingSystem.FreePhysicalMemory
	$totalVirtualMemorySize = $win32_OperatingSystem.TotalVirtualMemorySize
	$sizeStoredInPagingFiles = $win32_OperatingSystem.SizeStoredInPagingFiles
	$freeVirtualMemory = $win32_OperatingSystem.FreeVirtualMemory

	$computerName = $env:computername
	$userName = "$env:userdomain\$env:username"

	$ram = ([string]([math]::round([Int64]$win32_ComputerSystem.TotalPhysicalMemory / 1GB, 0)) + 'GB')
	$strPageFile = $win32_PageFileUsage.Caption
	$timeZone = $win32_TimeZone.StandardName
	#$processor = $win32_Processor.Name
	#$processor = $processor -replace ' {2,}',' ' # Removes duplicate spaces
	$biosManufacturer = $win32_BIOS.Manufacturer
	$biosVersion = $win32_BIOS.SMBIOSBIOSVersion
	$biosReleaseDate = $win32_BIOS.ReleaseDate
	$strBIOSVersion = "$biosManufacturer $biosVersion $biosReleaseDate"
	#$biosMinorVersion = [string]$win32_BIOS.SMBIOSMinorVersion
	#$biosMajorVersion = [string]$win32_BIOS.SMBIOSMajorVersion
	#$strSMBIOSVersion = [string]$win32_BIOS.SMBIOSMajorVersion + "." + [string]$win32_BIOS.SMBIOSMinorVersion

	$containerId = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -Name 'VirtualMachineName'
	if (!$containerId)
	{
		$containerId = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\GuestAgent' -Name 'ContainerId'
	}
	$incarnation = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\GuestAgent' -Name 'Incarnation'
	$heartbeatLastStatusUpdateTime = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\GuestAgent' -Name 'HeartbeatLastStatusUpdateTime'

	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
	$apiVersions = Invoke-RestMethod -Headers @{'Metadata' = 'true'} -Method GET -Proxy $null -Uri 'http://169.254.169.254/metadata/versions' | Select-Object -ExpandProperty apiVersions
	$apiVersion = $apiVersions[-1]
	$metadata = Invoke-RestMethod -Headers @{'Metadata' = 'true'} -Method GET -Proxy $null -Uri "http://169.254.169.254/metadata/instance?api-version=$apiVersion"
	if ($metadata)
	{
		$subscriptionId = $metadata.compute.subscriptionId
		$resourceGroupName = $metadata.compute.resourceGroupName
		$location = $metadata.compute.location
		$vmSize = $metadata.compute.vmSize
		$vmId = $metadata.compute.vmId
		$publisher = $metadata.compute.publisher
		$offer = $metadata.compute.offer
		$sku = $metadata.compute.sku
		$version = $metadata.compute.version
		$imageReferenceId = $metadata.compute.storageProfile.imageReference.id
		if ($publisher)
		{
			$imageReference = "$publisher|$offer|$sku|$version"
		}
		else
		{
			$imageReference = "$($imageReferenceId.Split('/')[-1]) (custom image)"
		}
		$privateIpAddress = $metadata.network.interface | Select-Object -First 1 | Select-Object -ExpandProperty ipv4 -First 1 | Select-Object -ExpandProperty ipAddress -First 1 | Select-Object -ExpandProperty privateIpAddress -First 1
		#$publicIpAddress = $metadata.network.interface | select -first 1 | select -ExpandProperty ipv4 -first 1 | select -ExpandProperty ipAddress -first 1 | select -ExpandProperty publicIpAddress -first 1
		$publicIpAddress = (Invoke-RestMethod -Uri https://checkip.amazonaws.com).Trim()
	}

	$length = 25
	$arrOutput += (Add-Padding -text "computerName: " -length $length -align left) + $computerName
	$arrOutput += (Add-Padding -text "osVersion: " -length $length -align left) + $osVersion
	$arrOutput += (Add-Padding -text "image: " -length $length -align left) + $imageReference
	$arrOutput += (Add-Padding -text "vmSize: " -length $length -align left) + $vmSize
	$arrOutput += (Add-Padding -text "cpu: " -length $length -align left) + $processor
	$arrOutput += (Add-Padding -text "ram: " -length $length -align left) + $ram
	$arrOutput += (Add-Padding -text "guestAgentVersion: " -length $length -align left) + $incarnation
	#$arrOutput += (Add-Padding -text "guestAgentLastHeartbeat: " -length $length -align left) + $heartbeatLastStatusUpdateTime
	$arrOutput += (Add-Padding -text "vmId: " -length $length -align left) + $vmId
	$arrOutput += (Add-Padding -text "containerId: " -length $length -align left) + $containerId
	$arrOutput += (Add-Padding -text "resourceGroupName: " -length $length -align left) + $resourceGroupName
	$arrOutput += (Add-Padding -text "subscriptionId: " -length $length -align left) + $subscriptionId
	$arrOutput += (Add-Padding -text "location: " -length $length -align left) + $location
	$arrOutput += (Add-Padding -text "privateIpAddress: " -length $length -align left) + $privateIpAddress
	$arrOutput += (Add-Padding -text "publicIpAddress: " -length $length -align left) + $publicIpAddress

	return $arrOutput
	#$global:o = $output
	#return $output #$outputString
}

function Update-Image($array)
{
	$longestString = $null
	$array | ForEach-Object {if ($_.Length -gt $longestString.Length) {$longestString = $_}}
	$columnWidth = [Windows.Forms.TextRenderer]::MeasureText($longestString, $font).Width

	if ($justify -eq 'left')
	{
		$horizontalPosition = 100
	}
	else
	{
		$horizontalPosition = ($workingAreaWidth - ($columnWidth + 50))
	}

	$verticalPosition = 40
	foreach ($item in $array)
	{
		# Create second column if first column is full
		# if this line is going off the screen...$fontHeight
		if ($verticalPosition -ge ($workingAreaHeight - 14))
		{
			# Then reset the vertical position back to the top
			$verticalPosition = 20
			# And move the horizontal position to the right
			$horizontalPosition += ($columnWidth + 40)
		}
		if ($item -match 'computername')
		{
			$image.DrawString($item, $font, (New-Object Drawing.SolidBrush('Cyan')), $horizontalPosition, $verticalPosition)
		}
		else
		{
			$image.DrawString($item, $font, (New-Object Drawing.SolidBrush('White')), $horizontalPosition, $verticalPosition)
		}

		# This controls the spacing between each line. Even without adding 1 to the height there is no overlap, but it looked too cramped that way.
		$verticalPosition += $fontHeight + 5
	}
}

function Save-Image
{
	$file = "$env:windir\web\wallpaper\$($env:computername)_custom_wallpaper.jpg"
	Remove-Item -Path $file -ErrorAction SilentlyContinue

	# XP/2003 require BMP for wallpaper and will convert from JPG to BMP on the fly if you right-click a JPG and select Set as Desktop Background.
	# JPEGs are a few hundred KB as compared to 10+ MB for BMP files in my testing, so it is worth it to special-case XP/2003 and only write BMP files for them and JPEGs on Vista+
	#$buildNumber = (Get-CimInstance Win32_OperatingSystem).BuildNumber
	$buildNumber = [environment]::osversion.version.build
	if ($buildNumber -ge 7600)
	{
		$bmpFile.Save($file, [System.Drawing.Imaging.ImageFormat]::jpeg)
		Write-Debug "oemBackground: $oemBackground"
		if ($oemBackground)
		{
			Write-Debug "BuildNumber: $buildNumber, attempting to set LogonUI background"
			# Requires elevation
			Set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background' -Name OEMBackground -Value 1 -type DWORD
			Write-Debug (Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background' -Name OEMBackground)

			$logonUIBackground = ($env:windir + '\System32\OOBE\info\Backgrounds\backgroundDefault.jpg')
			# PNG was 175KB, but JPEG was 266KB and would not display as the logon background (no error, just reverts to default logon background)
			#$bmpFile.Save($logonUIBackground, [System.Drawing.Imaging.ImageFormat]::jpeg)
			$encoderParameters = New-Object Drawing.Imaging.EncoderParameters
			# Informal testing showed 50% quality is a good balance of image size (trying to keep it below 256K else it will not display on LogonUI background) and readability.
			# Image size doesn't matter for the desktop background, only logon background has the 256K limit.
			$imageQuality = 100
			$imageSizeTooBig = $true
			do
			{
				$encoderParameters.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]$imageQuality)
				# From testing and looking online, you can't change the color depth of a JPEG file. And I wasn't getting it to work with BMP files either.
				# $encoderParameters.Param[1] = new-object Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::ColorDepth, [long]4)
				$JPEGCodec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.FormatDescription -eq 'JPEG'}
				$bmpFile | Get-Member
				$bmpFile.Save($logonUIBackground, $JPEGCodec, $encoderParameters)
				# http://msdn.microsoft.com/en-us/library/ff795022(v=winembedded.60).aspx
				if ((Get-ChildItem $logonUIBackground).Length -gt 256000)
				{
					Write-Host ('backgroundDefault.jpg needs to be 256000 bytes or less but it is ' + (Get-ChildItem $logonUIBackground).Length)
					$imageQuality -= 5
				}
				Else
				{
					$imageSizeTooBig = $false
					"ImageQuality = $imageQuality"
					('Image size   = ' + (Get-ChildItem $logonUIBackground).Length)
				}
			}
			while ($imageSizeTooBig)
		}
	}
	elseif ($buildNumber -ge 6000)
	{
		$bmpFile.Save($file, [System.Drawing.Imaging.ImageFormat]::jpeg)
	}
	else
	{
		$bmpFile.Save($file, [System.Drawing.Imaging.ImageFormat]::bmp)
	}
	$bmpFile.Dispose()

	$type = Add-Type -MemberDefinition $signature -Name Win32Utils -Namespace SystemParametersInfo -PassThru -ErrorAction SilentlyContinue
	$null = $type::SystemParametersInfo(20, 0, $file, 3)
}

function Main
{
	# Using .NET to get the resolution instead of WMI so far has worked reliably in all cases - RDP and console, 2003 and Win7.
	[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
	$boundsWidth = [Windows.Forms.Screen]::PrimaryScreen.Bounds.Width
	$boundsHeight = [Windows.Forms.Screen]::PrimaryScreen.Bounds.Height
	$workingAreaWidth = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width
	$workingAreaHeight = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height

	[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

	$bmpFile = New-Object System.Drawing.Bitmap($boundsWidth, $boundsHeight)
	$image = [System.Drawing.Graphics]::FromImage($bmpFile)
	# SmoothingMode makes no difference for text on a single color background, so set it to None
	$image.SmoothingMode = 'None'
	# TextRenderingHint is what matters in this scenario, and my testing showed ClearTypeGridFit looked best
	$image.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

	$rectangle = New-Object Drawing.Rectangle 0, 0, $workingAreaWidth, $workingAreaHeight
	$image.DrawImage($bmpFile, $rectangle, 0, 0, $workingAreaWidth, $workingAreaHeight, ([Drawing.GraphicsUnit]::Pixel))

	$font = New-Object System.Drawing.Font('Lucida Console', $fontSize)
	$fontWidth = [Windows.Forms.TextRenderer]::MeasureText('A', $font).Width
	$fontHeight = [Windows.Forms.TextRenderer]::MeasureText('A', $font).Height

	if ($blank)
	{
		Update-Image('')
	}
	else
	{
		Update-Image(get-osdetails)
	}
	Save-Image
}

$signature = @'
[DllImport("user32.dll")]
public static extern uint SystemParametersInfo(
    uint uiAction,
    uint uiParam,
    string pvParam,
    uint fWinIni);
'@

Main