<#
Set-ExecutionPolicy Bypass -Force
md c:\my
Invoke-WebRequest -Uri https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Wallpaper.ps1 -OutFile c:\my\Set-Wallpaper.ps1
c:\my\Set-Wallpaper.ps1

copy \\tsclient\c\src\bootstrap\set-wallpaper.ps1 c:\my\Set-Wallpaper.ps1;c:\my\Set-Wallpaper.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
	[string]$path = 'c:\my',
	[int]$fontSize = 22,
	[ValidateSet('left', 'right')]
	[string]
	$justify,
	[switch]$noweather,
	[switch]$addScheduledTask,
	[switch]$showDisconnects
)

trap
{
    $trappedError = $PSItem
    $global:trappedError = $trappedError
    $scriptLineNumber = $trappedError.InvocationInfo.ScriptLineNumber
    $line = $trappedError.InvocationInfo.Line.Trim()
    $exceptionMessage = $trappedError.Exception.Message
    $trappedErrorString = $trappedError.Exception.ErrorRecord | Out-String -ErrorAction SilentlyContinue
    Out-Log "[ERROR] $exceptionMessage Line $scriptLineNumber $line" -color Red
    exit
}

function Out-Log
{
    param(
        [string]$text,
        [switch]$verboseOnly,
        [string]$prefix,
        [switch]$raw,
        [switch]$logonly,
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [string]$color = 'White'
    )
    if ($verboseOnly)
    {
        if ($verbose)
        {
            $outputNeeded = $true
            $foreGroundColor = 'Yellow'
        }
        else
        {
            $outputNeeded = $false
        }
    }
    else
    {
        $outputNeeded = $true
        $foreGroundColor = 'White'
    }

    if ($outputNeeded)
    {
        if ($raw)
        {
            if ($logonly)
            {
                if ($logFilePath)
                {
                    $text | Out-File $logFilePath -Append
                }
            }
            else
            {
                Write-Host $text -ForegroundColor $color
                if ($logFilePath)
                {
                    $text | Out-File $logFilePath -Append
                }
            }
        }
        else
        {
            if ($prefix -eq 'timespan' -and $global:scriptStartTime)
            {
                $timespan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
                $prefixString = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan
            }
            elseif ($prefix -eq 'both' -and $global:scriptStartTime)
            {
                $timestamp = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
                $timespan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
                $prefixString = "$($timestamp) $('{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f $timespan)"
            }
            else
            {
                $prefixString = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
            }

            if ($logonly)
            {
                if ($logFilePath)
                {
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
            else
            {
                Write-Host $prefixString -NoNewline -ForegroundColor Cyan
                Write-Host " $text" -ForegroundColor $color
                if ($logFilePath)
                {
                    "$prefixString $text" | Out-File $logFilePath -Append
                }
            }
        }
    }
}

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Out-Log $command -logonly
    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        $global:errorRecordObject = $PSItem
        Out-Log "`n$command`n" -raw -color Red
        Out-Log "$global:errorRecordObject" -raw -color Red
        if ($LASTEXITCODE)
        {
            Out-Log "`$LASTEXITCODE: $LASTEXITCODE`n" -raw -color Red
        }
    }
}

function Get-CustomDateTimeString
{
	param(
		$dateTime,
		[switch]$timeFirst
	)
	if ($dateTime)
	{
		$shortTimeString = $dateTime.ToString('h:mmtt')
		$abbreviatedDayOfWeek = $dateTime.ToString('ddd')
		$abbreviatedMonthName = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName($dateTime.Month)
		$day = $dateTime.ToString('dd')
		if ($timeFirst)
		{
			$customDateTimeString = "$shortTimeString $abbreviatedDayOfWeek $abbreviatedMonthName $day"
		}
		else
		{
			$customDateTimeString = "$abbreviatedDayOfWeek $abbreviatedMonthName $day $shortTimeString"
		}
		return $customDateTimeString
	}
}

function Get-Age
{
	param(
		[datetime]$start,
		[datetime]$end = (Get-Date)
	)

	$timespan = New-TimeSpan -Start $start -End $end
	$years = [Math]::Round($timespan.Days / 365, 1)
	$months = [Math]::Round($timespan.Days / 30, 1)
	$days = $timespan.Days
	$hours = $timespan.Hours
	$minutes = $timespan.Minutes
	$seconds = $timespan.Seconds

	if ($years -gt 1)
	{
		$age = "$years years"
	}
	elseif ($years -eq 1)
	{
		$age = "$years year"
	}
	elseif ($months -gt 1)
	{
		$age = "$months months"
	}
	elseif ($months -eq 1)
	{
		$age = "$months month"
	}
	elseif ($days -gt 1)
	{
		$age = "$days days"
	}
	elseif ($days -eq 1)
	{
		$age = "$days day"
	}
	elseif ($hours -gt 1)
	{
		$age = "$hours hrs"
	}
	elseif ($hours -eq 1)
	{
		$age = "$hours hr"
	}
	elseif ($minutes -gt 1)
	{
		$age = "$minutes mins"
	}
	elseif ($minutes -eq 1)
	{
		$age = "$minutes min"
	}
	elseif ($seconds -gt 1)
	{
		$age = "$seconds secs"
	}
	elseif ($seconds -eq 1)
	{
		$age = "$seconds sec"
	}

	if ($age)
	{
		return $age
	}
}

function Test-Port
{
	param(
		[string]$ipAddress,
		[int]$port,
		[int]$timeout = 1000
	)
	<#
    Use TCPClient .NET class since Test-NetConnection cmdlet does not support setting a timeout
    Equivalent Test-NetConnection command (except no timeout since it doesn't support timeouts):
    Test-NetConnection -ComputerName $wireServer -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
    #>
	$tcpClient = New-Object System.Net.Sockets.TCPClient
	$connect = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
	$wait = $connect.AsyncWaitHandle.WaitOne($timeout, $false)

	$result = [PSCustomObject]@{
		Succeeded = $null
		Error     = $null
	}

	if ($wait)
	{
		try
		{
			$tcpClient.EndConnect($connect)
		}
		catch [System.Net.Sockets.SocketException]
		{
			$testPortError = $_
			$result.Succeeded = $false
			$result.Error = $testPortError
			return $result
		}

		if ([bool]$testPortError -eq $false)
		{
			$result.Succeeded = $true
			return $result
		}
	}
	else
	{
		$result.Succeeded = $false
		return $result
	}
	$tcpClient.Close()
	$tcpClient.Dispose()
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

$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptFolderPath = Split-Path -Path $scriptFullName
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

$currentPSDefaultParameterValues = $PSDefaultParameterValues
if ($currentPSDefaultParameterValues)
{
	Remove-Variable -Name PSDefaultParameterValues -Scope Global -ErrorAction SilentlyContinue
}
$PSDefaultParameterValues = @{
	'*:ErrorAction'   = 'Stop'
	'*:WarningAction' = 'SilentlyContinue'
}
$ProgressPreference = 'SilentlyContinue'

$verbose = [bool]$PSBoundParameters['verbose']
$debug = [bool]$PSBoundParameters['debug']

$logFilePath = "$env:TEMP\$scriptBaseName.log"
$logFile = Get-Item -Path $logFilePath -ErrorAction SilentlyContinue
if ($logFile -and $logFile.Length -ge 10MB)
{
	$logFile | Remove-Item
}

Out-Log "Getting system information"

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$isRdpSession = [System.Windows.Forms.SystemInformation]::TerminalServerSession
$monitorCount = [System.Windows.Forms.SystemInformation]::MonitorCount
$workingArea = [System.Windows.Forms.SystemInformation]::WorkingArea
$userInteractive = [System.Windows.Forms.SystemInformation]::UserInteractive
$screenOrientation = [System.Windows.Forms.SystemInformation]::ScreenOrientation
$primaryMonitorSize = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize
$monitorsSameDisplayFormat = [System.Windows.Forms.SystemInformation]::MonitorsSameDisplayFormat
$network = [System.Windows.Forms.SystemInformation]::Network
Out-Log "ComputerName: $env:computername, Monitors: $monitorCount, MonitorsSameDisplayFormat: $monitorsSameDisplayFormat, screenOrientation: $screenOrientation, userInteractive: $userInteractive" -verboseOnly

# 'Get-CimInstance -Query "SELECT Property1,Property FROM Win32_Something"' is slightly faster than 'Get-CimInstance -ClassName Win32_Something -Property Property,Property2'
$win32_SystemEnclosure = Get-CimInstance -Query 'SELECT ChassisTypes,Manufacturer,SerialNumber,Version FROM Win32_SystemEnclosure'
# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure
# 9='Laptop' 10='Notebook' 31='Convertible'
if ($win32_SystemEnclosure.ChassisTypes -in '9','10','31')
{
	$deviceType = 'Laptop'
	$isLaptop = $true
}
else
{
	$deviceType = 'Desktop'
	$isDesktop = $true
}

$vmBusStatus = Get-Service -Name vmbus | Select-Object -ExpandProperty Status
if ($vmBusStatus -eq 'Running')
{
	$deviceType = 'Virtual Machine'
	$isVm = $true
	$isPhysicalMachine = $false
}
else
{
	$isVm = $false
	$isPhysicalMachine = $true
}

if ($isPhysicalMachine -and $noweather -eq $false -and $isRdpSession -eq $false)
{
	# $weather = Invoke-RestMethod -Uri 'https://wttr.in/?1FQT' -ErrorAction SilentlyContinue
	# https://github.com/chubin/wttr.in#one-line-output
	$weather = Invoke-RestMethod -Uri 'https://wttr.in/?format=3' -ErrorAction SilentlyContinue
}

$win32_BaseBoard = Get-CimInstance -Query 'SELECT Product,Manufacturer FROM Win32_BaseBoard'
$win32_OperatingSystem = Get-CimInstance -Query 'SELECT Caption,FreePhysicalMemory,FreeVirtualMemory,InstallDate,LastBootUpTime,SizeStoredInPagingFiles,TotalVirtualMemorySize,Version FROM Win32_OperatingSystem'
$win32_ComputerSystem = Get-CimInstance -Query 'SELECT DaylightInEffect,HypervisorPresent,Name,Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory,UserName FROM Win32_ComputerSystem'
$win32_PageFileUsage = Get-CimInstance -Query 'SELECT Caption FROM Win32_PageFileUsage'
$win32_Processor = Get-CimInstance -Query 'SELECT Name,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors FROM Win32_Processor'
$cpuProductName = $win32_Processor.Name.Split(' ')[-1].Trim()
$cpuProductName = $win32_Processor.Name.Split('@')[0].Replace('(R)', '').Replace('(TM)', '').Replace('  ', ' ').Split(' ')[-1].Trim()
# $cpuProductName = $win32_Processor.Name.Split(' ') | Where-Object {$_ -match '-'}

# https://github.com/toUpperCase78/intel-processors
$intelCpusCsvUrl = 'https://raw.githubusercontent.com/toUpperCase78/intel-processors/master/intel_core_processors_v1_6.csv'
$intelCpusCsvName = Split-Path -Path $intelCpusCsvUrl -Leaf
$intelCpusCsvPath = "$env:TEMP\$intelCpusCsvName"
if ((Test-Path -Path $intelCpusCsvPath) -eq $false)
{
	Out-Log "Downloading $intelCpusCsvUrl" -verboseOnly
    (New-Object Net.Webclient).DownloadFile($intelCpusCsvUrl, $intelCpusCsvPath)
}
$intelCpuSpecs = Import-Csv -Path $intelCpusCsvPath -ErrorAction SilentlyContinue
if ($intelCpuSpecs)
{
	$cpuSpecs = $intelCpuSpecs | Where-Object {$_.Product.Split(' ')[-1] -eq $cpuProductName}
	if ($cpuSpecs)
	{
		$cores = "$($cpuSpecs.Cores)C"
		$threads = "$($cpuSpecs.Threads)T"
		$cpuBaseFreqGhz = "$($cpuSpecs.'Base Freq.(GHz)')GHz"
		$cpuMaxTurboFreqGhz = "$($cpuSpecs.'Max. Turbo Freq.(GHz)')GHz"
		$cpuCacheMB = "$($cpuSpecs.'Cache(MB)')MB"
		$cpuNodeSize = "$($cpuSpecs.'Lithography(nm)')nm"
		$cpuTdpWatts = "$($cpuSpecs.'TDP(W)')W"
		$cpu = "$cpuProductName $cores/$threads $cpuMaxTurboFreqGhz $cpuCacheMB $cpuNodeSize $cpuTdpWatts"
	}
}

if ([string]::IsNullOrEmpty($cpu))
{
	$cpuName = $win32_Processor.Name.Split('@')[0].Replace('(R)', '').Replace('(TM)', '').Replace('  ', ' ').Trim()
	$baseClock = $win32_Processor.MaxClockSpeed
	$baseClockString = (([Math]::Round($baseClock / 1000, 2)).ToString('0.00') + 'Ghz')
	$cores = $win32_Processor.NumberOfCores
	$threads = $win32_Processor.NumberOfLogicalProcessors
	$counter = '\Processor Information(_Total)\% Processor Performance'
	$processorPerformance = Get-Counter -Counter $counter | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
	$currentClock = [Math]::Round($baseClock * ($processorPerformance / 100) / 1000, 2)
	$currentClockString = ($currentClock.ToString('0.00') + 'Ghz')
	$cpu = "$cpuName $($cores)C/$($threads)T $baseClockString base $currentClockString current"
}

$win32_SystemDriver = Get-CimInstance -Query 'SELECT * FROM Win32_SystemDriver'

$win32_BIOS = Get-CimInstance -Query 'SELECT Manufacturer, Version, SMBIOSPresent, SMBIOSBIOSVersion, ReleaseDate, SMBIOSMajorVersion, SMBIOSMinorVersion, BIOSVersion FROM Win32_BIOS'
$win32_TimeZone = Get-CimInstance -Query 'SELECT StandardName FROM Win32_TimeZone'
$win32_PhysicalMemory = Get-CimInstance -Query 'SELECT Capacity,ConfiguredClockSpeed,Manufacturer,PartNumber,Speed FROM Win32_PhysicalMemory'
$win32_TPM = Get-CimInstance -Namespace root/cimv2/security/microsofttpm -Query 'SELECT IsEnabled_InitialValue,ManufacturerIdTxt,ManufacturerVersionInfo,ManufacturerVersion,SpecVersion FROM Win32_TPM'
if ($win32_TPM)
{
	$tpmIsEnabled = $win32_TPM.IsEnabled_InitialValue
	$tpmManufacturerVersionInfo = $win32_TPM.ManufacturerVersionInfo -replace "[^a-zA-Z0-9]", ''
	$tpmManufacturerVersion = $win32_TPM.ManufacturerVersion
	$tpmManufacturerId = $win32_TPM.ManufacturerIdTxt -replace "[^a-zA-Z0-9]", ''
	$tpmSpecVersion = $win32_TPM.SpecVersion
	$tpmString = "Enabled: $tmpIsEnabled $tpmManufacturerId $tpmManufacturerVersionInfo $tpmManufacturerVersion Version(s): $tpmSpecVersion"
	$tpmString = $tpmString -replace '\s+', ' '
}
$secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

$gpus = Get-CimInstance -Query 'SELECT AdapterCompatibility,CurrentHorizontalResolution,CurrentRefreshRate,CurrentVerticalResolution,DriverDate,DriverVersion,Name,PNPDeviceID FROM Win32_VideoController'
# Win32_VideoController AdapterRAM is wrong (shows 4GB for 4090 with 24GB) plus there's no native Windows way to get free/used VRAM
# But for NVIDIA cards, the NVIDIA driver installs nvidia-smi.exe, that can be used to get total/free/used VRAM
$hasNvidiaGPU = [bool]($gpus | Where-Object AdapterCompatibility -EQ 'NVIDIA')
if ($hasNvidiaGPU)
{
	$nvidiaSmiPath = "$env:SystemRoot\System32\nvidia-smi.exe"
	$hasNvidiaSmi = Test-Path -Path $nvidiaSmiPath -PathType Leaf
	if ($hasNvidiaSmi)
	{
		# "nvidia-smi --help-query-gpu" shows all possible valus to query
		# $vram = (nvidia-smi --query-gpu=memory.total,memory.used,memory.free --format=csv) | ConvertFrom-Csv
		$nvidiaSmiResult = nvidia-smi --query-gpu=memory.total,memory.used,memory.free,name,serial,uuid,pcie.link.gen.current,pcie.link.gen.gpumax,pcie.link.gen.hostmax,pcie.link.width.current,pcie.link.width.max,vbios_version,fan.speed,pstate,clocks_event_reasons.hw_thermal_slowdown,clocks_event_reasons.hw_power_brake_slowdown,clocks_event_reasons.sw_thermal_slowdown,utilization.gpu,utilization.memory,temperature.gpu,temperature.memory,power.management,power.draw,power.draw.average,power.draw.instant,power.limit,enforced.power.limit,power.default_limit,power.max_limit,clocks.current.graphics,clocks.current.memory,clocks.max.graphics,clocks.max.memory --format=csv
		$nvidiaSmiResult = $nvidiaSmiResult | ConvertFrom-Csv
		$global:dbgNvidiaSmiResult = $nvidiaSmiResult

		$pciLaneUsageCurrent = $nvidiaSmiResult.'pcie.link.width.current'
		$pciLaneUsageMax = $nvidiaSmiResult.'pcie.link.width.max'
		$gpuUtilization = $nvidiaSmiResult.'utilization.gpu [%]'.Replace(' %','%')
		$gpuMemoryUtilization = $nvidiaSmiResult.'utilization.memory [%]'.Replace(' %','%')
		$gpuFanSpeedPercent = $nvidiaSmiResult.'fan.speed [%]'.Replace(' %','%')
		$gpuTemperature = "$($nvidiaSmiResult.'temperature.gpu')C"
		$gpuPowerDraw = $nvidiaSmiResult.'power.draw [W]'.Replace(' W','W')
		$gpuPowerLimit = $nvidiaSmiResult.'power.limit [W]'.Replace(' W','W')
		$gpuInfo = "PCIE $pciLaneUsageCurrent/$pciLaneUsageMax GPU $gpuUtilization MEM $gpuMemoryUtilization FAN $gpuFanSpeedPercent TEMP $gpuTemperature DRAW $gpuPowerDraw LIMIT $gpuPowerLimit"

		$freeVram = "$([Math]::Round("$($nvidiaSmiResult.'memory.free [MiB]'.Replace(' MiB',''))MB"/1GB,0))GB"
		$usedVram = "$([Math]::Round("$($nvidiaSmiResult.'memory.used [MiB]'.Replace(' MiB',''))MB"/1GB,0))GB"
		$totalVram = "$([Math]::Round("$($nvidiaSmiResult.'memory.total [MiB]'.Replace(' MiB',''))MB"/1GB,0))GB"
		$vram = "$totalVram ($freeVram free)"
		$gpus | Where-Object AdapterCompatibility -EQ 'NVIDIA' | ForEach-Object {
			$_ | Add-Member -MemberType NoteProperty -Name VRAM -Value $vram -Force -ErrorAction SilentlyContinue
		}
	}
	else
	{
		Out-Log "NVIDIA GPU detected but $nvidiaSmiPath not found so VRAM details are not available" -verboseOnly
	}
}

# For non-NVIDIA GPUs, best we can get is total VRAM from the registry
$displayClassKey = Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
$displayClassSubkeyNames = $displayClassKey.GetSubKeyNames()
foreach ($displayClassSubkeyName in $displayClassSubkeyNames)
{
	$displayClassSubkey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\$displayClassSubkeyName" -ErrorAction SilentlyContinue
	$matchingDeviceId = $displayClassSubkey | Select-Object -ExpandProperty MatchingDeviceId -ErrorAction SilentlyContinue
	if ($matchingDeviceId)
	{
		$matchingDeviceId = $matchingDeviceId.ToUpper()
		$qwMemorySize = $displayClassSubkey.'HardwareInformation.qwMemorySize'
		if ($qwMemorySize)
		{
			$vram = "$([math]::round($displayClassSubkey.'HardwareInformation.qwMemorySize'/1GB))GB"
		}
		else
		{
			$vram = ''
		}
		$gpus | Where-Object {$_.PNPDeviceID.Contains($matchingDeviceId)} | ForEach-Object {
			$_ | Add-Member -MemberType NoteProperty -Name VRAM -Value $vram -ErrorAction SilentlyContinue
		}
	}
}

# Only get RAM details from physical machines as they are wrong when gotten from a VM
if ($isPhysicalMachine)
{
	$memoryModuleManufacturer = $win32_PhysicalMemory | Select-Object -ExpandProperty Manufacturer -Unique
	$memoryModuleCount = $win32_PhysicalMemory | Measure-Object | Select-Object -ExpandProperty Count
	$memoryModuleSize = $win32_PhysicalMemory | Select-Object -ExpandProperty Capacity -Unique
	$memoryModuleSizeGB = $memoryModuleSize/1GB
	$memoryModuleSpeed = $win32_PhysicalMemory | Select-Object -ExpandProperty Speed -Unique
	$memoryModuleConfiguredClockSpeed = $win32_PhysicalMemory | Select-Object -ExpandProperty ConfiguredClockSpeed -Unique
	$memoryModulePartNumber = $win32_PhysicalMemory | Select-Object -ExpandProperty PartNumber -Unique
}

$activePowerPlan = Get-CimInstance -Namespace root\cimv2\power -Query 'SELECT ElementName,InstanceID,IsActive FROM Win32_PowerPlan WHERE IsActive="True"'
$powerPlan = "$($activePowerPlan.ElementName) $($activePowerPlan.InstanceID.Replace('Microsoft:PowerPlan\',''))"

$msft_MpComputerStatus = Get-CimInstance -Query 'SELECT FullScanEndTime,QuickScanEndTime FROM MSFT_MpComputerStatus' -Namespace root/microsoft/windows/defender
$quickScanEndTime = $msft_MpComputerStatus.QuickScanEndTime
$fullScanEndTime = $msft_MpComputerStatus.FullScanEndTime
if ($quickScanEndTime)
{
	$quickScanEndTimeString = "$(Get-Age -Start $quickScanEndTime) ago $(Get-Date $quickScanEndTime -Format yyyy-MM-ddTHH:mm:ss)"
}
else
{
	$quickScanEndTimeString = 'Quick scan has yet to be run on this device'
}
if ($fullScanEndTimeString)
{
	$fullScanEndTimeString = "$(Get-Age -Start $fullScanEndTime) ago $(Get-Date $fullScanEndTime -Format yyyy-MM-ddTHH:mm:ss)"
}
else
{
	$fullScanEndTimeString = 'Full scan has yet to be run on this device'
}

$lastCumulativeUpdate = Get-WinEvent -FilterHashtable @{ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19} -ErrorAction SilentlyContinue | Where-Object {$_.KeywordsDisplayNames.Contains('Success')} | Where-Object {$_.Message.Contains('Cumulative Update for Windows')} | Sort-Object TimeCreated -Descending | Select-Object -First 1
if ($lastCumulativeUpdate)
{
	$lastCumulativeUpdateTime = $lastCumulativeUpdate.TimeCreated
	$lastCumulativeUpdateMessage = $lastCumulativeUpdate.Message
	$lastCumulativeUpdateMessage = $lastCumulativeUpdateMessage.Replace('Installation Successful: Windows successfully installed the following update:', '').Trim()
	$lastCumulativeUpdateString = "$(Get-Age $lastCumulativeUpdateTime) ago $(Get-Date $lastCumulativeUpdateTime -Format yyyy-MM-ddTHH:mm:ss) $lastCumulativeUpdateMessage"
}
else
{
	$lastCumulativeUpdateString = 'N/A'
}

$lastUpdateAccordingToWin32QuickFixEngineering = Get-CimInstance -Query 'Select InstalledOn,HotFixID,InstalledBy From Win32_QuickFixEngineering' | Sort-Object InstalledOn -Descending | Select-Object -First 1
$lastUpdateTimeAccordingToWin32QuickFixEngineering = Get-Date -Date $lastUpdateAccordingToWin32QuickFixEngineering.InstalledOn -Format yyyy-MM-ddTHH:mm:ss
$lastUpdateInstalledByAccordingToWin32QuickFixEngineering = $lastUpdateAccordingToWin32QuickFixEngineering.InstalledBy
$lastUpdateHotfixIdAccordingToWin32QuickFixEngineering = $lastUpdateAccordingToWin32QuickFixEngineering.HotFixID

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$historyCount = $searcher.GetTotalHistoryCount()
try {$queryHistoryResult = $searcher.QueryHistory(0, $historyCount)} catch {}
if ($queryHistoryResult)
{
	$lastUpdateAccordingToMicrosoftUpdateSession = $searcher.QueryHistory(0, $historyCount) | Sort-Object Date -Descending | Select-Object -First 1
	$lastUpdateTimeAccordingToMicrosoftUpdateSession = Get-Date -Date $lastUpdateAccordingToMicrosoftUpdateSession.Date.ToLocalTime() -Format yyyy-MM-ddTHH:mm:ss
	$lastUpdateTitleAccordingToMicrosoftUpdateSession = $lastUpdateAccordingToMicrosoftUpdateSession.Title
	$lastUpdateKBNumberAccordingToMicrosoftUpdateSession = (Select-String -InputObject $lastUpdateTitleAccordingToMicrosoftUpdateSession -Pattern 'KB\d{5,8}').Matches.Value.Trim()
	$lastUpdateAccordingToMicrosoftUpdateSessionString = "$(Get-Age $lastUpdateTimeAccordingToMicrosoftUpdateSession) ago $lastUpdateKBNumberAccordingToMicrosoftUpdateSession $lastUpdateTimeAccordingToMicrosoftUpdateSession (Microsoft.Update.Session)"
}
else
{
	$lastUpdateAccordingToMicrosoftUpdateSessionString = "N/A"
}

$autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
$lastUpdateTimeAccordingToMicrosoftUpdateAutoUpdate = Get-Date -Date $autoUpdate.Results.LastInstallationSuccessDate.ToLocalTime() -Format yyyy-MM-ddTHH:mm:ss
$lastCheckForUpdatesTimeAccordingToMicrosoftUpdateAutoUpdate = Get-Date -Date $autoUpdate.Results.LastSearchSuccessDate.ToLocalTime() -Format yyyy-MM-ddTHH:mm:ss

# For some reason in a fresh PS session sometimes running Get-MpComputerStatus twice is needed before the implicit module loading happens
# When it doesn't, it fails with error:
# The 'Get-MpComputerStatus' command was found in the module 'ConfigDefender', but the module could not be loaded. For more information, run 'Import-Module ConfigDefender'
try
{
	$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object FullScanAge, FullScanStartTime, AntispywareSignatureAge, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated, DeviceControlPoliciesLastUpdated, NISSignatureLastUpdated, QuickScanAge, QuickScanEndTime
}
catch
{
}

if (!$defender)
{
	$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object FullScanAge, FullScanStartTime, AntispywareSignatureAge, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated, DeviceControlPoliciesLastUpdated, NISSignatureLastUpdated, QuickScanAge, QuickScanEndTime
}

if ($defender)
{
	$defender = Get-MpComputerStatus | Select-Object FullScanAge, FullScanStartTime, AntispywareSignatureAge, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated, DeviceControlPoliciesLastUpdated, NISSignatureLastUpdated, QuickScanAge, QuickScanEndTime
	$antivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
	$lastAntiVirusSignatureUpdate = "$(Get-Age $antivirusSignatureLastUpdated) ago $(Get-Date $antivirusSignatureLastUpdated -Format yyyy-MM-ddTHH:mm:ss)"
}
else
{
	$lastAntiVirusSignatureUpdate = "N/A"
}

$newestAppLogEventTime = Get-Date
$oldestAppLogEventTime = Get-WinEvent -LogName Application -MaxEvents 1 -Oldest | Select-Object -ExpandProperty TimeCreated
$appLogTimespan = New-TimeSpan -Start $oldestAppLogEventTime -End $newestAppLogEventTime
$appLogTimespanDays = $appLogTimespan.Days
$oldestAppLogEventTimeString = Get-Date $oldestAppLogEventTime -Format yyyy-MM-dd
$appLogTimeRangeString = "goes back $appLogTimespanDays days to $oldestAppLogEventTimeString"

$newestSystemLogEventTime = Get-Date
$oldestSystemLogEventTime = Get-WinEvent -LogName System -MaxEvents 1 -Oldest | Select-Object -ExpandProperty TimeCreated
$systemLogTimespan = New-TimeSpan -Start $oldestSystemLogEventTime -End $newestSystemLogEventTime
$systemLogTimespanDays = $systemLogTimespan.Days
$oldestSystemLogEventTimeString = Get-Date $oldestSystemLogEventTime -Format yyyy-MM-dd
$systemLogTimeRangeString = "goes back $systemLogTimespanDays days to $oldestSystemLogEventTimeString"

$newestSecurityLogEventTime = Get-Date
$oldestSecurityLogEventTime = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest | Select-Object -ExpandProperty TimeCreated
$securityLogTimespan = New-TimeSpan -Start $oldestSecurityLogEventTime -End $newestSecurityLogEventTime
$securityLogTimespanDays = $securityLogTimespan.Days
$oldestSecurityLogEventTimeString = Get-Date $oldestSecurityLogEventTime -Format yyyy-MM-dd
$securityLogTimeRangeString = "goes back $securityLogTimespanDays days to $oldestSecurityLogEventTimeString"

$appLog = Get-WinEvent -ListLog Application
$appLogMode = $appLog.LogMode.ToString().ToLower()
$appLogFileSizeMB = [Math]::Round($appLog.FileSize / 1MB, 0)
$appLogMaxSizeMB = [Math]::Round($appLog.MaximumSizeInBytes / 1MB, 0)
$appLogRecordCount = $appLog.RecordCount.ToString('N0')
$appLogDetailsString = "$appLogRecordCount events, $($appLogFileSizeMB)/$($appLogMaxSizeMB)MB, $appLogMode, $appLogTimeRangeString"

$systemLog = Get-WinEvent -ListLog System
$systemLogMode = $systemLog.LogMode.ToString().ToLower()
$systemLogFileSizeMB = [Math]::Round($systemLog.FileSize / 1MB, 0)
$systemLogMaxSizeMB = [Math]::Round($systemLog.MaximumSizeInBytes / 1MB, 0)
$systemLogRecordCount = $systemLog.RecordCount.ToString('N0')
$systemLogDetailsString = "$systemLogRecordCount events, $($systemLogFileSizeMB)/$($systemLogMaxSizeMB)MB, $systemLogMode, $systemLogTimeRangeString"

$securityLog = Get-WinEvent -ListLog Security
$securityLogMode = $securityLog.LogMode.ToString().ToLower()
$securityLogFileSizeMB = [Math]::Round($securityLog.FileSize / 1MB, 0)
$securityLogMaxSizeMB = [Math]::Round($securityLog.MaximumSizeInBytes / 1MB, 0)
$securityLogRecordCount = $securityLog.RecordCount.ToString('N0')
$securityLogDetailsString = "$securityLogRecordCount events, $($securityLogFileSizeMB)/$($securityLogMaxSizeMB)MB, $securityLogMode, $securityLogTimeRangeString"

$lastBootUpTime = $win32_OperatingSystem.LastBootUpTime

$physicalNics = Get-NetAdapter -Physical | Select-Object InterfaceAlias,InterfaceDescription,InterfaceIndex,DriverDescription,DriverFileName,DriverDate,DriverVersionString,MacAddress,MediaConnectionState,NdisVersion,DriverInformation
$connectedPhysicalNics = $physicalNics | Where-Object MediaConnectionState -EQ 'Connected'
$ipConfigs = Get-NetIPConfiguration -Detailed
$ipV4Addresses = @()
foreach ($connectedPhysicalNic in $connectedPhysicalNics)
{
	foreach ($ipConfig in $ipConfigs)
	{
		if ($ipconfig.NetAdapter.LinkLayerAddress -eq  $connectedPhysicalNic.MacAddress)
		{
			$ipV4Addresses += $ipconfig.IPv4Address.IPAddress | Where-Object {$_.StartsWith('169.254') -eq $false}
		}
	}

	# -AddressState Preferred makes it so APIPA 169.254 addresses aren't returned, as they are -AddressState Tentative
	# $ipV4Addresses += Get-NetIPAddress -InterfaceIndex $physicalNic.InterfaceIndex -AddressFamily IPv4 -AddressState Preferred | Select-Object -ExpandProperty IPAddress
	# $ipV4Addresses += Get-NetIPAddress -InterfaceIndex $connectedPhysicalNic.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress
}
$ipV4AddressesString = $ipV4Addresses -join ','

if ($showDisconnects -and ($connectedPhysicalNics.DriverDescription -match 'I226' -or $connectedPhysicalNics.DriverDescription -match 'I225'))
{
	# This check for disconnects/idleworkingstate value is for the Intel i225-V/i226-V NICs
	# While I've added other NIC vendor's event providers to the query, they probably don't log a disconnect as Id 27 like Intel does
	# So I'll genericize this more as I come across how other NIC vendor's log disconnects
	$filterHashTable = @{
		LogName      = 'System'
		ProviderName = 'e2fnexpress', 'e2fexpress', 'e1i68x64', 'Netwtw10', 'rt68cx21', 'mlx4_bus', 'mlx4eth63', 'mlx5'
		Id           = 27
		#StartTime = (Get-Date).AddDays(-1)
		#EndTime = Get-Date
	}

	$disconnects = Get-WinEvent -FilterHashtable $filterHashTable -ErrorAction SilentlyContinue
	$disconnectCountLastDay = $disconnects | Measure-Object | Select-Object -ExpandProperty Count
	$lastNicDisconnectTime = $disconnects | Sort-Object TimeCreated -Descending | Select-Object -First 1 -ExpandProperty TimeCreated
	if ($lastNicDisconnectTime)
	{
		$timeSinceLastNicDisconnect = Get-Age $lastNicDisconnectTime
		$timeBetweenLastBootAndLastDisconnect = "$(Get-Age -Start $lastBootUpTime -End $lastNicDisconnectTime)"
		$disconnectsInfo = "$timeSinceLastNicDisconnect since last disconnect ($timeBetweenLastBootAndLastDisconnect after last boot), $disconnectCountLastDay disconnect(s) in last $(Get-Age $oldestSystemLogEventTime)"
	}
	else
	{
		$disconnectsInfo = "No disconnects in at least the last $(Get-Age $oldestSystemLogEventTime) (System log goes back to $(Get-Date $oldestSystemLogEventTime -Format yyyy-MM-ddTHH:mm:ss))"
	}
	$idleInWorkingState = Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Enum\PCI\VEN_8086&DEV_125C&SUBSYS_88671043&REV_06\581122FFFFB5FFBE00\Device Parameters\WDF' -Name IdleInWorkingState -ErrorAction SilentlyContinue
}

$checkIpUrl = 'https://checkip.amazonaws.com'
$checkIpResult = Invoke-RestMethod -Uri https://checkip.amazonaws.com
if ($checkIpResult)
{
	$wan = $checkIpResult.Trim()
}
$lan = (Get-NetIPAddress | Where-Object AddressFamily -EQ IPv4 | Where-Object PrefixOrigin -EQ Dhcp | Select-Object -First 1 -ExpandProperty IPAddress)
if ($isPhysicalMachine)
{
	$vpnName = 'MSFTVPN-Manual'
	$vpnConnections = Get-VpnConnection
	if ($vpnConnections -and $vpnConnections.Name -eq $vpnName)
	{
		$vpn = $vpnConnections | Where-Object Name -EQ $vpnName | Select-Object -ExpandProperty ConnectionStatus
		if ($vpn -eq 'Connected')
		{
			$vpnIpAddress = Get-NetIPAddress -InterfaceAlias $vpnName | Where-Object AddressFamily -EQ IPv4 | Select-Object -ExpandProperty IPAddress
			$vpn = $vpnIpAddress
		}
		else
		{
			$vpn = 'Not Connected'
		}
	}
}

if ($isPhysicalMachine)
{
	$PSNativeCommandUseErrorActionPreference = $false
	$lastBackupTime = wbadmin get versions | Select-String -SimpleMatch 'Backup time:' | Select-Object -ExpandProperty Line -Last 1
	$PSNativeCommandUseErrorActionPreference = $true
	if ($lastBackupTime)
	{
		$lastBackupTime = $lastBackupTime.Replace('Backup time: ', '').Trim()
		$lastBackupTime = "$(Get-Age -start $lastBackupTime) ago $(Get-Date $lastBackupTime -Format yyyy-MM-ddTHH:mm:ss)"
	}
}

$lastSystemCrash = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Level = 2; Id = 1001} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($lastSystemCrash)
{
	$signature = @{N = 'Signature'; E = {$_.properties[0].Value}}
	$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Age -Start $_.TimeCreated) ago: $($_.properties[0].Value)"}}
	$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
	$lastSystemCrash = $lastSystemCrash | Select-Object $timeCreated, $signature, $signatureWithTime
	$lastSystemCrashString = $lastSystemCrash | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
	$lastSystemCrashString = $lastSystemCrashString.Trim()
}
else
{
	$lastSystemCrashString = 'N/A No System log Event ID 1001 Microsoft-Windows-WER-SystemErrorReporting found'
}

$lastAppCrash = Get-WinEvent -FilterHashtable @{LogName = 'Application'; ProviderName = 'Application Error'; Level = 2; Id = 1000} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($lastAppCrash)
{
	$signature = @{N = 'Signature'; E = {"$($_.properties[6].Value) $($_.properties[0].value) $($_.properties[1].value) $($_.properties[3].value) $($_.properties[4].value)"}}
	$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Age -Start $_.TimeCreated) ago: $($_.properties[6].Value) $($_.properties[0].value) $($_.properties[1].value) $($_.properties[3].value) $($_.properties[4].value)"}}
	$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
	$lastAppCrash = $lastAppCrash | Select-Object $timeCreated, $signature, $signatureWithTime
	$lastAppCrashString = $lastAppCrash | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
	$lastAppCrashString = $lastAppCrashString.Trim()
}
else
{
	$lastAppCrashString = 'N/A No Application log Event ID 1000 Application Error found'
}

$lastHardwareError = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($lastHardwareError)
{
	$signature = @{N = 'Signature'; E = {$_.message.Replace("`r`n", ' ').Replace('  ', ' ').PadRight(80, ' ').SubString(0, 80)}}
	$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Age -Start $_.TimeCreated) ago: $($_.message.Replace("`r`n",' ').Replace('  ',' ').PadRight(80,' ').SubString(0,80))"}}
	$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
	$lastHardwareError = $lastHardwareError | Select-Object $timeCreated, $signature, $signatureWithTime
	$lastHardwareErrorString = $lastHardwareError | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
	$lastHardwareErrorString = $lastHardwareErrorString.Trim()
}
else
{
	$lastHardwareErrorString = 'N/A No System log Microsoft-Windows-WHEA-Logger events found'
}

$lastBadShutdown = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($lastBadShutdown)
{
	$signature = @{N = 'Signature'; E = {$_.message.Replace("`r`n", ' ').Replace('  ', ' ').PadRight(80, ' ').SubString(0, 80)}}
	$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Age -Start $_.TimeCreated) ago: $($_.message.Replace("`r`n",' ').Replace('  ',' ').PadRight(80,' ').SubString(0,80))"}}
	$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
	$lastBadShutdown = $lastBadShutdown | Select-Object $timeCreated, $signature, $signatureWithTime
	$lastBadShutdownString = $lastBadShutdown | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
	$lastBadShutdownString = $lastBadShutdownString.Trim()
}
else
{
	$lastBadShutdownString = 'N/A No System log Event ID 41 Microsoft-Windows-Kernel-Power found'
}

$lastCriticalSystemLogError = Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 1} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($lastCriticalSystemLogError)
{
	$signature = @{N = 'Signature'; E = {$_.message.Replace("`r`n", ' ').Replace('  ', ' ').PadRight(80, ' ').SubString(0, 80)}}
	$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Age -Start $_.TimeCreated) ago: $($_.message.Replace("`r`n",' ').Replace('  ',' ').PadRight(80,' ').SubString(0,80))"}}
	$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
	$lastCriticalSystemLogError = $lastCriticalSystemLogError | Select-Object $timeCreated, $signature, $signatureWithTime
	$lastCriticalSystemLogErrorString = $lastCriticalSystemLogError | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
	$lastCriticalSystemLogErrorString = $lastCriticalSystemLogErrorString.Trim()
}
else
{
	$lastCriticalSystemLogErrorString = 'N/A No critical (Level=1) System log events found'
}

$lastSystemLogError = Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 2} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($lastSystemLogError)
{
	$signature = @{N = 'Signature'; E = {$_.message.Replace("`r`n", ' ').Replace('  ', ' ').PadRight(80, ' ').SubString(0, 80)}}
	$signatureWithTime = @{N = 'SignatureWithTime'; E = {"$(Get-Age -Start $_.TimeCreated) ago: $($_.message.Replace("`r`n",' ').Replace('  ',' ').PadRight(80,' ').SubString(0,80))"}}
	$timeCreated = @{N = 'TimeCreated'; E = {Get-Date $_.TimeCreated -F yyyy-MM-ddTHH:mm:ss}}
	$lastSystemLogError = $lastSystemLogError | Select-Object $timeCreated, $signature, $signatureWithTime
	$lastSystemLogErrorString = $lastSystemLogError | Format-Table SignatureWithTime -HideTableHeaders -AutoSize | Out-String
	$lastSystemLogErrorString = $lastSystemLogErrorString.Trim()
}
else
{
	$lastSystemLogErrorString = 'N/A No error (Level=2) System log events found'
}

$netApi32MemberDefinition = @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public class NetAPI32{
    public enum DSREG_JOIN_TYPE {
      DSREG_UNKNOWN_JOIN,
      DSREG_DEVICE_JOIN,
      DSREG_WORKPLACE_JOIN
    }
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_USER_INFO {
        [MarshalAs(UnmanagedType.LPWStr)] public string UserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyId;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyName;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CERT_CONTEX {
        public uint   dwCertEncodingType;
        public byte   pbCertEncoded;
        public uint   cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_JOIN_INFO
    {
        public int joinType;
        public IntPtr pJoinCertificate;
        [MarshalAs(UnmanagedType.LPWStr)] public string DeviceId;
        [MarshalAs(UnmanagedType.LPWStr)] public string IdpDomain;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantId;
        [MarshalAs(UnmanagedType.LPWStr)] public string JoinUserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantDisplayName;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmEnrollmentUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmTermsOfUseUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmComplianceUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserSettingSyncUrl;
        public IntPtr pUserInfo;
    }
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern void NetFreeAadJoinInformation(
            IntPtr pJoinInfo);
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int NetGetAadJoinInformation(
            string pcszTenantId,
            out IntPtr ppJoinInfo);
}
'@

if ([bool]([System.Management.Automation.PSTypeName]'NetAPI32').Type -eq $false)
{
	$netApi32 = Add-Type -TypeDefinition $netApi32MemberDefinition -ErrorAction SilentlyContinue
}

if ([bool]([System.Management.Automation.PSTypeName]'NetAPI32').Type -eq $true)
{
	$netApi32 = Add-Type -TypeDefinition $netApi32MemberDefinition -ErrorAction SilentlyContinue
	$pcszTenantId = $null
	$ptrJoinInfo = [IntPtr]::Zero

	# https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
	# [NetAPI32]::NetFreeAadJoinInformation([IntPtr]::Zero);
	$retValue = [NetAPI32]::NetGetAadJoinInformation($pcszTenantId, [ref]$ptrJoinInfo)

	# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
	if ($retValue -eq 0)
	{
		# https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical
		$ptrJoinInfoObject = New-Object NetAPI32+DSREG_JOIN_INFO
		$joinInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrJoinInfo, [System.Type] $ptrJoinInfoObject.GetType())

		$ptrUserInfo = $joinInfo.pUserInfo
		$ptrUserInfoObject = New-Object NetAPI32+DSREG_USER_INFO
		$userInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrUserInfo, [System.Type] $ptrUserInfoObject.GetType())

		switch ($joinInfo.joinType)
		{
            ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_DEVICE_JOIN.value__) {$joinType = 'Joined to Azure AD (DSREG_DEVICE_JOIN)'}
            ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_UNKNOWN_JOIN.value__) {$joinType = 'Unknown (DSREG_UNKNOWN_JOIN)'}
            ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_WORKPLACE_JOIN.value__) {$joinType = 'Azure AD work account is added on the device (DSREG_WORKPLACE_JOIN)'}
		}
	}
	else
	{
		$joinType = 'Not Azure Joined'
	}
}

$lastBootUpTimeString = "$(Get-Age -Start $lastBootUpTime) ago $(Get-CustomDateTimeString $lastBootUpTime)"
$osInstallDate = $win32_OperatingSystem.InstallDate
$osInstallDateString = "$(Get-Age -Start $osInstallDate) ago $(Get-Date $osInstallDate -Format yyyy-MM-dd)"

$biosVersion = $win32_BIOS.Name
$biosDate = Get-Date -Date $win32_BIOS.ReleaseDate -Format yyyy-MM-dd
$biosDate = "$biosDate $(Get-Age -Start $win32_BIOS.ReleaseDate) old"
$bios = "$biosVersion $biosDate"

$systemManufacturer = $win32_ComputerSystem.Manufacturer
if ($isLaptop)
{
	$systemFamily = $win32_ComputerSystem.SystemFamily
	$systemSkuNumber = $win32_ComputerSystem.SystemSkuNumber
	$model = "$systemManufacturer $systemFamily" # $systemSkuNumber
}
else
{
	$baseBoardProduct = $win32_BaseBoard.Product
	$baseBoardManufacturer = $win32_BaseBoard.Manufacturer
	$mobo = "$baseBoardManufacturer $baseBoardProduct BIOS $bios"
}

$hyperVEnabled = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V | Select-Object -ExpandProperty State

$logicalDisks = Get-CimInstance -Query 'SELECT DeviceID,Size,FreeSpace FROM Win32_LogicalDisk' | Where-Object FreeSpace
$drive = @{Name = 'Drive'; Expression = {"DRIVE $($_.DeviceID.Replace(':',''))"}}
$free = @{Name = 'Free'; Expression = {"$([Math]::Round($_.FreeSpace/1GB, 0))GB"}}
$used = @{Name = 'Used'; Expression = {"$([Math]::Round(($_.Size-$_.FreeSpace)/1GB, 0))GB"}}
$size = @{Name = 'Size'; Expression = {"$([Math]::Round($_.Size/1GB, 0))GB"}}
$details = @{Name = 'Details'; Expression = {"Free:$((([Math]::Round($_.FreeSpace/1GB, 0)).ToString('N0')).PadLeft(6, ' '))GB Used:$((([Math]::Round(($_.Size-$_.FreeSpace)/1GB, 0)).ToString('N0')).PadLeft(6, ' '))GB Total:$((([Math]::Round($_.Size/1GB, 0)).ToString('N0')).PadLeft(6, ' '))GB"}}
$logicalDisks = $logicalDisks | Select-Object $drive, $free, $used, $size, $details
$logicalDisksTable = $logicalDisks | Format-Table -AutoSize | Out-String
# TODO: Get-BitLockerVolume

$letter = $systemDrive.DeviceID
$systemDrive = "$letter $($size)GB ($($free)GB Free)"
$version = $win32_OperatingSystem.Version
$caption = $win32_OperatingSystem.Caption

$ErrorActionPreference = 'SilentlyContinue'
$buildNumber = [System.Environment]::OSVersion.Version.Build
if ($buildNumber -ge 14393)
{
	$releaseId = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ReleaseId -ErrorAction SilentlyContinue
	$displayVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue
	$ubr = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UBR -ErrorAction SilentlyContinue
}
$ErrorActionPreference = 'Continue'

if ($releaseId -and $displayVersion)
{
	$osVersion = "$caption $displayVersion $releaseId $version $ubr"
}
else
{
	$osVersion = "$caption $version"
}

switch -regex ($osVersion)
{
	'Datacenter' {$osVersion = $osVersion.Replace('Datacenter', 'DTC')}
	'Enterprise' {$osVersion = $osVersion.Replace('Enterprise', 'ENT')}
	'Professional' {$osVersion = $osVersion.Replace('Professional', 'PRO')}
	'Standard' {$osVersion = $osVersion.Replace('Standard', 'STD')}
}
$osVersion = $osVersion.Replace('Microsoft Windows ', 'Win')

$freePhysicalMemory = $win32_OperatingSystem.FreePhysicalMemory
$totalVirtualMemorySize = $win32_OperatingSystem.TotalVirtualMemorySize
$sizeStoredInPagingFiles = $win32_OperatingSystem.SizeStoredInPagingFiles
$freeVirtualMemory = $win32_OperatingSystem.FreeVirtualMemory

$computerName = $env:computername
$userName = "$env:userdomain\$env:username"

$ram = ([string]([math]::round([Int64]$win32_ComputerSystem.TotalPhysicalMemory/1GB, 0)) + 'GB')
if ($isPhysicalMachine)
{
	# Thinkpad X1 Yoga reported **8** modules 4GB each, which is wrong or at least isn't being reported the way most machines do, so special-casing that
	if (($isLaptop -and $memoryModuleCount -gt 2) -or $isVm)
	{
		$ram = "$ram $($memoryModuleConfiguredClockSpeed)Mhz $memoryModuleManufacturer $memoryModulePartNumber"
	}
	else
	{
		$ram = "$ram $($memoryModuleCount)x$($memoryModuleSizeGB)GB $($memoryModuleConfiguredClockSpeed)Mhz $memoryModuleManufacturer $memoryModulePartNumber"
	}
	$ram = $ram.Replace('Intl', '').Replace('  ', ' ')
}
$strPageFile = $win32_PageFileUsage.Caption
$timeZone = $win32_TimeZone.StandardName
$biosManufacturer = $win32_BIOS.Manufacturer
$biosVersion = $win32_BIOS.SMBIOSBIOSVersion
$biosReleaseDate = $win32_BIOS.ReleaseDate
$strBIOSVersion = "$biosManufacturer $biosVersion $biosReleaseDate"

if ($isVm)
{
	$containerId = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'VirtualMachineName'
	if ([string]::IsNullOrEmpty($containerId))
	{
		$containerId = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\GuestAgent' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'ContainerId'
	}
	$incarnation = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\GuestAgent' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Incarnation'
	$heartbeatLastStatusUpdateTime = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\GuestAgent' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'HeartbeatLastStatusUpdateTime'
	$heartbeatLastStatusUpdateTime = "$(Get-Age $heartbeatLastStatusUpdateTime) ago $heartbeatLastStatusUpdateTime"

	$imdsReachable = Test-Port -ipAddress '169.254.169.254' -port 80 -timeout 1000

	if ($imdsReachable.Succeeded)
	{
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
			$publicIpAddress = $metadata.network.interface | Select-Object -First 1 | Select-Object -ExpandProperty ipv4 -First 1 | Select-Object -ExpandProperty ipAddress -First 1 | Select-Object -ExpandProperty publicIpAddress -First 1
			$publicIpAddressFromAwsCheckIpService = Invoke-RestMethod -Uri https://checkip.amazonaws.com
			if ($publicIpAddressFromAwsCheckIpService)
			{
				$publicIpAddressFromAwsCheckIpService = $publicIpAddressFromAwsCheckIpService.Trim()
			}
		}
	}
}

$objects = New-Object System.Collections.Generic.List[Object]

$refreshTime = Get-CustomDateTimeString -dateTime $scriptStartTime -timeFirst
$refreshDurationInSeconds = "$([Math]::Round((New-TimeSpan -Start $scriptStartTime -End (Get-Date)).TotalSeconds,2))s"
$objects.Add([PSCustomObject]@{Name = 'refreshed'; DisplayName = 'Refreshed'; Value = "$refreshTime in $refreshDurationInSeconds"; EmptyLineAfter = $true})
$objects.Add([PSCustomObject]@{Name = "weather"; DisplayName = ''; Value = $weather; EmptyLineAfter = $true})
<#
$i = 1
$weather | ForEach-Object {
	$objects.Add([PSCustomObject]@{Name = "weather$i"; DisplayName = ''; Value = $_})
	$i++
}
#>
$objects.Add([PSCustomObject]@{Name = 'computerName'; DisplayName = 'Name'; Value = "$computerName $ipV4AddressesString WAN:$wan$(if($vpn){" VPN:$vpn"})"})
$objects.Add([PSCustomObject]@{Name = 'osVersion'; DisplayName = 'OS'; Value = $osVersion})
$objects.Add([PSCustomObject]@{Name = 'lastBoot'; DisplayName = 'LAST BOOT'; Value = $lastBootUpTimeString})
$objects.Add([PSCustomObject]@{Name = 'osInstallDate'; DisplayName = 'OS INSTALLED'; Value = $osInstallDateString})
$objects.Add([PSCustomObject]@{Name = 'joinType'; DisplayName = 'JOIN TYPE'; Value = $joinType})
$objects.Add([PSCustomObject]@{Name = 'deviceType'; DisplayName = 'DEVICE TYPE'; Value = $deviceType; EmptyLineAfter = $true})

$objects.Add([PSCustomObject]@{Name = 'cpu'; DisplayName = 'CPU'; Value = $cpu})
$gpus | Where-Object {$_.Name -ne 'Microsoft Remote Display Adapter' -and $_.Name -notmatch 'Hyper-V'} | ForEach-Object {
	$gpu = $_
	$gpuName = $gpu.Name.Replace('(R)', '')
	$vram = $gpu.VRAM
	if ($gpu.CurrentRefreshRate)
	{
		$refreshRate = "$($gpu.CurrentRefreshRate)hz"
	}
	$gpuDriver = "$($gpu.DriverVersion) $(Get-Date -Date $gpu.DriverDate -Format yyyy-MM-dd) $(Get-Age -Start $gpu.DriverDate) old"
	$gpuDescription = "$gpuName $vram $refreshRate $gpuDriver" -replace '\s+', ' '
	$objects.Add([PSCustomObject]@{Name = 'gpu'; DisplayName = 'GPU'; Value = $gpuDescription})
}
if ($hasNvidiaGPU -and [string]::IsNullOrEmpty($gpuInfo) -eq $false)
{
	$objects.Add([PSCustomObject]@{Name = 'gpuInfo'; DisplayName = ''; Value = $gpuInfo})
}
$objects.Add([PSCustomObject]@{Name = 'mem'; DisplayName = 'MEM'; Value = $ram})
$objects.Add([PSCustomObject]@{Name = 'model'; DisplayName = 'MODEL'; Value = $model})
$objects.Add([PSCustomObject]@{Name = 'mobo'; DisplayName = 'MOBO'; Value = $mobo})
$objects.Add([PSCustomObject]@{Name = 'tpm'; DisplayName = 'TPM'; Value = $tpmString})
$objects.Add([PSCustomObject]@{Name = 'secureBootEnabled'; DisplayName = 'SECURE BOOT'; Value = $secureBootEnabled})

foreach ($physicalNic in $physicalNics)
{
	#$interfaceDescription = $physicalNic.InterfaceDescription.Replace('Intel(R) Ethernet Controller','Intel').Replace('Intel(R) Ethernet Connection','Intel').Replace('(R)','')
	$nicDescription = $physicalNic.DriverDescription.Replace('Intel(R) Ethernet Controller', 'Intel').Replace('Intel(R) Ethernet Connection', 'Intel').Replace('(R)', '')
	$driverInformation = "$($physicalNic.DriverFileName) $(Get-Date -Format $physicalNic.DriverVersionString) NDIS $(Get-Date -Format $physicalNic.NdisVersion) $(Get-Date -Format $physicalNic.DriverDate) $(Get-Age -Start $physicalNic.DriverDate) old"
	$objects.Add([PSCustomObject]@{Name = 'nic'; DisplayName = 'NIC'; Value = "$nicDescription $driverInformation"})
}
$objects.Add([PSCustomObject]@{Name = 'disconnectsInfo'; DisplayName = ''; Value = $disconnectsInfo})
$objects.Add([PSCustomObject]@{Name = 'hyperVEnabled'; DisplayName = 'HYPER-V'; Value = $hyperVEnabled})
$objects.Add([PSCustomObject]@{Name = 'powerPlan'; DisplayName = 'POWER'; Value = $powerPlan; EmptyLineAfter = $true})
foreach ($logicalDisk in $logicalDisks)
{
	$objects.Add([PSCustomObject]@{Name = $logicalDisk.Drive.Replace(' ', ''); DisplayName = $logicalDisk.Drive; Value = $logicalDisk.Details})
}
$objects.Add([PSCustomObject]@{Name = 'lastAppCrash'; DisplayName = 'LAST APP CRASH'; Value = $lastAppCrashString; EmptyLineBefore = $true})
$objects.Add([PSCustomObject]@{Name = 'lastSystemCrash'; DisplayName = 'LAST SYSTEM CRASH'; Value = $lastSystemCrashString})
$objects.Add([PSCustomObject]@{Name = 'lastBadShutdown'; DisplayName = 'LAST BAD SHUTDOWN'; Value = $lastBadShutdownString})
$objects.Add([PSCustomObject]@{Name = 'lastHardwareError'; DisplayName = 'LAST HARDWARE ERROR'; Value = $lastHardwareErrorString})
$objects.Add([PSCustomObject]@{Name = 'lastCriticalError'; DisplayName = 'LAST CRITICAL ERROR'; Value = $lastCriticalSystemLogErrorString})
$objects.Add([PSCustomObject]@{Name = 'lastSystemLogError'; DisplayName = 'LAST ERROR'; Value = $lastSystemLogErrorString; EmptyLineAfter = $true})
$objects.Add([PSCustomObject]@{Name = 'systemLogDetails'; DisplayName = 'SYSTEM'; Value = $systemLogDetailsString})
$objects.Add([PSCustomObject]@{Name = 'applicationLogDetails'; DisplayName = 'APPLICATION'; Value = $appLogDetailsString})
$objects.Add([PSCustomObject]@{Name = 'securityLogDetails'; DisplayName = 'SECURITY'; Value = $securityLogDetailsString; EmptyLineAfter = $true})

$objects.Add([PSCustomObject]@{Name = 'lastQuickScan'; DisplayName = 'LAST QUICK SCAN'; Value = $quickScanEndTimeString})
$objects.Add([PSCustomObject]@{Name = 'lastFullScan'; DisplayName = 'LAST FULL SCAN'; Value = $fullScanEndTimeString; EmptyLineAfter = $true})

$objects.Add([PSCustomObject]@{Name = 'lastBackup'; DisplayName = 'LAST BACKUP'; Value = $lastBackupTime})

$objects.Add([PSCustomObject]@{Name = 'lastCumulativeUpdate'; DisplayName = 'LAST CUMULATIVE UPDATE'; Value = $lastCumulativeUpdateString})
$objects.Add([PSCustomObject]@{Name = 'lastUpdateAccordingToWin32QuickFixEngineering'; DisplayName = 'LAST UPDATE'; Value = "$(Get-Age $lastUpdateTimeAccordingToWin32QuickFixEngineering) ago $lastUpdateHotfixIdAccordingToWin32QuickFixEngineering $lastUpdateTimeAccordingToWin32QuickFixEngineering (Win32_QuickfixEngineering)".Trim()})
$objects.Add([PSCustomObject]@{Name = 'lastUpdateAccordingToMicrosoftUpdateSession'; DisplayName = 'LAST UPDATE'; Value = $lastUpdateAccordingToMicrosoftUpdateSessionString})
$objects.Add([PSCustomObject]@{Name = 'lastUpdateAccordingToMicrosoftUpdateAutoUpdate'; DisplayName = 'LAST UPDATE'; Value = "$(Get-Age $lastUpdateTimeAccordingToMicrosoftUpdateAutoUpdate) ago $lastUpdateTimeAccordingToMicrosoftUpdateAutoUpdate (Microsoft.Update.AutoUpdate)".Trim()})
$objects.Add([PSCustomObject]@{Name = 'lastAntivirusSignatureUpdate'; DisplayName = 'LAST SIG UPDATE'; Value = $lastAntiVirusSignatureUpdate.Trim()})
$objects.Add([PSCustomObject]@{Name = 'lastUpdateCheckTime'; DisplayName = 'LAST CHECK FOR UPDATES'; Value = "$(Get-Age $lastCheckForUpdatesTimeAccordingToMicrosoftUpdateAutoUpdate) ago $lastCheckForUpdatesTimeAccordingToMicrosoftUpdateAutoUpdate (Microsoft.Update.AutoUpdate)".Trim()})

$objects.Add([PSCustomObject]@{Name = 'vmId'; DisplayName = 'VMID'; Value = $vmId; EmptyLineBefore = $true})
$objects.Add([PSCustomObject]@{Name = 'containerId'; DisplayName = 'CONTAINERID'; Value = $containerId})
$objects.Add([PSCustomObject]@{Name = 'vmSize'; DisplayName = 'VMSIZE'; Value = $vmSize})
$objects.Add([PSCustomObject]@{Name = 'image'; DisplayName = 'IMAGE'; Value = $imageReference})
$objects.Add([PSCustomObject]@{Name = 'resourceGroupName'; DisplayName = 'RESOURCEGROUPNAME'; Value = $resourceGroupName})
$objects.Add([PSCustomObject]@{Name = 'subscriptionId'; DisplayName = 'SUBSCRIPTIONID'; Value = $subscriptionId})
$objects.Add([PSCustomObject]@{Name = 'region'; DisplayName = 'REGION'; Value = $location})
$objects.Add([PSCustomObject]@{Name = 'privateIpAddress'; DisplayName = 'PRIVATE IP'; Value = $privateIpAddress})
$objects.Add([PSCustomObject]@{Name = 'publicIpAddress'; DisplayName = 'PUBLIC IP'; Value = $publicIpAddress})
$objects.Add([PSCustomObject]@{Name = 'guestAgentVersion'; DisplayName = 'VM AGENT'; Value = $incarnation})
$objects.Add([PSCustomObject]@{Name = 'lastGuestAgentHeartbeat'; DisplayName = 'HEARTBEAT'; Value = $heartbeatLastStatusUpdateTime})

$user32MemberDefinition = @'
[DllImport("user32.dll")]
public static extern uint SystemParametersInfo(
    uint uiAction,
    uint uiParam,
    string pvParam,
    uint fWinIni);
'@

# If we're in an RDP session, use those resolution values
if ([bool]($gpus.Name -eq 'Microsoft Remote Display Adapter'))
{
	$gpu = $gpus | Where-Object Name -EQ 'Microsoft Remote Display Adapter'
}
else
{
	$gpu = $gpus | Where-Object {$_.CurrentHorizontalResolution -and $_.CurrentVerticalResolution}
	if (($gpu | Measure-Object | Select-Object -ExpandProperty Count) -gt 1)
	{
		$gpu = $gpu | Sort-Object CurrentHorizontalResolution -Descending | Select-Object -First 1
		Out-Log "More than one GPU had CurrentHorizontalResolution/CurrentVerticalResolution defined, using the one with the higher resolution ($($gpu.Name) $($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution))" -verboseOnly
	}
}

[int32]$currentHorizontalResolution = $gpu.CurrentHorizontalResolution
[int32]$currentVerticalResolution = $gpu.CurrentVerticalResolution
if ($currentHorizontalResolution -and $currentVerticalResolution)
{
	$width = $currentHorizontalResolution
	$height = $currentVerticalResolution
	$workingAreaWidth = $currentHorizontalResolution
	$workingAreaHeight = ($currentVerticalResolution - 8)
	Out-Log "$($width)x$($height) resolution, $($workingAreaWidth)x$($workingAreaHeight) working area" -verboseOnly
}
else
{
	Out-Log 'Unable to determine current display resolution, exiting.'
	exit
}

$bitmap = New-Object System.Drawing.Bitmap($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
$rectangle = New-Object Drawing.Rectangle 0, 0, $workingAreaWidth, $workingAreaHeight
$graphics.DrawImage($bitmap, $rectangle, 0, 0, $workingAreaWidth, $workingAreaHeight, ([Drawing.GraphicsUnit]::Pixel))
$font = New-Object System.Drawing.Font('Lucida Console', $fontSize)
$fontWidth = [Windows.Forms.TextRenderer]::MeasureText('A', $font).Width
$fontHeight = [Windows.Forms.TextRenderer]::MeasureText('A', $font).Height

$length = 25
$longestString = ''
$objects = $objects | Where-Object {[string]::IsNullOrEmpty($_.Value) -eq $false}
foreach ($object in $objects)
{
	$string = "$((Add-Padding -Text "$($object.DisplayName): " -Length $length -Align Left) + $object.Value)"
	if ($string.Length -gt $longestString.Length)
	{
		$longestString = $string
	}
}

$columnWidth = [Windows.Forms.TextRenderer]::MeasureText($longestString, $font).Width
if ($justify -eq 'Left')
{
	$horizontalPosition = 100
}
else
{
	$horizontalPosition = ($workingAreaWidth - ($columnWidth + 50))
}

$textOutput = New-Object Text.StringBuilder

$verticalPosition = 40
$white = New-Object Drawing.SolidBrush White
$cyan = New-Object Drawing.SolidBrush Cyan

$objects = $objects | Where-Object {[string]::IsNullOrEmpty($_.Value) -eq $false}
foreach ($object in $objects)
{
	if ($object.EmptyLineBefore)
	{
		$verticalPosition += $fontHeight + 5
		[void]$textOutput.Append("`n")
	}

	# Create second column if first column is full
	# if this line is going off the screen...$fontHeight
	if ($verticalPosition -ge ($workingAreaHeight - 14))
	{
		# Then reset the vertical position back to the top
		$verticalPosition = 20
		# And move the horizontal position to the right
		$horizontalPosition += ($columnWidth + 40)
	}

	if ($object.Name.StartsWith('refreshed'))
	{
		$string = "$($object.DisplayName) $($object.Value)"
		$graphics.DrawString($string, $font, $white, $horizontalPosition, $verticalPosition)
	}
	elseif ($object.Name.StartsWith('weather'))
	{
		$string = $object.Value
		$graphics.DrawString($string, $font, $white, $horizontalPosition, $verticalPosition)
	}
	else
	{
		if ([string]::IsNullOrEmpty($object.DisplayName))
		{
			$displayName = $object.DisplayName
		}
		else
		{
			$displayName = "$($object.DisplayName): "
		}
		$value = $object.Value
		$string = (Add-Padding -Text $displayName -length $length -align Left) + $value
		#$string1 = (Add-Padding -Text $displayName -length $length -align Left)
		#$string2 = $value

		$graphics.DrawString($string, $font, $white, $horizontalPosition, $verticalPosition)
		[void]$textOutput.Append("$string`n")

		#$measureTextResult = [Windows.Forms.TextRenderer]::MeasureText($string1, $font).Width
		#Out-Log "`$measureTextResult: $measureTextResult" -verboseonly
		#$horizontalPosition += $graphics.MeasureString($string1, $font, (New-Object "System.Drawing.PointF" -ArgumentList @(0, 0)), (New-Object "System.Drawing.StringFormat" -ArgumentList @([System.Drawing.StringFormat]::GenericTypographic)))
		#$measureStringResult = $graphics.MeasureString($string1, $font) | Select-Object -ExpandProperty Width
		#Out-Log "`$measureStringResult:$measureStringResult" -verboseonly
		#$horizontalPosition += $measureStringResult
		#$graphics.DrawString($string2, $font, $cyan, $horizontalPositionp, $verticalPosition)
	}

	# This controls the spacing between each line. Even without adding 1 to the height there is no overlap, but it looked too cramped that way.
	$verticalPosition += $fontHeight + 5
	if ($object.EmptyLineAfter)
	{
		$verticalPosition += $fontHeight + 5
		[void]$textOutput.Append("`n")
	}
}

$wallpaperFolderPath = "$env:windir\web\wallpaper"
$wallpaperFileName = "CustomWallpaper$($width)x$($height).png"
$wallpaperFilePath = "$wallpaperFolderPath\$wallpaperFileName"

# First set wallpaper to solid black 1x1 PNG because sometimes it doesn't refresh correctly otherwise
$win32Utils = Add-Type -MemberDefinition $user32MemberDefinition -Name Win32Utils -Namespace SystemParametersInfo -PassThru -ErrorAction SilentlyContinue

$solidColorBlack1x1ImageFilePath = "$env:TEMP\SolidColorBlack1x1.png"
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
$solidColorBitmap = New-Object System.Drawing.Bitmap(1, 1)

$solidColorBitmap.Save($solidColorBlack1x1ImageFilePath, [System.Drawing.Imaging.ImageFormat]::Png)
$solidColorBitmap.Dispose()
[void]($win32Utils::SystemParametersInfo(20, 0, $solidColorBlack1x1ImageFilePath, 3))

# PNG is about 1/3rd the size of JPG for this type of text-only image
$bitmap.Save($wallpaperFilePath, [System.Drawing.Imaging.ImageFormat]::Png)
$bitmap.Dispose()
[void]($win32Utils::SystemParametersInfo(20, 0, $wallpaperFilePath, 3))

$wallpaperFile = Get-Item -Path $wallpaperFilePath
$wallpaperFileSizeKB = "$([Math]::Round($wallpaperFile.Length/1KB))KB"
Out-Log "Created $wallpaperFilePath ($wallpaperFileSizeKB)" -verboseonly

# Using a VBS script to launch a PS script is a workaround for PowerShell's -Hidden not working to hide the window when calling a PS1 from Task Scheduler
if ($scriptFullName.Startswith('\\') -eq $false)
{
	$setWallpaperVbsPath = $scriptFullName.Replace('.ps1', '.vbs')
}

$powerShellPath = Get-Process -Id $PID | Select-Object -ExpandProperty Path
$setWallpaperVbsContents = @"
Dim shell, command
command = """$powerShellPath"" -NoProfile -NoLogo -ExecutionPolicy Bypass -WindowStyle Hidden -File $scriptFullName"
Set shell = CreateObject("WScript.Shell")
shell.Run command,0
"@

$userId = "$env:userdomain\$env:username"
$ntAccount = New-Object System.Security.Principal.NTAccount($userId)
$sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
$sidString = $sid.Value

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$userId</Author>
    <URI>\Set-Wallpaper</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>$sidString</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
  	<LogonTrigger>
  		<UserId>$userId</UserId>
	</LogonTrigger>
    <TimeTrigger>
      <StartBoundary>2023-06-11T00:00:00-07:00</StartBoundary>
      <Repetition>
        <Interval>PT1H</Interval>
      </Repetition>
    </TimeTrigger>
    <SessionStateChangeTrigger>
      <StateChange>ConsoleConnect</StateChange>
      <UserId>$userId</UserId>
    </SessionStateChangeTrigger>
    <SessionStateChangeTrigger>
      <StateChange>SessionUnlock</StateChange>
      <UserId>$userId</UserId>
    </SessionStateChangeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>"$env:SystemRoot\System32\wscript.exe"</Command>
      <Arguments>$setWallpaperVbsPath</Arguments>
      <WorkingDirectory>$(Split-Path -Path $setWallpaperVbsPath)</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

if ($addScheduledTask)
{
	$taskName = (Get-Culture).TextInfo.ToTitleCase($scriptBaseName)
	Invoke-ExpressionWithLogging "Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false -ErrorAction SilentlyContinue"
	if ((Test-Path -Path $setWallpaperVbsPath -PathType Leaf) -eq $false)
	{
		Out-Log "$setWallpaperVbsPath not found, creating it..." -verboseonly
		$setWallpaperVbsContents | Out-File -FilePath $setWallpaperVbsPath -ErrorAction Stop
	}
	if (Test-Path -Path $setWallpaperVbsPath -PathType Leaf)
	{
		Out-Log "$setWallpaperVbsPath successfully created" -verboseonly
		if ($taskXml)
		{
			Out-Log "Registering $taskName task with XML" -verboseonly
			Invoke-ExpressionWithLogging "Register-ScheduledTask -TaskName $taskName -Xml '$taskXml' | Out-Null"
		}
		else
		{
			Out-Log "Registering $taskName task without XML" -verboseonly
			$execute = '"C:\Windows\System32\wscript.exe"'
			$argument = $setWallpaperVbsPath
			$userId = "$env:userdomain\$env:username"
			$runLevel = 'Highest'
			$action = New-ScheduledTaskAction -Execute $execute -Argument $argument -WorkingDirectory $scriptFolderPath
			$principal = New-ScheduledTaskPrincipal -UserId $userId -RunLevel $runLevel -LogonType Interactive
			$settings = New-ScheduledTaskSettingsSet -Compatibility Win8
			$trigger1 = New-ScheduledTaskTrigger -AtLogOn
			$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)
			$task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Trigger $trigger1, $trigger2
			Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
		}
	}

}

if ($addToProfile)
{
	if ((Test-Path -Path $profile -PathType Leaf) -eq $false)
	{
		New-Item -Path $profile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
	}
	if (Test-Path -Path $profile -PathType Leaf)
	{
		$profileAlreadyUpdated = Get-Content $profile | Select-String -SimpleMatch $setAliasCommand -Quiet
		if ($profileAlreadyUpdated -eq $false)
		{
			$setAliasCommand = "Set-Alias w `"$scriptFullName`""
			Out-Log "Adding '$setAliasCommand' to $profile" -verboseonly
			Add-Content -Value $setAliasCommand -Path $profile -Force
			. $profile
		}
	}
}

$global:dbgGraphics = $graphics
$global:dbgBitmap = $bitmap
$global:dbgRectangle = $rectangle
$global:dbgGraphics = $graphics
$global:dbgObjects = $objects
$global:dbgWeather = $weather
$global:cpuSpecs = $cpuSpecs

Out-Log "Log file: $logFilePath"
$scriptDuration = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
$scriptDuration = "$([Math]::Round($scriptDuration.TotalSeconds,2))s"
Out-Log "$scriptName duration: $scriptDuration"

$textOutputString = $textOutput.ToString() | Out-String
Out-Log $textOutputString -raw

if ($currentPSDefaultParameterValues)
{
	$global:PSDefaultParameterValues = $currentPSDefaultParameterValues
}