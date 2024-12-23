<#
Set-ExecutionPolicy Bypass -Force
md c:\meh
Invoke-WebRequest -Uri https://raw.githubusercontent.com/craiglandis/bootstrap/main/Set-Wallpaper.ps1 -OutFile c:\meh\Set-Wallpaper.ps1
c:\meh\Set-Wallpaper.ps1

copy \\tsclient\c\src\bootstrap\set-wallpaper.ps1 c:\meh\Set-Wallpaper.ps1;c:\meh\Set-Wallpaper.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
	[string]$path = 'c:\meh',
	[int]$fontSize,
	[ValidateSet('left', 'right')]
	[string]
	$justify,
	[switch]$noweather = $true,
	[switch]$addScheduledTask,
	[switch]$showDisconnects = $true,
	[switch]$temps,
    [switch]$noWallpaper
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
    # exit
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

function Get-PowerMode
{
    $actual = [Guid]::NewGuid()
    $ret = $power::PowerGetActualOverlayScheme([ref]$actual)
    $actualMode = ConvertFrom-GuidToName $actual.Guid

    $effective = [Guid]::NewGuid()
    $ret = $power::PowerGetEffectiveOverlayScheme([ref]$effective)
    $effectiveMode = ConvertFrom-GuidToName $effective.Guid

    if ($actualMode -eq $effectiveMode)
    {
        return $actualMode
    }
    else
    {
        return "Actual power mode $actualMode is different than effective power mode $effectiveMode"
    }
}


function ConvertFrom-GuidToName
{
    param(
        $guid
    )
    switch ($guid) {
        '961cc777-2547-4f9d-8174-7d86181b8a7a' {$name = 'Best power efficiency'}
        '00000000-0000-0000-0000-000000000000' {$name = 'Balanced'}
        'ded574b5-45a0-4f42-8737-46345c09c238' {$name = 'Best performance'}
    }
    return $name
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

function Get-Weather
{
	param(
		[string]$location
	)
	Out-Log "Getting $location weather"

	$weather = Invoke-RestMethod -Uri "wttr.in/$($location)?format=j1" -ConnectionTimeoutSeconds 5
	# Invoke-RestMethod -Uri "wttr.in/Redmond,WA?format=j1" -ConnectionTimeoutSeconds 5
	# $weather = Invoke-RestMethod -Uri 'wttr.in/Sydney,NSW?format=j1'
	if ($weather)
	{
		$today = $weather.weather[0]
		$tomorrow = $weather.weather[1]
		$dayAfterTomorrow = $weather.weather[2]

		$minTempF = $today.mintempF
		$maxTempF = $today.maxtempF
		$sunHour = $today.sunHour
		#$areaName = $weather.nearest_area.areaName.value
		$sunrise = $today.astronomy.sunrise
		$sunset = $today.astronomy.sunset

		$currentCondition = $weather.current_condition
		$feelsLikeF = $currentCondition.FeelsLikeF
		$cloudCover = $currentCondition.cloudcover
		$humidity =$currentCondition.humidity
		$precipInches = $currentCondition.precipInches
		$tempF = $currentCondition.temp_F
		$tempC = $currentCondition.temp_C
		$uvIndex = $currentCondition.uvIndex
		$weatherDesc = $currentCondition.weatherDesc.Value
		$visibilityMiles = $currentCondition.visibilityMiles
		$windspeedMiles = $currentCondition.windspeedMiles
		$pressureInches = $currentCondition.pressureInches
		$feelsLikeF = $currentCondition.FeelsLikeF
		$feelsLikeC = $currentCondition.FeelsLikeC
		# $weatherString = "$($areaName): $weatherDesc $($tempF)F/$($tempC)C Feel $($feelsLikeF)F/$($feelsLikeC)C Hum $($humidity)% Prec $($precipInches)in UV $uvIndex Clouds $cloudCover Viz $($visibilityMiles)mi Wind $($windspeedMiles)mph Press $pressureInches"
		$weatherString = "$($tempF)F/$($tempC)C Feel $($feelsLikeF)F/$($feelsLikeC)C Hum $($humidity)% Prec $($precipInches)in UV $uvIndex Clouds $cloudCover Viz $($visibilityMiles)mi Wind $($windspeedMiles)mph Press $pressureInches $weatherDesc"
	}
	else
	{
		$weatherString = ""
	}
	return $weatherString
}

function Get-DriveTemps
{
    $disks = New-Object System.Collections.Generic.List[Object]
	$readings = New-Object System.Collections.Generic.List[Object]
    # 'Realtek RTL9210 NVME' is the Orico Dual Bay M.2 enclosure, regardless which SSDs you swap in
    $friendlyNames = @('INTEL SSDPE21D960GA', 'INTEL SSDPF21Q800GB', 'Samsung SSD 990 PRO 2TB', 'Samsung SSD 980 PRO 2TB', 'Realtek RTL9210 NVME', 'CT4000P3PSSD8', 'SHPP41-2000GM')
    foreach ($friendlyName in $friendlyNames)
    {
        $physicalDisks = Get-PhysicalDisk -FriendlyName $friendlyName
        foreach ($physicalDisk in $physicalDisks)
        {
            $storageReliabilityCounter = $physicalDisk | Get-StorageReliabilityCounter
            $disk = [PSCustomObject]@{
                Name     = $physicalDisk.FriendlyName
                DeviceId = $physicalDisk.DeviceId
                Temp     = $storageReliabilityCounter.Temperature
                TempMax  = $storageReliabilityCounter.TemperatureMax
            }
            $disks.Add($disk)
        }
    }
    $reading = [PSCustomObject]@{
        Time = Get-Date
        Reading = $disks
    }
    $readings.Add($reading)
    # $disks | Format-Table Name, DeviceId, Temp, TempMax -AutoSize
	return $disks
}

Function Get-RegKeyInfo {
    <#
    .SYNOPSIS
    Gets details about a registry key.

    .DESCRIPTION
    Gets very low level details about a registry key.

    .PARAMETER Path
    The path to the registry key to get the details for. This should be a string with the hive and key path split by
    ':', e.g. HKLM:\Software\Microsoft, HKEY_CURRENT_USER:\Console, etc. The Hive can be in the short form like HKLM or
    the long form HKEY_LOCAL_MACHINE.

    .EXAMPLE
    Get-RegKeyInfo -Path HKLM:\SYSTEM\CurrentControlSet
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [String[]]
        $Path
    )

    begin {
		if ([bool]([System.Management.Automation.PSTypeName]'Registry.Key').Type -eq $false)
		{
        Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Registry
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_BASIC_INFORMATION
        {
            public Int64 LastWriteTime;
            public UInt32 TitleIndex;
            public Int32 NameLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public char[] Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_FLAGS_INFORMATION
        {
            // This struct isn't really documented and most of the snippets online just show the UserFlags field. For
            // whatever reason it seems to be 12 bytes in size with the flags in the 2nd integer value. The others I
            // have no idea what they are for.
            public UInt32 Reserved1;
            public KeyFlags UserFlags;
            public UInt32 Reserved2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_FULL_INFORMATION
        {
            public Int64 LastWriteTime;
            public UInt32 TitleIndex;
            public Int32 ClassOffset;
            public Int32 ClassLength;
            public Int32 SubKeys;
            public Int32 MaxNameLen;
            public Int32 MaxClassLen;
            public Int32 Values;
            public Int32 MaxValueNameLen;
            public Int32 MaxValueDataLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public char[] Class;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_HANDLE_TAGS_INFORMATION
        {
            public UInt32 HandleTags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_LAYER_INFORMATION
        {
            public UInt32 IsTombstone;
            public UInt32 IsSupersedeLocal;
            public UInt32 IsSupersedeTree;
            public UInt32 ClassIsInherited;
            public UInt32 Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_TRUST_INFORMATION
        {
            public UInt32 TrustedKey;
            public UInt32 Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_VIRTUALIZATION_INFORMATION
        {
            public UInt32 VirtualizationCandidate;
            public UInt32 VirtualizationEnabled;
            public UInt32 VirtualTarget;
            public UInt32 VirtualStore;
            public UInt32 VirtualSource;
            public UInt32 Reserved;
        }

        public enum KeyInformationClass : uint
        {
            Basic = 0,
            Node = 1,
            Full = 2,
            Name = 3,
            Cached = 4,
            Flags = 5,
            Virtualization = 6,
            HandleTags = 7,
            Trust = 8,
            Layer = 9,
        }
    }

    internal class NativeMethods
    {
        [DllImport("NtDll.dll")]
        public static extern UInt32 NtQueryKey(
            SafeHandle KeyHandle,
            NativeHelpers.KeyInformationClass KeyInformationClass,
            IntPtr KeyInformation,
            Int32 Length,
            out Int32 ResultLength
        );

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 RegOpenKeyExW(
            SafeHandle hKey,
            string lpSubKey,
            KeyOptions ulOptions,
            KeyAccessRights samDesired,
            out SafeRegistryHandle phkResult
        );

        [DllImport("NtDll.dll")]
        public static extern Int32 RtlNtStatusToDosError(
            UInt32 Status
        );
    }

    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMemoryBuffer() : base(true) { }
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }
        public SafeMemoryBuffer(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    [Flags]
    public enum KeyAccessRights : uint
    {
        QueryValue = 0x00000001,
        SetValue = 0x00000002,
        CreateSubKey = 0x00000004,
        EnumerateSubKeys = 0x00000008,
        Notify = 0x00000010,
        CreateLink = 0x00000020,
        Wow6464Key = 0x00000100,
        Wow6432Key = 0x00000200,

        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDAC = 0x00040000,
        WriteOwner = 0x00080000,
        StandardRightsRequired = Delete | ReadControl | WriteDAC | WriteOwner,
        AccessSystemSecurity = 0x01000000,

        Read = ReadControl | QueryValue | EnumerateSubKeys | Notify,
        Execute = Read,
        Write = ReadControl | SetValue | CreateSubKey,
        AllAccess = StandardRightsRequired | 0x3F
    }

    [Flags]
    public enum KeyFlags : uint
    {
        None = 0x00000000,
        Volatile = 0x00000001,
        Symlink = 0x00000002,
    }

    [Flags]
    public enum KeyOptions : uint
    {
        None = 0x00000000,
        Volatile = 0x00000001,
        CreateLink = 0x00000002,
        BackupRestore = 0x00000004,
        OpenLink = 0x00000008,
    }

    public class KeyInformation
    {
        public DateTime LastWriteTime { get; internal set; }
        public UInt32 TitleIndex { get; internal set; }
        public string Name { get; internal set; }
        public string Class { get; internal set; }
        public Int32 SubKeys { get; internal set; }
        public Int32 ValueCount { get; internal set ; }
        public KeyFlags Flags { get; internal set; }
        public bool VirtualizationCandidate { get; internal set; }
        public bool VirtualizationEnabled { get; internal set; }
        public bool VirtualTarget { get; internal set; }
        public bool VirtualStore { get; internal set; }
        public bool VirtualSource { get; internal set; }
        public UInt32 HandleTags { get; internal set; }
        public bool TrustedKey { get; internal set; }

        /*  Parameter is invalid
        public bool IsTombstone { get; internal set; }
        public bool IsSupersedeLocal { get; internal set; }
        public bool IsSupersedeTree { get; internal set; }
        public bool ClassIsInherited { get; internal set; }
        */
    }

    public class Key
    {
        public static SafeRegistryHandle OpenKey(SafeHandle key, string subKey, KeyOptions options,
            KeyAccessRights access)
        {
            SafeRegistryHandle handle;
            Int32 res = NativeMethods.RegOpenKeyExW(key, subKey, options, access, out handle);
            if (res != 0)
                throw new Win32Exception(res);

            return handle;
        }

        public static KeyInformation QueryInformation(SafeHandle handle)
        {
            KeyInformation info = new KeyInformation();

            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.Basic))
            {
                var obj = (NativeHelpers.KEY_BASIC_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_BASIC_INFORMATION));

                IntPtr nameBuffer = IntPtr.Add(buffer.DangerousGetHandle(), 16);
                byte[] nameBytes = new byte[obj.NameLength];
                Marshal.Copy(nameBuffer, nameBytes, 0, nameBytes.Length);

                info.LastWriteTime = DateTime.FromFileTimeUtc(obj.LastWriteTime);
                info.TitleIndex = obj.TitleIndex;
                info.Name = Encoding.Unicode.GetString(nameBytes, 0, nameBytes.Length);
            }

            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.Full))
            {
                var obj = (NativeHelpers.KEY_FULL_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_FULL_INFORMATION));

                IntPtr classBuffer = IntPtr.Add(buffer.DangerousGetHandle(), obj.ClassOffset);
                byte[] classBytes = new byte[obj.ClassLength];
                Marshal.Copy(classBuffer, classBytes, 0, classBytes.Length);

                info.Class = Encoding.Unicode.GetString(classBytes, 0, classBytes.Length);
                info.SubKeys = obj.SubKeys;
                info.ValueCount = obj.Values;
            }

            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.Flags))
            {
                var obj = (NativeHelpers.KEY_FLAGS_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_FLAGS_INFORMATION));

                info.Flags = obj.UserFlags;
            }

            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.Virtualization))
            {
                var obj = (NativeHelpers.KEY_VIRTUALIZATION_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_VIRTUALIZATION_INFORMATION));

                info.VirtualizationCandidate = obj.VirtualizationCandidate == 1;
                info.VirtualizationEnabled = obj.VirtualizationEnabled == 1;
                info.VirtualTarget = obj.VirtualTarget == 1;
                info.VirtualStore = obj.VirtualStore == 1;
                info.VirtualSource = obj.VirtualSource == 1;
            }

            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.HandleTags))
            {
                var obj = (NativeHelpers.KEY_HANDLE_TAGS_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_HANDLE_TAGS_INFORMATION));

                info.HandleTags = obj.HandleTags;
            }

            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.Trust))
            {
                var obj = (NativeHelpers.KEY_TRUST_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_TRUST_INFORMATION));

                info.TrustedKey = obj.TrustedKey == 1;
            }

            /*  Parameter is invalid
            using (var buffer = NtQueryKey(handle, NativeHelpers.KeyInformationClass.Layer))
            {
                var obj = (NativeHelpers.KEY_LAYER_INFORMATION)Marshal.PtrToStructure(
                    buffer.DangerousGetHandle(), typeof(NativeHelpers.KEY_LAYER_INFORMATION));

                info.IsTombstone = obj.IsTombstone == 1;
                info.IsSupersedeLocal = obj.IsSupersedeLocal == 1;
                info.IsSupersedeTree = obj.IsSupersedeTree == 1;
                info.ClassIsInherited = obj.ClassIsInherited == 1;
            }
            */

            return info;
        }

        private static SafeMemoryBuffer NtQueryKey(SafeHandle handle, NativeHelpers.KeyInformationClass infoClass)
        {
            int resultLength;
            UInt32 res = NativeMethods.NtQueryKey(handle, infoClass, IntPtr.Zero, 0, out resultLength);
            // STATUS_BUFFER_OVERFLOW or STATUS_BUFFER_TOO_SMALL
            if (!(res == 0x80000005 || res == 0xC0000023))
                throw new Win32Exception(NativeMethods.RtlNtStatusToDosError(res));

            SafeMemoryBuffer buffer = new SafeMemoryBuffer(resultLength);
            try
            {
                res = NativeMethods.NtQueryKey(handle, infoClass, buffer.DangerousGetHandle(), resultLength,
                    out resultLength);

                if (res != 0)
                    throw new Win32Exception(NativeMethods.RtlNtStatusToDosError(res));
            }
            catch
            {
                buffer.Dispose();
                throw;
            }

            return buffer;
        }
    }
}
'@
		}
    }

    process {
        $resolvedPaths = $Path

        foreach ($regPath in $resolvedPaths) {
            if (-not $regPath.Contains(':')) {
                $exp = [ArgumentException]"Registry path must contain hive and keys split by :"
                $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new(
                    $exp, $exp.GetType().FullName, 'InvalidArgument', $regPath
                ))
                continue
            }
            $hive, $subKey = $regPath -split ':', 2
            $hiveId = switch ($hive) {
                { $_ -in @('HKCR', 'HKEY_CLASES_ROOT') } { 0x80000000 }
                { $_ -in @('HKCU', 'HKEY_CURRENT_USER') } { 0x80000001 }
                { $_ -in @('HKLM', 'HKEY_LOCAL_MACHINE') } { 0x80000002 }
                { $_ -in @('HKU', 'HKEY_USERS') } { 0x80000003 }
                { $_ -in @('HKPD', 'HKEY_PERFORMANCE_DATA') } { 0x80000004 }
                { $_ -in @('HKPT', 'HKEY_PERFORMANCE_TEXT') } { 0x80000050 }
                { $_ -in @('HKPN', 'HKEY_PERFORMANCE_NLSTEXT') } { 0x80000060 }
                { $_ -in @('HKCC', 'HKEY_CURRENT_CONFIG') } { 0x80000005 }
                { $_ -in @('HKDD', 'HKEY_DYN_DATA') } { 0x80000006 }
                { $_ -in @('HKCULS', 'HKEY_CURRENT_USER_LOCAL_SETTINGS') } { 0x80000007 }
            }
            if (-not $hiveId) {
                $exp = [ArgumentException]"Registry hive path is invalid"
                $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new(
                    $exp, $exp.GetType().FullName, 'InvalidArgument', $regPath
                ))
                continue
            }
            if ($subKey.StartsWith('\')) {
                $subKey = $subKey.Substring(1)
            }

            $hive = [Microsoft.Win32.SafeHandles.SafeRegistryHandle]::new([IntPtr]::new($hiveId), $false)
            $key = $null
            try {
                # We can't use the PowerShell provider because it doesn't set OpenLink which means we couldn't detect
                # if the path was a link as the handle would be for the target.
                $key = [Registry.Key]::OpenKey($hive, $subKey, 'OpenLink', 'QueryValue')
                [Registry.Key]::QueryInformation($key)
            }
            catch {
                $PSCmdlet.WriteError([Management.Automation.ErrorRecord]::new(
                    $_.Exception, $_.Exception.GetType().FullName, 'NotSpecified', $regPath
                ))
                continue
            }
            finally {
                $key.Dispose()
            }
        }
    }
}

$global:scriptStartTime = Get-Date
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
<#
$PSDefaultParameterValues = @{
	'*:ErrorAction'   = 'Stop'
	'*:WarningAction' = 'SilentlyContinue'
}
#>
$ProgressPreference = 'SilentlyContinue'

$verbose = [bool]$PSBoundParameters['verbose']
$debug = [bool]$PSBoundParameters['debug']

$logFilePath = "$env:TEMP\$scriptBaseName.log"
$logFile = Get-Item -Path $logFilePath -ErrorAction SilentlyContinue
if ($logFile -and $logFile.Length -ge 10MB)
{
	$logFile | Remove-Item
}

if (!$addScheduledTask)
{
	Out-Log "Getting system information"

	# 'Get-CimInstance -Query "SELECT Property1,Property FROM Win32_Something"' is slightly faster than 'Get-CimInstance -ClassName Win32_Something -Property Property,Property2'
	$win32_SystemEnclosure = Get-CimInstance -Query 'SELECT ChassisTypes,Manufacturer,SerialNumber,Version FROM Win32_SystemEnclosure'
	# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure
	# 9='Laptop' 10='Notebook' 31='Convertible'
	if ($win32_SystemEnclosure.ChassisTypes -in '9','10','31')
	{
		$deviceType = 'Laptop'
		$isLaptop = $true
		# Defender complains about librehardwaremonitor, so skipping this
        #$temps = $true
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

	if ($temps)
	{
		$libreHardwareMonitorExePath = 'C:\ProgramData\chocolatey\lib\librehardwaremonitor\tools\LibreHardwareMonitor.exe'
		if (Test-Path -Path $libreHardwareMonitorExePath -PathType Leaf)
		{
			$isLibreHardwareMonitorRunning = [bool](Get-Process -Name LibreHardwareMonitor -ErrorAction SilentlyContinue)
			if ($isLibreHardwareMonitorRunning -eq $false)
			{
				# & $libreHardwareMonitorExePath
				Start-Process -FilePath $libreHardwareMonitorExePath -WindowStyle Hidden
			}
			# Wait for the WMI class to be available after the process is started
			$stopwatch = [System.Diagnostics.Stopwatch]::new()
			$stopwatch.Start()
			do
			{
				$cpuPackageTemp = Get-CimInstance -Query 'SELECT Value,Min,Max FROM Sensor WHERE Name="CPU Package" AND SensorType="Temperature"' -Namespace 'ROOT\LibreHardwareMonitor' -ErrorAction SilentlyContinue
				Start-Sleep -Seconds 1
				$secondsElapsed = $stopwatch.Elapsed.Seconds
				Out-Log $secondsElapsed -verboseOnly
			}
			until ($cpuPackageTemp.Value -gt 0 -or $secondsElapsed -ge 10)

			# Hardware class just has names and types of the hardware - CPU model, GPU model, etc.
			# $hardware = Get-CimInstance -ClassName 'Hardware' -Namespace 'ROOT\LibreHardwareMonitor'
			# $hardware | sort HardwareType | ft HardwareType,Name,Identifier
			$cpuPackageTempCurrent = $cpuPackageTemp.Value
			$cpuPackageTempMin = $cpuPackageTemp.Min
			$cpuPackageTempMax = $cpuPackageTemp.Max
			$cpuTemp = "Current $($cpuPackageTempCurrent)C Min $($cpuPackageTempMin)C Max $($cpuPackageTempMax)C"
		}
		else
		{
			Out-Log "File not found: $libreHardwareMonitorExePath"
		}
	}

	$getDeviceCaps = @'
using System;
using System.Runtime.InteropServices;
using System.Drawing;

public class DPI {
	[DllImport("gdi32.dll")]
	static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

	public enum DeviceCap {
	VERTRES = 10,
	DESKTOPVERTRES = 117
	}

	public static float scaling() {
	Graphics g = Graphics.FromHwnd(IntPtr.Zero);
	IntPtr desktop = g.GetHdc();
	int LogicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.VERTRES);
	int PhysicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.DESKTOPVERTRES);

	return (float)PhysicalScreenHeight / (float)LogicalScreenHeight;
	}
}
'@

	$function = @'
[DllImport("powrprof.dll", EntryPoint="PowerSetActiveOverlayScheme")]
public static extern int PowerSetActiveOverlayScheme(Guid OverlaySchemeGuid);
[DllImport("powrprof.dll", EntryPoint="PowerGetActualOverlayScheme")]
public static extern int PowerGetActualOverlayScheme(out Guid ActualOverlayGuid);
[DllImport("powrprof.dll", EntryPoint="PowerGetEffectiveOverlayScheme")]
public static extern int PowerGetEffectiveOverlayScheme(out Guid EffectiveOverlayGuid);
'@

	$power = Add-Type -MemberDefinition $function -Name Power -PassThru -Namespace System.Runtime.InteropServices

	if ($isLaptop)
	{
		$powerMode = Get-PowerMode
	}

	if ($PSEdition -eq 'Desktop')
	{
		Add-Type -TypeDefinition $getDeviceCaps -ReferencedAssemblies System.Drawing.dll
	}
	else
	{
		Add-Type -TypeDefinition $getDeviceCaps -ReferencedAssemblies System.Drawing.Common.dll
	}
	$scale = [Math]::round([DPI]::scaling(), 2) * 100

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

	if ($isPhysicalMachine -and $noweather -eq $false -and $isRdpSession -eq $false)
	{
		<# $weather = Invoke-RestMethod -Uri 'https://wttr.in/?1FQT' -ErrorAction SilentlyContinue
			https://github.com/chubin/wttr.in#one-line-output
			url wttr.in/:help
			View options:

			0                       # only current weather
			1                       # current weather + today's forecast
			2                       # current weather + today's + tomorrow's forecast
			A                       # ignore User-Agent and force ANSI output format (terminal)
			F                       # do not show the "Follow" line
			n                       # narrow version (only day and night)
			q                       # quiet version (no "Weather report" text)
			Q                       # superquiet version (no "Weather report", no city name)
			T                       # switch terminal sequences off (no colors)

		$currentCondition = (Invoke-RestMethod -Uri wttr.in?format=j1).current_condition
			FeelsLikeC       : 16
			FeelsLikeF       : 60
			cloudcover       : 75
			humidity         : 90
			localObsDateTime : 2023-06-29 06:59 AM
			observation_time : 01:59 PM
			precipInches     : 0.0
			precipMM         : 0.0
			pressure         : 1018
			pressureInches   : 30
			temp_C           : 15
			temp_F           : 59
			uvIndex          : 4
			visibility       : 16
			visibilityMiles  : 9
			weatherCode      : 116
			weatherDesc      : {@{value=Partly cloudy}}
			weatherIconUrl   : {@{value=}}
			winddir16Point   : SSW
			winddirDegree    : 210
			windspeedKmph    : 6
			windspeedMiles   : 4

			#>
		# $weather = Invoke-RestMethod -Uri 'https://wttr.in/?format=3' -ErrorAction SilentlyContinue
		# $weather = Invoke-RestMethod -Uri 'wttr.in?format=j1' -ErrorAction SilentlyContinue
		# $weather = Invoke-RestMethod -Uri 'wttr.in/Lititz,PA?format=j1'
		# $weather = Invoke-RestMethod -Uri 'wttr.in/Rochester,MI?format=j1'
		# $weather = Invoke-RestMethod -Uri 'wttr.in/Tucson,AZ?format=j1'
		# $weather = Invoke-RestMethod -Uri 'wttr.in/Sydney,NSW?format=j1'
		$redmond = Get-Weather -location "Redmond,WA"
		$lititz = Get-Weather -location "Lititz,PA"
		$rochester = Get-Weather -location "Rochester,MI"
	}

	if ($temps)
	{
		$driveTemps = Get-DriveTemps
	}

	$win32_BaseBoard = Get-CimInstance -Query 'SELECT Product,Manufacturer FROM Win32_BaseBoard'
	$win32_OperatingSystem = Get-CimInstance -Query 'SELECT Caption,FreePhysicalMemory,FreeVirtualMemory,InstallDate,LastBootUpTime,SizeStoredInPagingFiles,TotalVirtualMemorySize,Version FROM Win32_OperatingSystem'
	$win32_ComputerSystem = Get-CimInstance -Query 'SELECT DaylightInEffect,HypervisorPresent,Name,Manufacturer,Model,PCSystemType,SystemFamily,SystemSKUNumber,SystemType,TotalPhysicalMemory,UserName FROM Win32_ComputerSystem'
	$win32_PageFileUsage = Get-CimInstance -Query 'SELECT Caption FROM Win32_PageFileUsage'
	$win32_Processor = Get-CimInstance -Query 'SELECT Name,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors FROM Win32_Processor'
	$cpuProductName = $win32_Processor.Name.Split(' ')[-1].Trim()
	$cpuProductName = $win32_Processor.Name.Split('@')[0].Replace('(R)', '').Replace('(TM)', '').Replace('  ', ' ').Split(' ')[-1].Trim()
	# $cpuProductName = $win32_Processor.Name.Split(' ') | Where-Object {$_ -match '-'}

	switch ($pcSystemType)
	{
		# https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
		0 {$pcSystemType = 'Unspecified'}
		1 {$pcSystemType = 'Desktop'}
		2 {$pcSystemType = 'Mobile'}
		3 {$pcSystemType = 'Workstation'}
		4 {$pcSystemType = 'Enterprise Server'}
		5 {$pcSystemType = 'SOHO Server'}
		6 {$pcSystemType = 'Appliance PC'}
		7 {$pcSystemType = 'Performance Server'}
		8 {$pcSystemType = 'Maximum'}
		Default {$pcSystemType = 'Unknown'}
	}

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

	# $win32_SystemDriver = Get-CimInstance -Query 'SELECT * FROM Win32_SystemDriver'

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
	# $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue

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
			$nvidiaSmiResult = nvidia-smi --query-gpu=memory.total,memory.used,memory.free,name,serial,uuid,pcie.link.gen.gpucurrent,pcie.link.gen.gpumax,pcie.link.gen.hostmax,pcie.link.width.current,pcie.link.width.max,vbios_version,fan.speed,pstate,clocks_event_reasons.hw_thermal_slowdown,clocks_event_reasons.hw_power_brake_slowdown,clocks_event_reasons.sw_thermal_slowdown,utilization.gpu,utilization.memory,temperature.gpu,temperature.memory,power.management,power.draw,power.draw.average,power.draw.instant,power.limit,enforced.power.limit,power.default_limit,power.max_limit,clocks.current.graphics,clocks.current.memory,clocks.max.graphics,clocks.max.memory --format=csv
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

	if ($isDesktop -or $isVm)
	{
		$activePowerPlan = Get-CimInstance -Namespace root\cimv2\power -Query 'SELECT ElementName,InstanceID,IsActive FROM Win32_PowerPlan WHERE IsActive="True"'
		$powerPlan = "$($activePowerPlan.ElementName) $($activePowerPlan.InstanceID.Replace('Microsoft:PowerPlan\',''))"
	}

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
    	$lastUpdateHotfixIdAccordingToWin32QuickFixEngineering = $lastUpdateAccordingToWin32QuickFixEngineering.HotFixID
    	$lastUpdateInstalledByAccordingToWin32QuickFixEngineering = $lastUpdateAccordingToWin32QuickFixEngineering.InstalledBy
    	# Win32_QuickFixEngineering InstalledOn is in UTC, so to be consistent with other update-related timestamps, converting to local time
    	$lastUpdateTimeAccordingToWin32QuickFixEngineeringUtc = $lastUpdateAccordingToWin32QuickFixEngineering.InstalledOn
    	$lastUpdateTimeAccordingToWin32QuickFixEngineering = $lastUpdateTimeAccordingToWin32QuickFixEngineeringUtc.ToLocalTime()

	$session = New-Object -ComObject Microsoft.Update.Session
	$searcher = $session.CreateUpdateSearcher()
	$historyCount = $searcher.GetTotalHistoryCount()
	try {$queryHistoryResult = $searcher.QueryHistory(0, $historyCount)} catch {}
	if ($queryHistoryResult)
	{
		$lastUpdateAccordingToMicrosoftUpdateSession = $searcher.QueryHistory(0, $historyCount) | Sort-Object Date -Descending | Select-Object -First 1
		$global:dbglastUpdateAccordingToMicrosoftUpdateSession = $lastUpdateAccordingToMicrosoftUpdateSession
		if ($lastUpdateAccordingToMicrosoftUpdateSession)
		{
			$lastUpdateTimeAccordingToMicrosoftUpdateSession = Get-Date -Date $lastUpdateAccordingToMicrosoftUpdateSession.Date.ToLocalTime() -Format yyyy-MM-ddTHH:mm:ss
			$global:dbglastUpdateTimeAccordingToMicrosoftUpdateSession = $lastUpdateTimeAccordingToMicrosoftUpdateSession

			$lastUpdateTitleAccordingToMicrosoftUpdateSession = $lastUpdateAccordingToMicrosoftUpdateSession.Title
			$lastUpdateKBNumberAccordingToMicrosoftUpdateSession = Select-String -InputObject $lastUpdateTitleAccordingToMicrosoftUpdateSession -Pattern 'KB\d{5,8}'
			if ($lastUpdateKBNumberAccordingToMicrosoftUpdateSession)
			{
				$lastUpdateKBNumberAccordingToMicrosoftUpdateSession = $lastUpdateKBNumberAccordingToMicrosoftUpdateSession.Matches.Value.Trim()
			}
			$lastUpdateAccordingToMicrosoftUpdateSessionString = "$(Get-Age $lastUpdateTimeAccordingToMicrosoftUpdateSession) ago $lastUpdateKBNumberAccordingToMicrosoftUpdateSession $lastUpdateTimeAccordingToMicrosoftUpdateSession (Microsoft.Update.Session)"
		}
		else
		{
			$lastUpdateAccordingToMicrosoftUpdateSessionString = "N/A"
		}
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
		$lastThreatDetected = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object ProcessName,Resources,ThreatID,ThreatStatusErrorCode,InitialDetectionTime,RemediationTime,LastThreatStatusChangeTime -First 1
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
	$checkIpResult = Invoke-RestMethod -Uri $checkIpUrl
	if ($checkIpResult)
	{
		$wan = $checkIpResult.Trim()
	}
	$lan = (Get-NetIPAddress | Where-Object AddressFamily -EQ IPv4 | Where-Object PrefixOrigin -EQ Dhcp | Select-Object -First 1 -ExpandProperty IPAddress)
	if ($isPhysicalMachine)
	{
		# $vpnName = 'MSFTVPN-Manual'
		$vpnName = 'Azure VPN'
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
				$vpn = 'Disconnected'
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
	# Get-RegKeyInfo.ps1 -path "HKLM:\SYSTEM\CurrentControlSet\Services"
	# get-item C:\Windows\panther\UnattendGC\setupact.log | select creationtime
	# Profile creation may not be perfect, but so many other ways show the wrong times on some machines - WAY earlier than the OS was installed on
	# Maybe there's some registry key timestamp to use
	# Get-RegKeyInfo.ps1 -path "HKLM:\SYSTEM\CurrentControlSet\Services\vmms" | Select-Object -ExpandProperty LastWriteTime
	# Get-RegKeyInfo.ps1 -path "HKLM:\SYSTEM\CurrentControlSet\Services\w32time" | Select-Object -ExpandProperty LastWriteTime
	# $profileCreationTime = Get-Date -Date (Get-Item -Path $env:USERPROFILE -Force | Select-Object -ExpandProperty CreationTime) -Format yyyy-MM-ddTHH:mm:ss
	# get-service | where status -eq 'running' | select -expand name | %{"$_ $(Get-Date -Date (Get-RegKeyInfo.ps1 -path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" | Select-Object -ExpandProperty LastWriteTime) -Format yyyy-MM-ddTHH:mm:ss)"} | where {$_ -match '2023-07-01'}
	# SharedAccess and W32Time may be keys to use for their lastwritetime as indicative of real OS install time

	$w32TimeRegKeyLastWriteTime = Get-RegKeyInfo -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\w32time' | Select-Object -ExpandProperty LastWriteTime
	$w32TimeRegKeyLastWriteTime = "$(Get-Age -Start $w32TimeRegKeyLastWriteTime) ago $(Get-Date $w32TimeRegKeyLastWriteTime -Format yyyy-MM-dd)"

	$profileCreationTime = Get-Item -Path $env:USERPROFILE -Force | Select-Object -ExpandProperty CreationTime
	$profileCreationTime = "$(Get-Age -Start $profileCreationTime) ago $(Get-Date $profileCreationTime -Format yyyy-MM-dd)"

	$osInstallDateFromRegistry = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name InstallDate
	$osInstallDateFromRegistry = ([datetime]'1/1/1970').AddSeconds($osInstallDateFromRegistry)
	$osInstallDateFromRegistry = "$(Get-Age -Start $osInstallDateFromRegistry) ago $(Get-Date $osInstallDateFromRegistry -Format yyyy-MM-dd)"

	$osInstallDateFromWMI = $win32_OperatingSystem.InstallDate
	$osInstallDateFromWMI = "$(Get-Age -Start $osInstallDateFromWMI) ago $(Get-Date $osInstallDateFromWMI -Format yyyy-MM-dd)"

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
	#else
	#{
		$baseBoardProduct = $win32_BaseBoard.Product
		$baseBoardManufacturer = $win32_BaseBoard.Manufacturer
		$board = "$baseBoardManufacturer $baseBoardProduct BIOS $bios"
	#}

	# $hyperVEnabled = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V | Select-Object -ExpandProperty State

	$logicalDisks = Get-CimInstance -Query 'SELECT DeviceID,Size,FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3'
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
	$objects.Add([PSCustomObject]@{Name = "redmond"; DisplayName = 'Redmond'; Value = $redmond})
	$objects.Add([PSCustomObject]@{Name = "lititz"; DisplayName = 'Lititz'; Value = $lititz})
	$objects.Add([PSCustomObject]@{Name = "rochester"; DisplayName = 'Rochester'; Value = $rochester; EmptyLineAfter = $true})
	# $objects.Add([PSCustomObject]@{Name = "tucson"; DisplayName = ''; Value = $tucson; EmptyLineAfter = $true})
	# $objects.Add([PSCustomObject]@{Name = "lasColinas"; DisplayName = ''; Value = $lasColinas; EmptyLineAfter = $true})
	# $objects.Add([PSCustomObject]@{Name = "bangalore"; DisplayName = ''; Value = $bangalore; EmptyLineAfter = $true})

	<#
	$i = 1
	$weather | ForEach-Object {
		$objects.Add([PSCustomObject]@{Name = "weather$i"; DisplayName = ''; Value = $_})
		$i++
	}
	#>
	$objects.Add([PSCustomObject]@{Name = 'computerName'; DisplayName = 'NAME'; Value = "$computerName $ipV4AddressesString WAN:$wan$(if($vpn){" VPN:$vpn"})"; ValueColor = 'Cyan'})
	$objects.Add([PSCustomObject]@{Name = 'osVersion'; DisplayName = 'OS'; Value = $osVersion})
	$objects.Add([PSCustomObject]@{Name = 'lastBoot'; DisplayName = 'LAST BOOT'; Value = $lastBootUpTimeString})
	# These OS install dates reflect the last cumulative update install, not the original OS install date
	# $objects.Add([PSCustomObject]@{Name = 'osInstallDateFromWMI'; DisplayName = 'OS INSTALLED (WMI)'; Value = $osInstallDateFromWMI})
	# $objects.Add([PSCustomObject]@{Name = 'osInstallDateFromRegistry'; DisplayName = 'OS INSTALLED (REG)'; Value = $osInstallDateFromRegistry})
	$objects.Add([PSCustomObject]@{Name = 'profileCreationTime'; DisplayName = 'PROFILE CREATED'; Value = $profileCreationTime})
	$objects.Add([PSCustomObject]@{Name = 'w32TimeRegKeyLastWriteTime'; DisplayName = 'W32TIME KEY LAST WRITE'; Value = $w32TimeRegKeyLastWriteTime})
	$objects.Add([PSCustomObject]@{Name = 'joinType'; DisplayName = 'JOIN TYPE'; Value = $joinType; EmptyLineAfter = $true})
	# $objects.Add([PSCustomObject]@{Name = 'deviceType'; DisplayName = 'DEVICE TYPE'; Value = $deviceType; EmptyLineAfter = $true})

	$objects.Add([PSCustomObject]@{Name = 'cpu'; DisplayName = 'CPU'; Value = $cpu})
	if ($cpuTemp)
	{
		$objects.Add([PSCustomObject]@{Name = 'cpuTemp'; DisplayName = 'CPU TEMP'; Value = $cpuTemp})
	}
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
	$objects.Add([PSCustomObject]@{Name = 'board'; DisplayName = 'BOARD'; Value = $board})
	$objects.Add([PSCustomObject]@{Name = 'tpm'; DisplayName = 'TPM'; Value = $tpmString})
	# $objects.Add([PSCustomObject]@{Name = 'secureBootEnabled'; DisplayName = 'SECURE BOOT'; Value = $secureBootEnabled})

	foreach ($physicalNic in $physicalNics)
	{
		#$interfaceDescription = $physicalNic.InterfaceDescription.Replace('Intel(R) Ethernet Controller','Intel').Replace('Intel(R) Ethernet Connection','Intel').Replace('(R)','')
		$nicDescription = $physicalNic.DriverDescription.Replace('Intel(R) Ethernet Controller', 'Intel').Replace('Intel(R) Ethernet Connection', 'Intel').Replace('(R)', '')
		$driverInformation = "$($physicalNic.DriverFileName) $(Get-Date -Format $physicalNic.DriverVersionString) NDIS $(Get-Date -Format $physicalNic.NdisVersion) $(Get-Date -Format $physicalNic.DriverDate) $(Get-Age -Start $physicalNic.DriverDate) old"
		$objects.Add([PSCustomObject]@{Name = 'nic'; DisplayName = 'NIC'; Value = "$nicDescription $driverInformation"})
	}
	$objects.Add([PSCustomObject]@{Name = 'disconnectsInfo'; DisplayName = ''; Value = $disconnectsInfo})
	# $objects.Add([PSCustomObject]@{Name = 'hyperVEnabled'; DisplayName = 'HYPER-V'; Value = $hyperVEnabled})
	if ($isDesktop -or $isVm)
	{
		$objects.Add([PSCustomObject]@{Name = 'powerPlan'; DisplayName = 'POWER PLAN'; Value = $powerPlan; EmptyLineAfter = $true})
	}
	else
	{
		$objects.Add([PSCustomObject]@{Name = 'powerMode'; DisplayName = 'POWER MODE'; Value = $powerMode; EmptyLineAfter = $true})
	}

	foreach ($logicalDisk in $logicalDisks)
	{
		$objects.Add([PSCustomObject]@{Name = $logicalDisk.Drive.Replace(' ', ''); DisplayName = $logicalDisk.Drive; Value = $logicalDisk.Details})
	}

	if ($temps)
	{
		$objects.Add([PSCustomObject]@{Name = 'foo'; DisplayName = ''; Value = "`n"})
		foreach ($driveTemp in $driveTemps)
		{
			$driveName = $driveTemp.Name
			$driveTempCurrent = $driveTemp.Temp
			$driveTempMax = $driveTemp.TempMax
			$objects.Add([PSCustomObject]@{Name = $driveName; DisplayName = $driveName; Value = "Temp $($driveTempCurrent)C Max $($driveTempMax)C"})
		}
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
	$objects.Add([PSCustomObject]@{Name = 'lastAntivirusSignatureUpdate'; DisplayName = 'LAST SIGNATURE UPDATE'; Value = $lastAntiVirusSignatureUpdate.Trim()})
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
        # workaround for incorrect resolution being returned if scaling is not 100
        if ($scale -ne 100)
        {
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen
            $currentHorizontalResolution = $screen.Bounds.Width * ($scale/100)
            $currentVerticalResolution = $screen.Bounds.Height * ($scale/100)
        }
		$width = $currentHorizontalResolution
		$height = $currentVerticalResolution
		$workingAreaWidth = $currentHorizontalResolution
		$workingAreaHeight = ($currentVerticalResolution - 8)
		$displaySettings = "$($width)x$($height)x$($scale)"
		Out-Log "Display settings: $displaySettings"
		Out-Log "$($workingAreaWidth)x$($workingAreaHeight) working area" -verboseOnly
	}
	else
	{
		Out-Log 'Unable to determine current display resolution, exiting.'
		exit
	}

	if ([string]::IsNullOrEmpty($PSBoundParameters['fontSize']))
	{
		switch ($displaySettings) {
			"3840x2400x150" {$fontSize = 30}
			"3840x2160x100" {$fontSize = 30}
			"3840x2160x150" {$fontSize = 24}
			"2560x1600x100" {$fontSize = 20}
			"2560x1600x150" {$fontSize = 20}
			"2560x1600x200" {$fontSize = 18}
			"2560x1440x100" {$fontSize = 16}
			"2560x1440x125" {$fontSize = 16}
			"2560x1440x150" {$fontSize = 20}
			"1920x1200x100" {$fontSize = 18}
			"1920x1200x150" {$fontSize = 14}
			"1920x1080x100" {$fontSize = 14}
			Default {$fontSize = 14}
		}
	}
	Out-Log "Font size: $fontSize"

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
			$valueColor = $object.ValueColor

			# https://github.com/search?l=PowerShell&q=Drawing.SolidBrush+DrawString+language%3APowerShell&type=code
			# https://github.com/Fifteen15Studios/PowerShell/blob/9778d0e1e6380f47339573fe32e9f382ef7264ea/Tools/Create-LockScreenImage.ps1#L36
			# w/ MeasureText - https://github.com/search?q=Drawing.SolidBrush+DrawString+MeasureText+language%3APowerShell&type=code
			# w/ MeasureString - https://github.com/search?q=Drawing.SolidBrush+DrawString+MeasureString++language%3APowerShell&type=code
			if ($valueColor -eq 'foo')
			{
				# WORK IN PROGRESS
				$string1 = (Add-Padding -Text $displayName -length $length -align Left)
				$string2 = $value

				$measureTextResult = [Windows.Forms.TextRenderer]::MeasureText($string1, $font).Width
				Out-Log "`$measureTextResult: $measureTextResult" -verboseonly
				#$horizontalPosition += $graphics.MeasureString($string1, $font, (New-Object "System.Drawing.PointF" -ArgumentList @(0, 0)), (New-Object "System.Drawing.StringFormat" -ArgumentList @([System.Drawing.StringFormat]::GenericTypographic)))
				#$measureStringResult = $graphics.MeasureString($string1, $font) | Select-Object -ExpandProperty Width
				#Out-Log "`$measureStringResult:$measureStringResult" -verboseonly
				$horizontalPosition += $measureTextResult
				$graphics.DrawString($string2, $font, $cyan, $horizontalPositionp, $verticalPosition)
			}
			else
			{
				$string = (Add-Padding -Text $displayName -length $length -align Left) + $value
				$graphics.DrawString($string, $font, $white, $horizontalPosition, $verticalPosition)
				[void]$textOutput.Append("$string`n")
			}
		}

		# This controls the spacing between each line. Even without adding 1 to the height there is no overlap, but it looked too cramped that way.
		$verticalPosition += $fontHeight + 5
		if ($object.EmptyLineAfter)
		{
			$verticalPosition += $fontHeight + 5
			[void]$textOutput.Append("`n")
		}
	}

    if ($noWallpaper)
    {
        Out-Log "-noWallpaper specified, skipping wallpaper creation" -verboseonly
    }
    else
    {
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
    }
}

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

if ($env:userdomain -eq 'WORKGROUP')
{
	$userId = "$env:computername\craig"
}
else
{
	$userId = "$env:userdomain\$env:username"
}
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
	Out-Log "Adding scheduled task"
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
   			Get-ScheduledTask -TaskName $taskName
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

if (!$addScheduledTask)
{
	$textOutputString = $textOutput.ToString() | Out-String
	Out-Log $textOutputString -raw
    $outputFolderPath = 'C:\MISC\Set-Wallpaper'
    if (Test-Path -Path $outputFolderPath -PathType Container)
    {
        $filePath = "$outputFolderPath\$($scriptBaseName)_$($env:COMPUTERNAME)_$($scriptStartTimeString).txt"
    }
    else
    {
        $filePath = "$env:TEMP\$($scriptBaseName)_$($env:COMPUTERNAME)_$($scriptStartTimeString).txt"
    }
    $textOutputString | Out-File -FilePath $filePath
    Invoke-Item -Path $filePath
}

if ($currentPSDefaultParameterValues)
{
	$global:PSDefaultParameterValues = $currentPSDefaultParameterValues
}

$esc = [char]0x1b
$reset = "$esc[0m"
$blue = "$esc[94m"
$cyan = "$esc[96m" # $brightCyan = "$esc[96m"
$green = "$esc[92m" # $brightGreen = "$esc[92m"
$gray = "$esc[90m" # $brightBlack = "$esc[90m"
$magenta = "$esc[95m" # $brightMagenta = "$esc[95m"
$red = "$esc[91m" # $brightRed = "$esc[91m"
$white = "$esc[97m" # $brightWhite = "$esc[97m"
$yellow = "$esc[93m" # $brightYellow = "$esc[93m"

Out-Log "Log file: $logFilePath" -verboseOnly -raw
$scriptTimeSpan = New-TimeSpan -Start $global:scriptStartTime -End (Get-Date)
$scriptTotalSeconds = [int]$scriptTimeSpan.TotalSeconds
Out-Log "$($scriptTotalSeconds)s`n" -raw
Out-Log "Run $cyan$('Set-BlankWallpaper.ps1')$reset to set black wallpaper`n" -raw
