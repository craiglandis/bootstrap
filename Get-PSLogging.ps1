param(
    [switch]$enable,
    [switch]$disable,
    [switch]$export,
    [switch]$clear,
    [string]$exportFile = "$PWD\$($MyInvocation.MyCommand.Name.Replace('.ps1', ''))_$(Get-Date ((Get-Date).ToUniversalTime()) -format yyyyMMddHHmmss).csv",
    [string]$outputDirectory = 'C:\Transcripts',
    [Int]$maximumSizeInBytes = 104857600, # 104857600 bytes = 100MB
    [Int]$hours = 1
)

$now = Get-Date
$startTimeUtc = Get-Date ($now.AddHours(-$hours).ToUniversalTime()) -format 'yyyy-MM-ddTHH:mm:ssZ'
$endTimeUtc = Get-Date ($now.ToUniversalTime()) -format 'yyyy-MM-ddTHH:mm:ssZ'

$auditKeyName = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$processCreationIncludeCmdLine_EnabledValueName = 'ProcessCreationIncludeCmdLine_Enabled'
$transcriptionKeyName = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$enableTranscriptingValueName = 'EnableTranscripting'
$enableInvocationHeaderValueName = 'EnableInvocationHeader'
$outputDirectoryValueName = 'OutputDirectory'
$moduleLoggingKeyName = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$enableModuleLoggingValueName = 'EnableModuleLogging'
$moduleNamesKeyName = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
$moduleNamesValueName = '*'
$scriptBlockLoggingKeyName = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$enableScriptBlockLoggingValueName = 'EnableScriptBlockLogging'

function Get-Config
{
    $securityMaxSize = (Get-WinEvent -ListLog 'Security').MaximumSizeInBytes
    $powerShellOperationalMaxSize = (Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes
    Write-Output "Security log max size: $($securityMaxSize/1MB)MB ($securityMaxSize bytes)"
    Write-Output "Microsoft-Windows-PowerShell/Operational max size: $($powerShellOperationalMaxSize/1MB)MB ($powerShellOperationalMaxSize bytes)"

    if ((auditpol /get /subcategory:'Process Creation') -match 'Success')
    {
        Write-Output "`nAudit Process Creation: True"
    }
    else
    {
        Write-Output "`nAudit Process Creation: False"
    }

    $processCreationIncludeCmdLine_EnabledValueData = Get-ItemProperty -Path $auditKeyName -ErrorAction SilentlyContinue | Select-Object $processCreationIncludeCmdLine_EnabledValueName -ExpandProperty $processCreationIncludeCmdLine_EnabledValueName
    Write-Output "`n$auditKeyName"
    if ($processCreationIncludeCmdLine_EnabledValueData)
    {
        Write-Output "`t$processCreationIncludeCmdLine_EnabledValueName`: $processCreationIncludeCmdLine_EnabledValueData"
    }
    else
    {
        Write-Output "`t$processCreationIncludeCmdLine_EnabledValueName`: <registry value does not exist>"
    }

    $enableTranscriptingValueData = Get-ItemProperty -Path $transcriptionKeyName -ErrorAction SilentlyContinue | Select-Object $enableTranscriptingValueName -ExpandProperty $enableTranscriptingValueName
    Write-Output "`n$transcriptionKeyName"
    if ($enableTranscriptingValueData)
    {
        Write-Output "`t$enableTranscriptingValueName`: $enableTranscriptingValueData"
    }
    else
    {
        Write-Output "`t$enableTranscriptingValueName`: <registry value does not exist>"
    }

    $enableInvocationHeaderValueData = Get-ItemProperty -Path $transcriptionKeyName -ErrorAction SilentlyContinue | Select-Object $enableInvocationHeaderValueName -ExpandProperty $enableInvocationHeaderValueName
    if ($enableInvocationHeaderValueData)
    {
        Write-Output "`t$enableInvocationHeaderValueName`: $enableInvocationHeaderValueData"
    }
    else
    {
        Write-Output "`t$enableInvocationHeaderValueName`: <registry value does not exist>"
    }

    $outputDirectoryValueData = Get-ItemProperty -Path $transcriptionKeyName -ErrorAction SilentlyContinue | Select-Object $outputDirectoryValueName -ExpandProperty $outputDirectoryValueName
    if ($outputDirectoryValueData)
    {
        Write-Output "`t$outputDirectoryValueName`: $outputDirectoryValueData"
    }
    else
    {
        Write-Output "`t$outputDirectoryValueName`: <registry value does not exist>"
    }

    $enableModuleLoggingValueData = Get-ItemProperty -Path $moduleLoggingKeyName -ErrorAction SilentlyContinue | Select-Object $enableModuleLoggingValueName -ExpandProperty $enableModuleLoggingValueName
    Write-Output "`n$moduleLoggingKeyName"
    if ($enableModuleLoggingValueData)
    {
        Write-Output "`t$enableModuleLoggingValueName`: $enableModuleLoggingValueData"
    }
    else
    {
        Write-Output "`t$enableModuleLoggingValueName`: <registry value does not exist>"
    }

    $ErrorActionPreference = 'SilentlyContinue'
    $moduleNamesValueData = Get-ItemPropertyValue -Path $moduleNamesKeyName -Name $moduleNamesValueName
    $ErrorActionPreference = 'Continue'
    Write-Output "`n$moduleNamesKeyName"
    if ($moduleNamesValueData)
    {
        Write-Output "`t$moduleNamesValueName`: $moduleNamesValueData"
    }
    else
    {
        Write-Output "`t$moduleNamesValueName`: <registry value does not exist>"
    }

    $enableScriptBlockLoggingValueData = Get-ItemProperty -Path $scriptBlockLoggingKeyName -ErrorAction SilentlyContinue | Select-Object $enableScriptBlockLoggingValueName -ExpandProperty $enableScriptBlockLoggingValueName
    Write-Output "`n$scriptBlockLoggingKeyName"
    if ($enableScriptBlockLoggingValueData)
    {
        Write-Output "`t$enableScriptBlockLoggingValueName`: $enableScriptBlockLoggingValueData"
    }
    else
    {
        Write-Output "`t$enableScriptBlockLoggingValueName`: <registry value does not exist>"
    }
}

function Enable-Logging
{
    $securityMaxSize = (Get-WinEvent -ListLog 'Security').MaximumSizeInBytes
    if ($securityMaxSize -lt $maximumSizeInBytes)
    {
        wevtutil sl 'Security' /ms:$maximumSizeInBytes
    }

    $powerShellOperationalMaxSize = (Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes
    if ($powerShellOperationalMaxSize -lt $maximumSizeInBytes)
    {
        wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:$maximumSizeInBytes
    }

    $auditProcessCreation = auditpol /get /subcategory:'Process Creation'
    if ($auditProcessCreation -match 'No Auditing')
    {
        auditpol /set /subcategory:'Process Creation' /success:enable | Out-Null
    }

    If ((Test-Path $auditKeyName) -eq $false)
    {
        New-Item -Path $auditKeyName -Force | Out-Null
    }
    New-ItemProperty -Path $auditKeyName -Name $processCreationIncludeCmdLine_EnabledValueName -PropertyType 'DWord' -Value 1 -Force | Out-Null

    If ((Test-Path $transcriptionKeyName) -eq $false)
    {
        New-Item -Path $transcriptionKeyName -Force | Out-Null
    }
    New-ItemProperty -Path $transcriptionKeyName -Name $enableTranscriptingValueName -PropertyType 'DWord' -Value 1 -Force | Out-Null
    New-ItemProperty -Path $transcriptionKeyName -Name $enableInvocationHeaderValueName -PropertyType 'DWord' -Value 1 -Force | Out-Null
    New-ItemProperty -Path $transcriptionKeyName -Name $outputDirectoryValueName -PropertyType 'String' -Value $outputDirectory -Force | Out-Null

    If ((Test-Path $moduleLoggingKeyName) -eq $false)
    {
        New-Item -Path $moduleLoggingKeyName -Force | Out-Null
    }
    New-ItemProperty -Path $moduleLoggingKeyName -Name $enableModuleLoggingValueName -PropertyType 'DWord' -Value 1 -Force | Out-Null

    If ((Test-Path $moduleNamesKeyName) -eq $false)
    {
        New-Item -Path $moduleNamesKeyName -Force | Out-Null
    }
    New-ItemProperty -Path $moduleNamesKeyName -Name $moduleNamesValueName -PropertyType 'String' -Value '*' | Out-Null

    If ((Test-Path $scriptBlockLoggingKeyName) -eq $false)
    {
        New-Item -Path $scriptBlockLoggingKeyName -Force | Out-Null
    }
    New-ItemProperty -Path $scriptBlockLoggingKeyName -Name $enableScriptBlockLoggingValueName -PropertyType 'DWord' -Value 1 -Force | Out-Null
}

function Disable-Logging
{
    $securityMaxSize = (Get-WinEvent -ListLog 'Security').MaximumSizeInBytes
    if ($securityMaxSize -eq $maximumSizeInBytes)
    {
        wevtutil sl 'Security' /ms:20971520 # 20MB
    }

    $powerShellOperationalMaxSize = (Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational').MaximumSizeInBytes
    if ($powerShellOperationalMaxSize -eq $maximumSizeInBytes)
    {
        wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:15728640 # 15MB
    }

    $auditProcessCreation = auditpol /get /subcategory:'Process Creation'
    if ($auditProcessCreation -match 'Success')
    {
        auditpol /set /subcategory:'Process Creation' /success:disable | Out-Null
    }

    $processCreationIncludeCmdLine_EnabledValueData = Get-ItemProperty -Path $auditKeyName -ErrorAction SilentlyContinue | Select-Object $processCreationIncludeCmdLine_EnabledValueName -ExpandProperty $processCreationIncludeCmdLine_EnabledValueName
    if ($processCreationIncludeCmdLine_EnabledValueData -eq 1)
    {
        New-ItemProperty -Path $auditKeyName -Name $processCreationIncludeCmdLine_EnabledValueName -PropertyType 'DWord' -Value 0 -Force | Out-Null
    }

    $enableTranscriptingValueData = Get-ItemProperty -Path $transcriptionKeyName -ErrorAction SilentlyContinue | Select-Object $enableTranscriptingValueName -ExpandProperty $enableTranscriptingValueName
    if ($enableTranscriptingValueData -eq 1)
    {
        New-ItemProperty -Path $transcriptionKeyName -Name $enableTranscriptingValueName -PropertyType 'DWord' -Value 0 -Force | Out-Null
    }

    $enableInvocationHeaderValueData = Get-ItemProperty -Path $transcriptionKeyName -ErrorAction SilentlyContinue | Select-Object $enableInvocationHeaderValueName -ExpandProperty $enableInvocationHeaderValueName
    if ($enableInvocationHeaderValueData -eq 1)
    {
        New-ItemProperty -Path $transcriptionKeyName -Name $enableInvocationHeaderValueName -PropertyType 'DWord' -Value 0 -Force | Out-Null
    }

    $outputDirectoryValueData = Get-ItemProperty -Path $transcriptionKeyName -ErrorAction SilentlyContinue | Select-Object $outputDirectoryValueName -ExpandProperty $outputDirectoryValueName
    if ($outputDirectoryValueData -eq 1)
    {
        Remove-ItemProperty -Path $transcriptionKeyName -Name $outputDirectoryValueName
    }

    $enableModuleLoggingValueData = Get-ItemProperty -Path $moduleLoggingKeyName -ErrorAction SilentlyContinue | Select-Object $enableModuleLoggingValueName -ExpandProperty $enableModuleLoggingValueName
    if ($enableModuleLoggingValueData -eq 1)
    {
        New-ItemProperty -Path $moduleLoggingKeyName -Name $enableModuleLoggingValueName -PropertyType 'DWord' -Value 0 -Force | Out-Null
    }

    $moduleNamesValueData = Get-ItemProperty -Path $moduleNamesKeyName -ErrorAction SilentlyContinue | Select-Object $moduleNamesValueName -ExpandProperty $moduleNamesValueName
    if ($moduleNamesValueData -eq 1)
    {
        Remove-ItemProperty -Path $moduleNamesKeyName -Name $moduleNamesValueName
    }

    New-ItemProperty -Path $scriptBlockLoggingKeyName -Name $enableScriptBlockLoggingValueName -PropertyType 'DWord' -Value 1 -Force | Out-Null
    $enableScriptBlockLoggingValueData = Get-ItemProperty -Path $scriptBlockLoggingKeyName -ErrorAction SilentlyContinue | Select-Object $enableScriptBlockLoggingValueName -ExpandProperty $enableScriptBlockLoggingValueName
    if ($enableScriptBlockLoggingValueData -eq 1)
    {
        New-ItemProperty -Path $scriptBlockLoggingKeyName -Name $enableScriptBlockLoggingValueName -PropertyType 'DWord' -Value 0 -Force | Out-Null
    }
}

function Export-Logging
{
    $hours = 1
    $now = Get-Date
    $startTimeUtc = Get-Date ($now.AddHours(-$hours).ToUniversalTime()) -format 'yyyy-MM-ddTHH:mm:ssZ'
    $endTimeUtc = Get-Date ($now.ToUniversalTime()) -format 'yyyy-MM-ddTHH:mm:ssZ'

$filterXML = @"
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security">
            Event
            [
                System
                [
                    (EventID = '4688' or EventID = '4689')
                    and
                    TimeCreated
                    [
                        @SystemTime &gt;= '$startTimeUtc'
                        and
                        @SystemTime &lt;= '$endTimeUtc'
                    ]
                ]
                and
                EventData
                [
                    Data[@Name="SubjectUserSid"] = "S-1-5-18"
                ]
            ]
        </Select>
    </Query>
    <Query Id="1" Path="Microsoft-Windows-PowerShell/Operational">
        <Select Path="Microsoft-Windows-PowerShell/Operational">
            Event
            [
                System
                [
                    (EventID ='4103' or EventID ='4104')
                    and
                    Security
                    [
                        @UserID ='S-1-5-18'
                    ]
                    and
                    TimeCreated
                    [
                        @SystemTime &gt;= '$startTimeUtc'
                        and
                        @SystemTime &lt;= '$endTimeUtc'
                    ]
                ]
            ]
        </Select>
    </Query>
</QueryList>
"@

    Write-Output "Querying for events between $startTimeUtc and $endTimeUtc"
    $events = get-winevent -FilterXml $filterXML | Sort-Object TimeCreated
    if ($events)
    {
        $events | Group-Object -Property Id | Sort-Object -Property Name | Format-Table -Property @{Label = 'EventID'; Expression ={$_.Name}}, Count -AutoSize
        $events = $events | Select-Object -Property RecordId, TimeCreated, Id, MachineName, LogName, TaskDisplayName, Message
        # Find-Module -Name ImportExcel -Repository PSGallery
        # Install-Module -Name ImportExcel -Repository PSGallery
        # PowerShellGet requires NuGet provider version '2.8.5.201' or newer to interact with NuGet-based repositories.
        if (Get-Module -Name ImportExcel -ListAvailable)
        {
            Import-Module -Name ImportExcel
            $exportFile = $exportFile.Replace('.csv', '.xlsx')
            Write-Output "Exporting $($events.Count) events to file: $exportFile"
            $events | Export-Excel -Path $exportFile -TableStyle 'Medium13' -TableName 'Events' -AutoSize
        }
        else
        {
            Write-Output "Exporting $($events.Count) events to file: $exportFile"
            $events | Export-Csv -Path $exportFile -NoTypeInformation
        }
    }
    else
    {
        Write-Output "No events found."
    }
}

function Clear-Logs
{
    if((Read-Host -Prompt 'Clear Security event log and Microsoft-Windows-PowerShell/Operational event log?[Y/N]') -imatch 'Y')
    {
        wevtutil.exe cl Security
        wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
    }
}

if ($PSBoundParameters.Count -eq 0)
{
    Get-Config
}
elseif ($enable)
{
    Enable-Logging
    Get-Config
}
elseif ($disable)
{
    Disable-Logging
    Get-Config
}
elseif ($export)
{
    Export-Logging -path $exportFile
}
elseif ($clear)
{
    Disable-Logging
    Clear-Logs
}