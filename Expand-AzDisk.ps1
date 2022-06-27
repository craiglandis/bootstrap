param (
    [string]$resourceGroupName,
    [string]$vmName,
    [int]$newDiskSizeGB = 128,
    [switch]$diskpart
)

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Write-Output $command
    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        Write-Output "Failed: $command"
        Write-Output "`$LASTEXITCODE: $LASTEXITCODE"
    }
}

Set-StrictMode -Version 3.0

if ($diskpart)
{
    # https://github.com/search?l=PowerShell&q=diskpart+extend+size&type=Code
    # list volume
    # select volume <volumenumber>
    # extend [size=<size>]

    $volumes = Get-WmiObject -Class Win32_Volume
    $volumeIndex = 0
    foreach ($volume in $volumes) {
        if ($volume.BootVolume -eq $true)
        {
            $bootVolumeIndex = $volumeIndex
        }
        $volumeIndex++
    }
    $bootVolume = $volumes[$bootVolumeIndex]
    Write-Output "PowerShell $($PSVersionTable.PSVersion.ToString())"
    $os =Get-WmiObject -Class Win32_OperatingSystem
    "$($os.Caption) $(([Environment]::OSVersion).Version.ToString())"
    Write-Output "Boot volume index: $bootVolumeIndex, Name: $($bootVolume.Name), Caption: $($bootVolume.Caption), DriveLetter: $($bootVolume.DriveLetter), DeviceID: $($bootVolume.DeviceID)"
    $capacityBefore = [int]($bootVolume.Capacity/1024/1024/1024)
    Write-Output "Capacity: $([int]($bootVolume.Capacity/1024/1024/1024)) GB, Free $([int]($bootVolume.FreeSpace/1024/1024/1024)) GB, Used: $([int](($bootVolume.Capacity - $bootVolume.FreeSpace)/1024/1024/1024)) GB"

    $diskPartScriptPath = [IO.Path]::GetTempFileName()
    "select volume $bootVolumeIndex" | Out-File -FilePath $diskPartScriptPath -Append -ErrorAction Stop
    "extend" | Out-File -FilePath $diskPartScriptPath -Append -ErrorAction Stop

    & $env:SystemRoot\System32\diskpart.exe $diskPartScriptPath
    Remove-Item -Path $diskPartScriptPath -ErrorAction SilentlyContinue

    $volumes = Get-WmiObject -Class Win32_Volume
    $bootVolume = $volumes[$bootVolumeIndex]
    $capacityAfter = [int]($bootVolume.Capacity/1024/1024/1024)
    if ($capacityAfter -gt $capacityBefore)
    {
        Write-Output "Boot volume successfully expanded"
        Write-Output "Capacity: $([int]($bootVolume.Capacity/1024/1024/1024)) GB, Free $([int]($bootVolume.FreeSpace/1024/1024/1024)) GB, Used: $([int](($bootVolume.Capacity - $bootVolume.FreeSpace)/1024/1024/1024)) GB"
        exit 0
    }
    else
    {
        Write-Error "Failed to expand boot volume"
        exit 1
    }
}
else
{
    $scriptStartTime = Get-Date
    $scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
    $scriptFullName = $MyInvocation.MyCommand.Path
    $scriptPath = Split-Path -Path $scriptFullName
    $scriptName = Split-Path -Path $scriptFullName -Leaf
    $scriptBaseName = $scriptName.Split('.')[0]

    $PSDefaultParameterValues['Write-Output:Level'] = 'Output'
    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    $PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    Invoke-ExpressionWithLogging -command "Stop-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -Force -ErrorAction Stop"
    $vm = Invoke-ExpressionWithLogging -command "Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName"
    $osDiskName = $vm.StorageProfile.OsDisk.Name
    $osDisk = Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName $osDiskName
    $currentDiskSizeGB = $osDisk.DiskSizeGB
    Write-Output "Disk name: $osDiskName Current disk size GB: $currentDiskSizeGB"
    Write-Output "Updating to new disk size GB: $newDiskSizeGB"
    $osDisk.DiskSizeGB = 128
    Invoke-ExpressionWithLogging -command "Update-AzDisk -ResourceGroupName $resourceGroupName -Disk $osDisk -DiskName $osDiskName -ErrorAction Stop"
    Invoke-ExpressionWithLogging -command "Start-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -ErrorAction Stop"

    $expandAzDiskScriptUrl = 'https://raw.githubusercontent.com/craiglandis/bootstrap/main/Expand-AzDisk.ps1'
    $expandAzDiskScriptUrlFileName = $expandAzDiskScriptUrl.Split('/')[-1]
    $settings = @{
        'fileUris'         = @($expandAzDiskScriptUrl)
        'commandToExecute' = "powerShell -ExecutionPolicy Bypass -File $expandAzDiskScriptUrlFileName -diskpart"
        'ticks'            = (Get-Date).ticks
    }
    $publisher = 'Microsoft.Compute'
    $extensionType = 'CustomScriptExtension'
    $name = "$publisher.$extensionType"
    [version]$version = (Get-AzVMExtensionImage -Location $location -PublisherName $publisher -Type $extensionType | sort {[Version]$_.Version} -Desc | select Version -first 1).Version
    $typeHandlerVersion = "$($version.Major).$($version.Minor)"
    $result = Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Publisher $publisher -ExtensionType $extensionType -Name $name -Settings $settings -TypeHandlerVersion $typeHandlerVersion
    Write-Output "Set-AzVMExtension: IsSuccessStatusCode: $($result.IsSuccessStatusCode) StatusCode: $($result.StatusCode) ReasonPhrase: $($result.ReasonPhrase)"
    $scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
    Write-Output "$scriptName duration: $scriptDuration"
}