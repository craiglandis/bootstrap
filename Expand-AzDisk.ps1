param (
    [string]$resourceGroupName = 'rg',
    [string]$vmName = 'ws08r2test1',
    [int]$newDiskSizeGB = 128,
    [switch]$diskpart
)

function Invoke-ExpressionWithLogging
{
    param(
        [string]$command
    )
    Write-Host $command
    try
    {
        Invoke-Expression -Command $command
    }
    catch
    {
        Write-Host "Failed: $command"
        Write-Host "`$LASTEXITCODE: $LASTEXITCODE"
    }
}

if ($diskpart)
{
    # https://github.com/search?l=PowerShell&q=diskpart+extend+size&type=Code

    $volumes = Get-WmiObject -Class Win32_Volume
    $volumeIndex = 0
    foreach ($volume in $volumes)
    {
        if ($volume.BootVolume -eq $true)
        {
            $bootVolumeIndex = $volumeIndex
        }
        $volumeIndex++
    }
    $bootVolume = $volumes[$bootVolumeIndex]
    Write-Output "PowerShell $($PSVersionTable.PSVersion.ToString())"
    $os = Get-WmiObject -Class Win32_OperatingSystem
    Write-Output "$($os.Caption) $(([Environment]::OSVersion).Version.ToString())"
    Write-Output "Boot volume index: $bootVolumeIndex, Name: $($bootVolume.Name), Caption: $($bootVolume.Caption), DriveLetter: $($bootVolume.DriveLetter), DeviceID: $($bootVolume.DeviceID)"
    $capacityBefore = [int]($bootVolume.Capacity / 1024 / 1024 / 1024)
    Write-Output "Capacity: $capacityBefore GB, Free $([int]($bootVolume.FreeSpace/1024/1024/1024)) GB, Used: $([int](($bootVolume.Capacity - $bootVolume.FreeSpace)/1024/1024/1024)) GB"

    # -Encoding ASCII is necessary with Out-File, else the file is created as Unicode, and Diskpart just returns its help syntax when you try to use it
    $diskPartScriptPath = [IO.Path]::GetTempFileName()
    "select volume $bootVolumeIndex" | Out-File -FilePath $diskPartScriptPath -Encoding ASCII -Append -ErrorAction Stop
    "extend" | Out-File -FilePath $diskPartScriptPath -Encoding ASCII -Append -ErrorAction Stop
    & $env:SystemRoot\System32\diskpart.exe /s $diskPartScriptPath
    Remove-Item -Path $diskPartScriptPath -ErrorAction SilentlyContinue

    $volumes = Get-WmiObject -Class Win32_Volume
    $bootVolume = $volumes[$bootVolumeIndex]
    $capacityAfter = [int]($bootVolume.Capacity/1024/1024/1024)
    if ($capacityAfter -gt $capacityBefore)
    {
        Write-Output 'Boot volume successfully expanded'
        Write-Output "Capacity: $capacityAfter GB, Free $([int]($bootVolume.FreeSpace/1024/1024/1024)) GB, Used: $([int](($bootVolume.Capacity - $bootVolume.FreeSpace)/1024/1024/1024)) GB"
        exit 0
    }
    else
    {
        Write-Error 'Failed to expand boot volume'
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

    $vmStatus = Invoke-ExpressionWithLogging -command "Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -Status -ErrorAction Stop"
    $powerState = ($vmStatus.Statuses | Where-Object {$_.Code -match 'PowerState'}).Code.Split('/')[1]
    if ($powerState -ne 'deallocated')
    {
        $result = Invoke-ExpressionWithLogging -command "Stop-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -Force -ErrorAction Stop"
    }
    $vm = Invoke-ExpressionWithLogging -command "Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -ErrorAction Stop"
    $location = $vm.Location
    $osDiskName = $vm.StorageProfile.OsDisk.Name
    $osDisk = Invoke-ExpressionWithLogging -command "Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName $osDiskName"
    $currentDiskSizeGB = $osDisk.DiskSizeGB
    Write-Output "Current OS disk size GB: $currentDiskSizeGB OS disk name: $osDiskName"
    Write-Output "Updating OS disk to new disk size: $newDiskSizeGB GB"
    $osDisk.DiskSizeGB = $newDiskSizeGB
    Write-Output "Update-AzDisk -ResourceGroupName $resourceGroupName -Disk `$osDisk -DiskName $osDiskName -ErrorAction Stop"
    $result = Update-AzDisk -ResourceGroupName $resourceGroupName -Disk $osDisk -DiskName $osDiskName -ErrorAction Stop
    Invoke-ExpressionWithLogging -command "Start-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -ErrorAction Stop"
    do
    {
        Start-Sleep -Seconds 3
        $vmStatus = Invoke-ExpressionWithLogging -command "Get-AzVM -ResourceGroupName $resourceGroupName -Name $vmName -Status -ErrorAction Stop"
        $vmAgentStatus = $vmStatus.VMAgent.Statuses.DisplayStatus
        $powerState = ($vmStatus.Statuses | Where-Object {$_.Code -match 'PowerState'}).Code.Split('/')[1]
    } until ($vmAgentStatus -eq 'Ready' -and $powerState -eq 'running')
    Write-Output "Power state: $powerState, VM agent status: $vmAgentStatus"

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
    [version]$version = (Get-AzVMExtensionImage -Location $location -PublisherName $publisher -Type $extensionType | Sort-Object {[Version]$_.Version} -Desc | Select-Object Version -First 1).Version
    $typeHandlerVersion = "$($version.Major).$($version.Minor)"
    $result = Set-AzVMExtension -Location $location -ResourceGroupName $resourceGroupName -VMName $vmName -Publisher $publisher -ExtensionType $extensionType -Name $name -Settings $settings -TypeHandlerVersion $typeHandlerVersion
    $extensionStatus = Get-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName -Name $name -Status
    $stdout = $extensionStatus.SubStatuses | Where-Object {$_.Code -eq 'ComponentStatus/StdOut/succeeded'}
    $stdoutMessage = $stdout.Message
    Write-Output "STDOUT: `n$stdoutMessage"
    if ($extensionStatus.ProvisioningState -eq 'Failed')
    {
        $extensionErrorMessage = $extensionStatus.Statuses.Message
        $stderr = $extensionStatus.SubStatuses | Where-Object {$_.Code -eq 'ComponentStatus/StdErr/succeeded'}
        $stderrMessage = $stderr.Message
        Write-Output $extensionErrorMessage
        Write-Output "STDERR: `n$stderrMessage"
    }

    $scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
    Write-Output "$scriptName duration: $scriptDuration"
}