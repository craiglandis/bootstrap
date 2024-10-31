$btDevices = Get-PnpDevice -Class 'Bluetooth'
foreach ($device in $btDevices)
{
    $btDeviceProperty = Get-PnpDeviceProperty -KeyName 'DEVPKEY_Bluetooth_RadioLmpVersion' -InstanceId $device.InstanceID
    if ($btDeviceProperty -And $btDeviceProperty.Data)
    {
        $bluetoothVersion = switch ($btDeviceProperty.Data)
        {
            0 {'1.0b'}
            1 {'1.1'}
            2 {'1.2'}
            3 {'2.0 + EDR'}
            4 {'2.1 + EDR'}
            5 {'3.0 + HS'}
            6 {'4.0'}
            7 {'4.1'}
            8 {'4.2'}
            9 {'5.0'}
            10 {'5.1'}
            11 {'5.2'}
            12 {'5.3'}
            13 {'5.4'}
            14 {'6.0'}
            default {'UKNOWN'}
        }
    }
}
Write-Host $bluetoothVersion