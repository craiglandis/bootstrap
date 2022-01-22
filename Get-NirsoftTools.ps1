# Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force; \\tsclient\c\onedrive\my\Get-NirsoftTools.ps1
<#
.SYNOPSIS
    Get-Nirsoft.ps1
.DESCRIPTION
    Downloads some Nirsoft tools
    https://www.nirsoft.net/utils/index.html
.PARAMETER uri
    uri
.PARAMETER uri
    toolsPath
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    http://launcher.nirsoft.net/downloads/index.html explains that most of the NirSoft tools can be downloaded in a single zip -

    http://download.nirsoft.net/nirsoft_package_enc_1.23.43.zip

    But some of the password recovery tools get flagged as threats by antivirus, so simpler to just download the few I want
.LINK
    <URL>
#>
param(
    [string]$uri,
    [string]$toolsPath = "$env:SystemDrive\OneDrive\Tools"
)

function Get-Download
{
    param(
        [string]$uri
    )
    $outFile = "$env:TEMP\$(Split-Path -Leaf $uri)"
    $folderName = (Split-Path -Leaf $uri).TrimEnd('.zip')
    $destinationPath = "$env:TEMP\$folderName"
    Write-Output "Downloading $uri to $outFile"
    Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $outFile -ErrorAction Stop #-Verbose
    Expand-Archive -LiteralPath $outFile -DestinationPath $destinationPath -Force
    $newExeFile = Get-ChildItem -Path $destinationPath\*.exe | Select-Object -First 1
    $newExeFileFullName = $newExeFile.FullName
    $newExeFileName = $newExeFile.Name
    $newExeFileVersion = $newExeFile.VersionInfo.FileVersion
    $oldExeFile = Get-ChildItem -Path "$toolsPath\$newExeFileName" -ErrorAction SilentlyContinue
    if ($oldExeFile)
    {
        $oldExeFileFullName = $oldExeFile.Name
        $oldExeFileVersion = $oldExefile.VersionInfo.FileVersion
    }

    if ([Version]$newExeFileVersion -gt [Version]$oldExeFileVersion)
    {
        if ($oldExeFile)
        {
            Write-Output "Replacing $newExeFileName v$($oldExeFileVersion) with v$($newExeFileVersion)"
        }
        else
        {
            Write-Output "Copying $newExeFileName v$($newExeFileVersion) to $("$toolsPath\$newExeFileName")"
        }

        if (!(Test-Path -Path $toolsPath))
        {
            New-Item -Path $toolsPath -ItemType Directory -Force
        }
        Copy-Item -Path $newExeFileFullName -Destination "$toolsPath\$newExeFileName" -Force -ErrorAction Stop
    }
    else
    {
        Write-Output "$oldExeFileFullName v$($oldExeFileVersion) is already the latest version"
    }

    Remove-Item -Path $outFile -Force
}


# https://www.nirsoft.net/utils/index.html
$uris = @'
https://www.nirsoft.net/dot_net_tools/gacview.zip
https://www.nirsoft.net/utils/addrview.zip
https://www.nirsoft.net/utils/advancedrun-x64.zip
https://www.nirsoft.net/utils/allthreadsview-x64.zip
https://www.nirsoft.net/utils/appaudioconfig-x64.zip
https://www.nirsoft.net/utils/appcrashview.zip
https://www.nirsoft.net/utils/batteryinfoview.zip
https://www.nirsoft.net/utils/bluescreenview-x64.zip
https://www.nirsoft.net/utils/bluetoothcl.zip
https://www.nirsoft.net/utils/bulkfilechanger-x64.zip
https://www.nirsoft.net/utils/controlmymonitor.zip
https://www.nirsoft.net/utils/cports-x64.zip
https://www.nirsoft.net/utils/cprocess.zip
https://www.nirsoft.net/utils/csvfileview-x64.zip
https://www.nirsoft.net/utils/deviceioview-x64.zip
https://www.nirsoft.net/utils/devmanview-x64.zip
https://www.nirsoft.net/utils/dllexp-x64.zip
https://www.nirsoft.net/utils/dnsdataview.zip
https://www.nirsoft.net/utils/domainhostingview.zip
https://www.nirsoft.net/utils/dotnetresourcesextract.zip
https://www.nirsoft.net/utils/downtester.zip
https://www.nirsoft.net/utils/driverview-x64.zip
https://www.nirsoft.net/utils/driverview-x64.zip
https://www.nirsoft.net/utils/dumpedid.zip
https://www.nirsoft.net/utils/eventlogchannelsview-x64.zip
https://www.nirsoft.net/utils/eventlogsourcesview-x64.zip
https://www.nirsoft.net/utils/exeinfo.zip
https://www.nirsoft.net/utils/filetypesman-x64.zip
https://www.nirsoft.net/utils/firmwaretablesview-x64.zip
https://www.nirsoft.net/utils/folderchangesview.zip
https://www.nirsoft.net/utils/fulleventlogview-x64.zip
https://www.nirsoft.net/utils/gdiview-x64.zip
https://www.nirsoft.net/utils/guipropview-x64.zip
https://www.nirsoft.net/utils/heapmemview-x64.zip
https://www.nirsoft.net/utils/htmlastext.zip
https://www.nirsoft.net/utils/iconsext.zip
https://www.nirsoft.net/utils/injecteddll.zip
https://www.nirsoft.net/utils/installedappview-x64.zip
https://www.nirsoft.net/utils/installedcodec-x64.zip
https://www.nirsoft.net/utils/installeddriverslist-x64.zip
https://www.nirsoft.net/utils/installedpackagesview-x64.zip
https://www.nirsoft.net/utils/ipinfooffline.zip
https://www.nirsoft.net/utils/ipnetinfo.zip
https://www.nirsoft.net/utils/lastactivityview.zip
https://www.nirsoft.net/utils/loadeddllsview-x64.zip
https://www.nirsoft.net/utils/macaddressview.zip
https://www.nirsoft.net/utils/managewirelessnetworks.zip
https://www.nirsoft.net/utils/monitorinfoview.zip
https://www.nirsoft.net/utils/myeventviewer-x64.zip
https://www.nirsoft.net/utils/netconnectchoose.zip
https://www.nirsoft.net/utils/networkinterfacesview-x64.zip
https://www.nirsoft.net/utils/networktrafficview-x64.zip
https://www.nirsoft.net/utils/nircmd-x64.zip
https://www.nirsoft.net/utils/offlineregistryfinder-x64.zip
https://www.nirsoft.net/utils/offlineregistryview-x64.zip
https://www.nirsoft.net/utils/ofview-x64.zip
https://www.nirsoft.net/utils/openwithview.zip
https://www.nirsoft.net/utils/processactivityview-x64.zip
https://www.nirsoft.net/utils/processthreadsview-x64.zip
https://www.nirsoft.net/utils/regdllview-x64.zip
https://www.nirsoft.net/utils/regfileexport.zip
https://www.nirsoft.net/utils/regfileexport.zip
https://www.nirsoft.net/utils/regfromapp-x64.zip
https://www.nirsoft.net/utils/registrychangesview-x64.zip
https://www.nirsoft.net/utils/registrychangesview-x64.zip
https://www.nirsoft.net/utils/regscanner-x64.zip
https://www.nirsoft.net/utils/resourcesextract-x64.zip
https://www.nirsoft.net/utils/resourcesextract-x64.zip
https://www.nirsoft.net/utils/serviwin-x64.zip
https://www.nirsoft.net/utils/shman-x64.zip
https://www.nirsoft.net/utils/simpleprogramdebugger-x64.zip
https://www.nirsoft.net/utils/simplewmiview-x64.zip
https://www.nirsoft.net/utils/soundvolumeview-x64.zip
https://www.nirsoft.net/utils/specialfoldersview-x64.zip
https://www.nirsoft.net/utils/svcl-x64.zip
https://www.nirsoft.net/utils/sysexp-x64.zip
https://www.nirsoft.net/utils/tabletextcompare.zip
https://www.nirsoft.net/utils/tagsrep.zip
https://www.nirsoft.net/utils/taskschedulerview-x64.zip
https://www.nirsoft.net/utils/uninstallview-x64.zip
https://www.nirsoft.net/utils/userprofilesview.zip
https://www.nirsoft.net/utils/volumouse-x64.zip
https://www.nirsoft.net/utils/whatishang-x64.zip
https://www.nirsoft.net/utils/whoiscl.zip
https://www.nirsoft.net/utils/whoistd.zip
https://www.nirsoft.net/utils/whosip.zip
https://www.nirsoft.net/utils/winexp.zip
https://www.nirsoft.net/utils/winlister-x64.zip
https://www.nirsoft.net/utils/winsockservicesview.zip
https://www.nirsoft.net/utils/winupdatesview-x64.zip
https://www.nirsoft.net/utils/wirelessnetconsole.zip
https://www.nirsoft.net/utils/wul.zip
'@

if ($uri)
{
    Get-Download -uri $uri
}
else
{
    $uris = $uris.Split("`n").Trim()
    foreach ($uri in $uris) {
        Get-Download -uri $uri
    }
}