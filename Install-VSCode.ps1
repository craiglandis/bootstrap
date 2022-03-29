function Get-RedirectedUrl
{
    param (
        [parameter(Mandatory=$true)]
        [string]$url
    )

    $request = [System.Net.WebRequest]::Create($url)
    $request.AllowAutoRedirect = $false
    $response = $request.GetResponse()

    if ($response.StatusCode -eq 'Found')
    {
        $response.GetResponseHeader('Location')
    }
}

$infContents = @'
[Setup]
Lang=english
Dir=C:\Program Files\Microsoft VS Code
Group=Visual Studio Code
NoIcons=0
Tasks=addcontextmenufiles,addcontextmenufolders,associatewithfiles,addtopath,!runcode
'@
$infFilePath = "$env:TEMP\vscode.inf"
$infContents | Out-File -FilePath $infFilePath -Force

# TODO: needs to be updated
$downloadPath = 'c:\my'

<#
Using https://update.code.visualstudio.com/latest/win32-x64/stable because it is more desciptive than https://go.microsoft.com/fwlink/?Linkid=852157,
though both of those URLs are functionally identical in my testing.

They both seem like permanent links in as much as any link is ever 'permanent'.
They both redirect to the latest VSCodeSetup-x64-<version>.exe, for example:

https://az764295.vo.msecnd.net/stable/c722ca6c7eed3d7987c0d5c3df5c45f6b15e77d1/VSCodeSetup-x64-1.65.2.exe

Using https://update.code.visualstudio.com/latest/win32-x64/stable because it's more descriptive than the fwlink URL.
#>
$url = 'https://update.code.visualstudio.com/latest/win32-x64/stable'
$location = Get-RedirectedUrl -url $url
$fileName = $location.Split('/')[-1]
$filePath = "$downloadPath\$fileName"

$command ="Invoke-WebRequest -Uri $location -OutFile $filePath"
Invoke-Expression $command

if (Test-Path -Path $filePath -PathType Leaf)
{
    Start-Process -FilePath $filePath -ArgumentList "/verysilent /loadinf=$infFilePath"
}