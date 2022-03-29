#Requires -Modules Helper
param (
    $path = "D:\packages" # where setup EXE will be saved, TODO: caller in bootstrap.ps1 needs to specify "-path $packagesPath"
)

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

Set-StrictMode -Version 3.0
$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

Import-Module -Name Helper -Force
Set-PSFramework
$PSDefaultParameterValues['Write-PSFMessage:Level'] = 'Output'

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

if ((Test-Path -Path $path -PathType Container -ErrorAction SilentlyContinue) -eq $false)
{
    Write-PSFMessage "<c='yellow'>$path</c> not found, using <c='green'>$env:TEMP</c> instead"
    $path = $env:TEMP
}

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
$filePath = "$path\$fileName"

Invoke-ExpressionWithLogging "Invoke-WebRequest -Uri $location -OutFile $filePath"

if (Test-Path -Path $filePath -PathType Leaf)
{
    Write-PSFMessage "Starting: <c='white'>$filePath</c>"
    Start-Process -FilePath $filePath -ArgumentList "/verysilent /loadinf=$infFilePath" -Wait

    $codeCmdFilePath = "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd"
    if (Test-Path -Path $codeCmdFilePath -PathType Leaf)
    {
        Write-PSFMessage "Finished: <c='white'>$filePath</c>"
    }
    else
    {
        Write-PSFMessage "File not found: <c='yellow'>$codeCmdFilePath</c>, either VSCode is not installed, or is installed as user setup instead of system setup"
        exit 2
    }
}