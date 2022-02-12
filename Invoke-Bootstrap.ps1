# Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; \\tsclient\c\onedrive\my\Invoke-Bootstrap.ps1 -userName craig -password $password -bootstrapScriptUrl https://raw.githubusercontent.com/craiglandis/bootstrap/main/bootstrap.ps1
param(
    [string]$userName,
    [string]$password,
    [string]$bootstrapScriptUrl
)

$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'

if (!$userName)
{
    Write-Error "Required parameter missing: -userName <userName>"
    exit
}
elseif (!$password)
{
    Write-Error "Required parameter missing: -password <password>"
    exit
}
elseif (!$bootstrapScriptUrl)
{
    Write-Error "Required parameter missing: -bootstrapScriptUrl <bootstrapScriptUrl>"
    exit
}

$bsPath = "$env:SystemDrive\bs"
if (Test-Path -Path $bsPath -PathType Container)
{
    Write-Output "Log path $bsPath already exists, don't need to create it"
}
else
{
    Write-Output "Creating log path $bsPath"
    New-Item -Path $bsPath -ItemType Directory -Force | Out-Null
}

$bootstrapScriptFileName = $bootstrapScriptUrl.Split('/')[-1]
$bootstrapScriptFilePath = "$bsPath\$bootstrapScriptFileName"
Write-Output "Downloading $bootstrapScriptUrl to $bootstrapScriptFilePath"
(New-Object Net.Webclient).DownloadFile($bootstrapScriptUrl, $bootstrapScriptFilePath)

if (Test-Path -Path $bootstrapScriptFilePath -PathType Leaf)
{
    $passwordSecureString = ConvertTo-SecureString -String $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$userName", $passwordSecureString)
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    Invoke-Command -Credential $credential -ComputerName localhost -ScriptBlock {param($scriptPath) & $scriptPath} -ArgumentList $bootstrapScriptFilePath
    Disable-PSRemoting -Force
}
else
{
    Write-Error "File not found: $bootstrapScriptFilePath"
    exit 2
}
