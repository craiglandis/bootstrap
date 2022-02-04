param(
    [string]$userName,
    [string]$password,
    [string]$bootstrapScriptUrl
)

$bootstrapScriptFileName = $bootstrapScriptUrl.Split('/')[-1]
$bootstrapScriptFilePath = "$env:TEMP\$bootstrapScriptFileName"
(New-Object Net.Webclient).DownloadFile($bootstrapScriptUrl, $bootstrapScriptFilePath)

if (Test-Path -Path $bootstrapScriptFilePath -PathType Leaf)
{
    $passwordSecureString = ConvertTo-SecureString -String $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$userName", $passwordSecureString)    
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    Invoke-Command -FilePath $bootstrapScriptFilePath -Credential $credential -ComputerName localhost #$env:COMPUTERNAME
    Disable-PSRemoting -Force
}
else
{
    Write-Error "File not found: $bootstrapScriptFilePath"
    exit 2
}
