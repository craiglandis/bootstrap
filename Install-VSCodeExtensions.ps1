#Requires -Modules Helper
Set-StrictMode -Version 3.0
$scriptStartTime = Get-Date
$scriptStartTimeString = Get-Date -Date $scriptStartTime -Format yyyyMMddHHmmss
$scriptFullName = $MyInvocation.MyCommand.Path
$scriptName = Split-Path -Path $scriptFullName -Leaf
$scriptBaseName = $scriptName.Split('.')[0]

Import-Module -Name Helper -Force
Set-PSFramework
$PSDefaultParameterValues['Write-PSFMessage:Level'] = 'Output'

$extensionsToInstall = @'
AzurePolicy.azurepolicyextension
bencoleman.armview
christian-kohler.path-intellisense
cschlosser.doxdocgen
Darfka.vbscript
DotJoshJohnson.xml
eamodio.gitlens
fabiospampinato.vscode-todo-plus
golang.go
GrapeCity.gc-excelviewer
IBM.output-colorizer
ionutvmi.reg
jeff-hykin.better-cpp-syntax
jmviz.quote-list
LouisWT.regexp-preview
mark-wiemer.vscode-autohotkey-plus-plus
ms-azuretools.vscode-bicep
ms-dotnettools.csharp
ms-dotnettools.vscode-dotnet-runtime
ms-python.python
ms-python.vscode-pylance
ms-vscode-remote.remote-containers
ms-vscode-remote.remote-ssh
ms-vscode-remote.remote-ssh-edit
ms-vscode-remote.remote-wsl
ms-vscode.azure-account
ms-vscode.azurecli
ms-vscode.cmake-tools
ms-vscode.cpptools
ms-vscode.cpptools-extension-pack
ms-vscode.cpptools-themes
ms-vscode.powershell
msazurermtools.azurerm-vscode-tools
rangav.vscode-thunder-client
redhat.vscode-yaml
twxs.cmake
TylerLeonhardt.vscode-inline-values-powershell
Tyriar.sort-lines
VisualStudioExptTeam.vscodeintellicode
vscode-icons-team.vscode-icons
vsls-contrib.gistfs
yzhang.markdown-all-in-one
'@
$extensionsToInstall = $extensionsToInstall.Split("`n").Trim()

$installedExtensions = & "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd" --list-extensions

foreach ($extensionToInstall in $extensionsToInstall) {
    if ($installedExtensions.Contains($extensionToInstall))
    {
        Write-PSFMessage "Already installed: <c='green'>$extensionToInstall</c>"
    }
    else
    {
        # To test, uninstall one first:
        # & "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd" --uninstall-extension redhat.vscode-yaml
        Write-PSFMessage "Installing: <c='white'>$extensionToInstall</c>"
        & "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd" --install-extension $extensionToInstall | Out-Null
    }
}

$scriptDuration = '{0:hh}:{0:mm}:{0:ss}.{0:ff}' -f (New-TimeSpan -Start $scriptStartTime -End (Get-Date))
Write-PSFMessage "$scriptName duration: <c='white'>$scriptDuration</c>"