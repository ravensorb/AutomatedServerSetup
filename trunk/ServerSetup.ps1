param(
	[string] $configurationFile = "$PSScriptRoot\ServerSetup.xml"
)

$folderDesktop = [Environment]::GetFolderPath("Desktop")
$date = Get-Date -format "yyyyMMdd"
Start-Transcript "$folderDesktop\Setup-Server-Transcript-$date.rtf" -Append

$scriptCommand = $myinvocation.mycommand.definition
$workingDirectory = $PSScriptRoot
if ($workingDirectory -eq $null -or $workingDirectory.length -eq 0) {
	$workingDirectory = Split-Path $scriptCommand
}

Write-Host "Script: [$scriptCommand]" -Foregroundcolor Yellow
Write-Host "Working Directory: [$workingDirectory]" -Foregroundcolor Yellow
Write-Host "Configuration File: [$configurationFile]" -Foregroundcolor Yellow

$configurationFile = $configurationFile.Trim() -Replace "'",""

Import-Module "$workingDirectory\PSUtils" -Force

function Force-RunAsAdmin {
	if (-Not (Test-IsAdmin) -and (Test-IsUacEnabled)) {
		Write-Warning "This script needs to be run under elevated permissions.  Please wait while we restart the script in this mode."
		Stop-Transcript 
		Start-Process -ExecutionPolicy ByPass -Verb Runas -WorkingDirectory $workingDirectory -FilePath PowerShell.exe -ArgumentList "$workingDirectory\Setup-Server.ps1 -configurationFile $configurationFile"
		break
	}
}

function Restart {
	Write-Host "Setting RunOnce: $scriptCommand"
	Set-RunOnce -Description "SharePoint 2013 Server Set-up" -FileToRun $scriptCommand -Arguments "-configurationFile $configurationFile"
	
	Write-Host "The Computer will reboot in 10 seconds...."
	sleep 10
	Restart-Computer 
	
	exit
}

write-Host "Validating script is running under Administrative credentials" -Foregroundcolor Green
Force-RunAsAdmin

write-Host "Loading Configuration File: $configurationFile" -Foregroundcolor Green
$xmlSettings = New-Object -TypeName XML
$xmlSettings.Load($configurationFile)
$debug = $false
if ($xmlSettings.configuration.mode -eq "DEBUG") { $debug = $true }
if ($xmlSettings.configuration.workingDirectory -eq $null) {
	$xmlSettings.configuration.SetAttribute("workingDirectory", $workingDirectory)
}

Import-Module "$workingDirectory\ServerSetupCoreFuncs.ps1" -Force

$result = @{}

write-Host "Configuring Local Computer" -Foregroundcolor Green
$result["localcomputer"] = (Execute-ConfigureLocalComputer $xmlSettings)

write-Host "Setting up Chocolatey and related packages" -Foregroundcolor Green
$result["chocolatey"] = (Execute-InstallChocolatey $xmlSettings)
if ((Get-PendingReboot).RebootPending -eq $true) { Restart }

write-Host "Renaming Local Computer" -Foregroundcolor Green
$result["renamecomputer"] = (Execute-RenameComputer $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart }

write-Host "Configuring Windows Update" -Foregroundcolor Green
$result["wupdateconfig"] = (Execute-ConfigureWindowsUpdate $xmlSettings)

write-Host "Executing Windows Update" -Foregroundcolor Green
$result["wupdate"] = (Execute-WindowsUpdate $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart }

write-Host "Validating Network Configuration" -Foregroundcolor Green
$result["network"] = (Validate-NetworkConfiguration $xmlSettings)

write-Host "Installing Windows Features" -Foregroundcolor Green
$result["features"] = (Execute-InstallWindowsFeatures $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart }

write-Host "Installing and Configuring Active Directory" -Foregroundcolor Green
$result["ad"] = (Execute-ActiveDirectoryConfiguration $xmlSettings)
if ($result["ad"] -eq $true) { Restart }
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart }

write-Host "Creating Accounts" -Foregroundcolor Green
$result["accounts"] = Execute-ActiveDirectoryAccountCreation $xmlSettings

write-Host "Creating DNS Records" -Foregroundcolor Green
$result["dns"] = (Execute-ConfigureDNS $xmlSettings)

$promptResult = 0
if ($xmlSettings.configuration.applications.prompt -ne $null -and $([int]$xmlSettings.configuration.applications.prompt) -eq 1) {
	$promptResult = Show-YesNoQuestion -message "Do you want to install applications"
}

If ($promptResult -eq 0)
{
	write-Host "Installing Applications" -Foregroundcolor Green
	$result["applications"] = (Execute-InstallApplications $xmlSettings)
	if ((Get-PendingReboot).RebootPending -eq $true) { Restart }
}

foreach($k in $result.keys) { Write-Host $k "-" $result.$k }

Stop-Transcript