param(
	[string] $configurationFile = ".\ServerSetup.xml"
)

$configurationFile = (Resolve-Path $configurationFile).Path

$folderDesktop = [Environment]::GetFolderPath("Desktop")
$date = Get-Date -format "yyyyMMdd"
Start-Transcript "$folderDesktop\Setup-Server-Transcript-$date.rtf" -Append -ErrorAction SilentlyContinue

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
		Start-Process -ExecutionPolicy ByPass -Verb Runas -WorkingDirectory $workingDirectory -FilePath PowerShell.exe -ArgumentList "$workingDirectory\Setup-Server.ps1 -configurationFile '$configurationFile'"
		break
	}
}

function Restart {
	param([int] $step = 0)

	#Set-RunOnce -Description "AutoServerSetup" -FileToRun $scriptCommand -Arguments "-configurationFile '$configurationFile'"
	Set-RunOnce -Description "AutoServerSetup-$step" -FileToRun "$workingDirectory\ServerSetup.bat" -Arguments "'$configurationFile'"
	
	Write-Host "The Computer will reboot in 10 seconds...."
	sleep 10
	#Read-Host "Press any key to continue..."
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

Write-Host "Configuring Local Computer" -Foregroundcolor Green
$result["localcomputer"] = (Execute-ConfigureLocalComputer $xmlSettings)

Write-Host "Network Configuration" -Foregroundcolor Green
$result["network"] = (Execute-NetworkConfiguration $xmlSettings)
if ($result["network"] -eq "reboot" -or (Get-PendingReboot).RebootPending -eq $true) { Restart 5 }

Write-Host "Setting up Chocolatey and related packages" -Foregroundcolor Green
$result["chocolatey"] = (Execute-InstallChocolatey $xmlSettings)
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 1 }

Write-Host "Renaming Local Computer" -Foregroundcolor Green
$result["renamecomputer"] = (Execute-RenameComputer $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 2 }

Write-Host "Configuring Windows Update" -Foregroundcolor Green
$result["wupdateconfig"] = (Execute-ConfigureWindowsUpdate $xmlSettings)

Write-Host "Executing Windows Update" -Foregroundcolor Green
$result["wupdate"] = (Execute-WindowsUpdate $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 3 }

Write-Host "Installing Windows Features" -Foregroundcolor Green
$result["features"] = (Execute-InstallWindowsFeatures $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 4 }

Write-Host "Installing/Configuring Active Directory" -Foregroundcolor Green
$result["ad"] = (Execute-ActiveDirectoryConfiguration $xmlSettings)
Write-Host "Checking to see if reboot is required" -Foregroundcolor Green
if ($result["ad"] -eq "reboot" -or (Get-PendingReboot).RebootPending -eq $true) { Restart 5 }
if ($result["ad"] -eq "error") { 
	Write-Host "AD Installation Failed. Please review logs and rerun the script." -ForegroundColor Red
	exit 
} 

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

exit