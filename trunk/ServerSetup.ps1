param(
	[string] $configurationFile = ".\ServerSetup.xml"
)

# Resolve the Configuration file incase a relative path was specifed 
$configurationFile = (Resolve-Path $configurationFile).Path

# Setup the transcript logging to create a file on the desktop
$folderDesktop = [Environment]::GetFolderPath("Desktop")
$date = Get-Date -format "yyyyMMdd"
Start-Transcript "$folderDesktop\Setup-Server-Transcript-$date.rtf" -Append -ErrorAction SilentlyContinue

# Lets get the workingDirectory
$scriptCommand = $myinvocation.mycommand.definition
$workingDirectory = $PSScriptRoot
if ($workingDirectory -eq $null -or $workingDirectory.length -eq 0) {
	$workingDirectory = Split-Path $scriptCommand
	$workingDrive = Split-Path $scriptCommand -Qualifier
}

Write-Output "Script: [$scriptCommand]" -Foregroundcolor Yellow
Write-Output "Working Directory: [$workingDirectory]" -Foregroundcolor Yellow
Write-Output "Configuration File: [$configurationFile]" -Foregroundcolor Yellow

$configurationFile = $configurationFile.Trim() -Replace "'",""

# Lets unblock and files
gci "$workingDirectory" | Unblock-File

# Lets import the modules we need
Import-Module "$workingDirectory\Carbon" -Force
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
	
	Write-Output "The Computer will reboot in 10 seconds...."
	sleep 10
	#Read-Host "Press any key to continue..."
	Restart-Computer 
	
	exit
}

Write-Output "Validating script is running under Administrative credentials" -Foregroundcolor Green
Force-RunAsAdmin

Write-Output "Loading Configuration File: $configurationFile" -Foregroundcolor Green
$xmlSettings = New-Object -TypeName XML
$xmlSettings.Load($configurationFile)
$debug = $false
if ($xmlSettings.configuration.mode -eq "DEBUG") { $debug = $true }
if ($xmlSettings.configuration.workingDirectory -eq $null) {
	$xmlSettings.configuration.SetAttribute("workingDirectory", $workingDirectory)
}

if ($xmlSettings.configuration.workingDrive  -eq $null) {
	$xmlSettings.configuration.SetAttribute("workingDrive", $workingDrive)
}

if ($xmlSettings.configuration.version -ne "1.0.1") {
	Write-Output "Settings File Version number does not match expected version.  Possible incompatibility.  Please review the settings file and update if necessary." -ForegroundColor Red
	exit
}

Import-Module "$workingDirectory\ServerSetupCoreFuncs.ps1" -Force

$result = @{}

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Initializing Script" -Foregroundcolor Green
$result["initscript"] = (Execute-InitializeScript $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Configuring Local Computer" -Foregroundcolor Green
$result["localcomputer"] = (Execute-ConfigureLocalComputer $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Network Configuration" -Foregroundcolor Green
$result["network"] = (Execute-NetworkConfiguration $xmlSettings)
if ($result["network"] -eq "reboot" -or (Get-PendingReboot).RebootPending -eq $true) { Restart 5 }

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Renaming Local Computer" -Foregroundcolor Green
$result["renamecomputer"] = (Execute-RenameComputer $xmlSettings)
Write-Output "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 2 }

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Configuring Windows Update" -Foregroundcolor Green
$result["wupdateconfig"] = (Execute-ConfigureWindowsUpdate $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Executing Windows Update" -Foregroundcolor Green
$result["wupdate"] = (Execute-WindowsUpdate $xmlSettings)
Write-Output "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 3 }

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Installing Windows Features" -Foregroundcolor Green
$result["features"] = (Execute-InstallWindowsFeatures $xmlSettings)
Write-Output "Checking to see if reboot is required" -Foregroundcolor Green
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 4 }

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Setting up Chocolatey and related packages" -Foregroundcolor Green
$result["chocolatey"] = (Execute-InstallChocolatey $xmlSettings)
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 1 }

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Installing/Configuring Active Directory" -Foregroundcolor Green
$result["ad"] = (New-ADConfiguration -XmlData $xmlSettings)
Write-Output "Checking to see if reboot is required" -Foregroundcolor Green
if ($result["ad"] -eq "reboot" -or (Get-PendingReboot).RebootPending -eq $true) { Restart 5 }
if ($result["ad"] -eq "error") { 
	Write-Output "AD Installation Failed. Please review logs and rerun the script." -ForegroundColor Red
	exit 
} 

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Creating Accounts" -Foregroundcolor Green
$result["accounts"] = (Execute-CreateAccounts $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-Output "Creating DNS Records" -Foregroundcolor Green
$result["dns"] = (Execute-ConfigureDNS $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
$promptResult = 0
if ($xmlSettings.configuration.applications.prompt -ne $null -and $([int]$xmlSettings.configuration.applications.prompt) -eq 1) {
	$promptResult = Show-YesNoQuestion -message "Do you want to install applications"
}

If ($promptResult -eq 0)
{
	Write-Output "Installing Applications" -Foregroundcolor Green
	$result["applications"] = (Execute-InstallApplications $xmlSettings)
	if ((Get-PendingReboot).RebootPending -eq $true) { Restart }
}

#-------------------------------------------------------------------------------------------------------------------
foreach($k in $result.keys) { Write-Output $k " -> " $result.$k }

Stop-Transcript

exit