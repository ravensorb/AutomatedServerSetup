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
}
$workingDrive = Split-Path $workingDirectory -Qualifier
Write-Host "Script: [$scriptCommand]" -Foregroundcolor Yellow
Write-Host "Working Drive: [$workingDrive]" -Foregroundcolor Yellow
Write-Host "Working Directory: [$workingDirectory]" -Foregroundcolor Yellow
Write-Host "Configuration File: [$configurationFile]" -Foregroundcolor Yellow

$configurationFile = $configurationFile.Trim() -Replace "'",""

# Lets unblock and files
if ((Get-Command "Unblock-File" -errorAction SilentlyContinue) -ne $null) {
	gci "$workingDirectory" | Unblock-File
}

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
	#Set-RunOnce -Description "AutoServerSetup-$step" -FileToRun "$workingDirectory\ServerSetup.bat" -Arguments "'$configurationFile'"
	Set-RunOnce -Description "AutoServerSetup-$step" -FileToRun $scriptCommand -Arguments "'$configurationFile'"
	
	Write-LogMessage -level 1 -msg "The Computer will reboot in 10 seconds...."
	sleep 10
	#Read-Host "Press any key to continue..."
	Restart-Computer 
	
	exit
}

Write-Host "Validating script is running under Administrative credentials" -Foregroundcolor Green
Force-RunAsAdmin

Write-Host "Loading Configuration File: $configurationFile" -Foregroundcolor Green
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
	Write-Host "Settings File Version number does not match expected version.  Possible incompatibility.  Please review the settings file and update if necessary." -ForegroundColor Red
	exit
}

Import-Module "$workingDirectory\ServerSetupCoreFuncs.ps1" -Force

$result = @{}

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Initializing Script"
$result["initscript"] = (Execute-InitializeScript $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Configuring Local Computer"
$result["localcomputer"] = (Execute-ConfigureLocalComputer $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Network Configuration"
$result["network"] = (Execute-NetworkConfiguration $xmlSettings)
if ($result["network"] -eq "reboot" -or (Get-PendingReboot).RebootPending -eq $true) { Restart 5 }

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Renaming Local Computer"
$result["renamecomputer"] = (Execute-RenameComputer $xmlSettings)
Write-LogMessage -level 2 -msg "Checking to see if reboot is required"
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 2 }

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Configuring Windows Update"
$result["wupdateconfig"] = (Execute-ConfigureWindowsUpdate $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Executing Windows Update"
$result["wupdate"] = (Execute-WindowsUpdate $xmlSettings)
Write-LogMessage -level 2 -msg "Checking to see if reboot is required"
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 3 }

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Installing Windows Features"
$result["features"] = (Execute-InstallWindowsFeatures $xmlSettings)
Write-LogMessage -level 2 -msg "Checking to see if reboot is required"
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 4 }

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Setting up Chocolatey and related packages"
$result["chocolatey"] = (Execute-InstallChocolatey $xmlSettings)
Write-LogMessage -level 2 -msg "Checking to see if reboot is required"
if ((Get-PendingReboot).RebootPending -eq $true) { Restart 1 }

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Installing/Configuring Active Directory"
$result["ad"] = (New-ADConfiguration -XmlData $xmlSettings)
Write-LogMessage -level 2 -msg "Checking to see if reboot is required"
if ($result["ad"] -eq "reboot" -or (Get-PendingReboot).RebootPending -eq $true) { Restart 5 }
if ($result["ad"] -eq "error") { 
	Write-LogMessage -level 0 -msg "AD Installation Failed. Please review logs and rerun the script."
	exit 
} 

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Creating Accounts"
$result["accounts"] = (Execute-CreateAccounts $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
Write-LogMessage -level 3 -msg "Creating DNS Records"
$result["dns"] = (Execute-ConfigureDNS $xmlSettings)

#-------------------------------------------------------------------------------------------------------------------
$promptResult = 0
if ($xmlSettings.configuration.applications.prompt -ne $null -and $([int]$xmlSettings.configuration.applications.prompt) -eq 1) {
	$promptResult = Show-YesNoQuestion -message "Do you want to install applications"
}

If ($promptResult -eq 0)
{
	Write-LogMessage -level 3 -msg "Installing Applications"
	$result["applications"] = (Execute-InstallApplications $xmlSettings)
	Write-LogMessage -level 2 -msg "Checking to see if reboot is required"
	if ((Get-PendingReboot).RebootPending -eq $true) { Restart }
}

#-------------------------------------------------------------------------------------------------------------------
foreach($k in $result.keys) { Write-LogMessage -level 1 -msg "$($k): $($result.$k)" }

Stop-Transcript

exit