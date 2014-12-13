Function New-ADConfiguration
{
	<#
	.SYNOPSIS
		Installs and Configures AD.

	.DESCRIPTION
		Use New-ADConfiguration to setup a new Active Directory Installation
	
	.PARAMETER Path	
		Path to XML file with the configuration.

	.PARAMETER XmlData	
		An XML string with the configuration
		
	.EXAMPLE
		To load all of the objects in the file "ad-config.xml" into AD.
	
		PS C:\> New-ADConfiguration -Path C:\ad-config.xml

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Install AD based on: C:\ad-config.xml".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

	.EXAMPLE
		To load all of the objects in the XML variable "$xmlAD" into AD.
		
		PS C:\> New-ADConfiguration -XmlData $xmlAD

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Load AD Objects from data passed into the module".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

	.NOTES
		Author: Shawn Anderson
		Blog  : http://eye-catcher.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/
	
	.LINK
		http://msdn.microsoft.com/en-us/library/aa387290(v=vs.85).aspx
		http://support.microsoft.com/kb/926464
#Requires -Version 2.0 
	#>
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="High"
	)]
	Param
	(
		[parameter(Mandatory=$false)]
		[String]$Path = $null,
		[Parameter(Mandatory=$false)] 
		[Xml] $XmlData = $null,
		[Parameter(Mandatory=$false)] 
		[Boolean] $populate = $false
	)

	$DefaultName = "AD Installation and Configuration" 
		
	$User = [Security.Principal.WindowsIdentity]::GetCurrent()
	$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

	if(!$Role)
	{
		Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
	} #End If !$Role		

	If (($Path -eq $null -or $Path.Length -eq 0) -and ($XmlData -eq $null -or $XmlData.Length -eq 0))
	{
		Write-Warning "Please specify either a Path or an XmlData parameter"
		Return
	}

	$xmlSettings = $null

	If($Path -ne $null -and $Path.Length -gt 0) {
		if (Test-Path $Path) {
			# Resolve the Configuration file incase a relative path was specifed 
			$Path = (Resolve-Path $Path).Path

			Write-Host "Loading Configuration File: $Path" -Foregroundcolor Green
			
			$xmlSettings = New-Object -TypeName XML
			$xmlSettings.Load($Path)
		} 
	} #End If (Test-Path $Path)
	ElseIf ($XmlData -ne $null) {
		$xmlSettings = $XmlData
	} 
	
	if ($XmlSettings -eq $null) {
		Write-Warning "Unable to load any configuration data"
		Return
	}

	if ($xmlSettings.configuration.workingDirectory -eq $null) {
		# Lets get the workingDirectory
		$scriptCommand = $myinvocation.mycommand.definition
		$workingDirectory = $PSScriptRoot
		if ($workingDirectory -eq $null -or $workingDirectory.length -eq 0) {
			$workingDirectory = Split-Path $scriptCommand
		}

		$xmlSettings.configuration.SetAttribute("workingDirectory", $workingDirectory)
	}

	if ($xmlSettings.configuration.version -ne "1.0.1") {
		Write-Warning "Settings File Version number does not match expected version.  Possible incompatibility.  Please review the settings file and update if necessary." 
		exit
	}

	$result = Execute-ActiveDirectoryConfiguration $xmlSettings

	if ($result -and $xmlSettings.configuration.domain.ou -ne $null -and $populate -eq $true) {
		$result = Add-ADObjects -XmlData $xmlSettings
	}

	return $result
} #In The End :)

#-------------------------------------------------------------------------------------------------------------------
# Active Directory
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ActiveDirectoryConfiguration
# Description:
#	Handles the setup or the joining of an existing domain
#-------------------------------------------------------------------------------------------------------------------
function Execute-ActiveDirectoryConfiguration {
	param([xml] $xmlSettings)
	
	if (($xmlSettings.configuration.domain -eq $null) -or ($xmlSettings.configuration.domain.name -eq $null)) { return $false }
	if ($xmlSettings.configuration.domain.action -eq $null) { $xmlSettings.configuration.domain.SetAttribute("action", "join") }

	switch ($xmlSettings.configuration.domain.action) {
		"create" {
			$result = Execute-ActiveDirectoryInstallation $xmlSettings 
			return $result
		}
		"join" {
			$result = Execute-ActiveDirectoryJoin $xmlSettings 
			return $result
		}
		"none" {
		}
	}
	
	return $false
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ActiveDirectoryJoin
# Description:
#	Handles the the joining of an existing domain
#-------------------------------------------------------------------------------------------------------------------
function Execute-ActiveDirectoryJoin {
	param([xml] $xmlSettings)

	if (($xmlSettings.configuration.domain -eq $null) -or ($xmlSettings.configuration.domain.name -eq $null)) { return $false }

	process {
		try {
			$pwd = $($xmlSettings.configuration.defaultPassword)
			$defaultPasswordSecure = ConvertTo-SecureString -String $pwd -AsPlainText -Force
	
			$creds = New-Object System.Management.Automation.PSCredential ($env:username, $defaultPasswordSecure)
		
			Write-LogMessage -level 1 -msg "Joining Computer to Domain: "$([string]$xmlSettings.configuration.domain.name)
			if (-Not $debug) {
				Add-Computer -DomainName $([string]$xmlSettings.configuration.domain.name) -Credential $creds

				return $true
			}
		}
		catch {
			Write-Verbose $Error
		}

		return $false
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ActiveDirectoryInstallation
# Description:
#	Handles installing the AD feature and creating the AD structure form the configuration file
#-------------------------------------------------------------------------------------------------------------------
function Execute-ActiveDirectoryInstallation {
	param([xml] $xmlSettings)
	
	Write-LogMessage -level 1 -msg "Checking to see if AD is already installed"
	$adFeature = Get-WindowsFeature AD-Domain-Services, RSAT-ADDS
	if ($adFeature.Installed -eq $False) {
		Write-LogMessage -level 1 -msg "Installing AD Domain Services"
		
		if (-Not $debug)
		{
			$adFeatureInstall = Add-WindowsFeature $adFeature
			if ($adFeatureInstall.Success -ne $True) {
				Write-Error "Failed to install AD Features"

				return "error"
			} elseif ($adFeatureInstall.RestartNeeded -eq "Yes") {
				return "restart"
			}
		}
	}

	Write-LogMessage -level 1 -msg "Checking to see if AD needs to be configured"
	$adFeature = Get-WindowsFeature AD-Domain-Services 
	if ($adFeature.Installed -eq $True) {
		$pwd = $($xmlSettings.configuration.defaultPassword)
		# Write-LogMessage -level 1 -msg "Default Password: $pwd"
		$safeModePassword = ConvertTo-SecureString -String $pwd -AsPlainText -Force

		$osDetails = gwmi win32_operatingsystem

		$legacyMode = $False 
		if (((Get-Command "Test-ADDSForestInstallation" -errorAction SilentlyContinue) -eq $null) -or ($osDetails.Version -lt "6.1")) { $legacyMode = $True }
			
		#if ($osDetails.Version -match "6.1*") {
		if ($legacyMode) {
			Write-LogMessage  -level 1 -msg "Enabling Legacy Mode For AD Installation"

			$adPostConfigurationNeeded = $False

			try { Get-ADForest } catch { $adPostConfigurationNeeded = $True}

			if ($adPostConfigurationNeeded) {
				Write-LogMessage -level 1 -msg "Installing AD"

				$stdOutLogFile = "{SCRIPT FOLDER}\dcpromo.log"
				$stdErrLogFile = "{SCRIPT FOLDER}\dcpromo.err.log"
				$stdOutLogFile = Replace-TokensInString $stdOutLogFile 
				$stdErrLogFile = Replace-TokensInString $stdErrLogFile 

				$dcPromoFile = "{SCRIPT FOLDER}\dcpromo.ini"
				$dcPromoFile = Replace-TokensInString $dcPromoFile
				if (Test-Path -Path $dcPromoFile) { Remove-Item -Force $dcPromoFile }

				Write-LogMessage -level 1 -msg "`tCreating DCPromo Answer File"
				Add-Content -Path $dcPromoFile -Value "[DCINSTALL]"
				Add-Content -Path $dcPromoFile -Value "InstallDNS=yes"
				Add-Content -Path $dcPromoFile -Value "NewDomain=forest"
				Add-Content -Path $dcPromoFile -Value "NewDomainDNSName=$([string]$xmlSettings.configuration.domain.name)"
				Add-Content -Path $dcPromoFile -Value "DomainNetBiosName=$([string]$xmlSettings.configuration.domain.netBIOS)"

				Add-Content -Path $dcPromoFile -Value "SiteName=Default-First-Site-Name"
				Add-Content -Path $dcPromoFile -Value "ReplicaOrNewDomain=domain"
				Add-Content -Path $dcPromoFile -Value "ForestLevel=4"
				Add-Content -Path $dcPromoFile -Value "DomainLevel=4"
				Add-Content -Path $dcPromoFile -Value "SafeModeAdminPassword=$pwd"

				Add-Content -Path $dcPromoFile -Value "DatabasePath=""$env:SystemRoot\NTDS"""
				Add-Content -Path $dcPromoFile -Value "LogPath=""$env:SystemRoot\NTDS"""
				Add-Content -Path $dcPromoFile -Value "SYSVOLPath=""$env:SystemRoot\SYSVOL"""

				Add-Content -Path $dcPromoFile -Value "RebootOnCompletion=no"

				Write-LogMessage -level 1 -msg "`tExecuting dcpromo"
				$process = Start-Process -FilePath "dcpromo.exe" -ArgumentList "/unattend:$dcPromoFile" -Wait -PassThru -RedirectStandardOutput $stdOutLogFile -RedirectStandardError $stdErrLogFile

				return "reboot"
			}
		} else { #if ($osDetails.Version -match "6.2*") {
			if ($adFeature.PostConfigurationNeeded) {
				Write-LogMessage -level 1 -msg "Running Pre-checks for AD Forest Installation"
				$testADForestInstallation = Test-ADDSForestInstallation -DomainName $([string]$xmlSettings.configuration.domain.name) -SafeModeAdministratorPassword $safeModePassword -ErrorAction SilentlyContinue
				if ($testADForestInstallation.Status -ne "Success") {
					Write-Error "AD Forest Installation Test Failed"
					Write-Host $testADForestInstallation
					#$testADForestInstallation | fl
			
					return "error"
				}

				Write-LogMessage -level 1 -msg "Loading ADS Deployment Modules"
				Import-Module ADDSDeployment -Force

				Write-LogMessage -level 1 -msg "Installing AD"
				$installADForestResult = Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode $([string]$xmlSettings.configuration.domain.mode) -DomainName $([string]$xmlSettings.configuration.domain.name) -DomainNetbiosName $([string]$xmlSettings.configuration.domain.netBIOS) -ForestMode $([string]$xmlSettings.configuration.domain.mode) -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword $safeModePassword
		
				$installADForestResult | fl

				return "reboot"
			}
		}
						
		return "success"
	}
	
	return "success"
}
