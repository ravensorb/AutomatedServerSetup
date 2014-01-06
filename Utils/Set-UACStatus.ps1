function Set-UACStatus {
	<#
	.SYNOPSIS
		Enables or disables User Account Control (UAC) on a computer.

	.DESCRIPTION
		Enables or disables User Account Control (UAC) on a computer.

	.NOTES
		Version      			: 1.0
		Rights Required			: Local admin on server
								: ExecutionPolicy of RemoteSigned or Unrestricted
		Author(s)    			: Pat Richard (pat@innervation.com)
		Dedicated Post			: http://www.ehloworld.com/1026
		Disclaimer   			: You running this script means you won't blame me if this breaks your stuff.

	.EXAMPLE
		Set-UACStatus -Enabled [$true|$false]

		Description
		-----------
		Enables or disables UAC for the local computer.

	.EXAMPLE
		Set-UACStatus -Computer [computer name] -Enabled [$true|$false]

		Description
		-----------
		Enables or disables UAC for the computer specified via -Computer.

	.LINK
		http://www.ehloworld.com/1026

	.INPUTS
		None. You cannot pipe objects to this script.

	#Requires -Version 2.0
	#>

	param(
		[cmdletbinding()]
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $false)]
		[string]$Computer = $env:ComputerName,
		[parameter(ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
		[bool]$enabled
	)
	[string]$RegistryValue = "EnableLUA"
	[string]$RegistryPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
	$OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
	$Subkey = $OpenRegistry.OpenSubKey($RegistryPath,$true)
	$Subkey.ToString() | Out-Null
	if ($enabled -eq $true){
		$Subkey.SetValue($RegistryValue, 1)
	}else{
		$Subkey.SetValue($RegistryValue, 0)
	}
	$UACStatus = $Subkey.GetValue($RegistryValue)
	$UACStatus
	$Restart = Read-Host "`nSetting this requires a reboot of $Computer. Would you like to reboot $Computer [y/n]?"
	if ($Restart -eq "y"){
		Restart-Computer $Computer -force
		Write-Host "Rebooting $Computer"
	}else{
		Write-Host "Please restart $Computer when convenient"
	}
} # end function Set-UACStatus