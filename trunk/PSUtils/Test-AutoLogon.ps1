Function Test-AutoLogon {
<# 
	.Synopsis 
		Tests if Auto Logon is enabled
	.Description 
		This script tests to see if auto logon is enabled on the server
	
	PARAMETERS 

	.Example 
		Test-AutoLogon.ps1 -eq $True
	
		Tests to see if autologon is enabled on local computer

	.Notes 
		NAME:  Tests-Autologon
		AUTHOR: Shawn Anderson
		LASTEDIT: 11/26/2014
		KEYWORDS: 
	.Link 
		
#Requires -Version 2.0 
#> 
	param (
	)
	
	$value = (Get-RegistryKeyValue -Path "HKLM:\Software\Microsoft\Windows NT\Currentversion\WinLogon" -Name "AutoAdminLogon")
	return $value -ne $null -and $value -ne "0"
}

