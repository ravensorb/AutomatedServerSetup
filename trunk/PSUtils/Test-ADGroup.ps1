Function Test-ADGroup {
<# 
	.Synopsis 
		Tests to see if the specified AD Group Exists
	.Description 
		This script verifies the existing of the specified AD Group
	
	PARAMETERS 
		-dn the distinguished name (defaults to the current domain)
		-groupName the name of the group to validate
	.Example 
		Test-ADGroup.ps1 -groupName Applications
	
		Returns True or False depending on if the group "Applications" exists

	.Notes 
		NAME:  Test-ADGRoup
		AUTHOR: Shawn Anderson
		LASTEDIT: 08/26/2014
		KEYWORDS: 
	.Link 
		
#Requires -Version 2.0 
#> 
	param (
		[Parameter(Mandatory=$false)] [String]$dn,
		[Parameter(Mandatory=$true)] [String]$name
	)
	
	try {
		if (-Not ($dn)) { $dn = ([adsi]'').distinguishedName }

		Write-Verbose "Checking for group $name in $($dn)"
		
		$adUnit = (Get-ADGroup -LDAPFilter "(name=$name)" -SearchBase $dn)
		
		Write-Verbose "AD Unit: $adUnit"

		if ($adUnit) { Write-Output $True } Else { Write-Output $False }
	}
	catch {
		Write-Verbose $_.Exception

		Write-Output $False
	}
}