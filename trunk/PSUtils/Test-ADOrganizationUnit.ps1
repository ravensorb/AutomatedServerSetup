Function Test-ADOrganizationUnit {
<# 
	.Synopsis 
		Tests to see if the specified AD Orgnaiation Unit Exists
	.Description 
		This script verifies the existing of the specified AD Orgnaiational unit
	
	PARAMETERS 
		-dn the distinguished name (defaults to the current domain)
		-ouName the name of the group to validate
	.Example 
		Test-ADOrganizationUnit.ps1 -name Applications
	
		Returns True or False depending on if the group "Applications" exists

	.Notes 
		NAME:  Test-ADOrganizationUnit
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

		Write-Verbose "Checking for OU $name in $dn"
		
		$adUnit = (Get-ADOrganizationalUnit -LDAPFilter "(name=$name)" -SearchBase $($dn))
		if ($adUnit -eq $null) {
			Write-Verbose "Checking for Container $name in $dn"
			$adUnit = (Get-ADObject -LDAPFilter "(&(name=$name)(objectClass=container))" -SearchBase $($dn))
		}
		
		Write-Verbose "AD Unit: $adUnit"

		if ($adUnit) { Write-Output $True } Else { Write-Output $False }
	}
	catch {
		Write-Verbose $_.Exception

		Write-Output $False
	}
}