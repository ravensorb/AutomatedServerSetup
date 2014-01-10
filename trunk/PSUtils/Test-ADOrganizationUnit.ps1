Function Test-ADOrganizationUnit {
<# 
	.Synopsis 
		Tests to see if the specified AD Orgnaiation Unit Exists
	.Description 
		This script verifies the existing of the specified AD Orgnaiational unit
	
	PARAMETERS 
		-dn the distinguished name (defaults to the current domain)
		-groupName the name of the group to validate
	.Example 
		Test-ADOrganizationUnit.ps1 -groupName Applications
	
		Returns True or False depending on if the group "Applications" exists

	.Notes 
		NAME:  Test-ADOrganizationUnit
		AUTHOR: Shawn Anderson
		LASTEDIT: 12/06/2013
		KEYWORDS: 
	.Link 
		
#Requires -Version 2.0 
#> 
	param (
		[Parameter(Mandatory=$false)] [String]$dn,
		[Parameter(Mandatory=$true)] [String]$groupName
	)
	
	try {
		if (-Not ($dn)) { $dn = ([adsi]'').distinguishedName }

        Write-Verbose "Checking for group $groupName in $dn"
		
		$adUnit = (Get-ADOrganizationalUnit -LDAPFilter "(name=$groupName)" -SearchBase $dn)
		
        Write-Verbose "AD Unit: $adUnit"

        if ($adUnit) { Write-Output $True } Else { Write-Output $False }
	}
	catch {
        Write-Verbose $_.Exception

		Write-Output $False
	}
}