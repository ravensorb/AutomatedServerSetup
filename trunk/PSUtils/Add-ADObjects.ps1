Function Add-ADObjects
{
	<#
	.SYNOPSIS
		Load Objects into AD in bulk.

	.DESCRIPTION
		Use Add-ADObjects to create AD Users, Groups, and Containers in bulk
	
	.PARAMETER Path	
		Path to XML file with objects to load.

	.PARAMETER XmlData	
		An XML string with the objects to load
		
	.EXAMPLE
		To load all of the objects in the file "ad-structure.xml" into AD.
	
		PS C:\> Add-ADObjects -Path C:\ad-structure.xml

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Load AD Objects from: C:\ad-structure.xml".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

	.EXAMPLE
		To load all of the objects in the XML variable "$xmlAD" into AD.
		
		PS C:\> Add-ADObjects -XmlData $xmlAD

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
		[bool] $updateExisting = $false,
		[Parameter(Mandatory=$false)] 
		[bool] $resetPasswordOnExisting = $false
	)

	$DefaultName = "AD Objects to AD" 
		
	$User = [Security.Principal.WindowsIdentity]::GetCurrent()
	$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

	if(!$Role)
	{
		Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		Return 
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
		Write-Warning "Settings File Version number does not match expected version.  Possible incompatibility.  Please review the settings file and update if necessary." -ForegroundColor Red
		Return
	}

	Return Execute-ActiveDirectoryAccountCreation $xmlSettings
} #In The End :)


#-------------------------------------------------------------------------------------------------------------------
# Active Directory
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ActiveDirectoryAccountCreation
# Description:
#	Handles the creation of the AD Account (sets up a new user in the correct OU)
#-------------------------------------------------------------------------------------------------------------------
function Execute-ActiveDirectoryAccountCreation {
	param([xml] $xmlSettings)

	if ($xmlSettings.configuration.domain -eq $null) { return $true }

	# Test if we have access to an AD Domain
	try {
		Get-ADDomain
	} catch {
		Write-LogMessage -level 2 -msg "Unable to access any domain.  Please verify you are connected to a domain or this computer is a domain controller" -ForegroundColor Red
		return $false
	}

	if ($xmlSettings.configuration.domain -ne $null) {
		Write-Verbose "Processing Domain: $($xmlSettings.configuration.domain)"
		foreach ($ou in $xmlSettings.configuration.domain.ou) {
			if ($ou -ne $null) {
				$tmp = $xmlSettings.configuration.domain.name -split "\.",2,"Singleline,IgnoreCase"
				$dc = "DC=" + ($tmp -join ",DC=")

				$result = Execute-ActiveDirectoryProcessOU $($xmlSettings.configuration.domain.name) $dc $ou
			}
		}
	}
	
	return $result
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ActiveDirectoryProcessOU
# Description:
#	Handles creating the requested OU and any child objects (nested OUs and accounts)
#-------------------------------------------------------------------------------------------------------------------
function Execute-ActiveDirectoryProcessOU {
	param([string] $domain, [string] $path, $ouSettings)

	$result = $true
	
	Write-LogMessage -level 1 -msg "Checking for existence of group: $($ouSettings.name) in $path"
	if (-Not (Test-ADOrganizationUnit -name $ouSettings.name -dn $path)) {
		Write-LogMessage -level 2 -msg "`tCreating OU ($path): $($ouSettings.name)"
		if (-Not $debug)
		{
			New-ADOrganizationalUnit -Path $path -Name $($ouSettings.name)
		}
	} else {
		Write-LogMessage -level 2 -msg "`tGroup Exists"
	}
	
	$pwd = $($xmlSettings.configuration.defaultPassword)
	#Write-Verbose "`tDefault Password: $pwd"
	$defaultPasswordSecure = ConvertTo-SecureString -String $pwd -AsPlainText -Force
	$prefix = "OU="
	# Build in 
	if ($($ouSettings.name) -eq "Users") {
		$prefix = "CN="
	}

	$currentOU = $prefix + $ouSettings.name + ",$path"
	
	if ($ouSettings.account -ne $null) {
		Write-LogMessage -level 1 -msg "Processing Accounts"
		foreach ($account in $ouSettings.account) {
			$pwd = $($account.password)
			Write-Verbose "`t`tAccount Password: $pwd"
			if (($pwd -ne $null) -and ($pwd -ne "{DEFAULT PASSWORD}")) { 
				$password = ConvertTo-SecureString -String $pwd -AsPlainText -Force 
			} else { 
				$password = $defaultPasswordSecure 
			}
			
			if ((Test-ADUser -name $($account.name)) -eq $false)
			{
				Write-LogMessage -level 2 -msg "`tCreating User ($currentOU): $($account.name)"
				if (-Not $debug)
				{
					New-ADUser 	-Path $currentOU `
								-Name $account.name `
								-AccountPassword $password `
								-City $account.city `
								-Company $account.company `
								-Country $account.country `
								-Department $account.department `
								-Description $account.description `
								-DisplayName $account.displayName `
								-Division $account.division `
								-EmailAddress "$($account.name)@$domain" `
								-EmployeeID $account.employeeId `
								-Enabled $True `
								-GivenName $account.givenName `
								-Initials $account.initials `
								-Manager $account.manager `
								-Office $account.office `
								-Organization $account.organization `
								-PasswordNeverExpires ([bool]$account.passwordNeverExpires) `
								-SamAccountName $account.name `
								-State $account.state `
								-StreetAddress $account.streetAddress `
								-Surname $account.surname `
								-Title $account.title `
								-ChangePasswordAtLogon $false `
								-UserPrincipalName "$($account.name)@$domain" `
								-AccountExpirationDate $account.accountExpirationDate `
								-AccountNotDelegated ([bool]$account.AccountNotDelegated) `
								-AllowReversiblePasswordEncryption ([bool]$account.allowReversiblePasswordEncryption) `
								-CannotChangePassword ([bool]$account.cannotChangePassword) `
								-EmployeeNumber $account.employeeNumber `
								-Fax $account.fax `
								-HomeDirectory $account.homeDirectory `
								-HomeDrive $account.homeDrive `
								-HomePage $account.homePage `
								-HomePhone $account.homePhone `
								-MobilePhone $account.mobilePhone `
								-OfficePhone $account.officePhone `
								-PasswordNotRequired ([bool]$account.passwordNotRequired) `
								-POBox $account.poBox `
								-PostalCode $account.postalCode `
								-ProfilePath $account.profilePath `
								-ScriptPath $account.scriptPath `
								-SmartcardLogonRequired $account.smartcardLogonRequired `
								-TrustedForDelegation $account.trustedForDelegation 
				}
			} else {
				if ($resetPasswordOnExisting)
				{
					Write-LogMessage -level 2 -msg "`tSetting password for account: $($account.name)"
					if (-Not $debug)
					{
						Set-ADAccountPassword -Identity $($account.name) -Reset -NewPassword $password
					}
				}
				
				if ($updateExisting)
				{
					Write-LogMessage -level 2 -msg "`tUpdatting account: $($account.name)"

					if (-Not $debug)
					{
						$replace = @{}
					
						$replace["Name"] = $account.name;
						$replace["AccountPassword"] = $password;
						$replace["City"] = $account.city;
						$replace["Company"] = $account.company;
						$replace["Country"] = $account.country;
						$replace["Department"] = $account.department;
						$replace["Description"] = $account.description;
						$replace["DisplayName"] = $account.displayName;
						$replace["Division"] = $account.division;
						$replace["EmailAddress"] = "$($account.name)@$domain";
						$replace["EmployeeID"] = $account.employeeId;
						$replace["Enabled"] = $True;
						$replace["GivenName"] = $account.givenName;
						$replace["Initials"] = $account.initials;
						$replace["Manager"] = $account.manager;
						$replace["Office"] = $account.office;
						$replace["Organization"] = $account.organization;
						$replace["PasswordNeverExpires"] = ([bool]$account.passwordNeverExpires);
						$replace["SamAccountName"] = $account.name;
						$replace["State"] = $account.state;
						$replace["StreetAddress"] = $account.streetAddress;
						$replace["Surname"] = $account.surname;
						$replace["Title"] = $account.title;
						$replace["ChangePasswordAtLogon"] = $false;
						$replace["UserPrincipalName"] = "$($account.name)@$domain";
						$replace["AccountExpirationDate"] = $account.accountExpirationDate;
						$replace["AccountNotDelegated"] = ([bool]$account.AccountNotDelegated);
						$replace["AllowReversiblePasswordEncryption"] = ([bool]$account.allowReversiblePasswordEncryption);
						$replace["AuthType"] = $account.authType;
						$replace["CannotChangePassword"] = ([bool]$account.cannotChangePassword);
						$replace["EmployeeNumber"] = $account.employeeNumber;
						$replace["Fax"] = $account.fax;
						$replace["HomeDirectory"] = $account.homeDirectory;
						$replace["HomeDrive"] = $account.homeDrive;
						$replace["HomePage"] = $account.homePage;
						$replace["HomePhone"] = $account.homePhone;
						$replace["MobilePhone"] = $account.mobilePhone;
						$replace["OfficePhone"] = $account.officePhone;
						$replace["PasswordNotRequired"] = ([bool]$account.passwordNotRequired);
						$replace["POBox"] = $account.poBox;
						$replace["PostalCode"] = $account.postalCode;
						$replace["ProfilePath"] = $account.profilePath;
						$replace["ScriptPath"] = $account.scriptPath;
						$replace["SmartcardLogonRequired"] = $account.smartcardLogonRequired;
						$replace["TrustedForDelegation"] = $account.trustedForDelegation
						
						Get-ADUser -name $($account.name) | Set-ADUser -Replace $replace
					}
				}
			}
		}
	}

	if ($ouSettings.group -ne $null) {
		foreach ($group in $ouSettings.group) {
			Write-LogMessage -level 1 -msg "Processing Group: $($group.name) [$currentOU]"
			$pwd = $($account.password)
			Write-Verbose "`t`tAccount Password: $pwd"
			if (($pwd -ne $null) -and ($pwd -ne "{DEFAULT PASSWORD}")) { 
				$password = ConvertTo-SecureString -String $pwd -AsPlainText -Force 
			} else { 
				$password = $defaultPasswordSecure 
			}

			if (-Not (Test-ADGroup -name $($group.name))) {
				Write-LogMessage -level 2 -msg "`tCreating Group"
				if (-Not $debug)
				{
					if ($group.scope -eq $null) { $group.SetAttribute("scope", "Global") }
					if ($group.category -eq $null) { $group.SetAttribute("category", "Security") }

					# Scope - {DomainLocal | Global | Universal} 
					# Category - {Distribution | Security}] 
					New-ADGroup -Name $($group.name) `
								-GroupScope $($group.scope) `
								-Description $($group.description) `
								-DisplayName $($group.displayName) `
								-GroupCategory $($group.category) `
								-HomePage $($group.homePage) `
								-SamAccountName $($group.samAccount) `
								-Path $currentOU
				}
			}

			$groupMemberList = @()

			foreach ($grpAccount in $group.account)
			{
				$groupMemberList += Get-ADObject -LDAPFilter "(&(name=$($grpAccount.name))(objectClass=user))" | Select-Object -ExpandProperty distinguishedName
			}

			$tmp = $domain -split "\.",2,"Singleline,IgnoreCase"
			$dc = "DC=" + ($tmp -join ",DC=")

			foreach ($grpOU in $group.ou)
			{
				$dn = "OU=$($grpOU.name)"
				if ($grpOU.dn -ne $null) {
					$dn += ",$($grpOU.dn)"
				}
				$dn += ",$dc"
				
				Write-LogMessage -level 2 -msg "`tSearching for all users in $($grpOU.name) [$dn]"
				$ouMembers = Get-ADUser -Filter * -SearchBase $dn | Select-Object -ExpandProperty distinguishedName
				foreach ($m in $ouMembers) {
					$groupMemberList += $m
				}
			}

			if ($groupMemberList -ne $null -and $groupMemberList.Length -gt 0) {
				foreach ($m in $groupMemberList) {
					Write-LogMessage -level 2 -msg "`t[$($group.name)] Adding: $m"
					if (-Not $debug) {
						Get-ADGroup -LDAPFilter "(name=$($group.name))" | Add-ADGroupMember -Members $m
					}
				}
			}
		}
	}
	
	if ($ouSettings.ou -ne $null) {		
		foreach ($ou in $ouSettings.ou) {
			$result = Execute-ActiveDirectoryProcessOU $domain $currentOU $ou
		}
	}
	
	return $result
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Replace-TokensInString
# Description:
#	Replaces all known tokens in the specified string and returns the result
#-------------------------------------------------------------------------------------------------------------------
function Replace-TokensInString {
	param([string] $str, [string] $baseFolder = $null)

	#Write-LogMessage -level 1 -msg "Before: $str, BaseFolder: $baseFolder, AppFolder: $appFolder"
	
	if ($str -match "{SCRIPT FOLDER}") {
		$str = $str -replace "{SCRIPT FOLDER}", $($xmlSettings.configuration.workingDirectory)
	}
	if ($str -match "{BASE FOLDER}") {
		$str = $str -replace "{BASE FOLDER}", $baseFolder
	}
	if ($str -match "{PROGRAMFILESx86}") {
		$str = $str -replace "{PROGRAMFILESx86}", ${env:ProgramFiles(x86)}
	}
	if ($str -match "{PROGRAMFILES}") {
		$str = $str -replace "{PROGRAMFILES}", ${env:ProgramFiles}
	}
	if ($str -match "{SYSTEMDRIVE}") {
		$str = $str -replace "{SYSTEMDRIVE}", ${env:SystemDrive}
	}

	#Write-LogMessage -level 1 -msg "`tAfter: $str"
	
	return $str
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Write-LogMessage
# Description:
#	Writes a log message and color codes it based on the level (0: error, 1: general, 2: info, 3: highlight
#-------------------------------------------------------------------------------------------------------------------
function Write-LogMessage {
	param([int] $level = 1, [bool] $noNewLine = $false, [string] $msg)

	switch ($level) {
		0 { $color = "Red" }
		1 { $color = "White" }
		2 { $color = "Yellow" }
		3 { $color = "Green" }
	}

	if ($noNewLine) {
		Write-Host $msg -ForegroundColor $color -NoNewline
	} else {
		Write-Host $msg -ForegroundColor $color 
	}
}