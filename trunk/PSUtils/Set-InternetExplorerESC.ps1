function Set-InternetExplorerESC {
<#     
.SYNOPSIS     
   Function used to set the Internet Explorer Enhanced Security Settings
	 
.DESCRIPTION   
   Function used to set the Internet Explorer Enhanced Security Settings
	  
.NOTES     
	Name: Set-InternetExplorerESC
	Author: Shawn Anderson
	DateCreated: 6December2013    
	  
.EXAMPLE    
	Enable ESC for both Administrators and Users
	
	[PS] C:\> Set-InternetExplorerESC -Admin $True -User $True
.EXAMPLE     
	Disable ESC for only Administrators

	[PS] C:\> Set-InternetExplorerESC -Admin $False
	  
   
Description   
-----------       
Command will allow for enabling/disabling Internet Explorer Enhanced Security Checks 
#>  
	[cmdletbinding()]  
	param(
		[Boolean]$Admin = $false,
		[Boolean]$User = $true
	)

	set-alias ?: Invoke-Ternary -Option AllScope -Description "PSCX filter alias"
	filter Invoke-Ternary ([scriptblock]$decider, [scriptblock]$ifTrue, [scriptblock]$ifFalse)
	{
	   if (&$decider) { 
		  &$ifTrue
	   } else { 
		  &$ifFalse 
	   }
	}	

	$debug = $psboundparameters.debug.ispresent

	[bool] $skip = $false
	if (Get-Command -Name "Test-IsServer") {
		if (-Not (Test-IsServer)) {
			Write-Verbose "[Test-IsServer] return true.  Skipping"
			$skip = $true
		}
	} else {
		$os = Get-WmiObject -class Win32_OperatingSystem -computerName $computer
		if ($os.ProductType -eq 1) {
			Write-Verbose "[WMI OS Call] Product Type is 1.  Skipping"
			$skip = $true
		}
	}

	if ($skip) {
		Write-Host "IE Enhanced Security Configuration does not need to be set on a client workstation" -ForegroundColor Green
		return
	}

	if (-Not $debug) {
		$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
		Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value $Admin
	}
	Write-Host "IE Enhanced Security Configuration (ESC) has been" (?: {$Admin} {"enabled"} {"disabled"}) "for Administrators." -ForegroundColor Green
	
	$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	if (-Not $debug) {
		Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value $User
	}
	Write-Host "IE Enhanced Security Configuration (ESC) has been" (?: {$User} {"enabled"} {"disabled"}) "for Users." -ForegroundColor Green
	
	if (-Not $debug) {
		Write-Verbose ('Calling iesetup.dll hardening methods.')
		Rundll32 iesetup.dll, IEHardenLMSettings
		Rundll32 iesetup.dll, IEHardenUser
		Rundll32 iesetup.dll, IEHardenAdmin 
	}
}
