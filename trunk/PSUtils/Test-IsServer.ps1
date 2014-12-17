<#     
.SYNOPSIS     
   Tests the specfied computer to see if it is a "server" or a "client"
	 
.DESCRIPTION   
   Returns true if the specified computer is a server and false if it is a client
	  
.NOTES     
	Name: Test-IsServer
	Author: Shawn Anderson
	DateCreated: 16December2014    
	  
.EXAMPLE    
	Tests current computer to see if it is a server
	
	[PS] C:\> (Test-IsServer) -eq $true	  
   
Description   
-----------       
Returns true if the specified computer is a server and false if it is a client
#>  
function Test-IsServer
{
	[cmdletbinding()]  
	param(
		[string]$computer = $null
	)

	if ($computer -eq $null -or $computer.Length -eq 0) { $computer = $env:COMPUTERNAME }

	$os = Get-WmiObject -class Win32_OperatingSystem -computerName $computer
	
	Switch ($os.Version)
	{
		"5.1.2600" { return $false }
		DEFAULT {
			if ($os.ProductType -eq 1) {
				return $false
			} 
		}
	} #end switch

	return $true
} #end Test-IsServer