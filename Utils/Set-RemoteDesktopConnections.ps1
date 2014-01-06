Function Set-RemoteDesktopConnections {
<#     
.SYNOPSIS     
   Function used to enable/disable Remote Desktop connections for the current computer
     
.DESCRIPTION   
   Function used to enable/disable Remote Desktop connections for the current computer
      
.NOTES     
    Name: Set-RemoteDesktopConnections
    Author: Shawn Anderson
    DateCreated: 6December2013    
      
.EXAMPLE    
    [PS] C:\> Set-RemoteDesktopConnections -Enable $True
     
   
Description   
-----------       
Command allow for enabling/disabling Remote Desktop Connections for the current computer.
#>  
    [cmdletbinding()]  
 	param(
		[Parameter(Mandatory=$false)] [Boolean]$Enabled = $true
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
	
	$rdpKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
	Set-ItemProperty -Path $rdpKey -Name "fDenyTSConnections" -Value (!$Enabled)
	
	Write-Host "Remote Desktop connections have been" (?: {$Enabled} {"enabled"} {"disabled"}) "for this computer." -ForegroundColor Green
}
