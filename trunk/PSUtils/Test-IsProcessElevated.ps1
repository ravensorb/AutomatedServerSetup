Function Test-IsAdmin   
{  
<#     
.SYNOPSIS     
   Function used to detect if current current process is running in elevated mode.  
     
.DESCRIPTION   
   Function used to detect if current process was started in elevated mode. 
      
.NOTES     
    Name: Test-IsProcessElevated
    Author: Shawn Anderson
    DateCreated: 6December2013    
      
.EXAMPLE     
    Test-IsProcessElevated
      
   
Description   
-----------       
Command will check the current process was executed in elevated mode and return true or false accordingly.  
#>  
    [cmdletbinding()]  
    Param()  

	$isElevated = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

	Write-Output $isElevated

}