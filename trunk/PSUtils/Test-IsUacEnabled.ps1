Function Test-IsUacEnabled
{  
<#     
.SYNOPSIS     
   Function used to detect if UAC is curently enabled on this system.
     
.DESCRIPTION   
   Function used to detect if UAC is curently enabled on this system. 
      
.NOTES     
    Name: Test-IsUacEnabled
    Author: Shawn Anderson
    DateCreated: 6December2013    
      
.EXAMPLE     
    Test-IsUacEnabled
      
   
Description   
-----------       
Command will check if UAC is currently enabled and return true or false accordingly.  
#>  
    [cmdletbinding()]  
    Param()  

	$isUacEnabled = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System).EnableLua -ne 0

	Write-Output $isUacEnabled
}