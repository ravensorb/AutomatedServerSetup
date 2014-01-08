function Show-YesNoQuestion {
<#     
.SYNOPSIS     
   Function used to Ask end user a yes/no question and return the result
     
.DESCRIPTION   
   Function used to Ask end user a yes/no question and return the result
      
.NOTES     
    Name: Show-YesNoQuestion
    Author: Shawn Anderson
    DateCreated: 6December2013    
      
.EXAMPLE    
    [PS] C:\> Show-YesNoQuestion -message "Do you want to delete the files"
     
   
Description   
-----------       
Function used to Ask end user a yes/no question and return the result.
#>  
    [cmdletbinding()]  
	param(
		[Parameter(Mandatory=$false)] [string] $title = "Question",
		[Parameter(Mandatory=$true)] [string] $message,
		[Parameter(Mandatory=$false)] [string] $yes = "Yes",
		[Parameter(Mandatory=$false)] [string] $no = "No"
	)

	$yesChoice = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", $yes
	$noChoice = New-Object System.Management.Automation.Host.ChoiceDescription "&No", $no

	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yesChoice, $noChoice)

	$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

	return $result
}
