Function Get-WUAutoUpdateSettings
{
	<#
	.SYNOPSIS
	    Gets the Microsoft Auto Update Settings

	.DESCRIPTION
	    Use Get-WUAutoUpdateSettings to get the current settings for the Microsoft Auto Update Service.
                              		
	.EXAMPLE
		Get current Microsoft Update Service settings.
	
		PS C:\> Get-WUAutoUpdateSettings

	.NOTES
		Author: Shawn Anderson
		Blog  : http://blog.itramblings.com/
		
	.LINK
		http://blog.itramblings.com

	.LINK
	#>
	[OutputType('PSWindowsUpdate.WUAutoUpdateSettings')]
	[CmdletBinding()]
	Param(
	)#END: Param
	
	Begin
	{
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role	
	}
	
	Process
	{
	    If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Set Windows Update Settings")) 
		{
			$objAutoUpdateSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
			
			$objAutoUpdateSettings.Refresh()

			Return $objAutoUpdateSettings
	    } #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Set Windows Update Settings")		

	} #End Process
	
	End{}
} #In The End :)