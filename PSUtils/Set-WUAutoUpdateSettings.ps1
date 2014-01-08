Function Set-WUAutoUpdateSettings
{
	<#
	.SYNOPSIS
	    Sets the Microsoft Auto Update Settings

	.DESCRIPTION
	    Use Set-WUAutoUpdateSettings to set the current settings for the Microsoft Auto Update Service.
                              		
	.EXAMPLE
		Set settings to automatically download and install everything.
	
		PS C:\> Set-WUAutoUpdateSettings -Enable $True -Level 4

	.NOTES
		Author: Shawn Anderson
		Blog  : http://blog.itramblings.com/
		
	.LINK
		http://blog.itramblings.com

	.LINK
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline=$True,Position=0,Mandatory=$True)] 
		[Alias("e")]
		[Switch]$Enable,
		
		[Alias("level","l")]
		[Int]$NotificationLevel=4,
		
		[Alias("recommended", "r")]
		[Switch]$IncludeRecommendations=$false,
		
		[Alias("featured","f")]
		[Switch]$IncludedFeaturedUpdates=$false
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

			$objAutoUpdateSettings.NotificationLevel = $NotificationLevel
			$objAutoUpdateSettings.IncludeRecommendedUpdates = $IncludeRecommendations
			$objAutoUpdateSettings.FeaturedUpdatesEnabled = $IncludedFeaturedUpdates
			
			$objAutoUpdateSettings.Save()
			
			Return $True
	    } #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Set Windows Update Settings")		

	} #End Process
	
	End{}
} #In The End :)