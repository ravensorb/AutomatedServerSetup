##--------------------------------------------------------------------------
##  FUNCTION.......:  Set-RunOnce
##  PURPOSE........:  Changes the RunOnce registry key to run whatever is 
##                    specified by the user.
##  REQUIREMENTS...:  Administrator credentials are needed to write to the 
##                    HKLM registry hive.
##  NOTES..........:  
##--------------------------------------------------------------------------
Function Set-RunOnce {
	<#
	.SYNOPSIS
	 Changes the RunOnce registry key to run whatever is specified by the 
	 user.
	.DESCRIPTION
	 This function writes subkeys to 'HKLM:\SOFTWARE\Microsoft\Windows\
	 CurrentVersion\RunOnce'. 
	 
	 If run without parameters, this function will default RunOnce to run
	 notepad.exe on the next reboot.
	 
	 By default anything written to this key will not run in Safe Mode, and 
	 will not be run again if the operation fails.
	.PARAMETER Description
	 This is the name of the subkey that will be written to RunOnce. This 
	 can be any text, as long as there are no spaces in it.
	 Alias..: -name, -n
	.PARAMETER FileToRun
	 The full name (including path) of the file to run after reboot.
	 Alias..: -file, -f
	.PARAMETER PassScriptToPowerShell
	 In some instances it is necessary to specify the full path to the
	 PowerShell executable when using PowerShell scripts with RunOnce. This
	 Switch alters the FileToRun parameter to include this path.
	 Alias..: -UsePoSh, -p
	.PARAMETER RunElevated
	 This Switch will run powershell in elevated mode.
	 Alias..: -elevated, -e
	.PARAMETER SafeMode
	 This Switch will prepend a '*' character to the -FileToRun parameter,
	 which will allow RunOnce to function in Safe Mode.
	 Alias..: -safe, -s
	.PARAMETER Defer
	 This Switch will prepend a '!' character to the -FileToRun parameter,
	 which will delay the deletion of the RunOnce value until the command
	 has completed. As a result, if a RunOnce operation does not run 
	 properly, the associated program will be asked to run at the next boot.
	 Alias..: -d
	.EXAMPLE
	 C:\PS>Set-RunOnce
	 
	 This example will write a subkey to RunOnce named "Notepad" with a 
	 REG_SZ value of 'notepad.exe', causing notepad.exe to run at the next 
	 reboot.
	 
	.EXAMPLE
	 C:\PS>Set-RunOnce TestName c:\test.cmd
	 
	 This example will write a subkey to RunOnce named "TestName" with a 
	 REG_SZ value of 'c:\test.cmd', causing test.cmd to run at the next 
	 reboot.
	 
	.EXAMPLE
	 C:\PS>Set-RunOnce ps1 c:\a.ps1 -UsePoSh
	 
	 This example will write a subkey to RunOnce named "ps1" with a REG_SZ 
	 value of 
	 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe "c:\a.ps1"',
	 causing PowerShell to run the a.ps1 script at the next reboot. 
	 The use of the -PassScriptToPowerShell parameter (or it's aliases 
	 -UsePoSh or -u) is not strictly necessary to get PowerShell scripts to 
	 work with RunOnce, it will depend on how you have configured your 
	 system to handle the execution of PowerShell scripts. When in doubt, 
	 use this parameter to ensure that the script will run.
	 
	 NOTE:
	 PowerShell's Execution Policy must be set to allow scripts to run for
	 this to work.
	.EXAMPLE
	 C:\PS>"c:\a.ps1" | Set-RunOnce ps1 -p
	 
	 This example does the same thing as EXAMPLE 3, but uses pipelining to
	 pass the -FileToRun parameter, and uses the -p alias for the
	 -PassScriptToPowerShell parameter.
	 
	.NOTES
	 NAME......:  Set-RunOnce
	 AUTHOR....:  Joe Glessner
	 LAST EDIT.:  10JUN11
	 CREATED...:  11APR11
	.LINK
	 http://joeit.wordpress.com/
	.LINK
	 http://support.microsoft.com/kb/314866/EN-US
	.LINK
	 http://msdn.microsoft.com/en-us/library/aa376977%28v=vs.85%29.aspx
	#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline=$False,Position=0,Mandatory=$False)]
		[Alias("name","n")]
		[String]$Description=$null,
		
		[Parameter(ValueFromPipeline=$True,Position=1,Mandatory=$True)] 
		[Alias("file","f")]
		[String]$FileToRun,
		
		[Parameter(ValueFromPipeline=$True,Position=2,Mandatory=$False)] 
		[Alias("args","a")]
		[String]$Arguments = $null,
		
		[Alias("UsePosh","p")]
		[Switch]$PassScriptToPowerShell=$true,
		
		[Alias("psv")]
		[Float]$PowerShellVersion=$null,
		
		[Alias("Elevated", "e")]
		[Switch]$runElevated=$true,
		
		[Alias("safe","s")]
		[Switch]$SafeMode=$false,
		
		[Alias("d")]
		[Switch]$Defer=$false
	)#END: Param
	
	Write-Verbose "Verifying user context..."
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( `
	[Security.Principal.WindowsIdentity]::GetCurrent() ) 
	
	If ($currentPrincipal.IsInRole( `
		[Security.Principal.WindowsBuiltInRole]::Administrator )) { 
		Write-Verbose "PowerShell is running in Administrator context."
	}#END: If ($currentPrincipal.IsInRole(...
	Else { 
		Write-Warning "Set-RunOnce requires Administrator credentials."
		Write-Warning "Elevate PowerShell before retrying the operation."
		Write-Warning "No changes were made."
		Break
	}#END: Else 
	
	$RegistryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
	$PoSh = "C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe"
		
	If($PassScriptToPowerShell) {
		$char0 = [char] '"'
		$char1 = [char] "'"
		$args = ""
		$ver = ""
		if ($Arguments -ne $null) { $args = " $Arguments" }
		if (($PowerShellVersion -ne $null) -and ($PowerShellVersion -ne 0)) { $ver = " -Version " + $PowerShellVersion }
		$FullPath = $PoSh + $ver + " -File " + $char0 + $FileToRun + $char0 + $args
		Write-Verbose "Setting RunOnce to use PowerShell..."
		$FileToRun = $FullPath
	}#END: If($PassScriptToPowerShell)
	ElseIf($SafeMode) {
		$AltPath = "*" + $FileToRun
		Write-Verbose "Setting RunOnce to work in SafeMode..."
		$FileToRun = $AltPath
	}#END: ElseIf($SafeMode)
	
	If($Defer) {
		$AltPath = "!" + $FileToRun
		Write-Verbose "Setting to persist if $FileToRun fails to run ..."
		$FileToRun = $AltPath
	}#END: If($Defer)

	if (-Not $Description) { $Description = $FileToRun }
	
	Write-Host "Creating RunOnce subkey for $Description -> $FileToRun..." -Foregroundcolor Yellow
	Set-ItemProperty -Path $RegistryKey -Name $Description -Value $FileToRun

	Write-Verbose "Returning to marked location..."
}#END: Function Set-RunOnce