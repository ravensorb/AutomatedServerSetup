Function Enable-AutoLogon {
<# 
	.Synopsis 
		Enables Auto Logon for the specified user
	.Description 
		This script enables auto logon for a specified user 
	
	PARAMETERS 
		-computers array of computer names (defaults to the current computer)
		-defaultDomainName the default domain name (defaults to the current domain)
		-defaultUserName the default user name (defaults to the current user  
		-defaultPassword the password for the user  
		-autoLogonCount the number of times the auto logon will occur
	.Example 
		Enable-AutoLogon.ps1 -userName administrator -password NewPassword 
	
		Enables auto logon for Administrator for 1 time 
	.Example 
		Enable-AutoLogon.ps1 -password NewPassword -autoLogonCount 3
	
		Enables auto logon for the current user for 3 times

	.Notes 
		NAME:  Enable-Autologon
		AUTHOR: Shawn Anderson
		LASTEDIT: 12/06/2013
		KEYWORDS: 
	.Link 
		
#Requires -Version 2.0 
#> 
	param (
		[Parameter(Mandatory=$false)] [String[]]$computers = ".",
		[Parameter(Mandatory=$false)] [String]$domainName = $env:USERDOMAIN,
		[Parameter(Mandatory=$false)] [String]$userName = $env:USERNAME,
		[Parameter(Mandatory=$true)]  [String]$password,
		[Parameter(Mandatory=$false)] [Int]$autoLogonCount = 1
	)

	if ([IntPtr]::Size -eq 8) {
		$hostArchitecture = "amd64"
	} else {
		$hostArchitecture = "x86"
	}
	
	foreach ($computer in $computers) {
		if (($hostArchitecture -eq "x86") -and ((Get-WmiObject -ComputerName $computer -Class Win32_OperatingSystem).OSArchitecture -eq "64-bit")) {
			Write-Host "Remote System's OS architecture is amd64. You must run this script from x64 PowerShell Host"
			continue
		} else {
			if ($computer -ne ".") {
				if ((Get-Service -ComputerName $computer -Name RemoteRegistry).Status -ne "Running") {
					Write-Error "Remote registry service is not running on $($computer)"
					continue
				} else {
					Write-Verbose "Setting Auto logon on $($computer)"

					$remoteRegBaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$computer)
					$remoteRegSubKey = $remoteRegBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",$true)
					$remoteRegSubKey.SetValue("AutoAdminLogon",1,[Microsoft.Win32.RegistryValueKind]::DWord)
					$remoteRegSubKey.SetValue("ForceAutoLogin",1,[Microsoft.Win32.RegistryValueKind]::DWord)
					$remoteRegSubKey.SetValue("DefaultDomainName",$domainName,[Microsoft.Win32.RegistryValueKind]::String)
					$remoteRegSubKey.SetValue("DefaultUserName",$userName,[Microsoft.Win32.RegistryValueKind]::String)
					$remoteRegSubKey.SetValue("DefaultPassword",$password,[Microsoft.Win32.RegistryValueKind]::String)

					if ($AutoLogonCount) {
						$remoteRegSubKey.SetValue("AutoLogonCount",$AutoLogonCount,[Microsoft.Win32.RegistryValueKind]::DWord)
					}
				}
			} else {
				#do local modifications here
				Write-Verbose "Setting Auto logon on $($computer)"
				
				Push-Location
				Set-Location "HKLM:\Software\Microsoft\Windows NT\Currentversion\WinLogon"
				New-ItemProperty -Path $pwd.Path -Name "AutoAdminLogon" -Value 1 -PropertyType "DWord" -Force | Out-Null
				New-ItemProperty -Path $pwd.Path -Name "ForceAutoLogon" -Value 1 -PropertyType "DWord" -Force | Out-Null
				New-ItemProperty -Path $pwd.Path -Name "DefaultUserName" -Value $userName -PropertyType "String" -Force | Out-Null
				New-ItemProperty -Path $pwd.Path -Name "DefaultPassword" -Value $password -PropertyType "String" -Force | Out-Null
				New-ItemProperty -Path $pwd.Path -Name "DefaultDomainName" -Value $domainName -PropertyType "String" -Force | Out-Null
				
				if ($AutoLogonCount) {
					New-ItemProperty -Path $pwd.Path -Name "AutoLogonCount" -Value $autoLogonCount -PropertyType "Dword" -Force | Out-Null
				}
				
				Pop-Location
			}
		}
	}
}