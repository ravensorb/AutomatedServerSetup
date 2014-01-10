# ==============================================================================================
# 
# NAME: Set-TimeZone.ps1
# 
# AUTHOR: Ben Baird
# 
# Description: 
# Sets the current time zone based on the standard name
# of the time zone ("Mountain Standard Time", "Pacific
# Standard Time", "Eastern Standard Time", etc.).
#
# A Get-TimeZone function, while logically convenient,
# seems unnecessary since you get can the same result
# with a simple .NET class call:
# [TimeZoneInfo]::Local.StandardName
# ==============================================================================================

function Set-TimeZone {

	param(
		[parameter(Mandatory=$true)]
		[string]$TimeZone
	)
	
	$osVersion = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("CurrentVersion")
	$proc = New-Object System.Diagnostics.Process
	$proc.StartInfo.WindowStyle = "Hidden"

	if ($osVersion -ge 6.0)
	{
		# OS is newer than XP
		$proc.StartInfo.FileName = "tzutil.exe"
		$proc.StartInfo.Arguments = "/s `"$TimeZone`""
	}
	else
	{
		# XP or earlier
		$proc.StartInfo.FileName = $env:comspec
		$proc.StartInfo.Arguments = "/c start /min control.exe TIMEDATE.CPL,,/z $TimeZone"
	}

	$proc.Start() | Out-Null

}

