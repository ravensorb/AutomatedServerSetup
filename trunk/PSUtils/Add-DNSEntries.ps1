Function Add-DNSEntries 
{
	<#
	.SYNOPSIS
		Load Objects into DNS in bulk.

	.DESCRIPTION
		Use Add-DNSEntries to create DNS Records in bulk
	
	.PARAMETER Path	
		Path to XML file with objects to load.

	.PARAMETER XmlData	
		An XML string with the objects to load
		
	.EXAMPLE
		To load all of the objects in the file "dns-entries.xml" into AD.
	
		PS C:\> Add-DNSEntries -Path C:\dns-entries.xml

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Load AD Objects from: C:\dns-entries.xml".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

	.EXAMPLE
		To load all of the objects in the XML variable "$xmlAD" into AD.
		
		PS C:\> Add-DNSEntries -XmlData $xmlDNS

		Confirm
		Are you sure you want to perform this action?
		Performing operation "Load AD Objects from data passed into the module".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

	.NOTES
		Author: Shawn Anderson
		Blog  : http://eye-catcher.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/
	
	.LINK
		http://msdn.microsoft.com/en-us/library/aa387290(v=vs.85).aspx
		http://support.microsoft.com/kb/926464
#Requires -Version 2.0 
	#>
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="High"
	)]
	Param
	(
		[parameter(Mandatory=$false)]
		[String]$Path = $null,
		[Parameter(Mandatory=$false)] 
		[Xml] $XmlData = $null
	)

	$DefaultName = "AD Objects to AD" 
		
	$User = [Security.Principal.WindowsIdentity]::GetCurrent()
	$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

	if(!$Role)
	{
		Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		Return 
	} #End If !$Role		
	
	If (($Path -eq $null -or $Path.Length -eq 0) -and ($XmlData -eq $null -or $XmlData.Length -eq 0))
	{
		Write-Warning "Please specify either a Path or an XmlData parameter"
		Return
	}

	$xmlSettings = $null

	If($Path -ne $null -and $Path.Length -gt 0) {
		if (Test-Path $Path) {
			# Resolve the Configuration file incase a relative path was specifed 
			$Path = (Resolve-Path $Path).Path

			Write-Host "Loading Configuration File: $Path" -Foregroundcolor Green
			
			$xmlSettings = New-Object -TypeName XML
			$xmlSettings.Load($Path)
		} 
	} #End If (Test-Path $Path)
	ElseIf ($XmlData -ne $null) {
		$xmlSettings = $XmlData
	} 
	
	if ($XmlSettings -eq $null) {
		Write-Warning "Unable to load any configuration data"
		Return
	}
	if ($xmlSettings.configuration.workingDirectory -eq $null) {
		# Lets get the workingDirectory
		$scriptCommand = $myinvocation.mycommand.definition
		$workingDirectory = $PSScriptRoot
		if ($workingDirectory -eq $null -or $workingDirectory.length -eq 0) {
			$workingDirectory = Split-Path $scriptCommand
		}

		$xmlSettings.configuration.SetAttribute("workingDirectory", $workingDirectory)
	}

	if ($xmlSettings.configuration.version -ne "1.0.0") {
		Write-Warning "Settings File Version number does not match expected version.  Possible incompatibility.  Please review the settings file and update if necessary." -ForegroundColor Red
		Return
	}

	return Execute-CreateDNSEntries $xmlSettings

} #In The End :)

#-------------------------------------------------------------------------------------------------------------------
# DNS
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ConfigureDNS
# Description:
#	Handles installing and configuring DNS
#-------------------------------------------------------------------------------------------------------------------
function Execute-CreateDNSEntries {
	param([xml] $xmlSettings)

	if ($xmlSettings.configuration.dns -eq $null) { return $true }

	[string] $zoneName = $xmlSettings.configuration.dns.zone
	[string] $computerName = $($xmlSettings.configuration.computer.name)

	if ($computerName -eq $null -or $computerName.Length -eq 0) {
		$computerName = $Env:COMPUTERNAME
	}

	$osDetails = gwmi win32_operatingsystem
	
	Write-Output "Configuring DNS Records [Zone: $zoneName]"
	foreach ($record in $xmlSettings.configuration.dns.record) {
			if ($record.name -eq "{COMPUTER NAME}") { $record.SetAttribute("name", "$computerName") }
			
			switch ($record.type) {
				"a" {
					if ($record.address -eq "{IP ADDRESS}") { $record.SetAttribute("address", "127.0.0.1") }

					Execute-DNSCreateA $zoneName $($record.name) $($record.address)
				}
				"cname" {
					$rrData = $($record.name);
					if ($rrData -like "*.$zoneName") { $rrData = "$rrData.$zoneName" }
					if (-Not ($rrData -like "*.")) { $rrData = "$rrData.$zoneName" }

					Execute-DNSCreateCNAME $zoneName $($record.alias) $rrData
				}
				"srv" {
					Write-Warning "DNS SRV Records not supported yet"
				}
				"mx" {
					Write-Warning "DNS MX Records not supported yet"
				}
			}
	}
	
	return $true
}

function Execute-DNSCreateA {
	param([string] $zoneName, [string] $nodeName, [string] $rrData)

	$osDetails = gwmi win32_operatingsystem

	$create = $false
	if ($osDetails.Version -like "6.1*") {
		$result = (& dnscmd.exe /EnumRecords $zoneName $nodeName) -join ", "
		#Write-LogMessage 1, $result

		$create = ($result -like "*DOES_NOT_EXIST*") -or (-Not ($result -like "*@*" -and $result -like "* A`t*"))
	} else {
		$result = Get-DnsServerResourceRecord -ErrorAction SilentlyContinue -ZoneName $zoneName -RRType "A" -Name $nodeName

		$create = $result -eq $null
	}

	Write-Output "`tDNS Record: $nodeName [Exists: $(-Not $create)]"

	if (-Not $debug -and $create)
	{
		if ($osDetails.Version -like "6.1*") {
			Start-Process -FilePath dnscmd.exe -ArgumentList "/RecordAdd $zoneName $nodeName A $rrData"
		} else {
			Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $nodeName -IPv4Address $rrData
		}
	}
}

function Execute-DNSCreateCNAME {
	param([string] $zoneName, [string] $nodeName, [string] $rrdata)

	$osDetails = gwmi win32_operatingsystem

	$create = $false
	if ($osDetails.Version -like "6.1*") {
		$result = (& dnscmd.exe /EnumRecords $zoneName $nodeName) -join ", "
		#Write-LogMessage 1, $result

		$create = ($result -like "*DOES_NOT_EXIST*") -or (-Not ($result -like "*@*" -and $result -like "* CNAME`t*"))
	} else {
		$result = Get-DnsServerResourceRecord -ErrorAction SilentlyContinue -ZoneName $zoneName -RRType "CName" -Name $nodeName

		$create = $result -eq $null
	}

	Write-Output "`tDNS Record: $nodeName [Exists: $(-Not $create)]"

	if (-Not $debug -and $create)
	{
		if ($osDetails.Version -like "6.1*") {
			Start-Process -FilePath dnscmd.exe -ArgumentList "/RecordAdd $zoneName $nodeName CNAME $rrData"
		} else {
			Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $nodeName -HostNameAlias $rrData
		}
	}
}

function Execute-DNSCreateSRV {
}

function Execute-DNSCreateMX {
}