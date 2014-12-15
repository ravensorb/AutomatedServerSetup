#-------------------------------------------------------------------------------------------------------------------
# General
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InitializeScript
# Description:
#	Handles setting up the script, initializing variables, etc
# Function: Execute-InitializeScript
#-------------------------------------------------------------------------------------------------------------------
function Execute-InitializeScript {
	param([xml] $xmlSettings)

	if ($xmlSettings.configuration.defaultPassword -eq "*") {
		#TODO Need to handle storing this between reboots
		#Write-LogMessage -level 1 -msg "Prompting for new default password"
		#$defaultPasswordCredentials = (Get-Credential -UserName "Default Password" -Message "Set Default Password").GetNetworkCredential()
		#$defaultPassword = $defaultPasswordCredentials.Password
		#$xmlSettings.configuration.SetAttribute("defaultPassword", $defaultPassword)
	}

	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ConfigureLocalComputer
# Description:
#	Handles setting up the local computer (setting passwords, enabling auto-login, windows update, setting up RDP, etc)
# Function: Execute-ConfigureLocalComputer
#-------------------------------------------------------------------------------------------------------------------
function Execute-ConfigureLocalComputer {
	param([xml] $xmlSettings)
	
	Write-LogMessage -level 1 -msg "Checking Execution Policy"
	$executionPolicy = Get-ExecutionPolicy
	if ($executionPolicy -ne "ByPass" -and $executionPolicy -ne "Unrestricted") {
		Write-LogMessage -level 2 -msg "Execution Policy should be set to ByPass or Unrestricted. Setting it to ByPass now." 
		Set-ExecutionPolicy ByPass -Force
	}
	
	Execute-ComputerSecurity $xmlSettings

	if ($xmlSettings.configuration.computer.autoLogon -ne $null -and $xmlSettings.configuration.computer.autoLogon.enabled -eq 1) {
		if (Test-AutoLogon -eq $true) {
			Write-LogMessage -level 1 -msg "Autologon already enabled"
		} else {
			Write-LogMessage -level 1 -msg "Enabling Auto login"
			if (-Not $debug) {
				$autoLoginUserId = $($xmlSettings.configuration.computer.autoLogon.userId)
				$autoLoginDomain = $($xmlSettings.configuration.computer.autoLogon.domain)
				$autoLoginPassword = $($xmlSettings.configuration.computer.autoLogon.password)

				if ($xmlSettings.configuration.computer.autoLogon.count -eq $null) { $xmlSettings.configuration.computer.autoLogon.SetAttribute("count", 999) }
				
				if ($autoLoginUserId -eq "{CURRENT USER}") { $autoLoginUserId = $env:username }
				if ($autoLoginPassword -eq $null) { 
					$autoLoginCredentials = (Get-Credential -UserName $autoLoginUserId -Message "Autologon").GetNetworkCredential()
					$autoLoginUserId = $autoLoginCredentials.UserName
					$autoLoginDomain = $autoLoginCredentials.Domain
					$autoLoginPassword = $autoLoginCredentials.Password
				}
				
				Enable-Autologon -domainName $autoLoginDomain -userName $autoLoginUserId -password $autoLoginPassword -autoLogonCount $([int]$xmlSettings.configuration.computer.autoLogon.count)
			}
		}
	}
	
	if ($xmlSettings.configuration.computer.timeZone -ne $null) {
		Write-LogMessage -level 1 -msg "Setting TimeZone to $($xmlSettings.configuration.computer.timeZone)"
		if (-Not $debug) {
			Set-TimeZone $($xmlSettings.configuration.computer.timeZone)
		}
	}
	
	if ($xmlSettings.configuration.computer.remoteDesktop -ne $null) {
		Write-LogMessage -level 1 -msg "Setting up Remote Desktop"
		if (-Not $debug) {
			Write-Verbose "Setting Remote Desktop Connection: $([int]$xmlSettings.configuration.computer.remoteDesktop)"
			Set-RemoteDesktopConnections -Enabled $([int]$xmlSettings.configuration.computer.remoteDesktop)
		}
	}
		
	if ($xmlSettings.configuration.computer.ieSecurity -ne $null) {
		Write-LogMessage -level 1 -msg "Settings up Internet Explorer Enhanced Security"
		if (-Not $debug) {
			Write-Verbose "Setting ESC for Admin: $([int]$xmlSettings.configuration.computer.ieSecurity.admin)"
			Write-Verbose "Setting ESC for Users: $([int]$xmlSettings.configuration.computer.ieSecurity.user)"
			Set-InternetExplorerESC -Admin $([int]$xmlSettings.configuration.computer.ieSecurity.admin) -User $([int]$xmlSettings.configuration.computer.ieSecurity.user)
		}
	}
		
	Write-LogMessage -level 1 -msg "Settings Auto login for trusted web sites zone"
	if (-Not $debug) {
		Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' -Name "1A00" | Set-ItemProperty -Name "1A00" -Value "0"

		$zoneMapPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
		if(!(Test-Path $zoneMapPath)) {
			New-Item -Path $zoneMapPath | Out-Null
		}
		Set-ItemProperty -LiteralPath $zoneMapPath -Name "UncAsIntranet" -Value 1 -type DWORD
		
		$localhostKeyPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost"
		if(!(Test-Path $localhostKeyPath)) {
			New-Item -Path $localhostKeyPath | Out-Null
		}
		Set-ItemProperty -LiteralPath $localhostKeyPath -Name "http" -Value 1 -type DWORD

		$domainKeyPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$env:COMPUTERNAME"
		if(!(Test-Path $domainKeyPath)) {
			New-Item -Path $domainKeyPath | Out-Null
		}
		Set-ItemProperty -LiteralPath $domainKeyPath -Name "http" -Value 1 -type DWORD
	}
	
	switch ($([int]$xmlSettings.configuration.computer.updateHelp)) {
		0 { 
		}
		1 { 
			Write-LogMessage -level 1 -msg "Updating Powershell Help"
			Update-Help 
		}
		2 { 
			Write-LogMessage -level 1 -msg "Updating Powershell Help (Force)"
			Update-Help -Force 
		}
	}

	Execute-ComputerSQLAliases $xmlSettings
	
	Execute-ComputerServices $xmlSettings
	
	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ComputerServices
# Description:
#	Handles settings for local services 
#-------------------------------------------------------------------------------------------------------------------
function Execute-ComputerServices {
	param([xml] $xmlSettings)
	
	if ($xmlSettings.configuration.services -eq $null) { return $true }

	Write-LogMessage -level 1 -msg "Checking Services"

	$xmlSettings.configuration.computer.services.service | % { 
		Write-LogMessage level 1 -msg "`t$($_.name)"
		
		$svc = (Get-WmiObject -Class Win32_Service -Filter "name='$($_.name)'")
		$svc = Get-Service -Name $_.name -ErrorAction SilentlyContinue

		if ($svc -ne $null) {
			if ($svc.StartupMode -ne $_.startupMode) {
				Write-LogMessage -level 1 -msg "`t`tSetting Startup Mode: $($_.startupMode)"
				if (-Not $debug) {
					Set-Service -Name $_.name -StartupType $_.startupMode
				}
			}

			if ($svc.start -eq "1") {
				if ($svc.State -eq "Stopped") {
					Write-LogMessage -level 1 -msg "`t`tStarting Service"
					if (-Not $debug) {
						Start-Service -Name $_.name
					}
				}
			}
		}
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ComputerSQLAliases
# Description:
#	Handles seetting up SQL Aliases 
#-------------------------------------------------------------------------------------------------------------------
function Execute-ComputerSQLAliases {
	param([xml] $xmlSettings)
	
	if ($xmlSettings.configuration.sqlAliases -eq $null) { return $true }

	Write-LogMessage -level 1 -msg "Creating SQL Aliases"

	$xmlSettings.configuration.computer.sqlAliases.entry | % { 
		Write-LogMessage level 1 -msg "`t$_.name"
		if (-Not $debug) {
			Add-SQLAlias -aliasName $_.name -SQLInstance $_.server -port $.port 
		}
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ComputerSecurity
# Description:
#	Handles the local computer security (setting passwords)
#-------------------------------------------------------------------------------------------------------------------
function Execute-ComputerSecurity {
	param([xml] $xmlSettings)

	if ($xmlSettings.configuration.computer.security -eq $null) { return $true }

	foreach ($record in $xmlSettings.configuration.computer.security.account) {
		$userName = $([string]$record.name)
		$password = $([string]$record.password)

		if ($userName -eq "{CURRENT USER}") { $userName = $env:username }
		if ($password -eq "{DEFAULT PASSWORD}" -or $password -eq $null) { $password = $([string]$xmlSettings.configuration.defaultPassword) }
		if ($password -eq "*") {
			$userCredentials = (Get-Credential -UserName $userName -Message "Set Password for account").GetNetworkCredential()
			$password = $userCredentials.Password
		}		

		# Write-LogMessage -level 1 -msg "Settings '$userName' Password to: '$password'"
		if (-Not $debug) {
			if ($([int]$record.create) -eq 1) {
				Write-LogMessage -level 1 -msg "Creating Account: $userName"
				Install-User -UserName $userName -Password $password -Description $_.description -FullName $_.fullName				
			} else {		
				Set-LocalUserPassword -user $userName -password $password

				if (((Get-Command "Set-ADAccountPassword" -errorAction SilentlyContinue) -ne $null) -and ($password -ne $null))
				{
					if ($password -ne $null) { 
						$passwordSecure = ConvertTo-SecureString -String $password -AsPlainText -Force
					} else { 
						$passwordSecure = "" 
					}
					Set-ADAccountPassword -Identity $userName -Reset -NewPassword $passwordSecure -ErrorAction SilentlyContinue
				}
			}
		}	
	}

	if ($xmlSettings.configuration.computer.security.group -ne $null) {
		foreach ($record in $xmlSettings.configuration.computer.security.group) {
			$groupName = $([string]$record.name)
			 
			Write-LogMessage -level 1 -msg "Adding Users to group: $groupName"
			$record.account | % {
				$userName= $([string]$_.name)
				if ($userName -eq "{CURRENT USER}") { $userName = $env:username }

				Write-LogMessage -level 1 -msg "`t$userName"
				Add-GroupMember -Name $groupName -Member $userName
			}
		}
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-RenameComputer
# Description:
#	Handles renaming the local computer
#-------------------------------------------------------------------------------------------------------------------
function Execute-RenameComputer {
	param([xml] $xmlSettings)
	
	if ($xmlSettings.configuration.computer -eq $null -or $([int]$xmlSettings.configuration.computer.rename) -ne 1) { return $true }

	Write-LogMessage -level 1 -msg "Verifying computer name is correct."
	if ($env:ComputerName -ne $($xmlSettings.configuration.computer.name)) {
		$password = $($xmlSettings.configuration.defaultPassword)
		
		if ($password -ne $null) {
			$passwordSecure = ConvertTo-SecureString -String $password -AsPlainText -Force
		} else {
			$passwordSecure = ""
		}		
	
		$creds = New-Object System.Management.Automation.PSCredential ($env:username, $passwordSecure)
		
		if (-Not $debug) {
			Rename-Computer -NewName $($xmlSettings.configuration.computer.name) -LocalCredential $creds -Force
		}
	#$computer = Get-WmiObject Win32_ComputerSystem
	#if ($computer.Name -ne $($xmlSettings.configuration.computer.name)) {
	#	Write-LogMessage -level 1 -msg "Computer is being renamed to $($xmlSettings.configuration.computer.name)"
	#	if (-Not $debug)
	#	{
	#		$renameResult = $computer.Rename($($xmlSettings.configuration.computer.name))
	#	}
	} else {
		Write-LogMessage -level 1 -msg "Computer has already been renamed. Skipping..."
	}

	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ConfigureWindowsUpdate
# Description:
#	Setups of Windows Updated to Download but not install all updates
#-------------------------------------------------------------------------------------------------------------------
function Execute-ConfigureWindowsUpdate {
	param([xml] $xmlSettings)

	if ($xmlSettings.configuration.computer.wupdates -eq $null) { return $true }

	Write-LogMessage -level 1 -msg "Settings Windows Update to automatically download but not install updates"
	if (-Not $debug) {
		Set-WUAutoUpdateSettings -Enable -level $([int]$xmlSettings.configuration.computer.wupdates.enabled) -recommended -featured
	}
	
	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-WindowsUpdate
# Description:
#	Executes windows updates and installs all pending updates
#-------------------------------------------------------------------------------------------------------------------
function Execute-WindowsUpdate {
	param([xml] $xmlSettings)

	if (($xmlSettings.configuration.computer.wupdates -eq $null) -or ($([int]$xmlSettings.configuration.computer.wupdates.update) -ne 1)) { return $true }

	Write-LogMessage -level 1 -msg "Retrieving a list of Windows Updates that need to be installed. Please note that this may take several minutes."
	$wuList = Get-WUList

	if ($wuList -ne $null -and $wuList.Length -gt 0) {
		Write-LogMessage -level 1 -msg "List of updates to install..."
		$wuList | ft
		Write-LogMessage -level 1 -msg "Installing Windows Updates.  Please note that this may take several minutes or more."
		if (-Not $debug) {	
			Get-WUInstall -AcceptAll -IgnoreReboot -AutoSelectOnly -IgnoreUserInput
		}
	} else {
		Write-LogMessage -level 1 -msg "No updates found at this time..."
	}
	
	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Network
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-NetworkConfiguration
# Description:
#	Setups up the current network configuration (checks to see if we have static or dynamic IP address)
#-------------------------------------------------------------------------------------------------------------------
function Execute-NetworkConfiguration {
	param([xml] $xmlSettings)

	[string] $result = "success"

	if ($xmlSettings.configuration.computer.network -eq $null) {
		return $result
	}

	$networkSettings = $xmlSettings.configuration.computer.network

	$networkAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE
	if (($networkAdapter.DHCPEnabled -eq $true) -and ([int]$networkSettings.warnOnDHCP -eq 0)) {
		Write-LogMessage -level 2 -msg "Network card is set to use DHCP -- Ideally it should be set to a static IP address"	
	}

	if ($networkSettings.disableLoopbackCheck -ne $null) {
		if ((Test-RegistryKeyValue -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'DisableLoopbackCheck') -eq $false) {
			New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -Value $($networkSettings.disableLoopbackCheck) -PropertyType dword
		}
	}

	if (($networkSettings.ipAddress -ne $null) -and ($networkSettings.ipAddress -notcontains $([string]$networkSettings.ipAddress))) {
		Write-LogMessage -level 1 -msg "Settings IP Address"
	
		if (-not $debug) {
			$networkAdapter.EnableStatic($([string]$networkSettings.ipAddress), $([string]$networkSettings.netMask))
			$rc = $networkAdapter.SetGateways($([string]$networkSettings.gateway), 1)
			switch ($rc) {
				0 { $result = "success" }
				1 { $result = "reboot" }
				default { 
					Write-LogMessage -level 0 -msg "Failed to set IP Address. Error: $rc"

					return "error" 
				}
			}
		}
	}

	if ($networkSettings.dns -ne $null) {
		Write-LogMessage -level 1 -msg "Settings DNS Servers"

		if (-not $debug) {
			[string[]] $dnsServers = $([string]$networkSettings.dns) -split ";"
			$rc = $networkAdapter.SetDNSServerSearchOrder($dnsServers)
			switch ($rc) {
				0 { $result = "success" }
				1 { $result = "reboot" }
				default { 
					Write-LogMessage -level 0 -msg "Failed to set DNS Servers. Error: $rc"

					return  "error" 
				}
			}
		}
	}
	
	return $result
}

#-------------------------------------------------------------------------------------------------------------------
# Windows Features
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InstallWindowsFeatures
# Description:
#	Handles installing all requested Windows Features
#-------------------------------------------------------------------------------------------------------------------
function Execute-InstallWindowsFeatures {
	param([xml] $xmlSettings)
	
	#Import-Module ServerManager
	if ($xmlSettings.configuration.features -eq $null) { return $true }
	
	$featuresToAdd = ($xmlSettings.configuration.features.feature -join ",") -split ","
	
	Write-LogMessage -level 1 -msg "Requested Features: $featuresToAdd"
	
	Try {
		$features = Get-WindowsFeature $featuresToAdd | Where-Object { $_.Installed -eq $false }
		
		if (($features -ne $null) -and ($features.Count -gt 0))
		{
			Write-LogMessage -level 1 -msg "Adding Requested Features"
			if ($xmlSettings.configuration.features.source -ne $null -and $xmlSettings.configuration.features.source -ne "{ONLINE}")
			{
				if (-Not $debug)
				{
					$featuresToAddResult = Add-WindowsFeature $features -source $xmlSettings.configuration.features.source
				} 
			} else {
				if (-Not $debug)
				{
					$featuresToAddResult = Add-WindowsFeature $features
				} 
			}
		
			if ($featuresToAddResult -ne $null) {
				$featuresToAddResult | ft
				
				foreach ($f in $featuresToAddResult) {
					if ($f.Success -ne $true) {
						Write-Warning "Failed to install" $f
						
						return $false
					}
				}
				
				return $true
			} else {
				Write-LogMessage -level 1 -msg "Unable to validate features installed correctly" -Foregroundcolor Red
			}
		}
	}
	catch {
		Write-LogMessage -level 0 -msg $_.Exception.Message -Foregroundcolor Red
	}
	
	return $false
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-ConfigureDNS
# Description:
#	Handles installing and configuring DNS
#-------------------------------------------------------------------------------------------------------------------
function Execute-ConfigureDNS {
	param([xml] $xmlSettings)

	if ($xmlSettings.configuration.dns -ne $null) { 
		Add-DNSEntries -XmlData $xmlSettings
	}

	if ($xmlSettings.configuration.hostFile -ne $null) {
		Write-LogMessage -level 1 -msg "Setting Hostfile"

		if (-not $debug) {
			$xmlSettings.configuration.hostFile.entry | % { 
				$addr = $_.address
				if ($addr -eq "{IP ADDRESS}") { $addr = "127.0.0.1" }
				
				Set-HostsEntry -IPAddress $addr -Hostname $_.hostName 
			}
		}
	}

	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Accounts
#-------------------------------------------------------------------------------------------------------------------
function Execute-CreateAccounts {
	param([xml] $xmlSettings)

	#Import-Module ServerManager
	if ($xmlSettings.configuration.domain -eq $null) { return $true}

	Add-ADObjects -XmlData $xmlSettings
}


#-------------------------------------------------------------------------------------------------------------------
# Applications
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InstallChocolatey
# Description:
#	Installs Chocolatey
#-------------------------------------------------------------------------------------------------------------------
function Execute-InstallChocolatey {
	param([xml] $xmlSettings)

	Write-LogMessage -level 1 -msg "Installing Chocolatey"
	if (($xmlSettings.configuration.chocolatey -eq $null) -or ($([int]$xmlSettings.configuration.chocolatey.enabled) -eq 0)) {
		Write-LogMessage -level 1 -msg "`tNot enabled. Skipping installation."
		
		return $false
	}
	
	if (-Not (Get-Command "cinst" -errorAction SilentlyContinue)) {
		if (-Not $debug) {
			iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
			Write-LogMessage -level 1 -msg "Updating Path"
			$env:Path = $env:Path + "$env:SystemDrive\chocolatey\bin"
			[Environment]::SetEnvironmentVariable( "Path", $env:Path, [System.EnvironmentVariableTarget]::Machine )
		}
	} else {
		Write-LogMessage -level 1 -msg "`tAlready installed. Skipping installation..."
	}
	
	foreach ($package in $xmlSettings.configuration.chocolatey.package) {
		Execute-InstallChocoPackage $package, $($xmlSettings.configuration.applications.baseFolder)
	}
	
	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InstallChocoPackage
# Description:
#	Handles installing any/all Chocolatey Packages that are requested with in the configuration file. 
#-------------------------------------------------------------------------------------------------------------------
function Execute-InstallChocoPackage {
	param($package, [string] $baseFolder)

	Write-LogMessage -level 1 -msg "`tInstalling Package: $($package.name)"
	if ($package.source -ne $null) { Write-LogMessage -level 1 -msg "`t`tSource: $($package.source)" }
		
	if ($package.installCheck -ne $null) {
		$package.installCheck | % {
			$installCheckResult = Execute-InstallCheck -installCheck $_ -baseFolder $baseFolder
			if ($installCheckResult) {
				Write-LogMessage -level 1 -msg "`t`tAlready installed. Skipping installation..."
		
				return $true
			}
		}
	}
		
	if (-Not $debug) {
		if ($package.source -ne $null -and $package.source -ne "webpi") {
			cinst $($package.name) -source $($package.source)
		} elseif ($package.source -ne $null -and $package.source -eq "webpi") {
			cinst webpi $($package.name)
		} else {
			cinst $($package.name)
		}
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InstallWebPiPackage
# Description:
#	Handles installing any/all Web Platform Packages that are requested with in the configuration file. 
#-------------------------------------------------------------------------------------------------------------------
function Execute-InstallWebPiPackage {
	param($package, [string] $baseFolder)

	Write-LogMessage -level 1 -msg "`tInstalling WebPi Package: $($package.name)"
	if ($package.source -ne $null) { Write-LogMessage -level 1 -msg "`t`tSource: $($package.source)" }
		
	if ($package.installCheck -ne $null) {
		$package.installCheck | % {
			$installCheckResult = Execute-InstallCheck $_ $baseFolder
			if ($installCheckResult) {
				Write-LogMessage -level 1 -msg "`t`tAlready installed. Skipping installation..."
		
				return $true
			}
		}
	}
		
	$logFile = "{SCRIPT FOLDER}\webpi_" + $($package.name) + ".log"
	$logFile = Replace-TokensInString $logFile $baseFolder

	$path = "C:\Program Files\Microsoft\Web Platform Installer\WebPiCmd.exe" 
	$args = "/Install /Products:{PACKAGENAME} /Log:{LOGFILE} /SuppressReboot /AcceptEula"

	$args = $args -Replace "{PACKAGENAME}", $($package.name)
	$args = $args -Replace "{LOGFILE}", $logFile
	Write-LogMessage -level 1 -msg "Executing: $path $args"

	if (-Not $debug)
	{
		Try {
			$startTime = (Get-Date).ToString()

			$process = Start-Process -FilePath $path -ArgumentList $args -PassThru 

			Show-Progress -process $process.Name -color Blue -interval 5
			$delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
			Write-LogMessage -level 1 -msg "`tInstallation completed in $delta."
			If (-not $?) {
			}

			#Write-LogMessage -level 2 -msg "`tProcess Exist Code: "$process.ExitCode 
		}
		Catch {
			Write-LogMessage -level 0 -msg $_.Exception.Message
		}
	}
		
	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InstallApplications
# Description:
#	Handles installing any/all applications that are requested with in the configuration file. Note: There are special
#		cases for sql, visualstudio, and msoffice. Everything else is treated as a generic installation
#-------------------------------------------------------------------------------------------------------------------
function Execute-InstallApplications {
	param([xml] $xmlSettings)

	foreach ($install in ($xmlSettings.configuration.applications.install | Where { ($_.enabled -eq $null -or $_.enabled -ne "0") } | Sort-Object -Property order)) {
		[bool] $skipInstall = $false
		if ($install.args -eq $null) { # -or ($install.SelectSingleNode("./args") -eq $null)) {
			#Write-Host "Args: $($install.args)"
			$x = $xmlSettings.CreateElement("args");
			$x.SetAttribute("type", "params"); # This is a HACK to get get Powershell to add an actual element instead of an attribute
			$install.AppendChild($x)
		}

		$paramNameValueDelim = " "
		$paramFlagDelim = "/"
	
		switch ($($install.type)) {
			"sql" {
				$paramNameValueDelim = "="

				if ((Test-Path $($install.configFile)) -eq $false) {
					Write-LogMessage -level 0 -msg "Could not find the specfied configuraton file: $($install.configFile)"
					Write-LogMessage -level 0 -msg "Skipping Installation: $($install.name)"
					$skipInstall = true
					continue
				}
			
				$install.args.AppendChild((Create-ArgParameterElement $xmlSettings "ConfigurationFile" "{CONFIGFILE}"))
			}
			"visualstudio" {
				if ((Test-Path $($install.configFile)) -eq $false) {
					Write-LogMessage -level 0 -msg "Could not find the specfied configuraton file: $($install.configFile)"
					Write-LogMessage -level 0 -msg "Skipping Installation: $($install.name)"
					$skipInstall = true
					continue
				}

				if ($install.args.entry -eq $null) {
					$install.args.AppendChild((Create-ArgParameterElement $xmlSettings "adminfile" "{CONFIGFILE}"))
					$install.args.AppendChild((Create-ArgParameterElement $xmlSettings "Passive" ""))
					$install.args.AppendChild((Create-ArgParameterElement $xmlSettings "NoRestart" ""))
				}
			}
			"msoffice" {
				if ((Test-Path $($install.configFile)) -eq $false) {
					Write-LogMessage -level 0 -msg "Could not find the specfied configuraton file: $($install.configFile)"
					Write-LogMessage -level 0 -msg "Skipping Installation: $($install.name)"
					$skipInstall = true
					continue
				}

				if ($install.args.entry -eq $null) {
					$install.args.AppendChild((Create-ArgParameterElement $xmlSettings "config" "{CONFIGFILE}"))
				}
			}
			"ows" {
				if ($install.owaOptions -ne $null) {
				}
			}
			"choco" {
				if ($install.package -eq $null) {
					Write-LogMessage -level 1 -msg "`tSkipping Chocolatey Package as it was not defined"
					$skipInstall = true
				}	
			}
			"wepbi" {
				if ($install.package -eq $null) {
					Write-LogMessage -level 1 -msg "`tSkipping WebPi Package as it was not defined"
					$skipInstall = true
				}	
			}
			"generic" { 
			}
		}

		if ($skipInstall -eq $false) {
			[string]$args = ""
			if ($install.args.entry -ne $null) {
				$args = (($install.args.entry | % { if ($_.value -ne $null -and $_.value.Length -gt 0) { $paramFlagDelim + $_.name + $paramNameValueDelim + "'" + $_.value + "'" } else { $paramFlagDelim + $_.name } }) -join " ")
			} else {
				$args = $([string]$install.args)
			}

			if ($install.pwd -ne $null) {
				$args = $args -replace "{PASSWORD}", $($install.pwd)
			} else {
				$args = $args -replace "{PASSWORD}", "{DEFAULT PASSWORD}"
			}

			if (($($install.type) -eq "choco") -and $install.package -ne $null) {
				Execute-InstallChocoPackage $install.package
			} elseif (($($install.type) -eq "webpi") -and $install.package -ne $null) {
				Execute-InstallWebPiPackage $install.package
			} else {
				if ($args -ne $null -and $args.Length -gt 0) {
					$args = $args -Replace "{DEFAULT PASSWORD}",$($xmlSettings.configuration.defaultPassword)
				}

				if ($install.args.entry -ne $null) {
					$install.RemoveChild($install.args)
				}

				$install.SetAttribute("args", $args)

				Execute-Install $($xmlSettings.configuration.applications.baseFolder) $install
			}
		
			if ((Get-PendingReboot).RebootPending -eq $true) { Write-LogMessage -level 1 -msg "Reboot Required before we can continue"; return $true }
		}
	}
	
	# SharePoint should be installed AFTER everything else
	Execute-AutoSPInstaller $xmlSettings
		
	return $true
}

function Create-ArgParameterElement([xml] $xmlDoc, [string] $name, [string] $value)
{
	$x = $xmlDoc.CreateElement("entry");
	$x.SetAttribute("name", $name);

	if ($value -ne $null -and $value.Length -gt 0) {
		$x.SetAttribute("value", $value);
	}

	return $x
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-AutoSPInstaller
# Description:
#	Executes AutoSPInstaller correctly
#-------------------------------------------------------------------------------------------------------------------
function Execute-AutoSPInstaller {
	param([xml] $xmlSettings)

	$applications = $xmlSettings.configuration.applications
	$appSettings = $applications.autoSPInstaller

	if ($applications -eq $null -or $appSettings -eq $null -or ($appSetings.enabled -ne $null -and $([int]$appSettings.enabled) -eq 0)) { return $true }

	Write-LogMessage -level 1 -msg "Installing SharePoint via AutoSPInstaller"

	if ($appSettings.folder -eq $null -and $appSettings.iso -eq $null) {
		Write-Error "Please specify either a folder path or and ISO image for your Microsoft SharePoint Installation (via AutoSPInstaller)"
		
		return $false
	}
	
	if ($applications.baseFolder -ne $null) { $applications.SetAttribute("baseFolder", (Replace-TokensInString $($applications.baseFolder))) }
	if ($appSettings.folder -ne $null) { $appSettings.SetAttribute("folder", (Replace-TokensInString $($appSettings.folder) $($applications.baseFolder)))  }
	if ($appSettings.iso -ne $null) { $appSettings.SetAttribute("iso", (Replace-TokensInString $($appSettings.iso) $($applications.baseFolder) $($appSettings.folder))) }
	if ($appSettings.args -ne $null) { $appSettings.SetAttribute("args", (Replace-TokensInString $($appSettings.args) $($applications.baseFolder) $($appSettings.folder))) }
	if ($appSettings.configFile -ne $null) { $appSettings.SetAttribute("configFile", (Replace-TokensInString $($appSettings.configFile) $($applications.baseFolder) $($appSettings.folder))) }
	
	$mount = $null
	if ($appSettings.iso -ne $null) {
		$mount = Mount-DiskImage -ImagePath $($appSettings.iso) -PassThru
		$mountPath = ($mount | Get-Volume).DriveLetter + ":"
		$appSettings.folder = $mountPath
	}
	
	$networkDrive = $null
	if ($appSettings.folder -like "\\*")
	{
		Write-LogMessage -level 2 -msg "Network Path Detected. Mounting to local drive letter Q"
		$networkDrive = New-PSDrive -Name Q -Root $($appSettings.folder) -PSProvider FileSystem
		
		$appSettings.folder = $networkDrive.Name + ":"
	}

	Write-LogMessage -level 2 -msg "Source: $($appSettings.folder)"
	$setupPath = "$($appSettings.folder)"
	$setupCommand = "$setupPath\AutoSPInstaller\AutoSPInstallerLaunch.bat"
	if (!(Test-Path $setupCommand)) {
		Write-LogMessage -level 0 -msg "Unable to locate $setupCommand"
		
		return $false
	}
		
	if (($([int]$appSettings.installRoles) -ne $null) -and ($([int]$appSettings.installRoles) -eq 1))
	{
		Write-LogMessage -level 2 -msg "Installing PreReq Roles and Features"
		$cmd = "$($xmlSettings.configuration.workingDirectory)\Tools\Install-SP2013RolesFeatures.ps1"
		Write-LogMessage -level 3 -msg "Launching: $cmd"
		& $cmd -prompt $false
	}

	if (($([int]$appSettings.downloadPreReqs) -ne $null) -and ($([int]$appSettings.downloadPreReqs) -eq 1))
	{
		Write-LogMessage -level 2 -msg "Downloading SharePoint PreReq Files"
		$cmd = "$($xmlSettings.configuration.workingDirectory)\Tools\Download-SP2013PreReqFiles.ps1"
		$cmdArgs = "$($xmlSettings.configuration.workingDirectory)\PreReqs"
		Write-LogMessage -level 3 -msg "Launching: $cmd $cmdArgs"
		& $cmd -SharePoint2013Path $cmdArgs

		#$osDetails = gwmi win32_operatingsystem
		#if ($($osDetails.Version) -ge 6.2) {
		#	Write-LogMessage -level 2 -msg "Removing Unnecessary Files"
		#	if (Test-Path "$($xmlSettings.configuration.workingDirectory)\PreReqs\Windows6.1-KB974405-x64.msu") {
		#		Remove-Item "$($xmlSettings.configuration.workingDirectory)\PreReqs\Windows6.1-KB974405-x64.msu"
		#	}
		#}
	}

	if (($([int]$appSettings.installPreReqs) -ne $null) -and ($([int]$appSettings.installPreReqs) -eq 1))
	{
		Write-LogMessage -level 2 -msg "Installing PreReqs"
		$cmd = "$($xmlSettings.configuration.workingDirectory)\Tools\Install-SP2013PreReqFiles.ps1"
		$cmdArgs = "-SharePoint2013Path ""$setupPath"" -PreReqPath ""$($xmlSettings.configuration.workingDirectory)\PreReqs"""
		Write-LogMessage -level 3 -msg "Launching: $cmd $cmdArgs"
		& $cmd $cmdArgs
	}

	Write-LogMessage -level 2 -msg "Starting PRE Installations"
	$installsOther = $appSettings.install | Where { $_.mode -eq "PRE" } | Sort-Object -Property order | ForEach-Object {
		Execute-Install $($applications.baseFolder) $_
	}
	
	Write-LogMessage -level 2 -msg "Checking for Pending Reboot"
	if ((Get-PendingReboot).RebootPending -eq $true) { return $true }
		
	Write-LogMessage -level 2 -msg "Starting AutoSPInstaller"
	if (-Not $debug)
	{
		$cmdArgs = "$($appSettings.configFile)"
		Write-LogMessage -level 3 -msg "Launching: $setupCommand $cmdArgs"
		& $setupCommand $cmdArgs
	}

	Write-LogMessage -level 2 -msg "Starting POST Installations"
	$installsOther = $appSettings.install | Where { $_.mode -eq "POST" } | Sort-Object -Property order | ForEach-Object {
		Execute-Install $($applications.baseFolder) $_
	}
		
	if ($networkDrive -ne $null) {
		Remove-PSDrive $networkDrive.Name
	}
	
	if ($mount -ne $null) {
		Dismount-DiskImage -ImagePath $mount.ImagePath
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-InstallCheck
# Description:
#	Handles the check to see if an application is already installed 
#   Note: $true indicates that the install check succeeded and that the install should be skipped
#-------------------------------------------------------------------------------------------------------------------
function Execute-InstallCheck {
	param($installCheck, [string] $baseFolder)
	
	Write-LogMessage -level 2 -msg "`t`tChecking installation. " -noNewLine $true
	if ($installCheck -eq $null) { return $false}

	#Write-Verbose "installCheck.folder: $($installCheck.folder)"	
	if ($installCheck.type -eq $null) { $installCheck.SetAttribute("type","file") }
	if ($installCheck.match -eq $null) { $installCheck.SetAttribute("match","eq") }
	#if ($installCheck.versionMajor -eq $null) { $installCheck.SetAttribute("versionMajor","0") }
	#if ($installCheck.versionMinor -eq $null) { $installCheck.SetAttribute("versionMinor","0") }
	#if ($installCheck.versionBuild -eq $null) { $installCheck.SetAttribute("versionBuild","0") }

	if ($installCheck.folder -ne $null) { 
		$installCheck.SetAttribute("folder", (Replace-TokensInString $($installCheck.folder) $baseFolder)) 
	} else {
		$installCheck.SetAttribute("folder", "") 
	}
		
	switch ($($installCheck.type)) {
		"file" {
			if ($installCheck.folder -eq $null -or ($($installCheck.folder).length -eq 0) -or $installCheck.file -eq $null -or ($($installCheck.file).length -eq 0)) { 
				Write-LogMessage -level 0 -msg "Install Check requires both folder and file to be specified." 
					
				# Return TRUE here to "fake" that it is already installed
				return $true
			}
			
			$installCheckPath = Join-Path  -Path $($installCheck.folder) -ChildPath $($installCheck.file)
			Write-LogMessage -level 2 -msg "Checking for existance of file. " 
			if (Test-Path $installCheckPath) {
				return $true
			}

			if ($installCheck.version -ne $null) {
				Write-LogMessage -level 2 -msg "Checking version of file. " 
				$item = Get-Item $installCheckPath -ErrorAction SilentlyContinue
				if ($item -ne $null)
				{
					[Version] $itemVersion = $item.Version

					$versionCompareResult = Compare-Version $itemVersion $($installCheck.versionMajor) $($installCheck.versionMinor) $($installCheck.versionBuild)

					Write-Verbose "Version Compare returned $versionCompareResult"
					if ($versionCompareResult -eq $($installCheck.match)) { return $true }
				} else {
					Write-LogMessage -level 3 -msg "`tNot Found"
				}
			}
		}
		"registry" {
		}
		"poscommand" {
			Write-LogMessage -level 2 -msg "Checking Existance of PowerShell Command $($installCheck.commandName)."
			return ((Get-Command $($installCheck.commandName) -ErrorAction SilentlyContinue) -ne $null)
		}
		"posversion" {
			Write-LogMessage -level 2 -msg "Checking PowerShell Version."
			$psVer = $PSVersionTable.PSVersion
			$versionCompareResult = Compare-Version $psVer $($installCheck.versionMajor) $($installCheck.versionMinor) $($installCheck.versionBuild)

			Write-Verbose "Version Compare returned $versionCompareResult"
			if ($versionCompareResult -eq $($installCheck.match)) { return $true }
		}
		"osversion" {
			Write-LogMessage -level 2 -msg "Checking OS Version."
			$osDetails = [Environment]::OSVersion
			[Version] $osVer = $osDetails.Version
			if ($installCheck.platform -ne $null -and $($installCheck.platform) -ne $osDetails.Platform) { return $true }
			$versionCompareResult = Compare-Version -version $osVer -versionMajor $installCheck.versionMajor -versionMinor $installCheck.versionMinor -versionBuild $installCheck.versionBuild

			Write-Verbose "Version Compare returned $versionCompareResult"
			if ($versionCompareResult -eq $($installCheck.match)) { return $true }
		}
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Execute-Install
# Description:
#	Executes the actual application install
#-------------------------------------------------------------------------------------------------------------------
function Execute-Install {
	param([string] $baseFolder, $install)
	
	Write-LogMessage -level 1 -msg "Installing: $($install.name)"
	if ($install.command -eq $null) {
		Write-LogMessage -level 1 -msg "`tSkipping due to no command being specified"
		
		return $true
	}
	
	if ($install.enabled -ne $null -and $([int]$install.enabled) -eq 0) {
		Write-LogMessage -level 1 -msg "`tDisabled. Skipping..."
		
		return $true
	}
	
	if ($install.folder -eq $null -and $install.iso -eq $null) {
		Write-Error "Please specify either a folder path or and ISO image for your installation"
		
		return $false
	}
		
	#Write-Verbose "BaseFolder: $baseFolder"
	if ($baseFolder -ne $null) { $baseFolder = Replace-TokensInString $baseFolder }
	#Write-Verbose "install.iso: $($install.iso)"
	if ($install.iso -ne $null) { $install.SetAttribute("iso", (Replace-TokensInString $($install.iso) $baseFolder $($install.folder))) }
	#Write-Verbose "install.folder: $($install.folder)"
	if ($install.folder -ne $null) { $install.SetAttribute("folder", (Replace-TokensInString $($install.folder) $baseFolder)) }
	#Write-Verbose "install.configFile: $($install.configFile)"
	if ($install.configFile -ne $null) { $install.SetAttribute("configFile", (Replace-TokensInString $($install.configFile) $baseFolder $($install.folder))) }
	#Write-Verbose "install.args: $($install.args)"
	if ($install.args -ne $null) { 
		$install.SetAttribute("args", (Replace-TokensInString $($install.args) $baseFolder $($install.folder)))
		$install.SetAttribute("args", ($($install.args) -Replace "{CONFIGFILE}",$($install.configFile)))
	}
		
	$install.installCheck | % {
		$installCheckResult = Execute-InstallCheck $_ $baseFolder
		if ($installCheckResult) {
			Write-LogMessage -level 1 -msg "`t`tAlready installed. Skipping installation..."
		
			return $true
		}
	}
			
	$mount = $null
	if ($install.iso -ne $null) {
		Write-LogMessage -level 1 -msg "ISO File Detected. Mounting Image now"
		Write-LogMessage -level 2 -msg "ISO File: $($install.iso)"
		$mount = Mount-DiskImage -ImagePath $($install.iso) -PassThru
		$mountPath = ($mount | Get-Volume).DriveLetter + ":"
		Write-LogMessage -level 1 -msg "Mounted ISO To: $mountPath"
		$install.SetAttribute("folder", $mountPath) 
	}
		
	$networkDrive = $null
	if ($install.folder -like "\\*")
	{
		Write-LogMessage -level 1 -msg "Network Path Detected. Mounting to local drive letter Q"
		$networkDrive = New-PSDrive -Name Q -Root $($install.folder) -PSProvider FileSystem

		$install.SetAttribute("folder", $networkDrive.Name + ":") 
	}
		
	$skipInstall = $false
	$path = Join-Path -Path $($install.folder) -ChildPath $($install.command)
	if (!(Test-Path $path)) {
		Write-LogMessage -level 0 -msg "Unable to find application: $path" 
		
		$skipInstall = $true
	}

	if (-Not $skipInstall) {	
		$install.SetAttribute("args", ($($install.args) -Replace "'", """"))
		Write-LogMessage -level 1 -msg "Executing: $path $($install.args)"
		if (-Not $debug)
		{
			Try {
				$stdOutLogFile = "{SCRIPT FOLDER}\" + $($install.name) + ".log"
				$stdOutLogFile = Replace-TokensInString $stdOutLogFile $baseFolder
				Write-LogMessage -level 1 -msg "Log File: $stdOutLogFile"
			
				$startTime = (Get-Date).ToString()

				if ($path -like "*.msi") {
					$args = $([string]$install.args)
					if (-Not ($args -like "*/log")) { $args = $args + " /log ""$stdOutLogFile""" }
					#Write-LogMessage -level 1 -msg "$path -> $args"
					$process = Start-Process -FilePath $path -ArgumentList $args -PassThru
				} else {
					$process = Start-Process -FilePath $path -ArgumentList $($install.args) -PassThru -RedirectStandardOutput $stdOutLogFile
					Write-LogMessage -level 1 -msg $stdOut
				}

				Show-Progress -process $process.Name -color Blue -interval 5
				$delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
				Write-LogMessage -level 1 -msg "`tInstallation completed in $delta."
				If (-not $?) {
				}

				#Write-LogMessage -level 2 -msg "`tProcess Exist Code: "$process.ExitCode 
				Write-LogMessage -level 1 -msg "-----------------------------------------------------------------------------------------------"
			}
			Catch {
				Write-LogMessage -level 0 -msg $_.Exception.Message
			}
		}
	
	}

	#if (!(Test-Path $path)) {
	#	Write-LogMessage -level 0 -msg "Install was not successful" 
		
	#	return $false
	#}
	
	if ($install.taskbarLink -ne $null) {
		foreach ($tl in $install.taskbarLink) {
			Add-PinToTaskbar $($tl.name) $($tl.folder) $($tl.file)
		}
	}
	
	if ($networkDrive -ne $null) {
		Write-LogMessage -level 1 -msg "Removing Network Drive Map"
		Remove-PSDrive $networkDrive.Name
	}
	
	if ($mount -ne $null) {
		Write-LogMessage -level 1 -msg "Dismounting ISO Image"
		Dismount-DiskImage -ImagePath $mount.ImagePath
	}
	
	if ($skipInstall) { return $false }

	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Utilities
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function: Compare-Version
# Description:
#	Compares the major, minor, and build numbers with a version object and returns "gt", "lt", or "eq"
#-------------------------------------------------------------------------------------------------------------------
function Compare-Version {
	param([Version] $version, [int] $versionMajor, [int] $versionMinor, [int] $versionBuild)

	if ($version -eq $null) { return "ne" }

	Write-Verbose "Comparing $version to [Major: $versionMajor] [Minor: $versionMinor] [Build: $versionBuild]"

	if ($version.Major -gt $versionMajor) { return "gt" }
	if ($version.Major -eq $versionMajor) {
		if ($version.Minor -gt $versionMinor) { return "gt" }
		if ($version.Minor -eq $versionMinor) {
			if ($version.Build -gt $versionBuild) { return "gt" }
			if ($version.Build -lt $versionBuild) { return "lt" }

			return "eq"
		} else {
			return "lt"
		} 
	} else {
		return "lt"
	}
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Add-PinToTaskbar
# Description:
#	Executes the Shell verb "Pin to Taskbar" for the specified application
#-------------------------------------------------------------------------------------------------------------------
function Add-PinToTaskbar {
	param([string] $appName, [string] $path, [string] $exeName)
	
	Write-LogMessage -level 1 -msg "Pinning $appName to the Taskbar."

	$p = Replace-TokensInString $path

	if (!(Test-Path $p)) {
		Write-LogMessage -level 0 -msg "Unable to find $appName ($p)" 
		
		return $false
	}
	
	$shell = new-object -com "Shell.Application" 
	$devenvFolder = $shell.Namespace($p) 
	$devenvItem = $devenvFolder.Parsename($exeName)
	$verb = $devenvItem.Verbs() | ? {$_.Name -eq "Pin to Tas&kbar"}

	if (-Not $debug)
	{
		if ($verb) 
		{
			$verb.DoIt()
		}
	}
	
	return $true
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Test-ADUser
# Description:
#	Does a quick check if an user exists in AD or not (returns a simple true/false)
#-------------------------------------------------------------------------------------------------------------------
function Test-ADUser {
	param([string] $upn)

	Try {
		Write-LogMessage -level 1 -msg "Checking for existence of user $upn" 
		if ((Get-ADUser $upn -ErrorAction Continue) -ne $null) {
		#if ((Get-ADUser $upn -ErrorAction SilentlyContinue) -eq $null) {
			Write-LogMessage -level 2 -msg "`tUser Found"

			return $true
		}
	}
	Catch {
	}
	
	return $false
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Replace-TokensInString
# Description:
#	Replaces all known tokens in the specified string and returns the result
#-------------------------------------------------------------------------------------------------------------------
function Replace-TokensInString {
	param([string] $str, [string] $baseFolder = $null, [string] $appFolder = $null)

	#Write-LogMessage -level 1 -msg "Before: $str, BaseFolder: $baseFolder, AppFolder: $appFolder"
	
	if ($str -match "{SCRIPT FOLDER}") {
		$str = $str -replace "{SCRIPT FOLDER}", $($xmlSettings.configuration.workingDirectory)
	}
	if ($str -match "{BASE FOLDER}") {
		$str = $str -replace "{BASE FOLDER}", $baseFolder
	}
	if ($str -match "{APPLICATION FOLDER}") {
		$str = $str -replace "{APPLICATION FOLDER}", $appFolder
	}
	if ($str -match "{PROGRAMFILESx86}") {
		$str = $str -replace "{PROGRAMFILESx86}", ${env:ProgramFiles(x86)}
	}
	if ($str -match "{PROGRAMFILES}") {
		$str = $str -replace "{PROGRAMFILES}", ${env:ProgramFiles}
	}
	if ($str -match "{SYSTEMDRIVE}") {
		$str = $str -replace "{SYSTEMDRIVE}", ${env:SystemDrive}
	}

	#Write-LogMessage -level 1 -msg "`tAfter: $str"
	
	return $str
}

#-------------------------------------------------------------------------------------------------------------------
# Function: Write-LogMessage
# Description:
#	Writes a log message and color codes it based on the level (0: error, 1: general, 2: info, 3: highlight
#-------------------------------------------------------------------------------------------------------------------
function Write-LogMessage {
	param([int] $level = 1, [bool] $noNewLine = $false, [string] $msg)

	switch ($level) {
		0 { $color = "Red" }
		1 { $color = "White" }
		2 { $color = "Yellow" }
		3 { $color = "Green" }
	}

	if ($noNewLine) {
		Write-Host $msg -ForegroundColor $color -NoNewline
	} else {
		Write-Host $msg -ForegroundColor $color 
	}
}

# ====================================================================================
# Func: Show-Progress
# Desc: Shows a row of dots to let us know that $process is still running
# From: Brian Lalancette, 2012
# ====================================================================================
Function Show-Progress ($process, $color, $interval)
{
	While (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $process -or $_.Path -eq $process})
	{
		Write-Host -ForegroundColor $color "." -NoNewline
		Start-Sleep $interval
	}
	Write-Host -ForegroundColor $color "Done."
}
