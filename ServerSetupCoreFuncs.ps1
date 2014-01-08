function Execute-ConfigureLocalComputer {
	param([xml] $xmlSettings)
	
	Write-Host "Checking Execution Policy"
	$executionPolicy = Get-ExecutionPolicy
	if ($executionPolicy -ne "ByPass" -and $executionPolicy -ne "Unrestricted") {
		Write-Host "Execution Policy should be set to ByPass or Unrestricted. Setting it to ByPass now." -Foregroundcolor Yellow
		Set-ExecutionPolicy ByPass -Force
	}
	
	$pwd = $($xmlSettings.configuration.defaultPassword)
	Write-Verbose "Default Password: $pwd"
	$defaultPasswordSecure = ConvertTo-SecureString -String $pwd -AsPlainText -Force

	Write-Host "Settings Administrator and Current User Passwords to: $($xmlSettings.configuration.defaultPassword)"
	if (-Not $debug)
	{
		Set-LocalUserPassword -user Administrator -password $pwd
		Set-LocalUserPassword -user $env:username -password $pwd

		if ((Get-Command "Set-ADAccountPassword" -errorAction SilentlyContinue) -ne $null)
		{
			Set-ADAccountPassword -Identity $env:username -Reset -NewPassword $defaultPasswordSecure
		}	
	}
		
	if ($xmlSettings.configuration.computer.autoLogon -eq $null) { $xmlSettings.configuration.computer.autoLogon = 10 }

	Write-Host "Enabling Auto login"
	if (-Not $debug)
	{
		Enable-Autologon -password $pwd -autoLogonCount $([int]$xmlSettings.configuration.computer.autoLogon)
	}
	
	if ([TimeZoneInfo]::Local.StandardName -ne $($xmlSettings.configuration.computer.timeZone))
	{
		Write-Host "Settings TimeZone to $($xmlSettings.configuration.computer.timeZone)"
		if (-Not $debug)
		{
			Set-TimeZone $($xmlSettings.configuration.computer.timeZone)
		}
	}
	
	Write-Host "Setting up Remote Desktop"
	if (-Not $debug)
	{
		Write-Verbose "Setting Remote Desktop Connection: $([int]$xmlSettings.configuration.computer.remoteDesktop)"
		Set-RemoteDesktopConnections -Enabled $([int]$xmlSettings.configuration.computer.remoteDesktop)
	}
	
	Write-Host "Settings up Internet Explorer Enhanced Security"
	if (-Not $debug)
	{
		Write-Verbose "Setting ESC for Admin: $([int]$xmlSettings.configuration.ieSecurity.admin)"
		Write-Verbose "Setting ESC for Users: $([int]$xmlSettings.configuration.ieSecurity.user)"
		Set-InternetExplorerESC -Admin $([int]$xmlSettings.configuration.ieSecurity.admin) -User $([int]$xmlSettings.configuration.ieSecurity.user)
	}
	
	Write-Host "Settings Auto login for trusted web sites zone"
	if (-Not $debug)
	{
		Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' -Name "1A00" | Set-ItemProperty -Name "1A00" -Value "0"

		$zoneMapPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
		if(!(Test-Path $zoneMapPath))
		{
			New-Item -Path $zoneMapPath | Out-Null
		}
		Set-ItemProperty -LiteralPath $zoneMapPath -Name "UncAsIntranet" -Value 1 -type DWORD
		
		$localhostKeyPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\localhost"
		if(!(Test-Path $localhostKeyPath))
		{
			New-Item -Path $localhostKeyPath | Out-Null
		}
		Set-ItemProperty -LiteralPath $localhostKeyPath -Name "http" -Value 1 -type DWORD

		$domainKeyPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$env:COMPUTERNAME"
		if(!(Test-Path $domainKeyPath))
		{
			New-Item -Path $domainKeyPath | Out-Null
		}
		Set-ItemProperty -LiteralPath $domainKeyPath -Name "http" -Value 1 -type DWORD
	}
	
	switch ($([int]$xmlSettings.configuration.computer.updateHelp)) {
		0 { 
		}
		1 { 
			Write-Host "Updating Powershell Help"
			Update-Help 
		}
		2 { 
			Write-Host "Updating Powershell Help (Force)"
			Update-Help -Force 
		}
	}
	
	return $true
}

function Execute-RenameComputer {
	param([xml] $xmlSettings)
	
	Write-Host "Verifying computer name is correct."
	if ($env:ComputerName -ne $($xmlSettings.configuration.computer.name)) {
		$pwd = $($xmlSettings.configuration.defaultPassword)
		$defaultPasswordSecure = ConvertTo-SecureString -String $pwd -AsPlainText -Force
	
		$creds = New-Object System.Management.Automation.PSCredential ($env:username, $defaultPasswordSecure)
		
		if (-Not $debug) {
			Rename-Computer -NewName $($xmlSettings.configuration.computer.name) -LocalCredential $creds -Force
		}
	#$computer = Get-WmiObject Win32_ComputerSystem
	#if ($computer.Name -ne $($xmlSettings.configuration.computer.name)) {
	#	Write-Host "Computer is being renamed to $($xmlSettings.configuration.computer.name)"
	#	if (-Not $debug)
	#	{
	#		$renameResult = $computer.Rename($($xmlSettings.configuration.computer.name))
	#	}
	} else {
		Write-Host "Computer has already been renamed. Skipping..."
	}

	return $true
}

function Execute-ConfigureWindowsUpdate {
	param([xml] $xmlSettings)

	Write-Host "Settings Windows Update to automatically download but not install updates"
	if (-Not $debug)
	{
		Set-WUAutoUpdateSettings -Enable -level 3 -recommended -featured
	}
	
	return $true
}

function Execute-WindowsUpdate {
	param([xml] $xmlSettings)

	Write-Host "Retrieving a list of Windows Updates that need to be installed. Please note that this may take several minutes."
	$wuList = Get-WUList

	if ($wuList -ne $null -and $wuList.Length -gt 0) {
		Write-Host "List of updates to install..."
		Write-Host "Installing Windows Updates.  Please note that this may take several minutes or more."
		if (-Not $debug)
		{	
			Get-WUInstall -AcceptAll -IgnoreReboot -AutoSelectOnly
		}
	} else {
		Write-Host "No updates found at this time..."
	}
	
	return $true
}

function Validate-NetworkConfiguration {
	param([xml] $xmlSettings)

	$networkAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE
	if (($networkAdapter.DHCPEnabled -eq $true) -and ([int]$xmlSettings.configuration.computer.dhcpAllowed -eq 0)) {
		Write-Warning "Network card is set to use DHCP -- Ideally it should be set to a static IP address"	
		
		return $false
	}
	
	return $true
}

function Execute-InstallWindowsFeatures {
	param([xml] $xmlSettings)
	
	#Import-Module ServerManager
	
	$featuresToAdd = ($xmlSettings.configuration.features.feature -join ",") -split ","
	
	Write-Host "Requested Features: $featuresToAdd"
	
	Try {
		$features = Get-WindowsFeature $featuresToAdd | Where-Object { $_.Installed -eq $false }
		
		if (($features -ne $null) -and ($features.Count -gt 0))
		{
			Write-Host "Adding Requested Features"
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
				Write-Host "Unable to validate features installed correctly" -Foregroundcolor Red
			}
		}
	}
	catch {
		Write-Host $_.Exception.Message -Foregroundcolor Red
	}
	
	return $false
}

function Execute-ActiveDirectoryAccountCreation {
	if ($xmlSettings.configuration.domain.ou -ne $null) {
		$tmp = $xmlSettings.configuration.domain.name -split "\.",2,"Singleline,IgnoreCase"
		$dc = "DC=" + ($tmp -join ",DC=")

		$result = Execute-ActiveDirectoryProcessOU $xmlSettings.configuration.domain.name $dc $xmlSettings.configuration.domain.ou
	}
	
	return $result
}

function Execute-ActiveDirectoryProcessOU {
	param([string] $domain, [string] $path, $ouSettings)

	$result = $true
	
	Write-Verbose "Checking for existence of group: $($ouSettings.name)"
	if (-Not (Test-ADOrganizationUnit -groupName $ouSettings.name)) {
		Write-Host "Creating OU ($path): $($ouSettings.name)"
		if (-Not $debug)
		{
			New-ADOrganizationalUnit -Path $path -Name $ouSettings.name
		}
	}
	
	$pwd = $($xmlSettings.configuration.defaultPassword)
	Write-Verbose "Default Password: $pwd"
	$defaultPasswordSecure = ConvertTo-SecureString -String $pwd -AsPlainText -Force
	$currentOU = "OU=" + $ouSettings.name + ",$path"
	
	if ($ouSettings.account -ne $null) {
		Write-Verbose "Processing Accounts"
		foreach ($account in $ouSettings.account) {
			$pwd = $($account.password)
			Write-Verbose "Account Password: $pwd"
			if (($pwd -ne $null) -and ($pwd -ne "{DEFAULT PASSWORD}")) { 
				$password = ConvertTo-SecureString -String $pwd -AsPlainText -Force 
			} else { 
				$password = $defaultPasswordSecure 
			}
			
			Write-Host "Checking for user: $($account.name)"
			if ((Test-ADUser $($account.name)) -eq $false)
			{
				Write-Host "Creating User ($currentOU): $($account.name)"
				if (-Not $debug)
				{
					New-ADUser -Path $currentOU -AccountPassword $password -Enabled $True -Name $account.name -SamAccountName $account.name -UserPrincipalName "$($account.name)@$domain" -Description $account.description	
				}
			}
		}
	}
	
	if ($ouSettings.ou -ne $null) {		
		foreach ($ou in $ouSettings.ou) {
			$result = Execute-ActiveDirectoryProcessOU $domain $currentOU $ou
		}
	}
	
	return $result
}

function Execute-ActiveDirectoryConfiguration {
	param([xml] $xmlSettings)
	
	if ($xmlSettings.configuration.domain.create -eq 1)
	{
		$result = Execute-ActiveDirectoryInstallation $xmlSettings 
		return $result
	}
	
	return $false
}

function Execute-ActiveDirectoryInstallation {
	param([xml] $xmlSettings)
	
	$pwd = $($xmlSettings.configuration.defaultPassword)
	Write-Verbose "Default Password: $pwd"
	$safeModePassword = ConvertTo-SecureString -String $pwd -AsPlainText -Force

	Write-Host "Checking to see if AD is already installed"
	$adFeature = Get-WindowsFeature AD-Domain-Services, RSAT-ADDS
	if ($adFeature.Installed -eq $False) {
		Write-Host "Installing AD Domain Services"
		if (-Not $debug)
		{
			$adFeatureInstall = Install-WindowsFeature $adFeature
			if ($adFeatureInstall.Success -ne $True) {
				Write-Error "Failed to install AD Features"

				return $false
			}
		}
	}

	Write-Host "Checking to see if AD needs to be configured"
	$adFeature = Get-WindowsFeature AD-Domain-Services 
	if ($adFeature.Installed -eq $True -and $adFeature.PostConfigurationNeeded) {
		Write-Host "Running Pre-checks for AD Forest Installation"
		$testADForestInstallation = Test-ADDSForestInstallation -DomainName $([string]$xmlSettings.configuration.domain.name) -SafeModeAdministratorPassword $safeModePassword
		if ($testADForestInstallation.Status -ne "Success")
		{
			Write-Error "AD Forest Installation Test Failed"
			$testADForestInstallation | fl
			
			return $false
		}

		Write-Host "Loading ADS Deployment Modules"
		Import-Module ADDSDeployment -Force

		Write-Host "Installing AD"
		$installADForestResult = Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode $([string]$xmlSettings.configuration.domain.mode) -DomainName $([string]$xmlSettings.configuration.domain.name) -DomainNetbiosName $([string]$xmlSettings.configuration.domain.netBIOS) -ForestMode $([string]$xmlSettings.configuration.domain.mode) -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword $safeModePassword
		
		$installADForestResult | fl
		
		sleep 10
		
		return $true
	}
	
	return $false
}

function Execute-ConfigureDNS {
	param([xml] $xmlSettings)

	[string] $zoneName = $xmlSettings.configuration.dns.zone
	[string] $computerName = $($xmlSettings.configuration.computer.name)
	[string] $domanName = $($xmlSettings.domain.name)
	#Write-Host $computerName
	
	Write-Host "Configuring DNS Records"
	foreach ($record in $xmlSettings.configuration.dns.record) {
			if ($record.name -eq "{COMPUTER NAME}") { $record.name = $computerName }
			
			switch ($record.type) {
				"a" {
					if ($record.address -eq "{IP ADDRESS}") { $record.address = "127.0.0.1" }
					
					#Write-Host "Checking for existence of $($record.name)"
					$result = Get-DnsServerResourceRecord -ErrorAction SilentlyContinue -ZoneName $zoneName -RRType "A" -Name $($record.name)
					
					Write-Host $result
					if ($result -eq $null) {
						Write-Host "`tCreating: $($record.Name)"
						if (-Not $debug)
						{
							Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $($record.name) -IPv4Address $($record.address)
						}
					}
				}
				"cname" {
					Write-Host "Checking for existence of $($record.alias)"
					$result = Get-DnsServerResourceRecord -ErrorAction SilentlyContinue -ZoneName $zoneName -RRType "CName" -Name $($record.alias)

					#Write-Host $result
					if ($result -eq $null) {
						Write-Host "`tCreating: $($record.alias)"
						if (-Not $debug)
						{
							Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $($record.alias) -HostNameAlias "$($record.name)@$domainName"
						}
					}
				}
			}
	}
	
	return $true
}

function Execute-InstallChocolatey {
	param([xml] $xmlSettings)

	Write-Host "Installing Chocolatey"
	if (($xmlSettings.configuration.chocolatey -eq $null) -or ($([int]$xmlSettings.configuration.chocolatey.enabled) -eq 0)) {
		Write-Host "`tNot enabled. Skipping installation."
		
		return $false
	}
	
	if (-Not (Get-Command "cinst" -errorAction SilentlyContinue)) {
		if (-Not $debug) {
			iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
			Write-Host "Updating Path"
			$env:Path = $env:Path + "$env:SystemDrive\chocolatey\bin"
			[Environment]::SetEnvironmentVariable( "Path", $env:Path, [System.EnvironmentVariableTarget]::Machine )
		}
	} else {
		Write-Host "`tAlready installed. Skipping installation..."
	}
	
	foreach ($package in $xmlSettings.configuration.chocolatey.package) {
		Write-Host "`tInstalling Package: $($package.name)"
		
		if ($package.installCheck -ne $null) {
			$installCheckResult = Execute-InstallCheck $package.installCheck $($xmlSettings.configuration.applications.baseFolder)

			if ($installCheckResult) {
				Write-Host "`t`tAlready installed. Skipping installation..."
				
				continue
			}
		}
		
		if (-Not $debug) {
			cinst $($package.name)
		}
	}
	
	return $true
}

function Execute-InstallApplications {
	param([xml] $xmlSettings)
	
	foreach ($install in ($xmlSettings.configuration.applications.install | Where { $_.enabled -eq $null -or $_.enabled -ne "0" } | Sort-Object -Property order)) {
		switch ($($install.type)) {
			"sql" {
				if ($install.args -eq $null) {
					$install.SetAttribute("args", "/ConfigurationFile='{CONFIGFILE}' /SQLSVCPASSWORD='{DEFAULTPASSWORD}' /ASSVCPASSWORD='{DEFAULTPASSWORD}' /AGTSVCPASSWORD='{DEFAULTPASSWORD}' /ISSVCPASSWORD='{DEFAULTPASSWORD}' /RSSVCPASSWORD='{DEFAULTPASSWORD}' /SAPWD='{DEFAULTPASSWORD}'")
				}
			}
			"visualstudio" {
				if ($install.args -eq $null) {
					$install.SetAttribute("args", "/adminfile {CONFIGFILE} /Passive /NoRestart")
				}
			}
			"msoffice" {
				if ($install.args -eq $null) {
					$install.SetAttribute("args", "/config {CONFIGFILE}")
				}
			}
			"generic" { 
			}
		}

		$install.args = $($install.args) -Replace "{DEFAULTPASSWORD}",$($xmlSettings.configuration.defaultPassword)
		
		Execute-Install $($xmlSettings.configuration.applications.baseFolder) $install
		
		if ((Get-PendingReboot).RebootPending -eq $true) { Write-Host "Reboot Required before we can continue"; return $true }
	}
	
	if ($xmlSettings.configuration.applications.autoSPInstaller -ne $null)
	{
		Execute-AutoSPInstaller $xmlSettings
	}
		
	return $true
}

function Execute-AutoSPInstaller {
	param([xml] $xmlSettings)

	$applications = $xmlSettings.configuration.applications
	$appSettings = $xmlSettings.configuration.applications.autoSPInstaller

	Write-Host "Installing SharePoint via AutoSPInstaller"

	if ($appSettings.folder -eq $null -and $appSettings.iso -eq $null) {
		Write-Error "Please specify either a folder path or and ISO image for your Microsoft SharePoint Installation (via AutoSPInstaller)"
		
		return $false
	}
	
	if ($applications.baseFolder -ne $null) { $applications.baseFolder = Replace-TokensInString $($applications.baseFolder) }
	if ($appSettings.folder -ne $null) { $appSettings.folder = Replace-TokensInString $($appSettings.folder) $($applications.baseFolder)  }
	if ($appSettings.iso -ne $null) { $appSettings.iso = Replace-TokensInString $($appSettings.iso) $($applications.baseFolder) $($appSettings.folder) }
	if ($appSettings.args -ne $null) { $appSettings.args = Replace-TokensInString $($appSettings.args) $($applications.baseFolder) $($appSettings.folder) }
	if ($appSettings.configFile -ne $null) { $appSettings.configFile = Replace-TokensInString $($appSettings.configFile) $($applications.baseFolder) $($appSettings.folder) }
	
	$mount = $null
	if ($appSettings.iso -ne $null) {
		$mount = Mount-DiskImage -ImagePath $($appSettings.iso) -PassThru
		$mountPath = ($mount | Get-Volume).DriveLetter + ":"
		$appSettings.folder = $mountPath
	}
	
	$networkDrive = $null
	if ($appSettings.folder -like "\\*")
	{
		Write-Host "Network Path Detected. Mounting to local drive letter Q"
		$networkDrive = New-PSDrive -Name Q -Root $($appSettings.folder) -PSProvider FileSystem
		
		$appSettings.folder = $networkDrive.Name + ":"
	}

	Write-Host "Source: $($appSettings.folder)"
	$setupPath = "$($appSettings.folder)"
	$setupCommand = "$setupPath\AutoSPInstaller\AutoSPInstallerMain.ps1"
	if (!(Test-Path $setupCommand)) {
		Write-Host "Unable to locate $setupCommand" -Foregroundcolor Red
		
		return $false
	}
		
	Write-Host "Installing PreReq Roles and Features"
	$cmd = "$($xmlSettings.configuration.workingDirectory)\Install-SP2013RolesFeatures.ps1"
	& $cmd -prompt $false

	if (($([int]$appSettings.downloadPreReqs) -ne $null) -and ($([int]$appSettings.downloadPreReqs) -eq 1))
	{
		Write-Host "Downloading SharePoint 2013 PreReq Files"
		$cmd = "$($xmlSettings.configuration.workingDirectory)\Download-SP2013PreReqFiles.ps1"
		& $cmd -SharePoint2013Path "$($xmlSettings.configuration.workingDirectory)\PreReqs"
		Write-Host "Removing Unnecessary Files"
		if (Test-Path "$($xmlSettings.configuration.workingDirectory)\PreReqs\Windows6.1-KB974405-x64.msu") {
			Remove-Item "$($xmlSettings.configuration.workingDirectory)\PreReqs\Windows6.1-KB974405-x64.msu"
		}
	}
	
	$installsOther = $appSettings.install | Where { $_.mode -eq "PRE" } | Sort-Object -Property order | ForEach-Object {
		Execute-Install $($applications.baseFolder) $_
	}
	
	if ((Get-PendingReboot).RebootPending -eq $true) { return $true }
		
	Write-Host "Starting AutoSPInstaller"
	if (-Not $debug)
	{
		$args = "$($appSettings.configFile)"
		& $setupCommand $args
	}

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

function Execute-InstallCheck {
	param($installCheck, [string] $baseFolder)
	
	if ($installCheck -ne $null) {
		#Write-Verbose "installCheck.folder: $($installCheck.folder)"	
		if ($installCheck.type -eq $null) { $installCheck.SetAttribute("type","file") }
		if ($installCheck.folder -ne $null) { $installCheck.folder = Replace-TokensInString $($installCheck.folder) $baseFolder }
		
		switch ($($installCheck.type)) {
			"file" {
				if ($installCheck.folder -eq $null -or ($($installCheck.folder).length -eq 0) -or $installCheck.file -eq $null -or ($($installCheck.file).length -eq 0)) { 
					Write-Host "Install Check requires both folder and file to be specified" -Foregroundcolor Red
					
					# Return TRUE here to "fake" that it is already installed
					return $true
				}
			
				$installCheckPath = Join-Path  -Path $($installCheck.folder) -ChildPath $($installCheck.file)
				if (Test-Path $installCheckPath) {
					return $true
				}
			}
			"registry" {
			}
			"poscommand" {
				return ((Get-Command $($installCheck.commandName) -ErrorAction SilentlyContinue) -ne $null)
			}
		}
	}
	
	return $false
}

function Execute-Install {
	param([string] $baseFolder, $install)
	
	Write-Host "Installing: $($install.name)"
	if ($install.command -eq $null) {
		Write-Host "`tSkipping due to no command being specified"
		
		return $true
	}
	
	if ($install.enabled -ne $null -and $([int]$install.enabled) -eq 0) {
		Write-Host "`tDisabled. Skipping..."
		
		return $true
	}
	
	if ($install.folder -eq $null -and $install.iso -eq $null) {
		Write-Error "Please specify either a folder path or and ISO image for your Visual Studio Installation"
		
		return $false
	}
		
	#Write-Verbose "BaseFolder: $baseFolder"
	if ($baseFolder -ne $null) { $baseFolder = Replace-TokensInString $baseFolder }
	#Write-Verbose "install.folder: $($install.folder)"
	if ($install.folder -ne $null) { $install.folder = Replace-TokensInString $($install.folder) $baseFolder }
	#Write-Verbose "install.iso: $($install.iso)"
	if ($install.iso -ne $null) { $install.iso = Replace-TokensInString $($install.iso) $baseFolder $($install.folder) }
	#Write-Verbose "install.configFile: $($install.configFile)"
	if ($install.configFile -ne $null) { $install.configFile = Replace-TokensInString $($install.configFile) $baseFolder $($install.folder) }
	#Write-Verbose "install.args: $($install.args)"
	if ($install.args -ne $null) { 
		$install.args = Replace-TokensInString $($install.args) $baseFolder $($install.folder)
		$install.args = $($install.args) -Replace "{CONFIGFILE}",$($install.configFile)
	}
		
	$installCheckResult = Execute-InstallCheck $install.installCheck $baseFolder
	if ($installCheckResult) {
		Write-Host "`t`tAlready installed. Skipping installation..."
		
		return $true
	}
		
	$mount = $null
	if ($install.iso -ne $null) {
		Write-Host "ISO File Detected. Mounting Image now"
		$mount = Mount-DiskImage -ImagePath $($install.iso) -PassThru
		$mountPath = ($mount | Get-Volume).DriveLetter + ":"
		Write-Host "Mounted ISO To: $mountPath"
		$install.folder = $mountPath
	}
		
	$networkDrive = $null
	if ($install.folder -like "\\*")
	{
		Write-Host "Network Path Detected. Mounting to local drive letter Q"
		$networkDrive = New-PSDrive -Name Q -Root $($install.folder) -PSProvider FileSystem
		
		$install.folder = $networkDrive.Name + ":"
	}
				
	$path = Join-Path -Path $($install.folder) -ChildPath $($install.command)
	if (!(Test-Path $path)) {
		Write-Host "Unable to find application: $path" -Foregroundcolor Red
		
		return $false
	}
	
	$install.args = $($install.args) -Replace "'", """"
	Write-Host "Executing: $path $($install.args)"
	if (-Not $debug)
	{
		Try {
			$stdOutLogFile = "{SCRIPT FOLDER}\" + $($install.name) + ".log"
			$stdOutLogFile = Replace-TokensInString $stdOutLogFile $baseFolder
			Write-Host "Log File: $stdOutLogFile"
			
			if ($path -like "*.msi") {
				$args = $($install.args)
				if (-Not ($args -like "*/log")) { $args = $args + " /log ""$stdOutLogFile""" }
				#Write-Host "$path -> $args"
				$process = Start-Process -FilePath $path -ArgumentList $args -Wait -PassThru
			} else {
				$process = Start-Process -FilePath $path -ArgumentList $($install.args) -Wait -PassThru -RedirectStandardOutput $stdOutLogFile
				Write-Host $stdOut
			}

			Write-Host ""
			Write-Host "Process Exist Code: "$process.ExitCode -Foregroundcolor Yellow
			Write-Host "-----------------------------------------------------------------------------------------------"
		}
		Catch {
			Write-Host $_.Exception.Message
		}
	}

	#if (!(Test-Path $path)) {
	#	Write-Host "Install was not successful" -Foregroundcolor Red
		
	#	return $false
	#}
	
	if ($install.taskbarLink -ne $null) {
		Add-PinToTaskbar $($install.taskbarLink.name) $($install.taskbarLink.folder) $($install.taskbarLink.file)
	}
	
	if ($networkDrive -ne $null) {
		Write-Host "Removing Network Drive Map"
		Remove-PSDrive $networkDrive.Name
	}
	
	if ($mount -ne $null) {
		Write-Host "Dismounting ISO Image"
		Dismount-DiskImage -ImagePath $mount.ImagePath
	}
	
	return $true
}

function Add-PinToTaskbar {
	param([string] $appName, [string] $path, [string] $exeName)
	
	Write-Host "Pinning $appName to the Taskbar."

	$p = Replace-TokensInString $path

	if (!(Test-Path $p)) {
		Write-Host "Unable to find $appName ($p)" -Foregroundcolor Red
		
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

function Test-ADUser {
	param([string] $upn)

	Try {
		Write-Host "Checking for existence of user $upn" -Foregroundcolor Yellow
		if ((Get-ADUser $upn -ErrorAction Continue) -ne $null) {
		#if ((Get-ADUser $upn -ErrorAction SilentlyContinue) -eq $null) {
			Write-Host "User Found"

			return $true
		}
	}
	Catch {
	}
	
	return $false
}

function Replace-TokensInString {
	param([string] $str, [string] $baseFolder = $null, [string] $appFolder = $null)

	#Write-Host "Before: $str, BaseFolder: $baseFolder, AppFolder: $appFolder"
	
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

	#Write-Host "`tAfter: $str"
	
	return $str
}