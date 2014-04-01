Function Create-SPWorkflowFarm {
<# 
	.Synopsis 
		Creates SharePoint Workflow Farm
	.Description 
		This script creates the Workflow Farm for SharePoint
	
	PARAMETERS 
		-settings
	.Example 
		Create-SPWorkflowFarm.ps1 -settings SPWorkflowManager.xml
	
		Creates a new SharePoint Workflow Farm using the settings in WFFarmSettings.xml

	.Notes 
		NAME:  Create-SPWorkflowManager
		AUTHOR: http://ranaictiu-technicalblog.blogspot.com/2013/02/sharepoint-2013-workflow-manager.html
		LASTEDIT: 12/06/2013
		KEYWORDS: 
	.Link 
		
#Requires -Version 2.0 
#> 
	param (
		[Parameter(Mandatory=$false)] [String]$settings = ".\WFFarmSettings.xml"
	)

	#Get current user full login name
	$CurrentUserLoginName=[Environment]::UserName + '@' + [Environment]::UserDomainName;
	#Get current server fully qualified domain name
	$HostFQDN="$env:computername.$env:userdnsdomain";

	#Load SharePoint Snapin
	if ( (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue) -eq $null ){  
		Add-PsSnapin Microsoft.SharePoint.PowerShell
	}

	#Get DB Connection String
	function GetDBConnectionString([string]$connectionStringFormat, [string]$dbPrefix, [string]$dbName){
		if($dbPrefix -ne ""){
			$dbFullName=$(GetDBName $dbPrefix $dbName);
			return [string]::Format($connectionStringFormat,$dbFullName);
			}
		else {
			return $dbName;
		}
	}

	#Add Dev, Test etc. environment prefix, if needed
	function GetDBName([string]$dbPrefix,[string]$dbName){
		if(($dbPrefix) -and ($dbPrefix -ne "")){
			return $dbPrefix + "_" + $dbName;
		}
		return $dbName;
	}

	#Get current Script directory
	function Get-ScriptDirectory
	{
	  $Invocation = (Get-Variable MyInvocation -Scope 1).Value
	  Split-Path $Invocation.MyCommand.Path
	}

	function ConfigureWFManager([string]$settingsFile){
		[xml]$wfsettings = Get-Content $settingsFile
		$settings=$wfsettings.Settings;
		$SharePointSiteUrl=$settings.SiteUrl;
		$dbPrefix=$settings.DBPrefix;
		$CertificateKey=$settings.CertificationKey;
		$databaseServer=$settings.DBServer;
		$ConnectionStringFormat="Data Source=$databaseServer;Initial Catalog={0};Integrated Security=True;Encrypt=False";
		$RunAsAccount=$settings.WFManagerRunAsUser;
		$RunAsPasswordPlain=$settings.WFManagerRunAsPassword
		$WorkflowNamespace=$settings.WorkflowNamespace;
		if(ShouldIProvision($settings.AppManagementService))
		{
			ProvisionAppManagementService($settings);
		}

		# To be run in Workflow Manager PowerShell console that has both Workflow Manager and Service Bus installed.
		# Create new Service Bus Farm
		$SBCertificateAutoGenerationKey = ConvertTo-SecureString -AsPlainText  -Force  -String $CertificateKey -Verbose;

		New-SBFarm -SBFarmDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'SBManagementDB')  -InternalPortRangeStart 9000 -TcpPort 9354 -MessageBrokerPort 9356 -RunAsAccount $RunAsAccount -AdminGroup 'BUILTIN\Administrators' -GatewayDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'SBGatewayDB') -CertificateAutoGenerationKey $SBCertificateAutoGenerationKey -MessageContainerDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'SBMessageContainerDB') -Verbose;

		# To be run in Workflow Manager PowerShell console that has both Workflow Manager and Service Bus installed.

		# Create new Workflow Farm
		$WFCertAutoGenerationKey = ConvertTo-SecureString -AsPlainText  -Force  -String $CertificateKey -Verbose;


		New-WFFarm -WFFarmDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'WFManagementDB') -RunAsAccount $RunAsAccount -AdminGroup 'BUILTIN\Administrators' -HttpsPort 12290 -HttpPort 12291 -InstanceDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'WFInstanceManagementDB') -ResourceDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'WFResourceManagementDB') -CertificateAutoGenerationKey $WFCertAutoGenerationKey -Verbose;

		# Add Service Bus Host
		$SBRunAsPassword = ConvertTo-SecureString -AsPlainText  -Force  -String $RunAsPasswordPlain -Verbose;


		Add-SBHost -SBFarmDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'SBManagementDB') -RunAsPassword $SBRunAsPassword -EnableFirewallRules $true -CertificateAutoGenerationKey $SBCertificateAutoGenerationKey -Verbose;

		Try
		{
			# Create new Servie Bus Namespace
			New-SBNamespace -Name $WorkflowNamespace -AddressingScheme 'Path' -ManageUsers $RunAsAccount,$CurrentUserLoginName -Verbose;

			Start-Sleep -s 90
		}
		Catch [system.InvalidOperationException]
		{
		}

		# Get Service Bus Client Configuration
		$SBClientConfiguration = Get-SBClientConfiguration -Namespaces $WorkflowNamespace -Verbose;

		# Add Workflow Host
		$WFRunAsPassword = ConvertTo-SecureString -AsPlainText  -Force  -String $RunAsPasswordPlain -Verbose;


		Add-WFHost -WFFarmDBConnectionString $(GetDBConnectionString $connectionStringFormat $dbPrefix 'WFManagementDB') -RunAsPassword $WFRunAsPassword -EnableFirewallRules $true -SBClientConfiguration $SBClientConfiguration -EnableHttpPort  -CertificateAutoGenerationKey $WFCertAutoGenerationKey -Verbose;

		Write-Host "Registering workflow host (HTTP) to site: $SharePointSiteUrl";
		Register-SPWorkflowService –SPSite $SharePointSiteUrl –WorkflowHostUri $("http://$HostFQDN" + ":12291") –AllowOAuthHttp
	}

	function ProvisionAppManagementService([System.Xml.XmlNode] $settings){

		$appManagementServices=Get-SPServiceApplication | Where-Object { $_.GetType().ToString() -eq "Microsoft.SharePoint.AppManagement.AppManagementServiceApplication"}
		 If($appManagementServices -ne $null)
		 {
			 Write-Host "An App Managemetn service is already running. Returning.." -ForegroundColor Yellow
			return;
		 }    
	
		Write-Host "Provisioning App Management Service";
		$appManagementService=$settings.AppManagementService;
		$appPool=$(GetAppPool $appManagementService)
		$dbName=$(GetDBName $settings.DBPrefix $appManagementService.DBName);
		$appAppSvc = New-SPAppManagementServiceApplication -ApplicationPool $appPool -Name $appManagementService.Name -DatabaseName $dbName
		New-SPAppManagementServiceApplicationProxy -ServiceApplication $appAppSvc
	}

	function GetAppPool([System.Xml.XmlNode] $appManagementService){
		$pool = Get-SPServiceApplicationPool -Identity $AppManagementService.AppPoolName -ErrorVariable err -ErrorAction SilentlyContinue
		If ($err) {
			# The application pool does not exist so create.
			Write-Host -ForegroundColor White " - Getting $($appManagementService.ManagedAccountUserName) account for application pool..."
			$managedAccount = (Get-SPManagedAccount -Identity $appManagementService.ManagedAccountUserName -ErrorVariable err -ErrorAction SilentlyContinue)
			If ($err) {
				If (($appManagementService.ManagedAccountPassword -ne "") -and ($appManagementService.ManagedAccountPassword -ne $null)) 
				{
					$appPoolConfigPWD = (ConvertTo-SecureString $appManagementService.ManagedAccountPassword -AsPlainText -force)
					$accountCred = New-Object System.Management.Automation.PsCredential $appManagementService.ManagedAccountUserName,$appPoolConfigPWD
				}
				Else
				{
					$accountCred = Get-Credential $appManagementService.ManagedAccountUserName
				}
				$managedAccount = New-SPManagedAccount -Credential $accountCred
			}
			Write-Host -ForegroundColor White " - Creating applicatoin pool $($appManagementService.AppPoolName)..."
			$pool = New-SPServiceApplicationPool -Name $appManagementService.AppPoolName -Account $managedAccount
		}
		return $pool;
	}

	Function ShouldIProvision([System.Xml.XmlNode] $node)
	{
		If (!$node) {Return $false} # In case the node doesn't exist in the XML file
		# Allow for comma- or space-delimited list of server names in Provision or Start attribute
		If ($node.GetAttribute("Provision")) {$v = $node.GetAttribute("Provision").Replace(","," ")}
		ElseIf ($node.GetAttribute("Start")) {$v = $node.GetAttribute("Start").Replace(","," ")}
		ElseIf ($node.GetAttribute("Install")) {$v = $node.GetAttribute("Install").Replace(","," ")}
		If ($v -eq $true) { Return $true; }
		Return $false;
	}

	Write-Host "Configuring WF Manager"
	$location=Get-ScriptDirectory

	$settings = (Resolve-Path $settings).Path

	ConfigureWFManager $settings
}