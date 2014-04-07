Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

$scriptCommand = $myinvocation.mycommand.definition
$workingDirectory = $PSScriptRoot
if ($workingDirectory -eq $null -or $workingDirectory.length -eq 0) {
	$workingDirectory = Split-Path $scriptCommand
}

if (Test-Path .\Create-SPWorkflowFarm.ps1) {
	Import-Module ".\Create-SPWorkflowFarm.ps1" -Force -ErrorAction SilentlyContinue
} else {
	Import-Module "$workingDirectory\Tools\Create-SPWorkflowFarm.ps1" -Force -ErrorAction Stop
}

# Set Distributed Cache to use only 100MB of RAM -- http://technet.microsoft.com/en-us/library/jj219613.aspx
Write-Host "Setting SharePoint Distributed Cache Size"
Update-SPDistributedCacheSize -CacheSizeInMB 100

Write-Host "Installing Workflow Manager"
cinst WorkflowManagerRefresh -source webpi
cinst ServiceBusCU1 -source webpi
cinst WorkflowCU2 -source webpi
cinst OfficeToolsForVS2012RTW -source webpi
cinst WorkflowClient -source webpi
cinst WorkflowManagerToolsVS2012 -source webpi

Write-Host "Creating Workflow Farm"
Create-SPWorkflowFarm ".\Config\WorkflowManager-SP2013.xml"