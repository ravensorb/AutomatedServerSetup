$scriptCommand = $myinvocation.mycommand.definition
$workingDirectory = $PSScriptRoot
if ($workingDirectory -eq $null -or $workingDirectory.length -eq 0) {
	$workingDirectory = Split-Path $scriptCommand
}

Import-Module "$workingDirectory\Tools\Create-SPWorkflowFarm.ps1" -Force

# Set Distributed Cache to use only 100MB of RAM -- http://technet.microsoft.com/en-us/library/jj219613.aspx
Update-SPDistributedCacheSize -CacheSizeInMB 100

Create-SPWorkflowFarm ".\Config\WorkflowManager-SP2013.xml"