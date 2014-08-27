$PackageName = ""
$DestinationFolder = "..\Build"

$SourceFiles = @{ 
					"..\license.txt" = "";
					".\PSUtils" = ""; 
					".\Tools" = "";
					"ServerSetup.bat" = ""; 
					"ServerSetup.ps1" = "";
					"ServerSetupCoreFuncs.ps1" = "";
					"..\Samples\AutoServerSetup-Sample.xml" = "ServerSetup-Sample.xml";
					"..\Samples\AutoServerSetup-SP2013.xml" = "ServerSetup-SP2013.xml";
					"..\Samples\AutoServerSetup-Win8.xml" = "ServerSetup-Win8.xml";
					"..\Samples\MSOffice2013.xml" = "";
					"..\Samples\SQL2012-Developer.ini" = "";
					"..\Samples\VS2013-Pro.xml" = "";
					"..\Samples\AD-Sample.xml" = "";
					"..\Samples\DNS-Sample.xml" = "";
				}

Write-Output "Destination Folder: $DestinationFolder"

if (-Not (Test-Path $DestinationFolder -PathType Container)) {
	Write-Output "Creating Destination Folder: $DestinationFolder"
	New-Item $DestinationFolder -ItemType Container
} else {
	Write-Output "Removing all file in Destination Folder: $DestinationFolder"
	Remove-Item "$DestinationFolder\*" -Recurse
}

$DestinationFolder = Resolve-Path $DestinationFolder -ErrorAction SilentlyContinue

foreach ($key in $SourceFiles.Keys) {
	$dest = $SourceFiles[$key]
	$source = (Resolve-Path $key -ErrorAction SilentlyContinue).Path
	if ($source -eq $null -or -Not (Test-Path $source -ErrorAction SilentlyContinue)) {
		Write-Output "Skipping files (does not exist): $key [$source]"
		continue
	}

	if ($dest -eq $null -or $dest.Length -eq 0) {
		$dest = (Get-Item $source).Name
	} else {
	}

	$dest = Join-Path -Path $DestinationFolder -ChildPath $dest 

	Write-Output "Copying: $key -> $dest"
	if (Test-Path $source -pathtype container) {
		Copy-Item -Path $source -Destination $dest -Recurse -Force   
	} else {
		Copy-Item -Path $source -Destination $dest -Force  
	}
	
}