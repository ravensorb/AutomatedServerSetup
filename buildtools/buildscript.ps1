$psake.use_exit_on_error = $true
properties {
	$baseDir = (Split-Path -parent $psake.build_script_dir)
	if(Get-Command Git -ErrorAction SilentlyContinue) {
		$versionTag = git describe --abbrev=0 --tags
		$version = $versionTag + "."
		$version += (git log $($version + '..') --pretty=oneline | measure-object).Count
		$changeset=(git log -1 $($versionTag + '..') --pretty=format:%H)
	}
	else {
		$version="1.1.1"
	}
	$nugetExe = "$env:ChocolateyInstall\ChocolateyInstall\nuget"
	$ftpHost = "waws-prod-bay-001.ftp.azurewebsites.windows.net"
	$notes = $releaseNotes
}

Task default -depends Build
Task Build -depends Test, Package
Task Deploy -depends Build, Push-Codeplex
Task Package -depends Clean-Artifacts, Version-Module, Package-DownloadZip -description 'Versions the psd1 and packs the module and example package'
Task All-Tests -depends Test

Task Package-DownloadZip -depends Clean-Artifacts {
	if (Test-Path "$basedir\bin\AutoServerSetup.zip") {
	  Remove-Item "$baseDir\bin\AutoServerSetup.zip" -Recurse -Force
	}
	if(!(Test-Path "$baseDir\buildArtifacts")){
		mkdir "$baseDir\buildArtifacts"
	}
	#if(!(Test-Path "$baseDir\bin")){
	#	mkdir "$baseDir\bin"
	#}
	if (!(Test-Path $env:ProgramFiles\7-zip)){
		cinst 7zip
		cinst 7zip.commandline
	}
	Remove-Item "$env:temp\AutoServerSetup.zip" -Force -ErrorAction SilentlyContinue
	."$env:ProgramFiles\7-zip\7z.exe" a -tzip "$basedir\buildartifacts\AutoServerSetup.zip" "$basedir\Build" | out-Null

	#Move-Item "$basedir\buildartifacts\AutoServerSetup.zip" "$basedir\bin\AutoServerSetup.$version.zip"
}

Task Test -depends Package-DownloadZip {
	pushd "$baseDir"

	if(!(Test-Path "$baseDir\Tests")){
		mkdir "$baseDir\Tests"
	}
	$pesterDir = (dir $env:ChocolateyInstall\lib\Pester*)
	if($pesterDir.length -gt 0) {$pesterDir = $pesterDir[-1]}
	if($testName){
		exec {."$pesterDir\tools\bin\Pester.bat" $baseDir/Tests -testName $testName}
	}
	else{
		exec {."$pesterDir\tools\bin\Pester.bat" $baseDir/Tests }
	}
	popd
}

Task Version-Module -description 'Stamps the psd1 with the version and last changeset SHA' {
	Get-ChildItem "$baseDir\**\*.psd1" | % {
	   $path = $_
		(Get-Content $path) |
			% {$_ -replace "^ModuleVersion = '.*'`$", "ModuleVersion = '$version'" } | 
				% {$_ -replace "^PrivateData = '.*'`$", "PrivateData = '$changeset'" } | 
					Set-Content $path
	}

	$notes = $releaseNotes -Replace "[VERSION]",$version
}

Task Clean-Artifacts {
	if (Test-Path "$baseDir\buildArtifacts") {
	  Remove-Item "$baseDir\buildArtifacts" -Recurse -Force
	}
	mkdir "$baseDir\buildArtifacts"

	if (Test-Path "$baseDir\bin") {
	  Remove-Item "$baseDir\bin" -Recurse -Force
	}
	mkdir "$baseDir\bin"
}

Task Push-Codeplex {
	Add-Type -Path "$basedir\buildtools\CodePlexClientAPI\CodePlex.WebServices.Client.dll"
	 $releaseService=New-Object CodePlex.WebServices.Client.ReleaseService
	 $releaseService.Credentials = Get-Credential -Message "Codeplex credentials" -username "ravensorb"
	 $releaseService.CreateARelease("AutoServerSetup","AutoServerSetup $version",$notes,[DateTime]::Now,[CodePlex.WebServices.Client.ReleaseStatus]::Beta, $true, $true)
	 $releaseFile = New-Object CodePlex.WebServices.Client.releaseFile
	 $releaseFile.Name="AutoServerSetup $version"
	 $releaseFile.MimeType="application/zip"
	 $releaseFile.FileName="AutoServerSetup.$version.zip"
	 $releaseFile.FileType=[CodePlex.WebServices.Client.ReleaseFileType]::RuntimeBinary
	 $releaseFile.FileData=[System.IO.File]::ReadAllBytes("$basedir\bin\AutoServerSetup.$version.zip")
	 $fileList=new-object "System.Collections.Generic.List``1[[CodePlex.WebServices.Client.ReleaseFile]]"
	 $fileList.Add($releaseFile)
	 $releaseService.UploadReleaseFiles("AutoServerSetup", "AutoServerSetup $version", $fileList)
}

function PackDirectory($path){
	exec { 
		Get-ChildItem $path -Recurse -include *.nuspec | 
			% { .$nugetExe pack $_ -OutputDirectory $path -NoPackageAnalysis -version $version }
	}
}

function PushDirectory($path){
	exec { 
		Get-ChildItem "$path\*.nupkg" | 
			% { cpush $_ -source "http://www.myget.org/F/boxstarter/api/v2/package" }
	}
}
