#***************************************************************************************
# Written by Shawn Anderson
#
# Based on Script by Craig Lussier - http://craiglussier.com
#
# This script downloads Microsoft Updates
#   
# -Only run this script on Windows Server 2012 (RTM, either Standard or Datacenter)
# -Do not run this script on a Windows Server 2008 R2 SP1 Server!
# -Run this script as a local server Administrator
# -Run PowerShell as Administrator
#
# Don't forget to: Set-ExecutionPolicy RemoteSigned
# If you have not done so already within you Windows Server 2012 server
#****************************************************************************************
param([string] $UpdatePath = $(Read-Host -Prompt "Please enter the directory path to where you wish to save the Update files.")) 
 
# Import Required Modules
Import-Module BitsTransfer 

# Specify download url's for Microsoft Updates
$DownloadUrls = (
			"http://download.microsoft.com/download/5/1/C/51CA768E-C79E-41BA-91D4-7F7D929B0BFE/ubersrvsp2013-kb2767999-fullfile-x64-glb.exe", # SharePoint 2013 March 2013 PU
			"http://download.microsoft.com/download/C/7/1/C7110025-87E4-46F3-86C8-B7EFE3F02B18/msoloc2013-kb2810017-fullfile-x86-glb.exe", # Office 2013 update: June 11, 2013 - (KB2810017) 32-Bit Edition
			"http://download.microsoft.com/download/4/E/D/4ED39B27-3860-455A-8335-EFA15F71416F/msoloc2013-kb2810017-fullfile-x64-glb.exe" # Office 2013 update: June 11, 2013 - (KB2810017) 64-Bit Edition
	) 

function ExecuteDownloads() 
{ 
    Write-Host ""
    Write-Host "====================================================================="
    Write-Host "      Downloading Microsoft Product Updates Please wait..." 
    Write-Host "====================================================================="
     
    $ReturnCode = 0 
 
    foreach ($DownLoadUrl in $DownloadUrls) 
    { 
        ## Get the file name based on the portion of the URL after the last slash 
        $FileName = $DownLoadUrl.Split('/')[-1] 
        Try 
        { 
            ## Check if destination file already exists 
            If (!(Test-Path " $UpdatePath\$FileName")) 
            { 
                ## Begin download 
                Start-BitsTransfer -Source $DownLoadUrl -Destination $UpdatePath\$fileName -DisplayName "Downloading `'$FileName`' to $UpdatePath" -Priority High -Description "From $DownLoadUrl..." -ErrorVariable err 
                If ($err) {Throw ""} 
            } 
            Else 
            { 
                Write-Host " - File $FileName already exists, skipping..." 
            } 
        } 
        Catch 
        { 
            $ReturnCode = -1 
            Write-Warning " - An error occurred downloading `'$FileName`'" 
            Write-Error $_ 
            break 
        } 
    } 
    Write-Host " - Done downloading Microsoft Product Updates" 
     
    return $ReturnCode 
} 

function CheckProvidedDownloadPath()
{
    $ReturnCode = 0

    Try 
    { 
        # Check if destination path exists 
        If (!(Test-Path $UpdatePath)) {
			New-Item -path $UpdatePath -type directory
		}
		
        If (Test-Path $UpdatePath) {
        { 
			# Remove trailing slash if it is present
			$script:UpdatePath = $UpdatePath.TrimEnd('\')
			$ReturnCode = 0
        } Else {
			$ReturnCode = -1
			Write-Host ""
			Write-Warning "Your specified download path does not exist. Please verify your download path then run this script again."
			Write-Host ""
        } 
    } 
    Catch 
    { 
         $ReturnCode = -1 
         Write-Warning "An error has occurred when checking your specified download path" 
         Write-Error $_ 
         break 
    }     
    
    return $ReturnCode 
}

function DownloadFiles() 
{ 
    $rc = 0 
    $rc = CheckProvidedDownloadPath  

    # Download Files  
    if($rc -ne -1) 
    { 
        $rc = ExecuteDownloads 
    } 
     
    if($rc -ne -1)
    {
        Write-Host ""
        Write-Host "Script execution is now complete!"
        Write-Host ""
    }
} 

DownloadFiles
