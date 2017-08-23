# Project Description
This project was inspired by AutoSPInstaller.  The idea is completely script the setup of a Windows Server machine. The script picks up immediately following the OS install and can take care of the following

## Features
* Renaming Computer
* Setting Account Passwords
* Running Windows Update
* Settings IE Enhanced Security
* Installing Chocolately and selected packages (like boxstarter)
* Installing Active Directory (and creating any OUs and Account needed)
* Setting up DNS (and creating and records needed)
* Adding Windows Features
* Installing applications (SQL Server, Office, Visual Studio, etc)
* Executing AutoSPInstaler

And all of this is done via PowerShell and an XML Configuration file.

*Steps to use are:*
* Install Base OS (Windows Server 2012, 2012 R2, and Windows 2008, 2008 R2)
* Download Script
* Extract to folder of your choice
* Create any answer files you need (Office, Visual Studio, SQL Server, AutoSPInstaller, etc)
* Edit ServerSetup.xml file and set the key items
** Passwords
** Installation Paths
** Answer Files
* Open PowerShell with RunAs Administrator
* Run ServerSetup.ps1
* Sit back and relax and watch the server build (or not and come back in about an hour to check on progress)

*Note:* A majority of the scripts until the utils folder have been gathered from other sources on the net.  All original comments, licenses, and ownership information was maintained whenever possible.

