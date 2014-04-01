@ECHO OFF
SETLOCAL
cls
@TITLE -- AutoServerSetup --
FOR /F "tokens=2-4 delims=/ " %%i IN ('date /t') DO SET SHORTDATE=%%i-%%j-%%k
FOR /F "tokens=1-3 delims=: " %%i IN ('time /t') DO SET SHORTTIME=%%i-%%j%%k
:: Updated to support passing the input XML file as an argument to this batch file
IF "%1"=="" GOTO GETINPUT
IF EXIST "%~dp0\%1" Set InputFile="%~dp0\%1"
IF EXIST "%1" Set InputFile="%1"
ECHO - Specified Input File:
ECHO - %InputFile%
GOTO START
:GETINPUT
IF EXIST "%~dp0\ServerSetup-%COMPUTERNAME%.xml" (
	Set InputFile="%~dp0\ServerSetup-%COMPUTERNAME%.xml"
	ECHO - Using %COMPUTERNAME%-specific Input File.
	GOTO START
	)
IF EXIST "%~dp0\ServerSetup-%USERDOMAIN%.xml" (
	Set InputFile="%~dp0\ServerSetup-%USERDOMAIN%.xml"
	ECHO - Using %USERDOMAIN%-specific Input File.
	GOTO START
	)
IF EXIST "%~dp0\ServerSetup.xml" (
	Set InputFile="%~dp0\ServerSetup.xml"
	ECHO - Using standard Input File.
	GOTO START
	)
ECHO - Input File not found! Please check for ServerSetup.xml, ServerSetup-%USERDOMAIN%.xml, or ServerSetup-%COMPUTERNAME%.xml
GOTO END
:START
:: Check for Powershell
IF NOT EXIST "%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" (
	COLOR 0C
	ECHO - "powershell.exe" not found!
	ECHO - This script requires PowerShell - install v2.0/3.0, then re-run this script.
	COLOR
	pause
	EXIT
	)
:: Check for Powershell v2.0 (minimum)
ECHO - Checking for Powershell 2.0 (minimum)...
"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" $host.Version.Major | find "1" >nul
IF %ERRORLEVEL% == 0 (
	COLOR 0C
	ECHO - This script requires a minimum PowerShell version of 2.0!
	ECHO - Please install v2.0/3.0, then re-run this script.
	COLOR
	pause
	EXIT
	)
ECHO - OK.
GOTO LAUNCHSCRIPT
:LAUNCHSCRIPT
ECHO - Starting AutoServerSetup...
"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" -Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'-NoExit -ExecutionPolicy Bypass %~dp0\ServerSetup.ps1 %InputFile%'"
GOTO END
:END
ECHO - AutoServerSetup launched - finished with ServerSetup.bat.
rem pause
ENDLOCAL