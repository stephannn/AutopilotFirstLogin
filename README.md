# AutopilotFirstLogin

This repository contains the folders Code and Installer. Installer is using the WiX-Toolset to create a MSI installer inclusive scheduled task.
Code contains the actual first login script which does:
-	Blocks the start menu
-	Show a loading screen
-	Triggers the 'Schedule #3 created by enrollment client' task
-	Waits for the 'appidpolicyconverter' process
Also included is the serviceUI.exe and the PSADT, but the last one is just added for testing purposes.
