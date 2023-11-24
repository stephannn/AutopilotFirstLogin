<#
	Thanks to:
	https://web.archive.org/web/20200603004235/https://gallery.technet.microsoft.com/Hide-Windows-8-Start-432bfb86
	https://oofhours.com/2019/09/28/forcing-an-mdm-sync-from-a-windows-10-client/
	https://smbtothecloud.com/automate-a-reboot-or-custom-script-when-the-autopilot-esp-is-complete/
	https://call4cloud.nl/2022/10/intune-sync-debug-tool-the-last-royal-treasure/
	https://github.com/SMSAgentSoftware/CustomW10UpgradeSplashScreen
	https://www.petervanderwoude.nl/post/windows-10-mdm-policy-refresh/

	I hope I haven't forgetten anyone

	Changelog:

	0.2 add check if ESP is still running
	0.1 initial design

#>


[CmdletBinding()]
param(
	[bool]$dryRun = $false,
	[string]$defaultUserCulture = "en-US",
    [bool]$multiLanguageSupport = $false
)

$userDomains = @('AzureAD','FMDE')
$companyName = "SPIE"

if ($PSScriptRoot.Length -eq 0) {
	$scriptDirectory = (get-location).path
} else {
	$scriptDirectory = $PSScriptRoot
}

function Get-CurrentLoggedOnUser {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'CurrentLoggedOnUserUPN', Justification = 'variable is used')]
	param
    (
        [parameter(Mandatory=$true)]
        [string[]]$userDomains
    )
	$profilelist = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
	#$loggedonuser = Get-Ciminstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty username
	$CurrentLoggedOnUser = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -expand UserName)
	If ([String]::IsNullOrWhiteSpace($CurrentLoggedOnUser))
		{
			$CurrentUser = Get-Itemproperty "Registry::\HKEY_USERS\*\Volatile Environment"|Where-Object {$_.USERDOMAIN -in $userDomains -or $_.USERNAME -match 'WDAGUtilityAccount'}
			If (![String]::IsNullOrWhiteSpace($CurrentUser))
				{
					$CurrentLoggedOnUser = "$($CurrentUser.USERDOMAIN)\$($CurrentUser.USERNAME)"
					$CurrentLoggedOnUserSID = split-path $CurrentUser.PSParentPath -leaf
					If($CurrentUser.USERDOMAIN -match 'AzureAD')
						{
							$UPNKeys = $(reg query hklm\SOFTWARE\Microsoft\IdentityStore\LogonCache /reg:64).Split([Environment]::NewLine)| Where-Object {$_ -ne ""}
							ForEach ($item in $UPNKeys)
								{
									$UPN = reg @('query',"$item\Sid2Name\$CurrentLoggedOnUserSID",'/v','IdentityName','/reg:64')
									If ($LASTEXITCODE -eq 0){$CurrentLoggedOnUserUPN = ($UPN[2] -split ' {2,}')[3] ; Break}
								}
						}
				}
		}
		
	$userwithoutdomain = $CurrentLoggedOnUser -replace "^.*?\\"
	#CD $ProfileList
	$SIDobject = Get-ChildItem -Path $profilelist -rec -ea SilentlyContinue | Where-Object { (get-itemproperty -Path $_.PsPath) -match "$userwithoutdomain"  }
	
	return [pscustomobject]@{
		UserName = $CurrentLoggedOnUser -replace "^.*?\\"
		NTAccount = $CurrentLoggedOnUser
		SID = ($SIDobject.PsPath) -replace "^.*?list\\"
		ProfilePath = $SIDobject.GetValue("ProfileImagePath")
		UILanguage = (Get-ItemProperty "Registry::\HKEY_USERS\$(($SIDobject.PsPath) -replace "^.*?list\\")\Control Panel\Desktop" -ErrorAction SilentlyContinue).PreferredUILanguages
	}

}

$userObject = Get-CurrentLoggedOnUser -userDomains $userDomains

#====================================================#

if(($null -ne $userObject) -and ($userObject -notmatch "defaultUser")){
	#New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue
	$RegPath = "Registry::HKU\$($userObject.SID)\SOFTWARE\$companyName\Enrollment"

	# Not working anymore
	$MdmFinished = [bool]($(Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" -Class "MDM_EnrollmentStatusTracking_Setup01").HasProvisioningCompleted -eq "True")
	$MdmFinished = $true
	
	if( ([bool](Get-ItemProperty -Path $RegPath -Name 'FirstLoginSync' -ErrorAction SilentlyContinue) -eq $false -and $MdmFinished -eq $true) -or ($dryRun -eq $true) ){

		if(!([string]::IsNullOrEmpty($userObject.UILanguage))){
			$defaultUserCulture = $userObject.UILanguage | Select-Object -First 1
		}

		# Create new process to display UI
		$ProcessRunSpace = New-Object System.Diagnostics.Process
		$ProcessRunSpace.StartInfo.UseShellExecute = $false
		$ProcessRunSpace.StartInfo.WorkingDirectory = $scriptDirectory
		$ProcessRunSpace.StartInfo.FileName = "PowerShell.exe"
		$ProcessRunSpace.StartInfo.Arguments = "-File Create-Runspaces.ps1 -ProfilePath ""$($userObject.ProfilePath)"" -defaultUserCulture $defaultUserCulture -multiLanguageSupport $([int]$multiLanguageSupport)"
		$ProcessRunSpace.StartInfo.CreateNoWindow = $true
		$ProcessRunSpace.Start()

		# not working a system user
		# Check start menu
		#$ProcessStartMenu = New-Object System.Diagnostics.Process
		#$ProcessStartMenu.StartInfo.UseShellExecute = $false
		#$ProcessStartMenu.StartInfo.WorkingDirectory = $scriptDirectory
		#$ProcessStartMenu.StartInfo.RedirectStandardError = $true
		#$ProcessStartMenu.StartInfo.RedirectStandardOutput = $true
		#$ProcessStartMenu.StartInfo.FileName = "PowerShell.exe"
		#$ProcessStartMenu.StartInfo.Arguments = "-File Check-WindowsLauncher.ps1"
		#$ProcessStartMenu.StartInfo.CreateNoWindow = $true
		#$ProcessStartMenu.Start()

		# Create array with commands to run
		$commands = @()

		$commands += {
			$TaskName = 'Schedule #3 created by enrollment client'
			Write-Host "Starting scheduled task '$TaskName' ..."
			Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' | Where-Object { $_.TaskName -eq $TaskName -and $_.State -eq 'Ready' } | Start-ScheduledTask
			while ( (Get-ScheduledTask -TaskName ($TaskName)).State  -ne 'Ready') {
						Write-Host "Waiting on scheduled task '$TaskName' ..."
			}
		}

		$commands += {

			$proc = "appidpolicyconverter"
			$i = 0
			$imax = 25
			$iwait = 250
			Write-Host "Waiting for process '$proc' to start..."
			while ($true) {
				$getprocess = Get-Process $proc -ErrorAction SilentlyContinue
				if ($getprocess -ne $null) {
					Write-Host "'$proc' has started."
					Wait-Process -Name $proc -Verbose
					break
				}
				if ($getprocess -eq $null -and $i -ge $imax) {
					Write-Host "process '$proc' was not running after $($imax * $iwait / 1000) seconds"
					break
				}
				Start-Sleep -Milliseconds $iwait 
				Write-Host "Waiting for process '$proc' to start..."
				$i++
			}

		}

		$commands += {
			param($ScriptLocation)

			Write-Host "Create Check Start Menu Job for User Context"
			$taskName = "Autopilot First Login - BlockStartMenu"
			#$action = New-ScheduledTaskAction -Execute "cmd" -Argument "/c start /min `"`" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptLocation\Check-WindowsLauncher.ps1`"" -WorkingDirectory $ScriptLocation
			#$action = New-ScheduledTaskAction -Execute "mshta" -Argument "vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"powershell -WindowStyle Hidden -ExecutionPolicy Bypass & '$ScriptLocation\Check-WindowsLauncher.ps1'`"`", 0:close`")" -WorkingDirectory $ScriptLocation
			$action = New-ScheduledTaskAction -Execute "mshta" -Argument "vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"powershell -ExecutionPolicy Bypass -Command & { Set-ExecutionPolicy Bypass -Scope Process; & '$ScriptLocation\Check-WindowsLauncher.ps1'}`"`", 0:close`")" -WorkingDirectory $ScriptLocation
			$trigger = New-ScheduledTaskTrigger -AtLogOn
			$principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -expand UserName)
			$Setting = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -MultipleInstances Parallel
			#$Setting.CimInstanceProperties.Item('MultipleInstances').Value = 3   # 3 corresponds to 'Stop the existing instance'
			$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal  -Settings $Setting
			Register-ScheduledTask $taskName -InputObject $task -Force | Start-ScheduledTask
			Start-Sleep -Seconds 10
			Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
		}

	
		Start-Transcript -Path "$($userObject.ProfilePath)\AppData\Local\Temp\EnrollmentSync.log" -Verbose

		Write-Host "User profile language is: $($userObject.UILanguage)"

		$startedAt = [datetime]::UtcNow
		Write-Host "Start Jobs"
		$jobs = $commands | Foreach-Object { Start-Job -ScriptBlock $_ -ArgumentList $scriptDirectory }
		
		Receive-Job $jobs -Wait -AutoRemoveJob
		Write-Host "All jobs completed. Total runtime in secs.: $(([datetime]::UtcNow - $startedAt).TotalSeconds)"

		# Check if reg key already exists
		$RegPath | ForEach-Object { if (!(Test-Path $_)) { New-Item $_ -Force | Out-Null } }

		# Set Reg Key after first sync completed
		New-ItemProperty -Path $RegPath -Name 'FirstLoginSync' -Value (Get-Date -Format "dd-MM-yyyy HH:mm") -PropertyType String -Force | Out-Null
		
		# Lauch Toast Notification to adive user to restart
		# Execute-ProcessAsUser -Path $fileToStart -Parameters "-show"
		
		Write-Host "First Login Script is exiting with return code 0"
		
		# Is waiting for exit line in log file
		$ProcessRunSpace.WaitForExit()

		Write-Host "Kill PowerShell Process to stop Start Menu"
		Get-CimInstance -ClassName Win32_Process -filter "name = 'powershell.exe' and commandLine like '%Check-WindowsLauncher.ps1%'" | ForEach-Object {Get-Process -Id $_.ProcessID | Stop-Process -Force}

		#$ProcessStartMenu.Kill()

		Add-Type -AssemblyName System.Windows.Forms
		if($ProcessRunSpace.ExitCode -eq 0){
			#Show-DialogBox -Title 'Setup Complete' -Text 'Setup has completed. Please click OK and restart your computer.' -Icon 'Information' | Out-Null
			[System.Windows.Forms.MessageBox]::Show("Setup has completed. Please click OK and restart your computer.","Setup Complete",0) | Out-Null
		}
		if($ProcessRunSpace.ExitCode -eq 1){
			#Show-DialogBox -Title 'Setup Complete' -Text 'Setup has completed. Your machine will automatically be rebooted.' -Icon 'Information' | Out-Null
			[System.Windows.Forms.MessageBox]::Show("Setup has completed. Your machine will automatically be rebooted.","Setup Complete",0) | Out-Null
		}	

		Stop-Transcript -Verbose

	}
}