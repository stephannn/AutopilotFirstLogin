# Calls the script that creates the OS upgrade background into a runspace, one per detected screen
Param(
    [Parameter(Mandatory=$true)]
	$ProfilePath,
    [string]$defaultUserCulture = "en-US",
    [ValidateSet("0","1")]
    [int]$multiLanguageSupport
)
#Write-Host "Create Runspace $multiLanguageSupport"
Write-Host "defaultUserCulture: $defaultUserCulture"
Write-Host "multiLanguageSupport: $multiLanguageSupport"
Add-Type -AssemblyName System.Windows.Forms
$Screens = [System.Windows.Forms.Screen]::AllScreens
$Jobs = @()

Foreach ($Screen in $screens) { 
    $ScriptBlock = {
        param($ScriptLocation, $DeviceName, $ProfilePath, $defaultUserCulture, $multiLanguageSupport)
		#$ExePath = "$ScriptLocation\Create-FullScreenBackground.ps1"
		#$parm = @("-DeviceName `"$DeviceName`"", "-ProfilePath `"$ProfilePath`"")
		#$cmd = "& '$ExePath' $($parm -join " ")" 
		#Write-Host $cmd
        # powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Write-Host "Hello"; $cmd; Write-Host $LASTEXITCODE" 
		#-Command "`"""$ScriptLocation\Create-FullScreenBackground.ps1`""" -DeviceName $DeviceName -ProfilePath $ProfilePath; ; Write-Host "BLOCK: $LastExitCode"; exit $LastExitCode"
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'Output', Justification = 'used as dummy')]
		$Output = & powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$ScriptLocation\Create-FullScreenBackground.ps1" -DeviceName $DeviceName -ProfilePath $ProfilePath -defaultUserCulture $defaultUserCulture -multiLanguageSupport $multiLanguageSupport 

		$LASTEXITCODE
    }

    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $PSScriptRoot, $Screen.DeviceName, $ProfilePath, $defaultUserCulture, $multiLanguageSupport
    $Jobs += $Job
}

# Wait for jobs to complete
$Jobs | Wait-Job

$ReturnCodes = $null
$Jobs | ForEach-Object {
    $Job = $_
    $ReturnCodes += Receive-Job -Job $Job
    Remove-Job -Job $Job
	#Write-Host "ECX: $ReturnCodes"
}

exit $ReturnCodes