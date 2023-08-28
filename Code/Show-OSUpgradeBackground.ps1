Param(
	[Parameter(Mandatory=$true)]
	$ProfilePath,
    [string]$defaultUserCulture = "en-US",
    [bool]$multiLanguageSupport = $true
)
# Create a new PS process to call the "Show-OSUpgradeBackground" script, to avoid blocking the continuation of task sequence

$Process = New-Object System.Diagnostics.Process
$Process.StartInfo.UseShellExecute = $false
$Process.StartInfo.FileName = "PowerShell.exe"
$Process.StartInfo.Arguments = " -File ""$PSScriptRoot\Create-Runspaces.ps1"" -ProfilePath ""$ProfilePath"" -defaultUserCulture $defaultUserCulture -multiLanguageSupport $([int]($multiLanguageSupport))"
$Process.StartInfo.CreateNoWindow = $true
$Process.StartInfo.RedirectStandardOutput = $true
$Process.Start() | Out-Null

$Process.WaitForExit()
$Process.StandardOutput.ReadToEnd()