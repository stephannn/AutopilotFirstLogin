<#
.SYNOPSIS

PSAppDeployToolkit - Provides the ability to extend and customise the toolkit by adding your own functions that can be re-used.

.DESCRIPTION

This script is a template that allows you to extend the toolkit with your own custom functions.

This script is dot-sourced by the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.

PSApppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2023 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham and Muhammad Mashwani).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.EXAMPLE

powershell.exe -File .\AppDeployToolkitHelp.ps1

.INPUTS

None

You cannot pipe objects to this script.

.OUTPUTS

None

This script does not generate any output.

.NOTES

.LINK

https://psappdeploytoolkit.com
#>


[CmdletBinding()]
Param (
)

##*===============================================
##* VARIABLE DECLARATION
##*===============================================

# Variables: Script
[string]$appDeployToolkitExtName = 'PSAppDeployToolkitExt'
[string]$appDeployExtScriptFriendlyName = 'App Deploy Toolkit Extensions'
[version]$appDeployExtScriptVersion = [version]'3.9.2'
[string]$appDeployExtScriptDate = '02/02/2023'
[hashtable]$appDeployExtScriptParameters = $PSBoundParameters

##*===============================================
##* FUNCTION LISTINGS
##*===============================================

# <Your custom functions go here>

Function Write-Branding {
<#
.SYNOPSIS
	Writes a new package detection key
.DESCRIPTION
	Writes a new package detection key using detection base variable
.EXAMPLE
	Write-Branding 
.PARAMETER
.NOTES
	 
#>
	[CmdletBinding()]
	Param (
	)
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

		$RegPackages = "$RegDetectionPath"
		$RegPackageName = "$($appVendor)_$($appName)_$($appVersion)_$($appLang)_$($appArch)_$($appRevision)"
		$RegPackageKey = "$($RegPackages)\$RegPackageName"
	}
	Process {
		If (-not(Test-Path $RegPackageKey)) { New-Item -Path $RegPackageKey -Force }

		$RegPackageItems = Get-ChildItem -Path $RegPackageKey -Force
		If ($RegPackageItems.Installed -eq "1") {
			# Detection key already exists
			Return 0
		}
		Else {
			# Detection key doesn't exists
			Try {
				# Write new detection key
				Write-Log -Message "Write detection key for `"$RegPackageName`"" -Source ${CmdletName}
				New-ItemProperty -Path $RegPackageKey -Name "Installed" -Value "1" -PropertyType "String" -Force -ErrorAction Stop -ErrorVariable err
			}
			Catch [System.IO.IOException] {
				# Value exists
			}
			Catch [System.UnauthorizedAccessException] {
				# Missing permissions
				Return 1
			}
			Return 0
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}# End Write-Branding


Function Remove-Branding {
<#
.SYNOPSIS
	Removes old package detection key(s)
.DESCRIPTION
	Removes old package detection key(s) using detection base variable
.PARAMETER Old
.PARAMETER Package
.EXAMPLE
	Remove-Branding -Old
.EXAMPLE
	Remove-Branding -Package "Manufacturer_ProductName_*"
.NOTES
	 
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false)]
		[switch]$Old,
		[String]$Package
	)
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

		$RegPackages = "$RegDetectionPath"
		$RegPackageName = "$($appVendor)_$($appName)_$($appVersion)_$($appLang)_$($appArch)_$($appRevision)"
		$RegPackageKey = "$($RegPackages)\$RegPackageName"
	}
	Process {
		If ($Old.IsPresent) {
			# Remove detection key(s) if exist(s)
			Write-Log -Message "Search for detection key(s) `"$($appVendor)_$($appName)_*`"" -Source ${CmdletName}
			$RegItems = Get-ChildItem -LiteralPath $RegPackages -ErrorAction 'SilentlyContinue' | Where-Object { $_.PSChildName -Like "$($appVendor)_$($appName)_*" } | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'SilentlyContinue' } | Select-Object -ExpandProperty PSChildName -ErrorAction 'SilentlyContinue'
			ForEach ($RegItem in $RegItems) {
				Write-Log -Message "Remove detection key `"$RegItem`"" -Source ${CmdletName}
				Remove-RegistryKey -Key "$RegPackages\$RegItem" -Recurse
			}
		}
		ElseIf (-not([string]::IsNullOrEmpty($Package))) {
			# Remove detection key(s) if exist(s)
			Write-Log -Message "Search for detection key(s) `"$($Package)`"" -Source ${CmdletName}
			$RegItems = Get-ChildItem -LiteralPath $RegPackages -ErrorAction 'SilentlyContinue' | Where-Object { $_.PSChildName -Like "$($Package)" } | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'SilentlyContinue' } | Select-Object -ExpandProperty PSChildName -ErrorAction 'SilentlyContinue'
			ForEach ($RegItem in $RegItems) {
				Write-Log -Message "Remove detection key `"$RegItem`"" -Source ${CmdletName}
				Remove-RegistryKey -Key "$RegPackages\$RegItem" -Recurse
			}
		}
		Else {
			If (Test-Path $RegPackageKey) {
				# Detection key exists
				Try {
					Write-Log -Message "Remove detection key `"$RegPackageName`"" -Source ${CmdletName}
					Remove-Item -Path $RegPackageKey -Force -ErrorAction Stop -ErrorVariable err
				}
				Catch [System.IO.IOException] {
					# Value no longer exists
				}
				Catch [System.UnauthorizedAccessException] {
					# Missing permissions
					Return 1
				}
				Return 0
			}
			Else {
				# Detection key doesn't exists
				Return 0
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}# End Remove-Branding


Function Get-UninstallString {
<#
.SYNOPSIS
    Schreibt den Uninstallstring in eine Variable oder als Consolen Output
.DESCRIPTION
    Lese die Uninstall RegistryKeys aus und Ermittle anhand des Angegeben Displaynamens den UninstallString
.EXAMPLE
    $UninstallString = Get-UninstallString "Reader"
.PARAMETER SoftwareName
    Softwarename wie er in der Registry steht oder ein Teil des Softwarenamens
#>
    param(
    [Parameter(Mandatory = $true)]
    [string]$SoftwareName = $null,
    [switch]$Exact = $false
    )

    Write-Log "Suche den Uninstallstring für $SoftwareName"
    $UninstallObjects = @()
    If ($Exact -eq $false) {
        $RegItems = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
            Get-ItemProperty |
                Where-Object {$_.DisplayName -match "$SoftwareName"} |
                    Select-Object -Property DisplayName, UninstallString, PSChildName
    }
    ElseIf ($Exact -eq $true) {
        $RegItems = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
            Get-ItemProperty |
                Where-Object {$_.DisplayName -eq "$SoftwareName"} |
                    Select-Object -Property DisplayName, UninstallString, PSChildName
    }
    If ($RegItems -eq $null) {
        Write-Log "Kein UninstallString gefunden"
        Return 1
    }
    Else {
        ForEach ($item in $RegItems ) {
            Write-Log "SoftwareName : $($item.DisplayName)"
            Write-Log "UninstallString : $($item.Uninstallstring)"
            Write-Log "ProductCode : $($item.PSChildName)"
            $tempItem = $item.UninstallString -replace "`"",""
            $UninstallObjects += New-Object PSObject -Property @{
                SoftwareName = $item.DisplayName
                UninstallString = $tempItem
                ProductCode = $item.PSChildName
            }
        }

        Write-Log "Folgende Uninstallstring wurden gefunden"
        ForEach($item In $UninstallObjects) {
            Write-Log "SoftwareName : $($UninstallObjects.SoftwareName)"
            Write-Log "UninstallString : $($UninstallObjects.UninstallString)"
            Write-Log "ProductCode : $($item.ProductCode)"
        }
        Return $UninstallObjects
    }
}# End Get-Uninstallstring


Function Set-ARPEntrys {
<#
.SYNOPSIS
    Schreibt die angegebenen ARP Einträge für NoModify NoUninstall NoRepair und / oder Systemkomponent
.DESCRIPTION
    Setze für den Angegebenen Registrypfad die Registry Einträge
.EXAMPLE
    $UninstallString = Set-ARPEntrys
#>
    param(
    [Parameter(Mandatory = $true)]
    [string]$RegKey = $null,
    [bool]$NoModify = $true,
    [bool]$NoRepair = $true,
    [bool]$NoRemove = $true,
    [bool]$SystemComponent = $false
    )

    Write-Log -Message "Schreibe ARP Einträge" -Source "Set-ARPEntrys"
    If($NoModify -eq $true) {
        Set-RegistryKey -Key $RegKey -Name NoModify -Value 1 -Type DWord
    }
    If($NoRemove -eq $true) {
        Set-RegistryKey -Key $RegKey -Name NoRemove -Value 1 -Type DWord
    }
    If($NoRepair -eq $true) {
        Set-RegistryKey -Key $RegKey -Name NoRepair -Value 1 -Type DWord
    }
    If($SystemComponent -eq $true) {
        Set-RegistryKey -Key $RegKey -Name SystemComponent -Value 1 -Type DWord
    }
}# End Set-ARPEntrys


Function Remove-AltBranding {
<#
.SYNOPSIS
    Loescht eventuelle altes Branding
.DESCRIPTION
    Liest den BITBW Branding RegistryKeys aus und ermittle anhand des angegeben AppNamen und AppVendor den BrandingString
.EXAMPLE
.PARAMETER
.NOTES
      
#>
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		$RegPakete = "HKLM:\SYSTEM\BITBW\Pakete"

		## eventuelles Branding entf.
		Write-Log -Message "Lese Branding $($appVendor)_$($appName)*" -Source ${CmdletName}
		$RegItems = Get-ChildItem -LiteralPath $RegPakete -ErrorAction 'SilentlyContinue' | Where-Object {$_.PSChildName -Like "$($appVendor)_$($appName)_*"} | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'SilentlyContinue'} | Select-Object -ExpandProperty PSChildName -ErrorAction 'SilentlyContinue'
		ForEach($RegItem in $RegItems){
			Write-Log -Message "Entferne $RegItem" -Source ${CmdletName}
			Remove-RegistryKey -Key "$RegPakete\$RegItem" -Recurse
		}
	}
	End {
		If ($PassThru) { Write-Output -InputObject $ExecuteResults }
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}# End Remove-AltBranding


Function Rerun-Service {
<#
.SYNOPSIS
	Rerun Service - Service Names needed
.DESCRIPTION
	Get session details for all local and RDP logged on users using Win32 APIs. Get the following session details:
	 NTAccount, UserName, DomainName, SessionId, SessionName, ConnectState, IsCurrentSession, IsConsoleSession, IsUserSession,
	 LogonTime, IdleTime, DisconnectTime, ClientName, ClientProtocolType, ClientDirectory, ClientBuildNumber
.EXAMPLE
	RerunSerice
.NOTES
       
#>
	[CmdletBinding()]
	param(
		[parameter(Mandatory=$true)]
		[String]$ServiceName
	)

	Do {
		Stop-Service -Name $ServiceName
		#Write-Host "Spooler angehalten"
		Start-Sleep -Seconds 5
		$ServiceStatus = Get-Service -Name $ServiceName
	}
	While($ServiceStatus.Status -eq 'Running')

	Do {
		Start-Service -Name $ServiceName
		Start-Sleep -Seconds 5
		#Write-Host "Spooler gestartet"
		$ServiceStatus = Get-Service -Name $ServiceName
	}
	While($ServiceStatus.Status -eq 'Stopped')

}# End Rerun-Service


#System Variablen während der Laufzeit Aktualiseren
Function Update-Environment {
    $locations = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
                 #"HKCU:\Environment"

    $locations | ForEach-Object {
        $k = Get-Item $_
        $k.GetValueNames() | ForEach-Object {
            $name  = $_
            $value = $k.GetValue($_)
            Set-Item -Path Env:\$name -Value $value
        }
    }
}# End Update-Environment


Function Extract-ZipFile {
<#
.SYNOPSIS
	This Function unzip the given File to a favorite Destination.
    !!!! ZIP Destination wil not removed !!!!
.DESCRIPTION
	Extract ZipFile from $dirFiles to Destination, will use 7-Zip otherwise Windows unzipping routine.
    Destination is the named Directorie on SystemDrive\Destination.
.EXAMPLE (default)
	Extract-ZipFile -ZipFile "Path\Zipfile" -Destination "Named Directory"
.NOTES
        19.01.2016
.LINK
"#>
    Param (
		[Parameter(Mandatory=$true)]
		[string]$ZipFile,
		[string]$ZipDestination = $null
	)

    $7Zip = Join-Path $env:ProgramFiles "7-Zip\7z.exe"

    If ($ZipDestination -eq "" -or $ZipDestination -eq $null) {
		$ZipDestination = "TempZip"
	}
    If ($ZipDestination -match ":") {
		$ZipCachePath = $ZipDestination
	}
    Else {
		$ZipCachePath = Join-Path $env:SystemDrive "$($ZipDestination)"
	}

    If (Test-Path $7Zip) {
        Write-Log "7-Zip ist vorhanden "
        Write-Log "Beginne Entpacken des Archives"

        New-Item -Path $ZipCachePath -ItemType Directory -Force
        $ZipLog = $configMSILogDir + "\" + $($PackageName) + "_ZipLog.log"
        #Set-Location $SystemDriveTemp
        ."$7Zip" x "$ZipFile" -o"$($ZipCachePath)" -r -y | Out-File $ZipLog -Append -Force

        If ($LASTEXITCODE -ne 0) {
            Write-Log "Es ist ein Fehler beim Entpacken aufgetreten"
            Exit-Script 1
        }
        Else {
            Write-Log "Archiv erfolgreich entpackt."
        }
    }
    Else {
        Write-Log "7-Zip ist nicht vorhanden, nutze Windows Bordmittel zum Entpacken"
        #Extract-ZIPFile -ZipFile $ZipArchiv -Destination $AutoDeskInstallerDir
        If (Test-Path($ZipFile)) {
		    $shellApplication = New-Object -com shell.application
		    $zipPackage = $shellApplication.NameSpace($ZipFile)
            If (!(Test-path $ZipDestination)) {
				New-Item -Path $ZipDestination -ItemType Directory -Force
			}
		    $destinationFolder = $shellApplication.NameSpace($ZipCachePath)
		    $destinationFolder.CopyHere($zipPackage.Items(), 0x14)
	    }
        Else {
            Write-Log "ZipFile nicht vorhanden."
            Exit-Script 1
        }
        #$ziplog = Join-Path $logDirectory "unzip.log"
        #Remove-File $ziplog
    }
    Return $ZipCachePath
}# End Extract-ZipFile


Function Start-Hardwareinventory {
<#
.Synopsis
    Client Hardwareinvnetur erzwingen
.DESCRIPTION
    Läßt den Client bei Aufruf der Funktion eine "Hardwareinventory - FULL" durch führen
.EXAMPLE
    Start-Hardwareinventory -HWinvArt Delta
.PARAMETER -HWinvArt
    FULL = Full HWinv  |  Delta = Only Delta  |  IDMIF = Expand, inclusive IDMIF Data.
.NOTES
	    30.06.2016
#>
    Param (
		[Parameter(Mandatory=$false)]
		[string]$HWinvArt = "FULL"
	)

    Switch ($($HWinvArt)) {
        "FULL"  {
            $HardwareInventoryID = '{00000000-0000-0000-0000-000000000001}'
            Write-Log "HWinv - FULL wird ausgeführt"
            $Art = "FULL"
        }
        "Delta" {
            $HardwareInventoryID = '{00000000-0000-0000-0000-000000000001}'
            Write-Log "HWinv - Delta wird ausgeführt"
            $Art = "Delta"
        }
        "IDMIF" {
            $HardwareInventoryID = '{00000000-0000-0000-0000-000000000001}'
            Write-Log "HWinv - IDMIF wird ausgeführt"
            $Art = "IDMIF"
        }
        default {
            $HardwareInventoryID = '{00000000-0000-0000-0000-000000000001}'
            Write-Log "Kein oder falscher Parameter >> HWinv - FULL wird ausgeführt"
            $Art = "FULL"
        }
    }

    $WMIobjStatus = $Null
    $WMIobjStatus = Get-WmiObject -Namespace 'Root\CCM\INVAGT' -Class 'InventoryActionStatus'

    If ($WMIobjStatus -ne $Null) {
        Get-WmiObject -Namespace 'Root\CCM\INVAGT' -Class 'InventoryActionStatus' -Filter "InventoryActionID='$HardwareInventoryID'" | Remove-WmiObject
        Write-Log "HWinv - WMI entsprechend gesetzt << $($Art) >>"

    }
    Else {
        Write-Log "!! Es ist keine SCCM-Client vorhanden, und somit auch kein entsprechendes WMI-Objekt !!"
    }

}# End Start-HardwareInventory


Function Get-LoggedOnUsers {
<#
.SYNOPSIS
	Show all logged on Userss
.DESCRIPTION
    Collect all logged on Users from WMIObject Win32_LogonSession by Computername
    Return UserObjectArray with Domain\User
.EXAMPLE (default)
	Get-LoggedOnUsers
.NOTES
        05.07.2016
"#>
    $UserObjectArray = @()
    $computername = $env:COMPUTERNAME
    $UserObjects = Get-WmiObject -Class Win32_LogonSession -ComputerName $computername

    ForEach ($item in $UserObjects ) {
        $LogonId = $item.__RELPATH -replace """", "'"
        $User = Get-WmiObject -ComputerName $computername -Query "ASSOCIATORS OF {$LogonId} WHERE ResultClass = Win32_Account"
        $UserObjectArray += $User.Caption
    }
    Return $UserObjectArray
}# End Get-LoggedOnUsers


Function Get-ADDomainSystem {
<#
.SYNOPSIS
    Get Domain by System.DirectoryServices.DirectoryEntry
.DESCRIPTION
    Get Domain by System.DirectoryServices.DirectoryEntry
    Return $DomainName
    No RSAT-Tools needed
.EXAMPLE
    Get-ADDomainSystem
.NOTES
        05.06.2016
#>
    [CmdletBinding()]
    [OutputType([int])]
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $DomainName = $objDomain.dc
    Return $DomainName
}# End Get-ADDomainSystem


Function Set-UserRights {
<#
.SYNOPSIS
	Sets Userrights to a given folder
.DESCRIPTION
	xxx
.PARAMETER Folder
	A string containing the folder where the userrights should be modified
.PARAMETER SID
	A string containing the SID of the User or group
.PARAMETER UserRights
	A string containing the rights (Read, Write, Modify)
.EXAMPLE
	Set-UserRights -Folder "C:\Temp\" -SID "S-1-5-32-545" -UserRights "Modify"
#>
	Param (
		[Parameter(Mandatory=$true)]
		[string]$Folder,
		[Parameter(Mandatory=$true)]
		[string]$SID,
		[Parameter(Mandatory=$true)]
		[string]$UserRights
	)

	$UserGroup = New-Object System.Security.Principal.SecurityIdentifier($SID)
	$UserRights = [System.Security.AccessControl.FileSystemRights]$UserRights
	$InheritanceFlag1 = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
	$InheritanceFlag2 = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
	$InheritanceFlag = $InheritanceFlag1 -bor $InheritanceFlag2
	$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
	$RuleType =[System.Security.AccessControl.AccessControlType]::Allow
	$Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($UserGroup, $UserRights, $InheritanceFlag, $PropagationFlag, $RuleType)

	$Acl = Get-Acl -Path $Folder
	$Acl.AddAccessRule($Rule)

	Try {
		Set-Acl $Folder -AclObject $Acl
		Return $true
	}
	Catch {
		Return $false
	}
}# End Set-UserRights


Function Remove-EmptyFolder {
<#
.SYNOPSIS
    loescht leere Verzeichnisse
.DESCRIPTION
    Loescht ein Verzeichnis, wenn sich dort keine Dateien befinden
.EXAMPLE
    Remove-EmptyFolder -Path "C:\temp"
.PARAMETER -Path gibt Verzeichnispfad an
#>
    Param (
    	[Parameter(Mandatory=$true)]
    	[string]$Path
    )

	If (Test-Path -LiteralPath $Path -PathType Container) {
		if ((get-childitem -path $Path -recurse -force | ?{ ! $_.PSIsContainer }) -eq $null){
			Write-Log -Message "CUSTOM MESSAGE Das Verzeichnis $Path wird geloescht"
			Remove-Folder -Path $Path
		}
		Else {
			Write-Log -Message "CUSTOM MESSAGE Das Verzeichnis $Path enthaelt noch Dateien. Verzeichnis wird nicht gelöscht."
		}
	}
	Else {
		Write-Log -Message "CUSTOM MESSAGE Das Verzeichnis $Path nicht vorhanden."
	}
}# End Remove-EmptyFolder


Function Execute-Installer
{
 #  
#$AppParameter+= [hashtable]@{SetupFile = "mzVaultSetup.exe"; SetupParameter = "-silent"; DisplayName = "ThermoFisher mzVault"; DisplayVersion = "2.3.45.15"; ProductCode = "{1C9C9F90-079F-4428-A7A7-0863F2A4C74E}"; UninstallExe = "msiexec"; UninstallParameter = "/x {1C9C9F90-079F-4428-A7A7-0863F2A4C74E} /qb"}
#$AppParameter+= [hashtable]@{SetupFile = "mzVaultSetup.msi"; SetupParameter = "INSTALLDIR=c:\Software"; Transforms="mz.mst"}

    param
    (
		[Parameter(Mandatory=$false)]
		[ValidateSet('Install','Reinstall','Uninstall')]
		[string]$Action = 'Install',
		[Parameter(Mandatory=$true,HelpMessage='Please enter either the path to the MSI/EXE file')]
		[array]$Path
	)

	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		
		[array]::Reverse($Path)#in Umgekehrter Reihenfolge deinstallieren

		If(($Action -eq 'Install') -or ($Action -eq 'Reinstall')){
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Vorhandene Versionen prüfen
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
			Write-Log -Message "$('#' * 40)" -Source ${CmdletName}
			Write-Log -Message "Installation" -Source ${CmdletName}
			Write-Log -Message "Pruefe vorhandene Installationen" -Source ${CmdletName}
			ForEach($Installer in $Path){
				If($Installer -is [System.Collections.Hashtable]){
					$SetupFile = $Installer.SetupFile
				}Else{
					$SetupFile = $Installer
				}

				If(-not ($Installer.Action)){
					$Installer.Action = $Action
				}
				Write-Log -Message "Action=$($Installer.Action)" -Source ${CmdletName}
				
				If($Installer.UninstallOnly -and (-not $Installer.Uninstall)){
					Write-Log -Message "Anwendung soll nur deinstallieren $SetupFile" -Source ${CmdletName}
				}Else{
					#MSI
					If([IO.Path]::GetExtension($SetupFile) -eq '.msi'){
						Write-Log -Message "MSI $SetupFile" -Source ${CmdletName}

						If($SetupFile -ne "dummy.msi"){
							#MSI-Pfad zusammensetzen
							If (Test-Path -LiteralPath (Join-Path -Path $dirFiles -ChildPath $SetupFile -ErrorAction 'SilentlyContinue') -PathType 'Leaf' -ErrorAction 'SilentlyContinue') {
								[string]$msiFile = Join-Path -Path $dirFiles -ChildPath $SetupFile
							}
							ElseIf (Test-Path -LiteralPath $SetupFile -ErrorAction 'SilentlyContinue') {
								[string]$msiFile = (Get-Item -LiteralPath $SetupFile).FullName
							}
							Else {
								Write-Log -Message "Failed to find MSI file [$SetupFile]." -Severity 3 -Source ${CmdletName}
								If (-not $ContinueOnError) {
									Throw "Failed to find MSI file [$SetupFile]."
								}
								Continue
							}

							#Properies aus MSI auslesen
							Try {
								[hashtable]$GetMsiTablePropertySplat = @{ Path = $msiFile; Table = 'Property'; ContinueOnError = $false }
								If ($transforms) { $GetMsiTablePropertySplat.Add( 'TransformPath', $transforms ) }
								$msiProperties = Get-MsiTableProperty @GetMsiTablePropertySplat
							}
							Catch {
								Write-Log -Message "Failed to get the Properties from the MSI file." -Source ${CmdletName}
							}
							Try {[string]$MSIProductName = $msiProperties | Select-Object -ExpandProperty 'ProductName' -ErrorAction 'Stop'}Catch{Write-Log -Message "Failed to get the ProductName from the MSI file." -Source ${CmdletName}}
							Try {[string]$MSIProductVersion = $msiProperties | Select-Object -ExpandProperty 'ProductVersion' -ErrorAction 'Stop'}Catch{Write-Log -Message "Failed to get the ProductVersion from the MSI file." -Source ${CmdletName}}
							Try {[string]$MSIManufacturer = $msiProperties | Select-Object -ExpandProperty 'Manufacturer' -ErrorAction 'Stop'}Catch{Write-Log -Message "Failed to get the Manufacturer from the MSI file." -Source ${CmdletName}}
							Try {[string]$ProductCode = $msiProperties | Select-Object -ExpandProperty 'ProductCode' -ErrorAction 'Stop'}Catch{Write-Log -Message "Failed to get the ProductCode from the MSI file." -Source ${CmdletName}}
							Write-Log -Message "MSIProductName=$MSIProductName" -Source ${CmdletName}
							Write-Log -Message "MSIProductVersion=$MSIProductVersion" -Source ${CmdletName}
							Write-Log -Message "MSIManufacturer=$MSIManufacturer" -Source ${CmdletName}
							Write-Log -Message "ProductCode=$ProductCode" -Source ${CmdletName}

							#Vorhandene MSI Installationen prüfen und bei Bedarf deinstallieren
							Write-Log -Message "Pruefe auf ProductCode" -Source ${CmdletName}
							If(Get-InstalledApplication -ProductCode $ProductCode){
								Write-Log -Message "MSI ist installiert" -Source ${CmdletName}
								If($Installer.Action -eq 'Reinstall'){
									Write-Log -Message "Action=Reinstall" -Source ${CmdletName}
									Write-Log -Message "Anwendung deinstallieren" -Source ${CmdletName}
									Execute-MSI -Action 'Uninstall' -Path $ProductCode
								}
							}
						}Else{
							Write-Log -Message "MSI soll bei der Installation nur deinstalliert werden. Setze Dummy-Version." -Source ${CmdletName}
							$MSIProductVersion = "2147483647.2147483647.2147483647.2147483647"
						}

						If($Installer.DisplayName){
							Write-Log -Message "Pruefe auf DisplayName" -Source ${CmdletName}
							if($Installer.IncludeUpdatesAndHotfixes){
								$InstalledApplication = Get-InstalledApplication -Name ($Installer.DisplayName) -RegEx:$true -IncludeUpdatesAndHotfixes
							}Else{
								$InstalledApplication = Get-InstalledApplication -Name ($Installer.DisplayName) -RegEx:$true
							}
						}ElseIf($Installer.ProductCode){
							Write-Log -Message "Pruefe auf ProductCode" -Source ${CmdletName}
							if($Installer.IncludeUpdatesAndHotfixes){
								$InstalledApplication = Get-InstalledApplication -ProductCode ($Installer.ProductCode) -IncludeUpdatesAndHotfixes
							}Else{
								$InstalledApplication = Get-InstalledApplication -ProductCode ($Installer.ProductCode)
							}
						}Else{
							Write-Log -Message "Pruefe auf ProductName" -Source ${CmdletName}
							if($Installer.IncludeUpdatesAndHotfixes){
								$InstalledApplication = Get-InstalledApplication -Name ([Regex]::Escape($MSIProductName)) -RegEx:$true -IncludeUpdatesAndHotfixes
							}Else{
								$InstalledApplication = Get-InstalledApplication -Name ([Regex]::Escape($MSIProductName)) -RegEx:$true
							}
						}
						
						If($InstalledApplication -is [System.Object]){
							Write-Log -Message "Eintraege fuer die Anwendung gefunden Datentyp = $($InstalledApplication.GetType().FullName)" -Source ${CmdletName}
							$InstalledApplication = $InstalledApplication | Select-Object -first 1
							Write-Log -Message "verwende ersten Eintrag" -Source ${CmdletName}
						}

						$Installer.Install = $true
						If($InstalledApplication){#Anwendung mit dem Namen ist Installiert
							Write-Log -Message "Anwendung ist installiert. Version=$($InstalledApplication.DisplayVersion)" -Source ${CmdletName}
							If ([System.Version]$($($InstalledApplication.DisplayVersion -replace "[A-Z]", "") -replace "[ ]", ".") -lt [System.Version]$($MSIProductVersion -replace "[A-Z]", "")){#Alte Versionen deinstallieren
								Write-Log -Message "Es wurde eine aeltere Version von $MSIProductName gefunden $($InstalledApplication.ProductCode) $($InstalledApplication.DisplayVersion) < $MSIProductVersion" -Source ${CmdletName}
								If($Installer.Action -eq 'Update'){
									Write-Log -Message "Action=Update" -Source ${CmdletName}
									Write-Log -Message "Vorgaengerversion wird nicht deinstalliert." -Source ${CmdletName}
								}Else{
									Write-Log -Message "Anwendung deinstallieren" -Source ${CmdletName}
									If($($InstalledApplication.ProductCode)){
										Write-Log -Message "Verwende ProductCode" -Source ${CmdletName}
										if($Installer.IncludeUpdatesAndHotfixes){
											Execute-MSI -Action 'Uninstall' -Path $($InstalledApplication.ProductCode) -IncludeUpdatesAndHotfixes
										}else{
											Execute-MSI -Action 'Uninstall' -Path $($InstalledApplication.ProductCode)
										}
									}Else{
										Write-Log -Message "ProductCode nicht gesetzt." -Source ${CmdletName}
										If(($Installer.UninstallExe) -and ($Installer.UninstallParameter)){
											Write-Log -Message "Verwende UninstallExe und UninstallParameter." -Source ${CmdletName}
											Execute-Process -Path ($Installer.UninstallExe) -Parameters ($Installer.UninstallParameter) -WindowStyle 'Hidden' -ContinueOnError $true
										}Else{
											Write-Log -Message "Parameter UninstallExe und UninstallParameter sind nicht gesetzt - keine Deinstallation" -Source ${CmdletName}
										}
									}
								}
							}Else{#Akutelle oder neuere Version nur bei Bedarf deinstallieren
								Write-Log -Message "Es wurde die gleiche oder eine neuere Version von $MSIProductName gefunden $($InstalledApplication.ProductCode) $($InstalledApplication.DisplayVersion) >= $MSIProductVersion" -Source ${CmdletName}
								If($Installer.Action -eq 'Reinstall'){
									Write-Log -Message "Action=Reinstall" -Source ${CmdletName}
									Write-Log -Message "Anwendung deinstallieren" -Source ${CmdletName}
									if($Installer.IncludeUpdatesAndHotfixes){
										Execute-MSI -Action 'Uninstall' -Path $($InstalledApplication.ProductCode) -IncludeUpdatesAndHotfixes
									}else{
										Execute-MSI -Action 'Uninstall' -Path $($InstalledApplication.ProductCode)
									}
								}Else{
									$Installer.Install = $false
								}
							}
						}
					}Else{#EXE
						If($Installer.DisplayName -and $Installer.DisplayVersion)
						{
							#Vorhandene Installationen prüfen und bei Bedarf deinstallieren
							Write-Log -Message "Pruefe auf DisplayName und DisplayVersion" -Source ${CmdletName}
							$InstalledApplication = Get-InstalledApplication -Name ($Installer.DisplayName) -RegEx:$true
							if($InstalledApplication -is [System.Object]){
								Write-Log -Message "Mehrere Eintraege fuer die Anwendung gefunden Datentyp = $($InstalledApplication.GetType().FullName)" -Source ${CmdletName}
								$InstalledApplication = $InstalledApplication | Select-Object -first 1
								Write-Log -Message "verwende ersten Eintrag" -Source ${CmdletName}
							}

							$Installer.Install = $true
							If($InstalledApplication){#Anwendung mit dem Namen ist Installiert
								$InstalledApplication.UninstallString = $($InstalledApplication.UninstallString) -replace """", ""
								if($InstalledApplication.DisplayVersion -eq ''){$InstalledApplication.DisplayVersion = '1.0'}
								Write-Log -Message "Anwendung ist installiert. Version=$($InstalledApplication.DisplayVersion)" -Source ${CmdletName}
								If ([System.Version]$($($InstalledApplication.DisplayVersion -replace "[A-Z]", "") -replace "[ ]", ".") -lt [System.Version]$($Installer.DisplayVersion -replace "[A-Z]", "")){#Alte Versionen deinstallieren
									Write-Log -Message "Es wurde eine aeltere Version von $($Installer.DisplayName) gefunden $($InstalledApplication.DisplayVersion) > $($Installer.DisplayVersion)" -Source ${CmdletName}
									If($Installer.Action -eq 'Update'){
										Write-Log -Message "Action=Update" -Source ${CmdletName}
										Write-Log -Message "Vorgaengerversion wird nicht deinstalliert." -Source ${CmdletName}
									}Else{
										Write-Log -Message "Anwendung deinstallieren" -Source ${CmdletName}
										If($Installer.UninstallExe){
											if((Test-Path -LiteralPath ($Installer.UninstallExe) -PathType Leaf) -or (Test-Path -LiteralPath "$envSystem32Directory\$($Installer.UninstallExe)" -PathType Leaf) -or (Test-Path -LiteralPath "$dirFiles\$($Installer.UninstallExe)" -PathType Leaf)){
												Write-Log -Message "Deinstalliere mit uebergebenen EXE" -Source ${CmdletName}
												$ExecuteEXE = "Execute-Process -Path ""$($Installer.UninstallExe)"" -WindowStyle 'Hidden'"
												if($Installer.UninstallParameter){$UninstallParameter = $Installer.UninstallParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$UninstallParameter"""}
												if($Installer.IgnoreExitCodesUninst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesUninst)"""}
												Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
												Invoke-Expression $ExecuteEXE
											}else{
												Write-Log -Message "UninstallExe nicht gefunden $($Installer.UninstallExe)" -Source ${CmdletName}
											}
										}elseif($InstalledApplication.UninstallString){
											if(Test-Path -LiteralPath ($InstalledApplication.UninstallString) -PathType "Leaf"){
												Write-Log -Message "Deinstalliere mit UninstallString" -Source ${CmdletName}
												$ExecuteEXE = "Execute-Process -Path ""$($InstalledApplication.UninstallString)"" -WindowStyle 'Hidden'"
												if($Installer.UninstallParameter){$UninstallParameter = $Installer.UninstallParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$UninstallParameter"""}
												if($Installer.IgnoreExitCodesUninst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesUninst)"""}
												Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
												Invoke-Expression $ExecuteEXE
											}else{
												Write-Log -Message "UninstallString nicht gefunden $($InstalledApplication.UninstallString)" -Source ${CmdletName}
											}
										}
									}
								}else{#Akutelle oder neuere Version nur bei Bedarf deinstallieren
									Write-Log -Message "Es wurde die gleiche oder neuere Version von $($Installer.DisplayName) gefunden $($InstalledApplication.DisplayVersion) >= $($Installer.DisplayVersion)" -Source ${CmdletName}
									if($Installer.Action -eq 'Reinstall'){
										Write-Log -Message "Action=Reinstall" -Source ${CmdletName}
										Write-Log -Message "Anwendung deinstallieren" -Source ${CmdletName}
										if($Installer.ProductCode){#Für den Fall, dass in der Exe ein MSI steckt, kann mit ProductCode deinstalliert werden.
											Write-Log -Message "ProductCode $($Installer.ProductCode) gesetzt. Deinstalliere mit ProductCode." -Source ${CmdletName}
											Execute-MSI -Action "Uninstall" -Path ($Installer.ProductCode)
										}else{
											if($Installer.UninstallExe){
												if((Test-Path -LiteralPath ($Installer.UninstallExe) -PathType Leaf) -or (Test-Path -LiteralPath "$envSystem32Directory\$($Installer.UninstallExe)" -PathType Leaf) -or (Test-Path -LiteralPath "$dirFiles\$($Installer.UninstallExe)" -PathType Leaf)){
													Write-Log -Message "Deinstalliere mit uebergebenen EXE" -Source ${CmdletName}
													$ExecuteEXE = "Execute-Process -Path ""$($Installer.UninstallExe)"" -WindowStyle 'Hidden'"
													if($Installer.UninstallParameter){$UninstallParameter = $Installer.UninstallParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$UninstallParameter"""}
													if($Installer.IgnoreExitCodesUninst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesUninst)"""}
													Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
													Invoke-Expression $ExecuteEXE
												}else{
													Write-Log -Message "UninstallExe nicht gefunden $($Installer.UninstallExe)" -Source ${CmdletName}
												}
											}elseif($InstalledApplication.UninstallString){
												if(Test-Path -LiteralPath ($InstalledApplication.UninstallString) -PathType "Leaf"){
													Write-Log -Message "Deinstalliere mit UninstallString" -Source ${CmdletName}
													$ExecuteEXE = "Execute-Process -Path ""$($InstalledApplication.UninstallString)"" -WindowStyle 'Hidden'"
													if($Installer.UninstallParameter){$UninstallParameter = $Installer.UninstallParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$UninstallParameter"""}
													if($Installer.IgnoreExitCodesUninst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesUninst)"""}
													Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
													Invoke-Expression $ExecuteEXE
												}else{
													Write-Log -Message "UninstallString nicht gefunden $($InstalledApplication.UninstallString)" -Source ${CmdletName}
												}
											}
										}
									}else{
										$Installer.Install = $false
									}
								}
							}
						}else{
							$Installer.Install = $true#Installieren, wenn kein Erkennung möglich ist
						}
					}
				}
				Write-Log -Message "$('-' * 40)" -Source ${CmdletName}
			}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# UpdateCommand
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
			#Befehle zwischen Deinstallation der alten Version und Installation der neue Version ausführen
			foreach($Installer in $Path){
				if($Installer -is [System.Collections.Hashtable]){
					if($Installer.UpdateCommand -and $Installer.Install){
						Write-Log -Message "UpdateCommand=$($Installer.UpdateCommand)" -Source ${CmdletName}
						Invoke-Command -ScriptBlock ($Installer.UpdateCommand)
					}
				}
			}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Installation
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
			Write-Log -Message "$('#' * 40)" -Source ${CmdletName}
			Write-Log -Message "Installation ausfuehren" -Source ${CmdletName}

			[array]::Reverse($Path)#Reihenfolge für die Installation wieder drehen.
			#Installation ausführen
			foreach($Installer in $Path){
				if($Installer -is [System.Collections.Hashtable]){
					$SetupFile = $Installer.SetupFile
				}else{
					$SetupFile = $Installer
				}

				if($Installer.UninstallOnly){
					Write-Log -Message "Anwendung soll nur deinstallieren $SetupFile" -Source ${CmdletName}
				}else{
					if($Installer.Install){
						if([IO.Path]::GetExtension($SetupFile) -eq '.msi'){#MSI installieren
							$ExecuteMSI = "Execute-MSI -Action ""Install"" -Path ""$SetupFile"""
							if($Installer.SetupParameter){$SetupParameter = $Installer.SetupParameter -replace """",""""""; $ExecuteMSI+= " -Parameters ""$SetupParameter $configMSISilentParams"""}
							if($Installer.Transforms){$ExecuteMSI+= " -Transform ""$($Installer.Transforms)"""}
							Write-Log -Message "ExecuteMSI=$ExecuteMSI" -Source ${CmdletName}
							Invoke-Expression $ExecuteMSI
						}else{
							$ExecuteEXE = "Execute-Process -Path ""$SetupFile"" -WindowStyle 'Hidden'"
							if($Installer.SetupParameter){$SetupParameter = $Installer.SetupParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$SetupParameter"""}
							if($Installer.IgnoreExitCodesInst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesInst)"""}
							Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
							Invoke-Expression $ExecuteEXE
						}
					}else{
						Write-Log -Message "Anwendung bereits installiert $SetupFile" -Source ${CmdletName}
					}
				}
				Write-Log -Message "$('-' * 40)" -Source ${CmdletName}
			}

		}elseIf($Action -eq 'Uninstall'){
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Deinstallation
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
			Write-Log -Message "$('#' * 40)" -Source ${CmdletName}
			Write-Log -Message "Deinstallation" -Source ${CmdletName}
			foreach($Installer in $Path){
				if($Installer -is [System.Collections.Hashtable]){
					$SetupFile = $Installer.SetupFile
				}else{
					$SetupFile = $Installer
				}

				if($Installer.NoUninstall){
					Write-Log -Message "Anwendung soll nicht deinstalliert werden." -Source ${CmdletName}
				}else{
					if(([IO.Path]::GetExtension($SetupFile) -eq '.msi') -and ($SetupFile -ne "dummy.msi")){#MSI deinstallieren
						Write-Log -Message "MSI $SetupFile" -Source ${CmdletName}
							Execute-MSI -Action "Uninstall" -Path $SetupFile
					}else{#EXE deinstallieren
						if($Installer.ProductCode){#Für den Fall, dass in der Exe ein MSI steckt, kann mit ProductCode deinstalliert werden.
							Write-Log -Message "ProductCode $($Installer.ProductCode) gesetzt. Deinstalliere mit ProductCode." -Source ${CmdletName}
							Execute-MSI -Action "Uninstall" -Path ($Installer.ProductCode)
						}else{#Deinstallation der Anwendung nach Prüfung der Version
							if($Installer.DisplayName){
								Write-Log -Message "Pruefe auf ProductName" -Source ${CmdletName}
								$InstalledApplication = Get-InstalledApplication -Name ($Installer.DisplayName) -RegEx:$true
								if($InstalledApplication -is [System.Object]){
									Write-Log -Message "Eintraege fuer die Anwendung gefunden Datentyp = $($InstalledApplication.GetType().FullName)" -Source ${CmdletName}
									$InstalledApplication = $InstalledApplication | Select-Object -first 1
									Write-Log -Message "verwende ersten Eintrag" -Source ${CmdletName}
								}
								if($InstalledApplication){#Anwendung ist installiert
									if($InstalledApplication.DisplayVersion -eq ''){$InstalledApplication.DisplayVersion = '1.0'}
									Write-Log -Message "Anwendung ist installiert. Version=$($InstalledApplication.DisplayVersion)" -Source ${CmdletName}
									if ([System.Version]$($($InstalledApplication.DisplayVersion -replace "[A-Z]", "") -replace "[ ]", ".") -eq [System.Version]$($Installer.DisplayVersion -replace "[A-Z]", "")){#Nur wenn die Version stimmt, Deinstallation starten
										$InstalledApplication.UninstallString = $($InstalledApplication.UninstallString) -replace """", ""
										Write-Log -Message "Es wurde die gleiche Version von $($Installer.DisplayName) gefunden $($InstalledApplication.DisplayVersion)" -Source ${CmdletName}
										if($Installer.UninstallExe){
											if((Test-Path -LiteralPath ($Installer.UninstallExe) -PathType Leaf) -or (Test-Path -LiteralPath "$envSystem32Directory\$($Installer.UninstallExe)" -PathType Leaf) -or (Test-Path -LiteralPath "$dirFiles\$($Installer.UninstallExe)" -PathType Leaf)){
												Write-Log -Message "Anwendung mit UninstallExe deinstallieren" -Source ${CmdletName}
												$ExecuteEXE = "Execute-Process -Path ""$($Installer.UninstallExe)"" -WindowStyle 'Hidden'"
												if($Installer.UninstallParameter){$UninstallParameter = $Installer.UninstallParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$UninstallParameter"""}
												if($Installer.IgnoreExitCodesUninst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesUninst)"""}
												Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
												Invoke-Expression $ExecuteEXE
											}else{
												Write-Log -Message "UninstallExe nicht gefunden $($Installer.UninstallExe)" -Source ${CmdletName}
											}
										}elseif($InstalledApplication.UninstallString){
											if(Test-Path -LiteralPath ($InstalledApplication.UninstallString) -PathType Leaf){
												Write-Log -Message "Anwendung mit UninstallString deinstallieren" -Source ${CmdletName}
												$ExecuteEXE = "Execute-Process -Path ""$($InstalledApplication.UninstallString)"" -WindowStyle 'Hidden'"
												if($Installer.UninstallParameter){$UninstallParameter = $Installer.UninstallParameter -replace """",""""""; $ExecuteEXE+= " -Parameters ""$UninstallParameter"""}
												if($Installer.IgnoreExitCodesUninst){$ExecuteEXE+= " -IgnoreExitCodes ""$($Installer.IgnoreExitCodesUninst)"""}
												Write-Log -Message "ExecuteEXE=$ExecuteEXE" -Source ${CmdletName}
												Invoke-Expression $ExecuteEXE
											}else{
												Write-Log -Message "UninstallString nicht gefunden $($InstalledApplication.UninstallString)" -Source ${CmdletName}
											}
										}
									}else{
										Write-Log -Message "Es wurde andere Version von $ProductName gefunden $($InstalledApplication.DisplayVersion)" -Source ${CmdletName}
										Write-Log -Message "Keine Deinstalltaion" -Source ${CmdletName}
									}
								}
							}
						}
					}
				}
				Write-Log -Message "$('-' * 40)" -Source ${CmdletName}
			}
		}
	}
	End {
		If ($PassThru) { Write-Output -InputObject $ExecuteResults }
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}# End Execute-Installer


Function Execute-Process-DPInst {
<#
.SYNOPSIS
	Execute a process with optional arguments, working directory, window style.
.DESCRIPTION
	Executes a process, e.g. a file included in the Files directory of the App Deploy Toolkit, or a file on the local machine.
	Provides various options for handling the return codes (see Parameters).
.PARAMETER Path
	Path to the file to be executed. If the file is located directly in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.
	Otherwise, the full path of the file must be specified. If the files is in a subdirectory of "Files", use the "$dirFiles" variable as shown in the example.
.PARAMETER Parameters
	Arguments to be passed to the executable
.PARAMETER SecureParameters
	Hides all parameters passed to the executable from the Toolkit log file
.PARAMETER WindowStyle
	Style of the window of the process executed. Options: Normal, Hidden, Maximized, Minimized. Default: Normal.
	Note: Not all processes honor the "Hidden" flag. If it it not working, then check the command line options for the process being executed to see it has a silent option.
.PARAMETER CreateNoWindow
	Specifies whether the process should be started with a new window to contain it. Default is false.
.PARAMETER WorkingDirectory
	The working directory used for executing the process. Defaults to the directory of the file being executed.
.PARAMETER NoWait
	Immediately continue after executing the process.
.PARAMETER PassThru
	Returns ExitCode, STDOut, and STDErr output from the process.
.PARAMETER WaitForMsiExec
	Sometimes an EXE bootstrapper will launch an MSI install. In such cases, this variable will ensure that
	that this function waits for the msiexec engine to become available before starting the install.
.PARAMETER MsiExecWaitTime
	Specify the length of time in seconds to wait for the msiexec engine to become available. Default: 600 seconds (10 minutes).
.PARAMETER ContinueOnError
	Continue if an exit code is returned by the process that is not recognized by the App Deploy Toolkit. Default: $false.
.EXAMPLE
	Execute-Process-DPInst -Path 'uninstall_flash_player_64bit.exe' -Parameters '/uninstall' -WindowStyle 'Hidden'
	If the file is in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.
.EXAMPLE
	Execute-Process-DPInst -Path "$dirFiles\Bin\setup.exe" -Parameters '/S' -WindowStyle 'Hidden'
.EXAMPLE
	Execute-Process-DPInst -Path 'setup.exe' -Parameters "-s -f2`"$configToolkitLogDir\$installName.log`""
	Launch InstallShield "setup.exe" from the ".\Files" sub-directory and force log files to the logging folder.
.EXAMPLE
	Execute-Process-DPInst -Path 'setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$configToolkitLogDir\$installName.log`"`""
	Launch InstallShield "setup.exe" with embedded MSI and force log files to the logging folder.
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[Alias('FilePath')]
		[ValidateNotNullorEmpty()]
		[string]$Path,
		[Parameter(Mandatory=$false)]
		[Alias('Arguments')]
		[ValidateNotNullorEmpty()]
		[string[]]$Parameters,
		[Parameter(Mandatory=$false)]
		[switch]$SecureParameters = $false,
		[Parameter(Mandatory=$false)]
		[ValidateSet('Normal','Hidden','Maximized','Minimized')]
		[Diagnostics.ProcessWindowStyle]$WindowStyle = 'Normal',
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[switch]$CreateNoWindow = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$WorkingDirectory,
		[Parameter(Mandatory=$false)]
		[switch]$NoWait = $false,
		[Parameter(Mandatory=$false)]
		[switch]$PassThru = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WaitForMsiExec = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[timespan]$MsiExecWaitTime = $(New-TimeSpan -Seconds $configMSIMutexWaitTime),
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $false
	)

	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			$private:returnCode = $null

			## Validate and find the fully qualified path for the $Path variable.
			If (([IO.Path]::IsPathRooted($Path)) -and ([IO.Path]::HasExtension($Path))) {
				Write-Log -Message "[$Path] is a valid fully qualified path, continue." -Source ${CmdletName}
				If (-not (Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'Stop')) {
					Throw "File [$Path] not found."
				}
			}
			Else {
				#  The first directory to search will be the 'Files' subdirectory of the script directory
				[string]$PathFolders = $dirFiles
				#  Add the current location of the console (Windows always searches this location first)
				[string]$PathFolders = $PathFolders + ';' + (Get-Location -PSProvider 'FileSystem').Path
				#  Add the new path locations to the PATH environment variable
				$env:PATH = $PathFolders + ';' + $env:PATH

				#  Get the fully qualified path for the file. Get-Command searches PATH environment variable to find this value.
				[string]$FullyQualifiedPath = Get-Command -Name $Path -CommandType 'Application' -TotalCount 1 -Syntax -ErrorAction 'Stop'

				#  Revert the PATH environment variable to it's original value
				$env:PATH = $env:PATH -replace [regex]::Escape($PathFolders + ';'), ''

				If ($FullyQualifiedPath) {
					Write-Log -Message "[$Path] successfully resolved to fully qualified path [$FullyQualifiedPath]." -Source ${CmdletName}
					$Path = $FullyQualifiedPath
				}
				Else {
					Throw "[$Path] contains an invalid path or file name."
				}
			}

			## Set the Working directory (if not specified)
			If (-not $WorkingDirectory) { $WorkingDirectory = Split-Path -Path $Path -Parent -ErrorAction 'Stop' }

			## If MSI install, check to see if the MSI installer service is available or if another MSI install is already underway.
			## Please note that a race condition is possible after this check where another process waiting for the MSI installer
			##  to become available grabs the MSI Installer mutex before we do. Not too concerned about this possible race condition.
			If (($Path -match 'msiexec') -or ($WaitForMsiExec)) {
				[boolean]$MsiExecAvailable = Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds $MsiExecWaitTime.TotalMilliseconds
				Start-Sleep -Seconds 1
				If (-not $MsiExecAvailable) {
					#  Default MSI exit code for install already in progress
					[int32]$returnCode = 1618
					Throw 'Please complete in progress MSI installation before proceeding with this install.'
				}
			}

			Try {
				## Disable Zone checking to prevent warnings when running executables
				$env:SEE_MASK_NOZONECHECKS = 1

				## Using this variable allows capture of exceptions from .NET methods. Private scope only changes value for current function.
				$private:previousErrorActionPreference = $ErrorActionPreference
				$ErrorActionPreference = 'Stop'

				## Define process
				$processStartInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo' -ErrorAction 'Stop'
				$processStartInfo.FileName = $Path
				$processStartInfo.WorkingDirectory = $WorkingDirectory
				$processStartInfo.UseShellExecute = $false
				$processStartInfo.ErrorDialog = $false
				$processStartInfo.RedirectStandardOutput = $true
				$processStartInfo.RedirectStandardError = $true
				$processStartInfo.CreateNoWindow = $CreateNoWindow
				If ($Parameters) { $processStartInfo.Arguments = $Parameters }
				If ($windowStyle) { $processStartInfo.WindowStyle = $WindowStyle }
				$process = New-Object -TypeName 'System.Diagnostics.Process' -ErrorAction 'Stop'
				$process.StartInfo = $processStartInfo

				## Add event handler to capture process's standard output redirection
				[scriptblock]$processEventHandler = { If (-not [string]::IsNullOrEmpty($EventArgs.Data)) { $Event.MessageData.AppendLine($EventArgs.Data) } }
				$stdOutBuilder = New-Object -TypeName 'System.Text.StringBuilder' -ArgumentList ''
				$stdOutEvent = Register-ObjectEvent -InputObject $process -Action $processEventHandler -EventName 'OutputDataReceived' -MessageData $stdOutBuilder -ErrorAction 'Stop'

				## Start Process
				Write-Log -Message "Working Directory is [$WorkingDirectory]." -Source ${CmdletName}
				If ($Parameters) {
					If ($Parameters -match '-Command \&') {
						Write-Log -Message "Executing [$Path [PowerShell ScriptBlock]]..." -Source ${CmdletName}
					}
					Else {
						If ($SecureParameters) {
							Write-Log -Message "Executing [$Path (Parameters Hidden)]..." -Source ${CmdletName}
						}
						Else {
							Write-Log -Message "Executing [$Path $Parameters]..." -Source ${CmdletName}
						}
					}
				}
				Else {
					Write-Log -Message "Executing [$Path]..." -Source ${CmdletName}
				}
				[boolean]$processStarted = $process.Start()

				If ($NoWait) {
					Write-Log -Message 'NoWait parameter specified. Continuing without waiting for exit code...' -Source ${CmdletName}
				}
				Else {
					$process.BeginOutputReadLine()
					$stdErr = $($process.StandardError.ReadToEnd()).ToString() -replace $null,''

					## Instructs the Process component to wait indefinitely for the associated process to exit.
					$process.WaitForExit()

					## HasExited indicates that the associated process has terminated, either normally or abnormally. Wait until HasExited returns $true.
					While (-not ($process.HasExited)) { $process.Refresh(); Start-Sleep -Seconds 1 }

					## Get the exit code for the process
					Try {
						[int32]$returnCode = $process.ExitCode
					}
					Catch [System.Management.Automation.PSInvalidCastException] {
						#  Catch exit codes that are out of int32 range
						[int32]$returnCode = 60013
					}

					## Unregister standard output event to retrieve process output
					If ($stdOutEvent) { Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'; $stdOutEvent = $null }
					$stdOut = $stdOutBuilder.ToString() -replace $null,''

					If ($stdErr.Length -gt 0) {
						Write-Log -Message "Standard error output from the process: $stdErr" -Severity 3 -Source ${CmdletName}
					}
				}
			}
			Finally {
				## Make sure the standard output event is unregistered
				If ($stdOutEvent) { Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'}

				## Free resources associated with the process, this does not cause process to exit
				If ($process) { $process.Close() }

				## Re-enable Zone checking
				Remove-Item -LiteralPath 'env:SEE_MASK_NOZONECHECKS' -ErrorAction 'SilentlyContinue'

				If ($private:previousErrorActionPreference) { $ErrorActionPreference = $private:previousErrorActionPreference }
			}

			If (-not $NoWait) {
				## Check to see whether we should ignore exit codes
				$ignoreExitCodeMatch = $false
				#ExitCode for dpinst.exe #0xWWXXYYZZ
				#0xWW
					#If a package couldn’t be installed, this will be set to 0x80.
					#If a reboot is needed, its value will be 0x40.
					#Otherwise, it will be 0x00.
				#0xXX  Number of driver packages that could not be installed
				#0xYY  Number of driver packages that have been copied to the driver store but haven’t been installed on a device
				#0xZZ  Number of driver packages that have been installed on a device
				If ($returnCode -band 0x80000000) {
					Write-Log -Message "dpinst execution failed with exit code [$returnCode]." -Source ${CmdletName}
				}
				ElseIf ($returnCode -band 0x40000000) {
					Write-Log -Message "dbinst execution completed successfully with exit code [$returnCode]. A reboot is required." -Severity 2 -Source ${CmdletName}
					Set-Variable -Name 'msiRebootDetected' -Value $true -Scope 'Script'
					$ignoreExitCodeMatch = $true
				}
				Else {
					Write-Log -Message "dbinst execution completed successfully with exit code [$returnCode]." -Source ${CmdletName}
					$ignoreExitCodeMatch = $true
				}
				Write-Log -Message ([string](($returnCode -band 0x00ff0000) -shr 16) + " driver package(s) that could not be installed.")  -Source ${CmdletName}
				Write-Log -Message ([string](($returnCode -band 0x0000ff00) -shr 8) + " driver package(s) that have been copied to the driver store but haven’t been installed on a device.") -Source ${CmdletName}
				Write-Log -Message ([string]($returnCode -band 0x000000ff) + " driver package(s) that have been installed on a device.") -Source ${CmdletName}

				#  Or always ignore exit codes
				If ($ContinueOnError) { $ignoreExitCodeMatch = $true }

				## If the passthru switch is specified, return the exit code and any output from process
				If ($PassThru) {
					Write-Log -Message "Execution completed with exit code [$returnCode]." -Source ${CmdletName}
					[psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = $stdOut; StdErr = $stdErr }
					Write-Output -InputObject $ExecutionResults
				}
				ElseIf ($ignoreExitCodeMatch -or ($returnCode -eq 0)) {
					Write-Log -Message "Execution completed successfully with exit code [$returnCode]." -Source ${CmdletName}
				}
				Else {
					[string]$MsiExitCodeMessage = ''
					If ($Path -match 'msiexec') {
						[string]$MsiExitCodeMessage = Get-MsiExitCodeMessage -MsiExitCode $returnCode
					}

					If ($MsiExitCodeMessage) {
						Write-Log -Message "Execution failed with exit code [$returnCode]: $MsiExitCodeMessage" -Severity 3 -Source ${CmdletName}
					}
					Else {
						Write-Log -Message "Execution failed with exit code [$returnCode]." -Severity 3 -Source ${CmdletName}
					}
					Exit-Script -ExitCode $returnCode
				}
			}
		}
		Catch {
			If ([string]::IsNullOrEmpty([string]$returnCode)) {
				[int32]$returnCode = 60002
				Write-Log -Message "Function failed, setting exit code to [$returnCode]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
			Else {
				Write-Log -Message "Execution completed with exit code [$returnCode]. Function failed. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
			If ($PassThru) {
				[psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = If ($stdOut) { $stdOut } Else { '' }; StdErr = If ($stdErr) { $stdErr } Else { '' } }
				Write-Output -InputObject $ExecutionResults
			}
			Else {
				Exit-Script -ExitCode $returnCode
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}# End Execute-Process-DPInst

##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================

If ($scriptParentPath) {
    Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $appDeployToolkitExtName
}
Else {
    Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $appDeployToolkitExtName
}

##*===============================================
##* END SCRIPT BODY
##*===============================================
