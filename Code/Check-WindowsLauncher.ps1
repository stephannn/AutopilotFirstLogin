<#
    File:     Check-WindowsLauncher.ps1
    Version:  01.00.00
    Auther:   David Coulter (DCtheGeek)
    Purpose:  For Windows 8 / Server 2012, check if the Launcher (Start Screen) is active.
              If it is, send "Desktop"+Enter to show desktop.
    Comments: I'm still a PowerShell idiot.  If you have ideas to improve this, let me know!
              Also, special thanks to Kazun of the PowerShell forums for helping me figure out
              how to access IsLauncherVisible from PowerShell.

#>

# https://web.archive.org/web/20200603004235/https://gallery.technet.microsoft.com/Hide-Windows-8-Start-432bfb86
 
Try {
    Write-Host "Check-WindowsLauncher: Initializing AppVisible.App in C#."
    #Write-Progress -Activity "Check-WindowsLauncher..." -Status "Initializing AppVisible.App" -PercentComplete 40 -Id 1

# AppVisible Interface code, courtesy of Kazun (PowerShell Forums).
$code = @"
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AppVisible
{
	[ComImport, Guid("2246EA2D-CAEA-4444-A3C4-6DE827E44313"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAppVisibility {
		HRESULT GetAppVisibilityOnMonitor([In] IntPtr hMonitor, [Out] out MONITOR_APP_VISIBILITY pMode);
		HRESULT IsLauncherVisible([Out] out bool pfVisible);
		HRESULT Advise([In] IAppVisibilityEvents pCallback, [Out] out int pdwCookie);
		HRESULT Unadvise([In] int dwCookie);
	}

	public enum HRESULT : long {
		S_FALSE = 0x0001,
		S_OK = 0x0000,
		E_INVALIDARG = 0x80070057,
		E_OUTOFMEMORY = 0x8007000E
	}
	public enum MONITOR_APP_VISIBILITY {
		MAV_UNKNOWN = 0,         // The mode for the monitor is unknown
		MAV_NO_APP_VISIBLE = 1,
		MAV_APP_VISIBLE = 2
	}
	
	[ComImport, Guid("6584CE6B-7D82-49C2-89C9-C6BC02BA8C38"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAppVisibilityEvents {
		HRESULT AppVisibilityOnMonitorChanged(
			[In] IntPtr hMonitor,
			[In] MONITOR_APP_VISIBILITY previousMode,
			[In] MONITOR_APP_VISIBILITY currentMode);

		HRESULT LauncherVisibilityChange([In] bool currentVisibleState);
	}
		
	
	public class App 
	{		
		public static bool IsLauncherVisible()
		{
			Type tIAppVisibility = Type.GetTypeFromCLSID(new Guid("7E5FE3D9-985F-4908-91F9-EE19F9FD1514"));
			IAppVisibility appVisibility = (IAppVisibility)Activator.CreateInstance(tIAppVisibility);
			bool launcherVisible;
			HRESULT answer = appVisibility.IsLauncherVisible(out launcherVisible);
			return launcherVisible;
		}
	}
}
"@

    Add-Type -TypeDefinition $Code -Language CSharp

    while($true){
		If ([AppVisible.App]::IsLauncherVisible()) {
			Write-Host "Check-WindowsLauncher: IsLauncherVisible is True."
            (New-Object -ComObject "wscript.shell").SendKeys("^{ESC}")
            Start-Sleep -Seconds 1

			#Write-Progress -Activity "Check-WindowsLauncher..." -Status "Detected Launcher" -PercentComplete 60 -Id 1
			#Write-Host "Check-WindowsLauncher: Sending keystrokes...."
			#Write-Progress -Activity "Check-WindowsLauncher..." -Status "Closing Launcher" -PercentComplete 80 -Id 1
			#Add-Type -AssemblyName System.Windows.Forms
			#[System.Windows.Forms.SendKeys]::SendWait("Desktop~")
		} else {
			#Write-Host "Check-WindowsLauncher: IsLauncherVisible is False.  Nothing to do."
		}
        }

        Start-Sleep -Milliseconds 500
    }
Catch {
    Write-Error "Check-WindowsLauncher: Something bad happened."
    Write-Error $_
}
Finally	{
	Write-Host "Check-WindowsLauncher: Exiting..."
	#Write-Progress -Activity "Check-WindowsLauncher..." -Status "Done" -PercentComplete 100 -Id 1
}
 
