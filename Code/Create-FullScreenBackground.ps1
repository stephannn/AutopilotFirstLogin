# Creates a full screen 'background' styled for a Windows 10 upgrade, and hides the task bar
# Called by the "Show-OSUpgradeBackground" script

Param(
	[object]$DeviceName,
    [Parameter(Mandatory=$true)]
	[string]$ProfilePath,
    [string]$defaultUserCulture = "en-US",
    [ValidateSet("0","1")]
    [int]$multiLanguageSupport = 1
)

# Get Script location
if ($PSScriptRoot.Length -eq 0) {
    $Scriptlocation = (get-location).path
} else {
    $Scriptlocation = $PSScriptRoot
}

function Get-UserLanguage
{
  param(
	[string]$Scriptlocation,
    [bool]$MultiLanguageSupport = $true,
    [string]$defaultUserCulture
  )
    $Config = Join-Path ($Scriptlocation) "config.language.xml"

    if(Test-Path $Config){
        $userCulture = try { (Get-UICulture).Name } catch { Write-Log -Level Error -Message "Failed to get users local culture. This is used with the multilanguage option, which now might not work properly" }

        $Xml = [xml](Get-Content -Path $Config -Encoding UTF8)
        
        if ($MultiLanguageSupport -eq $true) {
                    if (-NOT[string]::IsNullOrEmpty($xml.Configuration.$userCulture)) {
                        Write-Verbose "Support for the users language culture found, localizing text using $userCulture"
                        $XmlLang = $xml.Configuration.$userCulture
                    }
                    # Else fallback to using default language "en-US"
                    elseif (-NOT[string]::IsNullOrEmpty($xml.Configuration.$defaultUserCulture)) {
                        Write-Verbose "No support for the users language culture found, using $defaultUserCulture as default fallback language"
                        $XmlLang = $xml.Configuration.$defaultUserCulture
                    }
                    else {
                        Write-Verbose "$defaultUserCulture not found language, using en-US"
                        $XmlLang = $xml.Configuration."en-US"
                    }
         }   
         elseif ($MultiLanguageSupport -eq $false -and (-NOT[string]::IsNullOrEmpty($xml.Configuration.$defaultUserCulture)) ) {
            Write-Verbose "MultiLanguageSupport is false but default language $defaultUserCulture exists"
            $XmlLang = $xml.Configuration.$defaultUserCulture
        }
            # Regardless of whatever might happen, always use "en-US" as language
         else {
            Write-Verbose "MultiLanguageSupport is false but default language $defaultUserCulture does not exist"
            $XmlLang = $xml.Configuration."en-US"
         }

        [array]$displayLanguage = @()
		
		# Load header text
		
		$displayObject = 'TextBottom'
        $displayLanguage += [pscustomobject][ordered]@{
                DisplayObject = $displayObject; Text = $XmlLang.Text | Where-Object {$_.Name -like $displayObject} | Where-Object { $_.PSobject.Properties.name -match '#text' } | Select-Object -ExpandProperty '#text'
            }

        $displayObject = 'RebootCheck'
        $displayLanguage += [pscustomobject][ordered]@{
                DisplayObject = $displayObject; Text = $XmlLang.Text | Where-Object {$_.Name -like $displayObject} | Where-Object { $_.PSobject.Properties.name -match '#text' } | Select-Object -ExpandProperty '#text'
            }

        $displayObject = 'TextArray'
        $displayLanguage += [pscustomobject][ordered]@{
                DisplayObject = $displayObject; Text = @($XmlLang.Rotation.Text) 
            }


    }

    return $displayLanguage
}

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Windows.Forms,System.Drawing,System.DirectoryServices.AccountManagement
Add-Type -Path "$Scriptlocation\bin\System.Windows.Interactivity.dll"
Add-Type -Path "$Scriptlocation\bin\ControlzEx.dll"
Add-Type -Path "$Scriptlocation\bin\MahApps.Metro.dll"

# Add custom type to hide the taskbar
# Thanks to https://stackoverflow.com/questions/25499393/make-my-wpf-application-full-screen-cover-taskbar-and-title-bar-of-window
$CSharpSource = @"
using System;
using System.Runtime.InteropServices;

public class Taskbar
{
    [DllImport("user32.dll")]
    private static extern int FindWindow(string className, string windowText);
    [DllImport("user32.dll")]
    private static extern int ShowWindow(int hwnd, int command);

    private const int SW_HIDE = 0;
    private const int SW_SHOW = 1;

    protected static int Handle
    {
        get
        {
            return FindWindow("Shell_TrayWnd", "");
        }
    }

    private Taskbar()
    {
        // hide ctor
    }

    public static void Show()
    {
        ShowWindow(Handle, SW_SHOW);
    }

    public static void Hide()
    {
        ShowWindow(Handle, SW_HIDE);
    }
}
"@
Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $CSharpSource -Language CSharp

# Add custom type to prevent the screen from sleeping
$code=@' 
using System;
using System.Runtime.InteropServices;

public class DisplayState
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]
    public static extern void SetThreadExecutionState(uint esFlags);

    public static void KeepDisplayAwake()
    {
        SetThreadExecutionState(
            0x00000002 | 0x80000000);
    }

    public static void Cancel()
    {
        SetThreadExecutionState(0x80000000);
    }
}
'@
Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $code -Language CSharp

# Load the main window XAML code
[XML]$Xaml = [System.IO.File]::ReadAllLines("$Scriptlocation\Xaml\SplashScreen.xaml") 

# Create a synchronized hash table and add the WPF window and its named elements to it
$UI = [System.Collections.Hashtable]::Synchronized(@{})
$UI.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml))
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | 
    ForEach-Object -Process {
        $UI.$($_.Name) = $UI.Window.FindName($_.Name)
    }

# Find screen by DeviceName
$Screens = [System.Windows.Forms.Screen]::AllScreens
$Screen = $Screens | Where-Object {$_.DeviceName -eq $DeviceName}
#$Screen =  [System.Windows.Forms.Screen]::PrimaryScreen
# Get the bounds of the primary screen
$script:Bounds = $Screen.Bounds

# Load Language
[array]$displayLanguage = Get-UserLanguage -Scriptlocation $Scriptlocation -MultiLanguageSupport $multiLanguageSupport -defaultUserCulture $defaultUserCulture

[int]$TimerInterval = 10 #1 # 10
[int]$FadeAnimation = 3 #1 # 3
[int]$ColourAnimation = 5 #2 #5
[int]$Script:i = 1

[int]$global:ExitCode = 0

# An array of sentences to display, in order. Leave the first one blank as the 0 index gets skipped.
$TextArray = @("") + ($displayLanguage | Where-Object {$_.DisplayObject -eq "TextArray"}).Text 

# Set some initial values
$UI.CheckBox_Reboot.isChecked = $true
$UI.MainTextBlock.MaxWidth = $Bounds.Width
#$UI.TextBlock2.MaxWidth = $Bounds.Width
#$UI.TextBlock3.MaxWidth = $Bounds.Width
$UI.TextBlock4.MaxWidth = $Bounds.Width
#$UI.TextBlock2.Text = "Windows Setup Progress 0%"
#$UI.TextBlock3.Text = "00:00:00"
$UI.TextBlock4.Text = ($displayLanguage | Where-Object {$_.DisplayObject -eq "TextBottom"}).Text
$UI.CheckBox_Reboot.Content = ($displayLanguage | Where-Object {$_.DisplayObject -eq "RebootCheck"}).Text

$UI.MainTextBlock.Text = $TextArray[1]

# Create some animations
$FadeinAnimation = [System.Windows.Media.Animation.DoubleAnimation]::new(0,1,[System.Windows.Duration]::new([Timespan]::FromSeconds($FadeAnimation)))
$FadeOutAnimation = [System.Windows.Media.Animation.DoubleAnimation]::new(1,0,[System.Windows.Duration]::new([Timespan]::FromSeconds($FadeAnimation)))
$ColourBrighterAnimation = [System.Windows.Media.Animation.ColorAnimation]::new("#012a47","#1271b5",[System.Windows.Duration]::new([Timespan]::FromSeconds($ColourAnimation)))
$ColourDarkerAnimation = [System.Windows.Media.Animation.ColorAnimation]::new("#1271b5","#012a47",[System.Windows.Duration]::new([Timespan]::FromSeconds($ColourAnimation)))


# Start a dispatcher timer. This is used to control when the sentences are changed.
$TimerCode = { 

    if(Test-Path -Path "$($ProfilePath)\AppData\Local\Temp\EnrollmentSync.log" ){
	    if (Get-Content -Path "$($ProfilePath)\AppData\Local\Temp\EnrollmentSync.log" -Tail 6 | Select-String -Pattern "First Login Script is exiting with return code" -SimpleMatch){
            Write-host "Script finised, closing UI" -ForegroundColor Green
		    $UI.Window.Close()
        }
    }
	
	if($i -ge ($TextArray.Count )){
		$script:i = 0
		Start-Sleep -Milliseconds 500
	}
	
    # The IF statement number should equal the number of sentences in the TextArray
    If ($i -lt ($TextArray.Count))
    {
        $FadeoutAnimation.Add_Completed({            
            $UI.MaintextBlock.Opacity = 0
            $UI.MaintextBlock.Text = $TextArray[$i] #+ $i + "!!!" + $TextArray.Count + "|||" + $($script:i)
            $UI.MaintextBlock.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)

        })   
        $UI.MaintextBlock.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeoutAnimation) 
    }
    # The final sentence to display ongoing
    #ElseIf ($i -eq ($TextArray.Count + 1))
    #{
        
        # $FadeoutAnimation.Add_Completed({            
            # $UI.MaintextBlock.Opacity  = 0
            # $UI.MaintextBlock.Text = "Windows 10 Upgrade in Progress"
            # $UI.MaintextBlock.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
            # $UI.ProgressRing.IsActive = $True

        # })   
        # $UI.MaintextBlock.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeoutAnimation)
    #}

    $ColourBrighterAnimation.Add_Completed({            
        $UI.Window.Background.BeginAnimation([System.Windows.Media.SolidColorBrush]::ColorProperty,$ColourDarkerAnimation)
    })
	
    $UI.Window.Background.BeginAnimation([System.Windows.Media.SolidColorBrush]::ColorProperty,$ColourBrighterAnimation)

    $Script:i++

}
$DispatcherTimer = New-Object -TypeName System.Windows.Threading.DispatcherTimer
$DispatcherTimer.Interval = [TimeSpan]::FromSeconds($TimerInterval)
$DispatcherTimer.Add_Tick($TimerCode)


$Stopwatch = New-Object System.Diagnostics.Stopwatch
$Stopwatch.Start()
# $TimerCode2 = {
    # $ProgressValue = Get-ItemProperty -Path HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress | Select -ExpandProperty SetupProgress -ErrorAction SilentlyContinue
    # $UI.TextBlock3.Text = "$($Stopwatch.Elapsed.Hours.ToString('00')):$($Stopwatch.Elapsed.Minutes.ToString('00')):$($Stopwatch.Elapsed.Seconds.ToString('00'))"
    # $UI.ProgressBar.Value  = $ProgressValue
    # $UI.TextBlock2.Text = "Windows Setup Progress $ProgressValue%"
# }
# $DispatcherTimer2 = New-Object -TypeName System.Windows.Threading.DispatcherTimer
# $DispatcherTimer2.Interval = [TimeSpan]::FromSeconds(1)
# $DispatcherTimer2.Add_Tick($TimerCode2)

# Event: Window loaded
$UI.Window.Add_Loaded({
    
    # Activate the window to bring it to the fore
    $This.Activate()

    # Fill the screen
    $This.Left = $Bounds.Left
    $This.Top = $Bounds.Top
    $This.Height = $Bounds.Height
    $This.Width = $Bounds.Width

    # Hide the taskbar
    [TaskBar]::Hide()

    # Hide the mouse cursor
    #[System.Windows.Forms.Cursor]::Hide()

    # Keep Display awake
    [DisplayState]::KeepDisplayAwake()
	
    # Begin animations
    $UI.MaintextBlock.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
    #$UI.TextBlock2.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
    #$UI.TextBlock3.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
    $UI.TextBlock4.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
    $UI.ProgressRing.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
    #$UI.ProgressBar.BeginAnimation([System.Windows.Controls.TextBlock]::OpacityProperty,$FadeinAnimation)
    $ColourBrighterAnimation.Add_Completed({            
        $UI.Window.Background.BeginAnimation([System.Windows.Media.SolidColorBrush]::ColorProperty,$ColourDarkerAnimation)
    })   
    $UI.Window.Background.BeginAnimation([System.Windows.Media.SolidColorBrush]::ColorProperty,$ColourBrighterAnimation)

})



# Event: Window closing (for testing)
$UI.Window.Add_Closing({

    # Restore the taskbar
    [Taskbar]::Show()

    # Restore the mouse cursor
    [System.Windows.Forms.Cursor]::Show()

    # Cancel keeping the display awake
    [DisplayState]::Cancel()

    $Stopwatch.Stop()
    $DispatcherTimer.Stop()
    #$DispatcherTimer2.Stop()
	
	# 1 = true; 0 = false
	#$global:ExitCode = ([int]($UI.CheckBox_Reboot.isChecked))

})

$UI.Window.Add_Closed({
	Write-Host "Closed"
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'ExitCode', Justification = 'variable is used in another scope')]
	$global:ExitCode = [int]("0x" + (([int]($UI.CheckBox_Reboot.isChecked))))

})
# Event: Close the window on right-click (for testing)
#$UI.Window.Add_MouseRightButtonDown({
#
#    $This.Close()
#
#})

# Display the window
$DispatcherTimer.Start()
#$DispatcherTimer2.Start()
$UI.Window.ShowDialog()

$LASTEXITCODE = $global:ExitCode
exit $global:ExitCode
