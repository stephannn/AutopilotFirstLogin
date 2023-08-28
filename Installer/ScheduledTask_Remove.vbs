On Error Resume Next

set fso = CreateObject ("Scripting.FileSystemObject")
Set WshShell = CreateObject("Wscript.Shell")

strCL = Session.Property("CustomActionData")
args = Split(strCL, "|", -1, 1)

installdir = args(0)
TaskName = args(1)

'Remove Task
strperm = "powershell.exe -command " & chr(34) & "Unregister-ScheduledTask -TaskName " & "'" & TaskName & "'" & " -Confirm:$False" & chr(34) 
'MsgBox strperm
WshShell.Run strperm, 0, true 


