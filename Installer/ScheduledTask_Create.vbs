On Error Resume Next

set fso = CreateObject ("Scripting.FileSystemObject")
Set WshShell = CreateObject("Wscript.Shell")

strCL = Session.Property("CustomActionData")
args = Split(strCL, "|", -1, 1)

installdir = args(0)
TaskTree = args(1)
TaskName = args(2)
TaskXml = installdir & "" & args(3)

'Create Task
strexe = "schtasks.exe /Create /XML " & chr(34) & TaskXml & chr(34) & " /tn " & chr(34) & TaskTree & "\" & TaskName & chr(34)
'MsgBox strexe
WshShell.Run strexe, 0, true 	

'Set Permisson
strperm = "powershell.exe -command " & chr(34) & "$TaskTree = '" & TaskTree & "'; $TaskName = '" & TaskName & "'; $TaskXml = '" & TaskXml & "'; $scheduler = New-Object -ComObject 'Schedule.Service'; $scheduler.Connect(); $task = $scheduler.GetFolder($TaskTree).GetTask($TaskName); $sec = $task.GetSecurityDescriptor(0xF); $sec = $sec + '(A;;GRGX;;;AU)'; $task.SetSecurityDescriptor($sec, 0);" & chr(34)
'MsgBox strperm
WshShell.Run strperm, 0, true 