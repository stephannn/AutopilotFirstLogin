Const ForReading = 1
Const ForWriting = 2
Const ForAppending = 8

Dim installdir, files, file, i, ag, strText, strCL, arrCLall

Set WshShell = CreateObject ("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strCL = Session.Property("CustomActionData")
arrCLall = Split(strCL, "|", -1, 1)

installdir = arrCLall(0)
files = Split(arrCLall(1), ",", -1, 1)

For each file in files

    Set objFile = objFSO.OpenTextFile(installdir & file, ForReading)
    strText = objFile.ReadAll
    objFile.Close

    Set objFile = objFSO.OpenTextFile(installdir & file, ForWriting)
	strNewText1 = Replace(strText, "[INSTALLDIR]", installdir)  
    objFile.WriteLine strNewText1
    objFile.Close
Next