Const adModeReadWrite = 3
Const adTypeText = 2
Const adSaveCreateOverWrite = 2

Dim installdir, files, file, i, ag, strText, strCL, arrCLall

Set WshShell = CreateObject ("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strCL = Session.Property("CustomActionData")
arrCLall = Split(strCL, "|", -1, 1)

installdir = arrCLall(0)
files = Split(arrCLall(1), ",", -1, 1)

Sub SaveToFile(text, filename)
  With CreateObject("ADODB.Stream")
    .Mode = adModeReadWrite
    .Type = adTypeText
    .Charset = "UTF-16"
    .Open
    .WriteText text
    .SaveToFile filename, adSaveCreateOverWrite
    .Close
  End With
End Sub

For each file in files

	Set objSTREAM = CreateObject("ADODB.Stream")
	objSTREAM.CharSet = "utf-16"
	objSTREAM.Open
	objSTREAM.LoadFromFile(installdir & file)
	strDATA = objStream.ReadText()
	strNewText1 = Replace(strData, "[INSTALLDIR]", installdir ) 

	SaveToFile strNewText1, (installdir & file)
Next