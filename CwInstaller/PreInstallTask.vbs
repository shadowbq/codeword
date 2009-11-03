
Function Kill()
	Set objShell = WScript.CreateObject( "WScript.Shell" )
	objShell.run "taskkill.exe -f -im CwAgent.exe",7,true
	Kill=1
	Exit Function
End Function

Kill()


