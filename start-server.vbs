Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")
root = fileSystem.GetParentFolderName(WScript.ScriptFullName)
command = "cmd.exe /c cd /d """ & root & """ && npm.cmd start >> """ & root & "\backend\server.log"" 2>&1"
shell.Run command, 0, False