' PDetector GUI launcher (no console window). Double-click to start.
Option Explicit
Dim sh, fso, dir, cmd
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
On Error Resume Next
sh.Run "pyw """ & dir & "\run_gui.pyw""", 0, False
If Err.Number <> 0 Then
  Err.Clear
  sh.Run "pythonw """ & dir & "\run_gui.pyw""", 0, False
End If
