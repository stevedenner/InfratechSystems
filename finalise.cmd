@echo off
setlocal

:PROMPT

SET /P RESPONSE=This will generalise the image and shut it down ready for adding to the image library.  Are you sure you want to shut down now (Y/[N])?
IF /I "%RESPONSE%" NEQ "Y" GOTO END

sc config "wuauserv" start=disabled

Powershell -ExecutionPolicy Unrestricted  "Get-AppxPackage | Remove-AppxPackage"

C:\Windows\System32\Sysprep\Sysprep /generalize /shutdown /oobe /quiet



:END
endlocal

