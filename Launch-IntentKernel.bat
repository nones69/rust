@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\launch-intentkernel.ps1" %*
pause