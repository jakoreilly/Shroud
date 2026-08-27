@echo off
rem Builds and launches the shroud desktop UI (Shroud.Ui).
setlocal
cd /d "%~dp0"
dotnet run --project src\Shroud.Ui
endlocal
