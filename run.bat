@echo off
echo ========================================================
echo   Launching DOGE - Security Research Workstation
echo ========================================================
echo.

set EXE_PATH=%~dp0desktop\DOGE.Desktop\bin\Debug\net10.0-windows\DOGE.exe

if exist "%EXE_PATH%" (
    echo Starting DOGE Desktop Workstation...
    start "" "%EXE_PATH%"
) else (
    echo Building and launching DOGE Desktop...
    dotnet run --project "%~dp0desktop\DOGE.Desktop\DOGE.Desktop.csproj"
)
