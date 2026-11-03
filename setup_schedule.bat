@echo off
REM ============================================================
REM  Registers (or updates) the Windows Scheduled Task that runs the scan
REM  unattended, using the SCHEDULE_* settings in config\config.txt.
REM  Run once per machine, and again after changing those settings.
REM ============================================================
setlocal
set "HERE=%~dp0"
cd /d "%HERE%"

call :launch --setup-schedule
set "RC=%ERRORLEVEL%"
echo.
echo ============================================================
echo  Press any key to close this window.
echo ============================================================
pause >nul
exit /b %RC%

:launch
if exist "%HERE%run_dependency_check.exe" (
    "%HERE%run_dependency_check.exe" %*
    exit /b
)
set "PY=python"
for %%V in (virtual venv .venv) do if exist "%HERE%%%V\Scripts\python.exe" set "PY=%HERE%%%V\Scripts\python.exe"
"%PY%" -m depcheck_automation %*
exit /b
