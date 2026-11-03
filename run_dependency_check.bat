@echo off
REM ============================================================
REM  Dependency-Check Automation - run a scan
REM
REM  Double-click for a normal run: it asks for Project Name / Application
REM  Code / Environment per application and keeps the window open at the end.
REM
REM  The scheduled task (see setup_schedule.bat) runs this with --scheduled:
REM  no prompts, no pause, output appended to reports\_logs\scheduled_runs.log,
REM  and the tool's exit code passed on so Task Scheduler shows failures.
REM
REM  Uses run_dependency_check.exe when it sits next to this file (portable
REM  release); otherwise Python from .venv (see scripts\setup_venv.bat).
REM ============================================================
setlocal
set "HERE=%~dp0"
cd /d "%HERE%"

set "SCHEDULED="
echo %* | findstr /I /C:"--scheduled" >nul && set "SCHEDULED=1"

if not defined SCHEDULED goto :interactive

set "LOG=%HERE%reports\_logs\scheduled_runs.log"
if not exist "%HERE%reports\_logs" mkdir "%HERE%reports\_logs"
REM Keep the log from growing forever: roll it over at ~5 MB.
if exist "%LOG%" for %%F in ("%LOG%") do if %%~zF GTR 5000000 move /y "%LOG%" "%LOG%.old" >nul
call :launch %* >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%

:interactive
call :launch %*
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
