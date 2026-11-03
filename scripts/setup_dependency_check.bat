@echo off
REM ============================================================
REM  Downloads OWASP dependency-check into tools\dependency-check - where
REM  config.template.txt's DEPCHECK_BIN_FOLDER points - so a fresh copy of
REM  the tool (a git clone, say) needs no hand-made install. The download is
REM  pinned to one release and checked against its published SHA-256.
REM
REM      scripts\setup_dependency_check.bat                  install if missing
REM      scripts\setup_dependency_check.bat --reinstall      replace it, keeping its NVD data
REM      scripts\setup_dependency_check.bat --zip "<file>"   from a zip downloaded by hand
REM
REM  Needs Python (the .venv from scripts\setup_venv.bat, or any Python 3.9+),
REM  or run_dependency_check.exe in the portable release. Java 11+ is needed
REM  to RUN dependency-check.
REM ============================================================
setlocal
cd /d "%~dp0.."
set "HERE=%CD%\"

call :launch --install-dependency-check %*
set "RC=%ERRORLEVEL%"
echo %* | findstr /I /C:"--no-pause" >nul || pause
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
