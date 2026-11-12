@echo off
REM ============================================================
REM  Creates the tool's own Python environment (.venv) and installs what
REM  this copy needs:
REM    - a developer checkout (requirements\dev.txt exists): runtime + tests
REM    - a deployed package: requirements\runtime.txt only
REM
REM  Safe to re-run. Pass --recreate to delete .venv and start over - needed
REM  after moving/copying the whole folder, because a venv remembers the path
REM  it was created at.
REM
REM  Needs Python 3.9+ installed (the "py" launcher or "python" on PATH).
REM ============================================================
setlocal
cd /d "%~dp0.."
set "VENV=%CD%\.venv"
set "VPY=%VENV%\Scripts\python.exe"

echo %* | findstr /I /C:"--recreate" >nul && if exist "%VENV%" (
    echo Removing the old .venv ...
    rmdir /s /q "%VENV%"
)

if exist "%VPY%" goto :install

set "BASE="
where py >nul 2>nul && set "BASE=py -3"
if not defined BASE where python >nul 2>nul && set "BASE=python"
if not defined BASE (
    echo ERROR: no Python found. Install Python 3.9 or newer from https://www.python.org
    echo        ^(tick "Add python.exe to PATH"^), then run this again.
    goto :failed
)
echo Creating .venv with: %BASE%
%BASE% -m venv "%VENV%" || goto :failed

:install
"%VPY%" -c "import sys" >nul 2>nul || (
    echo ERROR: .venv exists but its Python does not start - it was probably created
    echo        in another folder. Run:  scripts\setup_venv.bat --recreate
    goto :failed
)

set "REQ=requirements\runtime.txt"
if exist "requirements\dev.txt" set "REQ=requirements\dev.txt"
echo Installing %REQ% ...
"%VPY%" -m pip install --disable-pip-version-check -q -r "%REQ%" || goto :failed

echo.
echo ============================================================
echo  .venv is ready: "%VENV%"
echo  run_dependency_check.bat uses it automatically.
echo ============================================================
goto :done

:failed
echo.
echo ============================================================
echo  SETUP FAILED - see the messages above.
echo ============================================================
set "FAILED=1"

:done
echo %* | findstr /I /C:"--no-pause" >nul || pause
if defined FAILED exit /b 1
exit /b 0
