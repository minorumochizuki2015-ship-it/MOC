@echo off
setlocal
cd /d "%~dp0"

echo ========================================
echo Governing Core AI v5 - Modern UI
echo ========================================
echo.

set "OPENAI_COMPAT_BASE=http://127.0.0.1:8080/v1"
set "OPENAI_API_KEY=sk-local"
set "PYTHONPATH=%CD%"
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

echo [1/3] Searching Python...
set PYTHON_CMD=
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=python
    echo OK: Python command found
) else (
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe
        echo OK: Python312 found
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe
        echo OK: Python311 found
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
        set PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python310\python.exe
        echo OK: Python310 found
    ) else (
        echo ERROR: Python not found
        pause
        exit /b 1
    )
)

echo [2/3] Checking CustomTkinter...
"%PYTHON_CMD%" -c "import customtkinter; print('CustomTkinter OK')" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo WARN: CustomTkinter not found, installing...
    "%PYTHON_CMD%" -m pip install customtkinter
)

echo [3/3] Launching Modern UI...
echo.
echo ========================================
echo Governing Core AI v5 - Modern Interface
echo ========================================
echo.

"%PYTHON_CMD%" -X utf8 -u main_modern.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Governing Core AI launch error
    echo Error code: %ERRORLEVEL%
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Governing Core AI terminated normally
pause