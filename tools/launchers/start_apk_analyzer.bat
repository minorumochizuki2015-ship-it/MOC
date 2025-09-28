@echo off
chcp 65001 >nul
echo APK Analysis App Starting...

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM Install required dependencies
echo Installing required dependencies...
python -m pip install --quiet customtkinter lxml xmltodict pefile capstone pyelftools

REM Start Python app
echo Starting application...
python start_apk_analyzer.py

pause
