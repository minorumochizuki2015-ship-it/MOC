@echo off
chcp 65001 >nul
echo Unity Project Test Starting...

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM Check if Unity project exists
if not exist "data\clone_generation\UnityProject" (
    echo Error: Unity project not found!
    echo Please run the clone generation first.
    pause
    exit /b 1
)

echo Unity Project Test Menu
echo ========================
echo 1. Run project structure test
echo 2. Run comprehensive project validation
echo 3. Create additional scenes and prefabs
echo 4. Open Unity project folder
echo 5. Show test results
echo 6. Exit
echo.

set /p choice="Select option (1-6): "

if "%choice%"=="1" (
    echo Running project structure test...
    python test_unity_project.py
) else if "%choice%"=="2" (
    echo Running comprehensive validation...
    python test_improved_system.py
) else if "%choice%"=="3" (
    echo Creating additional scenes and prefabs...
    python create_simple_unity_scene.py
) else if "%choice%"=="4" (
    echo Opening Unity project folder...
    explorer "data\clone_generation\UnityProject"
) else if "%choice%"=="5" (
    echo Showing test results...
    if exist "data\test_outputs\unity_project_test_results.json" (
        type "data\test_outputs\unity_project_test_results.json"
    ) else (
        echo No test results found. Please run tests first.
    )
    echo.
    if exist "data\test_outputs\unity_project_field_test_report.md" (
        echo === Field Test Report ===
        type "data\test_outputs\unity_project_field_test_report.md"
    )
) else if "%choice%"=="6" (
    echo Exiting...
    exit /b 0
) else (
    echo Invalid choice. Please select 1-6.
)

echo.
pause