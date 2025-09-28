@echo off
chcp 65001 >nul
echo Unity Clone Generation Test
echo ============================

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

echo.
echo Starting Unity project tests...
echo.

REM Test Unity project validation
echo [1/3] Running Unity project validation...
call python test_unity_project.py
if %errorlevel% neq 0 (
    echo Error in Unity project validation!
    pause
    exit /b 1
)

echo.
echo [2/3] Creating Unity scenes and prefabs...
call python create_simple_unity_scene.py
if %errorlevel% neq 0 (
    echo Error in scene creation!
    pause
    exit /b 1
)

echo.
echo [3/3] Generating test summary...
echo Unity Project Test Summary > data\test_outputs\simple_test_summary.txt
echo ========================== >> data\test_outputs\simple_test_summary.txt
echo Test Date: %date% %time% >> data\test_outputs\simple_test_summary.txt
echo. >> data\test_outputs\simple_test_summary.txt

if exist "data\test_outputs\unity_project_test_results.json" (
    echo Unity Project Validation: PASSED >> data\test_outputs\simple_test_summary.txt
) else (
    echo Unity Project Validation: FAILED >> data\test_outputs\simple_test_summary.txt
)

if exist "data\clone_generation\UnityProject\Assets\Scenes\MainScene.unity" (
    echo Scene Creation: PASSED >> data\test_outputs\simple_test_summary.txt
) else (
    echo Scene Creation: FAILED >> data\test_outputs\simple_test_summary.txt
)

echo. >> data\test_outputs\simple_test_summary.txt
echo Unity project is ready for testing! >> data\test_outputs\simple_test_summary.txt

echo.
echo ========================================
echo 🎉 Unity project test completed!
echo ========================================
echo.
echo Test results saved to: data\test_outputs\simple_test_summary.txt
echo Unity project location: data\clone_generation\UnityProject
echo.
echo Next steps:
echo 1. Open Unity Editor (2022.3.0f1 or later)
echo 2. Open project: data\clone_generation\UnityProject
echo 3. Open scene: Assets\Scenes\MainScene.unity
echo 4. Press Play button to test the game
echo 5. Use WASD keys + Space for controls
echo.

REM Open Unity project folder
echo Opening Unity project folder...
start "" "data\clone_generation\UnityProject"

pause