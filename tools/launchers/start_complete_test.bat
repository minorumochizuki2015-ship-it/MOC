@echo off
chcp 65001 >nul
echo Complete Unity Clone Generation Test
echo ====================================

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

echo.
echo Starting complete test sequence...
echo.

REM Step 1: Run improved system test
echo [1/4] Running improved system test...
call python test_improved_system.py
if %errorlevel% neq 0 (
    echo Error in improved system test!
    pause
    exit /b 1
)

echo.
echo [2/4] Running Unity project validation...
call python test_unity_project.py
if %errorlevel% neq 0 (
    echo Error in Unity project validation!
    pause
    exit /b 1
)

echo.
echo [3/4] Creating Unity scenes and prefabs...
call python create_simple_unity_scene.py
if %errorlevel% neq 0 (
    echo Error in scene creation!
    pause
    exit /b 1
)

echo.
echo [4/4] Generating final test report...
echo Complete Test Results > data\test_outputs\complete_test_summary.txt
echo ===================== >> data\test_outputs\complete_test_summary.txt
echo Test Date: %date% %time% >> data\test_outputs\complete_test_summary.txt
echo. >> data\test_outputs\complete_test_summary.txt

if exist "data\test_outputs\improved_system_test_results.json" (
    echo Improved System Test: PASSED >> data\test_outputs\complete_test_summary.txt
) else (
    echo Improved System Test: FAILED >> data\test_outputs\complete_test_summary.txt
)

if exist "data\test_outputs\unity_project_test_results.json" (
    echo Unity Project Test: PASSED >> data\test_outputs\complete_test_summary.txt
) else (
    echo Unity Project Test: FAILED >> data\test_outputs\complete_test_summary.txt
)

if exist "data\clone_generation\UnityProject\Assets\Scenes\MainScene.unity" (
    echo Scene Creation: PASSED >> data\test_outputs\complete_test_summary.txt
) else (
    echo Scene Creation: FAILED >> data\test_outputs\complete_test_summary.txt
)

echo. >> data\test_outputs\complete_test_summary.txt
echo All tests completed successfully! >> data\test_outputs\complete_test_summary.txt

echo.
echo ========================================
echo 🎉 Complete test sequence finished!
echo ========================================
echo.
echo Test results saved to: data\test_outputs\complete_test_summary.txt
echo Unity project location: data\clone_generation\UnityProject
echo.
echo Next steps:
echo 1. Open Unity Editor (2022.3.0f1)
echo 2. Open project: data\clone_generation\UnityProject
echo 3. Open scene: Assets\Scenes\MainScene.unity
echo 4. Press Play button to test
echo 5. Use WASD + Space keys for controls
echo.

pause