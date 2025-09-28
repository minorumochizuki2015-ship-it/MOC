@echo off
chcp 65001 >nul
echo ========================================
echo Unity Hub Quick Installer
echo ========================================
echo.

echo [INFO] Opening Unity Hub download page...
start "" "https://unity.com/download"
echo.

echo [INFO] Unity Hub download steps:
echo 1. Click "Download Unity Hub" button
echo 2. Run the downloaded installer
echo 3. Follow installation wizard
echo 4. Launch Unity Hub after installation
echo.

echo [INFO] After Unity Hub installation:
echo 1. Sign in or create Unity account
echo 2. Install Unity Editor (recommended: 2022.3 LTS)
echo 3. Select modules: Android Build Support, Windows Build Support
echo 4. Open project from: %~dp0data\clone_generation\UnityProject
echo.

echo [INFO] Project location:
echo %~dp0data\clone_generation\UnityProject
echo.

echo [INFO] Opening project folder...
if exist "%~dp0data\clone_generation\UnityProject" (
    explorer "%~dp0data\clone_generation\UnityProject"
    echo [SUCCESS] Project folder opened
) else (
    echo [ERROR] Project folder not found!
    echo Please check if the Unity project was generated correctly.
)
echo.

echo [INFO] Opening setup guide...
if exist "%~dp0unity_setup_guide.md" (
    start "" "%~dp0unity_setup_guide.md"
    echo [SUCCESS] Setup guide opened
) else (
    echo [WARNING] Setup guide not found
)
echo.

echo ========================================
echo Next Steps:
echo 1. Download and install Unity Hub from the opened webpage
echo 2. Install Unity Editor 2022.3 LTS
echo 3. Open the Unity project from the opened folder
echo 4. Press Play button in Unity Editor to test the game
echo ========================================
echo.

pause