@echo off
echo Unity Project Quick Launcher
echo ============================

echo.
echo Unity Project Location:
echo    %~dp0data\clone_generation\UnityProject
echo.

REM Open project folder
echo Opening project folder...
start "" "%~dp0data\clone_generation\UnityProject"

echo.
echo Unity Editor Launch Steps:
echo --------------------------
echo 1. Start Unity Hub
echo 2. Click "Open" or "Add project from disk"
echo 3. Select UnityProject from opened folder
echo 4. Unity Editor will open the project
echo 5. Double-click Assets/Scenes/MainScene.unity
echo 6. Press Play button to run the game
echo.
echo Controls:
echo   WASD keys: Move
echo   Space key: Jump
echo.

REM Try to launch Unity Hub
echo Trying to launch Unity Hub...
if exist "C:\Program Files\Unity Hub\Unity Hub.exe" (
    echo Starting Unity Hub...
    start "" "C:\Program Files\Unity Hub\Unity Hub.exe"
) else (
    echo Unity Hub not found
    echo Please start Unity Hub manually
)

echo.
echo Project Path for copy:
echo %~dp0data\clone_generation\UnityProject
echo.

pause