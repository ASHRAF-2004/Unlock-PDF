@echo off
echo [=== PDF Password Cracker Example ===]
echo.

if not exist dual_password_cracker.exe (
    echo ERROR: Compiled executable not found!
    echo Please run compile.bat first
    pause
    exit /b 1
)

echo Running cracker with example files...
echo.

dual_password_cracker.exe passwords\passwordlist.txt test_files\file.pdf

pause