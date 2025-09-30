@echo off
setlocal enabledelayedexpansion

rem Determine the directory containing this script.
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR%"=="" set "SCRIPT_DIR=.\"

pushd "%SCRIPT_DIR%" || goto :error

python -m pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] PyInstaller not found. Installing...
    python -m pip install --upgrade pyinstaller || goto :error
)

set "BINARY_PATH=..\build\pdf_password_retriever.exe"
if exist "%BINARY_PATH%" (
    set "EXTRA_BIN=--add-binary \"%BINARY_PATH%;.\""
    echo [INFO] Bundling pdf_password_retriever.exe from %BINARY_PATH%
) else (
    set "EXTRA_BIN="
    echo [WARN] Could not find pdf_password_retriever.exe in ..\build
    echo [WARN] The GUI executable will be built without the cracker binary.
    echo [WARN] Copy pdf_password_retriever.exe next to UnlockPDFGui.exe after packaging.
)

python -m pyinstaller --noconfirm --windowed --name UnlockPDFGui %EXTRA_BIN% unlock_pdf_gui.py || goto :error

echo.
echo [OK] Build complete. The packaged app is in dist\UnlockPDFGui\.
echo     Launch dist\UnlockPDFGui\UnlockPDFGui.exe to start the GUI.

popd
exit /b 0

:error
echo.
echo [ERROR] Packaging failed.
popd
exit /b 1
