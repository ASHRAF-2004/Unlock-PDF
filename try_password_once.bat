@echo off
setlocal ENABLEDELAYEDEXPANSION

rem Ensure we are running from the repository root
pushd "%~dp0" >nul

set "BUILD_DIR=build"
set "TARGET=pdf_password_retriever"
set "BUILD_TYPE=Release"
set "PDF="
set "PASSWORD="
set "THREADS="
set "NOPAUSE=0"
set "EXIT_CODE=0"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--pdf" (
    shift
    if "%~1"=="" (
        echo Missing value for --pdf
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "PDF=%~1"
    shift
    goto parse_args
)
if /I "%~1"=="--password" (
    shift
    if "%~1"=="" (
        echo Missing value for --password
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "PASSWORD=%~1"
    shift
    goto parse_args
)
if /I "%~1"=="--threads" (
    shift
    if "%~1"=="" (
        echo Missing value for --threads
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "THREADS=%~1"
    shift
    goto parse_args
)
if /I "%~1"=="--build-dir" (
    shift
    if "%~1"=="" (
        echo Missing value for --build-dir
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "BUILD_DIR=%~1"
    shift
    goto parse_args
)
if /I "%~1"=="--debug" (
    set "BUILD_TYPE=Debug"
    shift
    goto parse_args
)
if /I "%~1"=="--no-pause" (
    set "NOPAUSE=1"
    shift
    goto parse_args
)
echo Unknown option: %~1
set "EXIT_CODE=1"
goto cleanup

:args_done

if not defined PDF (
    set /p PDF=Enter the full path to the encrypted PDF: 
)

if not exist "%PDF%" (
    echo PDF "%PDF%" not found.
    set "EXIT_CODE=1"
    goto cleanup
)

if not defined PASSWORD (
    for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "Read-Host -Prompt 'Enter the password to try'"`) do set "PASSWORD=%%I"
)

if not defined PASSWORD (
    echo No password supplied.
    set "EXIT_CODE=1"
    goto cleanup
)

set "TEMP_WORDLIST=%TEMP%\unlock_pdf_single_password.txt"

powershell -NoProfile -Command "Set-Content -LiteralPath '%TEMP_WORDLIST%' -Value $env:PASSWORD -Encoding UTF8"
if errorlevel 1 (
    echo Failed to write the temporary password file.
    set "EXIT_CODE=1"
    goto cleanup_with_wordlist
)

cmake -S . -B "%BUILD_DIR%" -A x64 -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo CMake configuration failed.
    set "EXIT_CODE=1"
    goto cleanup_with_wordlist
)

cmake --build "%BUILD_DIR%" --config %BUILD_TYPE%
if errorlevel 1 (
    echo Build failed.
    set "EXIT_CODE=1"
    goto cleanup_with_wordlist
)

set "EXEC=%BUILD_DIR%\%TARGET%.exe"
if not exist "%EXEC%" set "EXEC=%BUILD_DIR%\%BUILD_TYPE%\%TARGET%.exe"

if not exist "%EXEC%" (
    echo Could not locate %TARGET%.exe in build directories.
    set "EXIT_CODE=1"
    goto cleanup_with_wordlist
)

if defined THREADS (
    "%EXEC%" --pdf "%PDF%" --wordlist "%TEMP_WORDLIST%" --threads %THREADS%
) else (
    "%EXEC%" --pdf "%PDF%" --wordlist "%TEMP_WORDLIST%"
)
set "EXIT_CODE=%errorlevel%"

echo.
if %EXIT_CODE% EQU 0 (
    echo Finished. Exit code 0 (success).
) else (
    echo Finished. Exit code %EXIT_CODE%.
)

:cleanup_with_wordlist
if exist "%TEMP_WORDLIST%" del "%TEMP_WORDLIST%" >nul 2>nul

:cleanup
if not "%NOPAUSE%"=="1" (
    echo.
    pause
)

popd >nul
endlocal & exit /b %EXIT_CODE%