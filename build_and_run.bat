@echo off
setlocal enabledelayedexpansion

rem Ensure we are running from the repository root
pushd "%~dp0" >nul

set "BUILD_DIR=build"
set "TARGET=pdf_password_retriever"
set "WORDLIST=passwordlist.txt"
set "PDF=file.pdf"
set "EXIT_CODE=0"
set "BUILD_TYPE=Release"
set "NOPAUSE=0"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--wordlist" (
    shift
    if "%~1"=="" (
        echo Missing value for --wordlist
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "WORDLIST=%~1"
    shift
    goto parse_args
)
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

if not exist "%WORDLIST%" (
    echo Wordlist "%WORDLIST%" not found.
    set "EXIT_CODE=1"
    goto cleanup
)

if not exist "%PDF%" (
    echo PDF "%PDF%" not found.
    set "EXIT_CODE=1"
    goto cleanup
)

cmake -S . -B "%BUILD_DIR%" -A x64 -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo CMake configuration failed.
    set "EXIT_CODE=1"
    goto cleanup
)

cmake --build "%BUILD_DIR%" --config %BUILD_TYPE%
if errorlevel 1 (
    echo Build failed.
    set "EXIT_CODE=1"
    goto cleanup
)

set "EXEC=%BUILD_DIR%\%TARGET%.exe"
if exist "%EXEC%" (
    "%EXEC%" --pdf "%PDF%" --wordlist "%WORDLIST%"
    set "EXIT_CODE=%errorlevel%"
    goto cleanup
)

set "EXEC=%BUILD_DIR%\%BUILD_TYPE%\%TARGET%.exe"
if exist "%EXEC%" (
    "%EXEC%" --pdf "%PDF%" --wordlist "%WORDLIST%"
    set "EXIT_CODE=%errorlevel%"
    goto cleanup
)

echo Could not locate %TARGET%.exe in build directories.
set "EXIT_CODE=1"

goto cleanup

:cleanup
if not "%NOPAUSE%"=="1" (
    echo.
    pause
)
popd >nul
endlocal & exit /b %EXIT_CODE%
