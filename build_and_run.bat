@echo off
setlocal enabledelayedexpansion

rem Ensure we are running from the repository root
pushd "%~dp0" >nul

set BUILD_DIR=build
set TARGET=pdf_password_retriever
set WORDLIST=passwordlist.txt
set PDF=file.pdf
set EXIT_CODE=0

if not exist "%WORDLIST%" (
    echo Wordlist "%WORDLIST%" not found.
    set EXIT_CODE=1
    goto :cleanup
)

if not exist "%PDF%" (
    echo PDF "%PDF%" not found.
    set EXIT_CODE=1
    goto :cleanup
)

rem Configure the project (default generator)
cmake -S . -B %BUILD_DIR% -A x64
if errorlevel 1 (
    echo CMake configuration failed.
    set EXIT_CODE=1
    goto :cleanup
)

rem Build the project (Release configuration if available)
cmake --build %BUILD_DIR% --config Release
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

set EXEC=%BUILD_DIR%\%TARGET%.exe
if exist "%EXEC%" (
    "%EXEC%" "%WORDLIST%" "%PDF%"
    set EXIT_CODE=%errorlevel%
    goto :cleanup
)

set EXEC=%BUILD_DIR%\Release\%TARGET%.exe
if exist "%EXEC%" (
    "%EXEC%" "%WORDLIST%" "%PDF%"
    set EXIT_CODE=%errorlevel%
    goto :cleanup
)

echo Could not locate %TARGET%.exe in build directories.
set EXIT_CODE=1

goto :cleanup

:cleanup
popd >nul
endlocal & exit /b %EXIT_CODE%
