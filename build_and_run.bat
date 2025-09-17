@echo off
setlocal enabledelayedexpansion

set BUILD_DIR=build
set TARGET=pdf_password_retriever

rem Configure the project (default generator)
cmake -S . -B %BUILD_DIR% -A x64
if errorlevel 1 (
    echo CMake configuration failed.
    exit /b 1
)

rem Build the project (Release configuration if available)
cmake --build %BUILD_DIR% --config Release
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

set EXEC=%BUILD_DIR%\%TARGET%.exe
if exist "%EXEC%" (
    "%EXEC%" %*
    goto :eof
)

set EXEC=%BUILD_DIR%\Release\%TARGET%.exe
if exist "%EXEC%" (
    "%EXEC%" %*
    goto :eof
)

echo Could not locate %TARGET%.exe in build directories.
exit /b 1