@echo off
setlocal enabledelayedexpansion

rem Ensure the script runs from the repository root
pushd "%~dp0" >nul

set "BUILD_DIR=build"
set "TARGET=pdf_password_retriever"
set "BUILD_TYPE=Release"
set "PDF=file.pdf"
set "WORDLIST="
set "MIN_LENGTH="
set "MAX_LENGTH="
set "CLEAN_BUILD=1"
set "EXIT_CODE=0"
set "EXTRA_ARGS="
set "NOPAUSE=0"
set "INCLUDE_UPPERCASE="
set "INCLUDE_LOWERCASE="
set "INCLUDE_DIGITS="
set "INCLUDE_SPECIAL="

set "THREADS=%NUMBER_OF_PROCESSORS%"
if not defined THREADS set "THREADS=0"
for /f "delims=0123456789" %%A in ("%THREADS%") do set "THREADS="
if not defined THREADS set "THREADS=0"
set /a THREADS=THREADS 2>nul
if errorlevel 1 set "THREADS=0"
if %THREADS% LSS 1 set "THREADS=4"
if %THREADS% GTR 16 set "THREADS=16"

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
if /I "%~1"=="--threads" (
    shift
    if "%~1"=="" (
        echo Missing value for --threads
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "THREADS_VAL=%~1"
    for /f "delims=0123456789" %%A in ("%THREADS_VAL%") do set "THREADS_VAL="
    if not defined THREADS_VAL (
        echo Invalid numeric value supplied to --threads
        set "EXIT_CODE=1"
        goto cleanup
    )
    set /a THREADS=%~1 2>nul
    if errorlevel 1 (
        echo Invalid numeric value supplied to --threads
        set "EXIT_CODE=1"
        goto cleanup
    )
    if %THREADS% LSS 1 set "THREADS=1"
    if %THREADS% GTR 16 set "THREADS=16"
    shift
    goto parse_args
)
if /I "%~1"=="--min-length" (
    shift
    if "%~1"=="" (
        echo Missing value for --min-length
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "MIN_VAL=%~1"
    for /f "delims=0123456789" %%A in ("%MIN_VAL%") do set "MIN_VAL="
    if not defined MIN_VAL (
        echo Invalid numeric value supplied to --min-length
        set "EXIT_CODE=1"
        goto cleanup
    )
    set /a MIN_LENGTH=%~1 2>nul
    if errorlevel 1 (
        echo Invalid numeric value supplied to --min-length
        set "EXIT_CODE=1"
        goto cleanup
    )
    shift
    goto parse_args
)
if /I "%~1"=="--max-length" (
    shift
    if "%~1"=="" (
        echo Missing value for --max-length
        set "EXIT_CODE=1"
        goto cleanup
    )
    set "MAX_VAL=%~1"
    for /f "delims=0123456789" %%A in ("%MAX_VAL%") do set "MAX_VAL="
    if not defined MAX_VAL (
        echo Invalid numeric value supplied to --max-length
        set "EXIT_CODE=1"
        goto cleanup
    )
    set /a MAX_LENGTH=%~1 2>nul
    if errorlevel 1 (
        echo Invalid numeric value supplied to --max-length
        set "EXIT_CODE=1"
        goto cleanup
    )
    shift
    goto parse_args
)
if /I "%~1"=="--include-uppercase" (
    shift
    if "%~1"=="" (
        echo Missing value for --include-uppercase
        set "EXIT_CODE=1"
        goto cleanup
    )
    if /I "%~1"=="true" (
        set "INCLUDE_UPPERCASE=true"
    ) else if /I "%~1"=="false" (
        set "INCLUDE_UPPERCASE=false"
    ) else (
        echo Invalid boolean value for --include-uppercase. Use true or false.
        set "EXIT_CODE=1"
        goto cleanup
    )
    shift
    goto parse_args
)
if /I "%~1"=="--include-lowercase" (
    shift
    if "%~1"=="" (
        echo Missing value for --include-lowercase
        set "EXIT_CODE=1"
        goto cleanup
    )
    if /I "%~1"=="true" (
        set "INCLUDE_LOWERCASE=true"
    ) else if /I "%~1"=="false" (
        set "INCLUDE_LOWERCASE=false"
    ) else (
        echo Invalid boolean value for --include-lowercase. Use true or false.
        set "EXIT_CODE=1"
        goto cleanup
    )
    shift
    goto parse_args
)
if /I "%~1"=="--include-digits" (
    shift
    if "%~1"=="" (
        echo Missing value for --include-digits
        set "EXIT_CODE=1"
        goto cleanup
    )
    if /I "%~1"=="true" (
        set "INCLUDE_DIGITS=true"
    ) else if /I "%~1"=="false" (
        set "INCLUDE_DIGITS=false"
    ) else (
        echo Invalid boolean value for --include-digits. Use true or false.
        set "EXIT_CODE=1"
        goto cleanup
    )
    shift
    goto parse_args
)
if /I "%~1"=="--include-special" (
    shift
    if "%~1"=="" (
        echo Missing value for --include-special
        set "EXIT_CODE=1"
        goto cleanup
    )
    if /I "%~1"=="true" (
        set "INCLUDE_SPECIAL=true"
    ) else if /I "%~1"=="false" (
        set "INCLUDE_SPECIAL=false"
    ) else (
        echo Invalid boolean value for --include-special. Use true or false.
        set "EXIT_CODE=1"
        goto cleanup
    )
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
if /I "%~1"=="--no-pause" (
    set "NOPAUSE=1"
    shift
    goto parse_args
)
if /I "%~1"=="--no-clean" (
    set "CLEAN_BUILD=0"
    shift
    goto parse_args
)
if "%~1"=="--" (
    shift
    set "EXTRA_ARGS=%*"
    goto args_done
)
echo Unknown option: %~1
set "EXIT_CODE=1"
goto cleanup

:args_done

if not exist "%PDF%" (
    echo PDF "%PDF%" not found.
    set "EXIT_CODE=1"
    goto cleanup
)

if defined WORDLIST (
    if not exist "%WORDLIST%" (
        echo Wordlist "%WORDLIST%" not found.
        set "EXIT_CODE=1"
        goto cleanup
    )
)

if "%CLEAN_BUILD%"=="1" (
    if exist "%BUILD_DIR%" (
        echo Removing existing build directory "%BUILD_DIR%" for a clean Release configuration...
        rmdir /s /q "%BUILD_DIR%"
    )
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
if not exist "%EXEC%" (
    set "EXEC=%BUILD_DIR%\%BUILD_TYPE%\%TARGET%.exe"
)

if not exist "%EXEC%" (
    echo Could not find %TARGET%.exe after building.
    set "EXIT_CODE=1"
    goto cleanup
)

if %THREADS% LSS 1 set "THREADS=1"
if %THREADS% GTR 16 set "THREADS=16"

set RUN_ARGS=--threads %THREADS% --pdf "%PDF%"
if defined WORDLIST set RUN_ARGS=%RUN_ARGS% --wordlist "%WORDLIST%"
if defined MIN_LENGTH set RUN_ARGS=%RUN_ARGS% --min-length %MIN_LENGTH%
if defined MAX_LENGTH set RUN_ARGS=%RUN_ARGS% --max-length %MAX_LENGTH%
if defined INCLUDE_UPPERCASE (
    if /I "%INCLUDE_UPPERCASE%"=="true" (
        set RUN_ARGS=%RUN_ARGS% --include-uppercase
    ) else (
        set RUN_ARGS=%RUN_ARGS% --exclude-uppercase
    )
)
if defined INCLUDE_LOWERCASE (
    if /I "%INCLUDE_LOWERCASE%"=="true" (
        set RUN_ARGS=%RUN_ARGS% --include-lowercase
    ) else (
        set RUN_ARGS=%RUN_ARGS% --exclude-lowercase
    )
)
if defined INCLUDE_DIGITS (
    if /I "%INCLUDE_DIGITS%"=="true" (
        set RUN_ARGS=%RUN_ARGS% --include-digits
    ) else (
        set RUN_ARGS=%RUN_ARGS% --exclude-digits
    )
)
if defined INCLUDE_SPECIAL (
    if /I "%INCLUDE_SPECIAL%"=="true" (
        set RUN_ARGS=%RUN_ARGS% --include-special
    ) else (
        set RUN_ARGS=%RUN_ARGS% --exclude-special
    )
)
if defined EXTRA_ARGS set RUN_ARGS=%RUN_ARGS% %EXTRA_ARGS%

echo.
echo Launching %TARGET%.exe with %THREADS% thread^(s^):
echo    %RUN_ARGS%
echo.
call "%EXEC%" %RUN_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if %EXIT_CODE% EQU 0 (
    echo Execution completed successfully.
) else if %EXIT_CODE% EQU 1 (
    echo The executable reported an error. Review the output above for details.
) else if %EXIT_CODE% EQU 2 (
    echo Completed execution, but no matching password was found with the provided settings.
) else (
    echo The executable exited with unexpected code %EXIT_CODE%.
)

goto cleanup

:cleanup
echo.
popd >nul
if not "%NOPAUSE%"=="1" (
    pause
)
endlocal & exit /b %EXIT_CODE%
