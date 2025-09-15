@echo off
echo [=== PDF Password Cracker Compilation ===]
echo.

:: Set up paths
set VSTOOLS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set OPENSSL="C:\Program Files\OpenSSL-Win64"
set LIBPATH=%OPENSSL%\lib\VC\x64\MD
set INCPATH=%OPENSSL%\include

:: Initialize VS environment
call %VSTOOLS%

if not exist %OPENSSL% (
    echo ERROR: OpenSSL is not installed.
    echo Please install OpenSSL v3.0 or later from https://slproweb.com/products/Win64OpenSSL.html
    goto error
)

echo Environment check passed
echo.
echo Compiling with maximum optimization...

:: Copy OpenSSL DLLs (if not already present)
if not exist "libcrypto-3-x64.dll" (
    copy "C:\Program Files\OpenSSL-Win64\libcrypto-3-x64.dll" . || goto error
)
if not exist "libssl-3-x64.dll" (
    copy "C:\Program Files\OpenSSL-Win64\libssl-3-x64.dll" . || goto error
)

echo Building new_pdf_cracker.cpp...
:: Compile new version
cl /EHsc /O2 /MD /std:c++17 /W4 /I%INCPATH% new_pdf_cracker.cpp /link /LIBPATH:%LIBPATH% libcrypto.lib libssl.lib
if %errorlevel% neq 0 goto error

:: Only compile older versions if they exist
if exist pdf_cracker.cpp (
    echo Building pdf_cracker.cpp...
    cl /EHsc /O2 /MD /std:c++17 /W4 /I%INCPATH% pdf_cracker.cpp /link /LIBPATH:%LIBPATH% libcrypto.lib libssl.lib
    if %errorlevel% neq 0 goto error
)

if exist dual_password_cracker.cpp (
    echo Building dual_password_cracker.cpp...
    cl /EHsc /O2 /MD /std:c++17 /W4 /I%INCPATH% dual_password_cracker.cpp /link /LIBPATH:%LIBPATH% libcrypto.lib libssl.lib
    if %errorlevel% neq 0 goto error
)

if %errorlevel% equ 0 (
    echo.
    echo Compilation SUCCESSFUL!
    echo.
    echo Usage: pdf_cracker.exe passwordlist.txt file.pdf
    echo   or   dual_password_cracker.exe passwordlist.txt file.pdf
    echo.
    echo Example: pdf_cracker.exe passwords\passwordlist.txt test_files\file.pdf
) else (
    goto error
)

goto end

:error
echo.
echo Compilation FAILED!
echo Please check:
echo 1. Visual Studio C++ tools are installed
echo 2. OpenSSL is installed
echo 3. You have administrator rights

:end
pause