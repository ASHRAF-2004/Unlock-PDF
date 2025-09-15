@echo off
echo [=== PDF Password Cracker Compilation ===]
echo.

set OPENSSL=C:\Program Files\OpenSSL-Win64
set MSVC=C:\Program Files\Microsoft Visual Studio\2022\Community

call "%MSVC%\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%OPENSSL%" (
    echo ERROR: OpenSSL is not installed.
    echo Please install OpenSSL v3.0 or later from https://slproweb.com/products/Win64OpenSSL.html
    goto error
)

echo Environment check passed
echo.
echo Compiling with maximum optimization...

echo Building new_pdf_cracker.cpp...
cl /EHsc /O2 /MD /std:c++17 /W4 /I"%OPENSSL%\include" new_pdf_cracker.cpp /link /LIBPATH:"%OPENSSL%\lib\VC\x64\MD" libcrypto.lib libssl.lib
if %errorlevel% neq 0 goto error

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