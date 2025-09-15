@echo off
echo [=== PDF Password Cracker Compilation ===]
echo.

REM Initialize Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

REM Build the source file
echo Building new_pdf_cracker.cpp...
cl.exe /nologo /O2 /EHsc /MD new_pdf_cracker.cpp /I"C:\Program Files\OpenSSL-Win64\include" /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" libcrypto.lib libssl.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation successful!
) else (
    echo.
    echo Compilation failed with error code %ERRORLEVEL%
)

pause
