@echo off
echo [=== PDF Password Cracker Compilation ===]
echo.

:: Check required headers
if not exist podofo\podofo.h (
    echo ERROR: Missing podofo.h - main header file
    goto error
)

if not exist podofo\main\PdfError.h (
    echo ERROR: Missing PdfError.h - error handling
    goto error
)

if not exist podofo\main\PdfMemDocument.h (
    echo ERROR: Missing PdfMemDocument.h - document class
    goto error
)

:: Check library
if not exist lib\podofo.lib (
    echo ERROR: Missing podofo.lib - main library
    goto error
)

echo ✅ All required files found
echo.
echo Compiling with maximum optimization...

:: Compile command
cl /EHsc /O2 /MT /std:c++17 /I"podofo" dual_password_cracker.cpp /link /LIBPATH:"lib" podofo.lib

if %errorlevel% equ 0 (
    echo.
    echo 🎉 COMPILATION SUCCESSFUL!
    echo.
    echo Usage: dual_password_cracker.exe passwordlist.txt file.pdf
    echo Example: dual_password_cracker.exe passwords\passwordlist.txt test_files\file.pdf
) else (
    goto error
)

goto end

:error
echo.
echo ❌ COMPILATION FAILED!
echo Please check:
echo 1. All required headers in podofo/ folder
echo 2. podofo.lib in lib/ folder
echo 3. Visual Studio build tools installed

:end
echo.
pause
