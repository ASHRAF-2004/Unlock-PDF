@echo off@echo off

echo [=== PDF Password Cracker Compilation ===]echo [=== PDF Password Cracker Compilation ===]

echo.echo.



:: Setup Visual Studio environment:: Setup Visual Studio environment

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

if %errorlevel% neq 0 (if %errorlevel% neq 0 (

    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

))

if %errorlevel% neq 0 (if %errorlevel% neq 0 (

    echo ERROR: Could not find Visual Studio. Please install Visual Studio 2019 or 2022 with C++ development tools.    echo ERROR: Could not find Visual Studio. Please install Visual Studio 2019 or 2022 with C++ development tools.

    goto error    goto error

))



:: Check OpenSSL:: Check OpenSSL

if not exist "C:\Program Files\OpenSSL-Win64" (if not exist "C:\Program Files\OpenSSL-Win64" (

    echo ERROR: OpenSSL is not installed.    echo ERROR: OpenSSL is not installed.

    echo Please install OpenSSL v3.0 or later from https://slproweb.com/products/Win64OpenSSL.html    echo Please install OpenSSL v3.0 or later from https://slproweb.com/products/Win64OpenSSL.html

    goto error    goto error

))



echo ✅ Environment check passedecho ✅ Environment check passed

echo.echo.

echo Compiling with maximum optimization...echo Compiling with maximum optimization...



:: Compile command:: Compile command

cl /EHsc /O2 /MT /std:c++17 /W4 ^cl /EHsc /O2 /MT /std:c++17 /W4 ^

   /I"C:\Program Files\OpenSSL-Win64\include" ^   /I"C:\Program Files\OpenSSL-Win64\include" ^

   pdf_cracker.cpp ^   pdf_cracker.cpp ^

   /link "C:\Program Files\OpenSSL-Win64\lib\libssl.lib" ^   /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib" ^

   "C:\Program Files\OpenSSL-Win64\lib\libcrypto.lib"   libssl.lib libcrypto.lib



if %errorlevel% equ 0 (if %errorlevel% equ 0 (

    echo.    echo.

    echo 🎉 COMPILATION SUCCESSFUL!    echo 🎉 COMPILATION SUCCESSFUL!

    echo.    echo.

    echo Usage: pdf_cracker.exe passwordlist.txt file.pdf    echo Usage: pdf_cracker.exe passwordlist.txt file.pdf

    echo Example: pdf_cracker.exe passwords\passwordlist.txt test_files\file.pdf    echo Example: pdf_cracker.exe passwords\passwordlist.txt test_files\file.pdf

) else () else (

    goto error    goto error

))



goto endgoto end



:error:error

echo.echo.

echo ❌ COMPILATION FAILED!echo ❌ COMPILATION FAILED!

echo Please check:echo Please check:

echo 1. Visual Studio C++ tools are installedecho 1. Visual Studio C++ tools are installed

echo 2. OpenSSL is installed (https://slproweb.com/products/Win64OpenSSL.html)echo 2. OpenSSL is installed (https://slproweb.com/products/Win64OpenSSL.html)

echo 3. You have administrator rightsecho 3. You have administrator rights



:end:end

echo.echo.

pausepause