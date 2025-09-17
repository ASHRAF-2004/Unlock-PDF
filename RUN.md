# Build and Run Instructions

## Prerequisites
- A C++17-capable compiler (e.g., GCC 9+, Clang 10+, or MSVC 2019+)
- CMake 3.16 or newer
- (Optional) Ninja or Make if you prefer those generators

## Configure & Build (Linux/macOS)
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
The resulting executable will be located at `build/pdf_password_retriever`. Run it as:
```bash
./build/pdf_password_retriever <wordlist.txt> <encrypted.pdf>
```

## Configure & Build (Windows - x64)
```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```
The Release binary will be generated at `build/Release/pdf_password_retriever.exe`. Execute it via PowerShell or CMD:
```powershell
./build/Release/pdf_password_retriever.exe <wordlist.txt> <encrypted.pdf>
```

## Helper Script (Windows)
Run `build_and_run.bat` to configure, build, and invoke the cracker in one step. Pass the same arguments you would give the executable:
```cmd
build_and_run.bat passwords\\passwordlist.txt test_files\\file.pdf
```
The script stops if configuration or compilation fails and attempts to locate the executable in both single- and multi-config build directories.

## PDF Metadata Inspection
The tool automatically parses encryption metadata while attempting passwords. If you only need to inspect a PDF without cracking it, run:
```bash
./build/pdf_password_retriever --info <encrypted.pdf>
```