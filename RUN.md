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

## One-Click Helper Script (Windows)
Double-click `build_and_run.bat` to configure, build, and launch the cracker with the sample files (`passwordlist.txt` and `file.pdf`).

- The script automatically switches to the repository directory, runs CMake configuration, builds the executable, and executes it.
- If you want to test different files, edit the `WORDLIST` and `PDF` values at the top of the script before running it.

## Finding Additional Passwords
The tool stops after the first password match. If you know there is another password in your wordlist, remove the previously found password from the list (or comment it out) and run the program again to continue searching.

## PDF Metadata Inspection
The tool automatically parses encryption metadata while attempting passwords. If you only need to inspect a PDF without cracking it, run:
```bash
./build/pdf_password_retriever --info <encrypted.pdf>
```
