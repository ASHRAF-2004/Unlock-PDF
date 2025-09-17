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

## One-Click Helper Scripts

### Windows (`build_and_run.bat`)
Run the helper from an existing Command Prompt/PowerShell session or double-click it in Explorer. The console window now stays open so you can read the output.

- Default inputs are `passwordlist.txt` and `file.pdf`. Override them with command-line options, for example:
  ```powershell
  build_and_run.bat --wordlist my_passwords.txt --pdf secret.pdf
  ```
- Pass `--no-pause` when launching from an existing terminal to skip the final key prompt.
- Additional flags:
  - `--build-dir <dir>` – use a custom build folder.
  - `--debug` – configure a Debug build instead of Release.

### Linux (`build_and_run_linux.sh`)
```bash
./build_and_run_linux.sh
```
- Uses the same defaults and command-line options as the Windows helper (minus `--no-pause`).
- Add `--no-run` if you only want to configure and compile the project.

### macOS (`build_and_run_macos.sh`)
```bash
./build_and_run_macos.sh
```
- Identical behavior to the Linux script; it compiles the project with the default Apple toolchain and then launches the binary.
- Requires Xcode command-line tools (or an equivalent Clang toolchain) plus CMake.

## Finding Additional Passwords
The tool stops after the first password match. If you know there is another password in your wordlist, remove the previously found password from the list (or comment it out) and run the program again to continue searching.

## PDF Metadata Inspection
The tool automatically parses encryption metadata while attempting passwords. If you only need to inspect a PDF without cracking it, run:
```bash
./build/pdf_password_retriever --info <encrypted.pdf>
```
