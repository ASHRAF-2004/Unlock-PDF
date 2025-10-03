# Unlock PDF – Super Simple Guide

Unlock PDF is a helper tool that tries many passwords on a locked PDF file until it finds the right one. Follow these quick steps to build it and run it on your computer.

## What you need first
- A computer with Windows, macOS, or Linux.
- CMake (version 3.16 or newer).
- A C++17 compiler:
  - **Windows:** Visual Studio 2019 or newer (MSVC).
  - **macOS:** Xcode command-line tools.
  - **Linux:** GCC 9+ or Clang 10+.
- (Optional) Python 3 if you want to use the simple graphical window in `gui/unlock_pdf_gui.py`.

## Build the tool
Choose the instructions for your operating system. Each set creates a `build` folder with the program inside it.

### Windows
Open "x64 Native Tools Command Prompt for VS" or PowerShell, then run:
```powershell
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```
The program will appear at `build/Release/pdf_password_retriever.exe`.

### macOS
Open Terminal, then run:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
The program will appear at `build/pdf_password_retriever`.

### Linux
Open your shell, then run:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
The program will appear at `build/pdf_password_retriever`.

## Run the command-line tool
Use the program to test passwords from a word list (a text file with one password per line).

- **Windows:**
  ```powershell
  .\build\Release\pdf_password_retriever.exe --pdf locked.pdf --wordlist passwords.txt
  ```
- **macOS/Linux:**
  ```bash
  ./build/pdf_password_retriever --pdf locked.pdf --wordlist passwords.txt
  ```

Helpful options:
- `--min-length <number>` and `--max-length <number>` choose the shortest and longest passwords to try when you do not use a word list.
- `--threads <number>` uses more CPU cores to go faster.
- `--info <file>` shows PDF details without cracking it.

## Try the simple GUI (optional)
1. Build the command-line tool first.
2. Start the GUI:
   - **Windows:** double-click `gui/unlock_pdf_gui.pyw` or run `python gui\unlock_pdf_gui.py`.
   - **macOS/Linux:** `python3 gui/unlock_pdf_gui.py`
3. Pick the program, the locked PDF, and your word list. Press **Run Crack** to start.

Now you are ready to unlock PDFs like a pro!
