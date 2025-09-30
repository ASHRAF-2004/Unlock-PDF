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
The resulting executable will be located at `build/pdf_password_retriever`. Run it with explicit options, for example:
```bash
./build/pdf_password_retriever --pdf secret.pdf --wordlist passwords.txt
```

## Configure & Build (Windows - x64)
```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```
The Release binary will be generated at `build/Release/pdf_password_retriever.exe`. Execute it via PowerShell or CMD:
```powershell
./build/Release/pdf_password_retriever.exe --pdf secret.pdf --wordlist passwords.txt
```

## Hardware & Benchmark Utility
The repository also ships with `device_probe`, a helper that prints basic system information and runs a configurable brute-force
throughput benchmark. Build it alongside the main tool:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target device_probe
```

Run the probe with optional flags to tweak the workload:

```bash
./build/device_probe --lengths 6,8,10 --attempts 750000 --hash sha256 --include-special
```

On Windows builds generated with MSBuild, specify the configuration and use the corresponding
subdirectory when launching the executable:

```powershell
cmake --build build --target device_probe --config Release
./build/Release/device_probe.exe --lengths 6,8,10 --attempts 750000 --hash sha256 --include-special
```
If you keep the default Debug configuration (for example by omitting `--config Release`), the
binary will instead be located at `build/Debug/device_probe.exe`.

Key options:

- `--lengths <list>` – Comma separated password lengths to benchmark.
- `--attempts <n>` – Attempts per length (default: 500000).
- `--hash <mode>` – `none` (fast hash) or `sha256` for a heavier workload.
- `--include-special` – Adds printable punctuation to the default character set.
- `--custom <chars>` – Provide an explicit character set for testing.

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

### Windows (`full_speed_build_and_run.bat`)
```powershell
full_speed_build_and_run.bat --pdf secret.pdf [--wordlist rockyou.txt] [--threads 12]
```
- Always configures and compiles a **Release** build for maximum CPU throughput.
- Cleans the build directory (default: `build`) before configuring to avoid generator/platform mismatches. Pass `--no-clean` if you want to reuse an existing build tree.
- Auto-detects your logical core count (capped at 16 threads) and passes it to the cracker. Override with `--threads <n>`.
- Supports the common CLI options directly: `--pdf`, `--wordlist`, `--min-length`, `--max-length`, `--threads`, and `--build-dir`.
- Forward any other cracker flags by appending `--` followed by the desired arguments, for example:
  ```powershell
  full_speed_build_and_run.bat --pdf secret.pdf -- --include-digits --include-lowercase --min-length 6 --max-length 8
  ```

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

## Brute-Forcing Without a Wordlist
You can omit the `--wordlist` flag to generate candidate passwords on the fly. Adjust the character set and length bounds to fit your search space:
```bash
./build/pdf_password_retriever --pdf secret.pdf --min-length 6 --max-length 8 --include-digits --include-lowercase
```
By default the generator uses uppercase, lowercase, digits, and common special characters with a length range of 6–32. Large searches can take significant time; refine the options whenever possible.

## Maximizing Throughput
The brute-force engine is CPU-bound. On a single hardware thread you should expect roughly 20 guesses per second. To get the highest speed your device can provide:

- **Use an optimized build.** Always compile the Release configuration so the compiler enables all optimizations. The commands in the build sections above (`cmake -S . -B build -DCMAKE_BUILD_TYPE=Release` followed by `cmake --build build`) produce the tuned binary.
- **Increase the worker pool.** The executable accepts `--threads <n>` and auto-detects the CPU by default. If detection falls back to a low count (e.g., 2 threads), explicitly set `--threads 8` or `--threads 16` to let more cores run in parallel.
- **Constrain the search space.** Every extra character class or longer length multiplies the combinations. Use the `--min-length`, `--max-length`, and alphabet toggles (`--include-*`, `--exclude-*`, `--custom-chars`, `--use-custom-only`) to focus on likely candidates.
- **Prefer targeted lists.** Even a modest, curated wordlist runs through the multithreaded pipeline and typically completes far sooner than brute-forcing millions of random permutations.
- **Scale with hardware when needed.** After saturating 16 threads and narrowing the candidate space, the only lever left is faster CPUs—this implementation does not support GPU acceleration.

## Graphical Interface

If you prefer a point-and-click workflow, a Tkinter-based launcher is available at `gui/unlock_pdf_gui.py`. The utility wraps the
`pdf_password_retriever` executable and exposes the most common options through a desktop interface. It also includes a one-click
launcher for the `device_probe` benchmarking helper so you can inspect system throughput without leaving the GUI.

1. Build the CLI executable as described above so that `build/pdf_password_retriever` (or `build/pdf_password_retriever.exe` on
   Windows) exists.
2. Start the GUI with Python 3:

   ```bash
   python3 gui/unlock_pdf_gui.py
   ```

3. Use the "Browse" buttons to choose the executable, encrypted PDF, and optional wordlist.
4. Adjust the password generation options, then click **Run Crack** or **Get PDF Info** to launch the command.

The GUI streams the CLI output in real time and lets you stop the process if needed. Tkinter ships with most Python distributions;
if it is missing, install the appropriate `python3-tk` package for your platform.

### Packaging the GUI as a Windows `.exe`

If you want to launch the interface like a native application, build a standalone executable with PyInstaller:

```powershell
cd gui
package_gui_exe.bat
```

The helper script bootstraps PyInstaller (if necessary) and outputs a ready-to-run app in `gui\dist\UnlockPDFGui\UnlockPDFGui.exe`.
If the script cannot find `pdf_password_retriever.exe` in `build\`, copy the compiled CLI next to the generated GUI executable
before distributing it. Double-click `UnlockPDFGui.exe` to start the interface without opening a terminal window.

## PDF Metadata Inspection
The tool automatically parses encryption metadata while attempting passwords. If you only need to inspect a PDF without cracking it, run:
```bash
./build/pdf_password_retriever --info <encrypted.pdf>
```
