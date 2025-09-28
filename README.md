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

## PDF Metadata Inspection
The tool automatically parses encryption metadata while attempting passwords. If you only need to inspect a PDF without cracking it, run:
```bash
./build/pdf_password_retriever --info <encrypted.pdf>
```
