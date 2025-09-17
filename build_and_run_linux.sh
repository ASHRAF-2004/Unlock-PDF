#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="build"
BUILD_TYPE="Release"
TARGET="pdf_password_retriever"
WORDLIST="passwordlist.txt"
PDF="file.pdf"
RUN_AFTER_BUILD=1

usage() {
    cat <<'USAGE'
Usage: build_and_run_linux.sh [options]

Options:
  --wordlist <path>    Path to the password wordlist (default: passwordlist.txt)
  --pdf <path>         Path to the encrypted PDF file (default: file.pdf)
  --build-dir <path>   Directory to use for CMake build files (default: build)
  --debug              Configure the project with Debug build type
  --no-run             Only configure and build; skip executing the binary
  -h, --help           Show this help message
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wordlist)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --wordlist" >&2; exit 1; }
            WORDLIST="$1"
            ;;
        --pdf)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --pdf" >&2; exit 1; }
            PDF="$1"
            ;;
        --build-dir)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --build-dir" >&2; exit 1; }
            BUILD_DIR="$1"
            ;;
        --debug)
            BUILD_TYPE="Debug"
            ;;
        --no-run)
            RUN_AFTER_BUILD=0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
    shift
done

if [[ ! -f "$WORDLIST" ]]; then
    echo "Wordlist '$WORDLIST' not found." >&2
    exit 1
fi

if [[ ! -f "$PDF" ]]; then
    echo "PDF '$PDF' not found." >&2
    exit 1
fi

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
cmake --build "$BUILD_DIR"

if [[ "$RUN_AFTER_BUILD" -eq 0 ]]; then
    exit 0
fi

EXECUTABLE="$BUILD_DIR/$TARGET"
if [[ ! -x "$EXECUTABLE" ]]; then
    echo "Executable '$EXECUTABLE' was not produced. If you are using a multi-config generator, use --no-run and run the binary manually." >&2
    exit 1
fi

"$EXECUTABLE" --pdf "$PDF" --wordlist "$WORDLIST"
