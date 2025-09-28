#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="build"
TARGET="pdf_password_retriever"
BUILD_TYPE="Release"
PDF="file.pdf"
WORDLIST=""
MIN_LENGTH=6
MAX_LENGTH=6
CLEAN_BUILD=1
EXIT_CODE=0
EXTRA_ARGS=()
INCLUDE_UPPERCASE=true
INCLUDE_LOWERCASE=false
INCLUDE_DIGITS=false
INCLUDE_SPECIAL=false

# Detect a sane default thread count (1-16 range, default to 4 if detection fails)
detect_threads() {
    local detected
    if detected=$(getconf _NPROCESSORS_ONLN 2>/dev/null); then
        :
    elif detected=$(sysctl -n hw.ncpu 2>/dev/null); then
        :
    else
        detected=4
    fi

    if ! [[ "$detected" =~ ^[0-9]+$ ]]; then
        detected=4
    fi

    if (( detected < 1 )); then
        detected=4
    elif (( detected > 16 )); then
        detected=16
    fi

    printf '%s' "$detected"
}

THREADS="$(detect_threads)"

print_usage() {
    cat <<'USAGE'
Usage: full_speed_build_and_run.sh [options] [-- <extra args>]

Options:
  --pdf <path>              Path to the encrypted PDF file (default: file.pdf)
  --wordlist <path>         Path to a password wordlist
  --threads <n>             Number of worker threads (clamped to 1-16, default: auto)
  --min-length <n>          Minimum password length (default: 6)
  --max-length <n>          Maximum password length (default: 6)
  --include-uppercase       Require uppercase letters in the search space (default: on)
  --exclude-uppercase       Exclude uppercase letters from the search space
  --include-lowercase       Require lowercase letters in the search space
  --exclude-lowercase       Exclude lowercase letters from the search space (default)
  --include-digits          Require digits in the search space
  --exclude-digits          Exclude digits from the search space (default)
  --include-special         Require special characters in the search space
  --exclude-special         Exclude special characters from the search space (default)
  --build-dir <path>        Directory for CMake build files (default: build)
  --release                 Configure CMake in Release mode (default)
  --debug                   Configure CMake in Debug mode
  --no-clean                Skip deleting the build directory before configuring
  --clean                   Force deletion of the build directory before configuring
  -h, --help                Show this help message and exit

Any arguments following "--" are passed directly to the executable.
USAGE
}

ensure_numeric() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        printf 'Error: %s expects a non-negative integer, got "%s".\n' "$name" "$value" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pdf)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --pdf" >&2; exit 1; }
            PDF="$1"
            ;;
        --wordlist)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --wordlist" >&2; exit 1; }
            WORDLIST="$1"
            ;;
        --threads)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --threads" >&2; exit 1; }
            ensure_numeric "--threads" "$1"
            THREADS="$1"
            ;;
        --min-length)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --min-length" >&2; exit 1; }
            ensure_numeric "--min-length" "$1"
            MIN_LENGTH="$1"
            ;;
        --max-length)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --max-length" >&2; exit 1; }
            ensure_numeric "--max-length" "$1"
            MAX_LENGTH="$1"
            ;;
        --include-uppercase)
            INCLUDE_UPPERCASE=true
            ;;
        --exclude-uppercase)
            INCLUDE_UPPERCASE=false
            ;;
        --include-lowercase)
            INCLUDE_LOWERCASE=true
            ;;
        --exclude-lowercase)
            INCLUDE_LOWERCASE=false
            ;;
        --include-digits)
            INCLUDE_DIGITS=true
            ;;
        --exclude-digits)
            INCLUDE_DIGITS=false
            ;;
        --include-special)
            INCLUDE_SPECIAL=true
            ;;
        --exclude-special)
            INCLUDE_SPECIAL=false
            ;;
        --build-dir)
            shift
            [[ $# -gt 0 ]] || { echo "Missing value for --build-dir" >&2; exit 1; }
            BUILD_DIR="$1"
            ;;
        --debug)
            BUILD_TYPE="Debug"
            ;;
        --release)
            BUILD_TYPE="Release"
            ;;
        --no-clean)
            CLEAN_BUILD=0
            ;;
        --clean)
            CLEAN_BUILD=1
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        --)
            shift
            EXTRA_ARGS=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage >&2
            exit 1
            ;;
    esac
    shift || true
done

ensure_numeric "--threads" "$THREADS"
if (( THREADS < 1 )); then
    THREADS=1
elif (( THREADS > 16 )); then
    THREADS=16
fi

if (( MIN_LENGTH < 0 || MAX_LENGTH < 0 )); then
    echo "Password lengths must be non-negative." >&2
    exit 1
fi

if (( MIN_LENGTH > MAX_LENGTH )); then
    echo "--min-length must not exceed --max-length." >&2
    exit 1
fi

if [[ ! -f "$PDF" ]]; then
    printf 'PDF "%s" not found.\n' "$PDF" >&2
    exit 1
fi

if [[ -n "$WORDLIST" && ! -f "$WORDLIST" ]]; then
    printf 'Wordlist "%s" not found.\n' "$WORDLIST" >&2
    exit 1
fi

if (( CLEAN_BUILD )) && [[ -d "$BUILD_DIR" ]]; then
    echo "Removing existing build directory \"$BUILD_DIR\" for a clean $BUILD_TYPE configuration..."
    rm -rf -- "$BUILD_DIR"
fi

echo "Configuring project ($BUILD_TYPE)..."
if ! cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"; then
    echo "CMake configuration failed." >&2
    exit 1
fi

echo "Building project..."
if ! cmake --build "$BUILD_DIR" --config "$BUILD_TYPE"; then
    echo "Build failed." >&2
    exit 1
fi

EXECUTABLE="${BUILD_DIR}/${TARGET}"
if [[ ! -x "$EXECUTABLE" ]]; then
    ALT_EXECUTABLE="${BUILD_DIR}/${BUILD_TYPE}/${TARGET}"
    if [[ -x "$ALT_EXECUTABLE" ]]; then
        EXECUTABLE="$ALT_EXECUTABLE"
    fi
fi

if [[ ! -x "$EXECUTABLE" ]]; then
    printf 'Could not find executable "%s" after building.\n' "$TARGET" >&2
    exit 1
fi

RUN_ARGS=("--threads" "$THREADS" "--pdf" "$PDF")
if [[ -n "$WORDLIST" ]]; then
    RUN_ARGS+=("--wordlist" "$WORDLIST")
fi
RUN_ARGS+=("--min-length" "$MIN_LENGTH" "--max-length" "$MAX_LENGTH")

if [[ "$INCLUDE_UPPERCASE" == true ]]; then
    RUN_ARGS+=("--include-uppercase")
else
    RUN_ARGS+=("--exclude-uppercase")
fi

if [[ "$INCLUDE_LOWERCASE" == true ]]; then
    RUN_ARGS+=("--include-lowercase")
else
    RUN_ARGS+=("--exclude-lowercase")
fi

if [[ "$INCLUDE_DIGITS" == true ]]; then
    RUN_ARGS+=("--include-digits")
else
    RUN_ARGS+=("--exclude-digits")
fi

if [[ "$INCLUDE_SPECIAL" == true ]]; then
    RUN_ARGS+=("--include-special")
else
    RUN_ARGS+=("--exclude-special")
fi

if (( ${#EXTRA_ARGS[@]} )); then
    RUN_ARGS+=("${EXTRA_ARGS[@]}")
fi

echo
printf 'Launching %s with %s thread(s):\n' "$TARGET" "$THREADS"
echo "    ${RUN_ARGS[*]}"
echo

if "${EXECUTABLE}" "${RUN_ARGS[@]}"; then
    EXIT_CODE=0
else
    EXIT_CODE=$?
fi

echo
case "$EXIT_CODE" in
    0)
        echo "Execution completed successfully."
        ;;
    1)
        echo "The executable reported an error. Review the output above for details."
        ;;
    2)
        echo "Completed execution, but no matching password was found with the provided settings."
        ;;
    *)
        printf 'The executable exited with unexpected code %s.\n' "$EXIT_CODE"
        ;;
 esac

echo
exit "$EXIT_CODE"
