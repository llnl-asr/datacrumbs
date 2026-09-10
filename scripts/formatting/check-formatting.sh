#! /bin/bash

set -euo pipefail

clang_format_exe="clang-format"
repo_root=""
if [[ $# -ge 1 ]]; then
  clang_format_exe="$1"
fi
if [[ $# -ge 2 ]]; then
  repo_root="$2"
fi

SUPPORTED_CLANG_FORMAT_VERSION="19.1.7"

if ! command -v "$clang_format_exe" >/dev/null 2>&1; then
  echo "You must have 'clang-format' in PATH to use 'check-formatting.sh'"
  exit 1
fi

clang_format_version_str=$($clang_format_exe --version)
clang_format_version=$(echo "$clang_format_version_str" | grep -oP 'clang-format version \K\d+(\.\d+)+')

if [ "$clang_format_version" != "$SUPPORTED_CLANG_FORMAT_VERSION" ]; then
  echo "WARNING: the .clang-format file in this repo is designed for version $SUPPORTED_CLANG_FORMAT_VERSION."
  echo "         You are running with clang-format v$clang_format_version."
  echo "         The resulting check is highly likely to be incorrect."
fi

if ! command -v find >/dev/null 2>&1; then
  echo "You must have 'find' in PATH to use 'check-formatting.sh'"
  exit 1
fi

if ! command -v dirname >/dev/null 2>&1; then
  echo "You must have 'dirname' in PATH to use 'check-formatting.sh'"
  exit 1
fi

if ! command -v xargs >/dev/null 2>&1; then
  echo "You must have 'xargs' in PATH to use 'check-formatting.sh'"
  exit 1
fi

if ! command -v shfmt >/dev/null 2>&1; then
  echo "You must have 'shfmt' in PATH to use 'check-formatting.sh'"
  exit 1
fi

if ! command -v cmake-format >/dev/null 2>&1; then
  echo "You must have 'cmake-format' in PATH to use 'check-formatting.sh'"
  exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

curr_dir=$(pwd)
if [[ -z "$repo_root" ]]; then
  repo_root=$(cd "$SCRIPT_DIR/../.." && pwd)
fi
repo_root=$(cd "$repo_root" && pwd)

cd "$repo_root"

echo "Check formatting of C/C++ code in '.'"
find . \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" \) \( -path "./src/*" -o -path "./tools/*" -o -path "./tests/*" -o -path "./etc/datacrumbs/plugins/*" \) -print0 | xargs -0 -P "$(nproc)" "$clang_format_exe" --dry-run --Werror
src_check_rc=$?

echo "Check formatting of shell scripts in '.'"
find . \( -name "*.sh" -o -name "*.in" \) \( -path "./etc/datacrumbs/data/*" -o -path "./infrastructure/docker/*" -o -path "./scripts/datacrumbs/*" -o -path "./tests/*" -o -path "./tools/*" \) -not -path "*.txt.in" -print0 | xargs -0 shfmt -d
shell_check_rc=$?

echo "Check formatting of CMake files in '.'"
find . \( -name "CMakeLists.txt*" -o -name "*.cmake" \) \( -path "./src/*" -o -path "./tools/*" -o -path "./tests/*" -o -path "./cmake/*" \) -print0 | xargs -0 cmake-format --check
cmake_check_rc=$?

cd "$curr_dir"

if [ $src_check_rc -ne 0 ] || [ $shell_check_rc -ne 0 ] || [ $cmake_check_rc -ne 0 ]; then
  echo "Some formatting checks failed. Please run 'autoformat.sh' to fix the issues."
  exit 2
else
  echo "All checks passed successfully."
  exit 0
fi
