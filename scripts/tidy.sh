#! /bin/bash
set -e

if [[ -z $CLANG_TIDY ]]; then
	CLANG_TIDY="clang-tidy"
fi

echo "Using "$CLANG_TIDY

echo "Generate the compile commands"

mkdir -p build
cd build
# For the static analysis, only focus on an AES NI-enabled target
CFLAGS="-maes -DWITH_OPENSSL" CXXFLAGS="-maes -DWITH_OPENSSL" cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../src
cd ..


GLOBIGNORE='**/mbedtls/**' # do not look into mbedTLS code

echo "Ignoring files in "$GLOBIGNORE

LINE_FILTER="''"
set +e

eval "$CLANG_TIDY -line-filter=$LINE_FILTER -p=build src/**/*.{h,c}"
eval "$CLANG_TIDY -line-filter=$LINE_FILTER -p=build src/*.cpp src/**/*.{hpp,cpp}"

