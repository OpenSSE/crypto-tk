#! /bin/bash
set -e

if [[ -z $CPPCHECK ]]; then
	CPPCHECK="cppcheck"
fi

echo "Using "$CPPCHECK

echo "Generate the compile commands"

mkdir -p build
cd build
# For the static analysis, only focus on an AES NI-enabled target
CFLAGS="-maes -DWITH_OPENSSL" CXXFLAGS="-maes -DWITH_OPENSSL" cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../src
cd ..

set +e

CPPCHECK_TEMPLATE="gcc"

COMMAND="$CPPCHECK --project=build/compile_commands.json -i src/mbedtls --std=c++11 --force  --enable=warning,performance,portability,style --error-exitcode=1 --report-progress  --inline-suppr --template=$CPPCHECK_TEMPLATE"

echo $COMMAND

eval $COMMAND