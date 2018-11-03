#! /bin/bash
set -e

: ${CPPCHECK:=`which cppcheck`}
: ${STATIC_ANALYSIS_DIR:="static_analysis"}

bold=$(tput bold)
normal=$(tput sgr0)
red=$(tput setaf 1)

echo "Using $CPPCHECK"

if [ ! -f $STATIC_ANALYSIS_DIR/compile_commands.json ]; then
    echo "Generate the compile commands"

    mkdir -p $STATIC_ANALYSIS_DIR 
    cd $STATIC_ANALYSIS_DIR
    # For the static analysis, only focus on an AES NI-enabled target
    CFLAGS="-maes -DWITH_OPENSSL" CXXFLAGS="-maes -DWITH_OPENSSL" cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../src
    cd ..
fi

set +e

CPPCHECK_TEMPLATE="${bold}{file}:{line}${normal}\\n${bold}${red}error: ${normal}${bold}{severity}({id}): {message}${normal}\\n{code}"

COMMAND="$CPPCHECK --project=$STATIC_ANALYSIS_DIR/compile_commands.json -i src/mbedtls --std=c++11 --force  --enable=warning,performance,portability,style --error-exitcode=1 --report-progress  --inline-suppr --template='$CPPCHECK_TEMPLATE'"

echo $COMMAND

eval $COMMAND