#! /bin/bash
if [[ -z $CPPCHECK ]]; then
	CPPCHECK="cppcheck"
fi

INCLUDES="-Ibuild -Isrc -I/usr/local/opt/openssl/include -Isrc/include -Isrc/include/opensse/crypto"

COMMAND="$CPPCHECK src -i src/mbedtls $INCLUDES --quiet --verbose --std=c++11 --force  --enable=warning,performance,portability,style --error-exitcode=1 --report-progress  --inline-suppr --xml"

echo $COMMAND

eval $COMMAND