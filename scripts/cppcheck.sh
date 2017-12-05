#! /bin/sh
if [[ -z $CPPCHECK ]]; then
	CPPCHECK="cppcheck"
fi

eval "$CPPCHECK src -isrc/boost --verbose --std=c++11 --force  --enable=warning"