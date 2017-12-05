#! /bin/sh
if [[ -z $CPPCHECK ]]; then
	CPPCHECK="cppcheck"
fi

eval "$CPPCHECK src -isrc/boost --quiet --verbose --std=c++11 --force  --enable=warning --error-exitcode=1 --report-progress"