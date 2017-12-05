#! /bin/sh
if [[ -z $CPPCHECK ]]; then
	CPPCHECK="cppcheck"
fi

eval "$CPPCHECK src -isrc/boost --quiet --verbose --std=c++11 --force  --enable=warning,missingInclude,performance,portability,style --error-exitcode=1 --report-progress"