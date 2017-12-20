#! /bin/sh
if [[ -z $CPPCHECK ]]; then
	CPPCHECK="cppcheck"
fi

eval "$CPPCHECK src --quiet --verbose --std=c++11 --force  --enable=warning,performance,portability,style --error-exitcode=1 --report-progress  --inline-suppr"