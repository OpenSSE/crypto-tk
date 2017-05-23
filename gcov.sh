#! /bin/sh

if [ ! -d "gcov" ]; then
	mkdir gcov
fi

gcovr  -r . -f '(.*)src(.*)' -e '(.*)boost(.*)' --html --html-detail -o gcov/index.html