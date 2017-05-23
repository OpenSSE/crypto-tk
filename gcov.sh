#! /bin/sh

if [ ! -d "gcov" ]; then
	mkdir gcov
fi

gcovr  -r . -f '(.*)src(.*)' --html --html-detail -o gcov/index.html