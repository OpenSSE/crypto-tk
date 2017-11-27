#! /bin/sh
set -ex
#
# if [ ! -d "coverage" ]; then
# 	mkdir coverage
# fi

# gcovr  -r . -f '(.*)src(.*)' -e '(.*)boost(.*)' -u --html --html-detail -o gcov/index.html
lcov -q --directory ../build -b . --capture --output-file coverage.info
lcov -q --remove coverage.info 'tests/*' '/usr/*' '*boost*' --output-file coverage.info
lcov -q --remove coverage.info '/Applications/*' --output-file coverage.info # For Mac OS
# genhtml -q -o report coverage.info