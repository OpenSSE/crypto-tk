#! /bin/sh
set -ex
#
# if [ ! -d "coverage" ]; then
# 	mkdir coverage
# fi

lcov -q --directory build -b . --capture --output-file coverage/coverage.info
lcov -q --remove coverage/coverage.info 'tests/*' '/usr/*' --output-file coverage/coverage.info
lcov -q --remove coverage/coverage.info '/Applications/*' --output-file coverage/coverage.info # For Mac OS
# genhtml -q -o report coverage.info