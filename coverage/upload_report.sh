#! /bin/sh
set -ex

lcov --list build/check_coverage/check_coverage.info # debug before upload
coveralls-lcov build/check_coverage/coverage.info