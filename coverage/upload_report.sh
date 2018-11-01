#! /bin/sh
set -ex

lcov --list build/check_coverage.info # debug before upload
coveralls-lcov build/coverage.info