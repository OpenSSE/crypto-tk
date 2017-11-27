#! /bin/sh
set -ex

lcov --list coverage.info # debug before upload
coveralls-lcov coverage.info