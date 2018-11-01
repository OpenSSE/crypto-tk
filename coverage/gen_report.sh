#! /bin/sh
set -ex

cd build
make lcov-geninfo
make lcov-genhtml