#! /bin/bash
set -ex
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DENABLE_COVERAGE=${ENABLE_COVERAGE} ..
VERBOSE=1 cmake --build . --clean-first --target check