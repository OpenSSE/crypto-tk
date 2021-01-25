# OpenSSE's Cryptographic Toolkit

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![build status](https://badges.herokuapp.com/travis/OpenSSE/crypto-tk?branch=master&label=gcc%20build&env=COMPILER=gcc)](https://travis-ci.org/OpenSSE/crypto-tk)
[![build status](https://badges.herokuapp.com/travis/OpenSSE/crypto-tk?branch=master&label=clang%20build&env=COMPILER=clang)](https://travis-ci.org/OpenSSE/crypto-tk)
[![static analysis](https://badges.herokuapp.com/travis/OpenSSE/crypto-tk?branch=master&label=static%20analysis&env=STATIC_ANALYSIS=true)](https://travis-ci.org/OpenSSE/crypto-tk)
[![Coverity](https://img.shields.io/coverity/scan/17513.svg)](https://scan.coverity.com/projects/opensse-crypto-tk)
[![Coverage Status](https://coveralls.io/repos/github/OpenSSE/crypto-tk/badge.svg)](https://coveralls.io/github/OpenSSE/crypto-tk)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/1412/badge)](https://bestpractices.coreinfrastructure.org/projects/1412)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/5149d1eb77224a6e981d1b2f46bfb012)](https://www.codacy.com/app/rbost/crypto-tk?utm_source=github.com&utm_medium=referral&utm_content=OpenSSE/crypto-tk&utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/opensse/crypto-tk/badge)](https://www.codefactor.io/repository/github/opensse/crypto-tk)

The searchable encryption protocols rely on high level cryptographic features such as pseudo-random functions, hash functions, encryption schemes, or incremental set hashing. The cryptographic layer provides interfaces and implementations of these features.

## Why a new crypto library

A lot of great crypto libraries exist out there (_e.g._ [libsodium](https://github.com/jedisct1/libsodium)). Unfortunately, they do not offer the level of abstraction needed to implement searchable encryption schemes easily. Indeed, cryptographic objects such as pseudo-random functions, trapdoor permutations, pseudo-random generators, _etc_, are building blocks of such constructions, and OpenSSL or libsodium do not offer interfaces to such objects.

This library provides these APIs so that the SSE implementer has consistent high-level crypto interfaces and does not have to care about the inner implementation of the blocks.

## Disclaimer

This is code for a **research project**. It **should not be used in practice**: the code lacks good C/C++ security practice, and it has never been externally reviewed.

## Getting the Code

You can get the code by cloning the code repository from GitHub. When you do so, be sure to also pull the submodules, or otherwise, nothing will compile:

```sh
git clone https://github.com/OpenSSE/crypto-tk.git
cd crypto-tk
git submodule update --init --recursive
```

## Building

Building is done using CMake. The minimum required version is CMake 3.1.

### Dependencies

`libsse_crypto` uses the following dependencies

-   [libsodium](https://download.libsodium.org/doc/). libsodium version >=1.0.16 is necessary.

-   [RELIC](https://github.com/relic-toolkit/relic) Some features (puncturable encryption) are based on cryptographic pairings. These are implemented using the RELIC toolkit. RELIC has many compilation options. The current code has been tested against RELIC v0.5.0. To install RELIC in that version, you can do the following:

```sh
git clone -b relic-toolkit-0.5.0 https://github.com/relic-toolkit/relic.git
cd relic
mkdir build; cd build
cmake -G "Unix Makefiles" -DMULTI=PTHREAD -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" -DARCH="X64"  -DRAND="UDEV" -DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DBENCH=0 -DTESTS=1 -DARITH=gmp -DFP_PRIME=254 -DFP_QNRES=off -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DBN_PRECI=256 -DFP_QNRES=on ../.
make
make install
```

You can also replace the `-DARITH=gmp` option by `-DARITH=x64-asm-254` (for better performance) or `-DARITH=easy` (to get rid of the gmp dependency). Note that the first two depend on [gmp](https://gmplib.org).

#### Optional Dependencies

-   [OpenSSL](https://www.openssl.org)'s cryptographic library (`libcrypto`). The trapdoor permutation is based on RSA, and `libsse_crypto` can use OpenSSL to implement RSA. The code has been compiled and tested using OpenSSL 1.0.2. Note that this part of the code is now deprecated and is incompatible with OpenSSL 1.1.0 APIs.

### Compiler

`libsse_crypto` needs a compiler supporting C++11.
You can easily check that `libsse_crypto` is successfully built on Ubuntu 14 LTS with gcc 4.8 using Travis.
It has also been successfully built and tested on Ubuntu 16 LTS using both clang (versions 3.8, 4.0 and 5.0) and gcc (versions 4.8, 4.9 and 5.0) and on Mac OS X.12 using clang 9.0.0.

### Setting up your system

Here is what is necessary to set your system up from scratch, and build `libsse_crypto` (you will need to build RELIC first though).

#### Ubuntu 14.04 LTS

```sh
 [sudo] add-apt-repository ppa:ubuntu-toolchain-r/test
 [sudo] apt-get update
 [sudo] apt-get install build-essential cmake3 libtool libssl-dev libgmp-dev
```

To install the three dependencies, you can either follow the instructions of their website (in particular for libsodium), or use the embedded install scripts. These might have to be modified to fit your needs (e.g. if you do not want to install RELIC system-wide, or if you are not a sudoer).
To do so, move to directory `install_dependencies`, and run `./install_sodium.sh` to download and install libsodium 1.0.16 and `./install_relic_easy.sh` to install RELIC with the `easy` arithmetic.
If you want to use the gmp arithmetic or the x64 assembly arithmetic, run respectively `./install_relic_gmp.sh` and `./install_relic_asm.sh`.

#### Ubuntu 16.04 LTS

```sh
 [sudo] apt-get update
 [sudo] apt-get install build-essential cmake libtool libssl-dev libgmp-dev
```

You can then install libsodium as for Ubuntu 14.
For RELIC, use one of the scripts `install_relic_easy.sh`, `install_relic_gmp.sh`, or `install_relic_x64_asm.sh` depending on the arithmetic you prefer.

#### Mac OS

```sh
 [sudo] xcode-select --install
```

If you still haven't, you should get [Homebrew](https://brew.sh/).
You will actually need it to install dependencies:

```sh
 brew install cmake openssl gmp libsodium
```

You will only need to install RELIC, which can be done following the instructions found above, or use one of the scripts `install_relic_easy.sh`, `install_relic_gmp.sh`, or `install_relic_x64_asm.sh` depending on the arithmetic you prefer.

### Basic build

To build all of the targets with the default configuration in the `build` directory, run the following commands:

```sh
mkdir build && cd build
cmake ..
make
```

### Targets

The following targets can be built:

-   `debug_crypto`: the executable constructed from the `main.cpp` file. It must be used as a debugging tool (to develop new features).

-   `check`: unit tests. It uses [Google Test](https://github.com/google/googletest).

-   `test`: runs the unit tests produced by the previous target.

-   `sse_crypto`: the compiled library.

To only build the library, call `make sse_crypto` instead of just `make`.

### Build Configuration and Options

As the library builds using CMake, the configuration is highly configurable.
Like other CMake-based projects, options are set by passing `-DOPTION_NAME=value` to the `cmake` command.
For example, for a debug build, use `-DCMAKE_BUILD_TYPE=Debug`.
Also, you can change the compiler used for the project by setting the `CC` and `CXX` environment variables.
For example, if you wish to use Clang, you can set the project up with the following command
`CC=clang CXX=clang++ cmake ..`.

#### Options

This project's CMake takes the following options:

-   `ENABLE_COVERAGE=On|Off`: Respectively enables and disable the code coverage functionalities. Disabled by default.

-   `SANITIZE_ADDRESS=On|Off`: Compiles the library with [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer) when set to `On`. Great to check for stack/heap buffer overflows, memory leaks, ... Disabled by default.

-   `SANITIZE_UNDEFINED=On|Off`: When set to `On`, compiles the library with [UndefinedBehaviorSanitizer (UBSan)](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html). UBSan detects undefined behavior at runtime in your code. Disabled by default.

-   `opensse_ENABLE_WALL=On|Off`: Toggles the `-Wall` compiler option. On by default

-   `opensse_ENABLE_WEXTRA=On|Off`: Toggles the `-Wextra` compiler option. On by default

-   `opensse_ENABLE_WERROR=On|Off`: Toggles the `-Werror` compiler option to turn all warnings into errors. On by default

-   `CMAKE_BUILD_TYPE`: Sets the build type. See [CMake's documentation](https://cmake.org/cmake/help/v3.12/variable/CMAKE_BUILD_TYPE.html) for more details. The `Debug` build type is used by default. Use `Release` for an optimized build.

To see all the available options, and interactively edit them, you can also use the `ccmake` tool.

For more information about how to use CMake, take a look at [CMake's FAQ](https://gitlab.kitware.com/cmake/community/wikis/FAQ), or at the [documentation](https://cmake.org/cmake/help/v3.0/index.html).

This project used to support an OpenSSL-based backend for trapdoor functions. It is now deprecated as it is incompatible with the new OpenSSL 1.1.0 APIs.
The corresponding code will be removed at some point.

## Documentation

Documentation for the library's APIs can be built with Doxygen. There is a specific CMake target to build the documentation: use `$ make doc` to construct the HTML documentation. To display the documentation, open `build/src/doc/html/index.html`.

## Code coverage

Code coverage is available by passing the `-DENABLE_COVERAGE=On` option to CMake.
Once the tests have been run, a report can be then generated with the `lcov-genhtml` target.

So to generate the code coverage for all the tests, first install lcov with
`[sudo] apt-get install lcov` (on Ubuntu) or `brew install lcov` (on Mac OS). Then run

```sh
mkdir build && cd build
cmake -DENABLE_COVERAGE=On ..
make
make test
make lcov-geninfo && make lcov-genhtml
```

An HTML report will be available in the `build/lcov/html/selected_targets` directory.

## Contributors

An implementation of RSA (including key serialization functions) is embedded in `libsse_crypto`. It is originated from [mbedTLS](https://tls.mbed.org)).
The puncturable encryption code has been originally written by [Ian Miers](https://www.cs.jhu.edu/~imiers/) as a part of [libforwardsec](https://github.com/imichaelmiers/libforwardsec).
Unless otherwise stated, the rest of the code has been written by [Raphael Bost](https://raphael.bost.fyi/).

## Licensing

mbedTLS is released under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

Unless otherwise stated, the rest of the code is licensed under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl.html).

![AGPL](https://www.gnu.org/graphics/agplv3-88x31.png)
