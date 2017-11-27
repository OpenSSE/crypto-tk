# OpenSSE's Cryptographic Toolkit

[![build status](https://travis-ci.org/OpenSSE/crypto-tk.svg?branch=master)](https://travis-ci.org/OpenSSE/crypto-tk) 
[![Coverage Status](https://coveralls.io/repos/github/OpenSSE/crypto-tk/badge.svg)](https://coveralls.io/github/OpenSSE/crypto-tk)

The SSE protocols rely on high level cryptographic features such as pseudo-random functions, hash functions, encryption schemes, or incremental set hashing. The cryptographic layer provides interfaces and implementations of these features. 

For now, the hash function and encryption implementations rely on OpenSSL. This might (and probably will) in the future. However, this will have no influence on the code written using this library: the interfaces to the cryptographic services are *opaque*. It means that all implementation details are hidden. In particular, even if the implementation changes, the header files shouldn't.


## Why a new crypto library?

A lot of great crypto libraries exist out there (*e.g.* [libsodium](https://github.com/jedisct1/libsodium)). Unfortunately, they do not offer the level of abstraction needed to implement searchable encryption schemes easily. Indeed, cryptographic objects such as pseudo-random functions, trapdoor permutations, pseudo-random generators, *etc*, are building blocks of such constructions, and OpenSSL or libsodium do not offer interfaces to such objects.

This library provides these APIs so that the SSE implementer has consistent high-level crypto interfaces and does not have to care about the inner implementation of the blocks.


## Disclaimer

This is code for a **research project**. It **should not be used in practice**: the code lacks good C/C++ security practice, and it has never been externally reviewed.

## Building

Building is done through [SConstruct](http://www.scons.org).
 

### Dependencies

`libsse_crypto` uses the following dependencies

* [libsodium](https://download.libsodium.org/doc/)

* [Boost](http://www.boost.org/) Only headers from Boost are needed to build the library. As the incremental set hashing code relies on the [Endian](http://www.boost.org/doc/libs/release/libs/endian/) library, release older than 1.58 are necessary.

* [RELIC](https://github.com/relic-toolkit/relic) Some features (puncturable encryption) are based on cryptographic pairings. These are implemented using the RELIC toolkit. RELIC has many compilation options. To install RELIC, you can do the following:

```sh
git clone https://github.com/relic-toolkit/relic.git
cd relic
mkdir build; cd build
cmake -G "Unix Makefiles" -DMULTI=PTHREAD -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" -DARCH="X64"  -DRAND="UDEV" -DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DBENCH=0 -DTESTS=1 -DARITH=gmp -DFP_PRIME=254 -DFP_QNRES=off -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DBN_PRECI=256 -DFP_QNRES=on ../.
make 
make install
```
You can also replace the `-DARITH=gmp` option by `-DARITH=x64-asm-254` (for better performance) or `-DARITH=easy` (to get rid of the gmp dependency). Note that the first two depend on [gmp](https://gmplib.org).


#### Optional Dependencies

* [OpenSSL](https://www.openssl.org)'s cryptographic library (`libcrypto`). The trapdoor permutation is based on RSA, and `libsse_crypto` can use OpenSSL to implement RSA. The code has been compiled and tested using OpenSSL 1.0.2.

### Compiler/Assembler

`libsse_crypto` needs a compiler supporting C++14, and the [yasm](http://yasm.tortall.net) assembler. 
It has been successfully built and tested on Ubuntu 14 LTS using both clang 3.6 and gcc 4.9.3, and yasm 1.2.0 for the assembler, and on Mac OS X.12 using clang 9.0.0 and yasm 1.3.0.

### Setting up your system
Here is what is necessary to set your system up from scratch, and build `libsse_crypto` (you will need to build RELIC first though).

#### Ubuntu 14.04 LTS

```sh
 $ [sudo] add-apt-repository ppa:ubuntu-toolchain-r/test
 $ [sudo] apt-get update
 $ [sudo] apt-get install build-essential scons g++-4.9 libtool yasm libssl-dev libgmp-dev 
```

To set GCC 4.9 as the compiler, you have two options. Either set the environment variables `CC` and `CXX` to `gcc-4.9` and `g++-4.9` respectively, or edit the file `config.scons` to include the following lines:

```python
env['CC'] = 'gcc-4.9'
env['CXX'] = 'g++-4.9'
```

Then, to install the three dependencies, you can either follow the instructions of their website (in particular for libsodium and Boost), or use the embedded install scripts. These might have to be modified to fit your needs (e.g. if you do not want to install RELIC system-wide, or if you are not a sudoer).
To do so, move to directory `install_dependencies`, and run `./install_boost.sh` to download and move the boost headers in the `src` directory, `./install_sodium.sh` to download and install libsodium 1.0.15 and `./install_relic_ubuntu_14_easy.sh` to install RELIC with the `easy` arithmetic.
If you want to use the gmp arithmetic or the x64 assembly arithmetic, run respectively `./install_relic_ubuntu_14_gmp.sh` and `./install_relic_ubuntu_14_x64_asm.sh`.


#### Ubuntu 16.04 LTS

```sh
 $ [sudo] apt-get update
 $ [sudo] apt-get install build-essential scons libtool yasm libssl-dev libgmp-dev 
```

You can then install the Boost and libsodium as for Ubuntu 14.
For RELIC, use one of the scripts `install_relic_easy.sh`, `install_relic_gmp.sh`, or `install_relic_x64_asm.sh` depending on the arithmetic you prefer.

#### Mac OS

```sh
 $ [sudo] xcode-select --install
```

If you still haven't, you should get [Homebrew](http://brew.sh/). 
You will actually need it to install dependencies: 

```sh
 $ brew install yasm scons cmake openssl gmp boost libsodium
```

You will only need to install RELIC, which can be done following the instructions found above, or use one of the scripts `install_relic_easy.sh`, `install_relic_gmp.sh`, or `install_relic_x64_asm.sh` depending on the arithmetic you prefer.

### Targets

Three targets can be built:

* `debug_crypto`: the executable constructed from the `main.cpp` file. It must be used as a debugging tool (to develop new features). It is the default target, which can be built using only `scons`. 

* `check`: unit tests. It uses [Google Test](https://github.com/google/googletest).

* `lib`: the compiled library. It produces both the static and the shared versions of `libsse_crypto`, copied in the directory `library/lib`, together with the headers in `library/include`. If possible, unit tests are run before constructing the library.


To build the library, just enter in your terminal
``scons lib``.

### Building Configuration and Options 

The building script takes several options and can be easily configured to fit your system and your needs.

#### Configuration

The SConstruct files default values might not fit your system. For example, you might want to choose a specific C++ compiler.
You can easily change these default values without modifying the SConstruct file itself. Instead, create a file called `config.scons` and change the values in this file. For example, say you want to use clang instead of your default gcc compiler and you placed the headers and shared library for RELIC in some directories that are not in the compiler's include path, say
`~/relic/include` and `~/relic/lib`. Then you can use the following configuration file:

```python
Import('*')

env['CC'] = 'clang'
env['CXX'] = 'clang++'

env.Append(CPPPATH=['~/relic/include'])
env.Append(LIBPATH=['~/relic/lib'])
```

The `config.scons` will automatically be included by the main SConstruct script, and the options taken into account.


#### Options

The scons script takes the following options:

*  `no_aesni`: toggle the use of Intel's AES NI, which, when available, offer a huge speed up to the computation of AES. `no_aesni=1` disables the instructions. They are enabled by default.

*  `rsa_impl`: choose the RSA implementation. Available options are `rsa_impl=mbedTLS` and `rsa_impl=OpenSSL`. `mbedTLS` is the default option, and corresponds to the embedded implementation. `OpenSSL` requires OpenSSL's `libcrypto` to be available.

*  `static_relic`: choose to link between the static or the dynamic version of RELIC. This options is needed because RELIC's build script names the static library `relic_s` instead of `relic`. Use `static_relic=0` to link against the dynamic library, and `static_relic=1` for the static one. Uses the dynamic library by default.

*  `coverage`: `coverage=1` toggles on the flags needed for code coverage. Disabled by default.

*  `run_check`: By default, when the `check` target is built, the tests are automatically run upon successful compilation. The option `run_check=0` disables this behavior.

## Code coverage

Code coverage is available using the `coverage=1` option in the building script. A report can be then generated the `coverage.sh` script (which uses lcov). 

So to generate the code coverage for all the tests, first install lcov with
`[sudo] apt-get install lcov` (on Ubuntu) or `brew install lcov` (on Mac OS). Then run

```sh
$ scons check coverage=1
$ cd coverage
$ ./gen_coverage.sh && ./gen_report.sh
```

The HTML report will be available in the `report` directory.
To cleanup the `coverage` directory, run `./cleanup.sh`.

## Contributors

The code for the incremental (multi)set hash function has been written by Jeremy Maitin-Shepard.
It is directly available from its [GitHub repo](https://github.com/jbms/ecmh). The source files of the `src/ecmh` directory are directly taken from this codebase and its dependencies, with some minor fixes or modifications to make the code compile using gcc.

The implementation of the Blake2 hash functions has been written by [Samuel Neves](https://eden.dei.uc.pt/~sneves/).

SHA512 implementations are from Intel (x86 optimized assembly, using SSE4, AVX or AVX2) and ARM (C implementation from [mbed TLS](https://tls.mbed.org)).

An implementation of RSA (including key serialization functions) is embedded in `libsse_crypto`. It is originated from [mbed TLS](https://tls.mbed.org))

The puncturable encryption code has been originally written by [Ian Miers](http://www.cs.jhu.edu/~imiers/) as a part of [libforwardsec](https://github.com/imichaelmiers/libforwardsec).

Unless otherwise stated, the rest of the code has been written by [Raphael Bost](https://raphael.bost.fyi/).

## Licensing

Even if it is not explicitly stated, the ECMH code by Jeremy Maitin-Shepard (*i.e.* the the `src/ecmh` directory) must be considered as licensed under GPL (personal communications with Jeremy).

Blake2 implementations have been dedicated to the public domain (*cf.* [CC0 Public Domain Dedication](http://creativecommons.org/publicdomain/zero/1.0/)).

Intel's assembly code for SHA512 is covered by the Intel Open Software License (*cf.* `open_software_license.txt`).

mbed TLS is released under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

Unless otherwise stated, the rest of the code is licensed under the [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl.html).

![AGPL](http://www.gnu.org/graphics/agplv3-88x31.png)

