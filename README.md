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
Three targets can be built:

* `debug_crypto`: the executable constructed from the `main.cpp` file. It must be used as a debugging tool (to develop new features). It is the default target.

* `check`: unit tests. It uses [Google Test](https://github.com/google/googletest).

* `lib`: the compiled library. It produces both the static and the shared versions of `libsse_crypto`, copied in the directory `library/lib`, together with the headers in `library/include`. If possible, unit tests are run before constructing the library.


To build the library, just enter in your terminal
``scons lib ``.
### Dependencies

`libsse_crypto` uses the following dependencies

* [OpenSSL](https://www.openssl.org)'s cryptographic library (`libcrypto`). The code has been compiled and tested using OpenSSL 1.0.2.

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

### Compiler

`libsse_crypto` needs a compiler supporting C++14. It has been successfully built and tested on Ubuntu 14 LTS using both clang 3.6 and gcc 4.9.3 and on Mac OS X.10 using clang 7.0.0


## Contributors

The code for the incremental (multi)set hash function has been written by Jeremy Maitin-Shepard.
It is directly available from its [GitHub repo](https://github.com/jbms/ecmh). The source files of the `src/ecmh` directory are directly taken from this codebase and its dependencies, with some minor fixes or modifications to make the code compile using gcc.

The implementation of the Blake2 hash functions has been written by [Samuel Neves](https://eden.dei.uc.pt/~sneves/).

SHA512 implementations are from Intel (x86 optimized assembly, using SSE4, AVX or AVX2) and ARM (C implementation from [mbed TLS](https://tls.mbed.org)).

The puncturable encryption code has been originally written by [Ian Miers](http://www.cs.jhu.edu/~imiers/) as a part of [libforwardsec](https://github.com/imichaelmiers/libforwardsec).

Unless otherwise stated, the rest of the code has been written by [Raphael Bost](https://raphael.bost.fyi/).

## Licensing

Even if it is not explicitly stated, the ECMH code by Jeremy Maitin-Shepard (*i.e.* the the `src/ecmh` directory) must be considered as licensed under GPL (personal communications with Jeremy).

Blake2 implementations have been dedicated to the public domain (*cf.* [CC0 Public Domain Dedication](http://creativecommons.org/publicdomain/zero/1.0/)).

Intel's assembly code for SHA512 is covered by the Intel Open Software License (*cf.* `open_software_license.txt`).

mbed TLS is released under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

Unless otherwise stated, the rest of the code is licensed under the [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl.html).

![AGPL](http://www.gnu.org/graphics/agplv3-88x31.png)

