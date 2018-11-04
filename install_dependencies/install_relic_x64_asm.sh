#!/bin/sh

INSTALL_CMAKE=0;
CMAKE='cmake'

while getopts 'c' OPTION
do
  case $OPTION in
  c)	INSTALL_CMAKE=1; echo "Install CMAKE"
		;;
  esac
done
shift $(($OPTIND - 1))


set -ex

git clone https://github.com/relic-toolkit/relic.git
cd relic
mkdir build
cd build

if (($INSTALL_CMAKE == 1)); then
	# Download cmake
	curl -sSL https://cmake.org/files/v3.5/cmake-3.5.2-Linux-x86_64.tar.gz | tar -xz
	CMAKE='./cmake-3.5.2-Linux-x86_64/bin/cmake'
fi


$CMAKE -G "Unix Makefiles" -DSHLIB=on -DMULTI=PTHREAD -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native  -fPIC" -DARCH="X64"  -DRAND="UDEV" -DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DBENCH=0 -DTESTS=1 -DARITH=x64-asm-254 -DFP_PRIME=254 -DFP_QNRES=off -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DBN_PRECI=256 -DFP_QNRES=on ../.

make
sudo make install