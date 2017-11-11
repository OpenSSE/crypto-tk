#!/bin/sh
set -ex


wget -q https://download.libsodium.org/libsodium/releases/libsodium-1.0.15.tar.gz
tar xf libsodium-1.0.15.tar.gz

cd libsodium

./configure
make -j4
sudo make install