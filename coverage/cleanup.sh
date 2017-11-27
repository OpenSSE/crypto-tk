#! /bin/sh
set -ex

shopt -s extglob

rm *.!(sh) # remove everything except the scripts
rm -r report # remove the report