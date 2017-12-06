#! /bin/sh
set -ex

shopt -s extglob

rm coverage/*.!(sh) # remove everything except the scripts
rm -r coverage/report # remove the report