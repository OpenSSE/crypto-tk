#! /bin/bash

if [[ -z $CLANG_FORMAT ]]; then
	CLANG_FORMAT="clang-format"
fi


PATTERN=".*\\.\\(h\\|c\\|hpp\\|cpp\\)\$"

FILES="$(ls -d src/* | grep "$PATTERN")"
FILES+=$'\n'"$(ls -d src/hash/* | grep "$PATTERN")"
FILES+=$'\n'"$(ls -d src/ppke/* | grep "$PATTERN")"
FILES+=$'\n'"$(ls -d src/tdp_impl/* | grep "$PATTERN")"

for file in $FILES ; do
    eval "$CLANG_FORMAT -i ${file}"
done

INVALID_FORMAT_FILES=$(git diff --name-only | grep "$PATTERN")


NUM_INVALID_FILE=$(echo $INVALID_FORMAT_FILES | wc -l)

if [ $NUM_INVALID_FILE == "0" ]; then
    echo "All the source files are correctly formated."
else
    echo "The following files are incorrectly formated:"
    echo $INVALID_FORMAT_FILES
    exit 1
fi