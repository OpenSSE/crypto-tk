#! /bin/bash

if [[ -z $CLANG_FORMAT ]]; then
	CLANG_FORMAT="clang-format"
fi

shopt -s extglob nullglob

FILES=(src/*.{h,c,hpp,cpp})
FILES+=(src/include/sse/crypto/*.{h,c,hpp,cpp})
FILES+=(src/hash/*.{h,c,hpp,cpp})
FILES+=(src/ppke/*.{h,c,hpp,cpp})
FILES+=(src/tdp_impl/*.{h,c,hpp,cpp})
FILES+=(tests/*.{h,c,hpp,cpp})
FILES+=(bench/*.{h,c,hpp,cpp})

for file in "${FILES[@]}" ; do
    eval "$CLANG_FORMAT -i ${file}"
done

PATTERN=".*\\.\\(h\\|c\\|hpp\\|cpp\\)\$"

INVALID_FORMAT_FILES=$(git diff --name-only | grep "$PATTERN")


if [ -z "$INVALID_FORMAT_FILES" ]; then
    echo "All the source files are correctly formated."
else
    echo "The following files are incorrectly formated:"
    echo "$INVALID_FORMAT_FILES"
    exit 1
fi