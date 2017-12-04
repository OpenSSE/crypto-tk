#! /bin/sh
if [[ -z $CLANG_TIDY ]]; then
	CLANG_TIDY="clang-tidy"
fi

GLOBIGNORE='**/boost/**:boost/**:**/boost' # do not look into boost headers

COMPILE_OPTS="-std=c++14 -Weffc++ -Woverloaded-virtual -Wsign-promo -Wstrict-overflow=5 -D CHECK_TEMPLATE_INSTANTIATION -Wno-effc++ -march=native -fPIC -Wall -Wcast-qual -Wdisabled-optimization -Wformat=2 -Wmissing-declarations -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wstrict-overflow=5 -Wdeprecated -Wno-unused-function -O2 -DWITH_OPENSSL -Ibuild -Isrc -I/usr/local/opt/openssl/include"

LINE_FILTER="''"

eval "$CLANG_TIDY src/**/*.{hpp,cpp} -line-filter=$LINE_FILTER -- $COMPILE_OPTS"