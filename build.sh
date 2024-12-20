#!/usr/bin/env bash

# Simple script to create the Makefile and build

if [[ $OSTYPE == 'darwin'* ]]; then
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
fi

make distclean || echo "Ran clean previous"

rm -f Makefile.in
rm -f config.status
aclocal && autoheader && automake --add-missing --gnu --copy && autoconf || echo "Run conf done"

extracflags=""

./configure CXXFLAGS="$extracflags"

make 
