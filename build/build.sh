#!/usr/bin/env bash

# Simple script to create the Makefile and build

make distclean-local && make clean-local || echo "Clean failed, continuing anyway"

rm -f Makefile.in config.status VerusMinerDirect

#aclocal && autoheader && automake --add-missing --gnu --copy && autoconf || echo done
#vs
autoreconf -i
#🤦‍♂️️

extracflags=""

./configure CXXFLAGS="$extracflags"

make VerusMinerDirect
