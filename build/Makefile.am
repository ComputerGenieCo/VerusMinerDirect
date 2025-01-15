# allow to use Host cuda functions in C/C++
#DEF_INCLUDES = @CUDA_INCLUDES@

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/../src/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST		= autogen.sh README.md README.txt LICENSE.txt \
			  ../src/compat/gettimeofday.c ../src/compat/getopt/getopt_long.c ../src/main.h

SUBDIRS = ../src/compat
DIST_SUBDIRS = $(SUBDIRS)

bin_PROGRAMS = VerusMinerDirect

VerusMinerDirect_SOURCES	= ../src/elist.h ../src/main.h ../src/compat.h \
			  ../src/compat/inttypes.h ../src/compat/stdbool.h ../src/compat/unistd.h ../src/bignum.cpp ../src/bignum.hpp \
			  ../src/compat/sys/time.h ../src/compat/getopt/getopt.h \
			  ../src/crc32.c ../src/signal_handler.cpp ../src/config.cpp ../src/logging.cpp \
			  ../src/main.cpp ../src/workio.cpp ../src/daemon.cpp ../src/pools.cpp ../src/util.cpp \
			  ../src/api.cpp ../src/hashlog.cpp ../src/stats.cpp ../src/sysinfos.cpp \
			  ../src/stratum.cpp ../src/verus_stratum.cpp ../src/verus/verus_hash.cpp \
			  ../src/verus/haraka.c ../src/verus/verus_clhash.cpp



if HAVE_WINDOWS
VerusMinerDirect_SOURCES += ../src/compat/winansi.c
endif

VerusMinerDirect_LDFLAGS  = $(PTHREAD_FLAGS)

VerusMinerDirect_LDADD    = -lcurl @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @OPENMP_CFLAGS@ @LIBS@
VerusMinerDirect_CPPFLAGS = @OPENMP_CFLAGS@ $(CPPFLAGS) $(PTHREAD_FLAGS) -march=native -msse2avx -O3 -flto -fno-strict-aliasing $(JANSSON_INCLUDES) $(DEF_INCLUDES)


if HAVE_OSX
VerusMinerDirect_CXXFLAGS = -std=c++11
VerusMinerDirect_CPPFLAGS += -I/usr/local/llvm/lib/clang/4.0.0/include
endif

MAINTAINERCLEANFILES = Makefile.in Makefile
CLEANFILES = *.o verus/*.o
DISTCLEANFILES = *.o 

clean-local:
	-rm -f $(CLEANFILES)
	-rm -f $(DISTCLEANFILES)
	-rm -rf .deps

distclean-local:
	-rm -f $(DISTCLEANFILES)
	-rm -rf .deps

maintainer-clean-local:
	-rm -f $(MAINTAINERCLEANFILES)

gitclean:
	git clean -fxd
