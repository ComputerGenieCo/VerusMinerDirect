# allow to use Host cuda functions in C/C++
#DEF_INCLUDES = @CUDA_INCLUDES@

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST		= autogen.sh README.md README.txt LICENSE.txt \
			  ccminer.sln ccminer.vcxproj ccminer.vcxproj.filters \
			  compat/gettimeofday.c compat/getopt/getopt_long.c

SUBDIRS = compat

bin_PROGRAMS = VerusMinerDirect

VerusMinerDirect_SOURCES	= elist.h miner.h compat.h \
			  compat/inttypes.h compat/stdbool.h compat/unistd.h bignum.cpp bignum.hpp \
			  compat/sys/time.h compat/getopt/getopt.h \
			  crc32.c signal_handler.cpp \
			  miner.cpp pools.cpp util.cpp \
			  api.cpp hashlog.cpp stats.cpp sysinfos.cpp \
			  verus/equi-stratum.cpp verus/verus_hash.cpp \
			  verus/haraka.c verus/verus_clhash.cpp



if HAVE_WINDOWS
VerusMinerDirect_SOURCES += compat/winansi.c
endif

VerusMinerDirect_LDFLAGS  = $(PTHREAD_FLAGS)

VerusMinerDirect_LDADD    = -lcurl @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @OPENMP_CFLAGS@ @LIBS@
VerusMinerDirect_CPPFLAGS = @OPENMP_CFLAGS@ $(CPPFLAGS) $(PTHREAD_FLAGS) -march=native -msse2avx -O3 -flto -fno-strict-aliasing $(JANSSON_INCLUDES) $(DEF_INCLUDES)


if HAVE_OSX
VerusMinerDirect_CXXFLAGS = -std=c++11
VerusMinerDirect_CPPFLAGS += -I/usr/local/llvm/lib/clang/4.0.0/include
endif

gitclean:
	git clean -fxd
