AC_INIT([VerusMinerDirect], [3.9.0], [http://github.com/ComputerGenieCo/VerusMinerDirect/issues], [ccminerCPU], [http://github.com/ComputerGenieCo/VerusMinerDirect])
top_srcdir=$(cd "$(dirname "$0")/.."; pwd)

AC_PREREQ([2.71])
AC_CONFIG_SRCDIR([../src/main.cpp])
AM_INIT_AUTOMAKE([1.11 foreign subdir-objects -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([miner-config.h])

AM_MAINTAINER_MODE([enable])

dnl Checks for programs
AM_PROG_CC_C_O
AC_PROG_CXX
AM_PROG_AS
AC_PROG_RANLIB
AC_OPENMP

CXXFLAGS="-O2 -std=c++17"
CFLAGS="$CFLAGS -D_REENTRANT -I${top_srcdir}/src"

AC_SUBST(CFLAGS)
AC_MSG_NOTICE([Using compiler flags: $CFLAGS])

dnl Checks for header files
AC_CHECK_HEADERS([sys/endian.h sys/param.h syslog.h])
# sys/sysctl.h requires sys/types.h on FreeBSD
# sys/sysctl.h requires sys/param.h on OpenBSD
AC_CHECK_HEADERS([sys/sysctl.h], [], [],
[#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

AC_CHECK_DECLS([be32dec, le32dec, be32enc, le32enc], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_FUNC_ALLOCA
AC_CHECK_FUNCS([getopt_long])

case $target in
  i*86-*-*)
    have_x86=true
    ;;
  x86_64-*-*)
    have_x86=true
    have_x86_64=true
    ;;
  amd64-*-*)
    have_x86=true
    have_x86_64=true
    ;;
esac

PTHREAD_FLAGS="-pthread"
WS2_LIBS=""

case $target in
  *-*-mingw*)
    have_win32=true
    PTHREAD_FLAGS=""
    WS2_LIBS="-lws2_32"
    ;;
  *86*-apple-darwin*)
    have_osx=true
    PTHREAD_FLAGS=""
    ;;
esac

AC_CHECK_LIB(jansson, json_loads, request_jansson=false, request_jansson=true)
AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthread",
  AC_CHECK_LIB([pthreadGC2], [pthread_create], PTHREAD_LIBS="-lpthreadGC2",
    AC_CHECK_LIB([pthreadGC1], [pthread_create], PTHREAD_LIBS="-lpthreadGC1",
      AC_CHECK_LIB([pthreadGC], [pthread_create], PTHREAD_LIBS="-lpthreadGC"
))))

AC_CHECK_LIB([z],[gzopen], [], [])
AC_CHECK_LIB([ssl],[SSL_free], [], [AC_MSG_ERROR([OpenSSL library required])])
AC_CHECK_LIB([crypto],[EVP_DigestFinal_ex], [], [AC_MSG_ERROR([OpenSSL library required])])

AM_CONDITIONAL([WANT_JANSSON], [test x$request_jansson = xtrue])
AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([HAVE_OSX], [test x$have_osx = xtrue])
AM_CONDITIONAL([ARCH_x86], [test x$have_x86 = xtrue])
AM_CONDITIONAL([ARCH_x86_64], [test x$have_x86_64 = xtrue])

if test x$request_jansson = xtrue
then
    JANSSON_LIBS="${top_srcdir}/src/compat/jansson/libjansson.a"
else
    JANSSON_LIBS=-ljansson
fi

LIBCURL_CHECK_CONFIG(, 7.81.0, ,
  [AC_MSG_ERROR([Missing required libcurl >= 7.81.0])])

AC_SUBST(JANSSON_LIBS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(WS2_LIBS)

# Ensure proper directory handling
AC_CONFIG_FILES([
    Makefile
    ])

dnl find out what version we are running
ARCH=`uname -m`
if [[ $ARCH == "x86_64" ]];
then
  SUFFIX="64"
else
  SUFFIX=""
fi

if test x$have_osx = xtrue
then
  SUFFIX=""
fi

AC_SUBST(OPENMP_CFLAGS) 

AC_OUTPUT
