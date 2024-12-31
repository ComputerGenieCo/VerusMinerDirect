AUTOMAKE_OPTIONS = foreign

if WANT_JANSSON
SUBDIRS = jansson
else
SUBDIRS =
endif

AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -Wall -Wextra
AM_CXXFLAGS = -Wall -Wextra

noinst_HEADERS = stdbool.h inttypes.h unistd.h sys/time.h getopt/getopt.h
EXTRA_DIST = gettimeofday.c getopt/getopt_long.c

CLEANFILES = *.o *~
DISTCLEANFILES = Makefile.in

clean:
	-rm -f *.o
	-rm -rf .deps

distclean-local:
	-rm -f Makefile.in Makefile
	-rm -rf .deps

maintainerclean-local: distclean-local

all-local:
	@echo "Building compat..."
