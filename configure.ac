AC_PREREQ([2.60])
AC_INIT([stormfs], [0.01])

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/stormfs.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

CFLAGS="$CFLAGS -Wall -W"
LIBS="-lfuse -lcurl"

PKG_CHECK_MODULES([DEPS], [fuse >= 2.8.4, libcurl >= 7.0, glib-2.0 >= 2.3.0])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
