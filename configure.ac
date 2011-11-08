AC_PREREQ([2.60])
AC_INIT([stormfs], [0.01])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/stormfs.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_INSTALL

AC_CONFIG_FILES([Makefile src/Makefile])

PKG_CHECK_MODULES([DEPS], [fuse >= 2.8.4, libcurl >= 7.0])

AC_OUTPUT
