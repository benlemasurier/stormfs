AC_INIT(stormfs, [0.01])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR(src/stormfs.c)

AC_PROG_CC
AM_PROG_CC_C_O
CFLAGS="$CFLAGS -Wall -W -Wno-unused-parameter -std=c99 -pedantic"

PKG_CHECK_MODULES([FUSE], [fuse >= 2.8.3])
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.22.5])
PKG_CHECK_MODULES([GTHREAD], [gthread-2.0])
PKG_CHECK_MODULES([CURL], [libcurl >= 7.16.0])

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_OUTPUT
