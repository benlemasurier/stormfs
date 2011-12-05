AC_INIT(stormfs, [0.01])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR(src/stormfs.c)

AC_PROG_CC
AM_PROG_CC_C_O
CFLAGS="$CFLAGS -Wall -W -Wno-unused-parameter -std=c99 -pedantic"
LIBS=

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
PKG_CHECK_MODULES(STORMFS, [fuse >= 2.8.4 glib-2.0 >= 2.3.0  libcurl >= 7.0])

oldlibs="$LIBS"
LIBS="$LIBS $STORMFS_LIBS"

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
