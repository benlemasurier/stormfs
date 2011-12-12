#!/bin/sh

autoreconf --force --install \
  && aclocal -I /usr/local/share/aclocal \
  && automake -a -c \
  && autoconf
