#!/bin/sh

autoreconf -I /usr/local/share/aclocal --force --install \
  && aclocal \
  && automake -a -c \
  && autoconf
