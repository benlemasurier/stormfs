#!/bin/sh

autoreconf --force --install --verbose
if [ -d /usr/local/share/aclocal ]
then
  aclocal -I /usr/local/share/aclocal
else
  aclocal
fi

automake -a -c \
  && autoconf
