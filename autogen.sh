#! /bin/sh
export CFLAGS
export LDFLAGS
libtoolize --force --copy
aclocal
autoheader
automake -a -c
autoconf
autoheader
