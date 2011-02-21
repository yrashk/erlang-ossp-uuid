#! /bin/sh
LINUX=`uname | grep Linux | wc -l | xargs echo`
if [ -z "$LINUX" ]; then
   CFLAGS=
else
   CFLAGS=-fPIC
fi

[ -d deps/uuid-1.6.2 ] || (cd deps && tar xzvfp uuid-1.6.2.tar.gz && cd uuid-1.6.2 && CFLAGS=$CFLAGS ./configure -disable-debug --without-perl --without-php --without-pgsql && make)
