#! /bin/sh

[ -d deps/uuid-1.6.2 ] || (cd deps && tar xzvfp uuid-1.6.2.tar.gz && cd uuid-1.6.2 && ./configure -disable-debug --without-perl --without-php --without-pgsql && make)
