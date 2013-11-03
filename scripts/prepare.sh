#! /bin/sh
LINUX=`uname | grep Linux | wc -l | xargs echo`
if [ -z "$LINUX" ]; then
   CFLAGS=
else
   CFLAGS=-fPIC
fi

ERLWS=`erl -noshell -eval "io:format(\"~p\",[erlang:system_info(wordsize)])" -s erlang halt`

if [ "$ERLWS" == 4 ]; then
   CFLAGS=-m32
   LDFLAGS=-m32
fi

[ -d deps/uuid-1.6.2 ] || (cd deps && tar xzvfpo uuid-1.6.2.tar.gz && cd uuid-1.6.2 && CFLAGS=$CFLAGS LDFLAGS=$LDFLAGS ./configure -disable-debug --without-perl --without-php --without-pgsql && make)
