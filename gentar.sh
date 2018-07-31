#!/bin/sh

RELEASE=`cat RELEASE`
mkdir  -p ../distfiles/bruteblock-${RELEASE}
rm -f ../distfiles/${RELEASE}/*
mkdir  -p ../distfiles/bruteblock-${RELEASE}/doc \
    ../distfiles/bruteblock-${RELEASE}/iniparse \
    ../distfiles/bruteblock-${RELEASE}/etc/bruteblock  \
    ../distfiles/bruteblock-${RELEASE}/etc/rc.d
cp *.h *.c Makefile ../distfiles/bruteblock-${RELEASE}/
cp iniparse/*.c iniparse/*.h iniparse/Makefile \
  ../distfiles/bruteblock-${RELEASE}/iniparse
cp doc/CHANGES doc/LICENSE  doc/THANKS doc/BUGS\
     doc/bruteblock.8 ../distfiles/bruteblock-${RELEASE}/doc/
sed s/@RELEASE@/${RELEASE}/g doc/README >../distfiles/bruteblock-${RELEASE}/doc/README
sed s/@RELEASE@/${RELEASE}/g doc/README.russian >../distfiles/bruteblock-${RELEASE}/doc/README.russian

cp -r etc/rc.d/* ../distfiles/bruteblock-${RELEASE}/etc/rc.d/
cp -r etc/bruteblock/* ../distfiles/bruteblock-${RELEASE}/etc/bruteblock/

sed s/@RELEASE@/${RELEASE}/g webroot/index.html.ru> ../index.html.ru
sed s/@RELEASE@/${RELEASE}/g webroot/index.html.en> ../index.html.en

cd ../distfiles;tar -cvzf bruteblock-${RELEASE}.tar.gz bruteblock-${RELEASE}
