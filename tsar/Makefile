DIRS = modules src

DEST_INSTALL ?=

all:
	for i in $(DIRS); do make -C $$i; done

clean:
	for i in $(DIRS); do cd $$i;make clean;cd ..; done

install: all
	#mkdir for tsar
	mkdir -p ${DEST_INSTALL}/usr/local/tsar/modules
	mkdir -p ${DEST_INSTALL}/etc/tsar
	mkdir -p ${DEST_INSTALL}/etc/cron.d
	mkdir -p ${DEST_INSTALL}/etc/logrotate.d/
	mkdir -p ${DEST_INSTALL}/usr/local/man/man8/
	mkdir -p ${DEST_INSTALL}/usr/bin
	#copy tsar shared so
	cp modules/*.so ${DEST_INSTALL}/usr/local/tsar/modules
	#copy bin file
	cp src/tsar ${DEST_INSTALL}/usr/bin/tsar
	#copy config file
	cp conf/tsar.conf ${DEST_INSTALL}/etc/tsar/tsar.conf
	cp conf/tsar.logrotate ${DEST_INSTALL}/etc/logrotate.d/tsar
	cp conf/tsar.cron ${DEST_INSTALL}/etc/cron.d/tsar
	#copy man file
	cp conf/tsar.8 ${DEST_INSTALL}/usr/local/man/man8/

tsardevel:
	mkdir -p ${DEST_INSTALL}/usr/local/tsar/devel
	cp devel/mod_test.c ${DEST_INSTALL}/usr/local/tsar/devel/mod_test.c
	cp devel/mod_test.conf ${DEST_INSTALL}/usr/local/tsar/devel/mod_test.conf
	cp devel/tsar.h ${DEST_INSTALL}/usr/local/tsar/devel/tsar.h
	cp devel/Makefile.test ${DEST_INSTALL}/usr/local/tsar/devel/Makefile.test
	cp devel/tsardevel ${DEST_INSTALL}/usr/bin/tsardevel

uninstall:
	#rm tsar
	rm -rf ${DEST_INSTALL}/usr/local/tsar
	rm -rf ${DEST_INSTALL}/etc/tsar/cron.d
	rm -f ${DEST_INSTALL}/etc/logrotate.d/tsar
	rm -f ${DEST_INSTALL}/etc/cron.d/tsar
	rm -f ${DEST_INSTALL}/usr/local/man/man8/tsar.8
	#rm tsar
	rm -f ${DEST_INSTALL}/usr/bin/tsar
	#rm tsardevel
	rm -f ${DEST_INSTALL}/usr/bin/tsardevel
	#backup configure file
	if [ -f ${DEST_INSTALL}/etc/tsar/tsar.conf ]; then mv ${DEST_INSTALL}/etc/tsar/tsar.conf ${DEST_INSTALL}/etc/tsar/tsar.conf.rpmsave; fi
	#backup the log data file
	if [ -f ${DEST_INSTALL}/var/log/tsar.data ]; then mv ${DEST_INSTALL}/var/log/tsar.data ${DEST_INSTALL}/var/log/tsar.data.bak; fi

tags:
	ctags -R
	cscope -Rbq
