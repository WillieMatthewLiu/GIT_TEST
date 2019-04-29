PWD=$(shell pwd)
top_srcdir=$(PWD)/..
APPLICATION = gap20

DEBUG = 1
ifeq ($(PLATFORM), )
PLATFORM=x86
endif


SUBDIRS = 
SRCDIRS = .
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh

app_SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

#ifeq ($(PLATFORM), x86)
#PRIV_INCS = -I/usr/local/include
PRIV_INCS = -I$(SDKTARGETSYSROOT)/usr/include/
#endif
PRIV_INCS += -I$(top_srcdir)/
PRIV_INCS += -I$(top_srcdir)/ha/
PRIV_INCS += -I$(top_srcdir)/ipt/
PRIV_INCS += -I$(top_srcdir)/lib/
PRIV_INCS += -I$(top_srcdir)/utils/
PRIV_INCS += -I$(SDKTARGETSYSROOT)/usr/include/glib-2.0
PRIV_INCS += -I$(SDKTARGETSYSROOT)/usr/lib64/glib-2.0/include

PRIV_LIBS += -lssl -lcrypto -lcap -ldl -lm -levent -levent_pthreads -lglib-2.0 -lhtp -ljson-c\
	 -lmysqlclient -lprotobuf-c -lpthread  -lcrypt\
	-L$(top_srcdir)/.lib -lcapi -lha -lipt -lutils

PRIV_CFLAGS = -DHAVE_CONFIG_H

gap_app_SOURCES = $(filter-out %filter_init.c, $(app_SOURCES))
APPLICATION_OBJS=$(addsuffix .o, $(basename $(gap_app_SOURCES)))

APPLICATION_LIBS=

PARSER_FILES = ./parser_*.c
filter_init.c:${PARSER_FILES}
	#rm -f filter_init.*
	#./gen_parser_filter.pl ${PARSER_FILES} > filter_init.c

APPLICATION_OBJS += filter_init.o

.PHONY: $(APPLICATION)
APPLICATION:filter_init.o

PRIV_INSTALL=gap_install
$(PRIV_INSTALL):
	install -d $(DEST_INSTALL)/usr/bin
	install -d $(DEST_INSTALL)/etc/openssl/certs
	install -d $(DEST_INSTALL)/etc/openssl/private
	install -m 0755 $(PWD)/../config/openssl/certs/gap.crt $(DEST_INSTALL)/etc/openssl/certs/
	install -m 0755 $(PWD)/../config/openssl/private/ca.crt $(DEST_INSTALL)/etc/openssl/private/
	install -m 0755 $(PWD)/../config/openssl/private/gap.key $(DEST_INSTALL)/etc/openssl/private/
	install -d $(DEST_INSTALL)/etc/dbsql
	install -d $(DEST_INSTALL)/var/reportpy
	install -m 0755 $(PWD)/../script/gap.sql $(DEST_INSTALL)/etc/dbsql/
	install -m 0755 $(PWD)/../script/report.py $(DEST_INSTALL)/var/reportpy/
	install -m 0644 $(PWD)/../config/gap_sys_user.conf $(DEST_INSTALL)/etc/
	install -d ${DEST_INSTALL}/etc/gap
	touch ${DEST_INSTALL}/etc/gap/gap20_vty.conf
	touch ${DEST_INSTALL}/etc/gap/gap20_vty.conf.priv

include $(top_srcdir)/common.make
