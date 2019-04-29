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

ifeq ($(PLATFORM), x86)
PRIV_INCS = -I/usr/local/include
endif
PRIV_INCS += -I$(top_srcdir)/ha/include

PRIV_LIBS += -lutils -lhtp -levent -levent_pthreads -lprotobuf-c -lssl -lcrypto \
	 -lglib-2.0 -lpthread -lcapi -lncurses -lreadline -lrt -lcrypt -ldl\
	-L$(top_srcdir)/.lib -L../cmd_shell/lib \
	-L$(top_srcdir)/libs/$(PLATFORM)/readline \
	-L$(top_srcdir)/libs/$(PLATFORM)/openssl \
	-L$(top_srcdir)/libs/$(PLATFORM)/ncurses/lib/

PRIV_CFLAGS = -DHAVE_CONFIG_H

APPLICATION_OBJS=$(addsuffix .o, $(basename $(app_SOURCES)))

APPLICATION_LIBS=

.PHONY: $(APPLICATION)

PRIV_INSTALL=gap_install
$(PRIV_INSTALL):
	install -d $(DEST_INSTALL)/etc/openssl/certs
	install -d $(DEST_INSTALL)/etc/openssl/private
	install -m 0755 $(PWD)/../config/openssl/certs/gap.crt $(DEST_INSTALL)/etc/openssl/certs/
	install -m 0755 $(PWD)/../config/openssl/private/ca.crt $(DEST_INSTALL)/etc/openssl/private/
	install -m 0755 $(PWD)/../config/openssl/private/gap.key $(DEST_INSTALL)/etc/openssl/private/
	touch ${DEST_INSTALL}/etc/gap20.conf

include $(top_srcdir)/common.make
