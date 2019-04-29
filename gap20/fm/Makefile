PWD=$(shell pwd)
top_srcdir=$(PWD)/..
APPLICATION = fm


SRCDIRS = .
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh

app_SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

PRIV_INCS += -I$(top_srcdir)/db/include
PRIV_LIBS += -lpthread -lcapi -lrt -lcrypt -levent -levent_pthreads -lsqlite3  -lutils \
        -L$(top_srcdir)/.lib

APPLICATION_OBJS=$(addsuffix .o, $(basename $(app_SOURCES)))

.PHONY: $(APPLICATION)

PRIV_INSTALL=fm_install
$(PRIV_INSTALL):
	install -d $(DEST_INSTALL)/usr/bin
	install -d $(DEST_INSTALL)/etc/fm/mod/
	install -m 0755 $(PWD)/fm $(DEST_INSTALL)/usr/bin/
	install -m 0755 $(PWD)/gen_conf.sh $(DEST_INSTALL)/usr/bin/
	install -m 0755 $(PWD)/cmd/* $(DEST_INSTALL)/usr/bin/
	install -m 0644 $(PWD)/mod/*.mod $(DEST_INSTALL)/etc/fm/mod/
	install -m 0644 $(PWD)/base_agent.conf $(DEST_INSTALL)/etc/fm/

include $(top_srcdir)/common.make
