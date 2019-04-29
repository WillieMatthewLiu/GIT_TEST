top_srcdir=..

APPLICATION = gap_upgrade


SRCDIRS = .
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh

app_SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

PRIV_INCS = -I$(top_srcdir)/ha

PRIV_LIBS += -lpthread -lcapi -lncurses -lreadline -lrt -lcrypt -ldl  -lutils -lssl -lcrypto -lha -lm\
	 -levent -levent_pthreads \
        -L$(top_srcdir)/ha/ -L../cmd_shell/lib -L$(top_srcdir)/libs/$(PLATFORM)/readline \
        -L$(top_srcdir)/libs/$(PLATFORM)/openssl -L$(top_srcdir)/libs/$(PLATFORM)/ncurses/lib/

PRIV_CFLAGS = -DHAVE_CONFIG_H

APPLICATION_OBJS=$(addsuffix .o, $(basename $(app_SOURCES)))

APPLICATION_LIBS=

.PHONY: $(APPLICATION)

PRIV_INSTALL=gu_install
$(PRIV_INSTALL):
	install -d $(DEST_INSTALL)/etc/gap
	touch $(DEST_INSTALL)/etc/gap/gu.conf
	touch $(DEST_INSTALL)/etc/gap/gu.conf.priv
	install -d $(DEST_INSTALL)/usr/bin
	install -m 0755 ${SRCDIRS}/ShowImage ${DEST_INSTALL}/usr/bin/

include $(top_srcdir)/common.make
