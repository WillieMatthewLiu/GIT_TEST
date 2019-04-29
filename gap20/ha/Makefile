top_srcdir=../
STATIC_LIB = libha.a
APPLICATION = ha

SRCDIRS = .
#add another SRCDIR
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh


STATIC_LIB_SOURCES = ha_agent.c arp.c ha_appmgr.c 

#PRIV_LIBS += -lreadline -lcrypt -lncurses

PRIV_INCS = $(X86_PRIV_INCS)
PRIV_INCS += ${addprefix -I./,${SRCDIRS}}
PRIV_INCS += -I.
PRIV_CFLAGS += -DHAVE_CONFIG_H \
			   -Wno-missing-field-initializers \
			   -Wno-address \
			   -Wno-sign-compare \
			   -Wno-unused-but-set-variable \
			   -Wno-unused-function \
			   -Wno-unused-result \
			   -Wno-unused-variable \
			   -Wno-type-limits
PRIV_CFLAGS += -fPIC

STATIC_LIB_OBJS=$(addsuffix .o, $(basename $(STATIC_LIB_SOURCES)))



app_SOURCES = main.c ha_cmd.c ha_common.c ha_conf.c ha_election.c ha_heartbeat.c ha_init.c \
        ha_statemgr.c ha_syncmgr.c inout_partner.c ipm.c

PRIV_LIBS += -lpthread -lcapi -lncurses -lreadline -lrt -lcrypt -ldl -lha -lcapi -lutils -levent -levent_pthreads -lm\
        -lprotobuf -lprotobuf-c -L$(top_srcdir)/libs -L../cmd_shell/lib -L$(top_srcdir)/libs/$(PLATFORM)/readline \
        -L$(top_srcdir)/libs/$(PLATFORM)/openssl -L$(top_srcdir)/libs/$(PLATFORM)/ncurses/lib/ \
        -L$(top_srcdir)/ha

PRIV_CFLAGS = -DHAVE_CONFIG_H

APPLICATION_OBJS=$(addsuffix .o, $(basename $(app_SOURCES)))

APPLICATION_LIBS=

.PHONY: $(APPLICATION)

PRIV_INSTALL=ha_install
$(PRIV_INSTALL):
	install -d $(DEST_INSTALL)/etc/gap
	touch $(DEST_INSTALL)/etc/gap/ha.conf
	touch $(DEST_INSTALL)/etc/gap/ha.conf.priv

include $(top_srcdir)/common.make
