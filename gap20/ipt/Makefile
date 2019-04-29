top_srcdir=../

SRCDIRS = .
#add another SRCDIR
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh

LIB_SOURCES_ALL = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
LIB_SOURCES = $(shell echo ${LIB_SOURCES_ALL} | sed "s/\(.*\)\.\/zclient.c\(.*\)/\1\2/g")

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

STATIC_LIB = libipt.a
STATIC_LIB_OBJS = ipt_ctl.o

PRIV_INSTALL=ipt_install
$(PRIV_INSTALL): 
	install -d $(DEST_INSTALL)/usr/bin
	install -m 0755 $(top_srcdir)/config/iptables_init_inner $(DEST_INSTALL)/usr/bin
	install -m 0755 $(top_srcdir)/config/iptables_init_outer $(DEST_INSTALL)/usr/bin

include $(top_srcdir)/common.make

