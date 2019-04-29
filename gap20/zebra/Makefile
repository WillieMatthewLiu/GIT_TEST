top_srcdir=..
APPLICATION = zebra


SRCDIRS   = . ./cmd
#add another SRCDIR
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh

zebra_SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

#PRIV_LDFLAGS = -L/usr/lib/x86_64-linux-gnu/samba -L/usr/local/lib

#PRIV_LIBS = -ltalloc -lndr -lmagic -lcap-ng -lpcap -lnet -ljansson -lpthread -lyaml -lpcre -lz -lrt -lsamba-util
ifeq ($(MEM_DEBUG), 1)
PRIV_LIBS += -L$(top_srcdir)/src/mmstat -lmmstat
endif
PRIV_LIBS = -lreadline -lcrypt -lncurses -lrt -lpthread  -lcap
PRIV_LIBS += -L../lib -lcapi -lcrypt -lha -levent -levent_pthreads
PRIV_LIBS += -L$(top_srcdir)/libthrift -lgobject-2.0 -lglib-2.0 -lffi -lm
#PRIV_LIBS += $(PLATFORM_LIBS)

#PRIV_INCS = -I. -I$(top_srcdir)/libhtp -I /usr/include/samba-4.0 -I $(top_srcdir)/libndropc/ndropc
ifeq ($(DPI_ARCH), x86)
PRIV_INCS = $(X86_PRIV_INCS)
endif
PRIV_INCS += ${addprefix -I./,${SRCDIRS}}
PRIV_INCS += -I${top_srcdir}/libincludes
PRIV_INCS += -I${top_srcdir}/libthrift
PRIV_INCS += -I../lib -I. -I../ -I../cmd -I${PWD}/../vtysh -I../sharecfg -I../ha
PRIV_CFLAGS += -DHAVE_CONFIG_H -Wno-missing-field-initializers -Wno-address -Wno-unused-function


#PRIV_CFLAGS = -Werror -D_SVID_SOURCE -DHAVE_CONFIG_H -DHAVE_LIB_NDROPC -DLOCAL_STATE_DIR=\"/usr/local/var\" -DENABLE_PKT_STS -DRELEASE -DHAVE_LIBNET11 -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H  -DLIBPCAP_VERSION_MAJOR=1 -DHAVE_PCAP_SET_BUFF -DHAVE_LIBCAP_NG -DENABLE_DCERPC_PNIO
#PRIV_CFLAGS = -D_SVID_SOURCE -DHAVE_CONFIG_H -DHAVE_LIB_NDROPC -DLOCAL_STATE_DIR=\"/usr/local/var\" -DENABLE_PKT_STS -DRELEASE -DHAVE_LIBNET11 -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H  -DLIBPCAP_VERSION_MAJOR=1 -DHAVE_PCAP_SET_BUFF -DHAVE_LIBCAP_NG -DENABLE_DCERPC_PNIO

APPLICATION_OBJS=$(addsuffix .o, $(basename $(zebra_SOURCES)))
#APPLICATION_LIBS=$(top_srcdir)/.lib/libhtp.a $(top_srcdir)/.lib/libndropc.a $(top_srcdir)/asn1c-parser/mms-parser/libmms.a
.PHONY: libcapi cmd_init libsharecfg

all: libcapi  $(APPLICATION) ch_attr 

LIBCAPI_DIR = ../lib
libcapi_SOURCES = $(foreach d,$(LIBCAPI_DIR),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
libcapi:$(libcapi_SOURCES)
	make -C ../lib
libsharecfg:
	make -C ../sharecfg
cmd_init:
	rm -f cmd_init.c cmd_init.h cmd_init.o
	bash parse.sh

ifeq ($(MEM_DEBUG), 1)
$(APPLICATION): libmmstat.so
libmmstat.so:
	make -C $(top_srcdir)/src/mmstat
endif

ch_attr:
	chmod +s $(APPLICATION)
	cp -f $(APPLICATION) $(top_srcdir)/.lib --preserve=all

PRIV_INSTALL=zebra_install
$(PRIV_INSTALL):
	install -d $(DEST_INSTALL)/usr/bin
	install -d $(DEST_INSTALL)/etc/gap
	touch ${DEST_INSTALL}/etc/gap/zebra.conf
	touch ${DEST_INSTALL}/etc/gap/zebra.conf.priv

include $(top_srcdir)/common.make
