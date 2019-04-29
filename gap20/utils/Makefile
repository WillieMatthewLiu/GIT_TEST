top_srcdir=..
STATIC_LIB = libutils.a

SRCDIRS = .
#add another SRCDIR
SRCEXTS = .c .C .cc
#HDREXTS = .h .H .hh

STATIC_LIB_SOURCES_ALL = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
STATIC_LIB_SOURCES = $(shell echo ${STATIC_LIB_SOURCES_ALL} | sed "s/\(.*\)\.\/zclient.c\(.*\)/\1\2/g")

#PRIV_LIBS += -lreadline -lcrypt -lncurses

PRIV_INCS = $(X86_PRIV_INCS)
PRIV_INCS += ${addprefix -I./,${SRCDIRS}}
PRIV_INCS += -I. -I../include 
PRIV_CFLAGS += -DHAVE_CONFIG_H\
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

include $(top_srcdir)/common.make
