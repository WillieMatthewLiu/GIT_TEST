top_srcdir=..

OBJEXT=o
APPLICATION = vtysh$(EXEEXT)
nodist_vtysh_OBJECTS = vtysh_cmd.$(OBJEXT)
SOURCES = $(vtysh_SOURCES) $(nodist_vtysh_SOURCES)
DIST_SOURCES = $(vtysh_SOURCES)
VTYSH = vtysh

vtysh_SOURCES = vtysh_main.c vtysh.c vtysh_user.c vtysh_config.c 
nodist_vtysh_SOURCES = vtysh_cmd.c

CLEANFILES = vtysh_cmd.c
noinst_HEADERS = vtysh.h vtysh_user.h
SRCEXTS = .c

ifeq ($(PLATFORM), mips)
APP_DIR = $(top_srcdir)/gap20
APP_SOURCES = $(foreach d,$(DPI_DIR),$(wildcard $(addprefix $(d)/*,gap_cmd$(SRCEXTS))))

HA_DIR = $(top_srcdir)/ha
HA_SOURCES = $(foreach d,$(HA_DIR),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

vtysh_cmd_FILES = $(APP_DIR)/*.c $(HA_DIR)/*cmd.c
vtysh_cmd_SOURCES = $(foreach d,$(APP_DIR),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
vtysh_cmd_SOURCES += $(HA_SOURCES)
vtysh_cmd_SOURCES += ../lib/vty.c

vtysh_cmd_FILES += $(top_srcdir)/upgrade/*.c
vtysh_cmd_SOURCES +=  $(top_srcdir)/upgrade/*.c
else
APP_DIR = $(top_srcdir)/gap20
APP_SOURCES = $(foreach d,$(DPI_DIR),$(wildcard $(addprefix $(d)/*,gap_cmd$(SRCEXTS))))

HA_DIR = $(top_srcdir)/ha
HA_SOURCES = $(foreach d,$(HA_DIR),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))

vtysh_cmd_FILES = $(APP_DIR)/*.c $(HA_DIR)/*cmd.c
vtysh_cmd_SOURCES = $(foreach d,$(APP_DIR),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))
vtysh_cmd_SOURCES += $(HA_SOURCES)
vtysh_cmd_SOURCES += ../lib/vty.c

vtysh_cmd_FILES += $(top_srcdir)/upgrade/*.c
vtysh_cmd_SOURCES +=  $(top_srcdir)/upgrade/*.c
endif
vtysh_cmd_FILES += ../lib/vty.c ../zebra/*.c

am_vtysh_OBJECTS = vtysh_main.$(OBJEXT) vtysh.$(OBJEXT) vtysh_user.$(OBJEXT) vtysh_config.$(OBJEXT)
nodist_vtysh_OBJECTS = vtysh_cmd.$(OBJEXT)
vtysh_OBJECTS = $(am_vtysh_OBJECTS) $(nodist_vtysh_OBJECTS)

PRIV_INCS = -I$(top_srcdir)/libs/

PRIV_LIBS += -lreadline -lcapi -lcrypt -lncurses -lrt -lpthread  -lcap 
PRIV_LDFLAGS= -L../lib
EXTRA_DIST= ./extract.pl


PRIV_CFLAGS+=-I../lib -I../ -DHAVE_CONFIG_H -ggdb -I../cmd
PRIV_CFLAGS += -Wno-unused-variable \
			   -Wno-missing-field-initializers \
			   -Wno-unused-but-set-variable \
			   -Wno-unused-result

APPLICATION_OBJS=$(vtysh_OBJECTS)

all: $(APPLICATION) ch_attr
APPLICATION: vtysh_cmd.o
vtysh_cmd.c: $(DPI_SOURCES) $(vtysh_cmd_SOURCES)
	./$(EXTRA_DIST) $(vtysh_cmd_FILES) > vtysh_cmd.c
	@echo aaaaaaaaaa$(vtysh_cmd_FILES)
	@sed -i "s/VTYSH_GAP20,/VTYSH_APP,/g" vtysh_cmd.c
	@sed -i "s/VTYSH_CARD,/VTYSH_APP,/g" vtysh_cmd.c
vtysh_cmd.o: vtysh_cmd.c

ch_attr:
	chmod +s $(APPLICATION)
	cp -f $(APPLICATION) $(top_srcdir)/.lib --preserve=all

.PHONY:  cp_agent
LIBCAPI_DIR = ../lib


include $(top_srcdir)/common.make
