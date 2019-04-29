# export variables: PRIV_INCS, PRIV_CFLAGS, PRIV_LDFLAGS, 

ifeq ($(PLATFORM), mips)
PLATFORM_FLAGS= -DMIPS_PLATFORM
BASE_LIB = /usr/lib64
export PLATFORM_FLAGS
else 
ifeq ($(PLATFORM), arm)
PLATFORM_FLAGS= -DARM_PLATFORM
BASE_LIB = /usr/lib
export PLATFORM_FLAGS
else
PLATFORM_FLAGS= -DX86_PLATFORM
BASE_LIB = /usr/lib64
export PLATFORM_FLAGS
#export CC = gcc
#export CPP = gcc -E
#export AR = ar
#export RANLIB = ranlib
#export LD = ld
endif
endif

#DEBUG=1

export DEST_INSTALL=$(shell pwd)/image

year=${shell date +%y}
week=${shell date +%W}
realweek=${shell expr $(week) + 1}
SWE_PRODUCT="RSG-U1200"
SWE_APP="GAP"
SWE_VER_V="1"
SWE_VER_R="0"
SWE_VER_C="1"
SWE_VER_RD="SZ"
SWE_VER_YEAR="$(year)"
SWE_VER_WEEK="$(realweek)"
SWE_VER_BUILD="04"
SWE_VER_CUSTOM="01"
SWE_VER_GIT_HEAD="${shell git rev-parse --short HEAD}"
VERSION_FILE=swe_ver.h

LIBS_INC_ROOT = $(top_srcdir)/libs/$(PLATFORM)
INCS = -I./ -I$(top_srcdir)/ -I$(top_srcdir)/config/ -I$(top_srcdir)/lib/ \
	-I$(top_srcdir)/utils -I$(LIBS_INC_ROOT)/openssl -I$(LIBS_INC_ROOT)

#PROFILE = -pg
COMMON_CFLAGS += \
	$(PRIV_INCS) $(INCS) \
	-g -Wall -Wextra -std=gnu99 \
	-Wimplicit-function-declaration -fno-tree-pre -fno-strict-aliasing -Wno-unused-parameter \
	$(PROFILE)

ifdef DEBUG
COMMON_CFLAGS +=  -ggdb
else
COMMON_CFLAGS +=  -O2
endif

ifeq ($(GAP_ENABLE_GUANGTIE_FEATURE), 1)
COMMON_CFLAGS +=  -DGAP_ENABLE_GUANGTIE_FEATURE
endif

CFLAGS += $(COMMON_CFLAGS) $(PRIV_CFLAGS) $(PLATFORM_FLAGS) 

LDFLAGS = -L$(top_srcdir)/.lib $(PRIV_LDFLAGS) $(LIB_LOAD_DIR) -L$(top_srcdir)/libs/$(PLATFORM)
#ifeq ($(PLATFORM), x86)
#LDFLAGS +=  -L/usr/lib/x86_64-linux-gnu
#endif
#ifeq ($(PLATFORM), arm)
LDFLAGS += ${CFLAGS}
#endif

LDFLAGS += -rdynamic -lcap -ljson-c -lmysqlclient
#
# Common built targets:
#

${VERSION_FILE}:
	@mkdir -p $(dir $(VERSION_FILE))
	@( printf '#define SWE_PRODUCT %s\n' \
		'$(SWE_PRODUCT)' )>>  $@.tmp
	@( printf '#define SWE_APP %s\n' \
		'$(SWE_APP)' ) >> $@.tmp
	@( printf '#define SWE_VER_V %s\n' \
		'$(SWE_VER_V)' ) >> $@.tmp
	@( printf '#define SWE_VER_R %s\n' \
		'$(SWE_VER_R)' ) >> $@.tmp
	@( printf '#define SWE_VER_C %s\n' \
		'$(SWE_VER_C)' ) >> $@.tmp
	@( printf '#define SWE_VER_RD %s\n' \
		'$(SWE_VER_RD)' ) >> $@.tmp
	@( printf '#define SWE_VER_YEAR %s\n' \
		'$(SWE_VER_YEAR)' ) >> $@.tmp
	@( printf '#define SWE_VER_WEEK %s\n' \
		'$(SWE_VER_WEEK)' ) >> $@.tmp
	@( printf '#define SWE_VER_BUILD %s\n' \
		'$(SWE_VER_BUILD)' ) >> $@.tmp
	@( printf '#define SWE_VER_CUSTOM %s\n' \
		'$(SWE_VER_CUSTOM)' ) >> $@.tmp
	@( printf '#define SWE_VER_GIT_HEAD %s\n' \
		'$(SWE_VER_GIT_HEAD)' ) >> $@.tmp
	@cmp -s $@ $@.tmp && rm -f $@.tmp || mv -f $@.tmp $@

ifdef SHARE_LIB
$(SHARE_LIB):${VERSION_FILE} $(SHARE_LIB_OBJS)
	$(CC) -shared -Wl,-soname -Wl,$(SHARE_LIB) -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $(SHARE_LIB_OBJS) $(PRIV_LIBS) -lc
	mkdir -p $(top_srcdir)/.lib
	cp -f $@ $(top_srcdir)/.lib
endif

ifdef STATIC_LIB
$(STATIC_LIB):${VERSION_FILE} $(STATIC_LIB_OBJS)
	$(AR) cru $@ $(STATIC_LIB_OBJS)
	$(RANLIB) $@
	mkdir -p $(top_srcdir)/.lib
	cp -f $@ $(top_srcdir)/.lib
endif


ifdef SUBDIRS
SUBDIRSTARGET=subdirs
.PHONY: $(SUBDIRSTARGET) $(SUBDIRS)

$(SUBDIRSTARGET): $(SUBDIRS)

$(SUBDIRS):
	@echo "===> $@"; \
	if [ -f "$@/Makefile" ]; then \
		$(MAKE)  -C $@ $(MAKECMDGOALS) PLATFORM=$(PLATFORM) || exit $$?; \
	fi; \
	echo "<=== $@";
endif

ifdef APPLICATION
$(APPLICATION):$(SUBDIRSTARGET) ${VERSION_FILE} $(APPLICATION_OBJS) $(APPLICATION_LIBS)
	$(CC) -o $@ $(LDFLAGS) $(PRIV_LDFLAGS) $(APPLICATION_OBJS) $(APPLICATION_LIBS) $(PRIV_LIBS)
	mkdir -p $(top_srcdir)/.lib
	cp -f $@ $(top_srcdir)/.lib
endif

all:$(SUBDIRSTARGET) $(PRIV_ALL) $(SHARE_LIB) $(STATIC_LIB) $(APPLICATION)    

install: $(SUBDIRSTARGET) $(PRIV_INSTALL)
ifdef SHARE_LIB
	install -d $(DEST_INSTALL)$(BASE_LIB)
	install -m 0755 $(SHARE_LIB) $(DEST_INSTALL)$(BASE_LIB)
endif
ifdef APPLICATION
	install -d $(DEST_INSTALL)/usr/bin
	install -m 0755  $(APPLICATION)  $(DEST_INSTALL)/usr/bin
endif

#
# Generating dependency files in .deps/ directory while compiling
#
DEPDIR = .deps
%.o:%.c 
	-@[ -d $(DEPDIR) ] || mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) -c $< -o $@ -MD -MF $(@:.o=.d)
	@OUTFILE=`echo $*.d | sed -e 's/\//_/g'` && \
	(cp $*.d $(DEPDIR)/$$OUTFILE; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		    -e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $(DEPDIR)/$$OUTFILE; \
		    rm -f $*.d)
		    
%.o:%.S
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPDIR)/*.d

DEPDIR = .deps
DEPFILE = $(DEPDIR)/$(subst /,_,$*.d)
%.o %.gcno: %.cpp
	-@[ -d $(DEPDIR) ] || mkdir -p $(DEPDIR)
	$(CC) $(CXXFLAGS) $(ARCHFLAGS) -c $< -o $(@:.gcno=.o) -MD -MP -MF $(DEPFILE)


#
# clean
#
.PHONY: clean
clean: $(SUBDIRSTARGET)
	-rm -rf *.o *.a *~ .deps
	-rm -rf ./.lib
ifdef SHARE_LIB
	-rm -rf $(SHARE_LIB) $(SHARE_LIB_OBJS)
endif
ifdef STATIC_LIB
	-rm -rf $(STATIC_LIB) $(STATIC_LIB_OBJS)
endif
ifdef APPLICATION
	-rm -rf $(APPLICATION) $(APPLICATION_OBJS)
endif
	-rm -f unit_test/data/actual*
	#-rm -f $(VERSION_FILE)
	-rm -f ${shell find -name $(VERSION_FILE)}
realclean: clean
	@-rm -rf $(DEPDIR) *.d
