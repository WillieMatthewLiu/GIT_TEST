top_srcdir=.
SUBDIRS = utils lib vtysh
ifeq ($(PLATFORM), x86)
SUBDIRS +=  fm ipt ha upgrade zebra gap20 loadbalance 
else
SUBDIRS += card
endif



include $(top_srcdir)/common.make

