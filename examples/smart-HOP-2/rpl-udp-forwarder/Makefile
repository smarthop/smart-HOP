CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
all: udp-forwarder
APPS=servreg-hack
CONTIKI=../../..
UIP_CONF_IPV6=1


ifdef WITH_COMPOWER
APPS+=powertrace
CFLAGS+= -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4
endif

ifdef SERVER_REPLY
CFLAGS+=-DSERVER_REPLY=$(SERVER_REPLY)
endif
ifdef PERIOD
CFLAGS+=-DPERIOD=$(PERIOD)
endif

CFLAGS+= -DUIP_CONF_IPV6_RPL -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

include $(CONTIKI)/Makefile.include
