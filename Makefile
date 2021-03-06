PKG_CONFIG ?= pkg-config
CC=gcc

CFLAGS+=-c -Wall -O3 -DOSX  -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration 
LDFLAGS+=  -lm -lz -lpcap 
#LIBS=
#CFLAGS +=-DDEBUG
SOURCES=anonymization.c util.c sha1.c   mac-parser.c survey.c write.c
OBJECTS=  $(SOURCES:.c=.o)

OBJECTS_START= mac-darktest.o 
#OBJECTS_WRITE= write.o
EXECUTABLE=wifi_dump

all:  $(EXECUTABLE)


$(EXECUTABLE):   $(OBJECTS) $(OBJECTS_START)
	$(CC) $(LDFLAGS)  $(OBJECTS)  $(OBJECTS_START) -o $@

$(OBJECTS_START): mac-darktest.c
	$(CC)  -D_GNU_SOURCE  $(CFLAGS) -o $@ $<

# -DCONFIG_LIBNL20   -I$(STAGING_DIR)/usr/include/mac80211 -I$(STAGING_DIR)/usr/include/libnl-tiny
#$(OBJECTS_WRITE): write.c
#	$(CC)  -D_GNU_SOURCE  $(CFLAGS) -o $@ $<


.o:	%.c 
	$(CC) $(CFLAGS)  -o $@ $<


clean:
	rm -rf *.o mac-darktest
