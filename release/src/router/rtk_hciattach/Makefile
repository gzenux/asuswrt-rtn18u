#CC = msdk-linux-gcc
all: rtk_hciattach

rtk_hciattach: hciattach.c hciattach_rtk.o
	$(CC) -o rtk_hciattach hciattach.c hciattach_rtk.o

hciattach_rtk.o:hciattach_rtk.c
	$(CC) -c hciattach_rtk.c

clean:
	rm -f *.o  rtk_hciattach tags cscope.*

install:
	install -D rtk_hciattach $(INSTALLDIR)/bin/rtk_hciattach
	$(STRIP) $(INSTALLDIR)/bin/rtk_hciattach
	chmod 4755 $(INSTALLDIR)/bin/rtk_hciattach
tags: FORCE
	ctags -R
	find ./ -name "*.h" -o -name "*.c" -o -name "*.cc" -o -name "*.cpp" > cscope.files
	cscope -bkq -i cscope.files
PHONY += FORCE
FORCE:
