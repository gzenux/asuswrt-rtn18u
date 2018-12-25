OBJS = mpstat.o rd_stats.o common.o count.o
CFLAGS += -g -O2 -Wall -Wstrict-prototypes -pipe
LDFLAGS += -s
	
mpstat: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

romfs:
	$(ROMFSINST) /bin/mpstat

install:
	install -D mpstat $(INSTALLDIR)/bin/mpstat

clean:
	rm -f core mpstat *.o
