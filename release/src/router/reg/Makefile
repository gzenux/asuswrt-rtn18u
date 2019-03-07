EXEC = reg

all:
	cp $(PREBUILD)/reg reg

install: all
	install -D $(EXEC) $(INSTALLDIR)/bin/$(EXEC)
	$(STRIP) $(INSTALLDIR)/bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
