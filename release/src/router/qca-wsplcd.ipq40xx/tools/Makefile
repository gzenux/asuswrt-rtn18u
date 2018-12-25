
LIBS := -lwpa2

OBJS += ../ucpk_hyfi20.o ucpkgen.o

CFLAGS += -I..

ALL= ucpkgen

all: $(ALL)
	@echo tools compiled ok

install: all
#	cp -a $(ALL) $(INSTALL_ROOT)/sbin

ucpkgen: $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f core junk* *~ *.o *.d $(ALL)

-include $(OBJS:%.o=%.d)
