
ifeq ($(wildcard *.c), )
all:
	-cp ./prebuilt/radpd .
else
all: $(TARGET) 
endif

clean:
	rm -f $(TARGET) core *.o

$(TARGET): $(OBJS) radpd.h radpd.c
	$(CC) -o $@ $(OBJS) $(LDOPTS) 
	$(STRIP) $@

%.o: %.c
	$(CC) -c $(COPTS) $< -o $@
