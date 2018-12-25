#CC=rsdk-linux-gcc
CFLAGS := -s -Wall -c -Os $(CFLAGS)
LDFLAGS = -s -Wall

ifeq ($(SLINK),1)
CFLAGS  += -ffunction-sections -fdata-sections
LDFLAGS += --static -s -Wl,--gc-sections
endif

all:		test_11k

test_11k:		test_11k.o
			$(CC) $(LDFLAGS) -o test_11k test_11k.o 

clean:
			rm -f *.o
			rm -f test_11k

romfs:
	$(ROMFSINST) test_11k /bin/test_11k

test_11k.o:		test_11k.c 
			$(CC) $(CFLAGS) -o test_11k.o test_11k.c


