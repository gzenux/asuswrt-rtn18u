# libbcmcrypto
include $(TOP)/.config

vpath %.o $(SRCBASE)/router/libbcmcrypto/$(PREBUILT)

ifeq ($(RTCONFIG_HND_ROUTER_AX),y)
OBJS := aes.o aeskeywrap.o rijndael-alg-fst.o dh.o bn.o passhash.o md5.o rc4.o random.o sha2.o sha2x.o
else
OBJS := aes.o aeskeywrap.o rijndael-alg-fst.o dh.o bn.o sha1.o passhash.o prf.o md5.o hmac.o rc4.o random.o
endif
OBJS += sha256.o hmac_sha256.o

all: libbcmcrypto.so

install: all
	install -d $(INSTALLDIR)/usr/lib
	install -m 755 libbcmcrypto.so $(INSTALLDIR)/usr/lib
	$(STRIP) $(INSTALLDIR)/usr/lib/libbcmcrypto.so

clean:
	rm -f *.so

libbcmcrypto.so: $(OBJS)
	$(LD) -shared -o $@ $^
