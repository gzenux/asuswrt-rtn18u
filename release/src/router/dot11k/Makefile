include $(LINUXDIR)/.config
include $(TOP)/.config

CFLAGS += -Wall -O
CFLAGS += -DASUS
DOT11K_DEAMON = deamon
TEST_11K = test_11k

all:
	make -C $(DOT11K_DEAMON) clean
	make -C $(TEST_11K) clean
	make -C $(DOT11K_DEAMON)
	make -C $(TEST_11K)

install: all
	install -d $(INSTALLDIR)/usr/bin
	install $(DOT11K_DEAMON)/dot11k_deamon $(INSTALLDIR)/usr/bin
	install $(TEST_11K)/test_11k $(INSTALLDIR)/usr/bin
	$(STRIP) $(INSTALLDIR)/usr/bin/dot11k_deamon
	$(STRIP) $(INSTALLDIR)/usr/bin/test_11k
clean:
	make -C $(DOT11K_DEAMON) clean

.PHONY: all clean install
