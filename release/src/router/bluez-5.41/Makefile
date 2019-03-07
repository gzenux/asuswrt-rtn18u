include ../common.mak
CFLAGS = -Os -Wall $(EXTRACFLAGS)

all:
ifeq ($(wildcard $(SRCBASE)/include/bluetooth),)
ifeq ($(wildcard bluetooth),)
	mkdir bluetooth
	cp -rf lib/* bluetooth
endif
	cp -rf bluetooth $(SRCBASE)/include
endif

install: all
	cp -f $(PREBUILD)/bccmd				tools/
	cp -f $(PREBUILD)/bluemoon				tools/
	cp -f $(PREBUILD)/ciptool				tools/
	cp -f $(PREBUILD)/hcitool				tools/
	cp -f $(PREBUILD)/hcidump				tools/
	cp -f $(PREBUILD)/hciattach			tools/
	cp -f $(PREBUILD)/hciconfig			tools/
	cp -f $(PREBUILD)/hid2hci				tools/
	cp -f $(PREBUILD)/l2ping				tools/
	cp -f $(PREBUILD)/l2test				tools/
	cp -f $(PREBUILD)/mpris-proxy			tools/
	cp -f $(PREBUILD)/rctest				tools/
	cp -f $(PREBUILD)/rfcomm				tools/
	cp -f $(PREBUILD)/sdptool				tools/
	cp -f $(PREBUILD)/bluetoothctl			client/
	cp -f $(PREBUILD)/bluetoothd			src/
	cp -f $(PREBUILD)/gatttool				attrib/

clean:


.PHONY: all clean
