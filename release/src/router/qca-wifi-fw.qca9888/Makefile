# Convert asuswrt build environment variable to qca-wifi-fw
PKG_BUILD_DIR=$(shell pwd)/source

# Define variables for qca-wifi-fw
INSTALLFWDIR:=$(INSTALLDIR)/lib/firmware

all:
	@#Nothing to do

install:
	install -d $(INSTALLFWDIR)/QCA9888/hw.2
	install -m 644 $(PKG_BUILD_DIR)/hw.2/* $(INSTALLFWDIR)/QCA9888/hw.2
#	install -m 644 $(PKG_BUILD_DIR)/hw.2/.filenames $(INSTALLFWDIR)/QCA9888/hw.2
	[ ! -e $(BUILD_NAME) ] || install -m 644 $(BUILD_NAME)/*.bin $(INSTALLFWDIR)/QCA9888/hw.2

clean:
	@#Nothing to do
