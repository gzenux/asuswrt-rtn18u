# Convert asuswrt build environment variable to qca-wifi-fw
PKG_BUILD_DIR=$(shell pwd)/source

# Define variables for qca-wifi-fw
INSTALLFWDIR:=$(INSTALLDIR)/lib/firmware

all:
	@#Nothing to do

install:
	install -d $(INSTALLFWDIR)/AR900B/hw.1
	install -m 644 $(PKG_BUILD_DIR)/hw.1/* $(INSTALLFWDIR)/AR900B/hw.1
	install -m 644 $(PKG_BUILD_DIR)/hw.1/.filenames $(INSTALLFWDIR)/AR900B/hw.1
	install -d $(INSTALLFWDIR)/AR900B/hw.2
	install -m 644 $(PKG_BUILD_DIR)/hw.2/* $(INSTALLFWDIR)/AR900B/hw.2
	install -m 644 $(PKG_BUILD_DIR)/hw.2/.filenames $(INSTALLFWDIR)/AR900B/hw.2

clean:
	@#Nothing to do
