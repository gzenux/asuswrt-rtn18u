# Convert asuswrt build environment variable
TARGET_CROSS=$(CROSS_COMPILE)
LINUX_KARCH=$(ARCH)
LINUX_DIR=$(LINUXDIR)
LINUX_VERSION=$(LINUX_KERNEL)
KERNELRELEASE=1
PKG_BUILD_DIR=$(shell pwd)/source

# Define variables
INSTALLKMODDIR:=$(INSTALLDIR)/lib/modules/$(LINUX_VERSION)
QCAHYBRID_MODULE_LIST:=$(PKG_BUILD_DIR)/hyfi-bridging.ko

all:
	$(MAKE) -C "$(LINUX_DIR)" \
		M="$(PKG_BUILD_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		HYBRID_MC_MLD=1 \
		KERNELPATH= \
		KBUILDPATH="$(LINUX_DIR)" \
		KERNELRELEASE="$(KERNELRELEASE)" \
		MDIR="$(PKG_BUILD_DIR)" \
		modules

install:
	install -d $(INSTALLKMODDIR)
	install -m 755 $(foreach kmod,$(QCAHYBRID_MODULE_LIST),$(kmod)) $(INSTALLKMODDIR)
	$(STRIPX) $(INSTALLKMODDIR)/*.ko

clean:
	find $(PKG_BUILD_DIR) -type f -name ".*.o.cmd" \
		-o -name ".*.ko.cmd" \
		-o -name "*.o" \
		-o -name "modules.order" \
		-o -name "*.ko" \
		-o -name ".tmp_versions" \
		-o -name "Module.symvers" \
		-o -name "*.mod.c" | xargs rm -fr

stage:
	@touch $@
