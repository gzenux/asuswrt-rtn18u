
SKUDIR = $(INSTALLDIR)/ra_SKU

ifeq ($(BUILD_NAME), RT-AC52U)
SKU_2G_FCC  = "20131101_FCC_2.4GHz_SingleSKU.dat"
SKU_2G_CE   = "20131106_CE_2.4GHz_SingleSKU.dat"
SKU_5G_FCC  = "20131106_FCC_NCC_5GHz_RFMD_SingleSKU.dat"
SKU_5G_CE   = "20131101_CE_5GHz_RFMD_SingleSKU.dat"
SKU_2G_SG   = "20130826_SG_2.4GHz_SingleSKU.dat"
SKU_5G_SG   = "20130826_SG_5GHz_RFMD_SingleSKU.dat"
SKU_2G_AU   = "20131217_AU_2.4GHz_SingleSKU.dat"
SKU_5G_AU   = "20131217_AU_5GHz_RFMD_SingleSK.dat"
endif
ifeq ($(BUILD_NAME), RT-AC51U)
SKU_2G_FCC  = "20131101_FCC_2.4GHz_SingleSKU.dat"
SKU_2G_CE   = "20131106_CE_2.4GHz_SingleSKU.dat"
SKU_5G_FCC  = "20131106_FCC_NCC_5GHz_RFMD_SingleSKU.dat"
SKU_5G_CE   = "20131101_CE_5GHz_RFMD_SingleSKU.dat"
SKU_2G_SG   = "20130826_SG_2.4GHz_SingleSKU.dat"
SKU_5G_SG   = "20130826_SG_5GHz_RFMD_SingleSKU.dat"
SKU_2G_AU   = 
SKU_5G_AU   = 
endif
ifeq ($(BUILD_NAME), RT-N11P)
SKU_2G_FCC  = "20131101_FCC_2.4GHz_SingleSKU.dat"
SKU_2G_CE   = "20131106_CE_2.4GHz_SingleSKU.dat"
SKU_2G_SG   = "20130826_SG_2.4GHz_SingleSKU.dat"
SKU_5G_FCC  =
SKU_5G_CE   =
SKU_5G_SG   =
SKU_2G_AU   =
SKU_5G_AU   =
endif


SKU_FILES  = $(BUILD_NAME)/$(SKU_2G_FCC) $(BUILD_NAME)/$(SKU_2G_CE) $(BUILD_NAME)/$(SKU_5G_FCC) $(BUILD_NAME)/$(SKU_5G_CE)


# usage: $(call install_file, src_file, dest_file)
define install_file
	@( \
	if [ -e $(1) ]; then \
		install $(1) $(2) ; \
	else \
		echo "File ( $(1) ) not exist" ; exit 1; \
	fi; \
	)
endef



all clean:
	@if [ ! -d $(BUILD_NAME) ]; then \
		echo "No SingleSKU for $(BUILD_NAME)"; \
		exit 1; \
	fi

install: all
	@install -d $(SKUDIR)
ifneq ($(SKU_2G_FCC),)
	@install $(BUILD_NAME)/$(SKU_2G_FCC) $(SKUDIR)/SingleSKU_FCC.dat
endif
ifneq ($(SKU_2G_CE),)
	@install $(BUILD_NAME)/$(SKU_2G_CE)  $(SKUDIR)/SingleSKU_CE.dat
endif
ifneq ($(SKU_5G_FCC),)
	@install $(BUILD_NAME)/$(SKU_5G_FCC) $(SKUDIR)/SingleSKU_5G_FCC.dat
endif
ifneq ($(SKU_5G_CE),)
	@install $(BUILD_NAME)/$(SKU_5G_CE)  $(SKUDIR)/SingleSKU_5G_CE.dat
endif
ifneq ($(SKU_2G_SG),)
	@install $(BUILD_NAME)/$(SKU_2G_SG) $(SKUDIR)/SingleSKU_SG.dat
endif
ifneq ($(SKU_5G_SG),)
	@install $(BUILD_NAME)/$(SKU_5G_SG) $(SKUDIR)/SingleSKU_5G_SG.dat
endif
ifneq ($(SKU_2G_AU),)
	@install $(BUILD_NAME)/$(SKU_2G_AU) $(SKUDIR)/SingleSKU_AU.dat
endif
ifneq ($(SKU_5G_AU),)
	@install $(BUILD_NAME)/$(SKU_5G_AU) $(SKUDIR)/SingleSKU_5G_AU.dat
endif



.PHONY: all clean nstall
.PHONY: $(BUILD_NAME)
