#####################################################################
#																	 
#	Created by MIDE		17:06:54	07/30/02
#
#####################################################################

CROSS = $(CROSS_COMPILE)
OUTDIR	= .
OUTLIBDIR	= .
OUTNAME	= libcrypto.a
CC	= $(CROSS)gcc
AS	= $(CROSS)as
AR	= $(CROSS)ar
LD	= $(CROSS)ld
RM	= rm
STRIP = $(CROSS)strip
TOOLLDFLAGS	= -n
OPT	= -G 0
TEXT =
INCLUDES	= -I./crypto/include -I./crypto/include/openssl -I./
WARNING_FLAG = -Wall

CFLAGS	= $(WARNING_FLAG) -Os $(OPT) \
			-DOPENSSL_FIPS -D__linux__ -DRSDK_BUILT -DOPENSSL_NO_SPEED -DOPENSSL_THREADS -D_REENTRANT \
			-DDSO_DLFCN -DHAVE_DLFCN_H -DOPENSSL_NO_KRB5 -DB_ENDIAN -DTERMIO \
			-fomit-frame-pointer \
			$(INCLUDES)

ifeq ($(SLINK),1)
CFLAGS  += -ffunction-sections -fdata-sections
LDFLAGS += --static -Wl,--gc-sections
endif

CRT	=

LIBS	=

all: $(OUTLIBDIR)/$(OUTNAME)

include Files.mk

$(OUTLIBDIR)/$(OUTNAME) : $(OBJFILES)
	$(AR) rcs $(OUTLIBDIR)/$(OUTNAME) $(OBJFILES)

compile : $(OBJFILES)
