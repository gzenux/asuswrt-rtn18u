#
# $Id: ccfbfb41fcbb71ff1be9499f12b65733f817d27c $
#

SOURCES		:= rlm_ippool_tool.c
TARGET		:= rlm_ippool_tool
TGT_PREREQS	:= libfreeradius-radius.a
TGT_PRLIBS	:= ${LIBS}

SRC_CFLAGS	:= $(rlm_ippool_CFLAGS) 
TGT_LDLIBS	:= $(rlm_ippool_LDLIBS)

MAN		:= rlm_ippool_tool.8
