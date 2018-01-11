# $Id: config.mk,v 1.7 Broadcom SDK $
# $Copyright: (c) 2006 Broadcom Corp.
# All Rights Reserved.$
#
# CDK make rules and definitions
#

#
# Provide reasonable defaults for configuration variables
#

# Default build directory
ifndef CDK_BLDDIR
CDK_BLDDIR = $(CDK)/build
endif

# Location to build objects in
CDK_OBJDIR = $(CDK_BLDDIR)/obj
override BLDDIR := $(CDK_OBJDIR)

# Location to place libraries
CDK_LIBDIR = $(CDK_BLDDIR)
LIBDIR := $(CDK_LIBDIR)

# Option to retrieve compiler version
ifndef CDK_CC_VERFLAGS
CDK_CC_VERFLAGS := -v
endif
CC_VERFLAGS = $(CDK_CC_VERFLAGS); 

# Default suffix for object files
ifndef CDK_OBJSUFFIX
CDK_OBJSUFFIX = o
endif
OBJSUFFIX = $(CDK_OBJSUFFIX)

# Default suffix for library files
ifndef CDK_LIBSUFFIX
CDK_LIBSUFFIX = a
endif
LIBSUFFIX = $(CDK_LIBSUFFIX)

#
# Set up compiler options, etc.
#

# Default include path
CDK_INCLUDE_PATH = -I$(CDK)/include

# Import preprocessor flags avoiding include duplicates
TMP_CDK_CPPFLAGS := $(filter-out $(CDK_INCLUDE_PATH),$(CDK_CPPFLAGS))

# Convenience Makefile flags for building specific chips
ifdef CDK_CHIPS
CDK_DSYM_CPPFLAGS := -DCDK_CONFIG_INCLUDE_CHIP_DEFAULT=0 
CDK_DSYM_CPPFLAGS += $(foreach chip,$(CDK_CHIPS),-DCDK_CONFIG_INCLUDE_${chip}=1) 
endif
ifdef CDK_NCHIPS
CDK_DSYM_CPPFLAGS += $(foreach chip,$(CDK_NCHIPS),-DCDK_CONFIG_INCLUDE_${chip}=0)
endif

TMP_CDK_CPPFLAGS += $(CDK_DSYM_CPPFLAGS)
export CDK_DSYM_CPPFLAGS

ifdef DSYMS
TMP_CDK_CPPFLAGS += -DCDK_CONFIG_CHIP_SYMBOLS_USE_DSYMS=1
endif

override CPPFLAGS = $(TMP_CDK_CPPFLAGS) $(CDK_INCLUDE_PATH)


# Import compiler flags
override CFLAGS = $(CDK_CFLAGS)




#
# Define standard targets, etc.
#

ifdef LOCALDIR
override BLDDIR := $(BLDDIR)/$(LOCALDIR)
endif

ifndef LSRCS
LSRCS = $(wildcard *.c)
endif
ifndef LOBJS
LOBJS = $(addsuffix .$(OBJSUFFIX), $(basename $(LSRCS)))
endif
ifndef BOBJS
BOBJS = $(addprefix $(BLDDIR)/,$(LOBJS))
endif

# Use CDK_QUIET=1 to control printing of compilation lines.
ifdef CDK_QUIET
Q = @
endif

#
# Define rules for creating object directories
#

.PRECIOUS: $(BLDDIR)/.tree

%/.tree:
	@$(ECHO) 'Creating build directory $(dir $@)'
	$(Q)$(MKDIR) $(dir $@)
	@$(ECHO) "Build Directory for $(LOCALDIR) created" > $@

#
# Configure build tools
#
include $(CDK)/make/maketools.mk
