
# 
# Building the dsym program
#

CFLAGS = -Wall -I$(CDK)/include -I$(CDK) -I. 

DSYM_SRCS = $(wildcard *.c)
DSYM_HDRS = $(wildcard *.h)
DSYM_OBJS = $(patsubst %.c, %.o, $(DSYM_SRCS))

%.o: %.c Makefile $(DSYM_HDRS) $(CDK)/pkgsrc/installed-chips
	gcc -g $(CFLAGS) $(CDK_DSYM_CPPFLAGS) -c $< -o $@

dsyms: $(DSYM_OBJS) Makefile 
	gcc -g -o dsyms -Wall $(DSYM_OBJS) $(CFLAGS) $(DEFINES)

clean:
	-rm -f dsyms *.o

