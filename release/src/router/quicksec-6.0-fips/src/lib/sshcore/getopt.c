/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Source for IEEE Std1003.2-1992 (POSIX.2) compatible getopt.
   Uses ssh_getopt.  This is to be used as a replacement if system
   doesn't have one.
*/

#include "sshincludes.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "GetOptCompat"

int opterr = 1;
int optind = 1;
int optopt = 0;
int optreset = 0;
char *optarg = NULL;

static void ssh_set_externals(void);
static void ssh_get_externals(void);

int getopt(int argc, char * const argv[], const char *ostr)
{
  int r;

  ssh_get_externals();
  r = ssh_getopt(argc, argv, ostr, ((SshGetOptData)0));
  ssh_set_externals();
  return r;
}

static void ssh_get_externals()
{
  ssh_opterr = opterr;
  ssh_optind = optind;
  ssh_optopt = optopt;
  ssh_optarg = optarg;
  ssh_optreset = optreset;
}

static void ssh_set_externals()
{
  opterr = ssh_opterr;
  optind = ssh_optind;
  optopt = ssh_optopt;
  optarg = ssh_optarg;
}

/* eof (getopt.c) */
