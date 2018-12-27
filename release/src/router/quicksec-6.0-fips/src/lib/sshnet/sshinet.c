/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInet"

/* The address string of the SSH_IPADDR_ANY. */
const char *const ssh_ipaddr_any = "*** SSH_IPADDR_ANY ***";
const char *const ssh_ipaddr_any_ipv4 = "0.0.0.0";
const char *const ssh_ipaddr_any_ipv6 = "0::0";


