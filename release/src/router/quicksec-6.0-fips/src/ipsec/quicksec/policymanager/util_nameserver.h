/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   util_nameserver.h
*/

#ifndef _PM_UTIL_NAMESERVER_H_
#define _PM_UTIL_NAMESERVER_H_


/**********************************************************************
 * Callback function definitions.
 **********************************************************************/

/* Callback function for returning completion status.  `status' is TRUE
   if the operation was successful and FALSE if it failed. */
typedef void (*SshPmAddNameserverCB)(Boolean status, void * context);
typedef void (*SshPmRemoveNameserverCB)(Boolean status, void *context);


void ssh_pm_add_name_servers(SshInt32 num_dns,
                             SshIpAddr dns,
                             SshInt32 num_wins,
                             SshIpAddr wins,
                             SshPmAddNameserverCB callback,
                             void * context);
void ssh_pm_remove_name_servers(SshInt32 num_dns,
                             SshIpAddr dns,
                             SshInt32 num_wins,
                             SshIpAddr wins,
                             SshPmRemoveNameserverCB callback,
                             void * context);
#endif
