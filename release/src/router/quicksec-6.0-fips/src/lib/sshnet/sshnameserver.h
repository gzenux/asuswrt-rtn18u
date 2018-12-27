/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for name server lookups.
*/

#ifndef SSHNAMESERVER_H
#define SSHNAMESERVER_H

#include "sshtcp.h"

/* Configuration structure for the name server module. Note,
   that if you want to configure the internal dns resolver
   use ssh_name_server_resolver() function (sshdns.h) to get
   the handle to the internal dns resolver, and configure it
   using the functions in the sshdnsresolver.h. */
typedef struct SshNameServerConfigRec {
  /* Timeout in useconds for the internal resolver. Defaults
     to 120 seconds. */
  SshUInt32 timeout;
  /* Use system resolver. Defaults to FALSE. */
  Boolean use_system;
  /* Allow non authorative data from the DNS to be returned
     to the caller. This means that we do not pursue the
     authorative data from the authorative DNS server, but
     instead just take the first reply we got from the
     net. */
  Boolean allow_non_authorative_data;
  /* Enable forwarding support by forwarding dns queries to
     safety belt first. This will automatically enable the
     non authorative data, use the safety belt first, and
     request recursive queries from that name server. If the
     safety belt does not know how to reply to the recursive
     query, and do not return value, then the dns library
     will try to fetch the data from the real dns servers
     again. Note, that this automatically enables the
     allow_non_authorative_data. */
  Boolean forward_dns_queries;
  /* Ignore default safety belt, i.e. do not read
     /etc/resolv.conf etc. If this is set then the safety
     belt will be empty after the initialization, so the
     resolver cannot be used before entries have been added
     to the safety belt using
     ssh_dns_resolver_safety_belt_add function (use
     ssh_name_server_resolver to get the resolver needed). */
  Boolean ignore_default_safety_belt;
} *SshNameServerConfig, SshNameServerConfigStruct;

/* Initialize the name server module. If you do not call this the module will
   automatically initialize itself with default values (i.e. config == NULL)
   when you call any of the functions first time. */
Boolean ssh_name_server_init(SshNameServerConfig config);

/* Signal the name server module to shut down. This function signals
   underlying layers to close any idle sockets so that ssh_event_loop_run()
   can return. It is safe to call this function multiple times. */
void ssh_name_server_shutdown(void);

/* Uninitialize the name server module. This is needed if you want to clean out
   the memory used by the name server module. */
void ssh_name_server_uninit(void);

/* Gets the name of the host we are running on.  To get the
   corresponding IP address(es), a name server lookup must be done
   using the functions below. */
void ssh_tcp_get_host_name(unsigned char *buf, size_t buflen);

/* Callback function for name server lookups.  The function should
   copy the result; the argument string is only valid until this call
   returns.  The result is only valid if error is SSH_TCP_OK. */
typedef void (*SshLookupCallback)(SshTcpError error,
                                  const unsigned char *result,
                                  void *context);

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list when calling the callback.  The host name may
   already be an ip address, in which case it is returned directly. */
SshOperationHandle ssh_tcp_get_host_addrs_by_name(const unsigned char *name,
                                                  SshLookupCallback callback,
                                                  void *context);

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list. The host name may already be an ip address,
   in which case it is returned directly. This is an simplification
   of function ssh_tcp_get_host_addrs_by_name for situations when
   the operation may block.

   The function returns NULL if the name can not be resolved. When the
   return value is non null, it is a pointer to a string allocated by
   this function, and must be freed by the caller when no longer
   needed. */
unsigned char *ssh_tcp_get_host_addrs_by_name_sync(const unsigned char *name);

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip
   address.  Calls the callback with either error or success.  The
   callback should copy the returned name. */
SshOperationHandle ssh_tcp_get_host_by_addr(const unsigned char *addr,
                                            SshLookupCallback callback,
                                            void *context);

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip
   address. This is an simplification of function
   ssh_tcp_get_host_by_addr for situations when the operation may
   block.

   Function returns NULL, if the reverse lookup fails for some reason,
   or pointer to dynamically allocated memory containing the host
   name.  The memory should be deallocated by the caller when no
   longer needed.  */
unsigned char *ssh_tcp_get_host_by_addr_sync(const unsigned char *addr);

#endif /* not SSHNAMESERVER_H */
