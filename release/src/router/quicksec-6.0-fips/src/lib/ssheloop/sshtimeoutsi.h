/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Some internal functions for timeout handling. The platform
   independent functions are declared here, and implemented in
   sshtimeouts.c. The rest of the timeout code can be found from the
   event loop of the platform (sshunixeloop.c for Unix and
   win32/ssheloop.c for Windows).
*/

#ifndef SSHTIMEOUTSI_H_INCLUDED
#define SSHTIMEOUTSI_H_INCLUDED

#include "sshtimeouts.h"
#include "sshadt.h"
#include "sshadt_map.h"
#include "sshadt_priority_heap.h"

/* The timeout container structure. The timeouts are indexed by the
   identifier and by context for fast searches/and cancellation. The
   priority heap keeps the timeouts in the ascending order by their
   firing time.  */
typedef struct SshTimeoutContainerRec
{
  /* Priority heap in the timeout expiration order. */
  SshADTContainer ph_by_firing_time;
  /* Map by timeout ID */
  SshADTContainer map_by_identifier;
  /* Map by context */
  SshADTContainer map_by_context;

  /* The next timeout identifier */
  SshUInt64 next_identifier;

  /* Reference time for detecing clock moves */
  struct timeval reference_time;
} *SshTimeoutContainer, SshTimeoutContainerStruct;


/* Initialize the timeout container. Calls ssh_fatal if the
   initialization failed. */
void ssh_timeout_container_initialize(SshTimeoutContainer toc);

/* Uninitialize the event loop timeout container */
void ssh_timeout_container_uninitialize(SshTimeoutContainer toc);


/* Remove entries matching 'callback' and 'context' from the event
   loop context index from bucket pointed by 'cmh' (as in context map
   handle). This also removes the timeouts cancelled from the priority
   heap, and by-id mapping and frees dynamic entries. */
void
ssh_to_remove_from_contextmap(SshTimeoutContainer toc,
                              SshTimeoutCallback callback, void *context,
                              SshADTHandle cmh);

/* Checks if the clock has been adjusted (backward) and rearranges the
   timeout container accordingly */
void ssh_timeout_container_check_clock_jump(SshTimeoutContainer toc,
                                            struct timeval *tp);
#endif /* SSHTIMEOUTSI_H_INCLUDED */
