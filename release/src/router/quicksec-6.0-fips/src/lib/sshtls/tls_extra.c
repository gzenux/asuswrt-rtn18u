/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"

#ifdef SSHDIST_FUNCTIONALITY_TLS
/* Keep the distribution defines. This serves as a placeholder on
   distributions not containing, but augmentable with, TLS */

#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshstream.h"

#define SSH_DEBUG_MODULE "SshTlsExtra"

void ssh_tls_set_destroy_callback(SshStream stream,
                                  SshTlsGenericNotification callback,
                                  void *context)
{
  SshTlsProtocolState s = ssh_stream_get_context(stream);
  s->extra.deleted_notify = callback;
  s->extra.deleted_notify_context = context;
}

void ssh_tls_set_extra_flags(SshStream stream,
                             SshUInt32 flags)
{
  SshTlsProtocolState s = ssh_stream_get_context(stream);
  s->extra.flags = flags;
}

#else /* SSHDIST_FUNCTIONALITY_TLS */

void ssh_tls_placeholder(void)
{
  return;
}

#endif /* SSHDIST_FUNCTIONALITY_TLS */
