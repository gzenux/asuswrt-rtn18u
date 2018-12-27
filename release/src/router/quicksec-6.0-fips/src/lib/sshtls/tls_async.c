/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtlsi.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshTlsAsync"

void ssh_tls_async_freeze(SshTlsProtocolState s)
{
  SSH_DEBUG(6, ("Protocol state frozen."));

  s->flags |= SSH_TLS_FLAG_FROZEN;
}

void ssh_tls_freeze(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  ssh_tls_async_freeze(s);
}

static void continue_func(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  s->flags &= ~SSH_TLS_FLAG_FROZEN;

  if (s->flags & SSH_TLS_FLAG_DELETED)
    ssh_tls_destroy_if_possible(s);
  else
    {

      SSH_DEBUG(6, ("Melting the protocol: continue reading"));
      ssh_tls_try_read_in(s);

      if (s->flags & (SSH_TLS_FLAG_FROZEN|SSH_TLS_FLAG_DELETED)) return;

      SSH_DEBUG(6, ("Melting the protocol: process handshake data"));
      ssh_tls_kex_revive_processing(s);

      if (s->flags & (SSH_TLS_FLAG_FROZEN|SSH_TLS_FLAG_DELETED)) return;

      SSH_DEBUG(6, ("Melting the protocol: kex dispatch"));
      ssh_tls_kex_dispatch(s, 0, NULL, 0);

      if (s->flags & (SSH_TLS_FLAG_FROZEN|SSH_TLS_FLAG_DELETED)) return;

      /* Then try to parse more packets. */
      SSH_DEBUG(6, ("Melting the protocol: parsing more packets"));
      ssh_tls_parse_incoming(s);
    }
}

void ssh_tls_async_continue(SshTlsProtocolState s)
{
  SSH_ASSERT(s->flags & SSH_TLS_FLAG_FROZEN);

  /* Schedule the reviving function. */
  ssh_xregister_timeout(0L, 0L, continue_func, s);
}

void ssh_tls_continue(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  ssh_tls_async_continue(s);
}
