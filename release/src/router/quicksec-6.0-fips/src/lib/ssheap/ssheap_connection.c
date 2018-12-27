/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_connection.h"

#define SSH_DEBUG_MODULE "SshEapConnection"

void
ssh_eap_connection_set_mru(SshEapConnection con, unsigned long mru)
{
  con->mru = mru;
}

void
ssh_eap_connection_output_packet(SshEapConnection con, SshBuffer buf)
{
  if (con->flags & SSH_EAP_F_DISABLED
      || con->output_cb == NULL_FNPTR)
    {
      return;
    }

  con->output_cb(con, con->ctx, buf);
}

void
ssh_eap_connection_input_packet(SshEapConnection con, SshBuffer buf)
{
  if (con->flags & SSH_EAP_F_DISABLED || con->eap == NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("incoming packet discarded"));
      return;
    }

  ssh_eap_input_packet(con->eap, buf);
}

SshEapConnection
ssh_eap_connection_create_cb(SshEapConnectionOutputCB cb, void* ctx)
{
  SshEapConnection con;

  con = ssh_calloc(1, sizeof(*con));

  if (con == NULL)
    return NULL;

  con->flags = 0;
  con->mode = SSH_EAP_MODE_CB;
  con->mru = 1400;
  con->output_cb = cb;
  con->ctx = ctx;
  con->eap = NULL;

  return con;
}

void
ssh_eap_connection_enable(SshEapConnection con)
{
  con->flags &= ~(SSH_EAP_F_DISABLED);
}

void
ssh_eap_connection_disable(SshEapConnection con)
{
  con->flags |= SSH_EAP_F_DISABLED;
}

void
ssh_eap_connection_attach(SshEapConnection con, SshEap eap)
{
  SSH_ASSERT(con != NULL );
  SSH_ASSERT(con->eap == NULL);
  SSH_ASSERT(eap != NULL);

  con->eap = eap;
}

void
ssh_eap_connection_detach(SshEapConnection con)
{
  SSH_ASSERT(con->eap != NULL);

  con->eap = NULL;
}

void
ssh_eap_connection_destroy(SshEapConnection con)
{
  if (con != NULL)
    {
      SSH_ASSERT(con->eap == NULL);
    }

  ssh_free(con);
}
