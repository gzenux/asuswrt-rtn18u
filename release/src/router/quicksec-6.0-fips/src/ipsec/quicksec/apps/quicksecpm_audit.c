/**
   @copyright
   Copyright (c) 2003 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_audit.h"

struct SshPmAuditContextRec
{
  struct
  {
    SshUInt16 cur_elem;
    SshUInt16 max_elems;
    SshPmAuditEvent ring;
  } events;

  SshBufferStruct buffer;
};

static void ring_insert(SshPmAuditContext pmaudit,
                        unsigned char *data, size_t len)
{
  SshPmAuditEvent e = &pmaudit->events.ring[pmaudit->events.cur_elem];

  if (e->data)
    ssh_free(e->data);

  e->data = data;
  e->data_len = len;

  pmaudit->events.cur_elem =
    (pmaudit->events.cur_elem + 1) % pmaudit->events.max_elems;
}

/* Creates policy manager audit handler with backlog of ringsize entries. */
SshPmAuditContext
ssh_ipsecpm_audit_create(SshUInt16 ringsize)
{
  SshPmAuditContext pmaudit;

  pmaudit = ssh_calloc(1, sizeof(*pmaudit));
  if (pmaudit != NULL)
    {
      pmaudit->events.max_elems = ringsize;
      pmaudit->events.cur_elem = 0;
      pmaudit->events.ring =
        ssh_calloc(ringsize, sizeof(pmaudit->events.ring[0]));
      if (pmaudit->events.ring != NULL)
        {
          return pmaudit;
        }

      ssh_free(pmaudit);
    }
  return NULL;
}

void
ssh_ipsecpm_audit_destroy(SshPmAuditContext pmaudit)
{
  int i;

  for (i = 0; i < pmaudit->events.max_elems; i++)
    ssh_free(pmaudit->events.ring[i].data);
  ssh_free(pmaudit->events.ring);
  ssh_free(pmaudit);
}

SshUInt16 ssh_ipsecpm_audit_events(SshPmAuditContext pmaudit,
                                   SshPmAuditEvent *array)
{
  SshUInt16 off = 0;
  SshPmAuditEvent events;

  events = ssh_calloc(pmaudit->events.max_elems, sizeof(events[0]));
  if (events == NULL)
    return 0;

  if (pmaudit->events.ring[pmaudit->events.max_elems - 1].data)
    {
      off = pmaudit->events.max_elems - pmaudit->events.cur_elem;

      memmove(&events[0],
              &pmaudit->events.ring[pmaudit->events.cur_elem],
              off * sizeof(events[0]));
    }
  memmove(&events[off],
          &pmaudit->events.ring[0],
          pmaudit->events.cur_elem * sizeof(events[0]));
  off +=  pmaudit->events.cur_elem;

  if (off == 0)
    {
      ssh_free(events);
      *array = NULL;
    }
  else
    *array = events;

  return off;
}

void ssh_ipsecpm_audit_cb(SshAuditEvent event,
                          SshUInt32 argc, SshAuditArgument argv,
                          void *context)
{
  SshPmAuditContext pmaudit = (SshPmAuditContext) context;

  ssh_buffer_clear(&pmaudit->buffer);
  if (ssh_audit_format(&pmaudit->buffer, SSH_AUDIT_FORMAT_DEFAULT,
                       event, argc, argv))
    {
      if (ssh_buffer_append(&pmaudit->buffer, (unsigned char *)"\0", 1)
          == SSH_BUFFER_OK)
        {
          size_t len;

          /* Log into ring buffer. */
          len = ssh_buffer_len(&pmaudit->buffer);
          ring_insert(pmaudit,
                      ssh_buffer_steal(&pmaudit->buffer, NULL),
                      len);
        }
    }
}
