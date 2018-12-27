/**
   @copyright
   Copyright (c) 2003 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   quicksecpm_audit.h
*/

#include "sshincludes.h"
#include "sshaudit.h"

struct SshPmAuditEventRec
{
  unsigned char *data;
  size_t data_len;
};
typedef struct SshPmAuditEventRec *SshPmAuditEvent;

typedef struct SshPmAuditContextRec *SshPmAuditContext;

SshPmAuditContext
ssh_ipsecpm_audit_create(SshUInt16 ringsize);

void ssh_ipsecpm_audit_cb(SshAuditEvent event,
                          SshUInt32 argc, SshAuditArgument argv,
                          void *context);

SshUInt16 ssh_ipsecpm_audit_events(SshPmAuditContext pmaudit,
                                   SshPmAuditEvent *array);

void ssh_ipsecpm_audit_destroy(SshPmAuditContext pmaudit);
/** eof */
