/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Description:

*/

#include "sshincludes.h"
#include "sshaudit.h"
#include "sshaudit_syslog.h"
#include "sshaudit_file.h"

struct SshPmAuditEventRec
{
  unsigned char *data;
  size_t data_len;
};
typedef struct SshPmAuditEventRec *SshPmAuditEvent;

typedef struct SshPmAuditContextRec *SshPmAuditContext;

SshPmAuditContext
ssh_pm_audit_create(SshUInt16 ringsize,
                    SshAuditSyslogContext syslog,
                    SshAuditFileContext file);

void ssh_pm_audit_cb(SshAuditEvent event,
                     SshUInt32 argc, SshAuditArgument argv,
                     void *context);

SshUInt16 ssh_pm_audit_events(SshPmAuditContext pmaudit,
                              SshPmAuditEvent *array);

void ssh_pm_audit_destroy(SshPmAuditContext pmaudit);
/** eof */
