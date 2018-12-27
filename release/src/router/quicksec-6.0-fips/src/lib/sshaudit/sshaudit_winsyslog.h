/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit callback for storing events into Windows syslog.
*/

#ifndef SSHAUDIT_WINSYSLOG_H
#define SSHAUDIT_WINSYSLOG_H

#include "sshaudit.h"

/************************** Types and definitions ***************************/

/* Context data for the syslog back-end. */
typedef struct SshAuditWinSyslogContextRec *SshAuditWinSyslogContext;


/************* Creating and destroying Windows syslog back-ends *************/

/* Create a Windows syslog back-end for audit events.  The argument
   `event_source_name' specifies the event source name.The function
   returns a context data or NULL if the Windows syslog back-end could
   not be created.  The returned context data is the context data
   argument for the ssh_audit_winsyslog_cb function when it is
   configured to be used as the audit callback with the
   ssh_audit_create function. */
SshAuditWinSyslogContext
ssh_audit_winsyslog_create(const char *event_source_name,
                           SshAuditFormatType format);


/* Destroy the Windows syslog back-end `context'. */
void ssh_audit_winsyslog_destroy(SshAuditWinSyslogContext context);


/******* The audit callback function for the Windows syslog back-end ********/

/* The SshAuditCB callback function for the ssh_audit_create function.
   The context data `context' must be a context, created with the
   ssh_audit_winsyslog_create function.  It is configured with the
   `context' argument of the ssh_audit_create function when this
   callback function is configured to be the audit callback. */
void ssh_audit_winsyslog_cb(SshAuditEvent event, SshUInt32 argc,
                            SshAuditArgument argv, void *context);


#endif /* not SSHAUDIT_WINSYSLOG_H */
