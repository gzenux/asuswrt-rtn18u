/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit callback for storing events into syslog using
   ssh_log_event().
*/

#ifndef SSHAUDIT_SYSLOG_H
#define SSHAUDIT_SYSLOG_H

#include "sshaudit.h"

/************************** Types and definitions ***************************/

/* Context data for the syslog back-end. */
typedef struct SshAuditSyslogContextRec *SshAuditSyslogContext;


/***************** Creating and destroying syslog back-ends *****************/

/* Create a syslog back-end for audit events.  The arguments
   `facility' and `severity' specify the syslog event's facility and
   severity respectively.  The function returns a context data or NULL
   if the syslog back-end could not be created.  The returned context
   data is the context data argument for the ssh_audit_syslog_cb
   function when it is configured to be used as the audit callback
   with the ssh_audit_create function. */
SshAuditSyslogContext ssh_audit_syslog_create(SshLogFacility facility,
                                              SshLogSeverity severity,
                                              SshAuditFormatType format);

/* Destroy the syslog back-end `context'. */
void ssh_audit_syslog_destroy(SshAuditSyslogContext context);


/*********** The audit callback function for the syslog back-end ************/

/* The SshAuditCB callback function for the ssh_audit_create function.
   The context data `context' must be a context, created with the
   ssh_audit_syslog_create function.  It is configured with the
   `context' argument of the ssh_audit_create function when this
   callback function is configured to be the audit callback. */
void ssh_audit_syslog_cb(SshAuditEvent event, SshUInt32 argc,
                         SshAuditArgument argv, void *context);

#endif /* not SSHAUDIT_SYSLOG_H */
