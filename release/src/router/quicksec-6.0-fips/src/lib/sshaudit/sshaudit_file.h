/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit callback for storing events into a file.
*/

#ifndef SSHAUDIT_FILE_H
#define SSHAUDIT_FILE_H

#include "sshaudit.h"

/************************** Types and definitions ***************************/

/* Context data for the file back-end. */
typedef struct SshAuditFileContextRec *SshAuditFileContext;


/****************** Creating and destroying file back-ends ******************/

/* Create a file back-end for the file `file'.  The new audit events
   are appended to the end of the file.  The function returns a
   context data or NULL if the file back-end could not be created.
   The returned context data is the context data argument for the
   ssh_audit_file_cb function when it is configured to be used as the
   audit callback with the ssh_audit_create function. If 'append_newline'
   is TRUE, audit events are separated by a '\n' character in the file. */
SshAuditFileContext ssh_audit_file_create(const char *file,
                                          Boolean append_newline,
                                          SshAuditFormatType format);

/* Destroy the file back-end `context'. */
void ssh_audit_file_destroy(SshAuditFileContext context);


/************ The audit callback function for the file back-end *************/

/* The SshAuditCB callback function for the ssh_audit_create function.
   The context data `context' must be a context, created with the
   ssh_audit_file_create function.  It is configured with the
   `context' argument of the ssh_audit_create function when this
   callback function is configured to be the audit callback. */
void ssh_audit_file_cb(SshAuditEvent event, SshUInt32 argc,
                       SshAuditArgument argv, void *context);

#endif /* not SSHAUDIT_FILE_H */
