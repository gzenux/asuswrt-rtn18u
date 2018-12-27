/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit callback for storing events into syslog using
   ssh_log_event().
*/

#include "sshincludes.h"
#include "sshaudit_syslog.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAuditSyslog"

/* Context data for the syslog back-end. */
struct SshAuditSyslogContextRec
{
  SshLogFacility facility;
  SshLogSeverity severity;
  SshAuditFormatType format;
  SshBufferStruct buffer;
};


/***************** Creating and destroying syslog back-ends *****************/

SshAuditSyslogContext
ssh_audit_syslog_create(SshLogFacility facility, SshLogSeverity severity,
                        SshAuditFormatType format)
{
  SshAuditSyslogContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    return NULL;

  ctx->facility = facility;
  ctx->severity = severity;
  ctx->format = format;

  ssh_buffer_init(&ctx->buffer);

  return ctx;
}


void
ssh_audit_syslog_destroy(SshAuditSyslogContext context)
{
  if (context == NULL)
    return;

  ssh_buffer_uninit(&context->buffer);

  ssh_free(context);
}


/*********** The audit callback function for the syslog back-end ************/

void
ssh_audit_syslog_cb(SshAuditEvent event, SshUInt32 argc,
                    SshAuditArgument argv, void *context)
{
  SshAuditSyslogContext ctx = (SshAuditSyslogContext) context;

  ssh_buffer_clear(&ctx->buffer);

  if (!ssh_audit_format(&ctx->buffer, ctx->format, event, argc, argv))
    {
    error:
      SSH_DEBUG(SSH_D_ERROR, ("Could not format event into a string"));
      return;
    }

  if (ssh_buffer_append(&ctx->buffer, (unsigned char *) "\0", 1)
      != SSH_BUFFER_OK)
    goto error;

  ssh_log_event(ctx->facility, ctx->severity, "%s",
                (char *) ssh_buffer_ptr(&ctx->buffer));
}
