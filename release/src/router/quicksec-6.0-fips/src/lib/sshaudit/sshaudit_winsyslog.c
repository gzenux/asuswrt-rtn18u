/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit callback for storing events into Windows syslog.
*/

#include "sshincludes.h"
#include "sshaudit_winsyslog.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAuditWinSyslog"

/* Context data for the Windows syslog back-end. */
struct SshAuditWinSyslogContextRec
{
  HANDLE event_source;
  SshAuditFormatType format;
  SshBufferStruct buffer;
};


/***************** Creating and destroying syslog back-ends *****************/

SshAuditWinSyslogContext
ssh_audit_winsyslog_create(const char *event_source_name,
                           SshAuditFormatType format)
{
#ifdef UNICODE
  WCHAR *uc_buffer;
  size_t uc_buf_size;
#endif /* UNICODE */
  SshAuditWinSyslogContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto error;

#ifdef UNICODE
  uc_buf_size = (strlen(event_source_name) + 1) * sizeof(WCHAR);
  uc_buffer = ssh_calloc(1, uc_buf_size);

  if (uc_buffer == NULL)
    goto error;

  ssh_ascii_to_unicode(uc_buffer, uc_buf_size, event_source_name);
  ctx->event_source = RegisterEventSource(NULL, uc_buffer);
  ssh_free(uc_buffer);
#else
  ctx->event_source = RegisterEventSource(NULL, event_source_name);
#endif /* UNICODE */
  if (!ctx->event_source)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register event source"));
      goto error;
    }

  ctx->format = format;
  ssh_buffer_init(&ctx->buffer);

  /* All done. */
  return ctx;


  /* Error handling. */

 error:

  ssh_audit_winsyslog_destroy(ctx);
  return NULL;
}


void
ssh_audit_winsyslog_destroy(SshAuditWinSyslogContext context)
{
  if (context == NULL)
    return;

  ssh_buffer_uninit(&context->buffer);

  if (context->event_source)
    DeregisterEventSource(context->event_source);

  ssh_free(context);
}


/******* The audit callback function for the Windows syslog back-end ********/

void
ssh_audit_winsyslog_cb(SshAuditEvent event, SshUInt32 argc,
                       SshAuditArgument argv, void *context)
{
  SshAuditWinSyslogContext ctx = (SshAuditWinSyslogContext) context;
  LPTSTR strings[1];
#ifdef UNICODE
  size_t uc_str_size;
#endif /* UNICODE */

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

#ifdef UNICODE
  uc_str_size = (strlen(ssh_buffer_ptr(&ctx->buffer)) + 1) * sizeof(WCHAR);

  strings[0] = ssh_calloc(1, uc_str_size);
  if (strings[0] == NULL)
    goto error;

  ssh_ascii_to_unicode(strings[0], uc_str_size, ssh_buffer_ptr(&ctx->buffer));
#else
  strings[0] = ssh_buffer_ptr(&ctx->buffer);
#endif /* UNICODE */





  ReportEvent(ctx->event_source,    /* Handle of event source. */
              EVENTLOG_ERROR_TYPE,  /* Event type. */
              0,                    /* Event category. */
              0,                    /* Event ID. */
              NULL,                 /* Current user's SID. */
              1,                    /* Number of strings in `strings'. */
              0,                    /* Number of bytes of raw data. */
              strings,              /* Array of error strings. */
              NULL);                /* Raw data. */

#ifdef UNICODE
  ssh_free(strings[0]);
#endif /* UNICODE */
}
