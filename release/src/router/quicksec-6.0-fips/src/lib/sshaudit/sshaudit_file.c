/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit callback for storing events into a file.
*/

#include "sshincludes.h"
#include "sshaudit.h"
#include "sshaudit_file.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAuditFile"

/* Context data for the file back-end. */
struct SshAuditFileContextRec
{
  FILE *fp;
  Boolean append_newline;
  SshAuditFormatType format;
  SshBufferStruct buffer;
};


/****************** Creating and destroying file back-ends ******************/

SshAuditFileContext
ssh_audit_file_create(const char *file,  Boolean append_newline,
                      SshAuditFormatType format)
{
  SshAuditFileContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto error;

  ctx->format = format;
  ctx->append_newline = append_newline;

  ssh_buffer_init(&ctx->buffer);

  ctx->fp = fopen(file, "ab");

  if (ctx->fp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not open audit file `%s': %s",
                             file, strerror(errno)));
      goto error;
    }

  /* All done. */
  return ctx;

  /* Error handling. */
 error:

  ssh_audit_file_destroy(ctx);

  return NULL;
}


void
ssh_audit_file_destroy(SshAuditFileContext context)
{
  if (context == NULL)
    return;

  if (context->fp)
    fclose(context->fp);

  ssh_buffer_uninit(&context->buffer);

  ssh_free(context);
}


/************ The audit callback function for the file back-end *************/

void
ssh_audit_file_cb(SshAuditEvent event, SshUInt32 argc, SshAuditArgument argv,
                  void *context)
{
  SshAuditFileContext ctx = (SshAuditFileContext) context;
  size_t len;

  ssh_buffer_clear(&ctx->buffer);

  if (!ssh_audit_format(&ctx->buffer, ctx->format, event, argc, argv))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not format event into a string"));
      return;
    }

  len = ssh_buffer_len(&ctx->buffer);
  if (fwrite(ssh_buffer_ptr(&ctx->buffer), 1, len, ctx->fp) != len)
    {
    write_failed:
      SSH_DEBUG(SSH_D_ERROR, ("Write failed"));
      return;
    }

  if (ctx->append_newline)
    {
      if (fputc('\n', ctx->fp) == EOF)
        goto write_failed;
    }

  fflush(ctx->fp);
}
