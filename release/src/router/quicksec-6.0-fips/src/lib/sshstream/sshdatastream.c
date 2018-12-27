/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An SshStream around a blob of data.
*/

#include "sshincludes.h"
#include "sshdatastream.h"


/************************** Types and definitions ***************************/

/* Context data for the data stream. */
struct SshDataStreamContextRec
{
  /* Flags. */
  unsigned int static_data : 1; /* Data is static. */

  /* The data of the stream. */
  unsigned char *data;
  size_t len;

  /* Current reading position in the stream. */
  size_t pos;
};

typedef struct SshDataStreamContextRec SshDataStreamContextStruct;
typedef struct SshDataStreamContextRec *SshDataStreamContext;


/************************* Stream method functions **************************/

static int
ssh_data_stream_read(void *context, unsigned char *buf, size_t size)
{
  SshDataStreamContext ctx = (SshDataStreamContext) context;

  if (ctx->pos >= ctx->len)
    return 0;

  if (size > ctx->len - ctx->pos)
    size = ctx->len - ctx->pos;

  memcpy(buf, ctx->data + ctx->pos, size);
  ctx->pos += size;

  return size;
}

static int
ssh_data_stream_write(void *context, const unsigned char *buf, size_t size)
{
  return 0;
}

static void
ssh_data_stream_output_eof(void *context)
{
}

static void
ssh_data_stream_set_callback(void *context, SshStreamCallback callback,
                             void *callback_context)
{
  /* We do not have to set the callback since we never block.  Just
     notify user about possible data. */
  if (callback)
    (*callback)(SSH_STREAM_INPUT_AVAILABLE, callback_context);
}

static void
ssh_data_stream_destroy(void *context)
{
  SshDataStreamContext ctx = (SshDataStreamContext) context;

  if (!ctx->static_data)
    ssh_free(ctx->data);
  ssh_free(ctx);
}

static const SshStreamMethodsStruct ssh_data_stream_methods =
{
  ssh_data_stream_read,
  ssh_data_stream_write,
  ssh_data_stream_output_eof,
  ssh_data_stream_set_callback,
  ssh_data_stream_destroy,
};

/***************************** Public functions *****************************/

SshStream
ssh_data_stream_create(const unsigned char *data, size_t len,
                       Boolean static_data)
{
  SshDataStreamContext ctx;
  SshStream stream;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    return NULL;

  if (static_data)
    {
      ctx->static_data = 1;
      ctx->data = (unsigned char *) data;
    }
  else
    {
      ctx->data = ssh_memdup(data, len);
      if (ctx->data == NULL)
        {
          ssh_free(ctx);
          return NULL;
        }
    }
  ctx->len = len;

  stream = ssh_stream_create(&ssh_data_stream_methods, ctx);
  if (stream == NULL)
    {
      if (!static_data)
        ssh_free(ctx->data);
      ssh_free(ctx);
    }

  return stream;
}


SshStream
ssh_data_stream_create_buffer(SshBuffer buffer)
{
  SshStream stream;

  stream = ssh_data_stream_create(ssh_buffer_ptr(buffer),
                                  ssh_buffer_len(buffer), FALSE);

  /* This function frees the argument buffer. */
  ssh_buffer_free(buffer);

  return stream;
}
