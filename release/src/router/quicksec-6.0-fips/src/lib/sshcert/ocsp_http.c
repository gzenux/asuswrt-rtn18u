/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   OCSP (RFC2560) functions that are needed to implement
   the HTTP transport (OCSP over HTTP).
*/

#include "sshincludes.h"
#include "sshocsp.h"
#include "ocsp_internal.h"
#include "sshocsphttp.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshOcspHttp"

/* A structure that holds all the information needed in this process. */
typedef struct SshOcspHttpContextRec
{
  /* Handle for combined encoding and HTTP posting operation. */
  SshOperationHandle operation;

  /* Handle for HTTP operation. */
  SshOperationHandle http_op;
  /* Handle for encoding operation. */
  SshOperationHandle encode_op;

    /* Callback passed outside the module and its context. */
  SshOcspHttpCB client_callback;
  void *client_callback_context;

  /* The response to send to callback, this may be NULL. */
  SshOcspResponse response;

  /* HTTP client context and responder address. */
  SshHttpClientContext http_client_context;
  unsigned char *http_url;

  /* HTTP input buffer and stream. */
  SshBuffer input;
  SshStream stream;
} *SshOcspHttpContext, SshOcspHttpContextStruct;

/* Unregister the operation and free context memory. Call also the
   callback function and pass the response (if available) to the user
   along with the status of the operation. */
static void
ocsp_operation_finalize(SshOcspHttpContext context,
                        SshOcspStatus status,
                        SshHttpResult http_result)
{
  /* If HTTP operation is aborted, the operation is already unregistered. */
  if (http_result != SSH_HTTP_RESULT_ABORTED)
    {
      ssh_operation_unregister(context->operation);
      context->operation = NULL;
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Operation finalize: HTTP operation aborted."));
      return;
    }

  /* Free input buffer, stream and the whole context. */
  if (context->input)
    ssh_buffer_free(context->input);
  if (context->stream)
    ssh_stream_destroy(context->stream);
  ssh_free(context->http_url);

  SSH_DEBUG(10, ("Calling client callback."));
  (*context->client_callback)(status,
                              http_result,
                              context->response,
                              context->client_callback_context);
  ssh_free(context);
}

/* Handle incoming HTTP stream. Decode the response when all the data
   is read. */
static void
ocsp_handle_stream(SshStreamNotification notification,
                   void *context)
{
  int num_bytes = 0;
  unsigned char input[256];
  SshOcspHttpContext ctx = (SshOcspHttpContext) context;

  while (TRUE)
    {
      num_bytes = ssh_stream_read(ctx->stream, input, sizeof(input));
      if (num_bytes == 0) /* No more data available. */
        {
          SshOcspStatus status = SSH_OCSP_STATUS_OK;
          SshOcspResponse response = NULL;
          unsigned char *data = NULL;
          size_t len = 0;

          len = ssh_buffer_len(ctx->input);
          data = ssh_buffer_ptr(ctx->input);

          SSH_DEBUG(SSH_D_MIDOK, ("OCSP/HTTP client read %d bytes.", len));

          if (len > 0)
            {
              SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                                ("Received data:"), data, len);
              status = ssh_ocsp_response_decode(data, len, &response);
            }
          else
            {
              status = SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
            }

          ctx->response = response;
          ocsp_operation_finalize(ctx, status, SSH_HTTP_RESULT_SUCCESS);
          return;
        }
      else if (num_bytes < 0)
        {
          return;
        }
      else
        {
          /* Append data that was read to the buffer. */
          if (ssh_buffer_append(ctx->input, input, num_bytes)
              != SSH_BUFFER_OK)
            {
              ocsp_operation_finalize(ctx,
                                      SSH_OCSP_STATUS_INTERNAL_ERROR,
                                      SSH_HTTP_RESULT_SUCCESS);
              return;
            }
        }
    }
}


/* This is a callback function for the HTTP operation. */
static void
client_result_cb(SshHttpClientContext ctx,
                 SshHttpResult result,
                 SshTcpError ip_error,
                 SshStream stream,
                 void *callback_context)
{
  SshOcspHttpContext context = (SshOcspHttpContext) callback_context;

  if (result != SSH_HTTP_RESULT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("OCSP/HTTP Result: code=%d, message=%s",
                 result,
                 ssh_http_error_code_to_string(result)));
      ocsp_operation_finalize(context, SSH_OCSP_STATUS_HTTP_ERROR, result);
    }

  if (ip_error != SSH_TCP_OK)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP/HTTP: IP Error: %d, %s",
                 ip_error, ssh_tcp_error_string(ip_error)));
    }
  else if (result == SSH_HTTP_RESULT_SUCCESS)
    {
      const unsigned char *type;

      context->stream = stream;
      if ((context->input = ssh_buffer_allocate()) == NULL)
        {
          ocsp_operation_finalize(context,
                                  SSH_OCSP_STATUS_INTERNAL_ERROR,
                                  result);
          return;
        }
      type = ssh_http_get_header_field(ctx, (unsigned char *)"Content-Type");
      if (!type)
        SSH_DEBUG(5, ("The response had no Content-Type."));
      else
        SSH_DEBUG(5, ("Received response of type %s", type));

      /* Set callback and start reading the data. */
      ssh_stream_set_callback(stream, ocsp_handle_stream, context);
      ocsp_handle_stream(SSH_STREAM_INPUT_AVAILABLE, context);
    }
}


/* Start the HTTP POST operation. */
static SshOperationHandle
ocsp_http_send_request(SshHttpClientContext context,
                       const unsigned char *url,
                       const unsigned char *content_data,
                       size_t content_data_len,
                       SshHttpClientResultCb callback,
                       void *callback_context)
{
  SshOperationHandle handle = NULL;

  SSH_DEBUG(5, ("Start HTTP POST operation. Sending %d bytes to %s.",
                content_data_len, url));

  handle = ssh_http_post(context, url, content_data, content_data_len,
                         callback, callback_context,
                         SSH_HTTP_HDR_FIELD,
                         "Content-Type", "application/ocsp-request",
                         SSH_HTTP_HDR_END);

  return handle;
}

/* This is a callback function for the encoding operation. If it was
   successful, the encoded request is sent to the responder using
   the HTTP. */
static void
request_encode_done(SshOcspStatus status,
                    const unsigned char *der, size_t der_len,
                    void *context)
{
  SshOcspHttpContext ctx = (SshOcspHttpContext) context;
  SshOperationHandle http_handle = NULL;

  if (status != SSH_OCSP_STATUS_OK)
    {
      SSH_DEBUG(5, ("Request encoding failed."));
      ocsp_operation_finalize(ctx, status, SSH_HTTP_RESULT_SUCCESS);
      return;
    }

  SSH_DEBUG(5, ("Request encoded without errors."));

  /* Encode operation is now finished, so the handle is not valid
     any more. */
  ctx->encode_op = NULL;
  http_handle = ocsp_http_send_request(ctx->http_client_context,
                                       ctx->http_url,
                                       der, der_len,
                                       client_result_cb, ctx);
  ctx->http_op = http_handle;
}


/* Abort callback for the combined HTTP and encoding operation. */
static void
encode_and_send_abort(void *context)
{
  SshOcspHttpContext ctx = (SshOcspHttpContext) context;

  SSH_DEBUG(5, ("encode_and_send_abort called."));

  ssh_operation_abort(ctx->encode_op);
  if (ctx->http_op)
    {
      SSH_DEBUG(6, ("Aborting HTTP operation."));
      ssh_operation_abort(ctx->http_op);
    }
  ssh_free(ctx->http_url);
  ssh_free(ctx);
}


/* The main function that is seen outside this module. Encodes the
   request, sends it using HTTP, reads the response, decodes it and
   calls the callback function. */
SshOperationHandle
ssh_ocsp_http_send_request(SshOcspRequest request,
                           SshHttpClientContext context,
                           const unsigned char *url,
                           const SshPrivateKey private_key,
                           SshOcspHttpCB callback,
                           void *callback_context)
{
  SshOcspHttpContext op_context = NULL;
  SshOperationHandle handle = NULL;
  SshOperationHandle encode_op = NULL; /* Encoding operation. */

  op_context = ssh_malloc(sizeof(*op_context));

  if (op_context != NULL)
    {
      handle = ssh_operation_register(encode_and_send_abort, op_context);

      op_context->http_op = NULL;
      op_context->encode_op = NULL;
      op_context->operation = handle;
      op_context->client_callback = callback;
      op_context->client_callback_context = callback_context;
      op_context->http_url = ssh_ustrdup(url);
      op_context->http_client_context = context;
      op_context->response = NULL;
      op_context->input = NULL;
      op_context->stream = NULL;

      SSH_DEBUG(5, ("Encoding request."));

      encode_op = ssh_ocsp_request_encode(request, private_key,
                                          request_encode_done, op_context);

      if (encode_op)
        {
          op_context->encode_op = encode_op;
        }
      else
        {
          op_context->encode_op = NULL;
        }
    }
  else
    {
      (*callback)(SSH_OCSP_STATUS_INTERNAL_ERROR,
                  SSH_HTTP_RESULT_SUCCESS,
                  NULL,
                  callback_context);
      ssh_ocsp_request_free(request);
    }
  return handle;
}

/* end of file (ocsp_http.c) */
#endif /* SSHDIST_CERT */
