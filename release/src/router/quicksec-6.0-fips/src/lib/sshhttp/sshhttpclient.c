/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   HTTP/1.1 client functionality.
*/

#include "sshincludes.h"
#include "sshhttp.h"
#include "sshhttpi.h"
#include "sshurl.h"
#include "sshbuffer.h"
#include "sshstream.h"
#include "sshtimeouts.h"
#include "sshbase64.h"

#ifdef SSHDIST_HTTP_CLIENT

/*
 * Types and definitions.
 */

/*
  Debug levels:

    0  development
    5  HTTP protocol
    6  HTTP protocol heavy
    7  interface functions
    8  connection management & callbacks
    9  all
 */

#define SSH_DEBUG_MODULE "SshHttp"

/* The maximum amount of data the HTTP library will buffer in memory.
   If the server sends data faster that the user consumes it, the
   reading if blocked after this amount of data has been read.  The
   user can set this value with the `max_buffer_size' parameter of
   SshHttpClientParams structure. */
#define SSH_HTTP_MAX_BUFFER_SIZE        8192

/* A macro to check that the cookies are constructed in right order.
   The SSH_HTTP_HDR_COOKIE_* value specifiers can be specified only
   after a SSH_HTTP_HDR_COOKIE field. */
#define SET_VALUES_NEED_COOKIE(name)                            \
  do {                                                          \
    if (req->cookies == NULL)                                   \
      ssh_fatal("ssh_http_set_values: %s called without "       \
                "SSH_HTTP_HDR_COOKIE", (name));                 \
    cookie = &req->cookies[req->num_cookies - 1];               \
  } while(0)

/* The supported HTTP access methods. */
typedef enum
{
  SSH_HTTP_GET          = 1,
  SSH_HTTP_HEAD         = 2,
  SSH_HTTP_POST         = 3,
  SSH_HTTP_PUT          = 4
} SshHttpMethod;

/* The states in which an HTTP request writing can be. */
typedef enum
{
  SSH_HTTP_REQUEST_UNCONNECTED,
  SSH_HTTP_REQUEST_WRITING_HEADER,
  SSH_HTTP_REQUEST_EXPECTING_100_CONTINUE,
  SSH_HTTP_REQUEST_RECEIVED_100_CONTINUE,
  SSH_HTTP_REQUEST_WRITING_BODY,
  SSH_HTTP_REQUEST_WRITTEN
} SshHttpRequestWriteState;

/* The states in which an HTTP response reading can be. */
typedef enum
{
  SSH_HTTP_RESPONSE_READING_STATUS_LINE,
  SSH_HTTP_RESPONSE_READING_HEADER,
  SSH_HTTP_RESPONSE_READING_BODY,
  SSH_HTTP_RESPONSE_READ
} SshHttpResponseReadState;

/* An HTTP request. */
struct SshHttpRequestRec
{
  struct SshHttpRequestRec *next;

  /* The HTTP client context containing us. */
  SshHttpClientContext ctx;

  /* The SshOperation handle for this request. */
  SshOperationHandle operation;

  /* The HTTP method that is in use in this request. */
  SshHttpMethod method;

  /* Use HTTP/1.0 protocol for this request? */
  Boolean use_http_1_0;

  /* Do we know (because user told us) that the server is an HTTP/1.1
     server? */
  Boolean server_is_http_1_1;

  /* Do not expect `100 Continue' response before sending content
     data in HTTP/1.1 requests. */
  Boolean no_expect_100_continue;

  /* The number of redirections performed for this request. */
  SshUInt32 redirect_count;

  /* The number of retries performed for this request. */
  SshUInt32 retry_count;

  /* The server hostname and port. */
  unsigned char *host_name;
  unsigned char *port;

  /* Authorization, computed for this request. */
  unsigned char *authorization;

  /* Proxy authentication, computed for this request. */
  unsigned char *proxy_authorization;

  /* Username and password. */
  unsigned char *user_name;
  unsigned char *password;

  /* Proxy username and password. */
  unsigned char *proxy_user_name;
  unsigned char *proxy_password;

  /* The URI to access. */
  unsigned char *uri;

  /* Additional request header fields. */
  SshHttpKvHash header_fields;

  /* Cookies to send to the server. */
  SshHttpCookie *cookies;
  unsigned int num_cookies;

  /* Does this request have content data? */
  Boolean has_content_data;

  /* Use chunked transfer encoding for the content data. */
  Boolean use_chunked_te;

  /* Request's request write state. */
  struct
  {
    SshHttpRequestWriteState state;

    /* Is the EOF output to this stream? */
    Boolean eof_output;

    /* Should the connection be closed after this request has been
       send? */
    Boolean close;

    /* Content data.  Either the fixed amount of content data, or a
       user callback that writes it. */
    unsigned char *content_data;
    size_t content_data_len;
    size_t content_data_written;

    /* User callback to create a dynamic flow of content data. */
    SshHttpClientConnectCb callback;
    void *callback_context;

    /* Is the stream's length known?  If it is, you can find it from
       <stream_content_length>. */
    Boolean stream_content_length_known;
    size_t stream_content_length;
  } w;

  /* Request's response read state. */
  struct
  {
    SshHttpResponseReadState state;

    /* The user callback and its context. */
    SshHttpClientResultCb callback;
    void *callback_context;
  } r;
};

typedef struct SshHttpRequestRec SshHttpRequest;

/* The possible states for the ClientContext. */
typedef enum
{
  SSH_HTTP_CTX_IDLE             = 0,
  SSH_HTTP_CTX_CONNECTING,
  SSH_HTTP_CTX_CONNECTED
} SshHttpClientContextState;

struct SshHttpClientContextRec
{
  /* Should this context be deleted when all references have gone away? */
  Boolean deleted;

  /* Was the HTTP client uninitialized by the user when we were
     connecting to the server.  If so, the connect_callback() will
     eventually uninitialize the client. This is also set when we are
     going to destroy the connection and there might be outstanding
     callbacks. */
  Boolean client_uninitialized;

  /* Was the current request aborted by the user when we were
     connecting to the server.  If so, the connect_callback() will
     abort the request and continue from the next request. */
  Boolean connect_request_aborted;

  /* TCP connection operation handle. */
  SshOperationHandle connect_op;

  /* The state in which the context is. */
  SshHttpClientContextState state;

  /* Default arguments for the connection. */
  unsigned char *socks;

  /* The HTTP proxy name and port.  These are parsed from the
     params.http_proxy_url. */
  unsigned char *proxy_name;
  unsigned char *proxy_port;

  /* Authentication for HTTP proxy. */
  unsigned char *proxy_user_name;
  unsigned char *proxy_password;

  /* TCP/IP stream wrapper. */
  SshHttpClientTcpStreamWrapper tcp_wrapper;
  void *tcp_wrapper_context;

  unsigned char *user_name;
  unsigned char *password;
  Boolean use_http_1_0;
  Boolean server_version_known;
  SshUInt32 num_redirections;
  SshUInt32 num_retries;
  size_t max_buffer_size;
  SshUInt32 expect_100_continue_timeout;
  SshUInt32 tcp_connect_timeout;

  /* The current connection to a server. */
  SshStream http_stream;

  /* Is the EOF seen in <http_stream>? */
  Boolean eof_seen;

  /* Output buffer to hold the HTTP request. */
  SshBufferStruct out_buffer;

  /* Input buffer for the server's response. */
  SshBufferStruct in_buffer;

  /* Header values, parsed from the HTTP response */
  SshHttpKvHash values;

  /* The parsed `Set-Cookies' from the response. */
  SshHttpSetCookie *set_cookies;
  unsigned int num_set_cookies;

  /* Values, extracted from the HTTP response. */

  SshUInt32 version_major;
  SshUInt32 version_minor;

  SshHttpStatusCode status_code;
  unsigned char *status_reason_phrase;

  /* The content length of the reply as given in the header, or -1 if
     the information is not available. */
  SshUInt32 content_length;

  /* Was the `Connection: close' given in the response header? */
  Boolean connection_close;

  /* The UI stream to pass content data from the client to the HTTP
     server: User -> ctx.w -> server */
  struct
  {
    /* The user end-point of the content data write stream. */
    SshStream stream;

    /* User-callbacks for the <content_write_stream>. */
    SshStreamCallback callback;
    void *callback_context;
  } w;

  /* The UI stream to pass content data from the server to the
     client: server -> ctx.r -> client */
  struct
  {
    /* The raw content data read stream.  This stream reads the
       content data from this HTTP client context.  There might be
       separate transfer encoding decoder streams between this stream
       and the user's end-point `stream_user'.  */
    SshStream stream;

    /* The user end point of the stream.  This is needed only to abort
       the current connection. */
    SshStream stream_user;

    /* The number of bytes of content data read from the server. */
    size_t content_data_read;

    /* Is the end of the content data seen in <http_stream>? */
    Boolean end_of_content_data;

    /* The amount of user content-data read. */
    SshUInt32 user_content_data_read;
    Boolean user_content_length_known;
    SshUInt32 user_content_length;

    /* Is the input stream using chunked transform encoding. */
    Boolean use_chunked_te;

    /* Is the EOF reached at the chunked transform encoded stream? */
    Boolean chunked_eof_reached;
  } r;

  /* The next request, under construction.  This request will not be
     started before it is inserted in the list of pending requests. */
  SshHttpRequest *new_request;

  /* A list of requests pending on this context.  If the <http_stream>
     is open, it is valid for the first request in this list. */
  SshHttpRequest *req;
  SshHttpRequest *req_tail;

  /* Application specific data. */
  void *appdata;
};


/*
 * Prototypes for static functions.
 */

/* Perform an HTTP operation <method> with arguments <url> and
   <content_data>, <content_data_len>.  The success of the operation
   will be indicated by calling the callback function <callback>,
   <callback_context> with appropriate values. */
static SshOperationHandle ssh_http_operation(
                                SshHttpClientContext ctx,
                                SshHttpMethod method,
                                const unsigned char *url,
                                const unsigned char *content_data,
                                size_t content_data_len,
                                SshHttpClientConnectCb connect_callback,
                                void *connect_context,
                                SshHttpClientResultCb result_callback,
                                void *result_context,
                                va_list arguments);

/* Alloc and initialize a new request. */
static SshHttpRequest *ssh_http_new_request(SshHttpClientContext ctx);

/* Parse URL <url> into an HTTP request <req>.  If the URL is
   malformed or an unsupported protocol was requested, the client
   callback <callback> will be called with appropriate error message.
   The function returns a boolean success status.  If the operation
   was unsuccessful, the function does *not* free the request
   <req>. */
static Boolean ssh_http_parse_request(SshHttpClientContext ctx,
                                      SshHttpRequest *req,
                                      const unsigned char *url);

/* Free a parsed request <request>.  The function only frees the
   allocated resources.  The possible callbacks must be cancelled by
   the caller. */
static void ssh_http_free_request(SshHttpRequest *request);

/* Free the `Set-Cookie' structure from the context <ctx>. */
static void ssh_http_free_cookies(SshHttpClientContext ctx);

/* Set header fields, properties, etc. to the request <request> from
   the argument list <ap>. */
static void ssh_http_set_values_ap(SshHttpRequest *request, va_list ap);

/* Connect callback function to pass the fixed length content data to
   the server. */
static void ssh_http_fixed_content_data_connect_cb(SshHttpClientContext ctx,
                                                   SshStream stream,
                                                   void *callback_context);

/* Process requests in <ctx>. */
static void ssh_http_process_requests(SshHttpClientContext ctx);

/* A timeout function that is used to notify a keep-alive connection
   that there is a new request in the queue. */
static void ssh_http_signal_new_request_timeout(void *context);

/* Create an HTTP request for the first request in our queue to the
   <ctx>'s out_buffer. */
static void ssh_http_format_http_request(SshHttpClientContext ctx);

/* Connect callback that is called when we finally get connected to
   the HTTP server. */
static void ssh_http_connect_callback(SshTcpError error, SshStream stream,
                                      void *context);

/* Callback for the HTTP stream. */
static void ssh_http_stream_callback(SshStreamNotification notification,
                                     void *context);

/* An abort function for the SshOperationHandle, associated with an HTTP
   operation. */
static void ssh_http_abort_operation(void *context);

/* Close the currently active connection in <ctx> and move to the next
   request. */
static void ssh_http_finish_request(SshHttpClientContext ctx);

/* Retry to serve the first request in the queue.  Returns TRUE if we
   take another try or FALSE otherwise.  If the argument <force> is
   TRUE, the request is retried unconditionally. */
static Boolean ssh_http_retry_request(SshHttpClientContext ctx, Boolean force);

/* Process the input available in the context <ctx>.  Returns TRUE if
   the request has been processed successfully and the control should
   be returned from the read event loop.  If the function returns
   FALSE, more data should be read from the HTTP connection. */
static Boolean ssh_http_process_input(SshHttpClientContext ctx);

/* Create a stream through which the user can read the content data of
   the request.  The stream can be a pipeline of multiple streams.
   For example, when the Chunked Transfer Coding is used, the first
   stream is the basic content data stream that passes the chunked
   content data to the second stream.  The second stream is a chunked
   stream that removes the chunked transfer coding and passes the
   actual content data to the user.

   The function sets the base content data stream to <ctx->r.stream>
   and returns the user end point of the stream.  The returned stream
   should be passed to the user through the user callback function.
   The function returns NULL if the server's response was malformed.
   In that case, an error should be reported, or we can retry with
   HTTP/1.0. */
static SshStream ssh_http_create_content_data_stream(SshHttpClientContext ctx);

/* Create a byte-sink that will discard the data from the argument
   stream <stream>. */
static void ssh_http_create_byte_sink(SshStream stream);

/* Authenticate the failed request from <ctx>.  The function returns
   TRUE if the request should be retried and FALSE otherwise (we have
   already authenticated the request). */
static Boolean ssh_http_authentication(SshHttpClientContext ctx);

/* Authenticate the failed request from <ctx> for the HTTP proxy.  The
   function returns TRUE if the request should be retried and FALSE
   otherwise (we have already authenticated the request). */
static Boolean ssh_http_proxy_authentication(SshHttpClientContext ctx);


/*
 * The content data read stream.
 */

/* Client context for the content data stream. */
struct SshHttpContentStreamRec
{
  /* The HTTP client context to which we are bind to. */
  SshHttpClientContext ctx;

  /* Is the client blocked because there were no enough data available? */
  Boolean blocked;

  /* The user specified callback. */
  SshStreamCallback callback;
  void *callback_context;
};

typedef struct SshHttpContentStreamRec SshHttpContentStream;

/* Constructors for the content data stream. */

/* Write stream to pass the user data stream to the server. */
static SshStream
ssh_http_content_write_stream_create(SshHttpClientContext ctx);

/* Read stream to pass the server content data to the user. */
static SshStream
ssh_http_content_read_stream_create(SshHttpClientContext ctx);


/*
 * Static variables.
 */

static const SshKeywordStruct error_keywords[] =
{
  {"Success",                           SSH_HTTP_RESULT_SUCCESS},
  {"Malformed URL",                     SSH_HTTP_RESULT_MALFORMED_URL},
  {"Unsupported protocol",              SSH_HTTP_RESULT_UNSUPPORTED_PROTOCOL},
  {"Connection failed",                 SSH_HTTP_RESULT_CONNECT_FAILED},
  {"Connection closed",                 SSH_HTTP_RESULT_CONNECTION_CLOSED},
  {"Malformed reply header",
   SSH_HTTP_RESULT_MALFORMED_REPLY_HEADER},
  {"Broken redirect",                   SSH_HTTP_RESULT_BROKEN_REDIRECT},
  {"Redirection limit exceeded",
   SSH_HTTP_RESULT_REDIRECT_LIMIT_EXCEEDED},
  {"Redirection without location",
   SSH_HTTP_RESULT_REDIRECT_WITHOUT_LOCATION},
  {"HTTP error",                        SSH_HTTP_RESULT_HTTP_ERROR},
  {"Maximum memory buffer size reached",
   SSH_HTTP_RESULT_MAXIMUM_BUFFER_SIZE_REACHED},
  {"Connection aborted",                SSH_HTTP_RESULT_ABORTED},
  {"Authorization failed",              SSH_HTTP_RESULT_AUTHORIZATION_FAILED},
  {"Broken server",                     SSH_HTTP_RESULT_BROKEN_SERVER},
  {NULL, 0},
};

/* These request header fields can't be set by the user.  These fields
   are internal and their values are generated automatically by us. */
static const SshCharPtr ssh_http_client_hdr_skip_list[] =
{
  "CONNECTION",
  "CONTENT-LENGTH",
  "HOST",
  "TRANSFER-ENCODING",
  "EXPECT",
  NULL
};


/*
 * Global functions.
 */

SshHttpClientContext
ssh_http_client_init(SshHttpClientParams *params)
{
  SshHttpClientContext ctx;

  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    return NULL;

  ctx->num_redirections = 1;
  ctx->max_buffer_size = SSH_HTTP_MAX_BUFFER_SIZE;
  ctx->expect_100_continue_timeout = 5;

  /* Init the user parameters. */
  if (params)
    {
      if (params->socks)
        ctx->socks = ssh_strdup(params->socks);

      if (params->http_proxy_url)
        {
          if (ssh_url_parse(params->http_proxy_url, NULL,
                            &ctx->proxy_name,
                            &ctx->proxy_port,
                            &ctx->proxy_user_name,
                            &ctx->proxy_password,
                            NULL))
            {
              if (ctx->proxy_port == NULL)
                ctx->proxy_port = ssh_strdup("80");
            }
        }

      ctx->tcp_wrapper = params->tcp_wrapper;
      ctx->tcp_wrapper_context = params->tcp_wrapper_context;
      ctx->tcp_connect_timeout = params->tcp_connect_timeout;

      if (params->user_name)
        ctx->user_name = ssh_strdup(params->user_name);

      if (params->password)
        ctx->password = ssh_strdup(params->password);

      ctx->use_http_1_0 = params->use_http_1_0;
      ctx->server_version_known = FALSE;
      ctx->num_redirections = params->num_redirections;
      ctx->num_retries = params->num_retries;

      if (params->max_buffer_size)
        ctx->max_buffer_size = params->max_buffer_size;

      if (params->expect_100_continue_timeout)
        ctx->expect_100_continue_timeout = params->expect_100_continue_timeout;
    }

  /* Init the rest of the client context. */

  ssh_buffer_init(&ctx->out_buffer);
  ssh_buffer_init(&ctx->in_buffer);

  if ((ctx->values = ssh_http_kvhash_create(TRUE)) == NULL)
    {
      ssh_http_client_uninit(ctx);
      return NULL;
    }

  return ctx;
}


void
ssh_http_client_uninit(SshHttpClientContext ctx)
{
  SshHttpRequest *req, *req_next;

  ctx->deleted = TRUE;

  /* Cancel all timeouts. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, ctx);

  /* Check the state of the current request. */
  switch (ctx->state)
    {
    case SSH_HTTP_CTX_IDLE:
      /* Nothing here. */
      break;

    case SSH_HTTP_CTX_CONNECTING:
      /* Mark the context aborted.  The connect callback will handle
         the actual deletion. */
      ctx->client_uninitialized = TRUE;
     SSH_DEBUG(7, ("Leaving the deletion to the connect_callback()"));
      return;
      break;

    case SSH_HTTP_CTX_CONNECTED:
      /* Mark the context to be destroyed properly after the next
         request is processed. */
      ctx->client_uninitialized = TRUE;

      /* Destroy the possible user content data streams. */

      if (ctx->r.stream)
        {
          /* Mark the content data stream handle to NULL.  This will
             prevent the content_data_stream_destroy() to touch the
             requests in the <ctx>.*/
          ctx->r.stream = NULL;

          /* Destroy the user end point of the content data stream.
             This will eventually destroy the whole content data stream
             pipeline. */
          ssh_stream_destroy(ctx->r.stream_user);
        }

      if (ctx->w.stream)
        {
          SshStream s = ctx->w.stream;

          /* See the comments above. */
          ctx->w.stream = NULL;
          ssh_stream_destroy(s);
        }
      return;
      break;
    }

  /* Destroy the possible HTTP connection. */
  if (ctx->http_stream)
    ssh_stream_destroy(ctx->http_stream);

  /* Destroy all queued requests and signal their callback functions
     that they were aborted, unless the operation has been aborted.
     This is noted by setting the `req->operation' to NULL. */
  for (req = ctx->req; req; req = req_next)
    {
      req_next = req->next;
      if (req->operation && req->r.callback)
        (*req->r.callback)(ctx, SSH_HTTP_RESULT_ABORTED, SSH_TCP_OK,
                           NULL, req->r.callback_context);

      ssh_http_free_request(req);
    }

  /* Free the client context structure. */

  if (ctx->new_request)
    ssh_http_free_request(ctx->new_request);

  ssh_free(ctx->socks);
  ssh_free(ctx->proxy_name);
  ssh_free(ctx->proxy_port);
  ssh_free(ctx->proxy_user_name);
  ssh_free(ctx->proxy_password);
  ssh_free(ctx->user_name);
  ssh_free(ctx->password);

  ssh_buffer_uninit(&ctx->out_buffer);
  ssh_buffer_uninit(&ctx->in_buffer);

  ssh_http_kvhash_destroy(ctx->values);

  ssh_http_free_cookies(ctx);

  ssh_free(ctx->status_reason_phrase);

  ssh_free(ctx);
}


const unsigned char *
ssh_http_get_header_field(SshHttpClientContext ctx, const unsigned char *field)
{
  unsigned char *nfield;
  int i;
  const unsigned char *value = NULL;

  if ((nfield = ssh_strdup(field)) != NULL)
    {
      /* Convert the field to uppercase. */
      for (i = 0; nfield[i]; i++)
        if (islower(nfield[i]))
          nfield[i] = toupper(nfield[i]);

      value = ssh_http_kvhash_get(ctx->values, nfield);
      ssh_free(nfield);
    }

  return value;
}


const SshHttpSetCookie *
ssh_http_get_cookies(SshHttpClientContext ctx, unsigned int *num_return)
{
  const unsigned char *value;
  unsigned int i = 0;
  const unsigned char *attr;
  unsigned int attr_len;
  const unsigned char *attr_val;
  unsigned int attr_val_len;
  SshHttpSetCookie *cookie = NULL;
  Boolean first_av = TRUE;
  Boolean set_cookie2 = TRUE;

  if (ctx->set_cookies)
    {
      *num_return = ctx->num_set_cookies;
      return ctx->set_cookies;
    }

  /* The `Set-Cookie{,2}' headers have not been parsed yet, or there
     are no set cookies in the response.

     FIXME: If we have both `Set-Cookie' and `Set-Cookie2' cookies, we
     should (according to the draft) perform a cookie-by-cookie
     comparison and for each matching cookie, we should use the
     `Set-Cookie2' version.  However, I am lazy and we will only
     process one of these headers.  The other header will be
     ignored. */

  value = ssh_http_kvhash_get(ctx->values, ssh_custr("SET-COOKIE2"));
  if (value == NULL)
    {
      value = ssh_http_kvhash_get(ctx->values, ssh_custr("SET-COOKIE"));
      set_cookie2 = FALSE;
    }
  if (value == NULL)
    {
      /* No Set-Cookies requested. */
      *num_return = 0;
      return NULL;
    }

  /* Parse the value. */

  while (1)
    {
      if (!ssh_http_get_av(value, &i, &attr, &attr_len, &attr_val,
                           &attr_val_len))
        {
        malformed_cookie:
          SSH_DEBUG(SSH_D_FAIL, ("Malformed `Set-Cookie' header field"));
          break;
        }

      if (attr == NULL)
        {
          /* End of string reached. */
          if (cookie == NULL)
            /* No set-cookies in the value.*/
            goto malformed_cookie;

          break;
        }

      if (first_av)
        {
          SshHttpSetCookie *tmp;
          unsigned char *attrp, *valuep;

          if ((attrp = ssh_memdup(attr, attr_len)) == NULL ||
              (valuep = ssh_http_unescape_attr_value(attr_val, attr_val_len))
              == NULL)
            {
              ssh_free(attrp);
              attrp = NULL;
              goto malformed_cookie;
            }

          /* Start a new set-cookie. */
          if (ctx->set_cookies == NULL)
            {
              tmp = ssh_malloc(sizeof(SshHttpSetCookie));
              ctx->num_set_cookies = 1;
            }
          else
            {
              tmp =
                ssh_realloc(ctx->set_cookies,
                            ctx->num_set_cookies * sizeof(SshHttpSetCookie),
                            (ctx->num_set_cookies + 1) *
                            sizeof(SshHttpSetCookie));
              ctx->num_set_cookies++;
            }

          if (!tmp)
            {
              ssh_free(attrp);
              ssh_free(valuep);
              attrp = NULL;
              valuep = NULL;

              ctx->num_set_cookies--;
              goto malformed_cookie;
            }

          ctx->set_cookies = tmp;

          cookie = &ctx->set_cookies[ctx->num_set_cookies - 1];
          memset(cookie, 0, sizeof(*cookie));

          cookie->set_cookie2 = set_cookie2;
          cookie->name = attrp;
          cookie->value = valuep;
          first_av = FALSE;
        }
      else
        {
          unsigned char **target = NULL;

          /* Set attributes for a cookie. */
          if (attr_len == sizeof("Comment") - 1
              && strncasecmp("Comment", (char *) attr, attr_len) == 0)
            target = &cookie->comment;
          else if (attr_len == sizeof("CommentURL") - 1
                   && strncasecmp("CommentURL", (char *) attr, attr_len) == 0)
            target = &cookie->comment_url;
          else if (attr_len == sizeof("Discard") - 1
                   && strncasecmp("Discard", (char *) attr, attr_len) == 0)
            cookie->discard = TRUE;
          else if (attr_len == sizeof("Domain") - 1
                   && strncasecmp("Domain", (char *) attr, attr_len) == 0)
            target = &cookie->domain;
          else if (attr_len == sizeof("Max-Age") - 1
                   && strncasecmp("Max-Age", (char *) attr, attr_len) == 0)
            {
              char *p;

              if ((p =
                   (char *)ssh_http_unescape_attr_value(attr_val,
                                                        attr_val_len))
                  != NULL)
                {
                  cookie->max_age_given = TRUE;
                  cookie->max_age = (SshTime) strtol(p, NULL, 10);
                  ssh_free(p);
                }
            }
          else if (attr_len == sizeof("Expires") - 1
                   && strncasecmp("Expires", (char *) attr, attr_len) == 0)
            target = &cookie->expires;
          else if (attr_len == sizeof("Path") - 1
                   && strncasecmp("Path", (char *) attr, attr_len) == 0)
            target = &cookie->path;
          else if (attr_len == sizeof("Port") - 1
                   && strncasecmp("Port", (char *) attr, attr_len) == 0)
            target = &cookie->port;
          else if (attr_len == sizeof("Secure") - 1
                   && strncasecmp("Secure", (char *) attr, attr_len) == 0)
            cookie->secure = TRUE;
          /* All unknown attributes are ignored. */

          if (target)
            {
              if ((*target = ssh_http_unescape_attr_value(attr_val,
                                                          attr_val_len))
                  == NULL)
                {
                  break;
                }
            }
        }

      /* And move to the next attribute or cookie. */
      for (; value[i] && (isspace(value[i])
                          || value[i] == ';' || value[i] == ','); i++)
        if (value[i] == ',')
          /* This starts a new cookie. */
          first_av = TRUE;

      if (first_av)
        {
          /* Some post checks for the cookie. */

          if (cookie->expires && !cookie->max_age_given)
            {



            }
        }

      /* Continue */
    }

  *num_return = ctx->num_set_cookies;

  return ctx->set_cookies;
}


void
ssh_http_set_values(SshHttpClientContext ctx, ...)
{
  va_list ap;

  if (ctx->new_request == NULL)
    /* Allocate it. */
    ctx->new_request = ssh_http_new_request(ctx);

  va_start(ap, ctx);

  ssh_http_set_values_ap(ctx->new_request, ap);

  va_end(ap);
}


SshHttpInputStatus
ssh_http_get_input_status(SshHttpClientContext ctx)
{
  SSH_ASSERT(ctx != NULL);
  SSH_ASSERT(ctx->req != NULL);

  if (ctx->r.use_chunked_te)
    {
      if (ctx->r.chunked_eof_reached)
        {
          if (ctx->r.user_content_length_known
              && ctx->r.user_content_data_read != ctx->r.user_content_length)
            return SSH_HTTP_TRUNCATED;

          return SSH_HTTP_OK;
        }

      return SSH_HTTP_TRUNCATED;
    }

  if (ctx->r.user_content_length_known)
    {
      if (ctx->r.user_content_data_read == ctx->r.user_content_length)
        return SSH_HTTP_OK;

      return SSH_HTTP_TRUNCATED;
    }

  return SSH_HTTP_UNKNOWN;
}


SshUInt32
ssh_http_get_status_code(SshHttpClientContext ctx,
                         const unsigned char **reason_phrase_return)
{
  if (ctx->status_reason_phrase)
    *reason_phrase_return = ctx->status_reason_phrase;
  else
    *reason_phrase_return = (unsigned char *)"";

  return (SshUInt32) ctx->status_code;
}



SshOperationHandle
ssh_http_get(SshHttpClientContext ctx, const unsigned char *url,
             SshHttpClientResultCb callback, void *callback_context, ...)
{
  va_list ap;
  SshOperationHandle operation;

  va_start(ap, callback_context);

  operation = ssh_http_operation(ctx, SSH_HTTP_GET, url, NULL, 0,
                                 NULL_FNPTR, NULL,
                                 callback, callback_context, ap);

  va_end(ap);

  return operation;
}


SshOperationHandle
ssh_http_head(SshHttpClientContext ctx, const unsigned char *url,
              SshHttpClientResultCb callback, void *callback_context, ...)
{
  va_list ap;
  SshOperationHandle operation;

  va_start(ap, callback_context);

  operation = ssh_http_operation(ctx, SSH_HTTP_HEAD, url, NULL, 0,
                                 NULL_FNPTR, NULL,
                                 callback, callback_context, ap);

  va_end(ap);

  return operation;
}


SshOperationHandle
ssh_http_post(SshHttpClientContext ctx, const unsigned char *url,
              const unsigned char *content_data, size_t content_data_len,
              SshHttpClientResultCb callback, void *callback_context, ...)
{
  va_list(ap);
  SshOperationHandle operation;

  va_start(ap, callback_context);

  operation = ssh_http_operation(ctx, SSH_HTTP_POST, url,
                                 content_data, content_data_len, NULL_FNPTR,
                                 NULL, callback, callback_context, ap);

  va_end(ap);

  return operation;
}


SshOperationHandle
ssh_http_post_stream(SshHttpClientContext ctx, const unsigned char *url,
                     SshHttpClientConnectCb connect_callback,
                     void *connect_context,
                     SshHttpClientResultCb result_callback,
                     void *result_context, ...)
{
  va_list(ap);
  SshOperationHandle operation;

  va_start(ap, result_context);

  operation = ssh_http_operation(ctx, SSH_HTTP_POST, url, NULL, 0,
                                 connect_callback, connect_context,
                                 result_callback, result_context, ap);

  va_end(ap);

  return operation;
}


SshOperationHandle
ssh_http_put(SshHttpClientContext ctx, const unsigned char *url,
             const unsigned char *content_data, size_t content_data_len,
             SshHttpClientResultCb callback, void *callback_context, ...)
{
  va_list(ap);
  SshOperationHandle operation;

  va_start(ap, callback_context);

  operation = ssh_http_operation(ctx, SSH_HTTP_PUT, url,
                                 content_data, content_data_len, NULL_FNPTR,
                                 NULL, callback, callback_context, ap);

  va_end(ap);

  return operation;
}


SshOperationHandle
ssh_http_put_stream(SshHttpClientContext ctx, const unsigned char *url,
                    SshHttpClientConnectCb connect_callback,
                    void *connect_context,
                    SshHttpClientResultCb result_callback,
                    void *result_context, ...)
{
  va_list(ap);
  SshOperationHandle operation;

  va_start(ap, result_context);

  operation = ssh_http_operation(ctx, SSH_HTTP_PUT, url, NULL, 0,
                                 connect_callback, connect_context,
                                 result_callback, result_context, ap);

  va_end(ap);

  return operation;
}


const char *
ssh_http_error_code_to_string(SshHttpResult code)
{
  const char *str;

  str = ssh_find_keyword_name(error_keywords, code);
  if (str == NULL)
    str = "unknown";

  return str;
}


/*
 * Static functions.
 */

static void
ssh_http_start_processing_requests(void *context)
{
  SshHttpClientContext ctx = context;

  ssh_http_process_requests(ctx);
}


static SshOperationHandle
ssh_http_operation(SshHttpClientContext ctx, SshHttpMethod method,
                   const unsigned char *url, const unsigned char *content_data,
                   size_t content_data_len,
                   SshHttpClientConnectCb connect_callback,
                   void *connect_context,
                   SshHttpClientResultCb result_callback,
                   void *result_context,
                   va_list ap)
{
  SshHttpRequest *req;

  if (ctx == NULL)
    {
      ctx = ssh_http_client_init(NULL);
      ctx->deleted = TRUE;
    }

  if (ctx->new_request)
    {
      /* We already have it from the ssh_http_set_values()
         function. */
      req = ctx->new_request;
      ctx->new_request = NULL;
    }
  else
    /* Allocate a new request. */
    req = ssh_http_new_request(ctx);

  req->ctx = ctx;
  req->r.callback = result_callback;
  req->r.callback_context = result_context;

  /* Parse the URL into into the request. */
  if (!ssh_http_parse_request(ctx, req, url))
    {
      ssh_http_free_request(req);

      if (ctx->deleted)
        /* Free our on-demand allocated client context. */
        ssh_http_client_uninit(ctx);
      return NULL;
    }

  req->method = method;

  /* Insert all extra fields, etc. from the <ap> argument. */
  ssh_http_set_values_ap(req, ap);

  /* Insert our other default values.  Currently we don't have any,
     but this would be a good place to add them.  For example,
     accepted transfer encodings with the `TE' header field: deflate,
     gzip, etc. */

  /* The content data for the request. */
  if (method == SSH_HTTP_POST || method == SSH_HTTP_PUT)
    {
      /* We must have content data. */
      req->has_content_data = TRUE;

      if (connect_callback)
        {
          req->w.callback = connect_callback;
          req->w.callback_context = connect_context;
        }
      else
        {
          if (content_data)
            {
              req->w.content_data =
                ssh_memdup(content_data, content_data_len);
              req->w.content_data_len = content_data_len;
            }
          else
            {
              req->w.content_data = ssh_memdup("", 0);
              req->w.content_data_len = 0;
            }

          if (req->w.content_data == NULL)
            {
              ssh_http_free_request(req);

              if (ctx->deleted)
                /* Free our on-demand allocated client context. */
                ssh_http_client_uninit(ctx);
              return NULL;
            }

          req->w.callback = ssh_http_fixed_content_data_connect_cb;
          req->w.callback_context = ctx;
        }
    }

  /* Insert the request to our list of active requests. */
  if (ctx->req_tail)
    {
      ctx->req_tail->next = req;
      ctx->req_tail = req;
    }
  else
    ctx->req = ctx->req_tail = req;

  if (ctx->state == SSH_HTTP_CTX_IDLE)
    {
      /* We have currently no active connections running.  Let's order
         a timeout to start one. */
      ctx->state = SSH_HTTP_CTX_CONNECTING;
      ssh_xregister_timeout(0, 0, ssh_http_start_processing_requests, ctx);
    }

  req->operation = ssh_operation_register(ssh_http_abort_operation, req);

  return req->operation;
}


static SshHttpRequest *
ssh_http_new_request(SshHttpClientContext ctx)
{
  SshHttpRequest *req;

  if ((req = ssh_calloc(1, sizeof(*req))) != NULL)
    {
      req->use_http_1_0 = ctx->use_http_1_0;
      if ((req->header_fields = ssh_http_kvhash_create(FALSE)) == NULL)
        {
          ssh_free(req);
          req = NULL;
        }
    }
  return req;
}


static Boolean
ssh_http_parse_request(SshHttpClientContext ctx, SshHttpRequest *req,
                       const unsigned char *url)
{
  unsigned char *url_scheme = NULL;

  if (!ssh_url_parse(url, &url_scheme,
                     &req->host_name,
                     &req->port,
                     &req->user_name,
                     &req->password,
                     &req->uri))
    {
      /* Notify the error in the URL. */
    malformed_url:
      if (req->r.callback)
        (*req->r.callback)(ctx, SSH_HTTP_RESULT_MALFORMED_URL, SSH_TCP_OK,
                           NULL, req->r.callback_context);
      goto error_out;
    }

  /* Check that we support the given method. */
  if (ssh_usstrcasecmp(url_scheme, "http") != 0)
    {
      /* Not supported. */
      if (req->r.callback)
        (*req->r.callback)(ctx, SSH_HTTP_RESULT_UNSUPPORTED_PROTOCOL,
                           SSH_TCP_OK, NULL, req->r.callback_context);
      goto error_out;
    }

  /* http requires hostname */
  if (req->host_name == NULL)
      goto malformed_url;

  if (req->port == NULL)
    req->port = ssh_strdup("80");
  else if (req->port[0] == '\0')
    {
      /* The URL was given as `http://hostname:/uri'. */
      ssh_free(req->port);
      req->port = ssh_strdup("80");
    }

  if (req->uri == NULL)
    req->uri = ssh_strdup("");

  /* There was no space. */
  if (req->uri == NULL || req->port == NULL)
    goto malformed_url;

  /* Failing on these will yield into error later. */
  if (ctx->proxy_user_name)
    req->proxy_user_name = ssh_strdup(ctx->proxy_user_name);
  if (ctx->proxy_password)
    req->proxy_password = ssh_strdup(ctx->proxy_password);

  if (req->user_name == NULL && ctx->user_name)
    req->user_name = ssh_strdup(ctx->user_name);
  if (req->password == NULL && ctx->password)
    req->password = ssh_strdup(ctx->password);

  ssh_free(url_scheme);
  /* Success. */
  return TRUE;


  /* Error handling. */

 error_out:

  ssh_free(url_scheme);

  return FALSE;
}


static void
ssh_http_free_request(SshHttpRequest *request)
{
  unsigned int i;

  if (request)
    {
      /* Cancel the possible SshOperation. */
      if (request->operation)
        {
          ssh_operation_unregister(request->operation);
          request->operation = NULL;
        }

      ssh_free(request->host_name);
      ssh_free(request->port);
      ssh_free(request->user_name);
      ssh_free(request->password);
      ssh_free(request->proxy_user_name);
      ssh_free(request->proxy_password);
      ssh_free(request->authorization);
      ssh_free(request->proxy_authorization);
      ssh_free(request->uri);

      if (request->header_fields)
        ssh_http_kvhash_destroy(request->header_fields);

      /* Cookies. */

      for (i = 0; i < request->num_cookies; i++)
        {
          SshHttpCookie *cookie = &request->cookies[i];

          ssh_free(cookie->name);
          ssh_free(cookie->value);
          ssh_free(cookie->path);
          ssh_free(cookie->domain);
          ssh_free(cookie->port);
        }

      ssh_free(request->cookies);
      ssh_free(request->w.content_data);

      ssh_free(request);
    }
}


static void
ssh_http_free_cookies(SshHttpClientContext ctx)
{
  unsigned int i;

  /* Set-Cookies. */

  for (i = 0; i < ctx->num_set_cookies; i++)
    {
      SshHttpSetCookie *cookie = &ctx->set_cookies[i];

      ssh_free(cookie->name);
      ssh_free(cookie->value);
      ssh_free(cookie->comment);
      ssh_free(cookie->comment_url);
      ssh_free(cookie->domain);
      ssh_free(cookie->expires);
      ssh_free(cookie->path);
      ssh_free(cookie->port);
    }

  ssh_free(ctx->set_cookies);

  ctx->set_cookies = NULL;
  ctx->num_set_cookies = 0;
}


static void
ssh_http_set_values_ap(SshHttpRequest *req, va_list ap)
{
  int type;
  unsigned char *cp;
  SshHttpCookie *cookie;

  while ((type = va_arg(ap, int)) != SSH_HTTP_HDR_END)
    {
      switch (type)
        {
        case SSH_HTTP_HDR_CONNECTION_CLOSE:
          req->w.close = TRUE;
          break;

        case SSH_HTTP_HDR_USE_HTTP_1_0:
          req->use_http_1_0 = TRUE;
          break;

          /* SSH_HTTP_HDR_COOKIE_DISCARD is server only */

          /* SSH_HTTP_HDR_COOKIE_SECURE is server only */

          /* SSH_HTTP_HDR_COOKIE_SEND_EXPIRES is server only */

          /* SSH_HTTP_HDR_COOKIE_USE_SET_COOKIE2 is server only */

        case SSH_HTTP_HDR_NO_EXPECT_100_CONTINUE:
          req->no_expect_100_continue = TRUE;
          break;

        case SSH_HTTP_HDR_SERVER_IS_HTTP_1_1:
          req->server_is_http_1_1 = TRUE;
          break;

        case SSH_HTTP_HDR_CONTENT_LENGTH:
          req->w.stream_content_length_known = TRUE;
          req->w.stream_content_length = va_arg(ap, size_t);
          break;

        case SSH_HTTP_HDR_DATE:
          if ((cp = ssh_http_make_rfc1123_date(va_arg(ap, SshTime))) != NULL)
            {
              ssh_http_kvhash_put_cstrs(req->header_fields,
                                        ssh_custr("Date"), cp);
              ssh_free(cp);
            }
          break;

        case SSH_HTTP_HDR_EXPIRES:
          if ((cp = ssh_http_make_rfc1123_date(va_arg(ap, SshTime))) != NULL)
            {
              ssh_http_kvhash_put_cstrs(req->header_fields,
                                        ssh_custr("Expires"), cp);
              ssh_free(cp);
            }
          break;

        case SSH_HTTP_HDR_LAST_MODIFIED:
          if ((cp = ssh_http_make_rfc1123_date(va_arg(ap, SshTime))) != NULL)
            {
              ssh_http_kvhash_put_cstrs(req->header_fields,
                                        ssh_custr("Last-Modified"), cp);
              ssh_free(cp);
            }
          break;

          /* SSH_HTTP_HDR_COOKIE_MAX_AGE is server only */

        case SSH_HTTP_HDR_ACCEPT_CHARSET:
          ssh_http_kvhash_put_cstrs(req->header_fields,
                                    ssh_custr("Accept-Charset"),
                                    va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_ACCEPT_ENCODING:
          ssh_http_kvhash_put_cstrs(req->header_fields,
                                    ssh_custr("Accept-Encoding"),
                                    va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_ACCEPT_LANGUAGE:
          ssh_http_kvhash_put_cstrs(req->header_fields,
                                    ssh_custr("Accept-Language"),
                                    va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_ACCEPT:
          ssh_http_kvhash_put_cstrs(req->header_fields,
                                    ssh_custr("Accept"),
                                    va_arg(ap, unsigned char *));
          break;

          /* SSH_HTTP_HDR_HOST is created automatically */

          /* SSH_HTTP_HDR_LOCATION is server only */

          /* SSH_HTTP_HDR_SERVER is server only */

        case SSH_HTTP_HDR_TE:
          ssh_http_kvhash_put_cstrs(req->header_fields, ssh_custr("TE"),
                                    va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_USER_AGENT:
          ssh_http_kvhash_put_cstrs(req->header_fields,
                                    ssh_custr("User-Agent"),
                                    va_arg(ap, unsigned char *));
          break;

          /* SSH_HTTP_HDR_AUTHENTICATE_BASIC is server only */

          /* SSH_HTTP_HDR_COOKIE_COMMENT is server only */

          /* SSH_HTTP_HDR_COOKIE_COMMENT_URL is server only */

        case SSH_HTTP_HDR_COOKIE_DOMAIN:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_DOMAIN");
          cookie->domain = ssh_strdup(va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_COOKIE_PATH:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_PATH");
          cookie->path = ssh_strdup(va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_COOKIE_PORT:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_PORT");
          cookie->port = ssh_strdup(va_arg(ap, unsigned char *));
          break;





        case SSH_HTTP_HDR_CONTENT_MD5:
          {
            unsigned char *value;

            value = ssh_buf_to_base64(va_arg(ap, unsigned char *),
                                      va_arg(ap, size_t));
            if (value)
              {
                ssh_http_kvhash_put_cstrs(req->header_fields,
                                          ssh_custr("Content-MD5"), value);
                ssh_free(value);
              }
          }
          break;

        case SSH_HTTP_HDR_FIELD:
          {
            unsigned char *key = va_arg(ap, unsigned char *);
            unsigned char *val = va_arg(ap, unsigned char *);
            int i;

            /* Check the skip list. */
            for (i = 0; ssh_http_client_hdr_skip_list[i]; i++)
              if (ssh_usstrcasecmp(key, ssh_http_client_hdr_skip_list[i])
                  == 0)
                break;

            if (ssh_http_client_hdr_skip_list[i] == NULL)
              /* Accepted. */
              ssh_http_kvhash_put_cstrs(req->header_fields, key, val);
          }
          break;

        case SSH_HTTP_HDR_COOKIE:
          {
            unsigned char *name = va_arg(ap, unsigned char *);
            unsigned char *value = va_arg(ap, unsigned char *);
            SshHttpCookie *tmp;

            if (req->cookies == NULL)
              {
                tmp = ssh_malloc(sizeof(SshHttpCookie));
                req->num_cookies = 1;
              }
            else
              {
                tmp =
                  ssh_realloc(req->cookies,
                              req->num_cookies * sizeof(SshHttpCookie),
                              (req->num_cookies + 1) * sizeof(SshHttpCookie));
                req->num_cookies++;
              }

            if (tmp == NULL)
              {
                /* Skip the rest of headers, we would not have space for
                   them anyway. */
                ssh_free(req->cookies);
                return;
              }

            req->cookies = tmp;
            cookie = &req->cookies[req->num_cookies - 1];
            memset(cookie, 0, sizeof(*cookie));

            if ((cookie->name = ssh_strdup(name)) == NULL ||
                (cookie->value = ssh_strdup(value)) == NULL)
              {
                ssh_free(req->cookies);
                return;
              }
          }
          break;

        case SSH_HTTP_HDR_FIELD_LEN:
          {
            unsigned char *key = va_arg(ap, unsigned char *);
            size_t key_len = va_arg(ap, size_t);
            unsigned char *val = va_arg(ap, unsigned char *);
            size_t val_len = va_arg(ap, size_t);
            int i;

            /* Check the skip list. */
            for (i = 0; ssh_http_client_hdr_skip_list[i]; i++)
              if (strlen(ssh_http_client_hdr_skip_list[i]) == key_len
                  && ssh_usstrncasecmp(key, ssh_http_client_hdr_skip_list[i],
                                       key_len) == 0)
                break;

            if (ssh_http_client_hdr_skip_list[i] == NULL)
              /* Accepted. */
              ssh_http_kvhash_put(req->header_fields,
                                  key, key_len, val, val_len);
          }
          break;

        default:
          ssh_http_hdr_skip_next(ap, type);
          break;
        }
    }
}


static void
ssh_http_fixed_content_data_stream_cb(SshStreamNotification notification,
                                      void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;
  int i;
  SshHttpRequest *req = ctx->req;

  if (notification == SSH_STREAM_CAN_OUTPUT)
    {
      while (req->w.content_data_len - req->w.content_data_written > 0)
        {
          i = ssh_stream_write(ctx->w.stream,
                               (req->w.content_data
                                + req->w.content_data_written),
                               (req->w.content_data_len
                                - req->w.content_data_written));
          if (i == 0)
            /* EOF reached. */
            break;
          if (i < 0)
            /* Would block. */
            return;

          req->w.content_data_written += i;
        }

      /* Wrote it all. */
      ssh_stream_output_eof(ctx->w.stream);
      ssh_stream_destroy(ctx->w.stream);
    }
}


static void
ssh_http_fixed_content_data_connect_cb(SshHttpClientContext ctx,
                                       SshStream stream, void *context)
{
  ssh_stream_set_callback(stream, ssh_http_fixed_content_data_stream_cb,
                          context);
  ssh_http_fixed_content_data_stream_cb(SSH_STREAM_CAN_OUTPUT, context);
}


static void
ssh_http_process_requests(SshHttpClientContext ctx)
{
  SshHttpRequest *req, *req_next;

  /* If the context was destroyed (by client_uninitialize), destroy
     the connection and abort all pending callbacks */
  if (ctx->client_uninitialized)
    {
      /* Destroy the possible HTTP connection. */
      if (ctx->http_stream)
        ssh_stream_destroy(ctx->http_stream);

      /* Destroy all queued requests and signal their callback functions
         that they were aborted. */
      for (req = ctx->req; req; req = req_next)
        {
          req_next = req->next;
          if (req->r.callback)
            (*req->r.callback)(ctx, SSH_HTTP_RESULT_ABORTED, SSH_TCP_OK,
                               NULL, req->r.callback_context);

          ssh_http_free_request(req);
        }

      /* Free the client context structure. */

      if (ctx->new_request)
        ssh_http_free_request(ctx->new_request);

      ssh_free(ctx->socks);
      ssh_free(ctx->proxy_name);
      ssh_free(ctx->proxy_port);
      ssh_free(ctx->proxy_user_name);
      ssh_free(ctx->proxy_password);
      ssh_free(ctx->user_name);
      ssh_free(ctx->password);

      ssh_buffer_uninit(&ctx->out_buffer);
      ssh_buffer_uninit(&ctx->in_buffer);

      ssh_http_kvhash_destroy(ctx->values);

      ssh_http_free_cookies(ctx);

      ssh_free(ctx->status_reason_phrase);

      ssh_free(ctx);
      return;
    }

  if (ctx->req == NULL)
    {
      /* We'r done. */
      if (ctx->deleted)
        ssh_http_client_uninit(ctx);
      return;
    }

  /* Re-init everything in our context.  These variables might contain
     some garbage from the previous request. */

  ctx->eof_seen = FALSE;
  ssh_buffer_clear(&ctx->out_buffer);
  ssh_buffer_clear(&ctx->in_buffer);
  ctx->r.content_data_read = 0;
  ctx->r.end_of_content_data = FALSE;
  ssh_http_kvhash_clear(ctx->values);

  ssh_http_free_cookies(ctx);

  ctx->status_code = 0;
  if (ctx->status_reason_phrase)
    {
      ssh_free(ctx->status_reason_phrase);
      ctx->status_reason_phrase = NULL;
    }

  ctx->connection_close = FALSE;

  if (ctx->req->server_is_http_1_1)
    {
      ctx->server_version_known = TRUE;
      ctx->version_major = 1;
      ctx->version_minor = 1;
    }

  /* Format an HTTP request for the next request in our queue. */
  ssh_http_format_http_request(ctx);

  /* If the ctx->http_stream is open, it is recycled from the previous
     connection: we are trying to keep-alive it.  Otherwise, we must
     start a fresh connection. */

  if (ctx->http_stream)
    {
      /* Order a timeout that will signal our connection and cause it
         to write the new request. */
      ctx->req->w.state = SSH_HTTP_REQUEST_WRITING_HEADER;
      ssh_xregister_timeout(0, 0, ssh_http_signal_new_request_timeout, ctx);
    }
  else
    {
      SshTcpConnectParamsStruct tcp_connect_params;
      unsigned char *host;
      unsigned char *port;

      /* Start a fresh connection. */
      ctx->state = SSH_HTTP_CTX_CONNECTING;

      if (ctx->proxy_name)
        {
          host = ctx->proxy_name;
          port = ctx->proxy_port;
        }
      else
        {
          host = ctx->req->host_name;
          port = ctx->req->port;
        }

      memset(&tcp_connect_params, 0, sizeof(tcp_connect_params));
      tcp_connect_params.socks_server_url = ctx->socks;
      tcp_connect_params.connection_timeout = ctx->tcp_connect_timeout;
      ctx->connect_op = ssh_tcp_connect(host, port,
                                        -1, 0,
                                        &tcp_connect_params,
                                        ssh_http_connect_callback, ctx);
    }
}


static void
ssh_http_signal_new_request_timeout(void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  /* Notify the stream that we have more data available. */
  ssh_http_stream_callback(SSH_STREAM_CAN_OUTPUT, ctx);
  ssh_http_stream_callback(SSH_STREAM_INPUT_AVAILABLE, ctx);
}


static void
ssh_http_format_http_request(SshHttpClientContext ctx)
{
  SshHttpRequest *req = ctx->req;
  char *method = NULL;
  unsigned char buf[512];
  unsigned char *host_name;
  unsigned char *host_port;
  unsigned char *key;
  unsigned char *value;
  unsigned char *start, *end;

  switch (req->method)
    {
    case SSH_HTTP_GET:
      method = "GET ";
      break;

    case SSH_HTTP_HEAD:
      method = "HEAD ";
      break;

    case SSH_HTTP_POST:
      method = "POST ";
      break;

    case SSH_HTTP_PUT:
      method = "PUT ";
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  start = ssh_buffer_ptr(&ctx->out_buffer) + ssh_buffer_len(&ctx->out_buffer);

  if (ssh_buffer_append_cstrs(&ctx->out_buffer, method, NULL) != SSH_BUFFER_OK)
    goto failed;

  if (ctx->proxy_name)
    {
      if (ssh_usstrcmp(req->port, "80") == 0)
        {
          if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                      "http://", req->host_name, "/",
                                      NULL) != SSH_BUFFER_OK)
            goto failed;
        }
      else
        {
          if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                      "http://", req->host_name,
                                      ":", req->port, "/",
                                      NULL) != SSH_BUFFER_OK)
            goto failed;
        }
    }
  else
    {
      if (ssh_buffer_append_cstrs(&ctx->out_buffer, "/", NULL)
          != SSH_BUFFER_OK)
        goto failed;
    }

  if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                              req->uri,
                              " HTTP/1.", req->use_http_1_0 ? "0" : "1",
                              "\r\n",
                              NULL) != SSH_BUFFER_OK)
    goto failed;

  /* HTTP/1.1 requires the `Host' field.  It doesn't hurt on HTTP/1.0
     requests either. */
  if (ctx->proxy_name)
    {
      host_name = ctx->proxy_name;
      host_port = ctx->proxy_port;
    }
  else
    {
      host_name = req->host_name;
      host_port = req->port;
    }

  if (ssh_usstrcmp(host_port, "80") == 0)
    {
      if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                  "Host: ", host_name, "\r\n",
                                  NULL) != SSH_BUFFER_OK)
        goto failed;
    }
  else
    {
      if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                  "Host: ", host_name, ":", host_port, "\r\n",
                                  NULL) != SSH_BUFFER_OK)
        goto failed;
    }

  /* Authorization? */
  if (req->authorization)
    if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                "Authorization: ", req->authorization, "\r\n",
                                NULL) != SSH_BUFFER_OK)
      goto failed;

  /* Proxy authentication? */
  if (req->proxy_authorization)
    if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                "Proxy-Authorization:",
                                req->proxy_authorization,
                                "\r\n",
                                NULL) != SSH_BUFFER_OK)
      goto failed;

 /* The content data length and its possible transfer encoding. */
  if (req->has_content_data)
    {
      if (req->use_http_1_0 || !ctx->server_version_known)
        {
          if (req->w.content_data)
            {
              /* We have fixed length content data. */
              ssh_snprintf(buf, sizeof(buf), "Content-Length: %d\r\n",
                           req->w.content_data_len);
              if (ssh_buffer_append_cstrs(&ctx->out_buffer, buf,
                                          NULL) != SSH_BUFFER_OK)
                goto failed;
            }
          else if (req->w.stream_content_length_known)
            {
              /* Stream of content data but its length is known. */
              ssh_snprintf(buf, sizeof(buf), "Content-Length: %d\r\n",
                           req->w.stream_content_length);
              if (ssh_buffer_append_cstrs(&ctx->out_buffer, buf,
                                          NULL) != SSH_BUFFER_OK)
                goto failed;
            }
          else
            {
              /* Otherwise, we must close the connection since the
                 content data length is notified with the EOF. */
              req->w.close = TRUE;
            }
          req->use_chunked_te = FALSE;
        }
      else /* http 1.1 */
        {
          /* We use the chunked transfer coding. */
          if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                      "Transfer-Encoding: chunked\r\n",
                                      NULL) != SSH_BUFFER_OK)
            goto failed;
          req->use_chunked_te = TRUE;
        }
    }

  /* HTTP/1.0 specific fields. */
  if (req->use_http_1_0)
    {
      /* Connection must be closed when we are connecting to a proxy
         with the HTTP/1.0 protocol. */
      if (ctx->proxy_name)
        req->w.close = TRUE;
    }
  else                          /* HTTP/1.1 specific fields. */
    {
      if (req->has_content_data && !req->no_expect_100_continue)
        if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                    "Expect: 100-continue\r\n",
                                    NULL) != SSH_BUFFER_OK)
          goto failed;
    }

  if (req->w.close)
    {
      /* An explicit close requested. */
      if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                  "Connection: close\r\n",
                                  NULL) != SSH_BUFFER_OK)
        goto failed;
    }
  else if (req->use_http_1_0)
    {
      /* HTTP/1.0 `Connection: Keep-Alive'. */
      if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                  "Connection: Keep-Alive\r\n",
                                  NULL) != SSH_BUFFER_OK)
        goto failed;
    }

  /* The user specified header fields. */
  for (ssh_http_kvhash_reset_index(req->header_fields);
       ssh_http_kvhash_get_next(req->header_fields, &key, &value); )
    if (ssh_buffer_append_cstrs(&ctx->out_buffer, key, ": ", value, "\r\n",
                                NULL) != SSH_BUFFER_OK)
      goto failed;

  /* Cookies. */
  if (req->cookies)
    {
      unsigned int i;

      for (i = 0; i < req->num_cookies; i++)
        {
          SshHttpCookie *cookie = &req->cookies[i];

          /* Format the cookies like they are in the draft. */
          if (i == 0)
            {
              if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                          "Cookie: $Version=\"1\";",
                                          NULL) != SSH_BUFFER_OK)
                goto failed;
            }
          else
            {
              if (ssh_buffer_append_cstrs(&ctx->out_buffer, "        ", NULL)
                  != SSH_BUFFER_OK)
                goto failed;
            }

          /* NAME=VALUE */
          if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                      cookie->name, "=\"", cookie->value, "\"",
                                      NULL) != SSH_BUFFER_OK)
            goto failed;

          /* Attributes. */

          if (cookie->path)
            if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                        "; $Path=\"", cookie->path, "\"",
                                        NULL) != SSH_BUFFER_OK)
              goto failed;

          if (cookie->domain)
            if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                        "; $Domain=\"", cookie->domain, "\"",
                                        NULL) != SSH_BUFFER_OK)
              goto failed;
          if (cookie->port)
            if (ssh_buffer_append_cstrs(&ctx->out_buffer,
                                        "; $Port=\"", cookie->port, "\"",
                                        NULL) != SSH_BUFFER_OK)
              goto failed;

          /* Have more cookies? */
          if (i + 1 < req->num_cookies)
            /* Yes we have. */
            if (ssh_buffer_append_cstrs(&ctx->out_buffer, ";",
                                        NULL) != SSH_BUFFER_OK)
              goto failed;

          if (ssh_buffer_append_cstrs(&ctx->out_buffer, "\r\n",
                                      NULL) != SSH_BUFFER_OK)
            goto failed;

        }
    }

  /* The header / body separator. */
  if (ssh_buffer_append_cstrs(&ctx->out_buffer, "\r\n", NULL)
      != SSH_BUFFER_OK)
    goto failed;

  SSH_DEBUG(9, ("request=\"%.*s\"",
                (int) ssh_buffer_len(&ctx->out_buffer),
                ssh_buffer_ptr(&ctx->out_buffer)));

  return;

 failed:
  /* On error, consume what was written */
  end = ssh_buffer_ptr(&ctx->out_buffer) + ssh_buffer_len(&ctx->out_buffer);
  ssh_buffer_consume_end(&ctx->out_buffer, end - start);
  if (req->r.callback)
    (*req->r.callback)(ctx, SSH_HTTP_RESULT_ABORTED, SSH_TCP_OK,
                       NULL, req->r.callback_context);
  return;
}


static void
ssh_http_connect_callback(SshTcpError error, SshStream stream,
                          void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  ctx->connect_op = NULL;

  /* Check if the connection was aborted.  */
  if (ctx->client_uninitialized)
    {
    uninitialized:
      /* Yes it was. */
      SSH_DEBUG(8, ("Client uninitialized"));
      if (error == SSH_TCP_OK)
        ssh_stream_destroy(stream);

      ctx->state = SSH_HTTP_CTX_IDLE;
      ssh_http_client_uninit(ctx);
      return;
    }
  /* Check if the current operation was aborted. */
  if (ctx->connect_request_aborted)
    {
      /* Yes it was. */
      ctx->connect_request_aborted = FALSE;

      SSH_DEBUG(8, ("Request aborted"));
      if (error == SSH_TCP_OK)
        ssh_stream_destroy(stream);

      ssh_http_finish_request(ctx);
      return;
    }

  if (error != SSH_TCP_OK)
    {
      SSH_DEBUG(8, ("error=%d", error));

      /* Retry? */
      if (ssh_http_retry_request(ctx, FALSE))
        return;

      /* Tell our user that we failed to connect. */
      if (ctx->req->r.callback)
        {
          (*ctx->req->r.callback)(ctx, SSH_HTTP_RESULT_CONNECT_FAILED, error,
                                  NULL, ctx->req->r.callback_context);
          ctx->req->r.callback = NULL_FNPTR;
        }

      if (ctx->client_uninitialized)
        /* The user uninitialized us from the callback. */
        goto uninitialized;

      /* Continue with the next request. */
      ssh_http_finish_request(ctx);
    }
  else
    {
      SSH_DEBUG(8, ("SSH_TCP_OK"));

      ctx->state = SSH_HTTP_CTX_CONNECTED;
      ctx->http_stream = stream;
      ctx->req->w.state = SSH_HTTP_REQUEST_WRITING_HEADER;
      ctx->req->w.content_data_written = 0;

      /* Call the TCP wrapper function if specified. */
      if (ctx->tcp_wrapper)
        {
          ctx->http_stream = (*ctx->tcp_wrapper)(ctx,
                                                 ctx->http_stream,
                                                 ctx->tcp_wrapper_context);
        }
      ssh_stream_set_callback(ctx->http_stream, ssh_http_stream_callback, ctx);

      ssh_http_stream_callback(SSH_STREAM_CAN_OUTPUT, ctx);
      ssh_http_stream_callback(SSH_STREAM_INPUT_AVAILABLE, ctx);
    }
}


static void
ssh_http_expect_100_continue_timeout(void *context)
{
  SshHttpRequest *req = context;

  SSH_DEBUG(8, ("Expect `100 Continue' timeouted"));

  req->w.state = SSH_HTTP_REQUEST_RECEIVED_100_CONTINUE;
  ssh_http_stream_callback(SSH_STREAM_CAN_OUTPUT, req->ctx);
}


static void
ssh_http_stream_callback(SshStreamNotification notification, void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;
  SshHttpRequest *req = ctx->req;
  unsigned char *p;
  int l;

  if (ctx->client_uninitialized)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("HTTP client scheduled for removal, ignoring callback"));
      return;
    }

  switch (notification)
    {
    case SSH_STREAM_CAN_OUTPUT:
      switch (ctx->req->w.state)
        {
        case SSH_HTTP_REQUEST_UNCONNECTED:
          /* Nothing here. */
          break;

        case SSH_HTTP_REQUEST_WRITING_HEADER:
          if (ssh_buffer_len(&ctx->out_buffer) == 0)
            /* This is handled after we have written it all. */
            SSH_NOTREACHED;

          while (ssh_buffer_len(&ctx->out_buffer) != 0)
            {
              SSH_DEBUG(8, ("Can output, sending %zd bytes",
                            ssh_buffer_len(&ctx->out_buffer)));
              l = ssh_stream_write(ctx->http_stream,
                                   ssh_buffer_ptr(&ctx->out_buffer),
                                   ssh_buffer_len(&ctx->out_buffer));
              if (l == 0)
                {
                  /* EOF encountered, the server has closed our
                     connection. */

                  /* Retry? */
                  if (ssh_http_retry_request(ctx, FALSE))
                    return;

                  /* Report the failure. */
                  if (req->r.callback)
                    (*req->r.callback)(ctx,
                                       SSH_HTTP_RESULT_CONNECTION_CLOSED,
                                       SSH_TCP_OK, NULL,
                                       req->r.callback_context);

                  /* Done with this request.  Cleanup and move to the
                     next one. */
                  ssh_http_finish_request(ctx);
                  return;
                }

              if (l < 0)
                {
                  SSH_DEBUG(8, ("Write blocked"));
                  return;
                }
              ssh_buffer_consume(&ctx->out_buffer, l);
            }
          SSH_DEBUG(8, ("Request written successfully"));

          if (req->has_content_data
              && !req->no_expect_100_continue
              && !req->use_http_1_0)
            {
              /* Wait for the server's `100 Continue' response. */
              SSH_DEBUG(8, ("Waiting for `100 Continue'"));
              req->w.state = SSH_HTTP_REQUEST_EXPECTING_100_CONTINUE;

              /* Order a timeout to continue anyway. */
              ssh_xregister_timeout(ctx->expect_100_continue_timeout, 0,
                                   ssh_http_expect_100_continue_timeout, req);
              return;
            }

          /* Continue with the body, or just finish writing this
             request. */
          goto header_written;
          break;

        case SSH_HTTP_REQUEST_EXPECTING_100_CONTINUE:
          /* Nothing here. */
          break;

        case SSH_HTTP_REQUEST_RECEIVED_100_CONTINUE:
          /* Ok, we got it. */
          SSH_DEBUG(8, ("Received `100 Continue' or another header"));

          /* Cancel possible timeout. */
          ssh_cancel_timeouts(ssh_http_expect_100_continue_timeout, req);

        header_written:

          /* Continue writing the body of the request, or we are just
             done. */
          if (req->has_content_data)
            {
              /* Send the content data. */
              req->w.state = SSH_HTTP_REQUEST_WRITING_BODY;

              /* Call the connect callback. */
              if ((ctx->w.stream = ssh_http_content_write_stream_create(ctx))
                  == NULL)
                {
                alloc_failed:
                  (*req->r.callback)(ctx,
                                     SSH_HTTP_RESULT_CONNECTION_CLOSED,
                                     SSH_TCP_OK, NULL,
                                     req->r.callback_context);
                  return;
                }

              /* Chunked transfer coding. */
              if (req->use_chunked_te)
                if ((ctx->w.stream =
                     ssh_http_chunked_stream_create(ctx->w.stream,
                                                    FALSE, TRUE,
                                                    NULL_FNPTR,
                                                    NULL)) == NULL)
                  goto alloc_failed;

              /* Pass the stream to the user. */
              (*ctx->req->w.callback)(ctx, ctx->w.stream,
                                      ctx->req->w.callback_context);
              return;
            }
          else
            req->w.state = SSH_HTTP_REQUEST_WRITTEN;
          break;

        case SSH_HTTP_REQUEST_WRITING_BODY:
          /* Pass the notification to the UI stream. */
          if (ctx->w.callback)
            (*ctx->w.callback)(notification, ctx->w.callback_context);
          break;

        case SSH_HTTP_REQUEST_WRITTEN:
          /* Nothing here. */
          break;
        }
      break;

    case SSH_STREAM_INPUT_AVAILABLE:
      while (1)
        {
          size_t to_read;

          if (ssh_buffer_len(&ctx->in_buffer) >= ctx->max_buffer_size)
            {
              if (ctx->req->r.state == SSH_HTTP_RESPONSE_READING_BODY)
                {
                  /* Flow control in action.  We must wait for our
                     client to consume some of it. */
                  SSH_DEBUG(9, ("Flow control: buffered=%d",
                                ssh_buffer_len(&ctx->in_buffer)));
                  return;
                }
              else
                {
                  /* Sorry, can't read more. */
                toolong:
                  if (req->r.callback)
                    (*req->r.callback)(
                                ctx,
                                SSH_HTTP_RESULT_MAXIMUM_BUFFER_SIZE_REACHED,
                                SSH_TCP_OK, NULL, req->r.callback_context);

                  /* Done with this request. */
                  ssh_http_finish_request(ctx);
                  return;
                }
            }

          to_read = ctx->max_buffer_size - ssh_buffer_len(&ctx->in_buffer);

          if (ssh_buffer_append_space(&ctx->in_buffer, &p, to_read)
              != SSH_BUFFER_OK)
            goto toolong;

          if (ctx->http_stream == NULL)
            {
              SSH_DEBUG(8, ("HTTP stream is NULL"));
              ssh_buffer_consume_end(&ctx->in_buffer, to_read);
              return;
            }

          l = ssh_stream_read(ctx->http_stream, p, to_read);

          if (l < 0)
            {
              SSH_DEBUG(8, ("Read blocked"));
              ssh_buffer_consume_end(&ctx->in_buffer, to_read);
              return;
            }
          if (l == 0)
            {
              SSH_DEBUG(8, ("EOF received"));
              ssh_buffer_consume_end(&ctx->in_buffer, to_read);
              ctx->eof_seen = TRUE;

              if (ctx->r.content_data_read == 0)
                {
                  /* We have received zero bytes of content data.  Let's
                     retry. */
                  if (ssh_http_retry_request(ctx, FALSE))
                    return;

                  /* FALLTHROUGH */
                }

              ssh_http_process_input(ctx);
              return;
            }

          ssh_buffer_consume_end(&ctx->in_buffer, to_read - l);
          SSH_DEBUG(9, ("read=%d, buffered=%zd", l,
                        ssh_buffer_len(&ctx->in_buffer)));

          if (req->r.state == SSH_HTTP_RESPONSE_READING_BODY)
            /* Update the amount of content data read so far. */
            ctx->r.content_data_read += l;

          if (ssh_http_process_input(ctx))
            return;
        }
      break;

    case SSH_STREAM_DISCONNECTED:
      SSH_DEBUG(8, ("Disconnected"));
      break;
    }
}


static void
ssh_http_abort_operation(void *context)
{
  SshHttpRequest *req = (SshHttpRequest *) context;

  req->operation = NULL;
  SSH_DEBUG(7, ("Aborting connection"));

  /* Cancel all timeouts from this request. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, req);

  if (req == req->ctx->req)
    {
      /* Our request is the currently active request. */
      if (req->ctx->state == SSH_HTTP_CTX_CONNECTING)
        {
          ssh_operation_abort(req->ctx->connect_op);
          req->ctx->connect_request_aborted = TRUE;
          ssh_http_finish_request(req->ctx);
        }
      else
        ssh_http_finish_request(req->ctx);
    }
  else
    {
      SshHttpRequest *r, *p;

      /* It is in the wait queue.  This is trivial.  Just remove it
         from the queue and free the request. */

      for (p = NULL, r = req->ctx->req; r && r != req; p = r, r = r->next)
        ;
      SSH_ASSERT(r == req);

      if (p)
        p->next = req->next;
      else
        req->ctx->req = req->next;

      if (req->next == NULL)
        req->ctx->req_tail = p;

      ssh_http_free_request(req);
    }
}

static Boolean
ssh_http_request_addresses_equal(
        SshHttpRequest *request_a,
        SshHttpRequest *request_b)
{
  const unsigned char *port_a = request_a->port;
  const unsigned char *port_b = request_b->port;
  const unsigned char *name_a = request_a->host_name;
  const unsigned char *name_b = request_b->host_name;

  return
      port_a != NULL &&
      port_b != NULL &&
      ssh_ustrcasecmp(port_a, port_b) == 0 &&

      name_a != NULL &&
      name_b != NULL &&
      ssh_ustrcasecmp(name_a, name_b) == 0;
}


static void
ssh_http_finish_request(SshHttpClientContext ctx)
{
  SshHttpRequest *req = ctx->req;
  SshHttpRequest *nreq = req->next;
  const unsigned char *value;
  Boolean keep_alive;
  Boolean recycle_request = FALSE;
  Boolean recycle_same_server = FALSE;

  /* Cancel all timeouts from this request and from the context. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, req);
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, ctx);

  if (req->w.state == SSH_HTTP_REQUEST_WRITTEN
      && req->r.state == SSH_HTTP_RESPONSE_READ)
    {
      /* We managed to process the whole request.  Now, check the end
         rules. */
      switch (ctx->status_code)
        {
        case SSH_HTTP_STATUS_CONTINUE:
        case SSH_HTTP_STATUS_SWITCHING_PROTOCOLS:
          /* These are handled in the ssh_http_process_input(). */
          break;

        case SSH_HTTP_STATUS_OK:
        case SSH_HTTP_STATUS_CREATED:
        case SSH_HTTP_STATUS_ACCEPTED:
        case SSH_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION:
        case SSH_HTTP_STATUS_NO_CONTENT:
        case SSH_HTTP_STATUS_RESET_CONTENT:
        case SSH_HTTP_STATUS_PARTIAL_CONTENT:
          /* All done.  We are ready for the next request. */
          break;

        case SSH_HTTP_STATUS_NOT_MODIFIED:
          /* Nothing special with these. */
          break;

          /* SSH_HTTP_STATUS_USE_PROXY should be handled here as a
             special redirection.  Currently, we just return it as an
             error. */

        case SSH_HTTP_STATUS_LENGTH_REQUIRED:
          /* A request with content was sent, and the server requires
             us to resend it with a fixed content length. Even
             HTTP/1.1-compliant Apache 1.3.12 is doing this. We just
             resend the request using HTTP/1.0 which forces the
             sending of Content-Length. */
          req->use_http_1_0 = TRUE;
          recycle_request = TRUE;
          recycle_same_server = TRUE;
          break;

        case SSH_HTTP_STATUS_MULTIPLE_CHOICES:
        case SSH_HTTP_STATUS_MOVED_PERMANENTLY:
        case SSH_HTTP_STATUS_FOUND:
        case SSH_HTTP_STATUS_SEE_OTHER:
        case SSH_HTTP_STATUS_TEMPORARY_REDIRECT:
          /* Must perform a redirect. */
          value = ssh_http_kvhash_get(ctx->values, ssh_custr("LOCATION"));
          if (value)
            {
              unsigned char *old_host_name;
              unsigned char *old_port;
              unsigned char *old_uri;
              unsigned char *s, *u;

              /* Check the redirect limit. */
              if (++req->redirect_count > ctx->num_redirections)
                {
                  /* Sorry, not allowed anymore. */
                  if (req->r.callback)
                    (*req->r.callback)(ctx,
                                       SSH_HTTP_RESULT_REDIRECT_LIMIT_EXCEEDED,
                                       SSH_TCP_OK, NULL,
                                       req->r.callback_context);
                  break;
                }

              if (!ssh_url_parse_relaxed(value,
                                         &s, NULL, NULL, NULL, NULL, &u))
                {
                  if (req->r.callback)
                    (*req->r.callback)(ctx,
                                       SSH_HTTP_RESULT_MALFORMED_URL,
                                       SSH_TCP_OK, NULL,
                                       req->r.callback_context);
                  break;
                }

              if (s)
                {
                  /* Free all URL components from the request. */

                  ssh_free(s); ssh_free(u);

                  old_host_name = req->host_name;
                  req->host_name = NULL;

                  old_port = req->port;
                  req->port = NULL;

                  ssh_free(req->authorization);
                  req->authorization = NULL;

                  ssh_free(req->proxy_authorization);
                  req->proxy_authorization = NULL;

                  ssh_free(req->user_name);
                  req->user_name = NULL;

                  ssh_free(req->password);
                  req->password = NULL;

                  ssh_free(req->proxy_user_name);
                  req->proxy_user_name = NULL;

                  ssh_free(req->proxy_password);
                  req->proxy_password = NULL;

                  old_uri = req->uri;
                  req->uri = NULL;

                  /* Parse the redirected URL. */
                  if (!ssh_http_parse_request(ctx, req, value))
                    {
                      SSH_DEBUG(5, ("Broken redirect: URL=%s",
                                    value));
                      goto redirect_failed;
                    }
                }
              else
                {
                  ssh_free(s);

                  old_host_name = ssh_strdup(req->host_name);
                  old_port  = ssh_strdup(req->port);

                  old_uri = req->uri;
                  req->uri = u;
                }

              SSH_DEBUG(5, ("Redirect: "
                            "code=%d, from=%s:%s/%s, to=%s:%s/%s",
                            ctx->status_code,
                            old_host_name, old_port, old_uri,
                            req->host_name, req->port, req->uri));

              /* A redirection to the same server? */
              if (old_host_name &&
                  ssh_ustrcmp(old_host_name, req->host_name) == 0 &&
                  old_port &&
                  ssh_ustrcmp(old_port, req->port) == 0)
                recycle_same_server = TRUE;

              /* How about the content data in redirects?  Now we
                 could junk it. */

              /* Recycle current request. */
              recycle_request = TRUE;

            redirect_failed:
              /* Free tmp variables. */
              ssh_free(old_host_name);
              ssh_free(old_port);
              ssh_free(old_uri);
            }
          else
            {
              SSH_DEBUG(5, ("Redirection required but no `Location' given"));
              if (req->r.callback)
                (*req->r.callback)(ctx,
                                   SSH_HTTP_RESULT_REDIRECT_WITHOUT_LOCATION,
                                   SSH_TCP_OK, NULL, req->r.callback_context);
            }
          break;

        case SSH_HTTP_STATUS_UNAUTHORIZED:
          /* Authentication required. */
          if (ssh_http_authentication(ctx))
            {
              /* Retry. */
              recycle_request = TRUE;
              recycle_same_server = TRUE;
            }
          break;

        case SSH_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED:
          /* Proxy authentication required. */
          if (ssh_http_proxy_authentication(ctx))
            {
              /* Retry. */
              recycle_request = TRUE;
              recycle_same_server = TRUE;
            }
          break;

        default:
          /* Return all other codes as an HTTP error. */
          SSH_DEBUG(9, ("Assuming an error: code=%d %s",
                        ctx->status_code,
                        ctx->status_reason_phrase));
          if (req->r.callback)
            (*req->r.callback)(ctx, SSH_HTTP_RESULT_HTTP_ERROR, SSH_TCP_OK,
                               NULL, req->r.callback_context);
          break;
        }
    }

  /* Can we recycle our connection to the next request? */

  keep_alive = FALSE;

  if (req->w.state == SSH_HTTP_REQUEST_WRITTEN
      && req->r.state == SSH_HTTP_RESPONSE_READ
      && !req->w.close && !ctx->eof_seen && (nreq || recycle_request)
      && !ctx->connection_close
      && ctx->server_version_known
      && ctx->version_major == 1
      && (ctx->proxy_name != NULL
          || (recycle_request && recycle_same_server)
          || (!recycle_request &&
              ssh_http_request_addresses_equal(req, nreq))))
    {
      keep_alive = TRUE;

      if (ctx->version_minor == 0)
        {
          const unsigned char *value;

          /* On HTTP/1.0 we can keep it open if we have seen an
             explicit `Connection: Keep-Alive'. */

          value = ssh_http_kvhash_get(ctx->values, ssh_custr("CONNECTION"));
          if (!value || ssh_usstrcasecmp(value, "KEEP-ALIVE") != 0)
            keep_alive = FALSE;
        }
    }

  if (keep_alive)
    {
      /* Yes we can.  Just a cosmetic fix: we can recycle only if it
         is already open.  Let's not reports false alarms. */
      if (ctx->http_stream)
        {
          SSH_DEBUG(5, ("Keeping the connection open"));
        }
    }
  else
    {
      /* No, we can't keep our connection open. */
      if (ctx->http_stream)
        {
          ssh_stream_destroy(ctx->http_stream);
          ctx->http_stream = NULL;
        }
      ctx->state = SSH_HTTP_CTX_IDLE;
      ctx->server_version_known = FALSE;
    }

  /* Check if we have to cancel the UI streams. */
  if (ctx->w.stream)
    {
      SshStream s = ctx->w.stream;

      ctx->w.stream = NULL;
      ssh_stream_destroy(s);
    }
  if (ctx->r.stream)
    {
      ctx->r.stream = NULL;
      ssh_stream_destroy(ctx->r.stream_user);
    }

  if (recycle_request)
    {
      /* Init the recycled request. */

      req->w.state = SSH_HTTP_REQUEST_UNCONNECTED;
      req->w.eof_output = FALSE;
      req->w.close = FALSE;

      req->r.state = SSH_HTTP_RESPONSE_READING_STATUS_LINE;
    }
  else
    {
      /* Move to the next request. */
      if (ctx->req->next)
        ctx->req = ctx->req->next;
      else
        ctx->req = ctx->req_tail = NULL;

      ssh_http_free_request(req);
    }

  ssh_http_process_requests(ctx);
}


static Boolean
ssh_http_retry_request(SshHttpClientContext ctx, Boolean force)
{
  if (!force && ctx->req->retry_count++ >= ctx->num_retries)
    return FALSE;

  SSH_DEBUG(5, ("URL=%s:%s/%s, count=%u, force=%s",
                ctx->req->host_name, ctx->req->port, ctx->req->uri,
                (int) ctx->req->retry_count,
                force ? "TRUE" : "FALSE"));

  if (ctx->http_stream)
    {
      ssh_stream_destroy(ctx->http_stream);
      ctx->http_stream = NULL;
    }
  ctx->state = SSH_HTTP_CTX_IDLE;

  /* Cancel the user UI streams. */
  if (ctx->w.stream)
    {
      SshStream s = ctx->w.stream;

      ctx->w.stream = NULL;
      ssh_stream_destroy(s);
    }
  if (ctx->r.stream)
    {
      ctx->r.stream = NULL;
      ssh_stream_destroy(ctx->r.stream_user);
    }
  ctx->req->w.state = SSH_HTTP_REQUEST_UNCONNECTED;
  ctx->req->r.state = SSH_HTTP_RESPONSE_READING_STATUS_LINE;

  ssh_http_process_requests(ctx);

  return TRUE;
}


static Boolean
ssh_http_process_input(SshHttpClientContext ctx)
{
  SshHttpRequest *req = ctx->req;
  size_t len;
  SshUInt32 i, j, l;
  unsigned char *p;
  SshUInt32 code;
  const unsigned char *value;

  SSH_ASSERT(ctx->client_uninitialized == FALSE);

  while (1)
    {
      switch (req->r.state)
        {
        case SSH_HTTP_RESPONSE_READING_STATUS_LINE:
          /* Let's check the protocol version of the reply. */
          len = ssh_buffer_len(&ctx->in_buffer);
          p = ssh_buffer_ptr(&ctx->in_buffer);

          /* Can we find one line from the input? */
          for (i = 0; i < len && p[i] != '\n'; i++)
            ;
          if (i >= len)
            {
              if (ctx->eof_seen)
                {
                  /* We couldn't find single line and we have seen the
                     EOF.  This must be HTTP 0.9 reply. */
                http_0_9_reply:

                  SSH_DEBUG(5, ("Got an HTTP/0.9 reply"));
                  SSH_DEBUG(6, ("header=\"%.*s\"", len, p));

                  ctx->version_major = 0;
                  ctx->version_minor = 9;
                  ctx->status_code = SSH_HTTP_STATUS_OK;

                  /* Complete possible `100 Continue' expectation. */
                  if (ctx->req->w.state
                      == SSH_HTTP_REQUEST_EXPECTING_100_CONTINUE)
                    {
                      ctx->req->w.state
                        = SSH_HTTP_REQUEST_RECEIVED_100_CONTINUE;
                      ssh_http_stream_callback(SSH_STREAM_CAN_OUTPUT, ctx);
                    }

                  req->r.state = SSH_HTTP_RESPONSE_READING_BODY;
                  ctx->r.content_data_read = ssh_buffer_len(&ctx->in_buffer);
                  continue;
                }

              /* Wait for more input. */
              return FALSE;
            }

          /* One line of input received.  Parse it and move to other
             header fields.  */
          i++;

          if (p[0] != 'H' ||  p[1] != 'T' || p[2] != 'T' || p[3] != 'P'
              || p[4] != '/')
            goto http_0_9_reply;

          /* Read the protocol major number. */
          ctx->version_major = 0;
          for (j = 5; j < i && isdigit(p[j]); j++)
            {
              ctx->version_major *= 10;
              ctx->version_major += p[j] - '0';
            }
          if (p[j] != '.')
            goto http_0_9_reply;

          /* Read the protocol minor number. */
          ctx->version_minor = 0;
          for (j++; j < i && isdigit(p[j]); j++)
            {
              ctx->version_minor *= 10;
              ctx->version_minor += p[j] - '0';
            }

          /* Skip whitespace. */
          for (; j < i && isspace(p[j]); j++)
            ;

          /* Get numeric return code. */
          if (!isdigit(p[j]))
            goto http_0_9_reply;

          /* Now we know that the first line is a valid HTTP/X.Y reply. */
          code = 0;
          for (; j < i && isdigit(p[j]); j++)
            {
              code *= 10;
              code += p[j] - '0';
            }
          ctx->status_code = (SshHttpStatusCode) code;

          /* Skip whitespace. */
          for (; j < i && isspace(p[j]); j++)
            ;

          /* The rest of the line is a human readable description. */
          for (l = i - 1; l > j && isspace(p[l]); l--)
            ;
          l++;
          ctx->status_reason_phrase = ssh_memdup(p + j, l - j);
          ctx->server_version_known = TRUE;

          SSH_DEBUG(5, ("HTTP/%ld.%ld %d %s",
                        ctx->version_major, ctx->version_minor,
                        ctx->status_code,
                        ctx->status_reason_phrase));

          ssh_buffer_consume(&ctx->in_buffer, i);
          req->r.state = SSH_HTTP_RESPONSE_READING_HEADER;
          break;

        case SSH_HTTP_RESPONSE_READING_HEADER:
          /* Fetch one line of input. */
          len = ssh_buffer_len(&ctx->in_buffer);
          p = ssh_buffer_ptr(&ctx->in_buffer);

          for (i = 0; i < len && p[i] != '\n'; i++)
            ;
          if (i >= len)
            {
              if (ctx->eof_seen)
                {
                  /* Malformed reply. */
                  SSH_DEBUG(5, ("Malformed reply.  EOF in header"));

                  if (req->r.callback)
                    (*req->r.callback)(ctx,
                                       SSH_HTTP_RESULT_MALFORMED_REPLY_HEADER,
                                       SSH_TCP_OK, NULL,
                                       req->r.callback_context);

                  /* We'r done with this request. */
                  ssh_http_finish_request(ctx);
                  return TRUE;
                }

              /* Read more data. */
              return FALSE;
            }

          /* Got one line. */
          i++;

          /* Skip all leading whitespace. */
          for (j = 0; j < i && isspace(p[j]); j++)
            ;
          if (j >= i)
            {
              /* An empty row.  Let's make this a Header-body separator. */

              /* We got a response from the server.  In any case, this
                 is a `100 Continue' or another response, this
                 completes our `100 Continue' expectation. */
              if (ctx->req->w.state == SSH_HTTP_REQUEST_EXPECTING_100_CONTINUE)
                {
                  ctx->req->w.state = SSH_HTTP_REQUEST_RECEIVED_100_CONTINUE;
                  ssh_http_stream_callback(SSH_STREAM_CAN_OUTPUT, ctx);
                }

              /* Skip the informational response status code. */
              switch (ctx->status_code)
                {
                case SSH_HTTP_STATUS_CONTINUE:
                case SSH_HTTP_STATUS_SWITCHING_PROTOCOLS:
                  /* Clear all header fields, read so far. */

                  ctx->server_version_known = FALSE;

                  ssh_http_kvhash_clear(ctx->values);
                  ctx->version_major = 0;
                  ctx->version_minor = 0;
                  ctx->status_code = 0;
                  ssh_free(ctx->status_reason_phrase);
                  ctx->status_reason_phrase = NULL;

                  ctx->content_length = -1;
                  ctx->connection_close = FALSE;

                  /* Consume the data from the input buffer. */
                  ssh_buffer_consume(&ctx->in_buffer, i);

                  /* Continue reading more responses. */
                  req->r.state = SSH_HTTP_RESPONSE_READING_STATUS_LINE;
                  continue;
                  break;

                default:
                  /* This is a normal success or error response.
                     Process it. */
                  break;
                }

              req->r.state = SSH_HTTP_RESPONSE_READING_BODY;


              /* Extract the header fields we are interested in. */

              ctx->r.user_content_length_known = FALSE;
              ctx->r.user_content_length = 0;
              ctx->r.user_content_data_read = 0;
              ctx->r.chunked_eof_reached = FALSE;

              value = ssh_http_kvhash_get(ctx->values,
                                          ssh_custr("CONTENT-LENGTH"));
              if (value)
                {
                  ctx->r.user_content_length_known = TRUE;
                  ctx->r.user_content_length = ssh_ustrtoul(value, NULL,
                                                       10);
                  ctx->r.user_content_data_read = 0;

                  if (ssh_http_kvhash_get(ctx->values,
                                          ssh_custr("TRANSFER-ENCODING")))
                    /* Both `Content-Length' and `Transfer-Encoding'
                       specified, let's ignore the length. */
                    ctx->content_length = -1;
                  else
                    ctx->content_length = ctx->r.user_content_length;
                }
              else
                {
                  ctx->content_length = -1;
                }

              value = ssh_http_kvhash_get(ctx->values,
                                          ssh_custr("CONNECTION"));
              if (value && ssh_usstrcasecmp(value, "close") == 0)
                {
                  ctx->connection_close = TRUE;
                  ssh_http_retry_request(ctx, FALSE);
                }
            }
          else
            {
              if (j > 0)
                {
                  /* Whitespace in the beginning of the field.  This
                     is a continuation line. */

                  /* Skip whitespace form the end of the value. */
                  for (l = i - 1; l > j && isspace(p[l]); l--)
                    ;
                  l++;

                  SSH_DEBUG(6, ("+ %.*s", (int) (l - j), p + j));

                  if (!ssh_http_kvhash_append_last(ctx->values, p + j, l - j))
                    SSH_DEBUG(5, ("Malformed header continuation line"));
                }
              else
                {
                  SshUInt32 start = j;

                  /* Normal `VAR: VALUE' field. */
                  for (; j < i && p[j] != ':'; j++)
                    ;
                  if (j >= i)
                    SSH_DEBUG(5, ("Malformed header line.  No ':' found"));
                  else
                    {
                      SshUInt32 end = j;

                      /* Skip whitespace from the beginning of the
                         value. */
                      for (j++; j < i && isspace(p[j]); j++)
                        ;

                      /* Skip whitespace form the end of the value. */
                      for (l = i - 1; l > j && isspace(p[l]); l--)
                        ;
                      l++;

                      SSH_DEBUG(6, ("%.*s: %.*s",
                                    (int) (end - start),
                                    p + start,
                                    (int) (l - j),
                                    p + j));

                      ssh_http_kvhash_put(ctx->values,
                                          p + start, end - start,
                                          p + j, l - j);
                    }
                }
            }

          ssh_buffer_consume(&ctx->in_buffer, i);

          /* Have we seen it all? */
          if (req->r.state == SSH_HTTP_RESPONSE_READING_BODY)
            ctx->r.content_data_read = ssh_buffer_len(&ctx->in_buffer);
          break;

        case SSH_HTTP_RESPONSE_READING_BODY:
          /* The end of the content data condition. */
          if (ctx->eof_seen || ctx->r.content_data_read == ctx->content_length
              || req->method == SSH_HTTP_HEAD
              || SSH_HTTP_NO_CONTENT_STATUS(ctx->status_code))
            {
              SSH_DEBUG(9, ("The end of the content data reached"));
              ctx->r.end_of_content_data = TRUE;
            }

          if (ctx->r.stream == NULL)
            {
              SshStream user_stream;

              /* Must create a stream that reads or discards the
                 content data. */
              user_stream = ssh_http_create_content_data_stream(ctx);
              if (user_stream == NULL)
                {
                  /* The reply was malformed.  Must retry with
                     HTTP/1.0. */

                  if (req->use_http_1_0)
                    {
                      /* We have already used HTTP/1.0.  This is a
                         server error. */
                      (*req->r.callback)(ctx, SSH_HTTP_RESULT_BROKEN_SERVER,
                                         SSH_TCP_OK, NULL,
                                         req->r.callback_context);

                      /* Finish this request. */
                      ssh_http_finish_request(ctx);
                      return TRUE;
                    }
                  else
                    {
                      SSH_DEBUG(5, ("Switching to HTTP/1.0 protocol"));
                      ctx->server_version_known = TRUE;
                      req->use_http_1_0 = TRUE;
                      ssh_http_retry_request(ctx, TRUE);
                      return TRUE;
                    }
                }

              ctx->r.stream_user = user_stream;

              if (SSH_HTTP_SUCCESS_STATUS(ctx->status_code) && req->r.callback)
                /* This was a successful HTTP operation.  Our client
                   is the user who initiated this HTTP operation. */
                (*req->r.callback)(ctx, SSH_HTTP_RESULT_SUCCESS,
                                   SSH_TCP_OK, user_stream,
                                   req->r.callback_context);
              else
                /* Create a byte-sink that will discard the content
                   data.  This helps us to keep in sync with the
                   server and we can keep the connection open for the
                   possible following requests. */
                ssh_http_create_byte_sink(user_stream);

              /* We must return from this event loop immediately after
                 creating the content data stream.  After the user
                 gets a stream notification, it is up to him to pump
                 the data. */
              return TRUE;
            }
          else
            {
              SshHttpContentStream *stream_ctx;

              /* Check whether the content data stream has blocked. */
              stream_ctx = ssh_stream_get_context(ctx->r.stream);
              if (stream_ctx->blocked)
                {
                  /* Notify the client that we have more data available. */
                  SSH_DEBUG(9, ("Waking up a blocked client"));
                  if (stream_ctx->callback)
                    (*stream_ctx->callback)(SSH_STREAM_INPUT_AVAILABLE,
                                            stream_ctx->callback_context);

                  /* Return after the notification. */
                  return TRUE;
                }
            }

          if (req->r.state == SSH_HTTP_RESPONSE_READ)
            /* End of data seen.  We must return from the read loop
               and wait until the client processes the content data. */
            return TRUE;

          /* Continue reading more data from the server. */
          return FALSE;
          break;

        case SSH_HTTP_RESPONSE_READ:
          /* Nothing here.  And I thing that this code shouldn't even
             be reached. */
          SSH_NOTREACHED;
          return TRUE;
          break;
        }
    }

  /* NOTREACHED */
  return FALSE;
}

/* A notification callback function that is set to the `Chunked
   Transfer Encoding' stream.  The callbacks marks the EOF condition
   to the client context and passes all trailer fields to the
   request's header fields.  It could also report some errors to the
   user, but those are currently ignored. */
static void
ssh_http_chunked_stream_callback(SshHttpChunkedStreamNotification notification,
                                 const unsigned char *key, size_t key_len,
                                 const unsigned char *value, size_t value_len,
                                 void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  switch (notification)
    {
    case SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD:
      ssh_http_kvhash_put(ctx->values, key, key_len, value, value_len);
      break;

    case SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD_CONT:
      ssh_http_kvhash_append_last(ctx->values, value, value_len);
      break;

    case SSH_HTTP_CHUNKED_STREAM_READ_EOF_REACHED:
      /* The data has been processed successfully. */
      ctx->req->r.state = SSH_HTTP_RESPONSE_READ;
      ctx->r.chunked_eof_reached = TRUE;
      break;

    default:
      /* Ignore. */
      break;
    }
}


static SshStream
ssh_http_create_content_data_stream(SshHttpClientContext ctx)
{
  SshStream user_stream;
  const unsigned char *value;
  SshUInt32 chunked_count = 0;

  user_stream = ctx->r.stream = ssh_http_content_read_stream_create(ctx);

  if (user_stream == NULL)
    return NULL;

  /* Check what transfer encodings are in use in this connection. */
  value = ssh_http_kvhash_get(ctx->values, ssh_custr("TRANSFER-ENCODING"));
  if (value)
    {
      const unsigned char *start, *end, *separator;

      /* The value can have multiple encodings.  We process them from
         the last to the first. */
      end = value + ssh_ustrlen(value);
      while (1)
        {
          unsigned char *cmpvalue;

          /* Find the start. */
          for (start = end - 1; start >= value && *start != ','; start--)
            ;
          start++;

          /* Mark the separator. */
          separator = start;

          /* Skip all leading whitespace. */
          for (; start < end && isspace((unsigned char) *start); start++)
            ;

          if ((cmpvalue = ssh_memdup(start, end - start)) == NULL)
            {
              ctx->r.stream = NULL;
              ssh_stream_destroy(user_stream);
              return NULL;
            }

          ctx->r.use_chunked_te = FALSE;
          if (ssh_usstrcasecmp(cmpvalue, "chunked") == 0)
            {
              /* Chunked Transfer Coding. */
              if (++chunked_count > 1)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Chunked Transfer Coding "
                             "applied more than once"));

                  ssh_free(cmpvalue);
                  ctx->r.stream = NULL;
                  ssh_stream_destroy(user_stream);

                  return NULL;
                }

              SSH_DEBUG(6, ("Chunked Transfer Coding"));
              if ((user_stream =
                   ssh_http_chunked_stream_create(user_stream, TRUE, FALSE,
                                           ssh_http_chunked_stream_callback,
                                                  ctx)) == NULL)
                {
                  ssh_free(cmpvalue);
                  ctx->r.stream = NULL;
                  return NULL;
                }
              ctx->r.use_chunked_te = TRUE;
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Unknown transfer encoding `%s'", cmpvalue));

              /* Ok, we must stop here.  Now, either the client
                 requested this encoding with the SSH_HTTP_HDR_TE
                 flag, or the server did send a malformed reply.
                 TODO: we should check which case is this.  Currently
                 we don't check it - we just leave the correct
                 Transfer-Encoding to the header fields and let the
                 user to decide what to do. */

              ssh_free(cmpvalue);

              if ((cmpvalue = ssh_memdup(value, end - value)) == NULL)
                {
                  ctx->r.stream = NULL;
                  ssh_stream_destroy(user_stream);

                  return NULL;
                }
              ssh_http_kvhash_remove(ctx->values,
                                     ssh_custr("TRANSFER-ENCODING"));
              ssh_http_kvhash_put_cstrs(ctx->values,
                                        ssh_custr("TRANSFER-ENCODING"),
                                        cmpvalue);
              ssh_free(cmpvalue);

              return user_stream;
            }

          ssh_free(cmpvalue);

          /* Do we have more values? */
          if (separator <= value)
            /* No we don't. */
            break;

          end = separator - 1;
        }

      /* Ok, we managed to remove all transfer encodings from the
         data.  Remove the `transfer-encoding' key from the header
         fields. */
      ssh_http_kvhash_remove(ctx->values, ssh_custr("TRANSFER-ENCODING"));
    }

  return user_stream;
}


static void
ssh_http_byte_sink_callback(SshStreamNotification notification,
                            void *context)
{
  SshStream stream = (SshStream) context;
  int l;
  unsigned char buf[1024];

  while (1)
    {
      l = ssh_stream_read(stream, buf, sizeof(buf));
      if (l == 0)
        {
          /* EOF. */
          ssh_stream_destroy(stream);
          return;
        }
      if (l < 0)
        /* Would block. */
        return;

      /* Read more. */
    }
}


static void
ssh_http_create_byte_sink(SshStream stream)
{
  ssh_stream_set_callback(stream, ssh_http_byte_sink_callback, stream);
  ssh_http_byte_sink_callback(SSH_STREAM_INPUT_AVAILABLE, stream);
}


static Boolean
ssh_http_authentication(SshHttpClientContext ctx)
{
  SshHttpRequest *req = ctx->req;
  unsigned char *value, *base64;
  unsigned char *u, *p;

  /* We should check the `WWW-Authenticate' tag, method, etc.  But
     currently we only support the basic authentication.  That's
     it. */

  if (req->authorization)
    {
      /* We already tried it but it didn't work. */
    authorization_failed:
      if (req->r.callback)
        (*req->r.callback)(ctx, SSH_HTTP_RESULT_AUTHORIZATION_FAILED,
                           SSH_TCP_OK, NULL, req->r.callback_context);
      return FALSE;
    }

  /* Ok, create the authorization.  */

  u = req->user_name ? req->user_name : (unsigned char *)"";
  p = req->password ? req->password : (unsigned char *)"";

  if ((value = ssh_malloc(ssh_ustrlen(u) + 1 + ssh_ustrlen(p) + 1)) == NULL)
    goto authorization_failed;

  ssh_ustrcpy(value, u);
  ssh_ustrcat(value, (unsigned char *)":");
  ssh_ustrcat(value, p);

  if ((base64 = ssh_buf_to_base64(value, ssh_ustrlen(value)))
      == NULL)
    {
      ssh_free(value);
      goto authorization_failed;
    }
  ssh_free(value);

  if ((value = ssh_malloc(strlen("Basic ") + ssh_ustrlen(base64) + 1)) == NULL)
    {
      ssh_free(base64);
      goto authorization_failed;
    }

  ssh_ustrcpy(value, (unsigned char *)"Basic ");
  ssh_ustrcat(value, base64);
  ssh_free(base64);

  req->authorization = value;

  return TRUE;
}


static Boolean
ssh_http_proxy_authentication(SshHttpClientContext ctx)
{
  SshHttpRequest *req = ctx->req;
  unsigned char *value, *base64;
  unsigned char *u, *p;

  /* We should check the `Proxy-Authenticate' tag, method, etc.  But
     currently we only support the basic authentication.  That's
     it. */

  if (req->proxy_authorization)
    {
      /* We already tried it but it didn't work. */
    proxy_authentication_failed:
      if (req->r.callback)
        (*req->r.callback)(ctx, SSH_HTTP_RESULT_PROXY_AUTHORIZATION_FAILED,
                           SSH_TCP_OK, NULL, req->r.callback_context);
      return FALSE;
    }

  /* Ok, create the authorization.  */

  u = req->proxy_user_name ? req->proxy_user_name : (unsigned char *)"";
  p = req->proxy_password ? req->proxy_password : (unsigned char *)"";

  if ((value = ssh_malloc(ssh_ustrlen(u) + 1 + ssh_ustrlen(p) + 1)) == NULL)
    goto proxy_authentication_failed;

  ssh_ustrcpy(value, u);
  ssh_ustrcat(value, (unsigned char *)":");
  ssh_ustrcat(value, p);

  if ((base64 = ssh_buf_to_base64(value, ssh_ustrlen(value)))
      == NULL)
    {
      ssh_free(value);
      goto proxy_authentication_failed;
    }
  ssh_free(value);

  if ((value = ssh_malloc(strlen("Basic ") + ssh_ustrlen(base64) + 1))
      == NULL)
    {
      ssh_free(base64);
      goto proxy_authentication_failed;
    }

  ssh_ustrcpy(value, (unsigned char *)"Basic ");
  ssh_ustrcat(value, base64);
  ssh_free(base64);

  req->proxy_authorization = value;

  return TRUE;
}


/*
 * Content data write stream.
 */

static int
ssh_http_content_write_stream_read(void *context, unsigned char *buf,
                                  size_t size)
{
  /* The stream is write-only. */
  return 0;
}


static int
ssh_http_content_write_stream_write(void *context, const unsigned char *buf,
                                    size_t size)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  return ssh_stream_write(ctx->http_stream, buf, size);
}


static void
ssh_http_content_write_stream_output_eof(void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  if (ctx->req->w.eof_output)
    return;

  ctx->req->w.eof_output = TRUE;

  if (ctx->req->w.close && ctx->http_stream)
    /* Output the EOF to our http stream. */
    ssh_stream_output_eof(ctx->http_stream);
}


static void
ssh_http_content_write_stream_set_callback(void *context,
                                           SshStreamCallback callback,
                                           void *callback_context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  ctx->w.callback = callback;
  ctx->w.callback_context = callback_context;
}


static void
ssh_http_content_write_stream_destroy(void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;

  ssh_http_content_write_stream_output_eof(ctx);

  ctx->req->w.state = SSH_HTTP_REQUEST_WRITTEN;

  /* Finish the associated request only if this stream is connected to
     the client context.  Otherwise, the client context is currently
     being destroyed and we must only destroy ourselves. */
  if (ctx->w.stream)
    {
      ctx->w.stream = NULL;

      /* Are we the last reference to this request? */
      if (ctx->req->r.state == SSH_HTTP_RESPONSE_READ)
        /* Yes we are. */
        ssh_http_finish_request(ctx);
    }
}


static const SshStreamMethodsStruct
ssh_http_content_write_stream_methods_table =
{
  ssh_http_content_write_stream_read,
  ssh_http_content_write_stream_write,
  ssh_http_content_write_stream_output_eof,
  ssh_http_content_write_stream_set_callback,
  ssh_http_content_write_stream_destroy,
};


static SshStream
ssh_http_content_write_stream_create(SshHttpClientContext ctx)
{
  return ssh_stream_create(&ssh_http_content_write_stream_methods_table, ctx);
}




/*
 * Content data read stream.
 */

static void
ssh_http_ask_more_input_timeout(void *context)
{
  SshHttpClientContext ctx = (SshHttpClientContext) context;
  ssh_http_stream_callback(SSH_STREAM_INPUT_AVAILABLE, ctx);
}


static int
ssh_http_content_read_stream_read(void *context, unsigned char *buf,
                                  size_t size)
{
  SshHttpContentStream *stream = (SshHttpContentStream *) context;
  size_t avail;

  avail = ssh_buffer_len(&stream->ctx->in_buffer);
  if (avail == 0)
    {
      if (stream->ctx->r.end_of_content_data)
        {
          /* EOF */
          SSH_DEBUG(9, ("EOF"));

          /* Mark the current request completed. */
          stream->ctx->req->r.state = SSH_HTTP_RESPONSE_READ;
          return 0;
        }

      /* We would block.  Let's register a timeout that will be called
         from the bottom of the event loop.  The timeout will signal
         the HTTP stream callback so that it will try to read more
         data from the server. */
      SSH_DEBUG(9, ("Asking more input from the server"));
      stream->blocked = TRUE;
      ssh_xregister_timeout(0, 0, ssh_http_ask_more_input_timeout,
                           stream->ctx);

      /* And let's wait for that notification. */
      return -1;
    }

  /* Have some data in the buffer. */
  if (avail > size)
    avail = size;

  memcpy(buf, ssh_buffer_ptr(&stream->ctx->in_buffer), avail);
  ssh_buffer_consume(&stream->ctx->in_buffer, avail);

  SSH_DEBUG(9, ("Passing %u bytes to reader", avail));
  stream->ctx->r.user_content_data_read += avail;

  return avail;
}


static int
ssh_http_content_read_stream_write(void *context, const unsigned char *buf,
                                   size_t size)
{
  /* The stream is read-only. */
  return 0;
}


static void
ssh_http_content_read_stream_output_eof(void *context)
{
  /* The stream is read-only. */
}


static void
ssh_http_content_read_stream_set_callback(void *context,
                                          SshStreamCallback callback,
                                          void *callback_context)
{
  SshHttpContentStream *stream = (SshHttpContentStream *) context;

  stream->callback = callback;
  stream->callback_context = callback_context;
}


static void
ssh_http_content_read_stream_destroy(void *context)
{
  SshHttpContentStream *stream = (SshHttpContentStream *) context;
  SshHttpClientContext ctx = stream->ctx;

  /* Cancel timeouts. */
  ssh_cancel_timeouts(ssh_http_ask_more_input_timeout, ctx);

  /* Free the stream structure. */
  ssh_free(stream);

  /* Finish the associated request only if this stream is bind to the
     client context.  Otherwise, we are just a floating stream and
     we'r done.  This is the case when the creation of the content
     data stream pipeline failed. */
  if (ctx->r.stream)
    {
      ctx->r.stream = NULL;
      ctx->r.stream_user = NULL;

      /* Are we the last reference to this request? */
      if (ctx->req->w.state == SSH_HTTP_REQUEST_WRITTEN)
        /* Yes we are.  Finish this request. */
        ssh_http_finish_request(ctx);
    }
}


static const SshStreamMethodsStruct
ssh_http_content_read_stream_methods_table =
{
  ssh_http_content_read_stream_read,
  ssh_http_content_read_stream_write,
  ssh_http_content_read_stream_output_eof,
  ssh_http_content_read_stream_set_callback,
  ssh_http_content_read_stream_destroy,
};


static SshStream
ssh_http_content_read_stream_create(SshHttpClientContext ctx)
{
  SshHttpContentStream *stream_ctx;

  if ((stream_ctx = ssh_calloc(1, sizeof(*stream_ctx))) == NULL)
    return NULL;

  stream_ctx->ctx = ctx;
  return ssh_stream_create(&ssh_http_content_read_stream_methods_table,
                           stream_ctx);
}

void *
ssh_http_get_appdata(SshHttpClientContext ctx)
{
  return ctx ? ctx->appdata : NULL;
}

void *
ssh_http_set_appdata(SshHttpClientContext ctx, void *appdata)
{
  void *ret = ctx ? ctx->appdata : NULL;

  if (ctx != NULL)
    ctx->appdata = appdata;

  return ret;
}
#endif /* SSHDIST_HTTP_CLIENT */
