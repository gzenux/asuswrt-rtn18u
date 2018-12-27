/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   HTTP/1.1 server functionality.
*/

#include "sshincludes.h"
#include "sshhttp.h"
#include "sshhttpi.h"
#include "sshbuffer.h"
#include "sshstream.h"
#include "sshtimeouts.h"
#include "sshmatch.h"
#include "sshbase64.h"
#include "sshurl.h"
#include "sshnameserver.h"

#ifdef SSHDIST_HTTP_SERVER

/*
 * Types and definitions.
 */

#define SSH_DEBUG_MODULE "SshHttpServer"

#define SSH_HTTP_BUFFER_SIZE    8192

/* The end of the content data condition. */
#define SSH_HTTP_SERVER_CHECK_EOCD(conn)                                \
  do {                                                                  \
    if ((conn)->r.eof_seen                                              \
        || (conn)->r.content_data_read >= (conn)->r.content_length)     \
      (conn)->r.end_of_content_data = TRUE;                             \
  } while (0)

#define SET_VALUES_NEED_COOKIE(name)                                    \
  do {                                                                  \
    if (conn->set_cookies == NULL)                                      \
      ssh_fatal("ssh_http_server_set_values: %s called without "        \
                "SSH_HTTP_HDR_COOKIE", (name));                         \
    cookie = &conn->set_cookies[conn->num_set_cookies - 1];             \
  } while (0)

/* The states in which a connection can be.  */
typedef enum
{
  /* Waiting for a new request and reading its first line. */
  SSH_HTTP_CONN_READING_REQUEST,

  /* Reading the request header. */
  SSH_HTTP_CONN_READING_HEADER,

  /* Reading the request body and writing the reply. */
  SSH_HTTP_CONN_USER_IO
} SshHttpServerConnectionState;

/* A connection. */
struct SshHttpServerConnectionRec
{
  /* The connection are stored in a two-way linked list.  This eases
     removing them from the list. */
  struct SshHttpServerConnectionRec *prev;
  struct SshHttpServerConnectionRec *next;

  /* The server context to which this connection is connected to. */
  SshHttpServerContext ctx;

  /* The state of the connection. */
  SshHttpServerConnectionState state;

  /* Has the `read request timeout' been scheduled for this request? */
  Boolean read_request_timeout_scheduled;

  /* The request method. */
  unsigned char *method;

  /* Is the request a `HEAD' request? */
  Boolean is_head;

  /* The requested URI. */
  unsigned char *uri;

  /* Decoded path portion of the <uri>.  This is needed in matching
     the URI handlers. */
  unsigned char *uri_path;

  /* Request major version number. */
  SshUInt32 major;

  /* Request minor version number. */
  SshUInt32 minor;

  /* Request header fields. */
  SshHttpKvHash req_header_fields;

  /* Encountered header field line count in the request including
     fields continuing on the next line */
  SshUInt32 req_header_field_count;

  /* The parsed cookies from the request. */
  SshHttpCookie *cookies;
  unsigned int num_cookies;

  /* Was the `Connection: Keep-Alive' specified in the request? */
  Boolean req_keep_alive;

  /* The HTTP connection to the client. */
  SshStream stream;

  /* The remote end's address and port. */
  unsigned char *address;
  unsigned char *port;

  /* The local end's address */
  unsigned char *local_address;

  /* A buffer to hold the data from the client. */
  SshBufferStruct in_buffer;

  /* A buffer to hold our output to the client. */
  SshBufferStruct out_buffer;


  /* The reply header values. */

  /* Should the connection be closed after the reply has been written?
     The flag turns also on the `Connection: close' reply header. */
  Boolean close;

  /* The status code. */
  SshHttpStatusCode status;

  /* Reply header fields. */
  SshHttpKvHash reply_header_fields;

  /* Cookies to set for the client. */
  SshHttpSetCookie *set_cookies;
  unsigned int num_set_cookies;

  /* If the user reported an error from the URI handler, this is the
     error message he wanted to show to our client.  The user has also
     set the <status> to appropriate error code and the
     <reply_header_fields> contain the appropriate header fields. */
  SshBuffer error_message;

  /* The user's end point of the UI stream.  This is needed to
     implement the ssh_http_server_flush() function. */
  SshStream ui_stream;

  /* The read state of the user interface stream of this connection. */
  struct
  {
    /* Is the EOF seen in the input stream? */
    Boolean eof_seen;

    /* The value of the Content-Length header fields or -1 if not
       present. */
    SshUInt32 content_length;

    /* The number of bytes of content data read so far. */
    SshUInt32 content_data_read;

    /* Is the end of the content data seen in the request?  This is
       the smart end-of-the-content-data condition that is determined
       according to the EOF?, Content-Length and Transfer-Encoding
       fields.*/
    Boolean end_of_content_data;

    /* Is the read blocked? */
    Boolean blocked;

    /* The stream callback function for the read-only content data stream. */
    SshStreamCallback callback;
    void *callback_context;
  } r;

  /* The write state of the user interface stream of this connection. */
  struct
  {
    /* Is the reply header send to our client? */
    Boolean header_sent;

    /* Is the user's content length known? */
    Boolean content_length_known;

    /* If the content length is known, it is this. */
    size_t content_length;

    /* Is the `Chunked Transfer Encoding' in use in the out stream.
       This is exclusive with the <content_length_known> and
       <content_length>. */
    Boolean chunked_transfer_encoding;

    /* Is the EOF seen in the user's output?  If TRUE, the response is
       written when the <buffer> gets empty. */
    Boolean eof_seen;

    /* Is the write stream destroyed? */
    Boolean destroyed;

    /* The stream callback function for the write-only content data stream. */
    SshStreamCallback callback;
    void *callback_context;
  } w;

  /* Application specific data. */
  void *appdata;
};

/* An URI handler registry. */
typedef struct SshHttpServerUriHandlerRegistryRec
{
  struct SshHttpServerUriHandlerRegistryRec *next;
  unsigned char *pattern;
  int priority;
  SshHttpServerUriHandler handler;
  void *handler_context;
} SshHttpServerUriHandlerRegistry;


/* A server context. */
struct SshHttpServerContextRec
{
  /* User definable parameters. */

  SshUInt32 num_connections_soft_limit;
  SshUInt32 num_connections_hard_limit;
  SshUInt32 read_request_timeout;
  SshUInt32 write_response_timeout;
  SshUInt32 keep_open_timeout;
  SshUInt32 max_req_header_field_count;

  unsigned char *address;
  unsigned char *port;
  unsigned char *server_name;

  /* The HTTP listener. */
  SshTcpListener listener;

  /* The message formatter. */
  SshHttpServerMessageFormatter formatter;
  void *formatter_context;

  /* The TCP/IP stream wrapper. */
  SshHttpServerTcpStreamWrapper tcp_wrapper;
  void *tcp_wrapper_context;

  /* The number of connections in this server. */
  SshUInt32 num_connections;

  /* List that contains all active connections in this server. */
  SshHttpServerConnection connections;

  /* Registered URI handlers. */
  SshHttpServerUriHandlerRegistry *handlers;

  /* User callback to notify the application that the server has
     stopped. */
  SshHttpServerStoppedCb server_stopped_callback;
  void *server_stopped_context;
};

/* Context for the ssh_server_send_buffer() function. */
struct SshServerSendBufferCtxRec
{
  SshStream stream;
  SshBuffer buffer;
};

typedef struct SshServerSendBufferCtxRec SshServerSendBufferCtx;


/*
 * Prototypes for static functions.
 */

/* Destroy the HTTP server <ctx>. */
static void ssh_http_server_destroy(SshHttpServerContext ctx);

/* A callback function for the HTTP listener.  This is called for each
   incoming connection. */
static void ssh_http_server_listener_callback(SshTcpError error,
                                              SshStream stream, void *context);

/* Add a new connection the the server's pool of active
   connections.  The resource limits have already been checked. */
static SshHttpServerConnection ssh_http_server_new_connection(
                                        SshHttpServerContext ctx,
                                        SshStream stream,
                                        unsigned char *local_address,
                                        unsigned char *remote_address,
                                        unsigned char *remote_port);

/* Finish connection <conn> and determine whether it should be kept
   open or removed from the server. */
static void ssh_http_server_finish_connection(SshHttpServerConnection conn);

/* A timeout function to read more input from the HTTP stream. */
static void ssh_http_server_read_more_input_timeout(void *context);

/* Remove connection <conn> from the server's pool of active
   connections. */
static void ssh_http_server_remove_connection(SshHttpServerConnection conn);

/* Free the `Set-Cookie' and `Cookie' structures from the connetion
   <conn>. */
static void ssh_http_server_free_cookies(SshHttpServerConnection conn);

/* Connection stream notification callback.  This is bind to each
   connection stream in the server. */
static void ssh_http_server_connection_callback(
                                        SshStreamNotification notification,
                                        void *context);

/* Check whether the buffer <p>, <len> has at least one line of input.
   Returns TRUE if there is a line or FALSE otherwise.  Upon
   successful completion, the end of the line is returned in
   <end_return> */
static Boolean ssh_http_server_has_one_line(unsigned char *p, size_t len,
                                            size_t *end_return);

/* Create a handler for the parsed request from the connection
   <conn>. */
static void ssh_http_server_create_handler(SshHttpServerConnection conn);

/* Create a read-write UI stream around a connection <conn>.  The
   argument <input_is_chunked> specifies whether the input stream is
   chunked transfer coded. */
static SshStream ssh_http_server_create_ui_stream(
                                        SshHttpServerConnection conn,
                                        Boolean input_is_chunked);

/* The default URI handler if no user handler matched the request. */
static Boolean ssh_http_server_default_uri_handler(
                                        SshHttpServerContext ctx,
                                        SshHttpServerConnection conn,
                                        SshStream stream,
                                        void *context);

/* A timeout function to close a connection if a new request couldn't
   be read from it within the timeout time. */
static void ssh_http_server_read_req_timeout(void  *context);

/* A timeout function to close a connection if the response couldn't
   be written to the client within the timeout time. */
static void ssh_http_server_write_response_timeout(void  *context);

/* A timeout function to close a `Keep-Alive' connection if a new
   request is not seen in the specified time limit. */
static void ssh_http_server_keep_open_timeout(void *context);


/*
 * The reply handling, server errors, etc.
 */

/* The stream callback function for the ssh_http_server_send_buffer()
   function. */
static void ssh_http_server_send_buffer_stream_cb(
                                        SshStreamNotification notification,
                                        void *context);

/* The default message formatter that creates English reports. */
static void ssh_http_server_default_msg_formatter(SshHttpServerConnection conn,
                                                  SshBuffer buffer,
                                                  SshUInt32 code,
                                                  va_list ap,
                                                  void *context);

/* Format the reply header for the connection. */
static void ssh_http_server_format_reply(SshHttpServerConnection conn);

/* Terminate current connection and report the internal error that has
   already been prepared to the connection <conn> with the
   ssh_http_server_error() function.  This effectively terminates the
   current connection. */
static void ssh_http_server_internal_error(SshHttpServerConnection conn);

/* Enter the header fields and properties from <ap> to the connection
   <conn>. */
static void ssh_http_server_set_values_ap(SshHttpServerConnection conn,
                                          va_list ap);


/*
 * Streams.
 */

/* The read-only `Content Data Read' stream. */
static SshStream
ssh_http_server_content_read_stream(SshHttpServerConnection conn);

/* The write-only `Content Data Write' stream. */
static SshStream
ssh_http_server_content_write_stream(SshHttpServerConnection conn);

/* The read-write `User Interface' stream. */

struct SshHttpServerUiStreamRec
{
  /* The connection to which we are bind to. */
  SshHttpServerConnection conn;

  /* The read and write streams. */
  SshStream read_s;
  SshStream write_s;

  /* Any writes to this stream?  This is a 404 generation kludge. */
  Boolean written;

  /* Is the read stream at EOF? */
  Boolean read_s_at_eof;

  /* The user callback of this stream. */
  SshStreamCallback callback;
  void *callback_context;
};

typedef struct SshHttpServerUiStreamRec SshHttpServerUiStream;

static SshStream ssh_http_server_ui_stream(SshHttpServerConnection conn,
                                           SshStream read_s,
                                           SshStream write_s);


/*
 * Static variables.
 */

/* These response header fields can't be set with the
   ssh_http_server_set_values_ap() function. */
static const SshCharPtr ssh_http_server_hdr_skip_list[] =
{
  "CONNECTION",
  "CONTENT-LENGTH",
  "TRANSFER-ENCODING",
  NULL
};

/*
 * Global functions.
 */

SshHttpServerContext
ssh_http_server_start(SshHttpServerParams *params)
{
  SshHttpServerContext ctx;

  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    return NULL;

  /* Set the defaults. */

  ctx->num_connections_soft_limit = 30;
  ctx->num_connections_hard_limit = 50;
  ctx->read_request_timeout = 30;
  ctx->write_response_timeout = 30;
  ctx->keep_open_timeout = 30;
  ctx->max_req_header_field_count = 500;

  ctx->address = ssh_strdup(SSH_IPADDR_ANY);
  ctx->port = ssh_strdup("80");
  ctx->server_name = ssh_malloc(1024);

  if (ctx->address == NULL || ctx->port == NULL || ctx->server_name == NULL)
    goto failed;

  ssh_tcp_get_host_name(ctx->server_name, 1024);

  ctx->formatter = ssh_http_server_default_msg_formatter;
  ctx->formatter_context = NULL;

  if (params)
    {
      if (params->num_connections_soft_limit)
        ctx->num_connections_soft_limit = params->num_connections_soft_limit;
      if (params->num_connections_hard_limit)
        ctx->num_connections_hard_limit = params->num_connections_hard_limit;
      if (params->read_request_timeout)
        ctx->read_request_timeout = params->read_request_timeout;
      if (params->write_response_timeout)
        ctx->write_response_timeout = params->write_response_timeout;
      if (params->keep_open_timeout)
        ctx->keep_open_timeout = params->keep_open_timeout;
      if (params->max_req_header_field_count)
        ctx->max_req_header_field_count = params->max_req_header_field_count;

      if (params->address)
        {
          ssh_free(ctx->address);
          if ((ctx->address = ssh_strdup(params->address)) == NULL)
            goto failed;
        }
      if (params->port)
        {
          ssh_free(ctx->port);
          if ((ctx->port = ssh_strdup(params->port)) == NULL)
            goto failed;
        }

      ctx->tcp_wrapper = params->tcp_wrapper;
      ctx->tcp_wrapper_context = params->tcp_wrapper_context;

      if (params->message_formatter)
        {
          ctx->formatter = params->message_formatter;
          ctx->formatter_context = params->message_formatter_context;
        }

      if (params->server_name)
        {
          ssh_free(ctx->server_name);
          if ((ctx->server_name = ssh_strdup(params->server_name)) == NULL)
            goto failed;
        }
    }

  /* Create the server port. */
  ctx->listener = ssh_tcp_make_listener(ctx->address, ctx->port,
                                        -1,
                                        0,
                                        NULL,
                                        ssh_http_server_listener_callback,
                                        ctx);
  if (ctx->listener == NULL)
    {
    failed:
      ssh_http_server_destroy(ctx);
      return NULL;
    }

  SSH_DEBUG(5, ("Running on port %s", ctx->port));

  return ctx;
}


void
ssh_http_server_stop(SshHttpServerContext ctx,
                     SshHttpServerStoppedCb callback,
                     void *callback_context)
{
  if (ctx->listener)
    {
      ssh_tcp_destroy_listener(ctx->listener);
      ctx->listener = NULL;
    }

  if (ctx->num_connections == 0)
    {
      if (callback)
        (*callback)(ctx, callback_context);
      ssh_http_server_destroy(ctx);
    }
  else
    {
      /* Wait until the connections have been processed. */
      ctx->server_stopped_callback = callback;
      ctx->server_stopped_context  = callback_context;
    }
}

Boolean
ssh_http_server_set_handler(SshHttpServerContext ctx,
                            const unsigned char *uri_pattern,
                            int priority, SshHttpServerUriHandler handler,
                            void *handler_context)
{
  SshHttpServerUriHandlerRegistry *reg;
  SshHttpServerUriHandlerRegistry *r, *prev;

  if ((reg = ssh_calloc(1, sizeof(*reg))) == NULL)
    {
    failed:
      ssh_free(reg);
      return FALSE;
    }

  if ((reg->pattern = ssh_strdup(uri_pattern)) == NULL)
    goto failed;

  reg->priority = priority;
  reg->handler = handler;
  reg->handler_context = handler_context;

  /* Find the correct position in the handler list. */
  if (priority < 0)
    {
      /* To the beginning of the priority list. */
      priority = -priority;

      for (prev = NULL, r = ctx->handlers; r && r->priority > reg->priority;
           prev = r, r = r->next)
        ;
    }
  else
    {
      /* To the end of the priority list. */
      for (prev = NULL, r = ctx->handlers; r && r->priority >= reg->priority;
           prev = r, r = r->next)
        ;
    }

  /* Add the new handler. */
  if (prev)
    {
      reg->next = prev->next;
      prev->next = reg;
    }
  else
    {
      reg->next = ctx->handlers;
      ctx->handlers = reg;
    }

  return TRUE;
}


typedef struct WrappedHandlerRec {
  void *context;
  SshHttpServerVoidUriHandler handler;
} *WrappedHandler;

static Boolean generic_uri_handler(SshHttpServerContext server_context,
                                   SshHttpServerConnection conn,
                                   SshStream stream, void *context)
{
  WrappedHandler h = context;
  h->handler(server_context, conn, stream, h->context);
  return TRUE;
}

Boolean
ssh_http_server_set_void_handler(SshHttpServerContext ctx,
                                 const unsigned char *uri_pattern,
                                 int priority,
                                 SshHttpServerVoidUriHandler handler,
                                 void *context)
{
  WrappedHandler h = ssh_malloc(sizeof(*h));

  if (h)
    {
      h->context = context;
      h->handler = handler;

      if (ssh_http_server_set_handler(ctx, uri_pattern, priority,
                                      generic_uri_handler, h) == FALSE)
        {
          ssh_free(h);
          return FALSE;
        }

      return TRUE;
    }
  return FALSE;
}

void
ssh_http_server_remove_handlers(SshHttpServerContext ctx,
                                const unsigned char *uri_pattern,
                                SshHttpServerUriHandler handler,
                                void *context)
{
  SshHttpServerUriHandlerRegistry *reg, *prev;

  SSH_ASSERT(uri_pattern != NULL);
  SSH_ASSERT(handler != NULL_FNPTR);

 restart:

  for (prev = NULL, reg = ctx->handlers; reg; prev = reg, reg = reg->next)
    {
      if ((uri_pattern == SSH_HTTP_ALL_PATTERNS
           || ssh_ustrcmp(uri_pattern, reg->pattern) == 0)
          && (handler == reg->handler || handler == SSH_HTTP_ALL_HANDLERS)
          && (context == reg->handler_context
              || context == SSH_HTTP_ALL_CONTEXTS))
        {
          /* Found a match. */
          if (prev)
            prev->next = reg->next;
          else
            ctx->handlers = reg->next;

          /* Free this handler. */
          ssh_free(reg->pattern);
          ssh_free(reg);

          /* Restart from the beginning. */
          goto restart;
        }
    }
}

void
ssh_http_server_remove_void_handlers(SshHttpServerContext ctx,
                                     const unsigned char *uri_pattern,
                                     SshHttpServerVoidUriHandler handler,
                                     void *context)
{
  SshHttpServerUriHandlerRegistry *reg, *prev;
  WrappedHandler wh;

  SSH_ASSERT(uri_pattern != NULL);
  SSH_ASSERT(handler != NULL_FNPTR);

 restart:

  for (prev = NULL, reg = ctx->handlers; reg; prev = reg, reg = reg->next)
    {
      wh = reg->handler_context;
      if ((uri_pattern == SSH_HTTP_ALL_PATTERNS
           || ssh_ustrcmp(uri_pattern, reg->pattern) == 0)
          && (generic_uri_handler == reg->handler)
          && (handler == wh->handler
              || handler == SSH_HTTP_ALL_VOID_HANDLERS)
          && (context == wh->context
              || context == SSH_HTTP_ALL_CONTEXTS))
        {
          /* Found a match. */
          if (prev)
            prev->next = reg->next;
          else
            ctx->handlers = reg->next;

          /* Free this handler. */
          ssh_free(reg->pattern);
          ssh_free(reg);
          ssh_free(wh);

          /* Restart from the beginning. */
          goto restart;
        }
    }
}

const unsigned char *
ssh_http_server_get_local_address(SshHttpServerConnection conn)
{
  return conn->local_address;
}


const unsigned char *
ssh_http_server_get_address(SshHttpServerConnection conn)
{
  return conn->address;
}


const unsigned char *
ssh_http_server_get_port(SshHttpServerConnection conn)
{
  return conn->port;
}

const unsigned char *
ssh_http_server_get_method(SshHttpServerConnection conn)
{
  return conn->method;
}


const unsigned char *
ssh_http_server_get_uri(SshHttpServerConnection conn)
{
  return conn->uri;
}


void
ssh_http_server_get_protocol_version(SshHttpServerConnection conn,
                                     SshUInt32 *major_return,
                                     SshUInt32 *minor_return)
{
  *major_return = conn->major;
  *minor_return = conn->minor;
}


const unsigned char *
ssh_http_server_get_header_field(SshHttpServerConnection conn,
                                 const unsigned char *field)
{
  unsigned char *nfield = ssh_strdup(field);
  int i;
  const unsigned char *value;

  if (nfield == NULL)
    return NULL;

  /* Convert the field to uppercase. */
  for (i = 0; nfield[i]; i++)
    if (islower(nfield[i]))
      nfield[i] = toupper(nfield[i]);

  value = ssh_http_kvhash_get(conn->req_header_fields, nfield);
  ssh_free(nfield);

  return value;
}


static SshHttpAuthentication
ssh_http_server_parse_authentication(const unsigned char *value,
                                     unsigned char **name_return,
                                     unsigned char **password_return)
{
  unsigned char *cp;
  int i;

  /* Check the authentication method. */

  for (i = 0; value[i] && !isspace(value[i]); i++)
    ;

  if ((cp = ssh_memdup(value, i)) == NULL)
    return SSH_HTTP_AUTHENTICATION_NONE;

  if (strcasecmp((char *) cp, "Basic") == 0)
    {
      size_t value_len;
      unsigned char *cleaned;
      unsigned char *decoded;

      /* Basic authentication. */
      ssh_free(cp);

      if ((cleaned = ssh_base64_remove_whitespace(value + i, 0)) == NULL)
        return SSH_HTTP_AUTHENTICATION_NONE;

      if ((decoded = ssh_base64_to_buf(cleaned, &value_len)) == NULL)
        {
          ssh_free(cleaned);
          return SSH_HTTP_AUTHENTICATION_NONE;
        }
      ssh_free(cleaned);

      /* Check that the decoded strings seems valid.  It should be
         `userid:password'. */
      cp = (unsigned char *) strchr((char *) decoded, ':');
      if (cp == NULL)
        {
          ssh_free(decoded);
          return SSH_HTTP_AUTHENTICATION_NONE;
        }

      *name_return = ssh_memdup(decoded, cp - decoded);
      cp++;
      *password_return = ssh_memdup(cp, value_len - (cp - decoded));

      ssh_free(decoded);
      if (*name_return == NULL || *password_return == NULL)
        return SSH_HTTP_AUTHENTICATION_NONE;

      return SSH_HTTP_AUTHENTICATION_BASIC;
    }

  /* An unknown method. */
  ssh_free(cp);
  return SSH_HTTP_AUTHENTICATION_NONE;
}


SshHttpAuthentication
ssh_http_server_get_authentication(SshHttpServerConnection conn,
                                   unsigned char **name_return,
                                   unsigned char **password_return)
{
  const unsigned char *value;

  value = ssh_http_kvhash_get(conn->req_header_fields,
                              ssh_custr("AUTHORIZATION"));
  if (value == NULL)
    return SSH_HTTP_AUTHENTICATION_NONE;

  return ssh_http_server_parse_authentication(value, name_return,
                                              password_return);
}


SshHttpAuthentication
ssh_http_server_get_proxy_authentication(SshHttpServerConnection conn,
                                         unsigned char **name_return,
                                         unsigned char **password_return)
{
  const unsigned char *value;

  value = ssh_http_kvhash_get(conn->req_header_fields,
                              ssh_custr("PROXY-AUTHORIZATION"));
  if (value == NULL)
    return SSH_HTTP_AUTHENTICATION_NONE;

  return ssh_http_server_parse_authentication(value, name_return,
                                              password_return);
}


SshHttpCookiePtrConst
ssh_http_server_get_cookies(SshHttpServerConnection conn,
                            unsigned int *num_return)
{
  const unsigned char *value;
  unsigned int i = 0;
  const unsigned char *attr;
  unsigned int attr_len;
  const unsigned char *attr_val;
  unsigned int attr_val_len;
  SshHttpCookie *cookie = NULL;

  if (conn->cookies)
    {
      *num_return = conn->num_cookies;
      return conn->cookies;
    }

  /* The `Cookie' headers have not been parsed yet, or there are no
     cookies in the request. */

  value = ssh_http_kvhash_get(conn->req_header_fields, ssh_custr("COOKIE"));
  if (value == NULL)
    {
      /* Sorry, not available. */
      *num_return = 0;
      return NULL;
    }

  /* Parse the Cookie header. */

  while (1)
    {
      if (!ssh_http_get_av(value, &i, &attr, &attr_len, &attr_val,
                           &attr_val_len))
        {
          const unsigned char *user_agent;

        malformed_cookie:
          user_agent = ssh_http_kvhash_get(conn->req_header_fields,
                                           ssh_custr("USER-AGENT"));
          if (user_agent == NULL)
            user_agent = ssh_custr("<NULL>");

          SSH_DEBUG(SSH_D_FAIL,
                    ("Malformed `Cookie' header field: "
                     "Cookie=%s, User-Agent=%s", value, user_agent));
          break;
        }

      if (attr == NULL)
        {
          /* End of string reached. */
          if (cookie == NULL)
            /* No cookies in the value. */
            goto malformed_cookie;

          break;
        }

      /* Check what we got. */

      if (attr[0] == '$')
        {
          unsigned char **target = NULL;

          /* The versio information comes before any cookies.  */
          if (attr_len == 8
              && strncasecmp("$Version", (char *) attr, attr_len) == 0)
            {
              /* Ok, currently we just skip it. */
              ;
            }
          else
            {
              /* An attribute for the current cookie. */

              if (cookie == NULL)
                /* An attribute without NAME=VAL.  The `Cookie' header
                   is malformed. */
                goto malformed_cookie;

              else if (attr_len == 5
                       && strncasecmp("$Path", (char *) attr, attr_len) == 0)
                target = &cookie->path;
              else if (attr_len == 7
                       && strncasecmp("$Domain", (char *) attr, attr_len) == 0)
                target = &cookie->domain;
              else if (attr_len == 5
                       && strncasecmp("$Port", (char *) attr, attr_len) == 0)
                target = &cookie->port;
              /* Ignore all unknown tags. */

              /* Set the target's value. */
              if (target)
                {
                  /* Copy the value and remove possible escapeing. */
                  *target = ssh_http_unescape_attr_value(attr_val,
                                                         attr_val_len);
                }
            }
        }
      else
        {
          /* New cookie. */
          if (conn->cookies == NULL)
            {
              if ((conn->cookies = ssh_malloc(sizeof(SshHttpCookie))) == NULL)
                goto malformed_cookie;
              conn->num_cookies = 1;
            }
          else
            {
              void *tmp;

              if ((tmp =
                   ssh_realloc(conn->cookies,
                               conn->num_cookies * sizeof(SshHttpCookie),
                               (conn->num_cookies+1) * sizeof(SshHttpCookie)))
                  == NULL)
                goto malformed_cookie;

              conn->num_cookies++;
              conn->cookies = tmp;
            }

          cookie = &conn->cookies[conn->num_cookies - 1];
          memset(cookie, 0, sizeof(*cookie));

          cookie->name = ssh_memdup(attr, attr_len);
          cookie->value = ssh_http_unescape_attr_value(attr_val,
                                                       attr_val_len);
        }

      /* And move to the next attribute or cookie. */
      for (; value[i] && (isspace(value[i])
                          || value[i] == ';' || value[i] == ','); i++)
        ;

      /* Continue. */
    }

  *num_return = conn->num_cookies;

  return conn->cookies;
}


void
ssh_http_server_set_values(SshHttpServerConnection conn, ...)
{
  va_list ap;

  va_start(ap, conn);
  ssh_http_server_set_values_ap(conn, ap);
  va_end(ap);
}

/* Shortcut functions for using ssh_http_server_set_values(). */

void
ssh_http_server_set_cookie(SshHttpServerConnection conn,
                           const unsigned char *name,
                           const unsigned char *value,
                           const unsigned char *path)
{
  /* Set the expiration date of the page containing the cookie to this time
     yesterday.  This is in accordance with RFC2109, Section 4.2.3. */
  SshTime page_expire_time = ssh_time();
  page_expire_time -= 24 * 3600;

  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_COOKIE, name, value,
                             SSH_HTTP_HDR_COOKIE_PATH, path,
                             SSH_HTTP_HDR_COOKIE_MAX_AGE,
                             (SshTime)(10 * 365 * 24 * 3600L),
                             SSH_HTTP_HDR_COOKIE_SEND_EXPIRES,
                             SSH_HTTP_HDR_EXPIRES, page_expire_time,
                             SSH_HTTP_HDR_END);
}

void
ssh_http_server_set_value(SshHttpServerConnection conn,
                          const unsigned char *name,
                          const unsigned char *value)
{
  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_FIELD, name, value,
                             SSH_HTTP_HDR_END);
}

void
ssh_http_server_set_expires(SshHttpServerConnection conn,
                            SshTime expiration_time)
{
  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_EXPIRES, expiration_time,
                             SSH_HTTP_HDR_END);
}

void
ssh_http_server_set_content_length(SshHttpServerConnection conn,
                                   size_t bytes)
{
  ssh_http_server_set_values(conn,
                             SSH_HTTP_HDR_CONTENT_LENGTH, bytes,
                             SSH_HTTP_HDR_END);
}



void
ssh_http_server_send_buffer(SshHttpServerConnection conn,
                            SshBuffer buffer)
{
  SshServerSendBufferCtx *ctx;

  /* Allocate a context. */
  ctx = (SshServerSendBufferCtx *) ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      ssh_free(buffer);
      return;
    }

  ctx->stream = conn->ui_stream;
  ctx->buffer = buffer;

  ssh_stream_set_callback(conn->ui_stream,
                          ssh_http_server_send_buffer_stream_cb, ctx);
  ssh_http_server_send_buffer_stream_cb(SSH_STREAM_CAN_OUTPUT, ctx);
}


void
ssh_http_server_flush(SshHttpServerConnection conn)
{
  if (conn->ui_stream)
    (void) ssh_stream_write(conn->ui_stream, (unsigned char *) "", 0);
}


void
ssh_http_server_disconnect(SshHttpServerConnection conn)
{
  conn->w.eof_seen = TRUE;
  conn->close = TRUE;
  ssh_buffer_clear(&conn->out_buffer);
}


/* The user error functions. */

void
ssh_http_server_error_unauthorized(SshHttpServerConnection conn,
                                   const unsigned char *realm)
{
  ssh_http_server_error(conn, SSH_HTTP_STATUS_UNAUTHORIZED,
                        SSH_HTTP_HDR_WWW_AUTHENTICATE_BASIC, realm,
                        SSH_HTTP_HDR_END);
}


void
ssh_http_server_error_not_found(SshHttpServerConnection conn)
{
  ssh_http_server_error(conn, SSH_HTTP_STATUS_NOT_FOUND,
                        SSH_HTTP_HDR_END);
}


void
ssh_http_server_error_proxy_authentication_required(
                                                SshHttpServerConnection conn,
                                                const unsigned char *realm)
{
  ssh_http_server_error(conn, SSH_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED,
                        SSH_HTTP_HDR_PROXY_AUTHENTICATE_BASIC, realm,
                        SSH_HTTP_HDR_END);
}


void ssh_http_server_relative_redirect(SshHttpServerConnection conn,
                                       const unsigned char *location)
{
  ssh_http_server_error(conn, 301,
                        SSH_HTTP_HDR_LOCATION_RELATIVE, location,
                        SSH_HTTP_HDR_END);
}

void ssh_http_server_redirect(SshHttpServerConnection conn,
                              const unsigned char *location)
{
  ssh_http_server_error(conn, 301,
                        SSH_HTTP_HDR_LOCATION, location,
                        SSH_HTTP_HDR_END);
}

void ssh_http_server_error_code(SshHttpServerConnection conn,
                                int code)
{
  ssh_http_server_error(conn, code, SSH_HTTP_HDR_END);
}


void
ssh_http_server_error(SshHttpServerConnection conn, SshUInt32 status_code, ...)
{
  va_list ap;

  conn->status = status_code;

  if (SSH_HTTP_NO_CONTENT_STATUS(status_code))
    {
      /* These status codes must not have content data.  We do not
         call the message formatter just to avoid stupid user
         errors. */
      conn->error_message = NULL;
    }
  else
    {
      conn->error_message = ssh_buffer_allocate();

      if (conn->error_message)
        {
          va_start(ap, status_code);
          (*conn->ctx->formatter)(conn, conn->error_message, status_code,
                                  ap, conn->ctx->formatter_context);
          va_end(ap);

          /* Check if the message formatter really did produce an error
             message. */
          if (ssh_buffer_len(conn->error_message) == 0)
            {
              /* No it didn't.  Let's free the message buffer so the
                 byte-sink knows to send the header fields */
              ssh_buffer_free(conn->error_message);
              conn->error_message = NULL;
            }
        }
    }

  /* Format the header selectors & values into the reply kvhash. */
  va_start(ap, status_code);
  ssh_http_server_set_values_ap(conn, ap);
  va_end(ap);
}



/*
 * Static functions.
 */

static void
ssh_http_server_destroy(SshHttpServerContext ctx)
{
  SshHttpServerUriHandlerRegistry *reg, *next;

  ssh_free(ctx->address);
  ssh_free(ctx->port);
  ssh_free(ctx->server_name);

  SSH_ASSERT(ctx->listener == NULL);
  SSH_ASSERT(ctx->num_connections == 0);

  /* Free URI handlers. */
  for (reg = ctx->handlers; reg; reg = next)
    {
      next = reg->next;

      ssh_free(reg->pattern);
      ssh_free(reg);
    }

  ssh_free(ctx);
}


static void
ssh_http_server_listener_callback(SshTcpError error, SshStream stream,
                                  void *context)
{
  SshHttpServerContext ctx = (SshHttpServerContext) context;
  unsigned char remote_address[128];
  unsigned char remote_port[64];
  unsigned char local_address[128];
  SshHttpServerConnection conn;

  if (error == SSH_TCP_NEW_CONNECTION)
    {
      if (ctx->num_connections >= ctx->num_connections_hard_limit)
        {
          SSH_DEBUG(5, ("The hard limit of active connections exceeded"));
          ssh_stream_destroy(stream);
          return;
        }

      if (!ssh_tcp_get_remote_address(stream, remote_address,
                                      sizeof(remote_address)))
        strcpy(ssh_sstr(remote_address), "?.?.?.?");
      if (!ssh_tcp_get_remote_port(stream, remote_port,
                                   sizeof(remote_port)))
        strcpy(ssh_sstr(remote_port), "??");

      if (!ssh_tcp_get_local_address(stream, local_address,
                                     sizeof(local_address)))
        strcpy(ssh_sstr(local_address), "?.?.?.?");

      SSH_DEBUG(5, ("New connection from %s:%s",
                    remote_address, remote_port));

      /* Allocate one connection. */
      conn = ssh_http_server_new_connection(ctx, stream, local_address,
                                            remote_address,
                                            remote_port);
      /* Call the TCP wrapper function if specified. */
      if (ctx->tcp_wrapper)
        {
          stream = (*ctx->tcp_wrapper)(conn,
                                       stream, ctx->tcp_wrapper_context);
          conn->stream = stream;
        }

      if (ctx->num_connections >= ctx->num_connections_soft_limit)
        {
          SSH_DEBUG(5, ("The soft limit of active connections exceeded"));

          /* Write an error to the client and we'r done. */
          ssh_http_server_error(conn, SSH_HTTP_STATUS_SERVICE_UNAVAILABLE,
                                SSH_HTTP_HDR_END);
          ssh_http_server_internal_error(conn);
        }
      else
        {
          /* Signal the connection that we have some job to do. */
          ssh_stream_set_callback(stream, ssh_http_server_connection_callback,
                                  conn);
          ssh_http_server_connection_callback(SSH_STREAM_INPUT_AVAILABLE,
                                              conn);
        }
    }
  else
    {
      SSH_DEBUG(5, ("Error: %s", ssh_tcp_error_string(error)));
    }
}


static SshHttpServerConnection
ssh_http_server_new_connection(SshHttpServerContext ctx, SshStream stream,
                               unsigned char *local_address,
                               unsigned char *remote_address,
                               unsigned char *remote_port)
{
  SshHttpServerConnection conn;

  if ((conn = ssh_calloc(1, sizeof(*conn))) == NULL)
    return NULL;

  conn->state = SSH_HTTP_CONN_READING_REQUEST;

  conn->stream = stream;
  conn->address = ssh_strdup(remote_address);
  conn->port = ssh_strdup(remote_port);
  conn->local_address = ssh_strdup(local_address);

  if (conn->address == NULL || conn->port == NULL ||
      conn->local_address == NULL)
    goto failed;

  ssh_buffer_init(&conn->in_buffer);
  ssh_buffer_init(&conn->out_buffer);

  conn->req_header_fields = ssh_http_kvhash_create(TRUE);
  conn->reply_header_fields = ssh_http_kvhash_create(FALSE);

  if (conn->req_header_fields == NULL ||
      conn->reply_header_fields == NULL)
    {
    failed:
      ssh_http_server_remove_connection(conn);
      return NULL;
    }

  /* The default status of this request. */
  conn->status = SSH_HTTP_STATUS_OK;

  /* Order a `read request timeout'. */
  ssh_xregister_timeout(ctx->read_request_timeout, 0,
                       ssh_http_server_read_req_timeout, conn);
  conn->read_request_timeout_scheduled = TRUE;

  /* Insert it to the server's context. */

  conn->ctx = ctx;

  conn->next = ctx->connections;
  if (ctx->connections)
    ctx->connections->prev = conn;
  ctx->connections = conn;

  ctx->num_connections++;

  return conn;
}


static void
ssh_http_server_finish_connection(SshHttpServerConnection conn)
{
  Boolean keep_open = FALSE;

  /* Cancel all timeouts for this connection. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, conn);

  /* Check if we can leave the connection open. */
  if (!conn->close)
    {
      /* No EOFs found nor an active close requested.  Check the
         protocol versions.  HTTP/0.9 have always conn->close.
         Requests HTTP/2.x and bigger are already rejected. */
      if (conn->minor == 0)
        {
          /* HTTP/1.0. Must have `Connection: Keep-Alive'. */
          if (conn->req_keep_alive)
            keep_open = TRUE;
        }
      else
        {
          /* HTTP/1.x where x is greater than 0. Must not have
             `Connection: close'. */

          /* This is already checked in the create_handler() and if it
             was present, conn->close is TRUE. */
          keep_open = TRUE;
        }
    }

  /* Keep open and the server has not been stopped. */
  if (keep_open && conn->ctx->listener != NULL)
    {
      /* Ok, let's keep the connection open. */
      SSH_DEBUG(5, ("Leaving the connection open"));

      /* Reinit the handle. */

      conn->state = SSH_HTTP_CONN_READING_REQUEST;
      conn->read_request_timeout_scheduled = FALSE;
      ssh_free(conn->method);
      conn->method = NULL;
      ssh_free(conn->uri);
      conn->uri = NULL;
      ssh_free(conn->uri_path);
      conn->uri_path = NULL;
      conn->req_header_field_count = 0;

      ssh_http_kvhash_clear(conn->req_header_fields);
      ssh_http_kvhash_clear(conn->reply_header_fields);

      /* Clear Cookies and Set-Cookies. */
      ssh_http_server_free_cookies(conn);

      conn->req_keep_alive = FALSE;

      ssh_buffer_clear(&conn->in_buffer);
      ssh_buffer_clear(&conn->out_buffer);

      conn->status = SSH_HTTP_STATUS_OK;

      if (conn->error_message)
        {
          ssh_buffer_free(conn->error_message);
          conn->error_message = NULL;
        }

      conn->ui_stream = NULL;

      /* UI read stream. */
      memset(&conn->r, 0, sizeof(conn->r));

      /* UI write stream. */
      memset(&conn->w, 0, sizeof(conn->w));

      /* Order a timeout to close it. */
      ssh_xregister_timeout(conn->ctx->keep_open_timeout, 0,
                           ssh_http_server_keep_open_timeout, conn);

      /* And signal the stream callback that we might have some data
         to read. */
      ssh_xregister_timeout(0, 0, ssh_http_server_read_more_input_timeout,
                           conn);
    }
  else
    {
      /* Remove us from the server. */
      SSH_DEBUG(5, ("Closing the connection"));
      ssh_http_server_remove_connection(conn);
    }
}


static void
ssh_http_server_read_more_input_timeout(void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;
  ssh_http_server_connection_callback(SSH_STREAM_INPUT_AVAILABLE, conn);
}


static void
ssh_http_server_remove_connection(SshHttpServerConnection conn)
{
  SshHttpServerContext ctx = conn->ctx;

  /* Cancel all timeouts for this connection. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, conn);

  /* Remove it from the context. */
  if (ctx)
    {
      if (conn->next)
        conn->next->prev = conn->prev;
      if (conn->prev)
        conn->prev->next = conn->next;
      else
        ctx->connections = conn->next;

      ctx->num_connections--;
    }

  /* Cleanup and free the connection. */
  ssh_free(conn->method);
  ssh_free(conn->uri);
  ssh_free(conn->uri_path);

  ssh_http_kvhash_destroy(conn->req_header_fields);
  ssh_http_kvhash_destroy(conn->reply_header_fields);

  /* Clear Cookies and Set-Cookies. */
  ssh_http_server_free_cookies(conn);

  ssh_stream_output_eof(conn->stream);
  ssh_stream_destroy(conn->stream);

  ssh_free(conn->local_address);
  ssh_free(conn->address);
  ssh_free(conn->port);

  ssh_buffer_uninit(&conn->in_buffer);
  ssh_buffer_uninit(&conn->out_buffer);

  if (conn->error_message)
    ssh_buffer_free(conn->error_message);

  ssh_free(conn);

  /* Is the server stopped? */
  if (ctx)
    {
      if (ctx->listener == NULL && ctx->num_connections == 0)
        {
          /* Yes it was.  And we were the last connection.  Let's notify
             the application and free the server handle. */
          if (ctx->server_stopped_callback != NULL_FNPTR)
            {
              SSH_DEBUG(5, ("Server stopped, notifying the application."));
              (*ctx->server_stopped_callback)(ctx,
                                              ctx->server_stopped_context);
            }
          SSH_DEBUG(5, ("Destroying the server handle"));
          ssh_http_server_destroy(ctx);
        }
    }
}


static void
ssh_http_server_free_cookies(SshHttpServerConnection conn)
{
  unsigned int i;

  /* Cookies. */

  for (i = 0; i < conn->num_cookies; i++)
    {
      SshHttpCookie *cookie = &conn->cookies[i];

      ssh_free(cookie->name);
      ssh_free(cookie->value);
      ssh_free(cookie->path);
      ssh_free(cookie->domain);
      ssh_free(cookie->port);
    }

  ssh_free(conn->cookies);

  conn->cookies = NULL;
  conn->num_cookies = 0;


  /* Set-Cookies. */

  for (i = 0; i < conn->num_set_cookies; i++)
    {
      SshHttpSetCookie *cookie = &conn->set_cookies[i];

      ssh_free(cookie->name);
      ssh_free(cookie->value);
      ssh_free(cookie->comment);
      ssh_free(cookie->comment_url);
      ssh_free(cookie->domain);
      ssh_free(cookie->expires);
      ssh_free(cookie->path);
      ssh_free(cookie->port);
    }

  ssh_free(conn->set_cookies);

  conn->set_cookies = NULL;
  conn->num_set_cookies = 0;
}


static void
ssh_http_server_connection_callback(SshStreamNotification notification,
                                    void *context)
{
  int l, j;
  unsigned int i;
  SshHttpServerConnection conn = (SshHttpServerConnection) context;
  size_t to_read;
  unsigned char *p;
  size_t len;
  size_t end, start;
  unsigned int k;
  char *bad_request_reason;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      bad_request_reason = NULL;
      while (1)
        {
          /* Try to read. */
          to_read = (SSH_HTTP_BUFFER_SIZE - ssh_buffer_len(&conn->in_buffer));
          if (to_read == 0)
            {
              switch (conn->state)
                {
                case SSH_HTTP_CONN_READING_REQUEST:
                  ssh_http_server_error(conn,
                                        SSH_HTTP_STATUS_REQUEST_URI_TOO_LARGE,
                                        SSH_HTTP_HDR_END);
                  ssh_http_server_internal_error(conn);
                  return;
                  break;

                case SSH_HTTP_CONN_READING_HEADER:
                toolong:
                  ssh_http_server_error(
                                conn,
                                SSH_HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE,
                                SSH_HTTP_HDR_END);
                  ssh_http_server_internal_error(conn);
                  return;
                  break;

                case SSH_HTTP_CONN_USER_IO:
                  /* Flow control.  Let's wait that user consumes some
                     data from the buffer. */
                  SSH_DEBUG(6, ("Flow control"));
                  return;
                  break;
                }
            }
          if (ssh_buffer_append_space(&conn->in_buffer, &p, to_read)
              != SSH_BUFFER_OK)
            goto toolong;

          l = ssh_stream_read(conn->stream, p, to_read);

          if (l < 0)
            {
              SSH_DEBUG(9, ("Would block."));
              ssh_buffer_consume_end(&conn->in_buffer, to_read);
              return;
            }
          else if (l == 0)
            {
              SSH_DEBUG(9, ("Read: Client has closed connection"));
              conn->close = TRUE;
              conn->r.eof_seen = TRUE;
              ssh_buffer_consume_end(&conn->in_buffer, to_read);
            }
          else
            {
              ssh_buffer_consume_end(&conn->in_buffer, to_read - l);
              SSH_DEBUG(9, ("Read %d bytes", l));
            }

          /* Process the data. */

        process_more:

          p = ssh_buffer_ptr(&conn->in_buffer);
          len = ssh_buffer_len(&conn->in_buffer);

          switch (conn->state)
            {
            case SSH_HTTP_CONN_READING_REQUEST:
              /* This is a suitable place to cancel the possible
                 keep_open_timeout of this connection. */
              ssh_cancel_timeouts(ssh_http_server_keep_open_timeout, conn);

              /* For the `keep-alive' connections, this is a good
                 place to schedule a `read request timeout' (if not
                 already ordered). */
              if (!conn->read_request_timeout_scheduled)
                {
                  ssh_xregister_timeout(conn->ctx->read_request_timeout, 0,
                                       ssh_http_server_read_req_timeout, conn);
                  conn->read_request_timeout_scheduled = TRUE;
                }

              if (!ssh_http_server_has_one_line(p, len, &end))
                {
                  if (conn->r.eof_seen)
                    goto bad_request;

                  /* Read more. */
                  continue;
                }

              /* Parse the request line. */

              /* The method. */

              if (!isalpha(p[0]))
                {
                bad_request:
                  if (bad_request_reason != NULL)
                    {
                      ssh_http_server_error(conn, SSH_HTTP_STATUS_BAD_REQUEST,
                                            SSH_HTTP_HDR_BAD_REQUEST_REASON,
                                            bad_request_reason,
                                            SSH_HTTP_HDR_END);
                    }
                  else
                    {
                      ssh_http_server_error(conn, SSH_HTTP_STATUS_BAD_REQUEST,
                                            SSH_HTTP_HDR_END);
                    }
                  ssh_http_server_internal_error(conn);
                  return;
                }
              for (i = 0; i < end && isalpha(p[i]); i++)
                ;
              if (i >= end)
                goto bad_request;

              if (!isspace(p[i]))
                goto bad_request;

              if ((conn->method = ssh_memdup(p, i)) == NULL)
                goto bad_request;

              /* The method names are case-insensitive. */
              for (j = 0; conn->method[j]; j++)
                if (islower((unsigned char) conn->method[j]))
                  conn->method[j] = toupper((unsigned char) conn->method[j]);

              /* URI. */

              for (; i < end && isspace(p[i]); i++)
                ;
              if (i >= end)
                goto bad_request;

              start = i;
              for (; i < end && !isspace(p[i]); i++)
                ;
              if (i >= end)
                /* There must be the '\r' character at the end of the line. */
                goto bad_request;

              if ((conn->uri = ssh_memdup(p + start, i - start)) == NULL)
                goto bad_request;

              /* Extract and decode the path part of the uri. */
              {
                const unsigned char *sep;

                sep = ssh_ustrchr(conn->uri, '?');
                if (sep == NULL)
                  sep = conn->uri + ssh_ustrlen(conn->uri);

                if ((conn->uri_path = ssh_url_data_decode(conn->uri,
                                                          sep - conn->uri,
                                                          NULL)) == NULL)
                  goto bad_request;
              }

              /* Possible `HTTP/x.y' tag. */

              for (; i < end && isspace(p[i]); i++)
                ;

              if (i >= end)
                {
                  /* It was an HTTP/0.9 request. */
                  conn->close = TRUE;
                  conn->major = 0;
                  conn->minor = 9;
                  conn->state = SSH_HTTP_CONN_USER_IO;

                  /* Only the `GET' method is supported. */
                  if (ssh_ustrcmp(conn->method, (unsigned char *)"GET") != 0)
                    goto bad_request;
                }
              else
                {
                  if (p[i] != 'H' || p[i + 1] != 'T' || p[i + 2] != 'T'
                      || p[i + 3] != 'P' || p[i + 4] != '/')
                    goto bad_request;
                  i += 5;

                  /* Version major. */
                  conn->major = 0;
                  for (; i < end && isdigit(p[i]); i++)
                    {
                      conn->major *= 10;
                      conn->major += p[i] - '0';
                    }
                  if (i >= end || p[i] != '.')
                    goto bad_request;
                  i++;

                  /* Version minor. */
                  conn->minor = 0;
                  for (; i < end && isdigit(p[i]); i++)
                    {
                      conn->minor *= 10;
                      conn->minor += p[i] - '0';
                    }
                  if (i >= end)
                    goto bad_request;

                  /* Skip the trailing whitespace. */
                  for (; i < end && isspace(p[i]); i++)
                    ;
                  if (i < end)
                    goto bad_request;

                  conn->state = SSH_HTTP_CONN_READING_HEADER;
                }

              /* We did parse it successfully. */
              SSH_DEBUG(5, ("%s %s HTTP/%d.%d",
                            conn->method, conn->uri,
                            (int) conn->major,
                            (int) conn->minor));

              if (conn->major > 1)
                {
                  /* Sorry, we support only HTTP/1.x requests. */
                  ssh_http_server_error(
                                conn,
                                SSH_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
                                SSH_HTTP_HDR_END);
                  ssh_http_server_internal_error(conn);
                  return;
                }

              ssh_buffer_consume(&conn->in_buffer, end);
              p += end;
              len -= len;

              if (conn->state == SSH_HTTP_CONN_USER_IO)
                {
                  /* For the HTTP/0.9 requests. */
                  ssh_http_server_create_handler(conn);
                  return;
                }

              /* Process more data from the buffer. */
              goto process_more;
              break;

            case SSH_HTTP_CONN_READING_HEADER:
              while (ssh_http_server_has_one_line(p, len, &end))
                {
                  SshUInt32 key_end;
                  SshUInt32 value_start;

                  /* Skip the leading whitespace. */
                  for (i = 0; i < end && isspace(p[i]); i++)
                    ;
                  if (i >= end)
                    {
                      /* The header body separator found. */
                      ssh_buffer_consume(&conn->in_buffer, end);
                      conn->state = SSH_HTTP_CONN_USER_IO;
                      ssh_http_server_create_handler(conn);
                      return;
                    }

                  /* Limit maximum number of header fields to prevent DOS
                     attack by sending thousands of header fields. */
                  conn->req_header_field_count++;
                  SSH_ASSERT(conn->ctx != NULL);
                  if (conn->req_header_field_count >
                      conn->ctx->max_req_header_field_count)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("HTTP request maximum header field count %u "
                                 "exceeded",
                                 (int) conn->ctx->max_req_header_field_count));
                      bad_request_reason = "Too many header fields";
                      goto bad_request;
                    }

                  if (i > 0)
                    {
                      /* Whitespace in the beginning of the field.
                         This is a continuation line. */
                      value_start = i;

                      /* Skip the trailing whitespace. */
                      for (i = end - 1; i > value_start && isspace(p[i]); i--)
                        ;
                      i++;

                      SSH_DEBUG(6, ("+ %.*s",
                                    (int) (i - value_start),
                                    p + value_start));

                      if (!ssh_http_kvhash_append_last(conn->req_header_fields,
                                                       p + value_start,
                                                       i - value_start))
                        /* There were no last key.  This is a bad
                           request. */
                        goto bad_request;
                    }
                  else
                    {
                      start = i;

                      /* Find the ':' separator. */
                      for (; i < end && p[i] != ':'; i++)
                        ;
                      if (i >= end)
                        {
                          SSH_DEBUG(SSH_D_FAIL,
                                    ("Bad header line.  No ':' found"));
                          /* Bzzttt.  Bad request. */
                          goto bad_request;
                        }
                      key_end = i;

                      /* Skip the leading whitespace. */
                      for (i++; i < end && isspace(p[i]); i++)
                        ;
                      value_start = i;

                      /* Skip the trailing whitespace. */
                      for (i = end - 1; i > value_start && isspace(p[i]); i--)
                        ;
                      i++;

                      SSH_DEBUG(6, ("%.*s: %.*s",
                                    (int) (key_end - start), p + start,
                                    (int) (i - value_start), p + value_start));

                      /* Check for key name validity */
                      if (key_end - start == 0)
                        {
                          SSH_DEBUG(SSH_D_FAIL,
                                    ("Bad header line. Header field must "
                                     "contain at least one character."));
                          goto bad_request;
                        }
                      for (k = start; k < key_end; k++)
                        {
                          if (!SSH_HTTP_IS_TOKEN_CH(p[k]))
                            {
                              SSH_DEBUG(SSH_D_FAIL,
                                        ("Bad header line. Invalid character "
                                         "%c (0x%02x) in key name.",
                                         p[k], (unsigned char) p[k]));
                              goto bad_request;
                            }
                        }

                      ssh_http_kvhash_put(conn->req_header_fields,
                                          p + start, key_end - start,
                                          p + value_start, i - value_start);

                    }

                  ssh_buffer_consume(&conn->in_buffer, end);
                  p = ssh_buffer_ptr(&conn->in_buffer);
                  len = ssh_buffer_len(&conn->in_buffer);
                }

              /* Couldn't find a complete line. */
              if (conn->r.eof_seen)
                goto bad_request;

              /* Read more data. */
              break;

            case SSH_HTTP_CONN_USER_IO:
              if (l > 0)
                conn->r.content_data_read += l;

              /* The end of the content data condition. */
              SSH_HTTP_SERVER_CHECK_EOCD(conn);

              if (conn->r.blocked)
                {
                  conn->r.blocked = FALSE;
                  (*conn->r.callback)(SSH_STREAM_INPUT_AVAILABLE,
                                      conn->r.callback_context);
                  return;
                }

              if (l <= 0)
                return;

              /* Read more data. */
              break;
            }
        }
      break;

    case SSH_STREAM_CAN_OUTPUT:
      while (1)
        {
          switch (conn->state)
            {
            case SSH_HTTP_CONN_READING_REQUEST:
            case SSH_HTTP_CONN_READING_HEADER:
              /* Nothing here. */
              return;
              break;

            case SSH_HTTP_CONN_USER_IO:
              if (ssh_buffer_len(&conn->out_buffer) == 0)
                {
                  if (conn->w.destroyed)
                    {
                      /* We'r finished with this stream. */
                      ssh_http_server_finish_connection(conn);
                      return;
                    }

                  /* Ask the user to fill up the buffer or destroy
                     himself. */
                  if (conn->w.callback)
                    {
                      (*conn->w.callback)(SSH_STREAM_CAN_OUTPUT,
                                          conn->w.callback_context);
                      return;
                    }

                  else
                    {
                      /* No write callback.  We'r done. */
                      return;
                    }
                }

              l = ssh_stream_write(conn->stream,
                                   ssh_buffer_ptr(&conn->out_buffer),
                                   ssh_buffer_len(&conn->out_buffer));
              if (l == 0)
                {
                  /* EOF reached.  We'r finished with this connection. */
                  SSH_DEBUG(9, ("Write: Client has closed the connection"));
                  conn->close = TRUE;
                  conn->w.eof_seen = TRUE;
                  ssh_buffer_clear(&conn->out_buffer);
                }
              else if (l < 0)
                {
                  /* Would block. */
                  SSH_DEBUG(9, ("Would block"));
                  return;
                }
              else
                {
                  SSH_DEBUG(9, ("Wrote %d bytes", l));
                  ssh_buffer_consume(&conn->out_buffer, l);
                }
              break;
            }
        }
      break;

    case SSH_STREAM_DISCONNECTED:
      break;
    }
}

static Boolean
ssh_http_server_has_one_line(unsigned char *p, size_t len, size_t *end_return)
{
  size_t i;

  for (i = 0; i < len && p[i] != '\n'; i++)
    ;
  if (i >= len)
    return FALSE;

  *end_return = i + 1;

  return TRUE;
}


static void
ssh_http_server_create_handler(SshHttpServerConnection conn)
{
  const unsigned char *value;
  Boolean had_content_length = FALSE;
  SshHttpServerUriHandlerRegistry *reg;
  Boolean input_is_chunked = FALSE;
  Boolean client_expects_100_continue = FALSE;

  /* The request was read successfully.  Cancel the `read request
     timeout'. */
  ssh_cancel_timeouts(ssh_http_server_read_req_timeout, conn);

  /* Do we have message body in the request? */

  value = ssh_http_kvhash_get(conn->req_header_fields,
                              ssh_custr("CONTENT-LENGTH"));
  if (value)
    {
      conn->r.content_length = ssh_ustrtoul(value, NULL, 10);
      had_content_length = TRUE;
    }
  else
    conn->r.content_length = -1;

  if (conn->major == 0)
    {
      /* HTTP/0.9: No content data. */
      conn->r.content_length = 0;
      conn->r.end_of_content_data = TRUE;
    }
  else if (conn->minor == 0)
    {
      /* HTTP/1.0: if the content length is unspecified, we assume
         content data for POST and PUT requests. */
      if (!had_content_length)
        {
          if (ssh_usstrcasecmp(conn->method, "POST") == 0
              || ssh_usstrcasecmp(conn->method, "PUT") == 0)
            {
              /* An unspecified amount of content data.  We must read
                 to the EOF. */
              conn->r.content_length = -1;
              conn->close = TRUE;
            }
          else
            {
              /* Assume no content data. */
              conn->r.content_length = 0;
              conn->r.end_of_content_data = TRUE;
            }
        }
    }
  else
    {
      /* HTTP/1.1: content data only if the Content-Length or
         Transfer-Coding is specified. */
      value = ssh_http_kvhash_get(conn->req_header_fields,
                                  ssh_custr("TRANSFER-ENCODING"));
      if (value)
        {
          /* Let's see if we support this encoding. */
          /* the encoding can have multiple values. */
          if (ssh_usstrcasecmp(value, "chunked") != 0)
            {
              /* We don't support this. */
              ssh_http_server_error(conn, SSH_HTTP_STATUS_NOT_IMPLEMENTED,
                                    SSH_HTTP_HDR_END);
              ssh_http_server_internal_error(conn);
              return;
            }
          /* Ok, the input stream is chunked.  We can handle that. */
          input_is_chunked = TRUE;
        }
      else
        {
          if (!had_content_length)
            {
              /* No Content-Length or Transfer-Encoding specified =>
                 no content data. */
              conn->r.content_length = 0;
              conn->r.end_of_content_data = TRUE;
            }
        }
    }

  /* Validity checks for HTTP/1.1 and greater requests. */
  if (conn->major == 1 && conn->minor >= 1)
    {
      /* There must be a `Host: host' header field. */
      value = ssh_http_kvhash_get(conn->req_header_fields, ssh_custr("HOST"));
      if (value == NULL)
        {
          SSH_DEBUG(5,
                    ("HTTP/1.1 requests must have the `Host' header field"));
          ssh_http_server_error(conn, SSH_HTTP_STATUS_BAD_REQUEST,
                                SSH_HTTP_HDR_END);
          ssh_http_server_internal_error(conn);
          return;
        }
    }

  /* Fetch also some other interesting header fields. */

  value = ssh_http_kvhash_get(conn->req_header_fields,
                              ssh_custr("CONNECTION"));
  if (value)
    {
      if (ssh_usstrcasecmp(value, "close") == 0)
        conn->close = TRUE;
      if (ssh_usstrcasecmp(value, "keep-alive") == 0)
        conn->req_keep_alive = TRUE;
    }

  /* HTTP/1.1 fields. */
  if (conn->major == 1 && conn->minor == 1)
    {
      /* Expect: 100-continue */
      value = ssh_http_kvhash_get(conn->req_header_fields,
                                  ssh_custr("EXPECT"));
      if (value)
        {
          /* We only support the `100-continue' expectation. */
          if (ssh_usstrcmp(value, "100-continue") != 0)
            {
              ssh_http_server_error(conn, SSH_HTTP_STATUS_EXPECTATION_FAILED,
                                    SSH_HTTP_HDR_END);
              ssh_http_server_internal_error(conn);
              return;
            }
          SSH_DEBUG(5, ("Client expects `100 Continue'."));
          client_expects_100_continue = TRUE;

          /* Format the 100-continue to our output buffer. */
          if (ssh_buffer_append_cstrs(&conn->out_buffer,
                                      "HTTP/1.1 100 Continue\r\n\r\n",
                                      NULL) != SSH_BUFFER_OK)
            {
              ssh_http_server_error(conn, SSH_HTTP_STATUS_EXPECTATION_FAILED,
                                    SSH_HTTP_HDR_END);
              ssh_http_server_internal_error(conn);
              return;
            }
        }
    }

  /* Was it a `HEAD' request? */
  conn->is_head = (ssh_ustrcmp(conn->method, (unsigned char *)"HEAD") == 0);

  /* Init the content data count. */
  conn->r.content_data_read = ssh_buffer_len(&conn->in_buffer);

  /* The end of the content data condition. */
  SSH_HTTP_SERVER_CHECK_EOCD(conn);

  /* Create the UI input / ouput stream which wraps our connection. */
  conn->ui_stream = ssh_http_server_create_ui_stream(conn, input_is_chunked);

  /* Flush the 100 Continue. */
  if (client_expects_100_continue)
    ssh_http_server_connection_callback(SSH_STREAM_CAN_OUTPUT, conn);

  /* Are we shutting down? */
  if (conn->ctx->listener)
    {
      /* The TCP listener is still set so we are not shutting down.
         Pass the connection to the handlers until one of the accepts
         it and returns TRUE. */
      for (reg = conn->ctx->handlers; reg; reg = reg->next)
        if (ssh_match_pattern((char *)conn->uri_path, (char *)reg->pattern))
          {
            /* Spawn the handler. */
            if ((*reg->handler)(conn->ctx, conn, conn->ui_stream,
                                reg->handler_context))
              /* Ok, this handler did the job. */
              return;
          }
    }

  /* Couldn't find a matching handler.  Pass it to our default
     handler. */

  (void) ssh_http_server_default_uri_handler(conn->ctx, conn, conn->ui_stream,
                                             NULL);
}


static void
ssh_http_server_content_read_chunked_callback(
                                SshHttpChunkedStreamNotification notification,
                                const unsigned char *key, size_t key_len,
                                const unsigned char *value, size_t value_len,
                                void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  switch (notification)
    {
    case SSH_HTTP_CHUNKED_STREAM_READ_EOF_REACHED:
      conn->r.end_of_content_data = TRUE;
      break;

    case SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD:
      ssh_http_kvhash_put(conn->req_header_fields, key, key_len,
                          value, value_len);
      break;

    case SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD_CONT:
      ssh_http_kvhash_append_last(conn->req_header_fields, value, value_len);
      break;

    default:
      /* Ignore the rest. */
      break;
    }
}


static SshStream
ssh_http_server_create_ui_stream(SshHttpServerConnection conn,
                                 Boolean input_is_chunked)
{
  SshStream read_s, write_s;

  /* First, we create a read-only stream that can be used to read the
     content data. */
  if ((read_s = ssh_http_server_content_read_stream(conn)) == NULL)
    return NULL;

  /* Check possible additional input transfer encodings. */
  if (input_is_chunked)
    {
      SSH_DEBUG(5, ("Read: Chunked Transfer Coding"));
      if ((read_s =
           ssh_http_chunked_stream_create(read_s, TRUE, FALSE,
                        ssh_http_server_content_read_chunked_callback,
                                          conn)) == NULL)
        return NULL;
    }

  /* Second, we create a write-only stream that writes data to the
     HTTP stream.  */
  if ((write_s = ssh_http_server_content_write_stream(conn)) == NULL)
    {
      ssh_stream_destroy(read_s);
      return NULL;
    }

  /* We apply the `Chunked Transfer Encoding' for each HTTP/1.1 and
     bigger requests. */
  if (conn->major == 1 && conn->minor >= 1)
    {
      SSH_DEBUG(5, ("Write: Chunked Transfer Coding"));
      conn->w.chunked_transfer_encoding = TRUE;
      if ((write_s =
           ssh_http_chunked_stream_create(write_s, FALSE, TRUE,
                                          NULL_FNPTR, NULL)) == NULL)
        {
          ssh_stream_destroy(read_s);
          return NULL;
        }
    }

  /* Third, we create read-write stream that wraps the input and
     output streams into a nice user interface stream. */
  return ssh_http_server_ui_stream(conn, read_s, write_s);
}


static Boolean
ssh_http_server_default_uri_handler(SshHttpServerContext ctx,
                                    SshHttpServerConnection conn,
                                    SshStream stream, void *context)
{
  ssh_http_server_error_not_found(conn);
  ssh_stream_destroy(stream);

  return TRUE;
}


static void
ssh_http_server_read_req_timeout(void  *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  SSH_DEBUG(5, ("Closing the connection"));
  ssh_http_server_remove_connection(conn);
}


static void
ssh_http_server_write_response_timeout(void  *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  SSH_DEBUG(5, ("Closing the connection"));
  ssh_http_server_remove_connection(conn);
}


static void
ssh_http_server_keep_open_timeout(void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  SSH_DEBUG(5, ("Closing the connection"));
  ssh_http_server_remove_connection(conn);
}



/*
 * The reply handling, server errors, etc.
 */

static void
ssh_http_server_send_buffer_stream_cb(SshStreamNotification notification,
                                      void *context)
{
  SshServerSendBufferCtx *ctx = (SshServerSendBufferCtx *) context;
  int i;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      /* Ignore */
      break;

    case SSH_STREAM_CAN_OUTPUT:
      while (ssh_buffer_len(ctx->buffer) > 0)
        {
          i = ssh_stream_write(ctx->stream, ssh_buffer_ptr(ctx->buffer),
                               ssh_buffer_len(ctx->buffer));
          if (i == 0)
            /* EOF.  We'r done. */
            ssh_buffer_clear(ctx->buffer);
          else if (i < 0)
            /* Would block. */
            return;
          else
            /* Wrote something. */
            ssh_buffer_consume(ctx->buffer, i);
        }

      /* Ok, we have finished sending data. */
      ssh_buffer_free(ctx->buffer);
      ssh_stream_destroy(ctx->stream);
      ssh_free(ctx);
      break;

    case SSH_STREAM_DISCONNECTED:
      break;
    }
}


static void
ssh_http_server_default_msg_formatter(SshHttpServerConnection conn,
                                      SshBuffer buffer, SshUInt32 code,
                                      va_list ap, void *context)
{
  unsigned char buf[256];
  const unsigned char *msg;
  const unsigned char *cp;
  int count;
  int type;

  /* This function does what it can in limits of available memory. It
     does not try to recover from out of memory conditions. On
     out-of-memory conditions the output will be funny. */
  msg = ssh_custr("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                  "<HTML>\n<HEAD>\n<TITLE>");
  (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));

  ssh_snprintf(buf, sizeof(buf), "%ld %s", code,
               ssh_http_status_to_string(code));
  (void) ssh_buffer_append(buffer, buf, ssh_ustrlen(buf));

  msg = ssh_custr("</TITLE>\n</HEAD>\n<BODY>\n<H1>");
  (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));

  msg = ssh_custr(ssh_http_status_to_string(code));
  (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));

  msg = ssh_custr("</H1>\n");
  (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));

  /* A more specific error. */
  switch (code)
    {
    case SSH_HTTP_STATUS_MOVED_PERMANENTLY:
      msg = ssh_custr("The requested URL ");
      (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));
      (void) ssh_buffer_append(buffer, conn->uri, ssh_ustrlen(conn->uri));
      msg = ssh_custr(" has moved permanently to ");
      (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));

      count = 0;
      while ((type = va_arg(ap, int)) != SSH_HTTP_HDR_END)
        {
          switch (type)
            {
            case SSH_HTTP_HDR_LOCATION:
              msg = va_arg(ap, unsigned char *);

              if (count++ > 0)
                ssh_buffer_append_cstrs(buffer, ", ", NULL);

              ssh_buffer_append_cstrs(buffer,
                                      "<A HREF=\"", msg, "\">", msg, "</A>",
                                      NULL);
              break;

            case SSH_HTTP_HDR_LOCATION_RELATIVE:
              msg = va_arg(ap, unsigned char *);
              {
                char *prefix = msg[0] == '/' ? "" : "/";

                if (count++ > 0)
                  ssh_buffer_append_cstrs(buffer, ", ", NULL);

                cp = ssh_http_kvhash_get(conn->req_header_fields,
                                         ssh_custr("HOST"));
                if (cp)
                  ssh_buffer_append_cstrs(buffer,
                                          "<A HREF=\"http://",
                                          cp, prefix, msg, "\">",
                                          "http://", cp, prefix, msg,
                                          "</A>",
                                          NULL);
                else
                  ssh_buffer_append_cstrs(buffer,
                                          "<A HREF=\"http://",
                                          conn->ctx->server_name, ":",
                                          conn->ctx->port, prefix, msg, "\">",
                                          "http://",
                                          conn->ctx->server_name, ":",
                                          conn->ctx->port, prefix, msg,
                                          "</A>",
                                          NULL);
              }
              break;

            default:
              ssh_http_hdr_skip_next(ap, type);
              break;
            }
        }

      (void) ssh_buffer_append(buffer, ssh_custr(".\n"), 2);
      break;

    case SSH_HTTP_STATUS_BAD_REQUEST:
      while ((type = va_arg(ap, int)) != SSH_HTTP_HDR_END)
        {
          switch (type)
            {
            case SSH_HTTP_HDR_BAD_REQUEST_REASON:
              msg = va_arg(ap, unsigned char *);

              ssh_buffer_append_cstrs(buffer, msg, NULL);
              break;

            default:
              ssh_http_hdr_skip_next(ap, type);
              break;
            }
        }

      msg = ssh_custr("\n");
      (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));
      break;

    case SSH_HTTP_STATUS_NOT_FOUND:
      msg = ssh_custr("The requested URL ");
      (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));
      (void) ssh_buffer_append(buffer, conn->uri, ssh_ustrlen(conn->uri));
      msg = ssh_custr(" was not found on this server.<P>\n");
      (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));
      break;
    }

  msg = ssh_custr("</BODY>\n</HTML>\n");
  (void) ssh_buffer_append(buffer, msg, ssh_ustrlen(msg));
}

/* Several popular browsers (Konquerors at least upto and including
   v2.1.1, Mozilla v0.9.8, some unidentified old Netscapes, others)
   reject cookies with quoted attributes, so we quote the values only
   if necessary. */
static Boolean
ssh_http_server_format_append_cookie_attribute(SshBuffer out_buffer,
                                               unsigned char *name,
                                               unsigned char *value,
                                               Boolean include_separator)
{
  Boolean need_quotes = FALSE;
  unsigned char *p, *new_value;
  int value_len_growth = 0;
  SshBufferStatus bs;

  for (p = value; *p && !need_quotes; p++)
    {
      if (*p >= 32 && *p <= 126) /* CHAR but not CTL */
        switch (*p)
          {
            /* separators (RFC 2616) a.k.a tspecials (RFC 2068) */
          case '"': case '\\':
            value_len_growth++;
            /* FALLTHRU */
          case '(': case ')': case '<': case '>': case '@':
          case ',': case ';': case ':': /* see above for ESC and quote */
          case '/': case '[': case ']': case '?': case '=':
          case '{': case '}': case ' ': case '\t':
            need_quotes = TRUE;
            break;
          default:
            break;
          }
      else
        need_quotes = TRUE;
    }
  if (value_len_growth) /* malloc only when we have some ESCs or quotes
                         * to escape */
    {
      if ((new_value =
           ssh_malloc(ssh_ustrlen(value) + value_len_growth + 2))
          == NULL)
        return FALSE;

      for (p = value; *p;)
        {
          if (*p == '"' || *p == '\\')
            *new_value++ = '\\';
          *new_value++ = *p++;
        }
      *new_value = '\0';
    }
  else
    new_value = value;

  if (need_quotes)
    bs = ssh_buffer_append_cstrs(out_buffer,
                                 include_separator ? "; ": "",
                                 name, "=\"", new_value, "\"",
                                 NULL);
  else
    bs = ssh_buffer_append_cstrs(out_buffer,
                                 include_separator ? "; ": "",
                                 name, "=", new_value,
                                 NULL);

  if (value_len_growth)
    ssh_free(new_value);

  if (bs != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}

static void
ssh_http_server_format_reply(SshHttpServerConnection conn)
{
  const char *status_desc = ssh_http_status_to_string(conn->status);
  unsigned char buf[512];
  unsigned char *key;
  unsigned char *value;
  unsigned char *start, *end;

  ssh_snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\n",
               conn->status, status_desc);

  start = ssh_buffer_ptr(&conn->out_buffer)+ssh_buffer_len(&conn->out_buffer);

  if (ssh_buffer_append_cstrs(&conn->out_buffer, buf, NULL) != SSH_BUFFER_OK)
    goto failed;

  /* Can we leave the connection open?  In other words, does the
     client know the length of our content data?

      - for HTTP/0.9 requests, we must close the connection (and it is
        already marked to be closed)

      - for HTTP/1.0 requests, we must know the content length of the
        response

      - for HTTP/1.x protocol versions, we assume that everything is ok

     So, we must only check the HTTP/1.0 case here. */
  if (conn->major == 1 && conn->minor == 0)
    {
      /* The content data length must be known. */
      if (conn->w.content_length_known)
        {
          /* Then length of the content data is known. */
          ssh_snprintf(buf, sizeof(buf), "Content-Length: %u\r\n",
                       conn->w.content_length);
          if (ssh_buffer_append_cstrs(&conn->out_buffer, buf, NULL)
              != SSH_BUFFER_OK)
            goto failed;

          /* From our side, everything is ok for leaving the
             connection open if the client requested it and we are not
             doing an active close. */
          if (conn->req_keep_alive && !conn->close)
            {
              if (ssh_buffer_append_cstrs(&conn->out_buffer,
                                          "Connection: Keep-Alive\r\n", NULL)
                  != SSH_BUFFER_OK)
                goto failed;
            }
          else
            conn->close = TRUE;
        }
      else
        conn->close = TRUE;
    }

  if (conn->close)
    if (ssh_buffer_append_cstrs(&conn->out_buffer, "Connection: close\r\n",
                                NULL) != SSH_BUFFER_OK)
      goto failed;

  if (conn->w.chunked_transfer_encoding)
    if (ssh_buffer_append_cstrs(&conn->out_buffer,
                                "Transfer-Encoding: chunked\r\n",
                                NULL)
        != SSH_BUFFER_OK)
      goto failed;

  /* Insert all user-specified reply header fields. */
  for (ssh_http_kvhash_reset_index(conn->reply_header_fields);
       ssh_http_kvhash_get_next(conn->reply_header_fields, &key, &value); )
    if (ssh_buffer_append_cstrs(&conn->out_buffer, key, ": ", value, "\r\n",
                                NULL) != SSH_BUFFER_OK)
      goto failed;

  /* `Set-Cookie' headers. */
  if (conn->set_cookies)
    {
      unsigned int i;

      for (i = 0; i < conn->num_set_cookies; i++)
        {
          SshHttpSetCookie *cookie = &conn->set_cookies[i];

          /* The cookie management seems to be a mess.  There are
             three different specs about the issue:

               - http://www.netscape.com/newsref/std/cookie_spec.html
                 (Netscape)
               - RFC 2109 (Set-Cookie)
               - RFC 2965 (Set-Cookie2)

             This implementation does the best possible job to support
             them all.  Below, each Set-Cookie{,2} attribute is marked
             with a comment that describes what specification
             introduced the attribute. */

          /* Send each cookie as a separate header field. */
          if (ssh_buffer_append_cstrs(&conn->out_buffer,
                                      (cookie->set_cookie2
                                       ? "Set-Cookie2: " : "Set-Cookie: "),
                                      NULL) != SSH_BUFFER_OK)
            goto failed;

          /* NAME=VALUE */
          /* Konqueror note: the value should not be quoted, so the
             application should avoid special characters in the value */
          if (ssh_http_server_format_append_cookie_attribute(&conn->out_buffer,
                                                             cookie->name,
                                                             cookie->value,
                                                             FALSE)
              == FALSE)
            goto failed;
          /* Attributes. */

          /* `Comment' Set-Cookie */
          if (cookie->comment)
            if (ssh_http_server_format_append_cookie_attribute(
                                                           &conn->out_buffer,
                                                           ssh_ustr("Comment"),
                                                           cookie->comment,
                                                           TRUE)
                == FALSE)
              goto failed;

          /* `CommentURL' Set-Cookie2 */
          if (cookie->comment_url && cookie->set_cookie2)
            if (ssh_http_server_format_append_cookie_attribute(
                                           &conn->out_buffer,
                                           ssh_ustr("CommentURL"),
                                           cookie->comment_url,
                                           TRUE)
                == FALSE)
              goto failed;

          /* `Discard' Set-Cookie2 */
          if (cookie->discard && cookie->set_cookie2)
            if (ssh_buffer_append_cstrs(&conn->out_buffer, "; Discard", NULL)
                != SSH_BUFFER_OK)
              goto failed;

          /* `Domain' Netscape */
          if (cookie->domain)
            if (ssh_http_server_format_append_cookie_attribute(
                                                   &conn->out_buffer,
                                                   ssh_ustr("Domain"),
                                                   cookie->domain,
                                                   TRUE)
                == FALSE)
              goto failed;

          /* `Max-Age' Set-Cookie2 */
          /* Although Max-Age is a Set-Cookie2 attribute, we send it
             also for all responses. */
          if (cookie->max_age_given)
            {
              ssh_snprintf(buf, sizeof(buf), "%lu",
                           (unsigned long) cookie->max_age);
              /* Mozilla 0.9.8 note: no quotes allowed. */
              if (ssh_http_server_format_append_cookie_attribute(
                                                     &conn->out_buffer,
                                                     ssh_ustr("Max-Age"),
                                                     buf,
                                                     TRUE)
                  == FALSE)
                goto failed;
            }

          /* `Expires' Netscape Obsolete */
          if (cookie->expires)
            if (ssh_http_server_format_append_cookie_attribute(
                                                   &conn->out_buffer,
                                                   ssh_ustr("Expires"),
                                                   cookie->expires,
                                                   TRUE)
                == FALSE)
              goto failed;


          /* `Path' Netscape and Mozilla note: the value must not be a quoted
             string, although it typically contains slashes which technically
             should be quoted. */
          if (cookie->path)
            if (ssh_buffer_append_cstrs(&conn->out_buffer,
                                        "; Path=", cookie->path, NULL)
                != SSH_BUFFER_OK)
              goto failed;

          /* `Port' Set-Cookie2 */
          if (cookie->port && cookie->set_cookie2)
            if (ssh_http_server_format_append_cookie_attribute(
                                                   &conn->out_buffer,
                                                   ssh_ustr("Port"),
                                                   cookie->port,
                                                   TRUE)
                == FALSE)
              goto failed;

          /* `Secure' Netscape */
          if (cookie->secure)
            if (ssh_buffer_append_cstrs(&conn->out_buffer, "; Secure", NULL)
                != SSH_BUFFER_OK)
              goto failed;

          /* The `Version' Set-Cookie */
          if (ssh_buffer_append_cstrs(&conn->out_buffer, "; Version=1", NULL)
              != SSH_BUFFER_OK)
            goto failed;

          /* Is this the last cookie? */
          if (i + 1 < conn->num_set_cookies)
            /* No it is not.  Separate cookies with a ',' string. */
            if (ssh_buffer_append_cstrs(&conn->out_buffer, ",", NULL)
                != SSH_BUFFER_OK)
              goto failed;

          /* And terminate this line. */
          if (ssh_buffer_append_cstrs(&conn->out_buffer, "\r\n", NULL)
              != SSH_BUFFER_OK)
            goto failed;
        }
    }

  if (ssh_buffer_append_cstrs(&conn->out_buffer, "\r\n", NULL)
      != SSH_BUFFER_OK)
    goto failed;

  return;

 failed:
  /* On error, consume what was written */
  end = ssh_buffer_ptr(&conn->out_buffer) + ssh_buffer_len(&conn->out_buffer);
  ssh_buffer_consume_end(&conn->out_buffer, end - start);
  return;
}


static void
ssh_http_server_internal_error(SshHttpServerConnection conn)
{
  conn->close = TRUE;
  conn->w.eof_seen = TRUE;      /* No more data available. */
  conn->w.destroyed = TRUE;

  /* Cancel the possible `read request timeout'. */
  ssh_cancel_timeouts(ssh_http_server_read_req_timeout, conn);

  /* Schedule one `write response timeout'. */
  ssh_xregister_timeout(conn->ctx->write_response_timeout, 0,
                       ssh_http_server_write_response_timeout, conn);

  ssh_http_server_format_reply(conn);

  /* Append the message from the <conn->error_message> to the output
     buffer.  But not for the HEAD requests. We do not care about
     failure on this */
  if (conn->error_message != NULL)
    {
      if (conn->method == NULL || strcmp((char *)conn->method, "HEAD") != 0)
          (void) ssh_buffer_append(&conn->out_buffer,
                             ssh_buffer_ptr(conn->error_message),
                             ssh_buffer_len(conn->error_message));

      ssh_buffer_free(conn->error_message);
      conn->error_message = NULL;
    }

  conn->state = SSH_HTTP_CONN_USER_IO;

  ssh_http_server_connection_callback(SSH_STREAM_CAN_OUTPUT, conn);
}


static void
ssh_http_server_set_values_ap(SshHttpServerConnection conn,
                              va_list ap)
{
  int type;
  unsigned char *cp;
  SshHttpSetCookie *cookie;

  while ((type = va_arg(ap, int)) != SSH_HTTP_HDR_END)
    {
      switch (type)
        {
        case SSH_HTTP_HDR_CONNECTION_CLOSE:
          conn->close = TRUE;
          break;

          /* SSH_HTTP_HDR_USER_HTTP_1_0 is client-only */

        case SSH_HTTP_HDR_COOKIE_DISCARD:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_DISCARD");
          cookie->discard = TRUE;
          break;

        case SSH_HTTP_HDR_COOKIE_SECURE:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_SECURE");
          cookie->secure = TRUE;
          break;

        case SSH_HTTP_HDR_COOKIE_SEND_EXPIRES:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_SEND_EXPIRES");
          if (!cookie->max_age_given)
            ssh_fatal("ssh_http_server_set_values: "
                      "SSH_HTTP_HDR_COOKIE_SEND_EXPIRES called without "
                      "SSH_HTTP_HDR_COOKIE_MAX_AGE");
          if ((cookie->expires =
               ssh_http_make_rfc1123_date(ssh_time() +
                                          cookie->max_age))
              != NULL)
            {
              /* Yes, this is really a backwards compatibility hack. */
              cookie->expires[7] = '-';
              cookie->expires[11] = '-';
            }
          break;

        case SSH_HTTP_HDR_COOKIE_USE_SET_COOKIE2:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_USE_SET_COOKIE2");
          cookie->set_cookie2 = TRUE;
          break;

          /* SSH_HTTP_HDR_NO_EXPECT_100_CONTINUE is client-only */

          /* SSH_HTTP_HDR_SERVER_IS_HTTP_1_1 is client-only */

        case SSH_HTTP_HDR_CONTENT_LENGTH:
          conn->w.content_length_known = TRUE;
          conn->w.content_length = va_arg(ap, size_t);
          break;

        case SSH_HTTP_HDR_DATE:
          if ((cp = ssh_http_make_rfc1123_date(va_arg(ap, SshTime))) != NULL)
            ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                      ssh_custr("Date"), cp);
          ssh_free(cp);
          break;

        case SSH_HTTP_HDR_EXPIRES:
          if ((cp = ssh_http_make_rfc1123_date(va_arg(ap, SshTime))) != NULL)
            ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                      ssh_custr("Expires"), cp);
          ssh_free(cp);
          break;

        case SSH_HTTP_HDR_LAST_MODIFIED:
          if ((cp = ssh_http_make_rfc1123_date(va_arg(ap, SshTime))) != NULL)
            ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                      ssh_custr("Last-Modified"), cp);
          ssh_free(cp);
          break;

        case SSH_HTTP_HDR_COOKIE_MAX_AGE:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_MAX_AGE");
          cookie->max_age_given = TRUE;
          cookie->max_age = va_arg(ap, SshTime);
          break;

          /* SSH_HTTP_HDR_ACCEPT is a client-only */

          /* SSH_HTTP_HDR_HOST is a client-only */

        case SSH_HTTP_HDR_LOCATION:
          ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                    ssh_custr("Location"),
                                    va_arg(ap, unsigned char *));
          break;

        case SSH_HTTP_HDR_LOCATION_RELATIVE:
          {
            const unsigned char *v;
            char *loc;
            char *prefix;
            SshBufferStruct value;
            SshBufferStatus bs;

            v = ssh_http_kvhash_get(conn->req_header_fields,
                                    ssh_custr("HOST"));
            loc = va_arg(ap, char *);
            prefix = loc[0] == '/' ? "" : "/";

            ssh_buffer_init(&value);

            if (v)
              bs = ssh_buffer_append_cstrs(&value,
                                           "http://", v, prefix, loc,
                                           NULL);
            else
              bs = ssh_buffer_append_cstrs(&value,
                                           "http://",
                                           conn->ctx->server_name, ":",
                                           conn->ctx->port, prefix, loc,
                                           NULL);

            if (bs == SSH_BUFFER_OK)
              {
                v = ssh_buffer_ptr(&value);
                ssh_http_kvhash_put(conn->reply_header_fields,
                                    ssh_custr("Location"), 8,
                                    v, ssh_buffer_len(&value));
              }
            ssh_buffer_uninit(&value);
          }
          break;

        case SSH_HTTP_HDR_SERVER:
          ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                    ssh_custr("Server"),
                                    va_arg(ap, unsigned char *));
          break;

          /* SSH_HTTP_HDR_TE is a client-only */
          /* SSH_HTTP_HDR_USER_AGENT is a client-only */

        case SSH_HTTP_HDR_WWW_AUTHENTICATE_BASIC:
        case SSH_HTTP_HDR_PROXY_AUTHENTICATE_BASIC:
          {
            char *prefix = "Basic realm=\"";
            char *realm = va_arg(ap, char *);
            char *value;

            if ((value = ssh_malloc(strlen(prefix) + strlen(realm) + 2))
                == NULL)
              break;

            strcpy(value, prefix);
            strcat(value, realm);
            strcat(value, "\"");

            if (type == SSH_HTTP_HDR_WWW_AUTHENTICATE_BASIC)
              ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                        ssh_custr("WWW-Authenticate"),
                                        ssh_custr(value));
            else
              ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                        ssh_custr("Proxy-Authenticate"),
                                        ssh_custr(value));

            ssh_free(value);
          }
          break;

        case SSH_HTTP_HDR_COOKIE_COMMENT:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_COMMENT");
          cookie->comment = ssh_strdup(va_arg(ap, char *));
          break;

        case SSH_HTTP_HDR_COOKIE_COMMENT_URL:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_COMMENT_URL");
          cookie->comment_url = ssh_strdup(va_arg(ap, char *));
          break;

        case SSH_HTTP_HDR_COOKIE_DOMAIN:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_DOMAIN");
          cookie->domain = ssh_strdup(va_arg(ap, char *));
          break;

        case SSH_HTTP_HDR_COOKIE_PATH:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_PATH");
          cookie->path = ssh_strdup(va_arg(ap, char *));
          break;

        case SSH_HTTP_HDR_COOKIE_PORT:
          SET_VALUES_NEED_COOKIE("SSH_HTTP_HDR_COOKIE_PORT");
          cookie->port = ssh_strdup(va_arg(ap, char *));
          break;

          /* SSH_HTTP_HDR_AUTHORIZATION_DIGEST is a client-only */

        case SSH_HTTP_HDR_CONTENT_MD5:
          {
            char *value = (char *) ssh_buf_to_base64(va_arg(ap,
                                                            unsigned char *),
                                                     va_arg(ap, size_t));

            if (value)
              ssh_http_kvhash_put_cstrs(conn->reply_header_fields,
                                        ssh_custr("Content-MD5"),
                                        ssh_custr(value));
            ssh_free(value);
          }
          break;

        case SSH_HTTP_HDR_FIELD:
          {
            unsigned char *key = va_arg(ap, unsigned char *);
            unsigned char *val = va_arg(ap, unsigned char *);
            int i;

            /* Check the skip list. */
            for (i = 0; ssh_http_server_hdr_skip_list[i]; i++)
              if (ssh_usstrcasecmp(key, ssh_http_server_hdr_skip_list[i]) == 0)
                break;

            if (ssh_http_server_hdr_skip_list[i] == NULL)
              /* Accepted. */
              ssh_http_kvhash_put_cstrs(conn->reply_header_fields, key, val);
          }
          break;

        case SSH_HTTP_HDR_COOKIE:
          {
            char *name = va_arg(ap, char *);
            char *value = va_arg(ap, char *);
            void *tmp;

            if (conn->set_cookies == NULL)
              {
                if ((conn->set_cookies = ssh_malloc(sizeof(SshHttpSetCookie)))
                    != NULL)
                  conn->num_set_cookies = 1;
              }
            else
              {
                if ((tmp =
                     ssh_realloc(conn->set_cookies,
                                 conn->num_set_cookies *
                                 sizeof(SshHttpSetCookie),
                                 (conn->num_set_cookies + 1) *
                                 sizeof(SshHttpSetCookie))) != NULL)
                  {
                    conn->num_set_cookies++;
                    conn->set_cookies = tmp;

                    cookie = &conn->set_cookies[conn->num_set_cookies - 1];
                    memset(cookie, 0, sizeof(*cookie));

                    cookie->name = ssh_strdup(name);
                    cookie->value = ssh_strdup(value);
                  }
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
            for (i = 0; ssh_http_server_hdr_skip_list[i]; i++)
              if (strlen(ssh_http_server_hdr_skip_list[i]) == key_len
                  && ssh_usstrncasecmp(key, ssh_http_server_hdr_skip_list[i],
                                       key_len) == 0)
                break;

            if (ssh_http_server_hdr_skip_list[i] == NULL)
              /* Accepted. */
              ssh_http_kvhash_put(conn->reply_header_fields,
                                  key, key_len, val, val_len);
          }
          break;

        default:
          ssh_http_hdr_skip_next(ap, type);
          break;
        }
    }
}


/*
 * Streams.
 */

/* The read-only `Content Data Read' stream. */

static int
ssh_http_server_content_read_read(void *context, unsigned char *buf,
                                  size_t size)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;
  size_t avail;

  avail = ssh_buffer_len(&conn->in_buffer);
  if (avail == 0)
    {
      if (conn->r.end_of_content_data)
        /* EOF */
        return 0;

      /* We would block.  Let's register a timeout that will be called
         from the bottom of the event loop.  The timeout will signal
         the HTTP connection stream to get us a bit more data. */
      SSH_DEBUG(9, ("Asking more input from the client"));
      conn->r.blocked = TRUE;
      ssh_xregister_timeout(0, 0, ssh_http_server_read_more_input_timeout,
                           conn);

      /* And wait for that notificaition. */
      return -1;
    }

  /* We have some data in the buffer. */
  if (avail > size)
    avail = size;

  memcpy(buf, ssh_buffer_ptr(&conn->in_buffer), avail);
  ssh_buffer_consume(&conn->in_buffer, avail);

  return avail;
}


static int
ssh_http_server_content_read_write(void *context, const unsigned char *buf,
                                   size_t size)
{
  /* The stream is read-only. */
  return 0;
}


static void
ssh_http_server_content_read_output_eof(void *context)
{
  /* The stream is read-only. */
}


static void
ssh_http_server_content_read_set_callback(void *context,
                                          SshStreamCallback callback,
                                          void *callback_context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  conn->r.callback = callback;
  conn->r.callback_context = callback_context;
}


static void
ssh_http_server_content_read_destroy(void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  /* Cleanup. */
  conn->r.callback = NULL_FNPTR;
  conn->r.callback_context = NULL;
}


static const SshStreamMethodsStruct
ssh_http_server_content_read_methods_table =
{
  ssh_http_server_content_read_read,
  ssh_http_server_content_read_write,
  ssh_http_server_content_read_output_eof,
  ssh_http_server_content_read_set_callback,
  ssh_http_server_content_read_destroy,
};


static SshStream
ssh_http_server_content_read_stream(SshHttpServerConnection conn)
{
  return ssh_stream_create(&ssh_http_server_content_read_methods_table, conn);
}


/* The write-only `Content Data Write' stream. */

static int
ssh_http_server_content_write_read(void *context, unsigned char *buf,
                                  size_t size)
{
  /* The stream is write-only. */
  return 0;
}


static void
ssh_http_server_write_flush_buffer_timeout(void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;
  ssh_http_server_connection_callback(SSH_STREAM_CAN_OUTPUT, conn);
}


static int
ssh_http_server_content_write_write(void *context, const unsigned char *buf,
                                   size_t size)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;
  int avail;

  /* Is this the first write?  If so, we must send the HTTP reply
     header. */
  if (!conn->w.header_sent)
    {
      ssh_http_server_format_reply(conn);
      conn->w.header_sent = TRUE;
    }

  if (conn->w.eof_seen)
    /* We are very much finished here.  The client has closed the
       connection. */
    return 0;

  /* Can we output anything? */
  avail = (SSH_HTTP_BUFFER_SIZE - ssh_buffer_len(&conn->out_buffer));

  if (avail <= 0 || size == 0)  /* FLUSH: size == 0 */
    {
      /* The buffer has no space, or the <size> is 0 which is an
         explicit flush request. */

      if (size != 0 || avail < SSH_HTTP_BUFFER_SIZE)
        /* Order a timeout to flush some space to the buffer.  But for
           the explicit flushes, order the timout only if we have
           something to write. */
        ssh_xregister_timeout(0, 0, ssh_http_server_write_flush_buffer_timeout,
                             conn);

      SSH_DEBUG(9, ("Would block"));
      return -1;
    }

  if (size > (size_t)avail)
    size = avail;

  if (!conn->is_head)
    if (ssh_buffer_append(&conn->out_buffer, buf, size) != SSH_BUFFER_OK)
      return 0;

  return size;
}


static void
ssh_http_server_content_write_output_eof(void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  conn->w.eof_seen = TRUE;

  if (ssh_buffer_len(&conn->out_buffer) > 0)
    ssh_xregister_timeout(0, 0, ssh_http_server_write_flush_buffer_timeout,
                         conn);
}


static void
ssh_http_server_content_write_set_callback(void *context,
                                          SshStreamCallback callback,
                                          void *callback_context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  conn->w.callback = callback;
  conn->w.callback_context = callback_context;
}


static void
ssh_http_server_content_write_destroy(void *context)
{
  SshHttpServerConnection conn = (SshHttpServerConnection) context;

  conn->w.eof_seen = TRUE;
  conn->w.destroyed = TRUE;

  /* Order a timeout to flush our output buffer, and eventually, to
     finish this connection. */
  ssh_xregister_timeout(0, 0, ssh_http_server_write_flush_buffer_timeout,
                        conn);
}


static const SshStreamMethodsStruct
ssh_http_server_content_write_methods_table =
{
  ssh_http_server_content_write_read,
  ssh_http_server_content_write_write,
  ssh_http_server_content_write_output_eof,
  ssh_http_server_content_write_set_callback,
  ssh_http_server_content_write_destroy,
};


static SshStream
ssh_http_server_content_write_stream(SshHttpServerConnection conn)
{
  return ssh_stream_create(&ssh_http_server_content_write_methods_table,
                           conn);
}


/* The read-write `User Interface' stream. */

static int
ssh_http_server_ui_read(void *context, unsigned char *buf, size_t size)
{
  SshHttpServerUiStream *stream_ctx = (SshHttpServerUiStream *) context;
  int got;

  got = ssh_stream_read(stream_ctx->read_s, buf, size);
  if (got == 0)
    /* EOF reached. */
    stream_ctx->read_s_at_eof = TRUE;

  return got;
}


static int
ssh_http_server_ui_write(void *context, const unsigned char *buf,
                         size_t size)
{
  SshHttpServerUiStream *stream_ctx = (SshHttpServerUiStream *) context;

  stream_ctx->written = TRUE;

  return ssh_stream_write(stream_ctx->write_s, buf, size);
}


static void
ssh_http_server_ui_output_eof(void *context)
{
  SshHttpServerUiStream *stream_ctx = (SshHttpServerUiStream *) context;

  ssh_stream_output_eof(stream_ctx->write_s);
}


static void
ssh_http_server_ui_set_callback(void *context, SshStreamCallback callback,
                                void *callback_context)
{
  SshHttpServerUiStream *stream_ctx = (SshHttpServerUiStream *) context;

  stream_ctx->callback = callback;
  stream_ctx->callback_context = callback_context;
}


static void
ssh_http_server_ui_real_destroy(SshHttpServerUiStream *stream_ctx)
{
  /* Destroy the io streams. */
  ssh_stream_destroy(stream_ctx->read_s);
  ssh_stream_destroy(stream_ctx->write_s);

  /* And clear this stream handle. */
  ssh_free(stream_ctx);
}

/* Context for the smart byte-sink. */
struct SshHttpServerSmartByteSinkRec
{
  SshHttpServerUiStream *stream_ctx;

  /* Output data. */
  SshBuffer buffer;

  /* A temporary buffer for input data - just to save stack. */
  unsigned char buf[1024];

  /* Is the read EOF seen? */
  Boolean read_eof;
};

typedef struct SshHttpServerSmartByteSinkRec SshHttpServerSmartByteSink;


/* A forward declaration for the byte-sink's `write response' timeout. */
static void ssh_http_server_byte_sink_write_response_timeout(void *context);


static void
ssh_http_server_byte_sink_callback(SshStreamNotification notification,
                                   void *context)
{
  SshHttpServerSmartByteSink *byte_sink;
  int i;
  Boolean wrote = FALSE;

  byte_sink = (SshHttpServerSmartByteSink *) context;

  /* Read all we can. */
  while (!byte_sink->read_eof)
    {
      i = ssh_stream_read(byte_sink->stream_ctx->read_s, byte_sink->buf,
                          sizeof(byte_sink->buf));
      if (i == 0)
        {
          /* EOF reached.  All content data read. */
          byte_sink->read_eof = TRUE;
          break;
        }
      if (i < 0)
        /* We would block. */
        break;

      /* Read more. */
    }

  /* Write if any. */
  while (byte_sink->buffer && ssh_buffer_len(byte_sink->buffer) > 0)
    {
      i = ssh_stream_write(byte_sink->stream_ctx->write_s,
                           ssh_buffer_ptr(byte_sink->buffer),
                           ssh_buffer_len(byte_sink->buffer));
      if (i == 0)
        {
          /* Client has closed connection. */
          SSH_DEBUG(SSH_D_FAIL, ("Write: EOF"));
          break;
        }
      else if (i < 0)
        {
          /* Would block. */
          return;
        }
      else
        {
          ssh_buffer_consume(byte_sink->buffer, i);
          wrote = TRUE;
        }
    }

  /* Make our writes flushed. */
  if (wrote)
    (void) ssh_stream_write(byte_sink->stream_ctx->write_s,
                            (unsigned char *) "", 0);

  if (!byte_sink->read_eof)
    /* We must still read some data. */
    return;

  /* All done. */

  /* Cancel the byte-sink `write response' timeout. */
  ssh_cancel_timeouts(ssh_http_server_byte_sink_write_response_timeout,
                      byte_sink);

  ssh_http_server_ui_real_destroy(byte_sink->stream_ctx);
  if (byte_sink->buffer)
    ssh_buffer_free(byte_sink->buffer);

  ssh_free(byte_sink);
}


static void
ssh_http_server_byte_sink_write_response_timeout(void *context)
{
  SshHttpServerSmartByteSink *byte_sink;

  SSH_DEBUG(SSH_D_HIGHOK, ("Closing the connection"));
  byte_sink = (SshHttpServerSmartByteSink *) context;

  byte_sink->read_eof = TRUE;
  if (byte_sink->buffer)
    ssh_buffer_clear(byte_sink->buffer);

  /* This is an error condition.  We must close this connection. */
  byte_sink->stream_ctx->conn->close = TRUE;

  /* Let the byte-sink callback finish us. */
  ssh_http_server_byte_sink_callback(SSH_STREAM_CAN_OUTPUT, byte_sink);
}


static void
ssh_http_server_ui_destroy(void *context)
{
  SshHttpServerUiStream *stream_ctx = (SshHttpServerUiStream *) context;

  /* If the input stream has not been read to EOF and we want to keep
     the connection open, or the user has not wrote to the output
     stream, spawn a smart byte-sink that possibly consumes the
     request or writes the response header fields.  The byte-sink will
     eventually destroy the UI stream. */
  if ((!stream_ctx->read_s_at_eof && !stream_ctx->conn->close)
      || !stream_ctx->written)
    {
      SshHttpServerSmartByteSink *byte_sink;

      if ((byte_sink = ssh_calloc(1, sizeof(*byte_sink))) == NULL)
        {
          ssh_http_server_ui_real_destroy(stream_ctx);
          return;
        }

      SSH_DEBUG(6, ("Spawning smart byte-sink:%s%s",
                    stream_ctx->read_s_at_eof ? "" : " read",
                    stream_ctx->written ? "" : " write"));

      byte_sink->stream_ctx = stream_ctx;

      if (!stream_ctx->written)
        {
          /* The user has not written anything.  This is an error, or
             the response does not have any content data. */

          if (stream_ctx->conn->error_message == NULL)
            {
              /* No user error message given.  The response really has
                 an empty content data.  Let's perform an empty write
                 to the output stream.  This will flush the headers to
                 the client. */

              /* User might have optimized this in the HEAD requests.
                 Let's overwrite it only if it is unset. */
              if (!stream_ctx->conn->w.content_length_known)
                {
                  stream_ctx->conn->w.content_length_known = TRUE;
                  stream_ctx->conn->w.content_length = 0;
                }

              /* This will send the headers to the client. */
              (void) ssh_stream_write(stream_ctx->write_s, NULL, 0);
            }
          else
            {
              /* This is an error from the user. */

              byte_sink->buffer = stream_ctx->conn->error_message;
              stream_ctx->conn->error_message = NULL;

              /* We know the content length. */
              stream_ctx->conn->w.content_length_known = TRUE;
              stream_ctx->conn->w.content_length
                = ssh_buffer_len(byte_sink->buffer);
            }
        }
      else
        {
          /* User has generated the output.  Just flush it. */
          (void) ssh_stream_write(stream_ctx->write_s,
                                  (unsigned char *) "", 0);
        }

      /* Order a `write response timeout'. */
      ssh_xregister_timeout(stream_ctx->conn->ctx->write_response_timeout, 0,
                            ssh_http_server_byte_sink_write_response_timeout,
                            byte_sink);

      /* And set the callback functions for the UI read and write
         streams. */
      ssh_stream_set_callback(stream_ctx->read_s,
                              ssh_http_server_byte_sink_callback, byte_sink);
      ssh_stream_set_callback(stream_ctx->write_s,
                              ssh_http_server_byte_sink_callback, byte_sink);
      ssh_http_server_byte_sink_callback(SSH_STREAM_CAN_OUTPUT, byte_sink);
    }
  else
    /* Destroy us now. */
    ssh_http_server_ui_real_destroy(stream_ctx);
}


static const SshStreamMethodsStruct
ssh_http_server_ui_methods_table =
{
  ssh_http_server_ui_read,
  ssh_http_server_ui_write,
  ssh_http_server_ui_output_eof,
  ssh_http_server_ui_set_callback,
  ssh_http_server_ui_destroy,
};


static void
ssh_http_server_ui_stream_io_callback(SshStreamNotification notification,
                                      void *context)
{
  SshHttpServerUiStream *stream_ctx = (SshHttpServerUiStream *) context;

  if (stream_ctx->callback)
    (*stream_ctx->callback)(notification, stream_ctx->callback_context);
}


static SshStream
ssh_http_server_ui_stream(SshHttpServerConnection conn, SshStream read_s,
                          SshStream write_s)
{
  SshHttpServerUiStream *stream_ctx;
  SshStream str;
  if ((stream_ctx = ssh_calloc(1, sizeof(*stream_ctx))) == NULL)
    {
      ssh_stream_destroy(read_s);
      ssh_stream_destroy(write_s);
      return NULL;
    }

  stream_ctx->conn = conn;
  stream_ctx->read_s = read_s;
  stream_ctx->write_s = write_s;

  ssh_stream_set_callback(stream_ctx->read_s,
                          ssh_http_server_ui_stream_io_callback, stream_ctx);
  ssh_stream_set_callback(stream_ctx->write_s,
                          ssh_http_server_ui_stream_io_callback, stream_ctx);

  if ((str = ssh_stream_create(&ssh_http_server_ui_methods_table,
                               stream_ctx)) == NULL)
    {
      ssh_stream_destroy(read_s);
      ssh_stream_destroy(write_s);
      ssh_free(stream_ctx);
      return NULL;
    }
  return str;
}

size_t
ssh_http_server_content_data_read(SshHttpServerConnection conn)
{
  return conn->r.content_data_read;
}

/* Returns a pointer to the connection stream of the connection. */
SshStream
ssh_http_server_get_connection_stream(SshHttpServerConnection conn)
{
  if (!conn)
    return NULL;
  return conn->stream;
}

void *
ssh_http_server_get_connection_appdata(SshHttpServerConnection conn)
{
  return conn ? conn->appdata : NULL;
}

void *
ssh_http_server_set_connection_appdata(SshHttpServerConnection conn,
                                       void *appdata)
{
  void *ret = conn ? conn->appdata : NULL;

  if (conn != NULL)
    conn->appdata = appdata;

  return ret;
}
#endif /* SSHDIST_HTTP_SERVER */
