/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public interface to the SSH HTTP/1.1 library.  The library
   implements HTTP protocols 0.9, 1.0 and 1.1 (RFC 2616).
*/

#ifndef SSHHTTP_H
#define SSHHTTP_H

#include "sshtcp.h"
#include "sshstream.h"
#include "sshbuffer.h"
#include "sshoperation.h"
#include "sshhttp_status.h"

/*
 * Types and definitions.
 */

/* Wildcard selectors for the ssh_http_server_remove_handlers()
   function. */
#define SSH_HTTP_ALL_PATTERNS       ((unsigned char *) 1)
#define SSH_HTTP_ALL_HANDLERS       ((SshHttpServerUriHandler) 1)
#define SSH_HTTP_ALL_VOID_HANDLERS  ((SshHttpServerVoidUriHandler) 1)
#define SSH_HTTP_ALL_CONTEXTS       ((void *) 1)

/* HTTP client context. */
typedef struct SshHttpClientContextRec *SshHttpClientContext;

/* HTTP server context. */
typedef struct SshHttpServerContextRec *SshHttpServerContext;

/* A connection to the HTTP server. */
typedef struct SshHttpServerConnectionRec *SshHttpServerConnection;



/* The TCP/IP stream wrapper functions.  If the wrapper function is set
   for a server or client, it is called to wrap the native TCP/IP
   stream.  The function must return a valid SshStream that is used in
   place of the original stream <stream>. */

typedef SshStream (*SshHttpServerTcpStreamWrapper)(SshHttpServerConnection
                                                   conn,
                                                   SshStream stream,
                                                   void *context);

typedef SshStream (*SshHttpClientTcpStreamWrapper)(SshHttpClientContext
                                                   client,
                                                   SshStream stream,
                                                   void *context);

/* HTTP client parameters.  Caller can free everything after the
   ssh_http_client_init() call. */
typedef struct SshHttpClientParamsRec
{
  /* Socks server/port/exceptions. */
  unsigned char *socks;

  /* HTTP proxy URL. */
  unsigned char *http_proxy_url;

  /* TCP/IP stream wrapper.  This is called after the client has
     connected to the server but before any data has been read /
     written to the TCP/IP stream. */
  SshHttpClientTcpStreamWrapper tcp_wrapper;
  void *tcp_wrapper_context;

  /* The maximum time to wait for connection to establish (for tcp) */
  SshUInt32 tcp_connect_timeout;


  /* User name.  If <user_name> or <password> is NULL, the connection
     will fail if an authentication is required. */
  unsigned char *user_name;

  /* Password to use with <user_name>. */
  unsigned char *password;

  /* Use the HTTP/1.0 protocol.  The default is HTTP/1.1. */
  Boolean use_http_1_0;

 /* If the server responds with a 3xx redirection code, this option
    specifies how many redirections are followed.  The default 0 means
    that no redirections are followed. */
  SshUInt32 num_redirections;

  /* The maximum number of retries performed for each request.  The
     default 0 means that no retries are made. */
  SshUInt32 num_retries;

  /* The maximum number of data buffered in memory.  The default value
     is 8192 bytes.  This option limits, among other things, the
     maximum line length in the HTTP response. */
  size_t max_buffer_size;

  /* The maximum time to wait for server's `100 Continue' response. */
  SshUInt32 expect_100_continue_timeout;

} SshHttpClientParams, *SshHttpClientParamsPtr;


/* A message formatter function.  The message formatter function is
   called to format a report that describes the HTTP status
   <status_code>.  The report must be stored into the buffer <buffer>.
   The argument <conn> is the current connection.  It can be used to
   retrieve request header fields, requested URI, and other connection
   related values.  The argument <ap> holds additional HTTP header
   fields and values, coded as a SshHttpHeaderFieldSelector list. */
typedef void (*SshHttpServerMessageFormatter)(SshHttpServerConnection conn,
                                              SshBuffer buffer,
                                              SshUInt32 status_code,
                                              va_list ap,
                                              void *context);

/* HTTP server parameters.  Caller can free everything after the
   ssh_http_server_start() call. */
typedef struct SshHttpServerParamsRec
{
  /* The soft limit for the maximum number of concurrent connections.
     If a new connection is initiated and it would exceed the soft
     limit, a `530 Service Unavailable' error will be reported to the
     client. */
  SshUInt32 num_connections_soft_limit;

  /* The hard limit for the maximum number of concurrent connections.
     If a new connection is initiated and it would exceed the hard
     limit, the connection is closed unconditionally. */
  SshUInt32 num_connections_hard_limit;

  /* The maximum time that we allow for reading a request from a
     client.  The timeout is given in seconds. */
  SshUInt32 read_request_timeout;

  /* The maximum time that we will wait for a response to be written
     to a client.  The timeout is given in seconds. */
  SshUInt32 write_response_timeout;

  /* How long time a `Keep-Alive' connection is kept open if new
     requests are not seen.  The timeout is given in seconds. */
  SshUInt32 keep_open_timeout;

  /* The maximum amount (number of lines) of header fields a client can
     send to the server. If this value is exceeded, the request is
     denied. The default value is 500. */
  SshUInt32 max_req_header_field_count;

  /* The maximum amount (number of bytes) of data a client can send to
     the server. If this value is exceeded, the connection will be
     closed unconditionally. The default value is 1000000. */
  SshUInt32 max_input_data_length;

  /* Local address to which the server is bind.  The default address
     is SSH_IPADDR_ANY. */
  unsigned char *address;

  /* The port that the server will listen to.  The default port is
     80. */
  unsigned char *port;

  /* TCP/IP stream wrapper to be used with this server.  If the
     wrapper function <tcp_wrapper> is not NULL, it is called for each
     incoming connection. */
  SshHttpServerTcpStreamWrapper tcp_wrapper;
  void *tcp_wrapper_context;

  /* The message formatter function for the this server.  The HTTP
     server implements a default message formatter than creates
     English reports about all HTTP status codes.  You can set a new
     message formatter to translate the messages to other
     languages. */
  SshHttpServerMessageFormatter message_formatter;
  void *message_formatter_context;

  /* The hostname of the server.  This is used in the
     SSH_HTTP_HDR_LOCATION_RELATIVE header field selector if the
     request did not contain the `Host' header field.  If the
     <server_name> is NULL, the library will use the
     ssh_tcp_get_host_name() function. */
  unsigned char *server_name;
} SshHttpServerParams, *SshHttpServerParamsPtr;

/* An HTTP cookie that a client returns to a server in the `Cookie'
   header field. */
typedef struct SshHttpCookieRec
{
  unsigned char *name;                   /* NAME */
  unsigned char *value;                  /* VALUE */
  unsigned char *path;                   /* $Path */
  unsigned char *domain;                 /* $Domain */
  unsigned char *port;                   /* $Port */
} SshHttpCookie, *SshHttpCookiePtr;

typedef struct SshHttpCookieRec const *SshHttpCookiePtrConst;

/* An HTTP cookie set request that a server sends to a client in the
   `Set-Cookie{,2}' header field. */
struct SshHttpSetCookieRec
{
  Boolean set_cookie2;          /* Was this a `Set-Cookie2' cookie? */
  unsigned char *name;          /* NAME */
  unsigned char *value;         /* VALUE */
  unsigned char *comment;       /* Comment */
  unsigned char *comment_url;   /* CommentURL */
  Boolean discard;              /* Discard */
  unsigned char *domain;        /* Domain */
  Boolean max_age_given;        /* Is the Max-Agen given? */
  SshTime max_age;              /* Max-Age */
  unsigned char *expires;       /* Backwards compatiblity: `Expires'. */
  unsigned char *path;          /* Path */
  unsigned char *port;          /* Port */
  Boolean secure;               /* Secure */
};

typedef struct SshHttpSetCookieRec SshHttpSetCookie, *SshHttpSetCookiePtr;


/* HTTP operation result codes. */
typedef enum
{
  SSH_HTTP_RESULT_SUCCESS,
  SSH_HTTP_RESULT_MALFORMED_URL,
  SSH_HTTP_RESULT_UNSUPPORTED_PROTOCOL,
  SSH_HTTP_RESULT_CONNECT_FAILED,
  SSH_HTTP_RESULT_CONNECTION_CLOSED,
  SSH_HTTP_RESULT_MALFORMED_REPLY_HEADER,
  SSH_HTTP_RESULT_BROKEN_REDIRECT,
  SSH_HTTP_RESULT_REDIRECT_LIMIT_EXCEEDED,
  SSH_HTTP_RESULT_REDIRECT_WITHOUT_LOCATION,
  SSH_HTTP_RESULT_HTTP_ERROR,
  SSH_HTTP_RESULT_MAXIMUM_BUFFER_SIZE_REACHED,
  SSH_HTTP_RESULT_ABORTED,
  SSH_HTTP_RESULT_AUTHORIZATION_FAILED,
  SSH_HTTP_RESULT_PROXY_AUTHORIZATION_FAILED,
  SSH_HTTP_RESULT_BROKEN_SERVER
} SshHttpResult;

/* The authentication types. */
typedef enum
{
  SSH_HTTP_AUTHENTICATION_NONE,
  SSH_HTTP_AUTHENTICATION_BASIC
} SshHttpAuthentication;

/* HTTP selectors. */
typedef enum
{
  /* 0xx selectors which do not take arguments. */
  SSH_HTTP_HDR_CONNECTION_CLOSE         = 1,
  SSH_HTTP_HDR_USE_HTTP_1_0,
  SSH_HTTP_HDR_COOKIE_DISCARD,
  SSH_HTTP_HDR_COOKIE_SECURE,
  SSH_HTTP_HDR_COOKIE_SEND_EXPIRES,
  SSH_HTTP_HDR_COOKIE_USE_SET_COOKIE2,
  SSH_HTTP_HDR_NO_EXPECT_100_CONTINUE,
  SSH_HTTP_HDR_SERVER_IS_HTTP_1_1,

  /* 1xx selectors which take a `size_t' argument. */
  SSH_HTTP_HDR_CONTENT_LENGTH           = 101,

  /* 2xx selectors which take a `SshTime' argument. */
  SSH_HTTP_HDR_DATE                     = 201,
  SSH_HTTP_HDR_EXPIRES,
  SSH_HTTP_HDR_LAST_MODIFIED,
  SSH_HTTP_HDR_COOKIE_MAX_AGE,

  /* 3xx selectors which take a '\0' terminated string argument. */
  SSH_HTTP_HDR_ACCEPT                   = 301,
  SSH_HTTP_HDR_HOST,
  SSH_HTTP_HDR_LOCATION,
  SSH_HTTP_HDR_LOCATION_RELATIVE,
  SSH_HTTP_HDR_SERVER,
  SSH_HTTP_HDR_TE,
  SSH_HTTP_HDR_USER_AGENT,
  SSH_HTTP_HDR_WWW_AUTHENTICATE_BASIC,
  SSH_HTTP_HDR_PROXY_AUTHENTICATE_BASIC,
  SSH_HTTP_HDR_COOKIE_COMMENT,
  SSH_HTTP_HDR_COOKIE_COMMENT_URL,
  SSH_HTTP_HDR_COOKIE_DOMAIN,
  SSH_HTTP_HDR_COOKIE_PATH,
  SSH_HTTP_HDR_COOKIE_PORT,
  SSH_HTTP_HDR_BAD_REQUEST_REASON,
  SSH_HTTP_HDR_ACCEPT_CHARSET,
  SSH_HTTP_HDR_ACCEPT_ENCODING,
  SSH_HTTP_HDR_ACCEPT_LANGUAGE,

  /* 4xx selectors which take a `unsigned char *, size_t' pair
     argument. */
  SSH_HTTP_HDR_AUTHORIZATION_DIGEST     = 401,
  SSH_HTTP_HDR_CONTENT_MD5,

  /* 5xx selectors which take two '\0' terminated string arguments. */
  SSH_HTTP_HDR_FIELD                    = 501,
  SSH_HTTP_HDR_COOKIE,

  /* 6xx selectors which take two `unsigned char *, size_t' pair
     arguments. */
  SSH_HTTP_HDR_FIELD_LEN                = 601,

  /* End of header selectors. */
  SSH_HTTP_HDR_END                      = 0
} SshHttpHeaderFieldSelector;

/* The client connect callback function.  The function is called for
   ssh_http_post_stream(), and ssh_http_put_stream() functions when
   the client has connected to the server.  The argument <stream> can
   be used to write the request content data to the server.  When the
   content data has been written, the stream must be destroyed.  The
   result of the query is returned through the SshHttpClientresultCb
   function. */
typedef void (*SshHttpClientConnectCb)(SshHttpClientContext ctx,
                                       SshStream stream,
                                       void *callback_context);

/* The client callback function.  This callback function is called
   after each HTTP operation.  The argument <result> specifies the
   success status of the operation.  The argument <ip_error> contains
   the IP level error code when it is available.  If the operation was
   successfull, the argument <stream> can be used to read the content
   data of the reply.  The stream <stream> must be destroyed when the
   client has processed the data. */
typedef void (*SshHttpClientResultCb)(SshHttpClientContext ctx,
                                      SshHttpResult result,
                                      SshTcpError ip_error,
                                      SshStream stream,
                                      void *callback_context);

/* A handler callback for an URI.  The handler function will be called
   when its match pattern matches the URI of the incoming request.
   The requested URI and all the request fields and attributes can be
   accessed through the connection handle <conn>.  If the handler
   function returns TRUE, the server assumes that the handler function
   processed the request and no further processing is done.  If the
   handler function returns FALSE, the server assumes that the handler
   function did not handle the requests and it passes the request to
   the next matching (lower priority) URI handler function. */
typedef Boolean (*SshHttpServerUriHandler)(SshHttpServerContext ctx,
                                           SshHttpServerConnection conn,
                                           SshStream stream, void *context);

/* Like SshHttpServerUriHandler, but the handler function returns nothing.
   The server always assumes that the handler function processed the
   request and no further processing is done. */
typedef void (*SshHttpServerVoidUriHandler)(SshHttpServerContext ctx,
                                            SshHttpServerConnection conn,
                                            SshStream stream, void *context);

typedef void (*SshHttpServerStoppedCb)(SshHttpServerContext ctx,
                                       void *context);



/*
 * Prototypes for global client functions.
 */

/* Allocate and initialize an HTTP client contex. */
SshHttpClientContext ssh_http_client_init(SshHttpClientParamsPtr params);

/* Destroy an HTTP client context.  The function aborts all active
   requests. */
void ssh_http_client_uninit(SshHttpClientContext ctx);

/* Perform an HTTP get request for URL <url>.  The function calls the
   callback function <callback> to notify about the success of the
   request.  Additional options and header fields can be given as a
   SshHttpHeaderFieldSelector list after the <callback_context>. */
SshOperationHandle ssh_http_get(SshHttpClientContext ctx,
                                const unsigned char *url,
                                SshHttpClientResultCb callback,
                                void *callback_context,
                                ...);

/* Perform an HTTP head request for URL <url>.  The function calls the
   callback function <callback> to notify about the success of the
   request.  Additional options and header fields can be given as a
   SshHttpHeaderFieldSelector list after the <callback_context>. */
SshOperationHandle ssh_http_head(SshHttpClientContext ctx,
                                 const unsigned char *url,
                                 SshHttpClientResultCb callback,
                                 void *callback_context,
                                 ...);

/* Perform an HTTP post request for URL <url>.  The content data of
   the request is given in the argument <content_data> and its length
   is specified in the argumet <content_data_len>.  The function calls
   the callback function <callback> to notify about the success of the
   request.  Additional options and header fields can be given as a
   SshHttpHeaderFieldSelector list after the <callback_context>. */
SshOperationHandle ssh_http_post(SshHttpClientContext ctx,
                                 const unsigned char *url,
                                 const unsigned char *content_data,
                                 size_t content_data_len,
                                 SshHttpClientResultCb callback,
                                 void *callback_context,
                                 ...);

/* Perform an HTTP post request for URL <url>.  The content data of
   the request is given through the <connect_callback> function.  The
   function calls the callback function <callback> to notify about the
   success of the request.  Additional options and header fields can
   be given as a SshHttpHeaderFieldSelector list after the
   <callback_context>. */
SshOperationHandle ssh_http_post_stream(
                                SshHttpClientContext ctx,
                                const unsigned char *url,
                                SshHttpClientConnectCb connect_callback,
                                void *connect_context,
                                SshHttpClientResultCb result_callback,
                                void *result_context,
                                ...);

/* Perform an HTTP put request for URL <url>.  The content data of the
   request is given in the argument <content_data> and its length is
   specified in the argumet <content_data_len>.  The function calls
   the callback function <callback> to notify about the success of the
   request.  Additional options and header fields can be given as a
   SshHttpHeaderFieldSelector list after the <callback_context>. */
SshOperationHandle ssh_http_put(SshHttpClientContext ctx,
                                const unsigned char *url,
                                const unsigned char *content_data,
                                size_t content_data_len,
                                SshHttpClientResultCb callback,
                                void *callback_context,
                                ...);

/* Perform an HTTP put request for URL <url>.  The content data of the
   request is given through the <connect_callback> function.  The
   function calls the callback function <callback> to notify about the
   success of the request.  Additional options and header fields can
   be given as a SshHttpHeaderFieldSelector list after the
   <callback_context>. */
SshOperationHandle ssh_http_put_stream(SshHttpClientContext ctx,
                                       const unsigned char *url,
                                       SshHttpClientConnectCb connect_callback,
                                       void *connect_context,
                                       SshHttpClientResultCb result_callback,
                                       void *result_context,
                                       ...);

/* Get the status code of the latest HTTP response.  The function can
   be used to determine the reason why an HTTP operation failed when
   the callback function is called with the value
   SSH_HTTP_RESULT_HTTP_ERROR.  A human readable description string of
   the status code is returned in the argument <reason_phrase_return>.
   The value of the reason pharase is the reason string that the
   server returned for the status code.  Its value is valid as long as
   the control is in the client callback. */
SshUInt32 ssh_http_get_status_code(SshHttpClientContext ctx,
                                   const unsigned char **reason_phrase_return);

/* Get the value of the response header field <field>.  The function
   returns the value as a '\0' terminated strings or NULL if the field
   <field> is undefined.  The function can be called from the
   SshHttpClientResultCb callback function.  The returned value is
   valid as long as the control is in the client callback.  */
const unsigned char *ssh_http_get_header_field(SshHttpClientContext ctx,
                                               const unsigned char *field);

/* Return the `Set-Cookie' requests of the response.  The function
   returns a pointer to an array of set cookie requests.  The number
   of the requests in the array is returned in <num_return>.  If the
   response did not have any `Set-Cookie' requests, the <num_return>
   is set to 0 and the function returns a NULL pointer. */
const SshHttpSetCookie *ssh_http_get_cookies(SshHttpClientContext ctx,
                                             unsigned int *num_return);

/* Set fields and properties of for the next request according to the
   SshHttpHeaderFieldSelector arguments <...>.  You can call the
   ssh_http_set_values() function multiple times.  All the properties
   apply for the next request that is started with the method
   functions. */
void ssh_http_set_values(SshHttpClientContext ctx, ...);

/* Return codes for content data query.  These values describe whether
   the whole content data was received or not, or if the status it not
   known. */
typedef enum
{
  SSH_HTTP_OK,
  SSH_HTTP_TRUNCATED,
  SSH_HTTP_UNKNOWN
} SshHttpInputStatus;

/* Return the status of the content data stream.  The return value
   describes whether the whole content data was received or not, or if
   the status is not known. */
SshHttpInputStatus ssh_http_get_input_status(SshHttpClientContext ctx);


/* Get/set application specific data from/to the client object.
   Typically utilized in the TCP/IP stream wrapper function.
 */
void *
ssh_http_get_appdata(SshHttpClientContext ctx);

void *
ssh_http_set_appdata(SshHttpClientContext ctx, void *appdata);

/*
 * Prototypes for global server functions.
 */

/* Allocate and initialize an HTTP server context and start the
   server.  The function returns a server handle or NULL if the
   creation of the listener failed. */
SshHttpServerContext ssh_http_server_start(SshHttpServerParamsPtr params);

/* Stop the HTTP server.  The server will finish its current
   connections before it will shutdown.
   If the optional callback and context are provided, the callback
   will get called at shutdown.
*/
void ssh_http_server_stop(SshHttpServerContext ctx,
                          SshHttpServerStoppedCb callback,
                          void *context);

/* Bind a handler function for the URI pattern <uri_pattern>.  The
   handler function will be called when a connection is initiated to
   an URI that matches the pattern.  The server maintains the handlers
   in a priority list.  The first matching entry with the highest
   priority is used for each URI.  The argument <priority> specifies
   the priority of the handler.  The handlers with bigger priority are
   used before the handlers with lower priority.  If the argument
   <priority> is positive (> 0), the handler is inserted to the end of
   the list of handlers with the same priority.  If the priority is
   negative, the handler is inserted to the beginning of the list of
   handlers with the priority abs(priority). If inserting handler
   fails, this return FALSE. On success this returns TRUE. */
Boolean
ssh_http_server_set_handler(SshHttpServerContext ctx,
                            const unsigned char *uri_pattern, int priority,
                            SshHttpServerUriHandler handler,
                            void *handler_context);

/* Identical to ssh_http_server_set_handler() but for a different type of
   callback function. */
Boolean
ssh_http_server_set_void_handler(SshHttpServerContext ctx,
                                 const unsigned char *uri_pattern,
                                 int priority,
                                 SshHttpServerVoidUriHandler handler,
                                 void *handler_context);


/* Remove all URI handlers with a matching URI pattern, handler
   function, and context.  The argument <uri_pattern> can be
   SSH_HTTP_ALL_PATTERNS which matches all URI patterns.  The argument
   <handler> can be SSH_HTTP_ALL_HANDLERS which matches all handler
   functions of type SshHttpServerUriHandler.  The argument <handler_context>
   can be SSH_HTTP_ALL_CONTEXTS which matches all contexts. */
void ssh_http_server_remove_handlers(SshHttpServerContext ctx,
                                     const unsigned char *uri_pattern,
                                     SshHttpServerUriHandler handler,
                                     void *handler_context);


/* Identical to ssh_http_server_remove_handlers() but for a different type
   of callback function.  The argument <handler> can be
   SSH_HTTP_ALL_VOID_HANDLERS which matches all handler functions of type
   SshHttpServerVoidUriHandler. */
void ssh_http_server_remove_void_handlers(SshHttpServerContext ctx,
                                          const unsigned char *uri_pattern,
                                          SshHttpServerVoidUriHandler handler,
                                          void *handler_context);

/* Get the IP address of the server. The returned value is valid as
   long as the connection is alive. */
const unsigned char *
ssh_http_server_get_local_address(SshHttpServerConnection conn);

/* Get the IP address of the client.  The returned value is valid as
   long as the connection is alive. */
const unsigned char *ssh_http_server_get_address(SshHttpServerConnection conn);

/* Get the port of the client.  The returned value is valid as long as
   the connection is alive. */
const unsigned char *ssh_http_server_get_port(SshHttpServerConnection conn);

/* Get the HTTP request method from the connection <conn>.  The method
   names are converted to upper case.  The returned value is valid as
   long as the control remains in the URI handler function. */
const unsigned char *ssh_http_server_get_method(SshHttpServerConnection conn);

/* Get the connection stream of the connection <conn>. The returned
   stream is valid as long as the control remains in the URI handler
   function. */
SshStream
ssh_http_server_get_connection_stream(SshHttpServerConnection conn);

/* Get/set application specific data from/to the connection object.
   Typically utilized in the TCP/IP stream wrapper function.
 */
void *
ssh_http_server_get_connection_appdata(SshHttpServerConnection conn);

void *
ssh_http_server_set_connection_appdata(SshHttpServerConnection conn,
                                       void *appdata);

/* Get the request URI from the connection <conn>.  The returned URI
   is valid as long as the control remains in the URI handler
   function. */
const unsigned char *ssh_http_server_get_uri(SshHttpServerConnection conn);

/* Get the request HTTP protocol version information. */
void ssh_http_server_get_protocol_version(SshHttpServerConnection conn,
                                          SshUInt32 *major_return,
                                          SshUInt32 *minor_return);

/* Get the value of the HTTP request header field <field>.  The
   function returns NULL if the key is not defined. */
const unsigned char *
ssh_http_server_get_header_field(SshHttpServerConnection conn,
                                 const unsigned char *field);

/* Return the authentication method of the request.  If the request
   was authenticated, the user-name and password are returned in
   arguments <name_return> and <password_return>.  The values returned
   in the arguments <name_return> and <password_return> are
   ssh_xmalloc():ated '\0' terminated strings.  You must free them
   with the ssh_xfree() function when they are no longer needed. */
SshHttpAuthentication
ssh_http_server_get_authentication(SshHttpServerConnection conn,
                                   unsigned char **name_return,
                                   unsigned char **password_return);

/* Return the proxy authentication method of the request.  If the
   request was authenticated, the user-name and password are returned
   in arguments <name_return> and <password_return>.  The values
   returned in the arguments <name_return> and <password_return> are
   ssh_xmalloc():ated '\0' terminated strings.  You must free them
   with the ssh_xfree() function when they are no longer needed. */
SshHttpAuthentication
ssh_http_server_get_proxy_authentication(SshHttpServerConnection conn,
                                         unsigned char **name_return,
                                         unsigned char **password_return);

/* Return the cookies of the request, read from the connection <conn>.
   The function returns a pointer to an array of cookies.  The number
   of the cookies in the array is returned in <num_return>.  If the
   request did not have any cookies, the <num_return> is set to 0 and
   that the function returns a NULL pointer. */
SshHttpCookiePtrConst
ssh_http_server_get_cookies(SshHttpServerConnection conn,
                            unsigned int *num_return);

/* Set fields and properties of connection <conn> according to the
   SshHttpHeaderFieldSelector arguments <...>. */
void ssh_http_server_set_values(SshHttpServerConnection conn, ...);

/* Set cookie with given name, value and path to connection <conn>. */
void ssh_http_server_set_cookie(SshHttpServerConnection conn,
                                const unsigned char *name,
                                const unsigned char *value,
                                const unsigned char *path);

/* Set header field with name <name> to <value> in the connection <conn>. */
void ssh_http_server_set_value(SshHttpServerConnection conn,
                               const unsigned char *name,
                               const unsigned char *value);

/* Set expiration time header field to be the time given in <etime>. */
void ssh_http_server_set_expires(SshHttpServerConnection conn,
                                 SshTime etime);

/* Set content length header field to the value given in <bytes>. */
void ssh_http_server_set_content_length(SshHttpServerConnection conn,
                                        size_t bytes);


/* Send the contents of the buffer <buffer> to the connection and
   close the connection.  You must not touch, modify, or call any
   server functions for the connection <conn>.  After this call, the
   HTTP library owns the connection and it will close it (and destroy
   the related stream) when the contents of the buffer <buffer> has
   been written to the client.  You must also not touch, modify, or
   destroy the buffer <buffer> after this call.  The buffer belongs to
   the HTTP library after this call and the library will destroy it
   with the ssh_buffer_free() function when it is not needed
   anymore. */
void ssh_http_server_send_buffer(SshHttpServerConnection conn,
                                 SshBuffer buffer);

/* Notify the connection <conn> that it should flush all its possibly
   buffered data. */
void ssh_http_server_flush(SshHttpServerConnection conn);

/* Disconnect the current connection to the client.  This closes the
   connection stream and after this, the server will not write
   anything to the client.  You must still destroy the connection's UI
   stream. */
void ssh_http_server_disconnect(SshHttpServerConnection conn);

/* Return the number of bytes of client content data that has been
   read so far. */
size_t ssh_http_server_content_data_read(SshHttpServerConnection conn);

/* HTTP error generation functions.  These functions can be called
   from the URI handlers to report an HTTP error condition.  After the
   error is reported, the URI handler must destroy the stream and
   return.  The URI handler must not write any data to the stream
   before or after it calls the error reporting functions. */

/* Report a `401 Unauthorized' error to the connection <conn>. */
void ssh_http_server_error_unauthorized(SshHttpServerConnection conn,
                                        const unsigned char *realm);

/* Report a `404 Not Found' error to the connection <conn>. */
void ssh_http_server_error_not_found(SshHttpServerConnection conn);

/* Report a `407 Proxy Authentication Required' error to the
   connection <conn>. */
void ssh_http_server_error_proxy_authentication_required(
                                                SshHttpServerConnection conn,
                                                const unsigned char *realm);

/* Report `301 Moved Permanently' to a relative location to the
   connection <conn>. */
void ssh_http_server_relative_redirect(SshHttpServerConnection conn,
                                       const unsigned char *location);

/* Report `301 Moved Permanently' to an absolute location to the
   connection <conn>. */
void ssh_http_server_redirect(SshHttpServerConnection conn,
                              const unsigned char *location);

/* Report error code <code> to the connection <conn>. */
void ssh_http_server_error_code(SshHttpServerConnection conn,
                                int code);


/* A generic error reporting function.  This function can be called to
   format a more specific error message to the connection <conn>.  The
   argument <status_code> specifies the status code of the HTTP
   response.  The remaining arguments are SshHttpHeaderFieldSelector
   formatted header field selectors which can set appropriate response
   header fields.  The actual body of the error response is formatted
   with the normal SshHttpServerMessageFormatter functions.

   For example, a redirection response could be reported with the
   following code:

     ssh_http_server_error(conn, 301,
                           SSH_HTTP_HDR_LOCATION, moved_here_url,
                           SSH_HTTP_HDR_END);

   The status code 301 is `Moved Permanently' and the variables
   <moved_here_url> is assumed to contain the URL where the requested
   resource is moved. */
void ssh_http_server_error(SshHttpServerConnection conn,
                           SshUInt32 status_code, ...);


/*
 * General help functions.
 */

/* Skip the next SshHttpHeaderFieldSelector selector in va_list <ap>
   knowing that its type is <type>. */
#define ssh_http_hdr_skip_next(ap, type)        \
  do {                                          \
  switch (((type)) / 100)                       \
    {                                           \
    case 0:                                     \
      break;                                    \
    case 1:                                     \
      (void) va_arg((ap), size_t);              \
      break;                                    \
    case 2:                                     \
      (void) va_arg((ap), SshTime);             \
      break;                                    \
    case 3:                                     \
      (void) va_arg((ap), unsigned char *);     \
      break;                                    \
    case 4:                                     \
      (void) va_arg((ap), unsigned char *);     \
      (void) va_arg((ap), size_t);              \
      break;                                    \
    case 5:                                     \
      (void) va_arg((ap), unsigned char *);     \
      (void) va_arg((ap), unsigned char *);     \
      break;                                    \
    case 6:                                     \
      (void) va_arg((ap), unsigned char *);     \
      (void) va_arg((ap), size_t);              \
      (void) va_arg((ap), unsigned char *);     \
      (void) va_arg((ap), size_t);              \
      break;                                    \
    default:                                    \
      SSH_NOTREACHED;                           \
      break;                                    \
    }                                           \
  } while (0)

/* Convert the error code <code> to a human readable 7 bit ASCII
   string. */
const char *ssh_http_error_code_to_string(SshHttpResult code);


#endif /* not SSHHTTP_H */
