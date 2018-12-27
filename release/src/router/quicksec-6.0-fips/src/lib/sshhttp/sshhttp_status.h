/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   HTTP status codes and some function using them.
*/

#ifndef SSHHTTP_STATUS_H
#define SSHHTTP_STATUS_H

/*
 * Types and definitions.
 */

/* The HTTP response status codes. */
typedef enum
{
  SSH_HTTP_STATUS_CONTINUE                              = 100,
  SSH_HTTP_STATUS_SWITCHING_PROTOCOLS                   = 101,

  SSH_HTTP_STATUS_OK                                    = 200,
  SSH_HTTP_STATUS_CREATED                               = 201,
  SSH_HTTP_STATUS_ACCEPTED                              = 202,
  SSH_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION         = 203,
  SSH_HTTP_STATUS_NO_CONTENT                            = 204,
  SSH_HTTP_STATUS_RESET_CONTENT                         = 205,
  SSH_HTTP_STATUS_PARTIAL_CONTENT                       = 206,

  SSH_HTTP_STATUS_MULTIPLE_CHOICES                      = 300,
  SSH_HTTP_STATUS_MOVED_PERMANENTLY                     = 301,
  SSH_HTTP_STATUS_FOUND                                 = 302,
  SSH_HTTP_STATUS_SEE_OTHER                             = 303,
  SSH_HTTP_STATUS_NOT_MODIFIED                          = 304,
  SSH_HTTP_STATUS_USE_PROXY                             = 305,
  SSH_HTTP_STATUS_TEMPORARY_REDIRECT                    = 307,

  SSH_HTTP_STATUS_BAD_REQUEST                           = 400,
  SSH_HTTP_STATUS_UNAUTHORIZED                          = 401,
  SSH_HTTP_STATUS_PAYMENT_REQUIRED                      = 402,
  SSH_HTTP_STATUS_FORBIDDEN                             = 403,
  SSH_HTTP_STATUS_NOT_FOUND                             = 404,
  SSH_HTTP_STATUS_METHOD_NOT_ALLOWED                    = 405,
  SSH_HTTP_STATUS_NOT_ACCEPTABLE                        = 406,
  SSH_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED         = 407,
  SSH_HTTP_STATUS_REQUEST_TIMEOUT                       = 408,
  SSH_HTTP_STATUS_CONFLICT                              = 409,
  SSH_HTTP_STATUS_GONE                                  = 410,
  SSH_HTTP_STATUS_LENGTH_REQUIRED                       = 411,
  SSH_HTTP_STATUS_PRECONDITION_FAILED                   = 412,
  SSH_HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE              = 413,
  SSH_HTTP_STATUS_REQUEST_URI_TOO_LARGE                 = 414,
  SSH_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE                = 415,
  SSH_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE       = 416,
  SSH_HTTP_STATUS_EXPECTATION_FAILED                    = 417,

  SSH_HTTP_STATUS_INTERNAL_SERVER_ERROR                 = 500,
  SSH_HTTP_STATUS_NOT_IMPLEMENTED                       = 501,
  SSH_HTTP_STATUS_BAD_GATEWAY                           = 502,
  SSH_HTTP_STATUS_SERVICE_UNAVAILABLE                   = 503,
  SSH_HTTP_STATUS_GATEWAY_TIMEOUT                       = 504,
  SSH_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED            = 505,

  SSH_HTTP_STATUS_UNKNOWN
} SshHttpStatusCode;


/*
 * Prototypes for global functions.
 */

/* Find a description string for the status code <code>. */
const char *ssh_http_status_to_string(SshHttpStatusCode code);

#endif /* not SSHHTTP_STATUS_H */
