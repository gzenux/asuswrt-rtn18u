/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A public interface for the OCSP over HTTP part of the PKIX OCSP
   (Online Certificate Status Protocol). The implemention is done
   according to the RFC2560.
*/

#ifndef SSHOCSPHTTP_H
#define SSHOCSPHTTP_H

#include "sshhttp.h"
#include "sshocsp.h"

#if 0
/* Initialize the HTTP context. This function has to be called before
   calling the ssh_ocsp_http_send_request function.

   ´socks' parameter can be used to define the socks address. ´proxy_url'
   tells the location of the proxy server. The value of the parameters
   can be NULL, if socks or proxy server is not used.

   The function returns an HTTP context that should be freed using
   the function ssh_ocsp_http_uninit. */
/*
SshHttpClientContext ssh_ocsp_http_init(const char *socks,
                                        const char *proxy_url);
*/
/* The context parameter defines the HTTP client context that
   was allocated by calling the ssh_ocsp_http_init function. This
   function has to be called when HTTP is not needed anymore. */
/*
void ssh_ocsp_http_uninit(SshHttpClientContext context);
*/
/* Send the OCSP request using HTTP. ´context' defines the http client
   context. ´url' contains the address of the OCSP responder where
   request is to be sent. If the value of the parameter
   ´use_get_if_possible' is TRUE, request is sent using the GET method if
   the total length of the request after encoding is less than 255 bytes.
   ´content_data' and ´content_data_len' should define the encoded
   OCSP request. Function determined by ´callback' is called
   when the result is received. The ´callback_context' pointer is passed
   to the callback function. It can be used to carry arbitrary
   data to the callback function. */
/*
SshOperationHandle
ssh_ocsp_http_send_request(SshHttpClientContext context,
                           const char *url,
                           Boolean use_get_if_possible,
                           const unsigned char *content_data,
                           size_t content_data_len,
                           SshHttpClientResultCb callback,
                           void *callback_context);
*/
#endif

/* A callback function type for the operation that encodes the request
   and sends it to the responder using the HTTP. This function is
   called when the operation is finished. ´response' contains the decoded
   response, The ´context' parameter contains the pointer that was passed
   for the ssh_ocsp_http_send_request function. It can contain your
   own context-specific data. */

typedef void(*SshOcspHttpCB)(SshOcspStatus status,
                             SshHttpResult http_result,
                             SshOcspResponse response,
                             void *context);


/* Function encodes the request and sends the encoded message to
   the responder using the HTTP. The ´http_context' should contain
   the HTTP client context. ´url' specifies the responder's address.
   ´private_key' is used to sign the requests. It can be NULL if you
   do not want to sign the request. The function specified by the
   ´callback' parameter is called when the response is received and
   decoded. ´callback_context' is passed to the callback function.

   The function does not work, if the event loop is not initialized.
*/

SshOperationHandle
ssh_ocsp_http_send_request(SshOcspRequest request,
                           SshHttpClientContext http_context,
                           const unsigned char *url,
                           const SshPrivateKey private_key,
                           SshOcspHttpCB callback,
                           void *callback_context);

#endif /* SSHOCSPHTTP_H */
