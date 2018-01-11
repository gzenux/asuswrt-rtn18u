/**
 * A client-side 802.1x implementation supporting EAP/TLS
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 * 
 * Copyright (C) 2002 Bryan D. Payne & Nick L. Petroni Jr.
 * All Rights Reserved
 *
 * --- GPL Version 2 License ---
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * --- BSD License ---
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  - All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by the University of
 *       Maryland at College Park and its contributors.
 *  - Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*******************************************************************
 * EAPTLS (RFC 2716) Function header
 * 
 * File: eaptls.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _EAPTLS_H_
#define _EAPTLS_H_

#include <openssl/ssl.h>
#include <netinet/in.h>
#include "profile.h"

#define EAP_TYPE_TLS         0x0d

#define EAPTLS_LENGTH_MORE   0xC0
#define EAPTLS_LENGTH_INCL   0x80
#define EAPTLS_MORE_FRAGS    0x40
#define EAPTLS_START         0x20
#define EAPTLS_ACK           0x00
#define EAPTLS_FINAL         0x00

#define TLS_SESSION_KEY_CONST       "client EAP encryption"
#define TLS_SESSION_KEY_CONST_SIZE  21
#define TLS_SESSION_KEY_SIZE        128

struct tls_vars {
  SSL_CTX *ctx;       // Our OpenSSL context.
  SSL *ssl;
  BIO *ssl_in, *ssl_out;
  int resume;                // Should we attempt to resume this connection?
  int resuming;              // Are we in the process of resuming?

  int verify_mode;           // This should be set to SSL_VERIFY_PEER to 
                             // verify the peer certificate, and set to 
                             // SSL_VERIFY_NONE to ignore verification.

  int cnexact;               // Should be the same as the cnexact value for
                             // TTLS or PEAP, depending on which one we are
                             // using.

  char *cncheck;             // Should be the same as the cncheck .....
  char *tlsoutdata, *sessionkeyconst;
  int tlsoutsize,tlsoutptr,sessionkeylen;
  char *phase2data;
  int phase;                 // Which phase are we in?

  int cert_loaded;           // This should be set to TRUE when the user
                             // certificate is loaded.  This allows us to
                             // clear out thisint->tempPwd so that it can
                             // be used by a phase 2 type.

  // This next value needs some explaining.  With TTLS, as soon as the
  // the TLS piece is completed, we are expected to send back a response that
  // contains the inner authentication.  I choose to refer to this as a 
  // "quick" response.  With PEAP, we should simply ACK the final piece of
  // the TLS handshake, and wait for the RADIUS server to send us an inner
  // EAP Request Identity.  This is *not* a quick response.
  int quickResponse;
};

int eaptls_setup(struct generic_eap_data *);
int eaptls_process(struct generic_eap_data *, u_char *, int, u_char *, int *);
int eaptls_get_keys(struct interface_data *);
int eaptls_cleanup(struct generic_eap_data *);
int eaptls_keyblock(char *);
int eaptls_failed(struct generic_eap_data *);
#endif
