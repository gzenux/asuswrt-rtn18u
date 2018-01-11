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
 * En/Decrypt Function implementations
 *
 * File: tls_crypt.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: tls_crypt.c,v 1.1.1.1 2007/08/06 10:04:43 root Exp $
 * $Date: 2007/08/06 10:04:43 $
 * $Log: tls_crypt.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:43  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:31  ysc
 *
 *
 * Revision 1.1  2004/07/24 00:52:57  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.1  2004/07/24 00:40:55  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.8  2004/04/14 21:09:33  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.7  2004/04/13 22:13:31  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.6  2004/04/05 17:19:30  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.5  2004/04/02 20:50:21  chessing
 *
 * Attempt to fix PEAP with IAS. At this point, we can get through the TLS piece of the PEAP authentication, and successfully attempt a phase 2 authentication.  But, for some reason MS-CHAPv2 is failing when used with IAS.  (But at least we are one step closer!)  Also, removed the des pieces that were needed for eap-mschapv2, since we can use the OpenSSL routines instead.  The proper way to handle DES was found while looking at the CVS code for wpa_supplicant.  The fix for phase 1 of PEAP was found while looking at the commit notes for wpa_supplicant.  (wpa_supplicant is part of hostap, and is written/maintained by Jouni Malinen.)
 *
 * Revision 1.4  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.3  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.2  2003/11/21 05:09:47  chessing
 *
 * PEAP now works!
 *
 * Revision 1.1.1.1  2003/11/19 04:13:25  chessing
 * New source tree
 *
 *
 *******************************************************************/

#include <string.h>
#include <strings.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <netinet/in.h>

#include "config.h"
#include "profile.h"
#include "eap.h"
#include "eaptls.h"
#include "tls_funcs.h"
#include "../../xsup_debug.h"
#include "../../xsup_err.h"

u_char *tls_crypt_gen_keyblock(struct generic_eap_data *thisint, char *sesskey,
			      int sesskeylen)
{
  u_char seed[SSL3_RANDOM_SIZE*2];
  u_char *p = seed;
  struct tls_vars *mytls_vars;
  u_char *retblock;

  debug_printf(DEBUG_EVERYTHING, "Generating key block!\n");

  if ((!thisint) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to tls_crypt_gen_keyblock()!\n");
      return NULL;
    }

  if (!sesskey)
    {
      debug_printf(DEBUG_NORMAL, "Invalid session constant!\n");
      return NULL;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  if (!mytls_vars->ssl)
    {
      debug_printf(DEBUG_NORMAL, "No valid SSL context found!\n");
      return NULL;
    }

  debug_printf(DEBUG_EVERYTHING, "Using session key const of : %s\n",
	       sesskey);

  retblock = (u_char *)malloc(TLS_SESSION_KEY_SIZE);
  if (!retblock)
    return NULL;

  memcpy(p, mytls_vars->ssl->s3->client_random, SSL3_RANDOM_SIZE);
  p+= SSL3_RANDOM_SIZE;
  memcpy(p, mytls_vars->ssl->s3->server_random, SSL3_RANDOM_SIZE);
  tls_funcs_PRF(mytls_vars->ssl->session->master_key, 
		mytls_vars->ssl->session->master_key_length,
		sesskey, sesskeylen, seed, 
		SSL3_RANDOM_SIZE * 2, retblock, 
		TLS_SESSION_KEY_SIZE);

  return retblock;
}

// This function written by Danielle Brevi
int tls_crypt_decrypt(struct generic_eap_data *thisint, u_char *in_data, int in_size, u_char *out_data, int *out_size)
{
  struct tls_vars *mytls_vars;
  int rc=0;
  u_char p[1000];

  if ((!thisint) || (!thisint->eap_data) || (!in_data) || (!out_data) ||
      (!out_size))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to tls_crypt_decrypt()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;
  bzero(p,1000);

  BIO_reset(mytls_vars->ssl_in);
  rc=BIO_write(mytls_vars->ssl_in, in_data, in_size);

  BIO_reset(mytls_vars->ssl_out);

  rc=SSL_read(mytls_vars->ssl, out_data, 1000);
  *out_size = rc;

  // CLEAN THIS UP -- And use it.
  /*
    switch (SSL_get_error(ssl,rc))
    {
    case SSL_ERROR_NONE:
    printf("No SSL error!?   Dump :\n");
    for (i=0;i<=rc;i++)
    {
    printf("%02x ",out_data[i]);
    }
    printf("\n");
    break;
    case SSL_ERROR_ZERO_RETURN:
    printf("SSL Error Zero Return!\n");
    break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    printf("SSL Error want read or write.\n");
    break;
    case SSL_ERROR_WANT_CONNECT:
    printf("SSL Error want connect\n");
    break;
    case SSL_ERROR_WANT_ACCEPT:
    printf("SSL Error want accept\n");
    break;
    case SSL_ERROR_WANT_X509_LOOKUP:
    printf("SSL Error want x509 Lookup\n");
    break;
    case SSL_ERROR_SYSCALL:
    printf("SSL Error syscall\n");
    break;
    case SSL_ERROR_SSL:
    printf("SSL error of some sort!\n");
    break;
    default:
    printf("This shouldn't happen!\n");
    break;
    }
  */
  return XENONE;
}


int tls_crypt_encrypt(struct generic_eap_data *thisint, u_char *in_data, int in_size, u_char *out_data, int *out_size)
{
  struct tls_vars *mytls_vars;
  int rc=0;
  u_char *p;
  int to_send_size = 0;

#ifdef RTL_WPA_CLIENT  
  uint32_t length;
#else  
  uint64_t length;
#endif		

  if ((!thisint) || (!thisint->eap_data) || (!in_data) || (!out_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to tls_crypt_encrypt()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  // We need to modify this, to read more when there is more to be returned.
  p = (u_char *)malloc(1000);
  if (p == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of \"p\" in tls_crypt_encrypt().\n");
      return -1;
    }

  bzero(p,1000);
  
  BIO_reset(mytls_vars->ssl_in);
  BIO_reset(mytls_vars->ssl_out);

  rc=SSL_write(mytls_vars->ssl, in_data, in_size);

  rc = BIO_read(mytls_vars->ssl_out, p, 1000);   // Allow largest possible read.
  to_send_size = rc;

  out_data[0] = EAPTLS_LENGTH_INCL;  // No more to send.
  length = ntohl(to_send_size+5);
  memcpy(&out_data[1], &length, 4);
  memcpy(&out_data[5], p, to_send_size);

  *out_size = to_send_size+5;
  if(p)
    {
      free(p);
      p = NULL;
    }
  return XENONE;
}

int tls_crypt_encrypt_nolen(struct generic_eap_data *thisint, u_char *in_data, int in_size, u_char *out_data, int *out_size)
{
  struct tls_vars *mytls_vars;
  int rc=0;
  u_char *p;
  int to_send_size = 0;

  if ((!thisint) || (!thisint->eap_data) || (!in_data) || (!out_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to tls_crypt_encrypt()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  // We need to modify this, to read more when there is more to be returned.
  p = (u_char *)malloc(1000);
  if (p == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of \"p\" in tls_crypt_encrypt().\n");
      return -1;
    }

  bzero(p,1000);
  
  BIO_reset(mytls_vars->ssl_in);
  BIO_reset(mytls_vars->ssl_out);

  rc=SSL_write(mytls_vars->ssl, in_data, in_size);

  rc = BIO_read(mytls_vars->ssl_out, p, 1000);   // Allow largest possible read.
  to_send_size = rc;

  out_data[0] = 0x00;  // No more to send.
  memcpy(&out_data[1], p, to_send_size);

  *out_size = to_send_size+1;
  if(p)
    {
      free(p);
      p = NULL;
    }
  return XENONE;
}
