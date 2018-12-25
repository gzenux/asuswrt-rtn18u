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
 * EAPTLS (RFC 2716) Function implementations
 * 
 * File: eaptls.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: tls_funcs.c,v 1.1.1.1 2007/08/06 10:04:43 root Exp $
 * $Date: 2007/08/06 10:04:43 $
 * $Log: tls_funcs.c,v $
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
 * Revision 1.27  2004/05/04 00:42:48  chessing
 *
 * Fix a bug in tls_funcs_load_random.
 *
 * Revision 1.26  2004/04/14 21:09:33  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.25  2004/04/13 22:13:31  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.24  2004/04/12 18:43:43  chessing
 *
 * A few small cosmetic fixups.
 *
 * Revision 1.23  2004/04/06 20:31:27  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.22  2004/04/05 17:19:30  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.21  2004/03/28 20:37:10  chessing
 *
 * PEAP session resumption now works.
 *
 * Revision 1.20  2004/03/28 06:07:17  chessing
 * Added failure call to EAP methods to enable context resets for TLS based authentication protocols.  The resets are needed if an authentiction attempt fails, and we have session resumption enabled.  However, resetting it when we aren't using session resumption won't hurt anything, and probably isn't a bad idea.  The new failure handler can also be used to destroy passwords after a failed attempt, which will then cause xsupplicant to request another password from any listening GUIs. TLS session resumption is enabled (and works) for TLS and TTLS.  PEAP loops forever, and needs to be reviewed.
 *
 * Revision 1.19  2004/03/27 01:40:46  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.18  2004/03/26 21:34:52  chessing
 * Fixed problem with interface being down on startup causing xsupplicant to not read the proper configuration information when the interface is brought up.  Added/fixed code to rebuild userdata piece of structure when the essid changes.  Added code to avoid setting a key on an interface if the interface doesn't already have encryption enabled.  Added a little bit of debugging code to help find a solution to an IPC socket problem.
 *
 * Revision 1.17  2004/03/26 03:52:52  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.16  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.15  2004/03/17 21:21:41  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.14  2004/03/05 23:58:45  chessing
 *
 * Added CN (sometimes called server name) checking to TTLS and PEAP.  This resulted in two new config options in the eap-ttls, and eap-peap blocks.  cncheck should be the name (or partial name) to match in the CN.  cnexact should be yes/no depending on if we want to match the CN exactly, or just see if our substring is in the CN.
 *
 * Revision 1.13  2004/03/02 01:03:53  chessing
 *
 * Added Jari Ahonen's SSL verification callback.  Added support to PEAP and TTLS to turn off certificate validation checking by setting the root_cert variable in the config to NONE.  (Case sensative!)  We will also display a warning when running in this mode.  Added initial hooks to support certificate CN checking.
 *
 * Revision 1.12  2004/02/28 01:26:38  chessing
 *
 * Several critical updates.  Fixed the HMAC failure on some keys. (This was due to a lot more than just an off-by-one.)  Fixed up the key decryption routine to identify key packets with no encrypted key, and use the peer key instead.  When using the peer key, we also can handle packets that are padded funny.  (Our Cisco AP1200 has two null pad bytes at the end of some key frames.)  Changed the response ID function to not add a 00 to the end of the ID.  The 00 byte shouldn't have been seen by the RADIUS server unless they were not paying attention to the EAP-Length.  So, this wasn't really a bug fix.  Started to add support for CN checking for TLS based protocols.
 *
 * Revision 1.11  2004/02/06 06:13:32  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.10  2004/01/17 21:16:16  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.9  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.8  2004/01/14 22:07:25  chessing
 *
 * Fixes that were needed in order to allow us to authenticate correctly.  We should now be able to authenticate using only information provided by the config file!
 *
 * Revision 1.7  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.6  2004/01/06 23:35:08  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.5  2003/12/14 06:11:03  chessing
 *
 * Fixed some stuff with SIM in relation to the new config structures.  Cleaned out CR/LF from LEAP source files.  Added user certificate support to TTLS and PEAP. Some additions to the IPC code. (Not tested yet.)
 *
 * Revision 1.4  2003/12/07 06:20:20  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 * Revision 1.3  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.2  2003/11/21 05:09:47  chessing
 *
 * PEAP now works!
 *
 * Revision 1.1.1.1  2003/11/19 04:13:26  chessing
 * New source tree
 *
 *
 *******************************************************************/

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <netinet/in.h>
#include <string.h>
#include <inttypes.h>
#include "config.h"
#include "profile.h"
#include "eap.h"
#include "tls_funcs.h"
#include "tls_crypt.h"
#include "xsup_debug.h"
#include "xsup_err.h"

char *get_cert_common_name(SSL *ssl_ctx)
{
  char *commonName = NULL;
  X509 *server_cert;

  if (!ssl_ctx)
    {
      debug_printf(DEBUG_NORMAL, "Invalid SSL context in get_cert_common_name()!\n");
      return NULL;
    }

  // Get our certificate.
  server_cert = SSL_get_peer_certificate(ssl_ctx);

  if (!server_cert) return NULL;

  commonName = (char *)malloc(512);
  if (commonName == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to hold the common name!\n");
      return NULL;
    }

  if (X509_NAME_get_text_by_NID(X509_get_subject_name(server_cert),
				NID_commonName, commonName, 512) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't extract common name from server certificate!\n");
      return NULL;
    }

  debug_printf(DEBUG_AUTHTYPES, "Extracted common name of %s\n",commonName);
  return commonName;
}

static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  char buf[256];
  X509 *err_cert;
  int err, depth;

  if (!ctx)
    {
      debug_printf(DEBUG_NORMAL, "Invalid context in ssl_verify_callback()!\n");
      return XEMALLOC;
    }

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);
  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

  debug_printf(DEBUG_AUTHTYPES, "     --- SSL_verify : depth %d\n", depth);

  if (!preverify_ok)
    {
      debug_printf(DEBUG_AUTHTYPES, "     --- SSL_verify error : num=%d:%s:depth=%d:%s\n",
		   err, X509_verify_cert_error_string(err), depth, buf);

      if (err == 26) preverify_ok = 1;
    }

  return preverify_ok;
}

int tls_funcs_init(struct generic_eap_data *thisint)
{
  struct tls_vars *mytls_vars;
  SSL_METHOD *meth=NULL;

  if (thisint == NULL) return XETLSINIT;
  if (thisint->eap_data == NULL) return XETLSINIT;

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  SSL_library_init();
  SSL_load_error_strings();

  meth=TLSv1_method();
  if(meth==NULL)
  {
  	debug_printf(DEBUG_NORMAL, "TLSv1_method return NULL!\n");
      return XETLSINIT;
  }
  mytls_vars->ctx = SSL_CTX_new(meth);
  if (mytls_vars->ctx == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't initialize OpenSSL TLS library!\n");
      return XETLSINIT;
    }

  return XENONE;
}

int tls_funcs_start(struct tls_vars *mytls_vars)
{
  SSL_SESSION *sess = NULL;
  unsigned long err = 0;
  int counter = 0;
  if (mytls_vars == NULL) return XETLSSTARTFAIL;

  mytls_vars->resuming = 0;

  if (!mytls_vars->ssl)
    {
      mytls_vars->ssl = SSL_new(mytls_vars->ctx);
      if (!mytls_vars->ssl)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't create SSL object!\n");
	  // First, make sure we don't have any errors.
	  err = ERR_get_error();
	  if (err != 0)
	    {
	      debug_printf(DEBUG_NORMAL, "OpenSSL Error -- %s\n", 
			   ERR_error_string(err, NULL));
	    }

	  return XETLSSTARTFAIL;
	}
    } else {
      // We already established a connection, so we probably we need to
      // resume the session.
      if (mytls_vars->resume == RES_YES)
	{
	  sess = SSL_get_session(mytls_vars->ssl);
	  if (!sess)
	    {
	      mytls_vars->resuming = 0;
	    } else {
	      mytls_vars->resuming = 1;
	    }
	}

      // We don't want to send an alert to the other end..  So do a quiet
      // shutdown.  This violates the TLS standard, but it needed to avoid
      // confusing the other end of the connection when we want to do a
      // reconnect!
      SSL_set_quiet_shutdown(mytls_vars->ssl, 1);

      // Now, close off our old session.
      SSL_shutdown(mytls_vars->ssl);
	      while ((err == 0) && (counter < 10))
		{
		  err = SSL_shutdown(mytls_vars->ssl);
		  if (err == 0)
		    {
		      sleep(1);
		      counter++;
		    }
		}
	  SSL_free(mytls_vars->ssl);
      mytls_vars->ssl = NULL;
	   mytls_vars->ssl = SSL_new(mytls_vars->ctx);
      if (!mytls_vars->ssl)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't create SSL object!\n");
	  // First, make sure we don't have any errors.
	  err = ERR_get_error();
	  if (err != 0)
	    {
	      debug_printf(DEBUG_NORMAL, "OpenSSL Error -- %s\n", 
			   ERR_error_string(err, NULL));
	    }

	  return XETLSSTARTFAIL;
	}
    }

  mytls_vars->ssl_in = BIO_new(BIO_s_mem());
  if (!mytls_vars->ssl_in)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't create ssl_in!\n");
      return XETLSSTARTFAIL;
    }

  mytls_vars->ssl_out = BIO_new(BIO_s_mem());
  if (!mytls_vars->ssl_out)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't create ssl_out!\n");
      return XETLSSTARTFAIL;
    }

  SSL_set_bio(mytls_vars->ssl, mytls_vars->ssl_in, mytls_vars->ssl_out);

  if (sess != NULL)
    {
      // If we have session information, we need to use it to resume the 
      // session.
      debug_printf(DEBUG_AUTHTYPES, "Attempting to resume session...\n");
      SSL_set_session(mytls_vars->ssl, sess);
    }

  // Set this to SSL_VERIFY_NONE if we don't want to do anything with a failed
  // verification.
  SSL_set_verify(mytls_vars->ssl, mytls_vars->verify_mode, ssl_verify_callback);
  return XENONE;
}

int tls_funcs_parse(struct generic_eap_data *thisint, u_char *indata, 
		    int insize, char *outdata, int *outsize, int chunksize)
{
  int rc;
  BUF_MEM *retData;
  struct tls_vars *mytls_vars;
  char *retVal;

#ifdef RTL_WPA_CLIENT  
  uint32_t length;
#else  
  uint64_t length;
#endif		

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed to tls_funcs_parse()!\n");
      return XEMALLOC;
    }

  if ((!outdata) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid return buffer in tls_funcs_parse()!\n");
      return XEMALLOC;
    }

  if (insize > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Packet passed in to tls_funcs_parse() is too big! Ignoring!\n");
      return XEBADPACKETSIZE;
    }

  if (chunksize == 0)
    {
      chunksize = 1398;
    }

  if (thisint->eap_data == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "(TLS) eap_data has been destroyed, or not allocated!\n");
      return XEMALLOC;
    }
  mytls_vars = (struct tls_vars *)thisint->eap_data;


  if (mytls_vars->tlsoutsize==0) 
    {
      if (indata != NULL)
	{
	  debug_hex_dump(DEBUG_EVERYTHING, indata, insize);
	  BIO_reset(mytls_vars->ssl_in);
	  BIO_write(mytls_vars->ssl_in, indata, insize);
	} 
      BIO_reset(mytls_vars->ssl_out);
      if (mytls_vars->ssl == NULL) 
	{
	  debug_printf(DEBUG_NORMAL, "SSL context is NULL!!!!\n");
	  return XETLSNOCTX;
	}

      rc = SSL_connect(mytls_vars->ssl);
      BIO_get_mem_ptr(mytls_vars->ssl_out, &retData);
      
      mytls_vars->tlsoutdata = retData->data;
      mytls_vars->tlsoutsize = retData->length;
    }
  
  if (mytls_vars->tlsoutsize == 0) 
    {
      return XTLSNEEDDATA;
    }

  if ((mytls_vars->tlsoutsize - mytls_vars->tlsoutptr)>chunksize)
    {
      // Return a maximum sized chunk.
      
      if (mytls_vars->tlsoutptr == 0)  // This is our first chunk, include
	{                              // the length.
	  outdata[0] = EAPTLS_LENGTH_MORE;  // We will have a length value, and more.
	  length = htonl(mytls_vars->tlsoutsize);
	  memcpy(&outdata[1], &length, 4);
	  retVal = &outdata[5];
	  *outsize = chunksize+5; // To account for length.
	} else {
	  outdata[0] = EAPTLS_MORE_FRAGS;
	  retVal = &outdata[1];
	  *outsize = chunksize+1;
	}

      memcpy(retVal, &mytls_vars->tlsoutdata[mytls_vars->tlsoutptr], chunksize);
      mytls_vars->tlsoutptr += chunksize;

    } else {
      // Return what is left.

      if (mytls_vars->tlsoutptr == 0)  // This is our first chunk, include
	{                              // the length.
	  outdata[0] = EAPTLS_LENGTH_INCL;  // We will have a length value.
	  length = htonl(mytls_vars->tlsoutsize);
	  memcpy(&outdata[1], &length, 4);
	  retVal = &outdata[5];
	  *outsize = (mytls_vars->tlsoutsize - mytls_vars->tlsoutptr)+5;
	} else {
	  outdata[0] = EAPTLS_FINAL;
	  retVal = &outdata[1];
	  *outsize = (mytls_vars->tlsoutsize - mytls_vars->tlsoutptr)+1;
	}

      memcpy(retVal, &mytls_vars->tlsoutdata[mytls_vars->tlsoutptr], 
	     *outsize);
      
      // Clean out the data chunk.
      mytls_vars->tlsoutptr = 0;
      mytls_vars->tlsoutsize = 0;
    }

  return XENONE;
}

int tls_funcs_decode_packet(struct generic_eap_data *thisint, char *inframe, 
			    int insize, char *outframe, int *outsize,
			    phase2_call dophase2, int chunksize)
{
  unsigned long err;
  int rtnVal, tlsindex;
  char *tlsptr, *cnname = NULL, *temp;
  struct tls_vars *mytls_vars;

  if ((!thisint) || (!inframe) || (!outframe) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to tls_funcs_decode_packet()!\n");
      return XEMALLOC;
    }

  if (insize > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Packet size too big in tls_funcs_decode_packet()!  Ignoring!\n");
      return XEBADPACKETSIZE;
    }

  // First, make sure we don't have any errors.
  err = ERR_get_error();
  if (err != 0)
    {
      debug_printf(DEBUG_NORMAL, "OpenSSL Error -- %s\n", 
		   ERR_error_string(err, NULL));
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  if (mytls_vars == NULL)
    {
      debug_printf(DEBUG_NORMAL, "EAP data is invalid in tls_funcs_decode_packet()!\n");
      return XEMALLOC;
    }

  *outsize = 0;

  // Set up a pointer to the start of the data.
  tlsindex = 1;
  tlsptr = &inframe[tlsindex];

  rtnVal = XENONE;

  // The first byte should tell us what to do.
  switch ((uint8_t)inframe[0])
    {
    case EAPTLS_START:
      tls_funcs_start(mytls_vars);

      if (mytls_vars->ssl == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "The SSL handle is invalid in tls_funcs_decode_packet()!\n");
	  return XETLSNOCTX;
	}
      
      rtnVal = tls_funcs_parse(thisint, NULL, 0, outframe, outsize, chunksize);
      if (rtnVal < 0)
	{
	  debug_printf(DEBUG_NORMAL, "Failed to generate TLS data!\n");
	}
      break;

    case EAPTLS_LENGTH_MORE:
    case EAPTLS_LENGTH_INCL:
      // Skip the four octets that contain the length.  OpenSSL knows when
      // we are done.
      tlsptr+=4;
      tlsindex+=4;

      // DON'T BREAK HERE!  We want to do the next case!

    case EAPTLS_MORE_FRAGS:
    case EAPTLS_ACK:
      if ((SSL_get_state(mytls_vars->ssl) == 0x0003) && (dophase2 != NULL))
	{
	  // Handle the phase 2 piece.  We pass in the encrypted piece of
	  // the packet, and let phase 2 deal with it!

	  // But, before we do anything, verify the CN.
	  if (mytls_vars->cncheck != NULL)
	    {
	      cnname = get_cert_common_name(mytls_vars->ssl);

	      debug_printf(DEBUG_AUTHTYPES, "Certificate CN : %s\n",cnname);

	      // mytls_vars->cncheck == NULL, do nothing.
	      debug_printf(DEBUG_AUTHTYPES, "Doing a CN Check!\n");
	      
	      if (mytls_vars->cnexact == 1)
		{
		  debug_printf(DEBUG_AUTHTYPES, "Looking for an exact match!\n");

		  if (cnname != NULL)
		    {
		      if (strcmp(mytls_vars->cncheck, cnname) != 0)
			{
			  debug_printf(DEBUG_AUTHTYPES, "Certificate CN didn't match!\n");
			  outframe = NULL;
			  outsize = 0;
			  free(cnname);
			  return XEBADCN;
			} else {
			  debug_printf(DEBUG_AUTHTYPES, "Certificate CN matched!\n");
			}
		    }
		} else {
		  debug_printf(DEBUG_AUTHTYPES, "Looking for a relative match!\n");

		  temp = mytls_vars->cncheck;
		  if (cnname != NULL)
		    {
		      if (strstr(cnname, temp) == NULL)
			{
			  debug_printf(DEBUG_AUTHTYPES, "Certificate CN didn't match!\n");
			  outframe = NULL;
			  outsize = 0;
			  free(cnname);
			  return XEBADCN;
			} else {
			  debug_printf(DEBUG_AUTHTYPES, "Certificate CN matched!\n");
			}
		    }
		}
	    }
	  if (cnname != NULL)
	    {
	      free(cnname);
	      cnname = NULL;
	    }

	  // We are in phase 2, so indicate it.
	  mytls_vars->phase = 2;
	  
	  if ((mytls_vars->resuming != 1) || (mytls_vars->quickResponse != TRUE))
	    {
	      (*dophase2)(thisint, tlsptr, (insize-tlsindex), outframe, outsize);
	    } else {
	      if (*outsize == 0)
		{
		  debug_printf(DEBUG_AUTHTYPES, "Resumed session, ACKing ACK!\n");
		  tls_funcs_build_ack(outframe, outsize);
		  rtnVal = XENONE;	
		}
	    }	  
	} else {
	  rtnVal = tls_funcs_parse(thisint, tlsptr, (insize-tlsindex), outframe, outsize, chunksize);
	  if (rtnVal < 0)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't parse TLS data.\n");
	    }
      	  if ((SSL_get_state(mytls_vars->ssl) == 0x0003) && (dophase2 != NULL) && 
	      (mytls_vars->quickResponse == TRUE))
	    {
	      
	      if (mytls_vars->cncheck != NULL)
		{
		  // But, before we do anything, verify the CN.
		  cnname = get_cert_common_name(mytls_vars->ssl);

		  debug_printf(DEBUG_AUTHTYPES, "Certificate CN : %s\n",cnname);
		}

	      if (cnname != NULL)
		{
		  // mytls_vars->cncheck == NULL, do nothing.
		  if (mytls_vars->cncheck != NULL)
		    {
		      debug_printf(DEBUG_AUTHTYPES, "Doing a CN Check!\n");
		  
		      if (mytls_vars->cnexact == 1)
			{
			  debug_printf(DEBUG_AUTHTYPES, "Looking for an exact match!\n");
			  if (strcmp(mytls_vars->cncheck, cnname) != 0)
			    {
			      debug_printf(DEBUG_AUTHTYPES, "Certificate CN didn't match!\n");
			      outframe = NULL;
			      outsize = 0;
			      return XEBADCN;
			    } else {
			      debug_printf(DEBUG_AUTHTYPES, "Certificate CN matched!\n");
			    }
			} else {
			  debug_printf(DEBUG_AUTHTYPES, "Looking for a relative match!\n");
			  
			  temp = mytls_vars->cncheck;
			  if (strstr(cnname, temp) == NULL)
			    {
			      debug_printf(DEBUG_AUTHTYPES, "Certificate CN didn't match!\n");
			      outframe = NULL;
			      outsize = 0;
			      return XEBADCN;
			    } else {
			      debug_printf(DEBUG_AUTHTYPES, "Certificate CN matched!\n");
			    }
			}
		    }
		}

	      if (cnname != NULL)
		{
		  free(cnname);
		  cnname = NULL;
		}
	      
	      // We made it to phase 2.  So, indicate it.
	      mytls_vars->phase = 2;

	      if ((mytls_vars->resuming != 1) || (mytls_vars->quickResponse != TRUE))
		{
		  (*dophase2)(thisint, tlsptr, (insize-tlsindex), outframe, outsize);
		} else {
		  if (*outsize == 0)
		    {
		      debug_printf(DEBUG_AUTHTYPES, "Resumed session, ACKing ACK!\n");
		      tls_funcs_build_ack(outframe, outsize);
		      rtnVal = XENONE;
		    }
		}
	    } else if (rtnVal == XTLSNEEDDATA)
	      {
		tls_funcs_build_ack(outframe, outsize);
		rtnVal = XENONE;
	      } 
	}
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Invalid TLS flags! (%02X)\n",(uint8_t)inframe[0]);
      rtnVal = XETLSBADFLAGS;
    }

  return rtnVal;
}

char *tls_funcs_gen_keyblock(struct generic_eap_data *thisint)
{
  struct tls_vars *mydata;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "EAP data passed in to tls_funcs_gen_keyblock() is NULL!\n");
      return NULL;
    }

  mydata = (struct tls_vars *)thisint->eap_data;
  
  if (mydata == NULL) return NULL;

  return tls_crypt_gen_keyblock(thisint, mydata->sessionkeyconst,
				mydata->sessionkeylen);
}

int tls_funcs_build_ack(char *outframe, int *outsize)
{
  debug_printf(DEBUG_EVERYTHING, "Sending TLS ACK!\n");
  outframe[0] = 0x00;
  *outsize = 1;
  return XENONE;
}


static void ssl_info_callback(SSL *ssl, int w, int r)
{
  if (!ssl)
    {
      debug_printf(DEBUG_NORMAL, "Invalid context in ssl_info_callback!\n");
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "     --- SSL : %s\n", SSL_state_string_long(ssl));
  if (w & SSL_CB_ALERT)
    debug_printf(DEBUG_AUTHTYPES, "     --- ALERT : %s\n", SSL_alert_desc_string_long(r));
}


static int return_password(char *buf, int size, int rwflag, void *userdata)
{
  strncpy(buf, (char *)(userdata), size);
  buf[size-1] = '\0';
  return(strlen(buf));
}

int tls_funcs_load_root_certs(struct generic_eap_data *thisint, 
			      char *root_cert, char *root_dir, char *crl_dir)
{
  struct tls_vars *mytls_vars;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct in tls_funcs_load_root_certs()!\n");
      return XEMALLOC;
    }

  if ((!root_cert) && (!root_dir))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to tls_funcs_load_root_certs()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  if (!mytls_vars)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP data was passed in to tls_funcs_load_root_certs()!\n");
      return XEMALLOC;
    }

  if (root_cert == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error loading cert!  Path to cert is NULL!\n");
      return XETLSCERTLOAD;
    } else {
      debug_printf(DEBUG_CONFIG, "Loading certificate %s . . . \n", root_cert);
    }

  if (mytls_vars->ctx == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid context in tls_funcs_load_root_certs()!\n");
      return XEMALLOC;
    }

  SSL_CTX_set_info_callback(mytls_vars->ctx, (void (*) ()) ssl_info_callback);
  
  if (SSL_CTX_load_verify_locations(mytls_vars->ctx, root_cert, root_dir) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to initalize path to root certificate!\n");
      debug_printf(DEBUG_NORMAL, "Error : %s\n", ERR_error_string(ERR_get_error(), NULL));
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      return XETLSCERTLOAD;
    }

  debug_printf(DEBUG_CONFIG, "Loaded root certificate %s and dirctory %s\n",
		root_cert, root_dir);

  if (crl_dir) {
    if (SSL_CTX_load_verify_locations(mytls_vars->ctx, NULL, crl_dir) == 0)
      {
	debug_printf(DEBUG_NORMAL, "Failed to initalize path to CRLs!\n");
	debug_printf(DEBUG_NORMAL, "Error : %s\n", ERR_error_string(ERR_get_error(), NULL));
	if(mytls_vars->ctx)
	  {
	    SSL_CTX_free(mytls_vars->ctx);
	    mytls_vars->ctx = NULL;
	  }
	return XETLSCERTLOAD;
      }
  }
  

  /* Do we really want to pick up the default paths? */
  if (SSL_CTX_set_default_verify_paths(mytls_vars->ctx) == 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to initalize default paths for root certificates!\n");
      debug_printf(DEBUG_NORMAL, "Error : %s\n", ERR_error_string(ERR_get_error(), NULL));
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      return XETLSCERTLOAD;
    }

  return XENONE;
}

int tls_funcs_load_random(struct generic_eap_data *thisint, char *random_file)
{
  char *default_random = "/dev/urandom", *file;
  struct tls_vars *mytls_vars; 

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed in to tls_funcs_load_random()!\n");
      return XEMALLOC;
    }

  if (thisint->eap_data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP data in tls_funcs_load_random()!\n");
      return XEMALLOC;
    }

  mytls_vars = thisint->eap_data;

  file = random_file == NULL ? default_random : random_file;

  if (RAND_load_file(file, 1024) < 0)
    {
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
	  
      debug_printf(DEBUG_NORMAL, "Couldn't load random data from %s\n", file);

      return -1;
    } 

  return XENONE;
}


int tls_funcs_load_user_cert(struct generic_eap_data *thisint, 
			     char *client_cert, char *key_file, char *password,
			     char *random_file)
{
  struct tls_vars *mytls_vars;

  if ((!thisint) || (!client_cert) || (!key_file))
    {
      debug_printf(DEBUG_NORMAL, "Invalid state in tls_funcs_load_user_cert()!\n");
      return XENOUSERDATA;
    }

  if (!thisint->eap_data)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP data in tls_funcs_load_user_cert()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;
  	
  SSL_CTX_set_default_passwd_cb_userdata(mytls_vars->ctx, password);
  SSL_CTX_set_default_passwd_cb(mytls_vars->ctx, return_password);

  if (SSL_CTX_use_certificate_file(mytls_vars->ctx, client_cert, 
				   SSL_FILETYPE_ASN1) != 1 &&
      SSL_CTX_use_certificate_file(mytls_vars->ctx, client_cert, 
				   SSL_FILETYPE_PEM) != 1 )
    {
      debug_printf(DEBUG_NORMAL, "Couldn't load client certificate data!\n");
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      return XETLSCERTLOAD;
    }

  debug_printf(DEBUG_CONFIG, "Loading user Private Key from %s...\n", key_file);

  if (SSL_CTX_use_PrivateKey_file(mytls_vars->ctx, key_file, 
				  SSL_FILETYPE_PEM) != 1 &&
      SSL_CTX_use_PrivateKey_file(mytls_vars->ctx, key_file, 
				  SSL_FILETYPE_ASN1) != 1) 
    {
      if(mytls_vars->ctx)
	{
	  SSL_CTX_free(mytls_vars->ctx);
	  mytls_vars->ctx = NULL;
	}
      debug_printf(DEBUG_NORMAL, "Couldn't load client private key!\n");
      return XETLSCERTLOAD;
    }

  if (!SSL_CTX_check_private_key(mytls_vars->ctx))
    {
      debug_printf(DEBUG_NORMAL, "Private key isn't valid!\n");
      return XETLSCERTLOAD;
    }

  SSL_CTX_set_options(mytls_vars->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		      SSL_OP_SINGLE_DH_USE);

  SSL_CTX_set_verify(mytls_vars->ctx, SSL_VERIFY_PEER | 
		     SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  if (tls_funcs_load_random(thisint, random_file))
    {
      return XETLSCERTLOAD;
    }

  // If we made it this far, our user cert is loaded, so indicate it.
  mytls_vars->cert_loaded = TRUE;

  return XENONE;
}

int tls_funcs_failed(struct generic_eap_data *thisint)
{
  struct tls_vars *mytls_vars;

  debug_printf(DEBUG_EVERYTHING, "(TLS-FUNCS) Cleaning up (possible after a failure)!\n");

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct in tls_funcs_cleanup()!\n");
      return XEMALLOC;
    }

  if (!thisint->eap_data)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP data in tls_funcs_cleanup()!\n");
      return XEMALLOC;
    }

  ERR_free_strings();

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  if (mytls_vars->ctx)
    {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-TLS) Freeing mytls_vars->ctx!\n");
      SSL_CTX_free(mytls_vars->ctx);
      mytls_vars->ctx = NULL;
    }

  return XENONE;
}


int tls_funcs_cleanup(struct generic_eap_data *thisint)
{
  int err=XENONE;
  int counter;
  struct tls_vars *mytls_vars;

  debug_printf(DEBUG_EVERYTHING, "(TLS-FUNCS) Cleaning up!\n");

  if ((!thisint) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed to tls_funcs_cleanup()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  err = tls_funcs_failed(thisint);

  if(mytls_vars->ssl) {
      // We don't want to send an alert to the other end..  So do a quiet
      // shutdown.  This violates the TLS standard, but it needed to avoid
      // confusing the other end of the connection when we want to do a
      // reconnect!
      SSL_set_quiet_shutdown(mytls_vars->ssl, 1);

      // Now, close off our old session.
      err = 0;
      counter = 0;
      while ((err == 0) && (counter < 60)) {
        err = SSL_shutdown(mytls_vars->ssl);
        if (err == 0) {
            sleep(1);
            counter++;
        }
      }
      SSL_free(mytls_vars->ssl);
      mytls_vars->ssl = NULL;
  }
  if(mytls_vars->ssl_in) {
      BIO_free(mytls_vars->ssl_in);
      mytls_vars->ssl_in = NULL;
  }

  if (mytls_vars->sessionkeyconst != NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-TLS) Freeing session key const!\n");
      free(mytls_vars->sessionkeyconst);
      mytls_vars->sessionkeyconst = NULL;
    }

  return err;
}

/* TLS PRF from rfc2246 pages 11-12 */
int
tls_funcs_PRF(u_char *secret, int secret_len, u_char *label, int label_len, 
	     u_char *seed, int seed_len, u_char *output, int outlen)
{
  int retVal = 0;
  int L_S1, L_S2;
  u_char *S1, *S2;
  u_char *P_MD5_buf, *P_SHA1_buf;
  u_char *P_seed;
  int P_seed_len;
  u_char A_MD5[MD5_DIGEST_LENGTH];
  u_char A_SHA1[SHA_DIGEST_LENGTH];
  int MD5_iterations, SHA1_iterations;
  int i, hashed_len;
  const EVP_MD *hash;
  HMAC_CTX ctx;

  if ((!secret) || (!label) || (!seed) || (!output))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to tls_funcs_PRF()!\n");
      return XEMALLOC;
    }

  /* determine the length of "half" the secret */
  if (secret_len % 2 == 0) {
    L_S1 = secret_len / 2;
  }
  else {
    L_S1 = secret_len / 2 + 1;
  }
  L_S2 = L_S1;
  S1 = secret; /* first L_S1 bytes of secret */
  S2 = secret + secret_len - L_S2;  /* last L_S2 bytes of secret */
  MD5_iterations = outlen / MD5_DIGEST_LENGTH;
  /* if there is anything left over, iterate 1 more time */
  MD5_iterations = outlen % MD5_DIGEST_LENGTH == 0 ? 
    MD5_iterations : MD5_iterations + 1;
  SHA1_iterations = outlen / SHA_DIGEST_LENGTH;
  SHA1_iterations = outlen % SHA_DIGEST_LENGTH == 0 ?
    SHA1_iterations : SHA1_iterations + 1;
  P_seed_len = label_len + seed_len;
  P_seed = (u_char *)malloc(sizeof(u_char) * P_seed_len);
  if (P_seed == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of P_seed in tls_funcs_PRF().\n");
      return XEMALLOC;
    }

  memcpy(P_seed, label, label_len);
  memcpy(P_seed+label_len, seed, seed_len);
  P_MD5_buf = (u_char *)malloc(sizeof(u_char) * 
			       MD5_iterations  * MD5_DIGEST_LENGTH);
  if (P_MD5_buf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of P_MD5_buf in tls_funcs_PRF().\n");
      free(P_seed);
      P_seed = NULL;
      return XEMALLOC;
    }

  P_SHA1_buf = (u_char *)malloc(sizeof(u_char) *
				SHA1_iterations * SHA_DIGEST_LENGTH);
  if (P_SHA1_buf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of P_SHA1_buf in tls_funcs_PRF().\n");
      free(P_seed);
      P_seed = NULL;
      free(P_MD5_buf);
      P_MD5_buf = NULL;
      return XEMALLOC;
    }

  /* P_MD5 */
  hash = EVP_md5();
  /* Initialize A_MD5 */
  HMAC(hash, S1, L_S1, P_seed, P_seed_len, A_MD5, &hashed_len);

  for (i = 0; i < MD5_iterations; i++) {
    HMAC_Init(&ctx, S1, L_S1, hash);
    HMAC_Update(&ctx, A_MD5, MD5_DIGEST_LENGTH);
    HMAC_Update(&ctx, P_seed, P_seed_len);
    HMAC_Final(&ctx, P_MD5_buf + i*(MD5_DIGEST_LENGTH), &hashed_len);
    HMAC_cleanup(&ctx);
    HMAC(hash, S1, L_S1, A_MD5, MD5_DIGEST_LENGTH,
	 A_MD5, &hashed_len);
  }
    

  /* do P_SHA1 */
  hash = EVP_sha1();
  /* Initialize A_SHA1 */
  HMAC(hash, S2, L_S2, P_seed, P_seed_len, A_SHA1, &hashed_len);

  for (i = 0; i < SHA1_iterations; i++) {
    HMAC_Init(&ctx, S2, L_S2, hash);
    HMAC_Update(&ctx, A_SHA1, SHA_DIGEST_LENGTH);
    HMAC_Update(&ctx, P_seed, P_seed_len);
    HMAC_Final(&ctx, P_SHA1_buf + i*(SHA_DIGEST_LENGTH), &hashed_len);
    HMAC_cleanup(&ctx);
    HMAC(hash, S2, L_S2, A_SHA1, SHA_DIGEST_LENGTH,
	 A_SHA1, &hashed_len);
  }
  /* XOR Them for the answer */
  for (i = 0; i < outlen; i++) {
    *(output + i) = P_MD5_buf[i] ^ P_SHA1_buf[i];
  }
  if (P_seed)
    {free(P_seed); P_seed = NULL;}
  if (P_MD5_buf) 
    {free(P_MD5_buf); P_MD5_buf = NULL;}
  if (P_SHA1_buf) 
    {free(P_SHA1_buf); P_SHA1_buf = NULL;}
  return retVal;
}

