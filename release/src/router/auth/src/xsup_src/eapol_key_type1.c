/**
 * A client-side 802.1x implementation
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
 * Handle keying for type 1 (RC4, non-TKIP) EAPOL Keys
 * File: eapol_key_type1.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eapol_key_type1.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eapol_key_type1.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:24  ysc
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
 * Revision 1.12  2004/04/14 21:09:32  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.11  2004/04/06 20:31:26  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.10  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.9  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.8  2004/03/25 06:06:56  chessing
 *
 * Some debug code cleanups.  Fixed a bug with non-existant, or down interfaces defined in the allow_interfaces would loop forever.  Added calls to reset wireless keys to all 0s when we end up in disconnected, or held state.
 *
 * Revision 1.7  2004/03/24 18:35:46  chessing
 *
 * Added a modified version of a patch from David Relson to fix a problem with some of the debug info in config_grammer.y.  Added some additional checks to eapol_key_type1 that will keep us from segfaulting under some *REALLY* strange conditions.  Changed the set key code in cardif_linux to double check that we aren't a wireless interface before returning an error.  This resolved a problem when XSupplicant was started when an interface was done.  Upon bringing up the interface, XSupplicant would sometimes think it wasn't wireless, and not bother trying to set keys.
 *
 * Revision 1.6  2004/03/23 18:59:34  chessing
 *
 * Small patch to fix a problem where we would include trailing 0s in calculation of the key packet HMAC, causing the HMAC to fail.  This was a big problem with Cisco APs.  Hopefully this will resolve the last of the percieved problems with Atheros cards. ;)
 *
 * Revision 1.5  2004/03/20 05:24:38  chessing
 *
 * Fixed a nasty little keying bug where the HMAC passed, but the key wasn't decrypted correctly.  For some reason, this doesn't always cause problems.  (My Orinoco based card worked fine against an AP-2000 at work, but failed against both an DWL-AP900+, and AP-600b at home!)  This may resolve some of the issues people have seen on the list.
 *
 * Revision 1.4  2004/02/28 01:26:38  chessing
 *
 * Several critical updates.  Fixed the HMAC failure on some keys. (This was due to a lot more than just an off-by-one.)  Fixed up the key decryption routine to identify key packets with no encrypted key, and use the peer key instead.  When using the peer key, we also can handle packets that are padded funny.  (Our Cisco AP1200 has two null pad bytes at the end of some key frames.)  Changed the response ID function to not add a 00 to the end of the ID.  The 00 byte shouldn't have been seen by the RADIUS server unless they were not paying attention to the EAP-Length.  So, this wasn't really a bug fix.  Started to add support for CN checking for TLS based protocols.
 *
 * Revision 1.3  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.2  2003/11/19 04:23:18  chessing
 *
 * Updates to fix the import
 *
 *
 *
 *******************************************************************/

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <string.h>
//#include <stdint.h>
#include <netinet/in.h>
#include "xsup_debug.h"
#include "xsup_err.h"
#include "frame_structs.h"
#include "cardif/cardif.h"
#include "key_statemachine.h"
#include "eapol_key_type1.h"

int eapol_dump_keydata(char *inframe, int framesize)
{
  struct key_packet *keydata;
  int length;

  if (!inframe)
    {
      debug_printf(DEBUG_NORMAL, "Invalid frame passed to eapol_dump_keydata()!\n");
      return XEMALLOC;
    }

  keydata = (struct key_packet *)inframe;

  debug_printf(DEBUG_INT, "Key Descriptor   = %d\n",keydata->key_descr);

  memcpy(&length, keydata->key_length,2);
  debug_printf(DEBUG_INT, "Key Length       = %d\n",ntohs(length));
  debug_printf(DEBUG_INT, "Replay Counter   = ");
  debug_hex_printf(DEBUG_INT, keydata->replay_counter, 8);
  debug_printf(DEBUG_INT, "Key IV           = ");
  debug_hex_printf(DEBUG_INT, keydata->key_iv, 16);
  debug_printf(DEBUG_INT, "Key Index (RAW)  = %02X\n",keydata->key_index);
  debug_printf(DEBUG_INT, "Key Signature    = ");
  debug_hex_printf(DEBUG_INT, keydata->key_signature, 16);

  return XENONE;
}

/************************************
 *
 * Check the HMAC on the key packet we got.  If we can't validate the
 * HMAC, then we return FALSE, indicating an error.
 *
 ************************************/
int eapol_key_type1_check_hmac(struct interface_data *thisint, char *inframe,
			       int framesize)
{
  struct key_packet *keydata;
  char *framecpy, *calchmac;
  int outlen, retVal, length;

  framecpy = NULL;
  calchmac = NULL;
  keydata = NULL;
  outlen = 0;
  retVal = 0;
  length = 0;

  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_NORMAL, "Bad data passed in to eapol_key_type1_check_hmac()!\n");
      return XEMALLOC;
    }

  if (thisint->keyingMaterial == NULL)
    {
      debug_printf(DEBUG_EVERYTHING, "No keying material available!  Ignoring key frame!\n");
      return XEMALLOC;
    }

  // First, make a copy of the frame.
  framecpy = (char *)malloc(framesize);
  if (framecpy == NULL) return XEMALLOC;

  memcpy(framecpy, inframe, framesize);

  // Now, we want to zero out the HMAC.
  keydata = (struct key_packet *)&framecpy[4];

  memcpy(&length, keydata->key_length, 2);

  bzero((char *)&keydata->key_signature, 16);

  // Once we have done that, we need to calculate the HMAC.
  calchmac = (char *)malloc(16);   // The resulting MAC is 16 bytes long.
  if (calchmac == NULL) return XEMALLOC;

  HMAC(EVP_md5(), thisint->keyingMaterial+32, 32, framecpy, framesize,
       calchmac, &outlen);

  // Now, we need to compare the calculated HMAC to the one sent to us.
  keydata = (struct key_packet *)&inframe[4];

  eapol_dump_keydata((char *)keydata, framesize);

  if (memcmp(calchmac, keydata->key_signature, 16) == 0)
    {
      // The HMAC is valid.
      retVal = TRUE;
    } else {
      retVal = FALSE;
    }

  // Clean up after ourselves.
  free(framecpy);
  framecpy = NULL;
  free(calchmac);
  calchmac = NULL;

  return retVal;
}

int eapol_key_type1_get_rc4(struct interface_data *thisint, u_char *enckey, 
			    u_char *deckey, int keylen, u_char *iv, int ivlen)
{
  u_char *wholekey = NULL;
  RC4_KEY key;

  if ((thisint == NULL) || (enckey == NULL) || (deckey == NULL) ||
      (iv == NULL))
    {
      debug_printf(DEBUG_NORMAL, "Some value passed in to eapol_key_type1_get_rc4() is NULL!\n");
      return XEMALLOC;
    }

  wholekey = (u_char *)malloc(sizeof(u_char) * (ivlen + 32));
  if (wholekey == NULL) return XEMALLOC;

  memcpy(wholekey, iv, ivlen);

  if (!thisint->keyingMaterial)
    {
      debug_printf(DEBUG_NORMAL, "Invalid keying material!  Keys will not be handled correctly!\n");
      return XEMALLOC;
    }

  memcpy(wholekey + ivlen, thisint->keyingMaterial, 32);

  RC4_set_key(&key, ivlen + 32, wholekey);
  RC4(&key, keylen, enckey, deckey);

  if (wholekey)
    {
      free(wholekey);
      wholekey = NULL;
    }

  return XENONE;
}

/*********************************
 *
 * Decrypt the key, and set it on the interface.  If there isn't a key to
 * decrypt, then use the peer key.
 *
 *********************************/
int eapol_key_type1_decrypt(struct interface_data *thisint, char *inframe,
			    int framesize)
{
  struct key_packet *keydata = NULL;
  int keylen, rc=0, length;
  u_char *newkey = NULL, *enckey = NULL;

  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_NORMAL, "Bad data passed in to eapol_key_type1_decrypt()!\n");
      return XEMALLOC;
    }

  keydata = (struct key_packet *)&inframe[0];

  //  keylen = framesize - sizeof(*keydata) - 2;
  memcpy(&length, keydata->key_length, 2);
  keylen = ntohs(length);

  debug_printf(DEBUG_INT, "EAPoL Key Processed: %s [%d] %d bytes.\n",
	       keydata->key_index & UNICAST_KEY ? "unicast" : "broadcast",
	       (keydata->key_index & KEY_INDEX)+1, keylen);

  //  debug_printf(DEBUG_NORMAL, "Blah : %d >= %d\n", ((framesize)-sizeof(*keydata)), keylen);
  if ((keylen != 0) && ((framesize)-sizeof(*keydata) >= keylen))
    {
      newkey = (u_char *)malloc(sizeof(u_char) * keylen);
      if (newkey == NULL) return XEMALLOC;

      enckey = (u_char *)&inframe[sizeof(struct key_packet)];

      debug_printf(DEBUG_INT, "Key before decryption : ");
      debug_hex_printf(DEBUG_INT, enckey, keylen);

      if (eapol_key_type1_get_rc4(thisint, enckey, newkey, keylen, 
				  keydata->key_iv, 16) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't decrypt new key!\n");
	  return XEBADKEY;
	}

      debug_printf(DEBUG_INT, "Key after decryption : ");
      debug_hex_printf(DEBUG_INT, newkey, keylen);

      if (set_wireless_key(thisint, newkey, keylen, keydata->key_index) != 0)
	{
	  rc = FALSE;
	} else {
	  rc = TRUE;
	}

      free(newkey);
      newkey = NULL;
    } else {
      debug_printf(DEBUG_INT, "Using peer key!\n");
      memcpy(&length, keydata->key_length, 2);
      length = ntohs(length);
      if (set_wireless_key(thisint, thisint->keyingMaterial, length, keydata->key_index) != 0)
	{
	  rc = FALSE;
	} else {
	  rc = TRUE;
	}
    }

  return rc;
}

/**********************************
 *
 * We are handed in an EAPoL key frame.  From that frame, we check the frame
 * to make sure it hasn't been changed in transit.  We then determine the 
 * correct key, and make the call to set it.
 *
 **********************************/
void eapol_key_type1_process(struct interface_data *thisint, char *inframe,
			     int framesize)
{
  struct key_packet *keydata;
  struct eapol_header *eapolheader;
  int framelen;

  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to eapol_key_type1_process()!\n");
      return;
    }

  eapolheader = (struct eapol_header *)&inframe[OFFSET_PAST_MAC];

  framelen = ntohs(eapolheader->eapol_length);

  keydata = (struct key_packet *)&inframe[OFFSET_TO_EAPOL+4];

  if (keydata->key_descr != RC4_KEY_TYPE)
    {
      debug_printf(DEBUG_NORMAL, "Key type isn't RC4!\n");
      return;
    }

  if (eapol_key_type1_check_hmac(thisint, (char *)&inframe[OFFSET_TO_EAPOL], framelen+4)==FALSE)
    {
      debug_printf(DEBUG_NORMAL, "HMAC failed on key data!  This key will be discarded.\n");
      return;
      }

  if (eapol_key_type1_decrypt(thisint, (char *)&inframe[OFFSET_TO_EAPOL+4],
			      (framelen)) != TRUE)
    {
      debug_printf(DEBUG_NORMAL, "Failed to set wireless key!\n");
      return;
    }
}
