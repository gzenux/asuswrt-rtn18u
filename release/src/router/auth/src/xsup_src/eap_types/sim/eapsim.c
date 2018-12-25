/**
 * A client-side 802.1x implementation supporting EAP/SIM
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2003 Chris Hessing
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
* EAPOL Function implementations for supplicant
 * 
 * File: eapsim.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eapsim.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eapsim.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
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
 * Revision 1.16  2004/04/26 20:51:14  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.15  2004/04/13 22:13:30  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.14  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.13  2004/03/19 23:43:57  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.12  2004/02/13 05:51:32  chessing
 *
 * Removed pieces from sha1.c that were duplicates for OpenSSL calls.  Hopefully this will resolve the TLS issues that have been under discussion on the list.  Added support for a default path for the config file.  If a config file is not specified on the command line, xsupplicant will attempt to read it from /etc/xsupplicant.conf.  Moved code to request a password from each of the EAP types to interface.c/h.  Currently this change is only implemented in the EAP-SIM module.  The changes to the GUI prompt code now make more sense, and are easier to follow.  It will be updated in other EAP types soon.
 *
 * Revision 1.11  2004/02/07 07:19:37  chessing
 *
 * Fixed EAP-SIM so that it works with FreeRADIUS correctly.  Fixed a bunch of memory leaks in the EAP-SIM, and related code.
 *
 * Revision 1.10  2004/01/20 05:57:06  chessing
 *
 * All EAP types except PEAP and TTLS now support having their passwords sent in via the command line program.  (This means no more gets() call in OTP!)  A config_eap_otp structure was created in config.h to support GTC/OTP.  We need to define an eap_otp and eap_gtc config section.  Since both require some kind of information be presented there are no attributes that need to be defined in their part of the configuration.
 *
 * Revision 1.9  2004/01/20 03:44:32  chessing
 *
 * A couple of small updates.  TTLS now uses the correct phase 2 type as defined by the config file.  Setting dest_mac now works, and has the desired results.  One small fix to EAP-SIM.
 *
 * Revision 1.8  2004/01/20 00:07:07  chessing
 *
 * EAP-SIM fixes.
 *
 * Revision 1.7  2004/01/17 21:16:16  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.6  2004/01/15 23:45:11  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.5  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.4  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.3  2003/12/18 02:09:45  chessing
 *
 * Some small fixes, and working IPC code to get interface state.
 *
 * Revision 1.2  2003/11/24 04:56:04  chessing
 *
 * EAP-SIM draft 11 now works.  Statemachine updated to work based on the up/down state of an interface, rather than just assuming it is up.
 *
 * Revision 1.1  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 *
 *******************************************************************/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/


#ifdef EAP_SIM_ENABLE     // Only build this if it has been enabled.

#include <inttypes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "interactive.h"
#include "profile.h"
#include "config.h"
#include "eap.h"
#include "eapsim.h"
#include "sm_handler.h"
#include "fips.h"
#include "simd5.h"
#include "simd11.h"
#include "xsup_debug.h"
#include "xsup_err.h"

char *do_sha1(char *tohash, int size)
{
  EVP_MD_CTX ctx;
  char *hash_ret;
  int evp_ret_len;

  if (!tohash)
    {
      debug_printf(DEBUG_NORMAL, "Invalid value passed to do_sha1()!\n");
      return NULL;
    }

  hash_ret = (char *)malloc(21);  // We should get 20 bytes returned.
  if (hash_ret == NULL)
    {
      printf("There was a malloc() error in eapsim.c with hash_ret!\n");
      return NULL;
    }
 
  EVP_DigestInit(&ctx, EVP_sha1());
  EVP_DigestUpdate(&ctx, tohash, size);
  EVP_DigestFinal(&ctx, hash_ret, (int *)&evp_ret_len);

  if (evp_ret_len != 20) printf("SHA1 returned something other than what it should have!\n");

  return hash_ret;
}


int eapsim_setup(struct generic_eap_data *thisint)
{
  struct eaptypedata *mydata;

  debug_printf(DEBUG_AUTHTYPES, "(EAP-SIM) Initalized\n");

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed to eapsim_setup()!\n");
      return XEMALLOC;
    }

  thisint->eap_data = (char *)malloc(sizeof(struct eaptypedata));
  if (thisint->eap_data == NULL) return XEMALLOC;

  mydata = (struct eaptypedata *)thisint->eap_data;

  mydata->workingversion = 0;
  mydata->numrands = 0;
  mydata->verlistlen = 0;
  mydata->verlist = NULL;
  mydata->nonce_mt = NULL;
  mydata->keyingMaterial = NULL;
  bzero(&mydata->triplet[0], 3*sizeof(struct triplets));

  thisint->eap_data = (void *)mydata;

  // Initalize our smartcard context, and get ready to authenticate.
  return init_smartcard(thisint);
}

int eapsim_process(struct generic_eap_data *thisint, u_char *dataoffs,
		   int insize, u_char *out, int *outsize)
{
  int packet_offset, outptr, numVers, i, value16, maxver, saved_offset;
  int tlen;
  struct typelength *typelen;
  struct typelengthres *typelenres;
  struct eaptypedata *mydata;
  char *hash, *at_mac_sres, *nsres=NULL, *framecpy, *username;
  char sha1resp[20], K_sres[16], K_encr[16], K_recv[32], K_send[32];
  char mac_val[16], mac_calc[16], K_int[16];
  struct config_eap_sim *userdata;

  if ((!thisint) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed in to eapsim_process()!\n");
      return XEMALLOC;
    }

  mydata = (struct eaptypedata *)thisint->eap_data;
  userdata = (struct config_eap_sim *)thisint->eap_conf_data;

  if (!userdata)
    {
      debug_printf(DEBUG_NORMAL, "Invalid user data struct in eapsim_process()!\n");
      return XEMALLOC;
    }

  if ((thisint->tempPwd == NULL) && (userdata->password == NULL))
    {
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-SIM");
      thisint->eapchallenge = NULL;
      
      *outsize = 0;
      return XENONE;
    }

  // Make sure we have something to process...
  if (dataoffs == NULL) return XENONE;

  if (sc_need_init()==1)
    {
      init_smartcard(thisint);
    }

  if (userdata->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = userdata->username;
    }

  if ((userdata->password == NULL) && (thisint->tempPwd != NULL))
    {
      userdata->password = thisint->tempPwd;
      thisint->tempPwd = NULL;
    }

  *outsize = 0;
  bzero(&mac_calc[0], 16);
  bzero(&mac_val[0], 16);

  switch (dataoffs[0])
    {
    case SIM_START:
      debug_printf(DEBUG_AUTHTYPES, "Got SIM_START!\n");
      bzero(out, 100);
      packet_offset = 3;

      typelen = (struct typelength *)&out[0];
      typelen->type = SIM_START;
      typelen->length = 0;

      typelenres = (struct typelengthres *)&out[3];
      typelenres->type = AT_NONCE_MT;
      typelenres->length = 5;
      typelenres->reserved = 0;

      // Generate a few random bytes for our NONCE MT.
      mydata->nonce_mt = (char *)malloc(16);
      if (mydata->nonce_mt == NULL) return XEMALLOC;

      RAND_bytes(mydata->nonce_mt,16);

      debug_printf(DEBUG_AUTHTYPES, "NONCE MT = ");
      debug_hex_printf(DEBUG_AUTHTYPES, mydata->nonce_mt, 16);

      outptr = 7;
      memcpy(&out[outptr], mydata->nonce_mt, 16);
      outptr += 16;
     
      // Process SIM value fields.
      while (packet_offset < insize)
	{
	  switch (dataoffs[packet_offset])
	    {
	    case AT_MAC:
	      debug_printf(DEBUG_NORMAL, "You cannot have an AT_MAC in a Start packet!\n");
	      return XESIMNOATMAC;

	    case AT_ANY_ID_REQ:
	    case AT_FULLAUTH_ID_REQ:
	    case AT_PERMANENT_ID_REQ:
	      debug_printf(DEBUG_AUTHTYPES, "Got AT_FULLAUTH_ID_REQ or AT_PERMANENT_ID_REQ!\n");
	      typelenres = (struct typelengthres *)&dataoffs[packet_offset];
	      if ((typelenres->length != 5) && (typelenres->length != 1))
		{
		  debug_printf(DEBUG_NORMAL, "Invalid AT_FULLAUTH_ID_REQ length!\n");
		  return XESIMBADLEN;
		}
	      
	      packet_offset+=4;  // Skip the reserved and length bytes.
	      
	      // Build an AT_IDENTITY response.
	      typelenres = (struct typelengthres *)&out[outptr];
	      typelenres->type = AT_IDENTITY;
	      typelenres->length = (strlen(username)/4)+1;
	      typelenres->reserved = htons(strlen(username));
	      outptr+=sizeof(struct typelengthres);
	      
	      memcpy(&out[outptr], username, strlen(username));

	      outptr += strlen(username);

	      break;
	      
	    case AT_VERSION_LIST:
	      debug_printf(DEBUG_AUTHTYPES, "Got an AT_VERSION_LIST request!\n");
	      typelenres = (struct typelengthres *)&dataoffs[packet_offset];
	      
	      debug_printf(DEBUG_AUTHTYPES, "Version List Length (# versions) : %d\n", typelenres->length);
	      numVers = typelenres->length;
	      
	      mydata->verlistlen = ntohs(typelenres->reserved);
	      debug_printf(DEBUG_AUTHTYPES, "Version List Length (bytes) : %d\n",
			   mydata->verlistlen);
	      packet_offset+=sizeof(struct typelengthres);
	      maxver = 0;    // Set the starting value to be 0.

	      mydata->verlist = (char *)malloc(mydata->verlistlen);
	      if (mydata->verlist == NULL) return XEMALLOC;

	      memcpy(mydata->verlist, &dataoffs[packet_offset], 
		     mydata->verlistlen);
	      
	      for (i=0;i<numVers;i++)
		{
		  memcpy(&value16, &dataoffs[packet_offset], 2);
		  value16 = ntohs(value16);
		  debug_printf(DEBUG_AUTHTYPES, "AT_VERSION_LIST Value : %d\n",
			       value16);
		  if (value16 > maxver) maxver = value16;
		  
		  packet_offset += 2;
		}
	      
	      if (maxver > EAPSIM_MAX_SUPPORTED_VER) 
		maxver = EAPSIM_MAX_SUPPORTED_VER;
	      
	      debug_printf(DEBUG_AUTHTYPES, "Setting version to %d\n",maxver);
	      typelenres = (struct typelengthres *)&out[outptr];
	      typelenres->type = AT_SELECTED_VERSION;
	      typelenres->length = 1;
	      typelenres->reserved = htons(maxver);
	      outptr += sizeof(struct typelengthres);

	      mydata->workingversion = maxver;
	      break;
	      
	    default:
	      debug_printf(DEBUG_NORMAL, "Unknown SIM type!\n");
	      return XESIMBADTYPE;
	    }
	}
      // Write the length in the response header.
      value16 = htons(outptr);
      memcpy((char *)&out[1], &value16, 2); 
      *outsize = (outptr);
      break;

    case SIM_CHALLENGE:
      debug_printf(DEBUG_AUTHTYPES, "Got SIM_CHALLENGE!\n");
      packet_offset = 3;

      typelen = (struct typelength *)&out[0];
      typelen->type = SIM_CHALLENGE;
      outptr = 3;

      while (packet_offset < insize)
	{
	  switch (dataoffs[packet_offset])
	    {
	    case AT_RAND:
	      debug_printf(DEBUG_AUTHTYPES, "Got an AT_RAND.\n");
	      typelenres = (struct typelengthres *)&dataoffs[packet_offset];
	      packet_offset+=4;

	      memcpy(mydata->triplet[0].random, &dataoffs[packet_offset], 16);
	      debug_printf(DEBUG_AUTHTYPES, "Random1 = ");
	      debug_hex_printf(DEBUG_AUTHTYPES, mydata->triplet[0].random, 16);
	      do_gsm(mydata->triplet[0].random, mydata->triplet[0].response,
		     mydata->triplet[0].ckey);
	      packet_offset+=16;

	      memcpy(mydata->triplet[1].random, &dataoffs[packet_offset], 16);
	      debug_printf(DEBUG_AUTHTYPES, "Random2 = ");
	      debug_hex_printf(DEBUG_AUTHTYPES, mydata->triplet[1].random, 16);
	      do_gsm(mydata->triplet[1].random, mydata->triplet[1].response,
		     mydata->triplet[1].ckey);
	      packet_offset+=16;

	      memcpy(mydata->triplet[2].random, &dataoffs[packet_offset], 16);
	      debug_printf(DEBUG_AUTHTYPES, "Random3 = ");
	      debug_hex_printf(DEBUG_AUTHTYPES, mydata->triplet[2].random, 16);
	      do_gsm(mydata->triplet[2].random, mydata->triplet[2].response,
		     mydata->triplet[2].ckey);
	      packet_offset+=16;
	      
	      if (mydata->workingversion == 0)
		{
		  hash = (char *)malloc((8*3)+16);  // 3 keys + 16 nonce.
		  if (hash == NULL)
		    {
		      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to build hash!\n");
		      return XEMALLOC;
		    }

		  bzero(hash, ((8*3)+16));
		  memcpy(&hash[0], mydata->triplet[0].ckey, 8);
		  memcpy(&hash[8], mydata->triplet[1].ckey, 8);
		  memcpy(&hash[16], mydata->triplet[2].ckey, 8);
		  memcpy(&hash[24], mydata->nonce_mt, 16);

		  SHA1(hash, 40, &sha1resp[0]);
		} else {
		  tlen = strlen(username)+(8*3)+16+
		    mydata->verlistlen+2;
		  hash = (char *)malloc(tlen);
		  if (hash == NULL) return XEMALLOC;

		  nsres = (char *)malloc(4*3);
		  if (nsres == NULL) return XEMALLOC;

		  bzero(nsres, 12);
		  memcpy(&nsres[0], mydata->triplet[0].response, 4);
		  memcpy(&nsres[4], mydata->triplet[1].response, 4);
		  memcpy(&nsres[8], mydata->triplet[2].response, 4);

		  bzero(hash, tlen);
		  memcpy(&hash[0], username, strlen(username));
		  memcpy(&hash[strlen(username)], mydata->triplet[0].ckey, 8);
		  memcpy(&hash[strlen(username)+8], mydata->triplet[1].ckey, 8);
		  memcpy(&hash[strlen(username)+16],
			 mydata->triplet[2].ckey, 8);
		  memcpy(&hash[strlen(username)+24],
			 mydata->nonce_mt, 16);
		  memcpy(&hash[strlen(username)+24+16],
			 mydata->verlist, mydata->verlistlen);

		  value16 = htons(mydata->workingversion);
		  memcpy(&hash[strlen(username)+24+16+
			       mydata->verlistlen], &value16, 2);

      		  SHA1(hash, (strlen(username)+24+16+
				  mydata->verlistlen+2), sha1resp);

		  free(hash);
		  hash = NULL;
		}

	      debug_printf(DEBUG_AUTHTYPES, "MK = ");
	      debug_hex_printf(DEBUG_AUTHTYPES, &sha1resp[0], 20);

	      at_mac_sres = (char *)malloc(120);
	      if (at_mac_sres == NULL)
		{
		  debug_printf(DEBUG_NORMAL, "Couldn't malloc at_mac_sres!\n");
		  return XEMALLOC;
		}

	      fips186_2_prng(sha1resp, 20, NULL, 0, at_mac_sres, 120);

	      if (mydata->workingversion == 0)
		{
		  memcpy(&K_sres[0], &at_mac_sres[0], 16);
		  memcpy(&K_encr[0], &at_mac_sres[16], 16);
		  memcpy(&K_int[0], &at_mac_sres[32], 16);
		  
		  bzero(&K_recv[0], 32);
		  bzero(&K_send[0], 32);
		  
		  memcpy(&K_recv[0], &at_mac_sres[48], 20);
		  memcpy(&K_send[0], &at_mac_sres[68], 20);
		} else {
		  // K_int is the same as K_aut in Version 1.
       		  memcpy(&K_int[0], &at_mac_sres[16], 16);
		  memcpy(&K_recv[0], &at_mac_sres[32], 32);
		  memcpy(&K_send[0], &at_mac_sres[64], 32);
		}

	      // We should be done with at_mac_sres, so free it.
	      free(at_mac_sres);
	      at_mac_sres = NULL;
	      
	      if (mydata->keyingMaterial != NULL)
		{
		  free(mydata->keyingMaterial);
		  mydata->keyingMaterial = NULL;
		}
	      mydata->keyingMaterial = (char *)malloc(64);
	      if (mydata->keyingMaterial == NULL) return XEMALLOC;

	      bzero(mydata->keyingMaterial, 64);

	      memcpy(mydata->keyingMaterial, &K_recv[0], 32);
	      memcpy(&mydata->keyingMaterial[32], &K_send[0], 32);
	      
	      if (mydata->workingversion == 0)
		{
		  hash = (char *)malloc((4*3)+16);
		  if (hash == NULL) return XEMALLOC;

		  memcpy(&hash[0], mydata->triplet[0].response, 4);
		  memcpy(&hash[4], mydata->triplet[1].response, 4);
		  memcpy(&hash[8], mydata->triplet[2].response, 4);
		  hash[12] = 11;

		  HMAC(EVP_sha1(), &K_sres[0], 16, &hash[0], 13, (char *)&sha1resp[0], &i);
		  debug_printf(DEBUG_AUTHTYPES, "Final return value : ");
		  debug_hex_printf(DEBUG_AUTHTYPES, &sha1resp[0], i);

		  typelenres = (struct typelengthres *)&out[outptr];
		  typelenres->type = AT_MAC_SRES;
		  typelenres->length = 5;
		  typelenres->reserved = 0;

		  outptr += sizeof(struct typelengthres);
		  memcpy(&out[outptr], &sha1resp, i);
		  outptr += i;
		}
	      break;

	    case AT_IV:
	      debug_printf(DEBUG_AUTHTYPES, "Got an IV (Not supported)\n");
	      packet_offset+=5;
	      break;

	    case AT_ENCR_DATA:
	      debug_printf(DEBUG_AUTHTYPES, "Got an AT_ENCR_DATA (Not supported)\n");
	      packet_offset+=5;
	      break;

	    case AT_MAC:
	      debug_printf(DEBUG_AUTHTYPES, "Got an AT_MAC\n");
	      
	      saved_offset = packet_offset;

	      memcpy(&mac_val[0], &dataoffs[packet_offset+4], 16);
	      packet_offset+=20;

	      if (mydata->workingversion == 0)
		{
		  if (do_v0_at_mac(thisint, &K_int[0], dataoffs, insize, 
				   saved_offset, &mac_calc[0]) == -1)
		    {
		      debug_printf(DEBUG_NORMAL, "Error calculating AT_MAC for Version 0!\n");
		      return XESIMBADMAC;
		    }
		} else {
		  debug_printf(DEBUG_AUTHTYPES, "K_int[0] = ");
		  debug_hex_printf(DEBUG_AUTHTYPES, &K_int[0], 16);
		  if (do_v1_at_mac(thisint, &K_int[0], dataoffs, insize, 
				   saved_offset, mydata->nonce_mt, 
				   mydata->verlist, mydata->verlistlen, 
				   mydata->workingversion, &mac_calc[0]) == -1)
		    {
		      debug_printf(DEBUG_NORMAL, "Error calculating AT_MAC for Version 1!\n");
		      return XESIMBADMAC;
		    }
		}

	      if (memcmp(&mac_calc[0], &mac_val[0], 16) != 0)
		{
		  debug_printf(DEBUG_NORMAL, "ERROR : AT_MAC failed MAC check!\n");
		  debug_printf(DEBUG_AUTHTYPES, "mac_calc = ");
		  debug_hex_printf(DEBUG_AUTHTYPES, &mac_calc[0], 16);
		  debug_printf(DEBUG_AUTHTYPES, "mac_val  = ");
		  debug_hex_printf(DEBUG_AUTHTYPES, &mac_val[0], 16);
       		  //return XESIMBADMAC;
		}
	    }
	}

      if (mydata->workingversion == 1)
	{
	  framecpy = (char *)malloc(outptr+8+20+(8*3));
	  if (framecpy == NULL) return XEMALLOC;

	  bzero(framecpy, (outptr+5+20+(4*3)));
	  
	  framecpy[0] = 2;
	  framecpy[1] = thisint->eapid;
	  value16 = htons(outptr+5+20);
	  memcpy(&framecpy[2], &value16, 2);
	  framecpy[4] = EAP_TYPE_SIM;
	  memcpy(&framecpy[5], &out[0], outptr);
	  
	  framecpy[5+outptr] = AT_MAC;
	  framecpy[5+outptr+1] = 5;
	  memcpy(&framecpy[5+outptr+20], nsres, (4*3));

	  debug_printf(DEBUG_AUTHTYPES, "Hashing against :\n");
	  debug_hex_dump(DEBUG_AUTHTYPES, &framecpy[0], outptr+25+12);

	  HMAC(EVP_sha1(), &K_int[0], 16, framecpy, (outptr+5+20+12), &mac_calc[0], &i);
      	  memcpy(&out[outptr], &framecpy[5+outptr], 20);
	  memcpy(&out[outptr+4], &mac_calc[0], 16);
	  outptr += 20;

	  free(framecpy);
	  framecpy = NULL;
	}

      if (nsres != NULL)
	{
	  free(nsres);
	  nsres = NULL;
	}

      value16 = htons(outptr);
      memcpy((char *)&out[1], &value16, 2);

      *outsize = outptr;
      break;
	  
    case SIM_NOTIFICATION:
      debug_printf(DEBUG_NORMAL, "Got SIM_NOTIFICATION! (Unsupported)\n");
      break;
      
    case SIM_REAUTHENTICATION:
      debug_printf(DEBUG_NORMAL, "Got SIM_REAUTHENTICATION! (Unsupported)\n");
      break;
      
    default:
      debug_printf(DEBUG_NORMAL, "Unknown SubType value! (%d)\n", 
		   dataoffs[0]);
      break;
    }
  out[2] = 0;

  return XENONE;
}

int eapsim_get_keys(struct interface_data *thisint)
{
  struct eaptypedata *mydata;

  if ((!thisint) || (!thisint->userdata) || (!thisint->userdata->activemethod)
      || (!thisint->userdata->activemethod->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed to eapsim_get_keys()!\n");
      return XEMALLOC;
    }

  mydata = (struct eaptypedata *)thisint->userdata->activemethod->eap_data;
  if (thisint->keyingMaterial != NULL)
    {
      free(thisint->keyingMaterial);
    }

  thisint->keyingMaterial = (char *)malloc(64);
  if (thisint->keyingMaterial == NULL) return XEMALLOC;

  memcpy(thisint->keyingMaterial, mydata->keyingMaterial, 64);

  return XENONE;
}

int eapsim_failed(struct generic_eap_data *thisint)
{
  struct config_eap_sim *userdata;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_AUTHTYPES, "No valid configuration information in EAP-SIM!  Nothing to do!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_sim *)thisint->eap_conf_data;

#ifndef NO_PWD_RESET
  /*
  if (userdata->password != NULL)
    {
      free(userdata->password);
      userdata->password = NULL;
    }
  */
#endif

  return XENONE;
}

int eapsim_cleanup(struct generic_eap_data *thisint)
{
  debug_printf(DEBUG_AUTHTYPES, "(EAP-SIM) Cleaning up!\n");
  close_smartcard(thisint);
  return XENONE;
}

#endif
