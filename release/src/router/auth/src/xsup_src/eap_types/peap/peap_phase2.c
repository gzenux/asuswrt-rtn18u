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
 * The driver function for a Linux application layer EAPOL 
 * implementation
 * File: peap_phase2.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: peap_phase2.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: peap_phase2.c,v $
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
 * Revision 1.16  2004/04/14 21:09:32  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.15  2004/04/07 22:23:12  chessing
 *
 * Fixed a segfault when a phase 2 method wasn't defined for TTLS.  Also, fixed an issue with TTLS authentication with Funk's Steel-Belted Radius.  The Funk Server would claim that we send a connection termination message.  However, the issue was that we were sending a length value in our encrypted TLS packets, and it didn't like this.  (I am not sure if Funk uses the Microsoft Crypto Provider, but it may be a strange behavior in MCP.)
 *
 * Revision 1.14  2004/04/06 20:31:27  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.13  2004/04/05 17:19:30  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.12  2004/04/02 20:50:21  chessing
 *
 * Attempt to fix PEAP with IAS. At this point, we can get through the TLS piece of the PEAP authentication, and successfully attempt a phase 2 authentication.  But, for some reason MS-CHAPv2 is failing when used with IAS.  (But at least we are one step closer!)  Also, removed the des pieces that were needed for eap-mschapv2, since we can use the OpenSSL routines instead.  The proper way to handle DES was found while looking at the CVS code for wpa_supplicant.  The fix for phase 1 of PEAP was found while looking at the commit notes for wpa_supplicant.  (wpa_supplicant is part of hostap, and is written/maintained by Jouni Malinen.)
 *
 * Revision 1.11  2004/03/28 06:07:17  chessing
 * Added failure call to EAP methods to enable context resets for TLS based authentication protocols.  The resets are needed if an authentiction attempt fails, and we have session resumption enabled.  However, resetting it when we aren't using session resumption won't hurt anything, and probably isn't a bad idea.  The new failure handler can also be used to destroy passwords after a failed attempt, which will then cause xsupplicant to request another password from any listening GUIs. TLS session resumption is enabled (and works) for TLS and TTLS.  PEAP loops forever, and needs to be reviewed.
 *
 * Revision 1.10  2004/03/27 02:20:07  chessing
 *
 * Fixed a problem where the IPC socket wasn't getting deallocated correctly, and would keep xsupplicant from running a second time.  Added the needed hooks to make PEAP-GTC work.  (Not tested yet.)
 *
 * Revision 1.9  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.8  2004/03/17 21:21:40  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.7  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.6  2004/01/17 21:16:16  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.5  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.4  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.3  2003/11/22 06:10:39  chessing
 *
 * Changes to the eap type process calls, to remove a pointless parameter.
 *
 * Revision 1.2  2003/11/21 05:09:47  chessing
 *
 * PEAP now works!
 *
 *
 *******************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "config.h"
#include "profile.h"
#include "eap.h"
#include "peap_phase2.h"
#include "eappeap.h"
#include "../tls/eaptls.h"
#include "xsup_err.h"
#include "xsup_debug.h"
#include "../mschapv2/eapmschapv2.h"
#include "../otp/eapotp.h"
#include "../tls/tls_crypt.h"

#define VALID_EAP_TYPE  EAP_TYPE_MSCHAP
#define HIGHEST_PEAP_SUPPORTED   1

int set_peap_version(struct phase2_data *p2d, int new_version)
{
  if (!p2d)
    {
      debug_printf(DEBUG_NORMAL, "Invalid phase 2 data in set_peap_version()!\n");
      return XEMALLOC;
    }

  if (new_version > HIGHEST_PEAP_SUPPORTED) 
    {
      p2d->peap_version = HIGHEST_PEAP_SUPPORTED;
      return HIGHEST_PEAP_SUPPORTED;
    }

  // Only change versions if we are changing to a higher one.  This will 
  // keep us from backing off to a lower version mid-communication, should the
  // RADIUS server get confused.
  if (p2d->peap_version < new_version)
    {
      debug_printf(DEBUG_AUTHTYPES, "PEAP Version changed to %d\n",new_version);
      p2d->peap_version = new_version;
    }
  return p2d->peap_version;
}

// Remove the beginning 18 bytes.
void peap_unpad_frame(u_char *in, int in_size, u_char *out, int *out_size)
{
  int i;

  if ((!in) || (!out))
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet buffer in in or out at peap_unpad_frame()!\n");
      return;
    }

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Packet too large in peap_unpad_frame()!\n");
      return;
    }

  *out_size = in_size - 4;

  for (i=0;i<=*out_size;i++)
    {
      out[i] = in[4+i];
    }
}

// Pad out the beginning with 18 bytes.  (Probably 0s.)
void peap_pad_frame(u_char *in, int in_size, u_char *out, int *out_size)
{
  int i;

  if ((!in) || (!out))
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet buffer in in or out at peap_pad_frame()!\n");
      return;
    }

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "In packet size to large!  Ignoring!\n");
      return;
    }

  *out_size = in_size + 4;

  bzero(out, *out_size);
  for (i=0;i<=in_size;i++)
    {
      out[4+i] = in[i];
    }
}


void peap_parse_extension(struct peap_extension *pext, u_char *in ,int in_size)
{
	u_char *ptr;
	struct ext_tlv_header *ptlv_header; 
	ptr=in;
	while(ptr < in+in_size) {
		ptlv_header = (struct ext_tlv_header *)ptr;
		if(ptlv_header->tlv_type == PEAP_RESULT_TLV && ptlv_header->tlv_length ==  PEAP_RESULT_TLV_LEN) {
			pext->flag |= PEAP_RESULT_TLV_EXIST;
			pext->pResult_TLV = ptlv_header;
		}
		if(ptlv_header->tlv_type == PEAP_CRYPTOBINDING_TLV && ptlv_header->tlv_length == PEAP_CRYPTOBINDING_TLV_LEN) {
			pext->flag |= PEAP_CRYPTOBINDING_TLV_EXIST;
			pext->pCryptobinding_TLV = ptlv_header;
		}
		if(ptlv_header->tlv_type == PEAP_SOH_RESPONSE_TLV) {
			pext->flag |= PEAP_SOH_RESPONSE_TLV_EXIST;
			pext->pSoH_TLV = ptlv_header;
		}
		ptr += ptlv_header->tlv_length+sizeof(struct ext_tlv_header );
	}
}
/*Now we only buidl PEAP_RESULT_TLV
 *if Win2008 is forced PEAP_CRYPTOBINDING_TLV, then we can NOT connect. FIXME!!
 */
void peap_build_extension(struct peap_extension *pext,u_char *out,int *out_size)
{
	if(pext->flag & PEAP_RESULT_TLV_EXIST)
		memcpy(out,pext->pResult_TLV,pext->pResult_TLV->tlv_length+sizeof(struct ext_tlv_header));
	*out_size = pext->pResult_TLV->tlv_length+sizeof(struct ext_tlv_header );
}

void do_peap_version1(struct generic_eap_data *thisint, u_char *in, int in_size, 
		      u_char *out, int *out_size)
{
  char *new_frame = NULL, *username = NULL;
  int eapvalue, new_frame_size;
  uint16_t i;
  struct tls_vars *mytls_vars;
  struct config_eap_peap *userdata;

  if ((!thisint) || (!out) || (!out_size))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to do_peap_version1()!\n");
      if (out_size) *out_size = 0;
      return;
    }

  if (in_size > 1520)
    {
      debug_printf(DEBUG_NORMAL, "Invalid frame passed in to do_peap_version1()!\n");
      return;
    }
  
  *out_size = 0;

  /// XXXXXXXXX  Reconsider how this is done! (Phase 2 for PEAP in general.)
  userdata = (struct config_eap_peap *)thisint->eap_conf_data;

  if (!userdata)
    {
      debug_printf(DEBUG_NORMAL, "Invalid user configuration in do_peap_version1()!\n");
      return;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;
  // mytls_vars may be NULL here!  This is okay, as long as we aren't in the
  // middle of an inner authentication.

  eapvalue = in[4];

  debug_printf(DEBUG_AUTHTYPES, "Inner packet : \n");
  if (in_size < 1522)
    {
      debug_hex_dump(DEBUG_AUTHTYPES, in, in_size);
    } else {
      debug_printf(DEBUG_AUTHTYPES, "INVALID PACKET SIZE!\n");
    }

  new_frame = (char *)malloc(1024);
  if (new_frame == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for new_frame in do_peap_version1()!\n");
      return;
    }
  bzero(new_frame, 1024);

  switch ((uint8_t)eapvalue)
    {
    case EAP_REQUEST:
	// In version 1, we answer with an EAP header.
      debug_printf(DEBUG_AUTHTYPES, "Got a Phase 2 EAP_REQUEST!\n");
      out[0] = EAP_RESPONSE;
      out[1] = in[1];  // Use the same ID #

      username = thisint->identity;
      i = htons(strlen(username)+5);
      memcpy((char *)&out[2], (uint16_t *)&i, 2);  // The length of the username + header.
      out[4] = EAP_TYPE_IDENTITY;
      memcpy(&out[5], username, strlen(username)+1);
      thisint->need_password = 0;
      *out_size = strlen(username)+5;

      break;

    case EAP_SUCCESS:
      printf("Got a phase 2 success!\n");
      break;

    case EAP_FAILURE:
      printf("Got a phase 2 failure!\n");
      break;

    default:
    case EAP_TYPE_PEAP:  // Is this a PEAP inner request?
      debug_printf(DEBUG_AUTHTYPES, "Got a phase 2 request for PEAP, NAKing!\n");
      out[0] = EAP_RESPONSE;
      out[1] = in[1];
      out[2] = 0;
      out[3] = 6;
      out[4]=EAP_TYPE_NAK;  // NAK
      out[5]=EAP_TYPE_MSCHAPV2; // MS-CHAPv2
      *out_size = 6;
      break;
      
    case EAP_TYPE_GTC:
      debug_printf(DEBUG_AUTHTYPES, "Got a phase 2 request for GTC!\n");
      if (thisint->eap_data == NULL)
	{
	  eapotp_setup(thisint);
	  thisint->eapid = EAP_TYPE_GTC;
	  debug_printf(DEBUG_AUTHTYPES, "(PEAP - Phase 2) Initialized GTC!\n");
	}

      if (!thisint->eap_data)
	{
	  debug_printf(DEBUG_NORMAL, "Invalid EAP state data in GTC section of do_peap_version1()!\n");
	  return;
	}

      eapotp_process(thisint, (u_char *)&in[5], (in_size-5), new_frame, &new_frame_size);

      if (thisint->need_password == 0)
	{
	  out[0] = EAP_RESPONSE;
	  out[1] = in[1];

	  i = ntohs(6+new_frame_size); // 6 bytes header, plus out answer
	  memcpy(&out[2], (uint16_t *)&i, 2);
	  out[4] = EAP_TYPE_GTC;  // We have a GTC answer

	  memcpy(&out[5], new_frame, new_frame_size);
	  *out_size = new_frame_size+5;
	} else {
	  *out_size = 0;
	}
      break;

    case EAP_TYPE_MSCHAPV2: 
      debug_printf(DEBUG_AUTHTYPES, "Got a phase 2 request for MS-CHAPv2!\n");
      if (thisint->eap_data == NULL)
	{
	  eapmschapv2_setup(thisint);
	  thisint->eapid = EAP_TYPE_MSCHAPV2;
	  debug_printf(DEBUG_AUTHTYPES, "(PEAP - Phase 2) Initalized MS-CHAPv2..\n");
	}

      /*      if (thisint->tempPwd != NULL)
	{
	  debug_printf(DEBUG_AUTHTYPES, "Temp Password : %s\n", thisint->tempPwd);
	  }*/
      if (!thisint->eap_data)
	{
	  debug_printf(DEBUG_NORMAL, "Invalid EAP state data in MS-CHAPv2 part of do_peap_version1()!\n");
	  return;
	}

      eapmschapv2_process(thisint, (u_char *)&in[5], (in_size-5), new_frame, &new_frame_size);
      
      if ((thisint->need_password == 0) && ((new_frame_size > 0) && 
					    (new_frame_size < 1522)))
	{
	  out[0] = EAP_RESPONSE;
	  out[1] = in[1];

	  i = ntohs(6+new_frame_size); // 6 bytes header, plus out answer
	  memcpy(&out[2], (uint16_t *)&i, 2);
	  out[4] = EAP_TYPE_MSCHAPV2;  // We have an MSCHAPv2 answer

	  memcpy(&out[5], new_frame, new_frame_size);
	  *out_size = new_frame_size+5;
	} else {
	  *out_size = 0;
	}
      break;

    case PEAP_EAP_EXTENSION: // EAP Extension
#if 0
      debug_printf(DEBUG_AUTHTYPES, "Got an EAP extension frame!\n");
      out[0] = EAP_RESPONSE;
      memcpy(&out[1], &in[1], in_size-1);
      *out_size = in_size;
#else
  {
		int len=0;
		struct peap_extension ext;
		memset(&ext,0x0,sizeof(struct peap_extension));
		debug_printf(DEBUG_AUTHTYPES, "Got an EAP extension frame!\n");
		out[0] = EAP_RESPONSE;
		/*Copy EAP HEADER*/
		memcpy(&out[1],&in[1],4);
		peap_parse_extension(&ext,&in[5],in_size-5);
		peap_build_extension(&ext,&out[5],&len);
		*out_size=len+5;
		*(unsigned short *)(&out[2])=htons(*out_size);
	}
#endif
      break;

//          default:
      debug_printf(DEBUG_NORMAL, "Not sure how to handle this request! (%02X)\n", eapvalue);
      *out_size = 0;
//      break;
      
    }
  free(new_frame);
}

void do_peap_version0(struct generic_eap_data *thisint, u_char *in, int in_size, 
		      u_char *out, int *out_size)
{
  char *padded_frame, *new_frame;
  int padded_size, new_frame_size, eframe = 0;

  if (!out_size)
    {
      debug_printf(DEBUG_NORMAL, "Invalid pointer for out size!\n");
      return;
    }

  *out_size = 0;

  if (!in)
    {
      debug_printf(DEBUG_NORMAL, "Input frame was NULL!  Ignoring!\n");
      return;
    }

  if (!out)
    {
      debug_printf(DEBUG_NORMAL, "Invalid return buffer!\n");
      return;
    }

  if (in_size>1520)
    {
      debug_printf(DEBUG_NORMAL, "Input frame is too big! Ignoring!\n");
      *out_size = 0;
      return;
    }

  padded_size = in_size;

  padded_frame = (char *)malloc(in_size+19);  // It is 19 bytes to pad out.
  if (padded_frame == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Unable to allocate memory for padded_frame in do_peap_version0()!\n");
      return;
    }

  if ((in[4] == 0x21) && (in[5] == 0x80))  
    {
      eframe = 1;
      memcpy(padded_frame, in, in_size);
    }

  if (eframe != 1) 
    {
      peap_pad_frame(in, in_size, padded_frame, &padded_size);
    }

  new_frame = (char *)malloc(1024);
  if (new_frame == NULL)
    {
      debug_printf(DEBUG_NORMAL, "ACK!  We can't allocate memory!\n");
      return;
    }
 
  do_peap_version1(thisint, padded_frame, padded_size, new_frame, 
		   &new_frame_size);
  free(padded_frame);
  if (eframe !=1) 
    {
      peap_unpad_frame(new_frame, new_frame_size, out, out_size);
    } else {
      memcpy(out, new_frame, new_frame_size);
      *out_size = new_frame_size;
    }
  free(new_frame);

  eframe = 0;
}


void peap_do_phase2(struct generic_eap_data *thisint, u_char *in, int in_size, 
		    u_char *out, int *out_size)
{
  struct tls_vars *mytls_vars;
  struct phase2_data *p2d;
  u_char *decr_data, *encr_data;
  int encrsize, decrsize;
  struct config_eap_peap *peapconf;
  struct generic_eap_data *eapdata;

  if ((!thisint) || (!in) || (!out))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to peap_do_phase2()!\n");
      return;
    }

  *out_size = 0;

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  if (mytls_vars == NULL)
    {
      debug_printf(DEBUG_NORMAL, "mytls_vars (thisint->eap_data) == NULL!\n");
      return;
    }

  peapconf = (struct config_eap_peap *)thisint->eap_conf_data;

  if (peapconf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "peapconf == NULL!\n");
      return;
    }

  p2d = (struct phase2_data *)mytls_vars->phase2data;

  if (p2d->eapdata == NULL)
    {
      p2d->eapdata = (struct generic_eap_data *)malloc(sizeof(struct generic_eap_data));
      if (p2d->eapdata == NULL)
	{
	  *out_size = 0;
	  return;
	}
      memset(p2d->eapdata, 0, sizeof(struct generic_eap_data));
      
      p2d->eapdata->eap_data = NULL;
    }

  p2d->eapdata->eap_conf_data = peapconf->phase2->method_data;
  p2d->eapdata->identity = thisint->identity;

  decr_data = (char *)malloc(1550);
  if (decr_data == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for decryption buffer!\n");
      return;
    }

  encr_data = (char *)malloc(1550);
  if (encr_data == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for encryption buffer!\n");
      free(decr_data);
      return;
    }

  if (in_size > 0)
    {
      tls_crypt_decrypt(thisint, in, in_size, decr_data, &decrsize);
    } else {
      free(decr_data);
      decr_data = NULL;
    }

  // We need to check this.  I don't think it is needed anymore.
  if (decrsize <=0)
    {
      debug_printf(DEBUG_AUTHTYPES, "Sending ACK!\n");
      bzero(out,10);
      *out_size = 1;
      free(decr_data);
      free(encr_data);
      return;
    }

  debug_printf(DEBUG_AUTHTYPES, "Decrypted packet returned %d byte(s)\n", decrsize);

  if (thisint->tempPwd != NULL)
    {
      eapdata = p2d->eapdata;

      if (eapdata != NULL)
	{
	  eapdata->tempPwd = thisint->tempPwd;
	}
    }

  bzero(out, 100);
  switch (p2d->peap_version)
    {
    case 0:
      debug_printf(DEBUG_AUTHTYPES, "Doing PEAP v0!\n");
      do_peap_version0(p2d->eapdata, decr_data, decrsize, encr_data, &encrsize);
      break;
    case 1:
      debug_printf(DEBUG_AUTHTYPES, "Doing PEAP v1!\n");
      do_peap_version1(p2d->eapdata, decr_data, decrsize, encr_data, &encrsize);
      break;
    default:
      debug_printf(DEBUG_NORMAL, "Unknown PEAP version!  (%d)\n",p2d->peap_version);
      break;
    }

  eapdata = p2d->eapdata;
  
  if (eapdata->need_password == 1)
    {
      thisint->need_password = 1;
      thisint->eaptype = eapdata->eaptype;
      thisint->eapchallenge = eapdata->eapchallenge;
      *out_size = 0;
    }

  if (encrsize > 0)
    {
      debug_printf(DEBUG_AUTHTYPES, "Unencrypted return frame : \n");
      debug_hex_dump(DEBUG_AUTHTYPES, encr_data, encrsize);
      tls_crypt_encrypt_nolen(thisint, encr_data, encrsize, out, out_size);
      debug_printf(DEBUG_AUTHTYPES, "Encrypted return frame : \n");
      debug_hex_dump(DEBUG_AUTHTYPES, out, *out_size);
    }

  free(encr_data);
  free(decr_data);
}


void peap_phase2_failed(struct generic_eap_data *thisint)
{
  struct tls_vars *mytls_vars;
  struct phase2_data *p2d;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to peap_phase2_failed()!\n");
      return;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  if (mytls_vars == NULL)
    {
      debug_printf(DEBUG_NORMAL, "mytls_vars (thisint->eap_data) == NULL!\n");
      return;
    }

  p2d = (struct phase2_data *)mytls_vars->phase2data;

  if (p2d->eapdata == NULL)
    {
      // We didn't get to phase 2, so just bail.
      return;
    }

  // For now, we only support MS-CHAPv2, so we can call this.
  eapmschapv2_failed(p2d->eapdata);
}
