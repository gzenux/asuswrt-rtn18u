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
 * File: eap.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eap.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eap.c,v $
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
 * Revision 1.76  2004/04/14 21:09:31  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.75  2004/04/13 22:13:28  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.74  2004/04/06 20:31:25  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.73  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.72  2004/04/01 19:49:11  chessing
 *
 * Trapped the error reported by Pavel Roskin that happens with the config file doesn't have a proper EAP method defined.
 *
 * Revision 1.71  2004/03/28 20:37:09  chessing
 *
 * PEAP session resumption now works.
 *
 * Revision 1.70  2004/03/28 06:07:17  chessing
 * Added failure call to EAP methods to enable context resets for TLS based authentication protocols.  The resets are needed if an authentiction attempt fails, and we have session resumption enabled.  However, resetting it when we aren't using session resumption won't hurt anything, and probably isn't a bad idea.  The new failure handler can also be used to destroy passwords after a failed attempt, which will then cause xsupplicant to request another password from any listening GUIs. TLS session resumption is enabled (and works) for TLS and TTLS.  PEAP loops forever, and needs to be reviewed.
 *
 * Revision 1.69  2004/03/28 02:40:44  chessing
 *
 * Fixed a few small bugs that would cause a segfault if the interface jumpped to a new essid.
 *
 * Revision 1.68  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.67  2004/03/26 03:52:47  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.66  2004/03/25 06:06:56  chessing
 *
 * Some debug code cleanups.  Fixed a bug with non-existant, or down interfaces defined in the allow_interfaces would loop forever.  Added calls to reset wireless keys to all 0s when we end up in disconnected, or held state.
 *
 * Revision 1.65  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.64  2004/03/19 23:43:56  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.63  2004/02/28 01:26:38  chessing
 *
 * Several critical updates.  Fixed the HMAC failure on some keys. (This was due to a lot more than just an off-by-one.)  Fixed up the key decryption routine to identify key packets with no encrypted key, and use the peer key instead.  When using the peer key, we also can handle packets that are padded funny.  (Our Cisco AP1200 has two null pad bytes at the end of some key frames.)  Changed the response ID function to not add a 00 to the end of the ID.  The 00 byte shouldn't have been seen by the RADIUS server unless they were not paying attention to the EAP-Length.  So, this wasn't really a bug fix.  Started to add support for CN checking for TLS based protocols.
 *
 * Revision 1.62  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.61  2004/01/20 00:07:07  chessing
 *
 * EAP-SIM fixes.
 *
 * Revision 1.60  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.59  2004/01/17 21:16:15  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.58  2004/01/15 23:45:10  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.57  2004/01/15 01:12:44  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.56  2004/01/14 22:07:24  chessing
 *
 * Fixes that were needed in order to allow us to authenticate correctly.  We should now be able to authenticate using only information provided by the config file!
 *
 * Revision 1.55  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.54  2004/01/13 01:55:55  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.53  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.52  2003/12/28 20:41:57  chessing
 *
 * Added support for EAP-GTC.  It is the exact same code as OTP, so only the EAP type and defines in eap.c were needed.
 *
 * Revision 1.51  2003/12/28 07:13:21  chessing
 *
 * Fixed a problem where we would segfault on an EAP type we didn't understand.  Added EAP-OTP.  EAP-OTP has been tested using the opie package, and Radiator 3.8.  EAP-OTP currently prompts for a passphrase, which it shouldn't do, so it should be considered *VERY* much in test mode until we finish the GUI.
 *
 * Revision 1.50  2003/12/14 06:11:03  chessing
 *
 * Fixed some stuff with SIM in relation to the new config structures.  Cleaned out CR/LF from LEAP source files.  Added user certificate support to TTLS and PEAP. Some additions to the IPC code. (Not tested yet.)
 *
 * Revision 1.49  2003/12/07 06:20:19  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 * Revision 1.48  2003/12/04 04:36:24  chessing
 *
 * Added support for multiple interfaces (-D now works), also added DEBUG_EXCESSIVE to help clean up some of the debug output (-d 6).
 *
 * Revision 1.47  2003/11/29 04:46:02  chessing
 *
 * EAP-SIM changes : EAP-SIM will now try to use the IMSI as the username, when the preferred EAP type is SIM, and the username value is NULL.  Also, if simautogen is TRUE, then we will also build and attach a realm as specified in the RFC.
 *
 * Revision 1.46  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.45  2003/11/28 07:46:23  chessing
 *
 * EAPOL no longer uses malloc for allocating the frame buffers.  State machine init stuff is now in statemachine.c where it belongs.  eap_init() now accepts an interface_data struct, to make it conform to other init calls.
 *
 * Revision 1.44  2003/11/27 02:33:25  chessing
 *
 * Added LEAP code from Marios Karagiannopoulos.  Keying still needs to be completed.
 *
 * Revision 1.43  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 * Revision 1.42  2003/11/22 06:10:36  chessing
 *
 * Changes to the eap type process calls, to remove a pointless parameter.
 *
 * Revision 1.41  2003/11/19 04:27:15  chessing
 *
 * Added a few more files that got missed.
 *
 *
 *
 *******************************************************************/

#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "frame_structs.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "config.h"
#include "profile.h"
#include "eap.h"
#include "cmd_handler.h"
#include "interactive.h"

// Header files for auth types we know about.
#include "eap_types/md5/eapmd5.h"
#include "eap_types/tls/eaptls.h"
#include "eap_types/ttls/eapttls.h"
#include "eap_types/mschapv2/eapmschapv2.h"
#include "eap_types/peap/eappeap.h"
#include "eap_types/leap/eapleap.h"
#include "eap_types/otp/eapotp.h"

#ifdef EAP_SIM_ENABLE
#include "eap_types/sim/eapsim.h"
#endif

struct eap_type_handler {
  int eap_auth_type;
  char *eapname;
  int (*eap_auth_setup)(struct generic_eap_data *);
  int (*eap_auth_handlers)(struct generic_eap_data *, u_char *, int, u_char *,
			   int*);
  int (*eap_auth_get_keys)(struct interface_data *);
  int (*eap_auth_failed)(struct generic_eap_data *);
  int (*eap_auth_cleanup)(struct generic_eap_data *);
};

struct eap_type_handler eaphandlers[] = {
#if 0//#ifdef RTL_WPA_CLIENT  

  {EAP_TYPE_TLS, "EAP_TLS", eaptls_setup, eaptls_process, eaptls_get_keys,
   eaptls_failed, eaptls_cleanup},
  {EAP_TYPE_MD5, "EAP_MD5", eapmd5_setup, eapmd5_process, eapmd5_get_keys,
   eapmd5_failed, eapmd5_cleanup},
   {EAP_TYPE_PEAP, "EAP_PEAP", eappeap_setup, eappeap_process, eappeap_get_keys,
   eappeap_failed, eappeap_cleanup},
   {EAP_TYPE_MSCHAPV2, "EAP_MSCHAPV2", eapmschapv2_setup, eapmschapv2_process, 
   eapmschapv2_get_keys, eapmschapv2_failed, eapmschapv2_cleanup},
#else  
  {EAP_TYPE_MD5, "EAP_MD5", eapmd5_setup, eapmd5_process, eapmd5_get_keys,
   eapmd5_failed, eapmd5_cleanup},
  {EAP_TYPE_TLS, "EAP_TLS", eaptls_setup, eaptls_process, eaptls_get_keys,
   eaptls_failed, eaptls_cleanup},
  {EAP_TYPE_TTLS, "EAP_TTLS", eapttls_setup, eapttls_process, eapttls_get_keys,
   eapttls_failed, eapttls_cleanup},
  {EAP_TYPE_MSCHAPV2, "EAP_MSCHAPV2", eapmschapv2_setup, eapmschapv2_process, 
   eapmschapv2_get_keys, eapmschapv2_failed, eapmschapv2_cleanup},
  {EAP_TYPE_PEAP, "EAP_PEAP", eappeap_setup, eappeap_process, eappeap_get_keys,
   eappeap_failed, eappeap_cleanup},
  {EAP_TYPE_LEAP, "EAP_LEAP", eapleap_setup, eapleap_process, eapleap_get_keys,
   eapleap_failed, eapleap_cleanup},
#ifdef EAP_SIM_ENABLE
  {EAP_TYPE_SIM, "EAP_SIM", eapsim_setup, eapsim_process, eapsim_get_keys, 
   eapsim_failed, eapsim_cleanup},
#endif
  {EAP_TYPE_OTP, "EAP_OTP", eapotp_setup, eapotp_process, eapotp_get_keys,
   NULL, eapotp_cleanup},
  {EAP_TYPE_GTC, "EAP_GTC", eapotp_setup, eapotp_process, eapotp_get_keys,
   NULL, eapotp_cleanup},
#endif /* TL_WPA_CLIENT */
  {NO_EAP_AUTH, NULL, NULL, NULL, NULL, NULL, NULL}
};

/***************************************************
 *
 * Initalize anything needed for EAP.
 *
 ***************************************************/
void eap_init(struct interface_data *thisint)
{

}

/***************************************************
 *
 * Cleanup the active EAP type, and anything else that we set up for using
 * EAP.
 *
 ***************************************************/
void eap_cleanup(struct interface_data *thisint)
{
  int searchval;

  if ((!thisint) || (!thisint->userdata))
    {
      debug_printf(DEBUG_EVERYTHING, "Nothing to do in EAP-Cleanup!\n");
      return;
    }

  debug_printf(DEBUG_EVERYTHING, "Calling EAP-Cleanup!\n");
  searchval = 0;
  if (thisint->eapType != 0)
    {
      if (thisint->userdata->activemethod == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "There was nothing in the active method!?\n");
	  return;
	}

      // Find the EAP type we are working with, and call it's cleanup method.
      while ((eaphandlers[searchval].eap_auth_type != thisint->eapType) &&
	     (eaphandlers[searchval].eap_auth_type != NO_EAP_AUTH))
	{
	  searchval++;
	}

      if (eaphandlers[searchval].eap_auth_type != NO_EAP_AUTH)
	{
	  (*eaphandlers[searchval].eap_auth_cleanup)(thisint->userdata->activemethod);
	  thisint->eapType = 0;
	} else {
	  debug_printf(DEBUG_NORMAL, "Couldn't clean up after active EAP type! (Type : %d)\n",thisint->eapType);
	  debug_printf(DEBUG_NORMAL, "This shouldn't be possible!  Please report it to the XSupplicant list!\n");
	}

      if (thisint->userdata->activemethod->identity != NULL)
	{
	  free(thisint->userdata->activemethod->identity);
	  thisint->userdata->activemethod->identity = NULL;
	}

      if (thisint->userdata->activemethod != NULL)
	{
	  free(thisint->userdata->activemethod);
	  thisint->userdata->activemethod = NULL;
	}
    }
}


extern int wpa_keying;

static int wpa_keying_material(struct interface_data *thisint)
{
	int s, ret = 0;

#ifdef RTL_WPA_CLIENT
	debug_printf(DEBUG_EVERYTHING, "%s: set RTLClient.global->supp_kmsm->PMK\n", __FUNCTION__);
	if(thisint->keyingMaterial != NULL)
		memcpy(RTLClient.global->supp_kmsm->PMK, thisint->keyingMaterial, 32);
	else
		memset(RTLClient.global->supp_kmsm->PMK, 0, 32);
//        debug_hex_dump(DEBUG_EVERYTHING, RTLClient.global->supp_kmsm->PMK, 32);
#else
	struct sockaddr_un addr;
	if (!wpa_keying)
		return 0;

	if (thisint->keyingMaterial == NULL)
		return -1;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	debug_printf(DEBUG_NORMAL, "Sending master key to wpa_supplicant.\n");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	addr.sun_path[0] = '\0';
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,
		 "wpa_supplicant");
	if (sendto(s, thisint->keyingMaterial, 32, 0,
		   (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("send");
		ret = -1;
	}
	close(s);
#endif	
	return ret;
}

/*******************************************
 *
 * We got an EAP-Notify message.  Parse, and display it for now.
 *
 *******************************************/
void eap_do_notify(struct interface_data *thisint, char *inframe, int insize)
{
  struct eap_header *myeap;
  char myval[255];

  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_EVERYTHING, "Got a Notify, but nothing to process!\n");
      return;
    }

  myeap = (struct eap_header *)&inframe[OFFSET_TO_EAP];

  bzero(&myval[0], 255);
  
  // We need to determine how long the string that we were returned is.
  // So, take the EAP length value, and subtract 5 to account for the EAP
  // header.
  strncpy(&myval[0], &inframe[OFFSET_TO_DATA], (ntohs(myeap->eap_length)-5));

  debug_printf(DEBUG_NORMAL, "EAP Notification : %s\n", &myval[0]);
}

/*******************************************
 *
 * Process the EAP piece of the packet, determine what type of EAP packet it is
 * and set state machine variables accordingly.  The variables set will
 * cause the state machine to know what to do next.
 *
 *******************************************/
void eap_process_header(struct interface_data *thisint, char *inframe, 
			int insize)
{
  struct eap_header *myeap;

  debug_printf(DEBUG_STATE, "%s: pid = %d\n", __FUNCTION__, getpid());

  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_NORMAL, "Nothing to do in eap_process_header()!\n");
      return;
    }

  if (!thisint->statemachine)
    {
      debug_printf(DEBUG_NORMAL, "Statemachine not initialized in eap_process_header()!\n");
      return;
    }

  myeap = (struct eap_header *)&inframe[OFFSET_TO_EAP];

#ifdef RTL_WPA_CLIENT
 {      
      int old_level = debug_getlevel();
//      debug_setlevel(8, 0);		//Added for test
#endif
  switch (myeap->eap_code)
    {
    case EAP_REQUEST:
      thisint->statemachine->previousId = thisint->statemachine->receivedId;
      thisint->statemachine->receivedId = myeap->eap_identifier;

      switch (myeap->eap_type)
	{
	case EAP_TYPE_IDENTITY:
	  debug_printf(DEBUG_EVERYTHING, "Got EAP-Request-Identification.\n");
	  thisint->statemachine->reqId = TRUE;
	  break;
	  
	case EAP_TYPE_NOTIFY:
	  debug_printf(DEBUG_EVERYTHING, "Got an EAP-Notify.\n");
	  
	  // Process an EAP Notification
	  eap_do_notify(thisint, inframe, insize);
	  break;
	  
	default:
	  debug_printf(DEBUG_EVERYTHING, "Got EAP-Request-Authentication.\n");
	  if (ntohs(myeap->eap_length) <= 4)
	    {
	      debug_printf(DEBUG_NORMAL, "Got invalid EAP packet, ignoring!\n");
	    } else {
	      thisint->statemachine->reqAuth = TRUE;
	    }
	  break;
	}
      break;

    case EAP_RESPONSE:
      debug_printf(DEBUG_EVERYTHING, "Got EAP-Response, ignoring(?).\n");
      if (myeap->eap_type == EAP_TYPE_LEAP) {
	debug_printf(DEBUG_EVERYTHING, "Got LEAP Response Packet.  Ready for AP verification!\n");
	thisint->statemachine->reqAuth = TRUE;
      }
      break;

    case EAP_SUCCESS:
      debug_printf(DEBUG_EVERYTHING, "Got EAP-Success!\n");
      if (thisint->eapType == EAP_TYPE_LEAP) {
      	thisint->statemachine->reqAuth = TRUE;
	myeap->eap_type = EAP_TYPE_LEAP;
      } else {
	debug_printf(DEBUG_NORMAL, "Authenticated!\n");
	thisint->statemachine->eapSuccess = TRUE;
      }

      // Here, we need to execute any commands that are needed after
      // a successful authentication.
#ifndef RTL_WPA_CLIENT
      if (thisint->firstauth == TRUE)
	{
	  cmd_handler_exec(thisint, config_get_first_auth_cmd());
	  thisint->firstauth = FALSE;
	} else {
	  cmd_handler_exec(thisint, config_get_reauth_cmd());
	}
#endif
      // And get our keying material
      eap_get_keying_material(thisint);
      wpa_keying_material(thisint);
      break;

    case EAP_FAILURE:
      debug_printf(DEBUG_EVERYTHING, "Got EAP-Failure!\n");
      debug_printf(DEBUG_NORMAL, "Failure!\n");
      thisint->statemachine->eapFail = TRUE;
      eap_do_fail(thisint);
      break;
    }
#ifdef RTL_WPA_CLIENT
      debug_setlevel(old_level, 0);
 }
#endif
}

/************************************************
 *
 * Process an EAP Request ID, and respond with the username information that
 * we have configured.  (If nothing is configured, we should ignore the
 * packet, and just return.  Returning an outsize of 0 means that we are
 * ignoring things.)
 *
 ************************************************/
void eap_request_id(struct interface_data *thisint, char *outframe, 
		    int *outsize, int *eapsize)
{
  struct eap_header *myeap;
  char *username_ofs;

  if ((!thisint) || (!outframe) || (!outsize) || (!eapsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed to eap_request_id()!\n");
      return;
    }

  if (!thisint->statemachine)
    {
      debug_printf(DEBUG_NORMAL, "State machine not initialized in eap_request_id()!\n");
      return;
    }

  if (!thisint->userdata) return;

  if (!thisint->userdata->methods)
    {
      debug_printf(DEBUG_NORMAL, "No EAP methods defined to use!\n");
      return;
    }

  myeap = (struct eap_header *)&outframe[OFFSET_TO_EAP];

  myeap->eap_code = EAP_RESPONSE;
  myeap->eap_identifier = thisint->statemachine->receivedId;

#ifdef EAP_SIM_ENABLE
  // If we have SIM enabled, there is no username, and the primary EAP method
  // is SIM, then ask the SIM card for it's IMSI to use as the username.
  if ((thisint->userdata->identity == NULL) && 
      (thisint->userdata->methods->method_num == EAP_TYPE_SIM))
    {
      thisint->userdata->identity = (char *)malloc(50);
      if (thisint->userdata->identity == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for identity!\n");
	  return;
	}
      eapsim_get_username(thisint);
    }
#endif

  if (thisint->userdata->identity == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No identity has been specified!  Authentication will not happen!\n");
      return;
    }

  *eapsize = (strlen(thisint->userdata->identity)+sizeof(struct eap_header)-1);
  myeap->eap_length = htons(*eapsize);
  myeap->eap_type = EAP_TYPE_IDENTITY;

  username_ofs = (char *)&outframe[OFFSET_TO_EAP+sizeof(struct eap_header)-1];
  strncpy(username_ofs, thisint->userdata->identity, 
	  strlen(thisint->userdata->identity));

  *outsize = (strlen(thisint->userdata->identity)-1)+sizeof(struct eap_header)+
             sizeof(struct eapol_header);
}
#ifdef RTL_TTLS_MD5_CLIENT
/************************************************
 *
 * Process an authentication request.  Based on the information in the packet,
 * we call the correct EAP type.  We return an error if it is an EAP type
 * that we don't know.
 *
 ************************************************/
int eap_ttls_md5_request_auth(struct generic_eap_data *activemethod,
		     struct config_eap_method *eapConfig,
		     char *inframe, int insize, char *outframe, int *eapsize)

{
  struct eap_header *myouteap, *myineap;
  int eapmethod, done, valideap, working_eap_type, eapinsize = 0;
  struct config_eap_method *start=NULL, *cur=NULL, *newmethod = NULL;
  char *tosendframe;
  int retVal = XENONE, pwd_needed;


	if(!outframe || !eapsize)
		return XEMALLOC;
  if (insize < 5)
    {
      // We got a runt EAP frame.  We don't know what to do with it.
      debug_printf(DEBUG_NORMAL, "Can't process EAP request.  Packet must be"
		   " > 5 bytes, but packet was only %d byte(s).\n", insize);
      return XEMALLOC;
    }

  eapmethod = 0;
  *eapsize = 0;
  done = FALSE;
  valideap = FALSE;

  myineap = (struct eap_header *)inframe;
  tosendframe = (char *)&inframe[sizeof(struct eap_header)-1];
  working_eap_type = myineap->eap_type;
  
  myouteap = (struct eap_header *)outframe;

  // Make sure we have valid method data.
  if (eapConfig == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No EAP methods available in "
		   "eap_request_auth()!\n");
      return XEMALLOC;
    }

  // Check to make sure that the type requested is in our list of valid
  // types.
  
  start = eapConfig;
  cur = start;

  while ((cur != NULL) && (cur->method_num != working_eap_type))
    {
      cur = cur->next;
    }

  // If we have a type that matches, then go ahead...
  if (cur != NULL)
    {
      valideap = TRUE;
      newmethod = cur;
      activemethod->eap_conf_data = newmethod->method_data;
    } else {
      valideap = FALSE;
      activemethod->eap_conf_data = NULL;
    }

  // If the requested EAP type isn't valid, then send a NAK.
  if ((valideap == FALSE) && (ntohs(myineap->eap_length)>4))
    {
      debug_printf(DEBUG_STATE, "Unsupported EAP type requested. (%d)  Sending NAK!\n",myineap->eap_type);
      myouteap->eap_code = EAP_RESPONSE;
      myouteap->eap_identifier = myineap->eap_identifier;
      myouteap->eap_length = htons(6);
      myouteap->eap_type = EAP_TYPE_NAK;

      if (eapConfig == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "There are no authentication methods "
		       "defined for this interface!  Make sure you have at "
		       "least one valid EAP type defined in your "
		       "configuration.\n");
	  return XEBADCONFIG;
	}

      outframe[sizeof(struct eap_header)-1] = eapConfig->method_num;
      *eapsize = 6;
      return *eapsize;
    }

  // Now, determine which authenticator in our array is the right one.
  //eapmethod = eap_find_type(working_eap_type);
    while ((eaphandlers[eapmethod].eap_auth_type != NO_EAP_AUTH) &&
	 (eaphandlers[eapmethod].eap_auth_type != working_eap_type))
    {
      eapmethod++;
    }

  if (eaphandlers[eapmethod].eap_auth_type == NO_EAP_AUTH)
    {
      debug_printf(DEBUG_NORMAL, "No valid EAP type could be found in "
		   "%s:%d!\n", __FUNCTION__, __LINE__);
      // We got an error.
      return -1;
    }

  // If we had an EAP type before, and we have changed this time through,
  // make sure we call the cleanup methods.
  if ((activemethod->eapNum > 0) && 
      (activemethod->eapNum != eaphandlers[eapmethod].eap_auth_type))
    {
      debug_printf(DEBUG_AUTHTYPES, "EAP Type Changed!  Cleaning up old "
		   "type!\n");
      eap_clear_active_method(activemethod);
    }

  // If this is a new EAP type, call the setup method.
  if (activemethod->eapNum == 0)
    {
      if (((*eaphandlers[eapmethod].eap_auth_setup)(activemethod)) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "EAP method failed to set up properly! "
		       "Calling cleanup routine.\n");
	  eap_cleanup(&activemethod);
	  
	  return -1;
	}
	  
      activemethod->eapNum = eaphandlers[eapmethod].eap_auth_type;

      if (activemethod->eap_data == NULL)
	{
	  debug_printf(DEBUG_AUTHTYPES, "This EAP type didn't set up any "
		       "state information!?\n");
	}
    } 

  activemethod->eapid = myineap->eap_identifier;
  eapinsize = ntohs(myineap->eap_length)-5;

  pwd_needed = activemethod->need_password;

 (*eaphandlers[eapmethod].eap_auth_handlers)(activemethod, 
							  (uint8_t *) tosendframe, eapinsize, 
							  (uint8_t *) &outframe[sizeof(struct eap_header)-1], 
							  eapsize);
	

  // See if an EAP type requested a password.
  #if 0
  if ((activemethod->need_password == 1) && (pwd_needed == 0))
    {
      debug_printf(DEBUG_AUTHTYPES, "Requesting password from GUI!\n");

      xsup_ipc_gui_prompt(activemethod->intName, activemethod->tempPwd, 
			  activemethod->eaptype, activemethod->eapchallenge);

      *eapsize = 0;
      free(activemethod->eaptype);
      activemethod->eaptype = NULL;
      free(activemethod->eapchallenge);
      activemethod->eapchallenge = NULL;

      return XENONE;
    };
  #endif
  if ((activemethod->need_password == 1) && (pwd_needed == 1) &&
      (!activemethod->tempPwd)) *eapsize = 0;

  // If we are using LEAP, we need to make some extra calls here.
  if (eaphandlers[eapmethod].eap_auth_type == EAP_TYPE_LEAP)
    {
      if (eapleap_done(activemethod) == 1)
	{
	  retVal = 4;
	}
    }

  if (*eapsize > 0)
    {
      *eapsize = *eapsize + (sizeof(struct eap_header)-1);
      myouteap->eap_length = htons(*eapsize);
      if (eaphandlers[eapmethod].eap_auth_type == EAP_TYPE_LEAP &&
	  myineap->eap_code == EAP_SUCCESS) {
	myouteap->eap_code = EAP_REQUEST;
	myouteap->eap_identifier = myineap->eap_identifier;
      } else {
	myouteap->eap_code = EAP_RESPONSE;
	if (myineap == NULL)
	  {
	    debug_printf(DEBUG_NORMAL, "Invalid packet! (%s:%d)\n",
			 __FUNCTION__, __LINE__);
	    return XENOFRAMES;
	  }
	myouteap->eap_identifier = myineap->eap_identifier;
      }
      myouteap->eap_type = activemethod->eapNum;
    } 

  return retVal;
}

void eap_ttls_md5_request_id(char *identity, int eapid, char *outframe, 
		    int *eapsize)
{
  struct eap_header *myeap;
  char *username_ofs;
  

	if(!identity || !outframe || !eapsize)
		return;
  myeap = (struct eap_header *)outframe;

  myeap->eap_code = EAP_RESPONSE;
  myeap->eap_identifier = eapid; 

  *eapsize = (strlen(identity)+sizeof(struct eap_header) -1);
  myeap->eap_length = htons(*eapsize);
  myeap->eap_type = EAP_TYPE_IDENTITY;

  username_ofs = (char *)&outframe[sizeof(struct eap_header)-1];
  strncpy(username_ofs, identity, strlen(identity));
}

/************************************************
 *
 * Create/update the active method struct.
 *
 ************************************************/
int eap_create_active_method(struct generic_eap_data **activemethod,
			     char *identity, char *tempPwd, char *intname)
{
  struct generic_eap_data *mymethod;

  if (!activemethod )
    return XEMALLOC;

  mymethod = *activemethod;

  if (mymethod == NULL)
    {
      *activemethod = (struct generic_eap_data *)malloc(sizeof(struct generic_eap_data));
      mymethod = *activemethod;

      if (mymethod == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory in %s:%d!\n",
		       __FUNCTION__, __LINE__);
	  return XEMALLOC;
	}

      memset(mymethod, 0, sizeof(struct generic_eap_data));

      mymethod->eap_conf_data = NULL;
      mymethod->eap_data = NULL;
   
      mymethod->identity = (char *)malloc(strlen(identity)+1);
      
      if (mymethod->identity == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to copy identity!\n");
	} else {
	  strcpy(mymethod->identity, identity);
	}
    }

  mymethod->tempPwd = tempPwd;
  mymethod->intName = intname;

  return XENONE;
}

#endif

/************************************************
 *
 * Process an authentication request.  Based on the information in the packet,
 * we call the correct EAP type.  We return an error if it is an EAP type
 * that we don't know.
 *
 ************************************************/
int eap_request_auth(struct interface_data *thisint, char *inframe, 
		      int insize, char *outframe, int *payloadsize, int *eapsize)
{
  struct eap_header *myouteap, *myineap;
  int eapmethod, done, valideap, working_eap_type, eapinsize = 0;
  struct config_eap_method *start=NULL, *cur=NULL, *newmethod = NULL;
  char *tosendframe;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "There is no interface data available in eap_request_auth()!\n");
      return XEMALLOC;
    }

  if ((!outframe) || (!payloadsize) || (!eapsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameter passed in to eap_request_auth()!\n");
      return XEMALLOC;
    }

  eapmethod = 0;
  done = FALSE;
  valideap = FALSE;

  if (inframe != NULL)
    {
      myineap = (struct eap_header *)&inframe[OFFSET_TO_EAP];
      tosendframe = (char *)&inframe[OFFSET_TO_DATA];
      working_eap_type = myineap->eap_type;
    } else {
      myineap = NULL;
      working_eap_type = thisint->eapType;
      tosendframe = NULL;
    }

  myouteap = (struct eap_header *)&outframe[OFFSET_TO_EAP];

  // Make sure we have valid method data.
  if (thisint->userdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No user data available in eap_request_auth()!\n");
      return XEMALLOC;
    }

  if (thisint->userdata->methods == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No EAP methods available in eap_request_auth()!\n");
      return XEMALLOC;
    }

  // Check to make sure that the type requested is in our list of valid
  // types.
  
  start = thisint->userdata->methods;
  cur = start;

  while ((cur != NULL) && (cur->method_num != working_eap_type))
    {
      cur = cur->next;
    }

  // If we have a type that matches, then go ahead...
  if (cur != NULL)
    {
      valideap = TRUE;
      newmethod = cur;   
    } else {
      valideap = FALSE;
    }

  // If the requested EAP type isn't valid, then send a NAK.
  if ((valideap == FALSE) && (inframe != NULL) && (ntohs(myineap->eap_length)>4))
    {
      debug_printf(DEBUG_STATE, "Unsupported EAP type requested. (%d)  Sending NAK!\n",myineap->eap_type);
      myouteap->eap_code = EAP_RESPONSE;
      myouteap->eap_identifier = thisint->statemachine->receivedId;
      myouteap->eap_length = htons(6);
      myouteap->eap_type = EAP_TYPE_NAK;

      if (thisint->userdata == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Userdata is NULL when trying to return a NAK!  Check your configuration to see if it is correct.\n");
	  return XEBADCONFIG;
	}

      if (thisint->userdata->methods == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "There are no authentication methods defined for this interface!  Make sure you have at least one EAP type defined in your configuration.\n");
	  return XEBADCONFIG;
	}

      outframe[OFFSET_TO_DATA] = thisint->userdata->methods->method_num;
      *eapsize = 6;
      *payloadsize = (6 + sizeof(struct eapol_header));
      return *payloadsize;
    }

  // Now, determine which authenticator in our array is the right one.
  eapmethod = 0;

  while ((eaphandlers[eapmethod].eap_auth_type != NO_EAP_AUTH) &&
	 (eaphandlers[eapmethod].eap_auth_type != working_eap_type))
    {
      eapmethod++;
    }
     
  if (eaphandlers[eapmethod].eap_auth_type == NO_EAP_AUTH) 
    {
      if (inframe != NULL)
	{
	  debug_printf(DEBUG_NORMAL, 
		       "No EAP Type Handler found for EAP Type %d!\n",
		       myineap->eap_type);
	}
      return -1;
    }

  // If we had an EAP type before, and we have changed this time through,
  // make sure we call the cleanup methods.
  if ((thisint->eapType > 0) && 
      (thisint->eapType != eaphandlers[eapmethod].eap_auth_type))
    {
      debug_printf(DEBUG_AUTHTYPES, "EAP Type Changed!  Cleaning up old type!\n");
      eap_clear_active_method(thisint);
    }

  // If this is a new EAP type, call the setup method.
  if ((thisint->eapType == 0) || (thisint->userdata->activemethod == NULL))
    {

      if (thisint->userdata->activemethod != NULL)
	{
	  debug_printf(DEBUG_NORMAL, "For some reason thisint->userdata->activemethod != NULL!  We will attempt to clean it up.\n");
	  
	  // If, by some strange alignment of the planets, we managed to get
	  // here, there is a good chance that we will leak memory!
	  free(thisint->userdata->activemethod);
	  thisint->userdata->activemethod = NULL;
	}

      thisint->userdata->activemethod = (struct generic_eap_data *)malloc(sizeof(struct generic_eap_data));
      if (thisint->userdata->activemethod == NULL)
	return -1;
      memset(thisint->userdata->activemethod, 0,
	     sizeof(struct generic_eap_data));

      thisint->userdata->activemethod->eap_conf_data = newmethod->method_data;
      thisint->userdata->activemethod->eap_data = NULL;
      thisint->userdata->activemethod->staleFrame = NULL;
      thisint->userdata->activemethod->staleSize = 0;
      
      thisint->userdata->activemethod->identity = (char *)malloc(strlen(thisint->userdata->identity)+1);
      if (thisint->userdata->activemethod->identity == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory to copy identity!\n");
	} else {
	  strcpy(thisint->userdata->activemethod->identity,
		 thisint->userdata->identity);
	}

      (*eaphandlers[eapmethod].eap_auth_setup)(thisint->userdata->activemethod);
      thisint->eapType = eaphandlers[eapmethod].eap_auth_type;
      if (thisint->userdata->activemethod->eap_data == NULL)
	{
	  debug_printf(DEBUG_AUTHTYPES, "This EAP type didn't set up any state information!?\n");
	}
    }

  // If we were passed a frame, then record the ID, otherwise leave it the
  // same as it was before.  (Assume we are still working on processing the
  // last frame.)
  if (myineap != NULL)
    {
      if (thisint->userdata->activemethod == NULL) 
	{
	  debug_printf(DEBUG_NORMAL, "Memory allocation failure! Activemethod is NULL!\n");
	  return XEMALLOC;
	}
      thisint->userdata->activemethod->eapid = myineap->eap_identifier;
    }

  // If we have had a password given to us from a GUI client, we need to 
  // send it up to our EAP type, so it can be handled.
  if (thisint->userdata->activemethod != NULL)
    {
      if (thisint->tempPassword != NULL)
	{
	  thisint->userdata->activemethod->tempPwd = thisint->tempPassword;
	}
    }

  if (inframe != NULL)
    {
      eapinsize = ntohs(myineap->eap_length)-5;

    }

  if (thisint->userdata->activemethod != NULL)
    {
      if ((thisint->userdata->activemethod->staleFrame != NULL) && (inframe == NULL))
	{
	  debug_printf(DEBUG_AUTHTYPES, "Attempting to repost stale buffer.\n");
	  tosendframe = (char *)malloc(thisint->userdata->activemethod->staleSize);
	  if (tosendframe == NULL)
	    {
	      debug_printf(DEBUG_NORMAL, "Failed to malloc memory for temporary frame buffer!\n");
	      return XEMALLOC;
	    }
	  memcpy(tosendframe, thisint->userdata->activemethod->staleFrame,
		 thisint->userdata->activemethod->staleSize);
	}
    }

  if (tosendframe == NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "No data in frame, returning.\n");
      *payloadsize = 0;
      return XENONE;
    }

  (*eaphandlers[eapmethod].eap_auth_handlers)(thisint->userdata->activemethod, 
					      tosendframe,
					      eapinsize, 
					      &outframe[OFFSET_TO_DATA], 
					      eapsize);

  // See if an EAP type requested a password.
  if (thisint->userdata->activemethod->need_password == 1)
    {
      debug_printf(DEBUG_AUTHTYPES, "Saving current frame!\n");
      debug_printf(DEBUG_AUTHTYPES, "To save frame :\n");
      debug_hex_dump(DEBUG_AUTHTYPES, tosendframe, eapinsize);

      interactive_store_frame(tosendframe, eapinsize, 
			      thisint->userdata->activemethod);
      debug_printf(DEBUG_AUTHTYPES, "Requesting password from GUI!\n");
      interactive_gui_prompt(thisint, thisint->userdata->activemethod->tempPwd,
			     thisint->userdata->activemethod->eaptype,
			     thisint->userdata->activemethod->eapchallenge);
      *eapsize = 0;
      free(thisint->userdata->activemethod->eaptype);
      thisint->userdata->activemethod->eaptype = NULL;
      free(thisint->userdata->activemethod->eapchallenge);
      thisint->userdata->activemethod->eapchallenge = NULL;
      thisint->userdata->activemethod->need_password = 0;
      return XENONE;
    } else {
      // We have used this packet, so remove it from the stale frame buffer.
      if (thisint->userdata->activemethod->staleFrame != NULL)
	{
	  debug_printf(DEBUG_AUTHTYPES, "Clearing out stale buffer!\n");
	  free(thisint->userdata->activemethod->staleFrame);
	  thisint->userdata->activemethod->staleFrame = NULL;
	  thisint->userdata->activemethod->staleSize = 0;
	}
      
      if (thisint->userdata->activemethod->tempPwd == NULL)
	{
	  thisint->tempPassword = NULL;
	}
    }

  if ((tosendframe != NULL) && (inframe == NULL))
  {
    if (tosendframe != NULL)
      {
	debug_printf(DEBUG_AUTHTYPES, "tosendframe isn't the same as inframe!  Purging!\n");
	free(tosendframe);
	tosendframe = NULL;
      }
  }

  // If we are using LEAP, we need to make some extra calls here.
#ifndef RTL_WPA_CLIENT  
  if (eaphandlers[eapmethod].eap_auth_type == EAP_TYPE_LEAP)
    {
      thisint->statemachine->eapSuccess = eapleap_done(thisint->userdata->activemethod);
      if (thisint->statemachine->eapSuccess == 1)
	{
	  eapleap_get_keys(thisint);
	}
    }
#endif    

  if (*eapsize > 0)
    {
      *eapsize = *eapsize + (sizeof(struct eap_header)-1);
      myouteap->eap_length = htons(*eapsize);
      if (eaphandlers[eapmethod].eap_auth_type == EAP_TYPE_LEAP &&
	  myineap->eap_code == EAP_SUCCESS) {
	myouteap->eap_code = EAP_REQUEST;
	myouteap->eap_identifier = myineap->eap_identifier;
      } else {
	myouteap->eap_code = EAP_RESPONSE;
	myouteap->eap_identifier = thisint->statemachine->receivedId;
      }
      myouteap->eap_type = thisint->eapType;
      
      *payloadsize = (*eapsize + sizeof(struct eapol_header));
    } else {
      *payloadsize = 0;
    }

  return *payloadsize;
}


/************************************************************************
 *
 * Clear the active EAP type.  This will be called when the EAP type we are
 * using has changed, or we have encountered another event (such as an
 * essid change) that should require a completely new authentication!
 *
 ************************************************************************/
int eap_clear_active_method(struct interface_data *thisint)
{
  int eapmethod = 0;

  if ((!thisint) || (!thisint->userdata))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct in eap_clear_active_method()!\n");
      return XEMALLOC;
    }

  // First, make sure we have something to clean up.
  if (thisint->userdata->activemethod == NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "There was nothing to clean up in eap_clear active_method!\n");
      return XENONE;
    }

  while ((eaphandlers[eapmethod].eap_auth_type != NO_EAP_AUTH) &&
	 (eaphandlers[eapmethod].eap_auth_type != thisint->eapType))
    {
      eapmethod++;
    }

  if (eaphandlers[eapmethod].eap_auth_type == NO_EAP_AUTH)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find an EAP type handler to clean up from!\n");
      debug_printf(DEBUG_NORMAL, "We will probably leak memory!\n");
      return XENONE;
    }

  (*eaphandlers[eapmethod].eap_auth_cleanup)(thisint->userdata->activemethod);
  thisint->eapType = 0;

  if (thisint->userdata->activemethod->identity != NULL)
    {
      free(thisint->userdata->activemethod->identity);
      thisint->userdata->activemethod->identity = NULL;
    }

  // Our EAP cleanup should have cleared out all of the memory it used,
  // so we only need to clean up activemethod.
  if (thisint->userdata->activemethod != NULL) 
    {
      free(thisint->userdata->activemethod);
      thisint->userdata->activemethod = NULL;
    }

  return XENONE;
}

/*************************************************
 *
 * Ask the EAP method to give us keying material.
 *
 *************************************************/
int eap_get_keying_material(struct interface_data *thisint)
{
  int eapmethod = 0;

  if ((!thisint) || (!thisint->userdata))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure in eap_get_keying_material()!\n");
      return XEMALLOC;
    }

  if (thisint->userdata->activemethod == NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "The EAP type doesn't seem to exist anymore!\n");
      return XENONE;
    }

  while ((eaphandlers[eapmethod].eap_auth_type != NO_EAP_AUTH) &&
	 (eaphandlers[eapmethod].eap_auth_type != thisint->eapType))
    {
      eapmethod++;
    }

  if (eaphandlers[eapmethod].eap_auth_type == NO_EAP_AUTH)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find an EAP type handler to clean up from!\n");
      debug_printf(DEBUG_NORMAL, "We will probably leak memory!\n");
      return XENONE;
    }

  (*eaphandlers[eapmethod].eap_auth_get_keys)(thisint);

  return XENONE;
}

/************************************************************************
 *
 * Notify the eap method that the attempt has failed.  This should be used
 * for things such as destroying a password that has failed, so it will be
 * requested again.  Or, for resetting a context in the case of TLS based
 * authentication methods.
 *
 ************************************************************************/
int eap_do_fail(struct interface_data *thisint)
{
  int eapmethod = 0;

  if ((!thisint) || (!thisint->userdata))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct in eap_do_fail()!\n");
      return XEMALLOC;
    }

  // Make sure that we have something to clear.
  if (thisint->userdata->activemethod == NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "There was no method defined for executing a failure!\n");
      return XENONE;
    }

  while ((eaphandlers[eapmethod].eap_auth_type != NO_EAP_AUTH) &&
	 (eaphandlers[eapmethod].eap_auth_type != thisint->eapType))
    {
      eapmethod++;
    }

  if (eaphandlers[eapmethod].eap_auth_type == NO_EAP_AUTH)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't find an EAP type handler to notify of the failure!\n");
      return XENONE;
    }

  if (eaphandlers[eapmethod].eap_auth_failed == NULL) 
    {
      debug_printf(DEBUG_AUTHTYPES, "EAP handler didn't have a failure method!\n");
      return XENONE;
    }

  (*eaphandlers[eapmethod].eap_auth_failed)(thisint->userdata->activemethod);

  return XENONE;
}
