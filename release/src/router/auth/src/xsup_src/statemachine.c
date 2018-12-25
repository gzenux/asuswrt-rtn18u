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
 * File: statemachine.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: statemachine.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: statemachine.c,v $
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
 * Revision 1.17  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.16  2004/03/29 21:57:13  chessing
 *
 * Changed the socket number we use for communication with the daemon from 10240 (which seems like a bad choice) to 26798 (which seems a little more random ;).  Also changed our debug code so that it doesn't output to the console when we are running in daemon mode.  The only way to get debug info while in daemon mode is to set a log file!!!
 *
 * Revision 1.15  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.14  2004/03/25 06:06:56  chessing
 *
 * Some debug code cleanups.  Fixed a bug with non-existant, or down interfaces defined in the allow_interfaces would loop forever.  Added calls to reset wireless keys to all 0s when we end up in disconnected, or held state.
 *
 * Revision 1.13  2004/03/24 18:35:46  chessing
 *
 * Added a modified version of a patch from David Relson to fix a problem with some of the debug info in config_grammer.y.  Added some additional checks to eapol_key_type1 that will keep us from segfaulting under some *REALLY* strange conditions.  Changed the set key code in cardif_linux to double check that we aren't a wireless interface before returning an error.  This resolved a problem when XSupplicant was started when an interface was done.  Upon bringing up the interface, XSupplicant would sometimes think it wasn't wireless, and not bother trying to set keys.
 *
 * Revision 1.12  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.11  2004/03/17 21:21:40  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.10  2004/03/06 03:53:54  chessing
 *
 * We now send logoffs when the process is terminated.  Added a new option to the config file "wireless_control" which will allow a user to disable non-EAPoL key changes.  Added an update to destination BSSID checking that will reset the wireless key to all 0s when the BSSID changes.  (This is what "wireless_control" disables when it is set to no.)  Roaming should now work, but because we are resetting keys to 128 bit, there may be issues with APs that use 64 bit keys.  I will test this weekend.
 *
 * Revision 1.9  2004/02/09 21:50:06  chessing
 *
 * Added patches from Jouni Malinen.  Includes an EAP-MD5 fix, dec_if_nz() patch, more debugging information from the state machine, and global state changes.
 *
 * Revision 1.8  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.7  2004/01/15 23:45:10  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.6  2004/01/15 01:12:44  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.5  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.4  2003/11/28 07:46:23  chessing
 *
 * EAPOL no longer uses malloc for allocating the frame buffers.  State machine init stuff is now in statemachine.c where it belongs.  eap_init() now accepts an interface_data struct, to make it conform to other init calls.
 *
 * Revision 1.3  2003/11/24 04:56:03  chessing
 *
 * EAP-SIM draft 11 now works.  Statemachine updated to work based on the up/down state of an interface, rather than just assuming it is up.
 *
 * Revision 1.2  2003/11/19 04:23:18  chessing
 *
 * Updates to fix the import
 *
 *
 *
 *******************************************************************/

#include <stdio.h>
#include <netinet/in.h>

#include "statemachine.h"
#include "xsup_debug.h"
#include "frame_structs.h"
#include "config.h"
#include "eap.h"
#include "eapol.h"
#include "xsup_err.h"
#include "cardif/cardif.h"

/******************************************
 *
 * Decrement a value, as long as it is greater than 0.
 *
 ******************************************/
void dec_if_nz(int *decval)
{
  if (!decval) return;

  if (*decval > 0) (*decval)--;
}

/******************************************
 *
 * Initalize the state machine
 *
 ******************************************/
int statemachine_init(struct interface_data *newint)
{
  if (!newint) 
    {
      debug_printf(DEBUG_NORMAL, "newint == NULL in statemachine_init()!\n");
      return XEMALLOC;
    }

  newint->statemachine = (struct dot1x_state *)malloc(sizeof(struct dot1x_state));
  
  if (newint->statemachine == NULL) return XEMALLOC;
	memset((unsigned char *)newint->statemachine,0,sizeof(struct dot1x_state));
  // Make sure our state machine is in initalize mode.
  newint->statemachine->initialize = 1;

  // Now, we want to set up a few defaults as per the 802.1x doc, and
  // initalize a few other statemachine variables that we will be needing.
  newint->statemachine->authPeriod = 30;
  newint->statemachine->authWhile = newint->statemachine->authPeriod;

  newint->statemachine->heldPeriod = 60;
  newint->statemachine->heldWhile = newint->statemachine->heldPeriod;

#ifdef RTL_WPA_CLIENT  
  newint->statemachine->startPeriod = 5;
#else  
  newint->statemachine->startPeriod = 30;
#endif  
  newint->statemachine->startWhen = 0;     // Trigger sending an EAPOL-Start
  newint->statemachine->maxStart = 3;

  // Set up our inital state.
  newint->statemachine->reqId = FALSE;
  newint->statemachine->userLogoff = FALSE;
  newint->statemachine->logoffSent = FALSE;
  newint->statemachine->reqAuth = FALSE;
  newint->statemachine->eapSuccess = FALSE;
  newint->statemachine->eapFail = FALSE;
  newint->statemachine->startCount = 0;
  newint->statemachine->previousId = 0xff;
  newint->statemachine->receivedId = 0xff;
  newint->statemachine->suppStatus = UNAUTHORIZED;

  newint->statemachine->tick = FALSE;

  return XENONE;
}


#ifdef RTL_WPA_CLIENT

int statemachine_reset(struct interface_data *newint)
{
  if (!newint) 
    {
      debug_printf(DEBUG_NORMAL, "newint == NULL in statemachine_init()!\n");
      return XEMALLOC;
    }

  //newint->statemachine = (struct dot1x_state *)malloc(sizeof(struct dot1x_state));
  if (newint->statemachine == NULL) return XEMALLOC;

  // Make sure our state machine is in initalize mode.
  newint->statemachine->initialize = 1;

  // Now, we want to set up a few defaults as per the 802.1x doc, and
  // initalize a few other statemachine variables that we will be needing.
  newint->statemachine->authPeriod = 30;
  newint->statemachine->authWhile = newint->statemachine->authPeriod;

  newint->statemachine->heldPeriod = 60;
  newint->statemachine->heldWhile = newint->statemachine->heldPeriod;

#ifdef RTL_WPA_CLIENT  
  newint->statemachine->startPeriod = 30;
#else  
  newint->statemachine->startPeriod = 30;
#endif  
  newint->statemachine->startWhen = 0;     // Trigger sending an EAPOL-Start
  newint->statemachine->maxStart = 3;

  // Set up our inital state.
  newint->statemachine->reqId = FALSE;
  newint->statemachine->userLogoff = FALSE;
  newint->statemachine->logoffSent = FALSE;
  newint->statemachine->reqAuth = FALSE;
  newint->statemachine->eapSuccess = FALSE;
  newint->statemachine->eapFail = FALSE;
  newint->statemachine->startCount = 0;
  newint->statemachine->previousId = 0xff;
  newint->statemachine->receivedId = 0xff;
  newint->statemachine->suppStatus = UNAUTHORIZED;

  newint->statemachine->tick = FALSE;

  return XENONE;
}

#endif /* RTL_WPA_CLIENT */

/******************************************
 *
 * Process the state machine, send a frame if we need to.  Returns >0 if
 * there is a frame to be send.
 *
 ******************************************/
int statemachine_run(struct interface_data *thisint, char *inframe, 
		     int insize, char *outframe, int *outsize)
{
  int retVal = XENONE;

  //printf("%s:\n", __FUNCTION__);

  if ((!thisint) || (!outframe) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to statemachine_run()!\n");
      return XEMALLOC;
    }

  if (thisint->statemachine == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Statemachine is not set up correctly in statemachine_run()!\n");
      return XEMALLOC;
    }

  if (thisint->statemachine->tick == TRUE)
    {
      // The clock ticked -- Update all of the needed counters.
      dec_if_nz(&thisint->statemachine->authWhile);
      dec_if_nz(&thisint->statemachine->heldWhile);
      dec_if_nz(&thisint->statemachine->startWhen);
      thisint->statemachine->tick = FALSE;
#ifdef RTL_WPA_CLIENT
     if (thisint->statemachine->curState != AUTHENTICATED) {
      int old_level = debug_getlevel();
//      debug_setlevel(8, 0);		//Added for test
#endif
      debug_printf(DEBUG_EVERYTHING, "Clock tick! authWhile=%d heldWhile=%d "
		   "startWhen=%d curState=",
		   thisint->statemachine->authWhile,
		   thisint->statemachine->heldWhile,
		   thisint->statemachine->startWhen,
		   thisint->statemachine->curState);
      
      switch (thisint->statemachine->curState)
	{
	case DISCONNECTED:
	  debug_printf_nl(DEBUG_EVERYTHING, "DISCONNECTED\n");
	  break;
	case LOGOFF:
	  debug_printf_nl(DEBUG_EVERYTHING, "LOGOFF\n");
	  break;
	case ACQUIRED:
	  debug_printf_nl(DEBUG_EVERYTHING, "ACQUIRED\n");
	  break;
	case AUTHENTICATING:
	  debug_printf_nl(DEBUG_EVERYTHING, "AUTHENTICATING\n");
	  break;
	case AUTHENTICATED:
	  debug_printf_nl(DEBUG_EVERYTHING, "AUTHENTICATED\n");
	  break;
	case CONNECTING:
	  debug_printf_nl(DEBUG_EVERYTHING, "CONNECTING\n");
	  break;
	case HELD:
	  debug_printf_nl(DEBUG_EVERYTHING, "HELD\n");
	  break;
	default:
	  debug_printf_nl(DEBUG_EVERYTHING, "UNKNOWN!\n");
	  break;
	}
#ifdef RTL_WPA_CLIENT
      debug_setlevel(old_level, 0);
     }
#endif
    }

  thisint->statemachine->portEnabled = get_if_state(thisint);

//  printf("%s(%d):portEnabled(%d), initialize(%d), thisint->statemachine->reqId(%d) 22222---------------\n",__FUNCTION__,__LINE__,
//  	thisint->statemachine->portEnabled,thisint->statemachine->initialize,thisint->statemachine->reqId);//Added for test

  // Our state machine is in initalize mode, so set things up.  (THIS ONE
  // MUST COME LAST, before the switch!)
  if ((thisint->statemachine->initialize == TRUE) || 
      (thisint->statemachine->portEnabled == FALSE))
    {
	////////////////////
	//Need more test here.
	//if((thisint->statemachine->initialize == TRUE)&&(thisint->statemachine->portEnabled == FALSE))
	if(thisint->statemachine->initialize == TRUE)
	{
		//patch for rcv eap request ID when boot up.
		if(thisint->statemachine->reqId==TRUE)
		{
			// do as statemachine->curState == HELD
			  debug_printf(DEBUG_STATE, "[0] Processing HELD state.\n");
			  thisint->statemachine->heldWhile = thisint->statemachine->heldPeriod;
			  thisint->statemachine->eapFail = FALSE;
			  thisint->statemachine->suppStatus = UNAUTHORIZED;
			
		      if (thisint->statemachine->heldWhile == 0)
			{
			  thisint->statemachine->lastState = HELD;
			  thisint->statemachine->curState = DISCONNECTED;
			  debug_printf(DEBUG_STATE, "[0] HELD -> DISCONNECTED\n");
			}
		      if (thisint->statemachine->reqId == TRUE)
			{
			  thisint->statemachine->lastState = HELD;
			  thisint->statemachine->curState = ACQUIRED;
			  debug_printf(DEBUG_STATE, "[0] HELD -> ACQUIRED\n");
			}
		      thisint->statemachine->lastState = HELD;

			thisint->statemachine->initialize = FALSE;	//Added for test
		}
	}
	////////////////////
	else
	{
		      debug_printf(DEBUG_STATE, "(global) -> DISCONNECTED\n");
		      thisint->statemachine->curState = DISCONNECTED;
		      thisint->statemachine->initialize = FALSE;
		      if (thisint->isWireless == TRUE) cardif_reset_keys(thisint);
	}
    }
  else if (thisint->statemachine->eapFail &&
	   !(thisint->statemachine->initialize || 
	     !thisint->statemachine->portEnabled) &&
	   !thisint->statemachine->userLogoff &&
	   !thisint->statemachine->logoffSent)
    {
      debug_printf(DEBUG_STATE, "(global) -> HELD\n");
      thisint->statemachine->lastState = thisint->statemachine->curState;
      thisint->statemachine->curState = HELD;
      if (thisint->isWireless == TRUE) cardif_reset_keys(thisint);
    }
  else if (thisint->statemachine->userLogoff &&
	   !thisint->statemachine->logoffSent &&
	   !(thisint->statemachine->initialize || 
	     !thisint->statemachine->portEnabled))
    {
      debug_printf(DEBUG_STATE, "(global) -> LOGOFF\n");
      thisint->statemachine->lastState = thisint->statemachine->curState;
      thisint->statemachine->curState = LOGOFF;
      if (thisint->isWireless == TRUE) cardif_reset_keys(thisint);
    }
  else if (thisint->statemachine->eapSuccess &&
	   !(thisint->statemachine->initialize || 
	     !thisint->statemachine->portEnabled) &&
	   !thisint->statemachine->userLogoff &&
	   !thisint->statemachine->logoffSent)
    {
      debug_printf(DEBUG_STATE, "(global) -> AUTHENTICATED\n");
      thisint->statemachine->lastState = thisint->statemachine->curState;
      thisint->statemachine->curState = AUTHENTICATED;
    }

  switch (thisint->statemachine->curState)
    {
    case DISCONNECTED:
      debug_printf(DEBUG_STATE, "Processing DISCONNECTED state.\n");
      thisint->statemachine->eapSuccess = FALSE;
      thisint->statemachine->eapFail = FALSE;
      thisint->statemachine->startCount = 0;
      thisint->statemachine->logoffSent = FALSE;
      thisint->statemachine->previousId = 256;
      thisint->statemachine->suppStatus = UNAUTHORIZED;
      thisint->statemachine->lastState = DISCONNECTED;

      // Automatically change to connected state.
      thisint->statemachine->curState = CONNECTING;
      debug_printf(DEBUG_STATE, "DISCONNECTED -> CONNECTING\n");
      break;

    case LOGOFF:
      if (((thisint->statemachine->userLogoff == TRUE) &&
	   (thisint->statemachine->logoffSent == FALSE)) &&
	  !((thisint->statemachine->initialize == TRUE) ||
	    (thisint->statemachine->portEnabled == FALSE)))
	{
	  debug_printf(DEBUG_STATE, "Processing LOGOFF state.\n");
	  txLogoff(outframe, outsize);
	  thisint->statemachine->logoffSent = TRUE;
	  thisint->statemachine->suppStatus = UNAUTHORIZED;
	  retVal = XDATA;    // We have some data to return.
	}
      if (thisint->statemachine->userLogoff != 1)
	{
	  // If we aren't stuck in logoff state, switch to disconnected.
	  thisint->statemachine->lastState = LOGOFF;
	  thisint->statemachine->curState = DISCONNECTED;
	  debug_printf(DEBUG_STATE, "LOGOFF -> DISCONNECTED\n");
	}
      thisint->statemachine->lastState = LOGOFF;
      break;

    case HELD:
      if ((thisint->statemachine->eapFail == TRUE) && 
	  !((thisint->statemachine->initialize == TRUE) || 
	    (thisint->statemachine->portEnabled == FALSE)) &&
	  (thisint->statemachine->userLogoff == FALSE) &&
	  (thisint->statemachine->logoffSent == FALSE))
	{
	  debug_printf(DEBUG_STATE, "Processing HELD state.\n");
	  thisint->statemachine->heldWhile = thisint->statemachine->heldPeriod;
	  thisint->statemachine->eapFail = FALSE;
	  thisint->statemachine->suppStatus = UNAUTHORIZED;
	}
      if (thisint->statemachine->heldWhile == 0)
	{
	  thisint->statemachine->lastState = HELD;
	  thisint->statemachine->curState = DISCONNECTED;
	  debug_printf(DEBUG_STATE, "HELD -> DISCONNECTED\n");
	}
      if (thisint->statemachine->reqId == TRUE)
	{
	  thisint->statemachine->lastState = HELD;
	  thisint->statemachine->curState = ACQUIRED;
	  debug_printf(DEBUG_STATE, "HELD -> ACQUIRED\n");
	}
      thisint->statemachine->lastState = HELD;
      break;

    case AUTHENTICATED:
      if ((thisint->statemachine->eapSuccess == TRUE) &&
	  !((thisint->statemachine->initialize == TRUE) ||
	    (thisint->statemachine->portEnabled == FALSE)))
	{
	  thisint->statemachine->eapSuccess = FALSE;
	  thisint->statemachine->eapFail = FALSE;
	  thisint->statemachine->suppStatus = AUTHORIZED;


	}
      if (thisint->statemachine->reqId == TRUE)
	{
	  thisint->statemachine->lastState = AUTHENTICATED;
	  thisint->statemachine->curState = ACQUIRED;
	  debug_printf(DEBUG_STATE, "AUTHENTICATED -> ACQUIRED\n");
	}
      thisint->statemachine->lastState = AUTHENTICATED;
      break;

    case ACQUIRED:
      if (thisint->statemachine->reqId)
	{
	  debug_printf(DEBUG_STATE, "Processing ACQUIRED state.\n");
	  debug_printf(DEBUG_NORMAL, "Connection established, authenticating...\n");
	  thisint->statemachine->authWhile = thisint->statemachine->authPeriod;
	  thisint->statemachine->startCount = 0;
	  thisint->statemachine->reqId = FALSE;
	  thisint->statemachine->reqAuth = FALSE;
	  txRspId(thisint, outframe, outsize);
	  thisint->statemachine->previousId = thisint->statemachine->receivedId;
	  retVal = XDATA;
	}
      if (thisint->statemachine->reqAuth == TRUE)
	{
	  thisint->statemachine->lastState = ACQUIRED;
	  thisint->statemachine->curState = AUTHENTICATING;
	  debug_printf(DEBUG_STATE, "ACQUIRED -> AUTHENTICATING)\n");
	  // Below is a hack.  We should find a better way to handle this!
	  retVal=statemachine_run(thisint, inframe, insize, outframe, outsize);
	}
      thisint->statemachine->lastState = ACQUIRED;
      break;

    case AUTHENTICATING:
      if (thisint->statemachine->reqAuth == TRUE)
	{
	  debug_printf(DEBUG_STATE, "Processing AUTHENTICATING state.\n");
	  thisint->statemachine->authWhile = thisint->statemachine->authPeriod;
	  thisint->statemachine->reqAuth = FALSE;
	  txRspAuth(thisint, inframe, insize, outframe, outsize);
	  
	  if (inframe != NULL)
	    thisint->statemachine->previousId = thisint->statemachine->receivedId;
	  if (*outsize != 0) 
	    {
	      retVal = XDATA;
	    }
	} else {
	  // Even though reqAuth != when we are in this state, we want to
	  // call txRspAuth in order to allow EAP types to request 
	  // interactive data.
	  txRspAuth(thisint, inframe, insize, outframe, outsize);
	  if (*outsize != 0)
	    {
	      retVal = XDATA;
	    }
	}
      if (thisint->statemachine->authWhile == 0)
	{
	  thisint->statemachine->lastState = AUTHENTICATING;
	  thisint->statemachine->curState = CONNECTING;
	  debug_printf(DEBUG_STATE, "AUTHENTICATING -> CONNECTING\n");
	}
      if (thisint->statemachine->reqId == TRUE)
	{
	  thisint->statemachine->lastState = AUTHENTICATING;
	  thisint->statemachine->curState = ACQUIRED;
	  debug_printf(DEBUG_STATE, "AUTHENTICATING -> ACQUIRED\n");
	}
      thisint->statemachine->lastState = AUTHENTICATING;
      break;

    case CONNECTING:
      if ((thisint->statemachine->startWhen==0) && 
	  (thisint->statemachine->startCount < thisint->statemachine->maxStart))
	{
	  debug_printf(DEBUG_STATE, "Processing CONNECTING state.\n");
	  thisint->statemachine->startWhen = thisint->statemachine->startPeriod;
	  thisint->statemachine->startCount++;
	  thisint->statemachine->reqId = FALSE;
	  txStart(outframe, outsize);
	  retVal = XDATA;
	}
      if (thisint->statemachine->reqId == TRUE)
	{
	  thisint->statemachine->lastState = CONNECTING;
	  thisint->statemachine->curState = ACQUIRED;
	  debug_printf(DEBUG_STATE, "CONNECTING -> ACQUIRED\n");
	}
#ifndef RTL_WPA_CLIENT  
      if ((thisint->statemachine->startWhen == 0) && 
	  (thisint->statemachine->startCount >= thisint->statemachine->maxStart))
	{
	  debug_printf(DEBUG_NORMAL, "Defaulting to AUTHENTICATED state!\n");

	  thisint->statemachine->lastState = CONNECTING;
	  thisint->statemachine->curState = AUTHENTICATED;
	  debug_printf(DEBUG_STATE, "CONNECTING -> AUTHENTICATED\n");
	}
#endif /* RTL_WPA_CLIENT */	
      thisint->statemachine->lastState = CONNECTING;
      break;
    }

  return retVal;
}

/*****************************************
 *
 * Clean up our state machine.
 *
 *****************************************/
int statemachine_cleanup(struct interface_data *thisint)
{
  debug_printf(DEBUG_EVERYTHING, "Doing statemachine cleanup!\n");

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to statemachine_cleanup()!\n");
      return XEMALLOC;
    }

  if (thisint->statemachine != NULL)
    {
      free(thisint->statemachine);
      thisint->statemachine = NULL;
    }
  
  return XENONE;
}

/*****************************************
 *
 * Create a logoff frame to be sent out to the network.
 *
 *****************************************/
int txLogoff(char *outframe, int *outsize)
{
  struct eapol_header *myframe;

  if ((!outframe) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to txLogoff()!\n");
      return XEMALLOC;
    }

  debug_printf(DEBUG_STATE, "Sending EAPOL-Logoff Frame.\n");

  myframe = (struct eapol_header *)&outframe[OFFSET_PAST_MAC];

  myframe->frame_type = htons(EAPOL_FRAME);
  myframe->eapol_version = MAX_EAPOL_VER;
  myframe->eapol_type = EAPOL_LOGOFF;
  myframe->eapol_length = 0;

  *outsize = sizeof(struct eapol_header)+OFFSET_PAST_MAC;
  return *outsize;
}

/********************************************
 *
 * Build the response ID frame to be sent out to the network.
 *
 ********************************************/
int txRspId(struct interface_data *thisint, char *outframe, int *outsize)
{
  struct eapol_header *myframe;
  int eapsize, outfsize;

  debug_printf(DEBUG_STATE, "Sending EAPOL-Response-Identification\n");

  if ((!thisint) || (!outframe) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to txRspId()!\n");
      return XEMALLOC;
    }

  myframe = (struct eapol_header *)&outframe[OFFSET_PAST_MAC];

  myframe->frame_type = htons(EAPOL_FRAME);
  myframe->eapol_version = MAX_EAPOL_VER;
  myframe->eapol_type = EAP_PACKET;

  eap_request_id(thisint, outframe, &outfsize, &eapsize);

  myframe->eapol_length = htons(eapsize); 

  *outsize = (outfsize + OFFSET_PAST_MAC);

  return XDATA;
}

/*************************************************
 *
 * Build the authentication response frame, and return it to be sent out the
 * interface.
 *
 *************************************************/
int txRspAuth(struct interface_data *thisint, char *inframe, int insize,
	      char *outframe, int *outsize)
{
  struct eapol_header *myframe;
  int payloadsize, eapsize=0;

  debug_printf(DEBUG_STATE, "Sending EAPOL-Response-Authentication\n");

  if ((!thisint) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to txRspAuth()!\n");
      return XEMALLOC;
    }

  if (outframe == NULL)
    {
      debug_printf(DEBUG_STATE, "Output appears to be NULL!\n");
      return XENOTHING_TO_DO;
    }

  myframe = (struct eapol_header *)&outframe[OFFSET_PAST_MAC];

  eap_request_auth(thisint, inframe, insize, outframe, &payloadsize, &eapsize);

  if (eapsize != 0)
    {
      myframe->frame_type = htons(EAPOL_FRAME);
      myframe->eapol_version = MAX_EAPOL_VER;
      myframe->eapol_type = EAP_PACKET;
      myframe->eapol_length = htons(eapsize);

      *outsize = (payloadsize + OFFSET_PAST_MAC);
    } else {
     debug_printf(DEBUG_STATE,"%s:%d ERROR!\n",__FUNCTION__, __LINE__);
      *outsize = 0;
    }
  return *outsize;
}

/*********************************************
 *
 * Build an EAPoL Start frame to be sent out to the network.
 *
 *********************************************/
int txStart(char *outframe, int *outsize)
{
  struct eapol_header *myframe;

  if ((!outframe) || (!outsize))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to txStart()!\n");
      return XEMALLOC;
    }

  debug_printf(DEBUG_STATE, "Sending EAPOL-Start Frame.\n");
  
  myframe = (struct eapol_header *)&outframe[OFFSET_PAST_MAC];

  myframe->frame_type = htons(EAPOL_FRAME);
  myframe->eapol_version = MAX_EAPOL_VER;
  myframe->eapol_type = EAPOL_START;
  myframe->eapol_length = 0;

  *outsize = sizeof(struct eapol_header)+OFFSET_PAST_MAC;
  return *outsize;
}
