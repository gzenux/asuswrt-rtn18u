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
 *
 * File: interactive.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: interactive.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: interactive.c,v $
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
 * Revision 1.5  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.4  2004/03/20 05:24:38  chessing
 *
 * Fixed a nasty little keying bug where the HMAC passed, but the key wasn't decrypted correctly.  For some reason, this doesn't always cause problems.  (My Orinoco based card worked fine against an AP-2000 at work, but failed against both an DWL-AP900+, and AP-600b at home!)  This may resolve some of the issues people have seen on the list.
 *
 * Revision 1.3  2004/03/19 23:43:56  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.2  2004/03/17 21:21:40  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.1  2004/02/13 05:51:32  chessing
 *
 * Removed pieces from sha1.c that were duplicates for OpenSSL calls.  Hopefully this will resolve the TLS issues that have been under discussion on the list.  Added support for a default path for the config file.  If a config file is not specified on the command line, xsupplicant will attempt to read it from /etc/xsupplicant.conf.  Moved code to request a password from each of the EAP types to interface.c/h.  Currently this change is only implemented in the EAP-SIM module.  The changes to the GUI prompt code now make more sense, and are easier to follow.  It will be updated in other EAP types soon.
 *
 *
 *******************************************************************/

#include <stdlib.h>
#include <string.h>
#include "xsup_err.h"
#include "xsup_debug.h"
#include "config.h"
#include "profile.h"
#include "eap.h"
#include "ipc_callout.h"
#include "xsup_ipc.h"
#include "interactive.h"

/*******************************************************************
 *
 * Check to see if we need to poke the GUI to ask for a password.  If we do,
 * then send the GUI a message, and return.  If we determine we have a 
 * password, then we should set procReady to TRUE.
 *
 * The caller should check the return to see if it is XPROMPT, or XENONE.
 * If it is XPROMPT, the caller may choose to check if the frame buffer 
 * contains anything.  If it does, it should call the 
 * interactive_store_frame() function.
 *
 * When called, **password should point to a pointer to the password for
 * the calling EAP type.  *tempPwd should point to thisint->tempPwd, and
 * eapType should point to a string that identifies the EAP type that is
 * calling the function.  (The EAP type string will be passed to the GUI
 * to be displayed in the box that prompts for a password.)  Optionally,
 * the caller may fill in a value for challenge.  This is a string that
 * will be sent to the GUI to be used to create the correct return value.
 * For EAP types like OTP and GTC, it should contain the challenge string
 * to be displayed to the user.  (Or it could be used with an OTP front-end
 * that simply requires the users password be typed, and it generates the
 * correct response sequence.  If there is no challenge data to be passed
 * up, this value should be NULL!
 *
 *******************************************************************/
int interactive_gui_prompt(struct interface_data *thisint,  char *tempPwd, 
			   char *eapType, char *challenge)
{
  char packet[1512];
  struct ipc_header *header;
  int bufptr = 0;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed in to interactive_gui_prompt()!\n");
      return XEMALLOC;
    }

  if (tempPwd == NULL)
    {
      // Ask the GUI to prompt for a password.
      debug_printf(DEBUG_AUTHTYPES, "Asking the GUI for a password.\n");
      debug_printf(DEBUG_AUTHTYPES, "EAP type is %s, challenge is %s\n",
		   eapType, challenge);

      bzero((char *)&packet[0], 512);
      header = (struct ipc_header *)&packet[0];
      header->version = 1;
      strcpy(&header->interface[0], thisint->intName);
      header->numcmds = 0;

      ipc_callout_request_password(thisint, &bufptr, (char *)&packet[0],
				   512, eapType, challenge);

      xsup_ipc_send_all_registered(thisint, (char *)&packet, bufptr);
      
      // Let the caller know we are asking for a password.
      return XPROMPT;
    }

  return XENONE;
}

/***********************************************************************
 *
 * This function stores a frame in to an EAP type's data structure to be used
 * at a later time, once the needed interactive piece is complete.  (Usually
 * after the user has entered a password to the GUI.)  If there is no frame
 * to pass in, the cur_frame value should be NULL (or *NULL) and cur_size 
 * should be 0.  **frame_hook should be a pointer to a memory buffer that
 * we can allocate to store the frame passed in through cur_frame.  It should
 * be assumed that this buffer will be destroyed, and refilled in a new 
 * request frame comes in!  (Which is why we allocate the buffer in here. ;)
 * hook_size should be a pointer to an int that can hold the numeric 
 * representation of the size of frame_hook.
 *
 * In general, if the value for **cur_frame is NULL, there is no need to call
 * this function.  (It will simply waste a few cycles calling, and returning.)
 * However, calling this function with a NULL value will not fail, it will
 * simply return XENONE.
 *
 ***********************************************************************/
int interactive_store_frame(char *cur_frame, int cur_size, 
			    struct generic_eap_data *thisint)
{
  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Bad interface struct passed in to interactive_store_frame()\n");
      return XEMALLOC;
    }

  // First, make sure we have what we need!
  if (cur_size == 0) 
    {
      return XENONE;
    }
  if (cur_frame == NULL) 
    {
      return XENONE;
    }

  if (thisint->staleFrame != NULL)
    {
      free(thisint->staleFrame);
      thisint->staleFrame = NULL;
    }
  
  thisint->staleFrame = (char *)malloc(cur_size);
  if (thisint->staleFrame == NULL) return XEMALLOC;

  // Store the frame.
  memcpy(thisint->staleFrame, cur_frame, cur_size);
  thisint->staleSize = cur_size;
  // There were no errors to report.
  return XENONE;
}

