/**
 * A client-side 802.1x implementation 
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below. 
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
 * File: eapol.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eapol.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eapol.c,v $
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
 * Revision 1.74  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.73  2004/01/15 23:45:10  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.72  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.71  2003/12/04 04:36:24  chessing
 *
 * Added support for multiple interfaces (-D now works), also added DEBUG_EXCESSIVE to help clean up some of the debug output (-d 6).
 *
 * Revision 1.70  2003/11/28 07:46:23  chessing
 *
 * EAPOL no longer uses malloc for allocating the frame buffers.  State machine init stuff is now in statemachine.c where it belongs.  eap_init() now accepts an interface_data struct, to make it conform to other init calls.
 *
 * Revision 1.69  2003/11/19 04:27:15  chessing
 *
 * Added a few more files that got missed.
 *
 *
 *
 *******************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <strings.h>

#include "frame_structs.h"
#include "statemachine.h"
#include "eapol.h"
#include "eap.h"
#include "cardif/cardif.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "key_statemachine.h"


/********************************************
 *
 * Set up anything that we will need for EAPoL.  This includes setting the
 * default values for the state machine.
 *
 ********************************************/
int eapol_init(struct interface_data *newint)
{
  if (!newint)
    {
      debug_printf(DEBUG_NORMAL, "NULL data passed in to eapol_init()!\n");
      return XEMALLOC;
    }

  statemachine_init(newint);
  eap_init(newint);

  return XENONE;
}

/*****************************************
 *
 * Do anything that is needed to clean up, and exit cleanly.
 *
 *****************************************/
int eapol_cleanup(struct interface_data *thisint)
{
  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "NULL data passed in to eapol_cleanup()!\n");
      return XEMALLOC;
    }

  statemachine_cleanup(thisint);
  eap_cleanup(thisint);

  return XENONE;
}

/*****************************************
 *
 * Actually check to see if we have a frame, and process it if we do.
 *
 *****************************************/
int eapol_execute(struct interface_data *workint)
{
  char newframe[1518], respframe[1518];
  int framesize, respsize, retval=0;
  struct eapol_header *temp;
  char *inframe;    // A pointer to our frame data.  (Normally will point
                    // to the newframe[] array.)

  if (!workint)
    {
      debug_printf(DEBUG_NORMAL, "NULL data passed in to eapol_execute()!\n");
      return XEMALLOC;
    }

  bzero(&newframe, 1518);

  if (getframe(workint, (char *)&newframe, &framesize) < 0)
    {
      debug_printf(DEBUG_EXCESSIVE, "There are no frames to process.\n");
      framesize = 0;
      retval = XENOFRAMES;
      inframe = NULL;         // Have the EAP types process, if they are in
                              // a state to request information from the GUI.
    } else {

      // We want to let getframe be called, even if we don't have any
      // config information.  That will keep the frame queue empty so that
      // when we do have enough config information we can start by processing
      // an EAP request that is valid.  If we don't have any config informtion,
      // we should just bail here, and not return an error.

      inframe = (char *)&newframe;

      if (workint->userdata == NULL) return XEMALLOC;

      temp = (struct eapol_header *)&newframe[OFFSET_PAST_MAC];

      if (ntohs(temp->frame_type) == 0x888e)
	{
	  if (temp->eapol_version > MAX_EAPOL_VER)
	    {
	      debug_printf(DEBUG_EVERYTHING, "Got invalid EAPOL frame!\n");
	      framesize = 0;
	    } else {
	      switch (temp->eapol_type)
		{
		case EAP_PACKET:
		  // Process the EAP header, and determine if we need to set
		  // any state machine variables.
		  eap_process_header(workint, (char *)&newframe, framesize);
		  break;

		case EAPOL_START:
		  debug_printf(DEBUG_NORMAL, "Got EAPoL-Start! Ignoring!\n");
		  return XEIGNOREDFRAME;

		case EAPOL_LOGOFF:
		  debug_printf(DEBUG_NORMAL, "Got EAPoL-Logoff! Ignoring!\n");
		  return XEIGNOREDFRAME;

		case EAPOL_KEY:
		  debug_printf(DEBUG_NORMAL, "Processing EAPoL-Key!\n");
		  workint->statemachine->rxKey = TRUE;
		  run_key_statemachine(workint, (char *)&newframe, framesize);
		  return XGOODKEYFRAME;

		case EAPOL_ASF_ALERT:
		  debug_printf(DEBUG_NORMAL, "Got EAPoL-ASF-Alert!\n");
		  return XEIGNOREDFRAME;

		default:
		  debug_printf(DEBUG_NORMAL, "Unknown EAPoL type! (%02X)\n",
			       temp->eapol_type);
		  return XEIGNOREDFRAME;
		}
	    }
	} else {
	  debug_printf(DEBUG_EVERYTHING, "Got a frame, but it isn't an EAPoL frame, ignoring.\n");
	}
    }

  // Process our state machine.
  if (statemachine_run(workint, inframe, framesize, 
		       (char *)&respframe, &respsize) == XDATA)
    {
      // Send a frame out.
      sendframe(workint, (char *)&respframe, respsize);
    } 

  return XENONE;
}
