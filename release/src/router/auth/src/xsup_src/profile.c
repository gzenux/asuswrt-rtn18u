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
 * File: profile.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: profile.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: profile.c,v $
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
 * Revision 1.15  2004/04/26 20:51:12  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.14  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.13  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.12  2004/03/26 21:34:51  chessing
 * Fixed problem with interface being down on startup causing xsupplicant to not read the proper configuration information when the interface is brought up.  Added/fixed code to rebuild userdata piece of structure when the essid changes.  Added code to avoid setting a key on an interface if the interface doesn't already have encryption enabled.  Added a little bit of debugging code to help find a solution to an IPC socket problem.
 *
 * Revision 1.11  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.10  2004/01/15 01:12:44  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.9  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.8  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.7  2003/12/19 06:29:56  chessing
 *
 * New code to determine if an interface is wireless or not.  Lots of IPC updates.
 *
 * Revision 1.6  2003/12/18 02:09:45  chessing
 *
 * Some small fixes, and working IPC code to get interface state.
 *
 * Revision 1.5  2003/12/07 06:20:19  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 * Revision 1.4  2003/12/04 04:36:24  chessing
 *
 * Added support for multiple interfaces (-D now works), also added DEBUG_EXCESSIVE to help clean up some of the debug output (-d 6).
 *
 * Revision 1.3  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.2  2003/11/19 04:23:18  chessing
 *
 * Updates to fix the import
 *
 *
 *
 *******************************************************************/

#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "profile.h"
#include "xsup_err.h"
#include "cardif/cardif.h"
#include "xsup_debug.h"
#include "eapol.h"

/*******************************************
 *
 * Initalize the default values for the structure.  In general, state machine
 * and user configuration variables won't need to be set here.  We should
 * set up variables that are in the root of the structure.
 *
 *******************************************/
int init_interface_struct(struct interface_data *work, char *intname, 
			  struct daemon_conf *dconf)
{
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

  // It is valid to have a NULL dconf here.  So, don't do any checking.

  if (!work)
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to init_interface_struct()!\n");
      return XEMALLOC;
    }

  if (!intname)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface name passed in to init_interface_struct()!\n");
      return XEMALLOC;
    }

  work->intName = (char *)malloc(strlen(intname)+1);
  bzero(work->intName, strlen(intname)+1);
  strncpy(work->intName, intname, strlen(intname));

  work->sockInt = -1;
  bzero(&work->sll, sizeof(struct sockaddr_ll));  // Linux specific.

  bzero(work->source_mac, 6);
  bzero(work->dest_mac, 6);

  //  work->eapTypeData = NULL;
  work->eapType = 0;

  work->keyingMaterial = NULL;

  work->firstauth = TRUE;

  // The default MAC specified by the IEEE 802.1x spec.
  memcpy(&work->dest_mac[0], &dot1x_default_dest, 6);
	
  work->cur_essid = NULL;

  work->isWireless = -1;     // -1 means we don't know.
  work->wasDown = TRUE;      // As far as we know, the interface was down
                             // before we started.

  eapol_init(work);

  work->userdata = NULL;

  work->ipc = NULL;

  work->daemoncfg = dconf;

  work->tempPassword = NULL;

  return XENONE;
}

/**********************************************
 *
 * Clean out the daemon configuration structure.
 *
 **********************************************/
void profile_daemon_deinit(struct interface_data *workint)
{
  struct daemon_conf *myconf;

  if (!workint) return;

  myconf = workint->daemoncfg;

  if (myconf == NULL) return;

  if (myconf->random_file != NULL) free(myconf->random_file);
  if (myconf->first_auth != NULL) free(myconf->first_auth);
  if (myconf->after_auth != NULL) free(myconf->after_auth);
}


/**********************************************
 *
 * Clean out a structure.  Clear out everything but return a pointer to "next"
 * the pointer to next should be used in a successive call.
 *
 **********************************************/
struct interface_data *destroy_interface_struct(struct interface_data *intdata)
{
  struct interface_data *next;

  if (!intdata) return NULL;

  // We should *always* have something in intName.
  free(intdata->intName);

  if (intdata->cur_essid) free(intdata->cur_essid);
  if (intdata->keyingMaterial) free(intdata->keyingMaterial);

  next = intdata->next;
  return next;
}
