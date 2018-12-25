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
 * Handle the EAPOL keying state machine.
 * File: key_statemachine.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: key_statemachine.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: key_statemachine.c,v $
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
 * Revision 1.4  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
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

#include "key_statemachine.h"
#include "eapol_key_type1.h"
#include "xsup_debug.h"
#include "frame_structs.h"

/*************************************************
 *
 * Call the processKey() function defined in the 802.1x standard.  Here, we
 * need to determine what type of key it is, and call the correct handler.
 * Currently, the only type of key we can have, is RC4, but that will
 * change soon. ;)
 *
 *************************************************/
void processKey(struct interface_data *thisint, char *inframe,
		int insize)
{
  struct key_packet *keydata;

  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to processKey()!\n");
      return;
    }

  keydata = (struct key_packet *)&inframe[OFFSET_TO_EAP];

  switch (keydata->key_descr)
    {
    case RC4_KEY_TYPE:
      eapol_key_type1_process(thisint, inframe, insize);
      break;
      
    case WPA_KEY_TYPE:
      /* External program, e.g., wpa_supplicant, can process WPA frames */
      debug_printf(DEBUG_NORMAL, "WPA EAPOL-Key - ignoring it\n");
      break;

    default:
      debug_printf(DEBUG_NORMAL, "Unknown EAPoL Key Descriptor (%d)!\n",
		   keydata->key_descr);
      break;
    }
}

/*************************************************
 *
 * Run the keying state machine that is defined in the 802.1x standard.  
 * Depending on the state, we may need to process a key.
 *
 *************************************************/
void run_key_statemachine(struct interface_data *thisint, char *inframe,
			  int insize)
{
  if ((!thisint) || (!inframe))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to run_key_statemachine()!\n");
      return;
    }

  if ((thisint->statemachine->initialize == TRUE) ||
      (thisint->statemachine->portEnabled == FALSE))
    {
      // Do the NO_KEY_RECIEVE part of the state machine.

    }

  if (thisint->statemachine->rxKey == TRUE)
    {
      processKey(thisint, inframe, insize);
      thisint->statemachine->rxKey = FALSE;
    }
}
