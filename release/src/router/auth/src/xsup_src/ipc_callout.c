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
 * File: ipc_callout.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: ipc_callout.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: ipc_callout.c,v $
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
 * Revision 1.10  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.9  2004/03/19 23:43:56  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.8  2004/03/17 21:21:40  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.7  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.6  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.5  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.4  2003/12/23 04:57:10  chessing
 *
 * IPC additions, GUI client routines.
 *
 * Revision 1.3  2003/12/19 06:29:56  chessing
 *
 * New code to determine if an interface is wireless or not.  Lots of IPC updates.
 *
 * Revision 1.2  2003/12/18 02:09:45  chessing
 *
 * Some small fixes, and working IPC code to get interface state.
 *
 * Revision 1.1  2003/12/14 06:17:09  chessing
 *
 * Added ipc_callout.* needed to build.
 *
 *
 *******************************************************************/
#include <netinet/in.h>
#include <strings.h>
#include <string.h>

#include "profile.h"
#include "config.h"
#include "xsup_debug.h"
#include "xsup_ipc.h"
#include "ipc_callout.h"

/*******************************************************************
 *
 * Fill in the next command record with the authentication state of the
 * selected interface.
 *
 *******************************************************************/
void ipc_callout_auth_state(struct interface_data *thisint, int *bufptr,
			    char *buffer, int bufsize, char *resbuf, 
			    int *resbufptr)
{
  struct ipc_cmd *cmd;
  struct ipc_header *header;

  if ((!thisint) || (!bufptr) || (!buffer) || (!resbuf) || (!resbufptr) ||
      (!thisint->statemachine))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_auth_state()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  if (cmd->attribute != AUTH_STATE) 
    {
      debug_printf(DEBUG_NORMAL, "Incorrect call to ipc_callout_auth_state!\n");
    }

  if (cmd->len != 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid length!  This will be the last request we answer!\n");
      *bufptr = bufsize;
    }
  *bufptr+=3;

  // Build the actual answer.
  cmd = (struct ipc_cmd *)&resbuf[*resbufptr];
  cmd->attribute = AUTH_STATE;
  cmd->len = 1;
  *resbufptr+=2;

  resbuf[*resbufptr] = thisint->statemachine->curState;
  *resbufptr+=1;

  header->numcmds++;
}

/*****************************************************************
 *
 * Get or set config values.
 *
 *****************************************************************/
void ipc_callout_process_conf(struct interface_data *thisint, int *bufptr,
			      char *buffer, int bufsize, char *resbuf, 
			      int *resbufptr)
{
  struct ipc_cmd *cmd;
  struct ipc_header *header;

  if ((!thisint) || (!bufptr) || (!buffer) || (!resbuf) || (!resbufptr))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_process_conf()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  if (cmd->attribute != CONFIG) 
    {
      debug_printf(DEBUG_NORMAL, "Incorrect call to ipc_callout_process_conf!\n");
    }

  *bufptr += sizeof(struct ipc_cmd);


}

/****************************************************************
 *
 * Register a client to receive pushed messages from the daemon.
 *
 ****************************************************************/
void ipc_callout_reg_client(struct interface_data *thisint, int *bufptr,
			    char *buffer, int bufsize, char *resbuf, 
			    int *resbufptr, struct sockaddr *mysock)
{
  struct ipc_cmd *cmd;
  struct registered_clients *cur;
  struct ipc_header *header;

  if ((!thisint) || (!bufptr) || (!buffer) || (!resbuf) || (!resbufptr) ||
      (!mysock) || (!thisint->ipc))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_reg_client()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  if (cmd->attribute != REGISTER) 
    {
      debug_printf(DEBUG_NORMAL, "Incorrect call to ipc_callout_reg_client!\n");
    }

  if (cmd->len != 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid length!  This will be the last request we answer! (From this packet)\n");
      *bufptr = bufsize;
    }
  *bufptr+=3;

  // Now register the client.  And, assuming we register correctly, return
  // an ACK.
  if (thisint->ipc->reged == NULL)
    {
      thisint->ipc->reged = (struct registered_clients *)malloc(sizeof(struct registered_clients));
      cur = thisint->ipc->reged;
    } else {
      cur = thisint->ipc->reged;

      while (cur->next != NULL)
	{
	  cur = cur->next;
	}

      cur->next = (struct registered_clients *)malloc(sizeof(struct registered_clients));
      cur = cur->next;
    }
  
  cur->addr = (struct sockaddr *)malloc(sizeof(struct sockaddr));
  memcpy(cur->addr, mysock, sizeof(struct sockaddr));
  cur->next = NULL;

  cmd = (struct ipc_cmd *)&resbuf[*resbufptr];

  cmd->attribute = REGISTER;
  cmd->len = 1;
  
  *resbufptr += 2;

  resbuf[*resbufptr] = ACK;
  *resbufptr += 1;

  header->numcmds++;
}

/****************************************************************
 *
 *  Return a comma seperated list of interfaces we know about.
 *
 ****************************************************************/
void ipc_callout_get_ints(struct interface_data *startint, 
			  struct interface_data *thisint, int *bufptr,
			  char *buffer, int bufsize, char *resbuf, 
			  int *resbufptr)
{
  struct ipc_cmd *cmd;
  struct interface_data *cur;
  int interfaces;
  char *retlist;
  struct ipc_header *header;

  if ((!startint) || (!thisint) || (!bufptr) || (!buffer) || (!resbuf) ||
      (!resbufptr))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_get_ints()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  if (cmd->attribute != INTERFACES) 
    {
      debug_printf(DEBUG_NORMAL, "Incorrect call to ipc_callout_get_ints!\n");
    }

  if (cmd->len != 0)
    {
      debug_printf(DEBUG_NORMAL, "Invalid length!  This will be the last request we answer!\n");
      *bufptr = bufsize;
    }
  *bufptr+=3;


  interfaces = 0;

  cur = startint;
  while (cur != NULL)
    {
      interfaces++;
      cur = cur->next;
    }

  retlist = (char *)malloc(interfaces*16);
  if (retlist == NULL) return;             // We won't answer.

  bzero(retlist, (interfaces*16));

  // Build the answer.
  cmd = (struct ipc_cmd *)&resbuf[*resbufptr];
  cmd->attribute = INTERFACES;

  *resbufptr += 2;
  
  cur = startint;
  while (cur != NULL)
    {
      strcat(retlist, cur->intName);
      cur = cur->next;
      if (cur != NULL) strcat(retlist, ",");
    }

  debug_printf(DEBUG_EVERYTHING, "Returning interface list of : %s\n", 
	       retlist);

  cmd->len = strlen(retlist);

  strncpy((char *)&resbuf[*resbufptr], retlist, strlen(retlist));
  *resbufptr += strlen(retlist);
  
  header->numcmds++;
}

/******************************************************************
 *
 * Build a message to be sent.  This should be used *ONLY* as a call
 * internal to the ipc_callout.c file!
 *
 ******************************************************************/
void ipc_callout_build_msg(struct interface_data *thisint, int *bufptr,
			   char *buffer, int bufsize, int msgtype, 
			   char *message)
{
  struct ipc_cmd *cmd;
  struct ipc_header *header;

  if ((!thisint) || (!bufptr) || (!buffer) || (!message))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_build_msg()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  cmd->attribute = msgtype;
  cmd->len = strlen(message);

  *bufptr += 2;

  strcpy((char *)&buffer[*bufptr], message);

  *bufptr += strlen(message);

  header->numcmds++;
}

/****************************************************************
 *
 * Send an error message to a client.
 *
 ****************************************************************/
void ipc_callout_send_error(struct interface_data *thisint, int *bufptr,
			    char *buffer, int bufsize, char *message)
{
  if ((!thisint) || (!bufptr) || (!buffer) || (!message))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_send_error()!\n");
      return;
    }

  ipc_callout_build_msg(thisint, bufptr, buffer, bufsize, ERROR_MSG, message);
}

/****************************************************************
 *
 * Send a notification to the client.
 *
 ****************************************************************/
void ipc_callout_send_notify(struct interface_data *thisint, int *bufptr,
			     char *buffer, int bufsize, char *message)
{
  if ((!thisint) || (!bufptr) || (!buffer) || (!message))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_send_notify()!\n");
      return;
    }

  ipc_callout_build_msg(thisint, bufptr, buffer, bufsize, NOTIFY, message);
}

/****************************************************************
 *
 * Get or set the profile we are using.
 *
 ****************************************************************/
void ipc_callout_getset_profile(struct interface_data *thisint, int *bufptr,
				char *buffer, int bufsize, char *resbuf, 
				int *resbufptr)
{
  struct ipc_header *header;
  //  struct ipc_cmd *cmd;

  if ((!thisint) || (!bufptr) || (!buffer) || (!resbuf) || (!resbufptr))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_getset_profile()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }
  debug_printf(DEBUG_NORMAL, "Get/Set Profile Not Implemented!\n");
}

/***************************************************************
 *
 * Set a temporary password.  This password will be used by the first EAP
 * method that needs it.  Once it has been used, the EAP method should
 * bzero, and free the memory, in order to keep the password from sitting
 * in memory too long.
 *
 ***************************************************************/
void ipc_callout_set_password(struct interface_data *thisint, int *bufptr,
			      char *buffer, int bufsize, char *resbuf, 
			      int *resbufptr)
{
  struct ipc_header *header;
  struct ipc_cmd *cmd;

  if ((!thisint) || (!bufptr) || (!buffer) || (!resbuf) || (!resbufptr))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_set_password()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  // If we already have a temp password, we need to get rid of it.
  if (thisint->tempPassword != NULL)
    {
      free(thisint->tempPassword);
      thisint->tempPassword = NULL;
    }
  
  thisint->tempPassword = (char *)malloc(cmd->len+1);
  if (thisint->tempPassword == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for temporary password!\n");
      return;
    }

  bzero(thisint->tempPassword, cmd->len+1);
  *bufptr += 2;
  strcpy(thisint->tempPassword, (char *)&buffer[*bufptr]);

  *bufptr += strlen(thisint->tempPassword);

  cmd = (struct ipc_cmd *)&resbuf[*resbufptr];

  cmd->attribute = TEMPPASSWORD;
  cmd->len = 1;
  
  *resbufptr += 2;

  resbuf[*resbufptr] = ACK;
  *resbufptr += 1;

  header->numcmds++;
}

/***********************************************************************
 *
 * Ask any attached clients for a password.  In this message, we will
 * also pass the EAP type that is requesting the password, and any
 * challenge string that the EAP type may need.
 *
 ***********************************************************************/
void ipc_callout_request_password(struct interface_data *thisint, 
				  int *bufptr, char *buffer, int bufsize,
				  char *eapname, char *challenge)
{
  struct ipc_cmd *cmd;
  struct ipc_header *header;

  if ((!thisint) || (!bufptr) || (!buffer) || (!eapname))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ipc_callout_request_password()!\n");
      return;
    }

  header = (struct ipc_header *)buffer;

  // If the header is invalid, then return.
  if (header->version != 1)
    {
      debug_printf(DEBUG_NORMAL, "Invalid packet header.\n");
      return;
    }

  if (*bufptr <= 0)
    {
      *bufptr = sizeof(struct ipc_header);
    }

  cmd = (struct ipc_cmd *)&buffer[*bufptr];

  cmd->attribute = PASSWORD;
  if (challenge != NULL)
    {
      cmd->len = strlen(eapname)+strlen(challenge)+2;  // The string, with a NULL.
    } else {
      cmd->len = strlen(eapname)+2;
    }

  *bufptr += 2;

  bzero((char *)&buffer[*bufptr],cmd->len);
  strcpy((char *)&buffer[*bufptr], eapname);
  *bufptr += (strlen(eapname)+1);

  if (challenge != NULL)
    {
      strcpy((char *)&buffer[*bufptr], challenge);
      *bufptr += (strlen(challenge)+1);
    }

  header->numcmds++;
}
