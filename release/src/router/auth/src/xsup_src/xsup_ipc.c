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
 * File: xsup_ipc.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: xsup_ipc.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: xsup_ipc.c,v $
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
 * Revision 1.14  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.13  2004/03/29 21:57:14  chessing
 *
 * Changed the socket number we use for communication with the daemon from 10240 (which seems like a bad choice) to 26798 (which seems a little more random ;).  Also changed our debug code so that it doesn't output to the console when we are running in daemon mode.  The only way to get debug info while in daemon mode is to set a log file!!!
 *
 * Revision 1.12  2004/03/27 02:20:07  chessing
 *
 * Fixed a problem where the IPC socket wasn't getting deallocated correctly, and would keep xsupplicant from running a second time.  Added the needed hooks to make PEAP-GTC work.  (Not tested yet.)
 *
 * Revision 1.11  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.10  2004/03/26 21:34:51  chessing
 * Fixed problem with interface being down on startup causing xsupplicant to not read the proper configuration information when the interface is brought up.  Added/fixed code to rebuild userdata piece of structure when the essid changes.  Added code to avoid setting a key on an interface if the interface doesn't already have encryption enabled.  Added a little bit of debugging code to help find a solution to an IPC socket problem.
 *
 * Revision 1.9  2004/03/17 21:21:40  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.8  2004/02/11 03:31:07  npetroni
 * simple check to avoid segfault in ipc cleanup
 *
 * Revision 1.7  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.6  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.5  2003/12/23 04:57:10  chessing
 *
 * IPC additions, GUI client routines.
 *
 * Revision 1.4  2003/12/19 06:29:56  chessing
 *
 * New code to determine if an interface is wireless or not.  Lots of IPC updates.
 *
 * Revision 1.3  2003/12/18 02:09:45  chessing
 *
 * Some small fixes, and working IPC code to get interface state.
 *
 * Revision 1.2  2003/12/14 06:11:03  chessing
 *
 * Fixed some stuff with SIM in relation to the new config structures.  Cleaned out CR/LF from LEAP source files.  Added user certificate support to TTLS and PEAP. Some additions to the IPC code. (Not tested yet.)
 *
 * Revision 1.1  2003/12/07 06:20:19  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 *
 *******************************************************************/

#include <sys/socket.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "profile.h"
#include "config.h"
#include "xsup_ipc.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "ipc_callout.h"


/******************************************************************
 *
 * Initalize the socket that we will use to communicate with a client/clients.
 * Also, set up any structures that may be needed.
 *
 ******************************************************************/
int xsup_ipc_init(struct interface_data *startint)
{
  int sockErr = 0;
  int sockOpts;
  int sockdesc;
  char *error = NULL;
  struct sockaddr_in sa;
  struct ipc_struct *ipc;
  struct interface_data *cur;

  if (!startint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface passed in to xsup_ipc_init()!\n");
      return XEMALLOC;
    }

  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(26798);

  // Socket we will be using to communicate.
  sockdesc = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockdesc == -1) {
    debug_printf(DEBUG_NORMAL, "Couldn't establish handler to daemon socket!\n");
    return XENOSOCK;
  } 

  debug_printf(DEBUG_CONFIG, "Opened socket descriptor #%d\n", sockdesc);

  sockOpts = fcntl(sockdesc, F_GETFL, 0);

  sockErr = fcntl(sockdesc, F_SETFL, sockOpts | O_NONBLOCK);
  if (sockErr == -1)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't set socket non-blocking!\n");
      close(sockdesc);
      return XENOSOCK;
    }

  sockErr = bind(sockdesc, (struct sockaddr *)&sa, sizeof(sa));
  if (sockErr == -1) 
    {
      error = strerror(errno);
      debug_printf(DEBUG_NORMAL, "An error occured binding to socket.  (Error : %s)\n", error);
      close(sockdesc);
      return XENOSOCK;
    }

  ipc = (struct ipc_struct *)malloc(sizeof(struct ipc_struct));
  if (ipc == NULL)
    {
      debug_printf(DEBUG_NORMAL, "An error occured allocating memory for our IPC structure!\n");
      close(sockdesc);
      return XENOSOCK;
    }

  ipc->sockid = sockdesc;
  ipc->reged = NULL;

  cur = startint;
  while (cur != NULL)
    {
      cur->ipc = ipc;
      cur = cur->next;
    }

  return XENONE;
}

/**************************************************************
 *
 * Send a message to a client.
 *
 **************************************************************/
void xsup_ipc_send_message(int sockdesc, struct sockaddr *tohost, 
			   int tohost_len, char *tosend, int tolen)
{
  if ((!tohost) || (!tosend))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to xsup_ipc_send_message()!\n");
      return;
    }

  if (sendto(sockdesc, tosend, tolen, 0, tohost, tohost_len) != tolen)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't send message to a client!\n");
    }
}

/**************************************************************
 *
 * Get a message from a client.  Validate it, and return the payload.
 * outsize should be passed in a valid that is the maximum size of
 * outbuf.  outsize will then be changed to the size of the result
 * buffer.
 *
 **************************************************************/
void xsup_ipc_get_message(int sockdesc, char *outbuf, int *outsize, 
			  char *interface, struct sockaddr *fromhost, 
			  int *fromhost_length)
{
  int readStat = -1;
  struct ipc_header *myheader;

  if ((!outbuf) || (!outsize) || (!interface) || (!fromhost) ||
      (!fromhost_length))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to xsup_ipc_get_message()!\n");
      return;
    }

  *fromhost_length = *outsize;
  readStat = recvfrom(sockdesc, outbuf, *outsize, 0, fromhost,fromhost_length);

  if (readStat < 0)
    {
      if (errno != EWOULDBLOCK)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't read message from a client! (%s)\n",
		       strerror(errno));
	} 

      *outsize = 0;
    } else {
      // Validate that the packet we got is valid.
      
      *outsize = readStat;
      myheader = (struct ipc_header *)outbuf;

      // Make sure we have a valid version.
      if (myheader->version == 1) 
	{
	  // We have a valid version.
	  debug_printf(DEBUG_EVERYTHING, "Version %d : Interface %s\n",
		       myheader->version, myheader->interface);

	  strcpy(interface, myheader->interface);

	  switch (myheader->getset)
	    {
	    case IPC_RESPONSE:
	      debug_printf(DEBUG_EVERYTHING, "  -- Got an IPC Response!\n");
	      break;
	    case IPC_GET:
	      debug_printf(DEBUG_EVERYTHING, "  -- Got an IPC Get!\n");
	      break;
	    case IPC_SET:
	      debug_printf(DEBUG_EVERYTHING, "  -- Got an IPC Set!\n");
	      break;
	    }
	} else {
	  debug_printf(DEBUG_NORMAL, "Error : Invalid packet header!\n");
	  *outsize = 0;
	}
    }
}

/***********************************************************
 *
 * Send a message to all registered clients.
 *
 ***********************************************************/
int xsup_ipc_send_all_registered(struct interface_data *thisint, char *message,
				 int msglen)
{
  struct registered_clients *cur;

  if ((!thisint) || (!thisint->ipc) || (!message))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to xsup_ipc_send_all_registered()!\n");
      return XEMALLOC;
    }

  cur = thisint->ipc->reged;

  while (cur != NULL)
    {
      // Send a message to the client that is currently registered.
      xsup_ipc_send_message(thisint->ipc->sockid, cur->addr, 
			    sizeof(struct sockaddr), message, msglen);

      cur = cur->next;
    }
  return XENONE;
}

/***********************************************************
 *
 * Locate the correct interface, and return a pointer to it's structure. If
 * it isn't a valid interface, then return NULL, and send an error packet
 * back.
 *
 ***********************************************************/
struct interface_data *xsup_ipc_select_int(char *interface, 
					   struct sockaddr *tohost, 
					   int tohost_len,
					   struct interface_data *thisint)
{
  char outbuf[1500];
  char retstr[150];
  struct ipc_header *myheader;
  struct interface_data *cur;
  int bufptr;

  if ((!interface) || (!tohost) || (!thisint))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to xsup_ipc_select_int()!\n");
      return NULL;
    }

  cur = thisint;

  // Check to see if there is a valid interface name.
  if (interface[0] == '\0') 
    {
      debug_printf(DEBUG_EVERYTHING, "Interface field is blank!  Returning base pointer!\n");
      return thisint;
    }

  while ((cur != NULL) && (strcmp(interface, cur->intName) != 0))
    {
      cur = cur->next;
    }
  if (cur != NULL) return cur;

  // Otherwise, we don't know about the interface that was requested so we 
  // send an error message.
  debug_printf(DEBUG_NORMAL, "Unknown interface %s!\n",interface);
  bzero(&outbuf, 1500);
  myheader = (struct ipc_header *)&outbuf[0];
  
  myheader->version = 1;  // We only know about version 1 for now.
  strcpy(&myheader->interface[0], interface);
  myheader->getset = IPC_RESPONSE;
  myheader->numcmds = 0;

  bufptr = sizeof(struct ipc_header);

  sprintf((char *)&retstr, "Unknown interface %s!", interface);

  ipc_callout_send_error(thisint, &bufptr, (char *)&outbuf[0], 1500, 
			 (char *)&retstr);

  xsup_ipc_send_message(thisint->ipc->sockid, tohost, tohost_len, &outbuf[0], 
			bufptr);
  return NULL;
}

/***********************************************************
 *
 * Process any IPC messages, and respond accordingly.
 *
 ***********************************************************/
void xsup_ipc_process(struct interface_data *thisint)
{
  char buffer[1520];   // We shouldn't have a message larger than this.
  char result_buf[1520], interface[16];
  int bufsize, bufptr, resbufptr, salen, numcmds;
  struct interface_data *workint;
  struct ipc_header *rethead, *inhead;
  struct sockaddr mysock;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct in xsup_ipc_process()!\n");
      return;
    }

  if (!thisint->ipc)
    {
      debug_printf(DEBUG_NORMAL, "No ipc information available!\n");
      return;
    }

  bufsize = 1520;
  resbufptr = 0;
  numcmds = 0;

  //  debug_printf(DEBUG_NORMAL, "Socket descriptor is #%d\n",thisint->ipc->sockid);

  rethead = (struct ipc_header *)&result_buf[0];
  bzero(&result_buf[0], 1520);

  inhead = (struct ipc_header *)&buffer[0];

  xsup_ipc_get_message(thisint->ipc->sockid, (char *)&buffer, &bufsize, 
		       (char *)&interface, &mysock, &salen);

  // If our buffer is 0, then we don't have anything to process.
  if (bufsize == 0)
    {
      return;
    }

  bufptr = sizeof(struct ipc_header);
  
  workint = xsup_ipc_select_int((char *)&interface, &mysock, salen, thisint);

  if (workint == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't locate requested interface!\n");
      return;
    }

  // Set up our header.
  rethead->version = 1;
  strcpy((char *)&rethead->interface, (char *)&interface);
  rethead->getset = IPC_RESPONSE;
  resbufptr = sizeof(struct ipc_header);

  while (bufptr < bufsize)
    {
      switch (buffer[bufptr])
	{
	case AUTH_STATE:
	  if (inhead->getset == IPC_GET)
	    {
	      debug_printf(DEBUG_EVERYTHING, "Checking auth state!\n");
	      ipc_callout_auth_state(workint, &bufptr, (char *)&buffer, 
				     bufsize, (char *)&result_buf, &resbufptr);
	      numcmds++;
	    } else {
	      debug_printf(DEBUG_NORMAL, "Can't SET the authentication state!  Ignoring remaining requests!\n");
	      bufptr = bufsize+1;
	    }
	  break;

	case CONFIG:
	  debug_printf(DEBUG_EVERYTHING, "Setting password!\n");
	  ipc_callout_process_conf(workint, &bufptr, (char *)&buffer, 
				   bufsize, (char *)&result_buf, 
				   &resbufptr);
	  numcmds++;
	  break;

	case REGISTER:
	  if (inhead->getset == IPC_SET)
	    {
	      debug_printf(DEBUG_EVERYTHING, "Registering client!\n");
	      ipc_callout_reg_client(workint, &bufptr, (char *)&buffer, 
				     bufsize, (char *)&result_buf, &resbufptr,
				     &mysock);
	      numcmds++;
	    } else {
	      debug_printf(DEBUG_NORMAL, "Can't GET a client registration!  Ignoring remaining requests!\n");
	      bufptr = bufsize+1;
	    }
	  break;

	case INTERFACES:
	  if (inhead->getset == IPC_GET)
	    {
	      debug_printf(DEBUG_EVERYTHING, "Returning interface list!\n");
	      ipc_callout_get_ints(thisint, workint, &bufptr, (char *)&buffer, 
				   bufsize, (char *)&result_buf, &resbufptr);
	      numcmds++;
	    } else {
	      debug_printf(DEBUG_NORMAL, "Can't SET a client registration!  Ignoring remaining requests!\n");
	      bufptr = bufsize+1;
	    }
	  break;

	case PROFILE:
	  // Get or set a profile.
	  debug_printf(DEBUG_EVERYTHING, "Loading new profile...\n");
	  ipc_callout_getset_profile(workint, &bufptr, (char *)&buffer,
				     bufsize, (char *)&result_buf, &resbufptr);
	  numcmds++;
	  break;

	case TEMPPASSWORD:
	  // Set a temporary password.
	  debug_printf(DEBUG_EVERYTHING, "Setting temporary password.\n");
	  ipc_callout_set_password(workint, &bufptr, (char *)&buffer,
				   bufsize, (char *)&result_buf, &resbufptr);
	  numcmds++;
	  break;

	case ERROR_MSG:
	  debug_printf(DEBUG_NORMAL, "Got an error message from the client.  Your client is probably broken!\n");
	  break;

	default:
	  debug_printf(DEBUG_NORMAL, "Unknown command %02X!\n",buffer[bufptr]);
	  bufptr++;
	}
    }
  if (resbufptr > 0)
    {
      debug_printf(DEBUG_EVERYTHING, "Sending IPC response!\n");
      rethead->numcmds = numcmds;

      xsup_ipc_send_message(thisint->ipc->sockid, &mysock, salen, 
			    (char *)&result_buf, resbufptr);
    }
}

/***********************************************************
 *
 * Clean up any structures used, and close out the communication socket.
 *
 ***********************************************************/
void xsup_ipc_cleanup(struct interface_data *startint)
{
  struct registered_clients *cur, *next;
  char *error;

  if (!startint || !startint->ipc)
    return;
  
  cur = startint->ipc->reged;
  while (cur != NULL)
    {
      next = cur->next;
      free(cur);
      cur = next;
    }
  //  free(startint->ipc);

  debug_printf(DEBUG_EVERYTHING, "Shutting down IPC socket!\n");
  debug_printf(DEBUG_CONFIG, "Closing socket descriptor #%d\n", startint->ipc->sockid);
  if (close(startint->ipc->sockid) < 0)
    {
      error = strerror(errno);
      debug_printf(DEBUG_NORMAL, "Error closing socket!  (Error : %s)\n",
		   error);
    }
  free(startint->ipc);
}
