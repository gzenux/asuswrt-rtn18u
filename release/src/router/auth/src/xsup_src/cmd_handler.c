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
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: cmd_handler.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: cmd_handler.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:24  ysc
 *
 *
 * Revision 1.1  2004/07/24 00:52:56  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.1  2004/07/24 00:40:55  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.3  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.2  2004/01/15 23:45:10  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.1  2004/01/15 01:12:44  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 *
 *******************************************************************/
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "config.h"
#include "profile.h"
#include "cmd_handler.h"
#include "xsup_err.h"
#include "xsup_debug.h"

/*******************************************************************
 *
 * Find all places that we have a %i, and replace it with the current
 * interface name.
 *
 *******************************************************************/
int cmd_handler_do_int(struct interface_data *intdata, char *cmdin, 
			char *cmdout)
{
  char *str1, *str2, intname[16];

  if (cmdin == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No command to execute!\n");
      return XENONE;
    }

  if (cmdout == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No response buffer available in cmd_handler_do_int()!\n");
      return XEMALLOC;
    }

  if (intdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid interface data in cmd_handler_do_int()!\n");
      return XEMALLOC;
    }

  // First, copy our string to cmdout.  This is where we will work with it.
  strcpy(cmdout, cmdin);

  // We make use of intdata->intName in the loop below, make sure it is valid!
  if (intdata->intName == NULL)
    {
      debug_printf(DEBUG_NORMAL, "intdata->intName is NULL in cmd_handler_do_int()!\n");
      return XEMALLOC;
    }

  while ((str1 = strstr(cmdout, "%i")) != NULL)
    {
      // We have a string we need to work with.  So, allocate some memory.
      // We need to allocate the length of the string, -2 (for the %i), 
      // + enough memory to stick thisint->intName in to. +1 for a NULL.

      str2 = (char *)malloc((strlen(cmdout)-2)+(strlen(intdata->intName))+1);
      if (str2 == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate enough memory to process command string!\n");

	  return XEMALLOC;
	}

      bzero(str2, ((strlen(cmdout)-2)+(strlen(intdata->intName))+1));

      str1[0] = '\0';
      str1++;

      // Now, copy the first part of the string to our destination buffer.
      strncpy(str2, cmdout, strlen(cmdout));

      bzero((char *)&intname, 16);
      strcpy((char *)&intname, intdata->intName);

      // Then, cat the interface name on.
      strcat(str2, (char *)&intname);

      // And cat that on.
      strcat(str2, (char *)&str1[1]);

      // And copy it all back to cmdout.
      bzero(cmdout, strlen(str2)+1);
      strcpy(cmdout, str2);

      // And free str2
      free(str2);
      str2 = NULL;
    }

  return XENONE;
}


/*******************************************************************
 *
 *  This function expands the command variables that we can have in the
 * config file.   Things such as %i for interface.  (And, others later
 * on.)
 *
 *******************************************************************/
int cmd_handler_subst(struct interface_data *intdata, char *cmd_to_exec,
		      char *expanded_cmd_to_exec)
{
  int retval;

  if (intdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No valid interface data provided in cmd_handler_subst()!\n");
      return XEMALLOC;
    }

  if (cmd_to_exec == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Nothing to do in cmd_handler_subst()!\n");
      return XENONE;
    }

  if (expanded_cmd_to_exec == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No available buffer in cmd_handler_subst()!\n");
      return XEMALLOC;
    }

  debug_printf(DEBUG_EVERYTHING, "Processing command : %s\n",cmd_to_exec);

  // Now, process the command.
  retval = cmd_handler_do_int(intdata, cmd_to_exec, expanded_cmd_to_exec);
  if (retval != XENONE) return retval;

  debug_printf(DEBUG_EVERYTHING, "Returning command : %s\n",expanded_cmd_to_exec);

  return XENONE;
}

/*******************************************************************
 *
 * This is the function that should be called when we need to execute some
 * kind of a program outside of the normal functioning of XSupplicant.
 * Programs that could be executed include dhcp client daemons, VPN
 * connections, etc.  (Large chunks of this code is from the original
 * XSupplicant codebase.  Not sure if it was written by Nick, or Bryan.)
 *
 *******************************************************************/
int cmd_handler_exec(struct interface_data *intdata, char *cmd_to_exec)
{
  char execme[256];    
  char *args[10];
  char *p;
  int index = 0;
  int i;
  int retval;
  int pid;

  if (!cmd_to_exec) return -1;
  if (intdata == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No interface data provided in cmd_handler_exec()!\n");
      return XEMALLOC;
    }

  cmd_handler_subst(intdata, cmd_to_exec, (char *)&execme);

  p = strtok((char *)&execme, " ");
  args[index++] = strdup(p);
  while (p && (p = strtok(NULL, " ")) != NULL && index < 10) {
    args[index++] = strdup(p);
  }
  args[index] = NULL;
  debug_printf(DEBUG_EVERYTHING, "Actual command being called is %s\n",(char *)&execme);

  // Fork, so we don't die when we call this program.
  pid = fork();

  if (pid == 0)
    {
      // We are the child, so execute the command.
      retval = execvp((char *)&execme, args);
    } else {
      // We are the parent, do nothing.
      retval = 0;
    }

  for (i = 0; i < index; i++) {
    free(args[i]);
  }
  return  retval  == -1? retval : 0;
}
