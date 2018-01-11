/**
 * A client-side 802.1x implementation supporting EAP/TLS
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
 * File: xsup_debug.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: xsup_debug.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: xsup_debug.c,v $
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
 * Revision 1.11  2004/04/29 17:51:08  chessing
 *
 * Fix a logic error in xsup_debug.c.  Not defining a log file no longer segfaults.
 *
 * Revision 1.10  2004/04/26 20:51:12  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.9  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.8  2004/03/29 21:57:13  chessing
 *
 * Changed the socket number we use for communication with the daemon from 10240 (which seems like a bad choice) to 26798 (which seems a little more random ;).  Also changed our debug code so that it doesn't output to the console when we are running in daemon mode.  The only way to get debug info while in daemon mode is to set a log file!!!
 *
 * Revision 1.7  2004/03/26 03:52:47  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.6  2004/03/24 08:16:13  galimorerpg
 * Added Pavel Roskin's deny_first patch:
 *
 * If I put an interface to the deny list it means that I don't want xsupplicant to touch it in any way.  In particular, it should not be probed and validated, whatever it means.
 *
 * The attached patch swaps the order of the checks - deny list is checked before cardif_validate()
 *
 *
 * A small typo fix was also added to xsup_driver.c
 *
 * Revision 1.5  2004/03/24 07:42:33  galimorerpg
 * Fixed a *NASTY* recursive loop in config.c/config_get_logfile()
 * Where config_get_logfile was debug_printf()ing and debug_printf()
 * was calling config_get_logfile.  I've worked around this by *NOT*
 * debug_printf()ing from config_get_logfile()
 *
 * On a side note, I found this bug because xsupplicant was crashing.
 * There's a handy option in the 2.4.25 kernel (CONFIG_OOM_KILLER) that
 * can kill programs that it decides are trying to use too much memory.
 *
 * Interestingly enough, valgrind didn't crash on this problem, presumably
 * because of its memory management?  Either that or the kernel didn't think
 * valgrind was hitting the memory hard enough.
 *
 * Revision 1.4  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.3  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 * Revision 1.2  2003/11/19 04:23:18  chessing
 *
 * Updates to fix the import
 *
 *
 *
 *******************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "xsup_debug.h"
#include "config.h"

int debug_level = 0;     // By default just show the "normal" stuff.
int isdaemon = 0;
FILE *logfile = NULL;

/***************************************************
 *
 * Remove an old logfile, and create a new one.
 *
 ***************************************************/
void logfile_setup(char *logfilename)
{
  if (logfilename != NULL)
    {
      if (isdaemon != 2)
	{
	  unlink(logfilename);

	  logfile = fopen(logfilename, "w+");
	}
    }
}

/**************************************************
 *
 * Clean up our old logfile.
 *
 **************************************************/
void logfile_cleanup()
{
  if (logfile != NULL)
    {
      fclose(logfile);
    }
}

/*************************************************
 *
 * Depending on the value of fh, we will either print to the screen, or
 * a log file.
 *
 *************************************************/
void ufprintf(FILE *fh, char *instr)
{
  if ((isdaemon == 2) || (fh == NULL))
    {
      printf("%s", instr);
    } else {
      fprintf(fh, "%s", instr);
      fflush(fh);
    }
}

/*************************************************
 *
 * Set the debug level.  This is a global value, and shouldn't be set per
 * interface.
 *
 *************************************************/
void debug_setlevel(int level, int xdaemon)
{
  debug_level = level;

  isdaemon = xdaemon;

  if (xdaemon == TRUE)
    {
      close(0);
      close(1);
      close(2);
    }
}

/*************************************************
 *
 * Get the debug level for debug situations where we can't use debug_printf
 * easily.
 *
 *************************************************/
int debug_getlevel()
{
  return debug_level;
}

/*************************************************
 *
 * Dump hex values, without the ascii versions.
 *
 *************************************************/
void debug_hex_printf(int level, u_char *hextodump, int size)
{
  int i;
  char chrstr[1024];

  if (debug_level < level) return;

  if (hextodump == NULL) return;

  for (i=0;i<size;i++)
    {
      bzero((char *)&chrstr, 1024);
      sprintf((char *)&chrstr, "%02X ", hextodump[i]);
      ufprintf(logfile, (char *)&chrstr);
    }
  ufprintf(logfile, "\n");
}

/*************************************************
 *
 * dump some hex values -- also
 * show the ascii version of the dump.
 *
 *************************************************/
void debug_hex_dump(int level, u_char *hextodump, int size)
{
  int i,x,s,t;
  char chrstr[1024];

  if (debug_level < level) return;

  if (hextodump == NULL) return;

  s=0;
  for (i=0;i<size;i++)
    {
      bzero((char *)&chrstr, 1024);
      sprintf((char *)&chrstr, "%02X ",hextodump[i]);
      ufprintf(logfile, (char *)&chrstr);

      if ((i>0) && (((i+1) % 8) == 0) && (((i+1) % 16) != 0)) 
	{
	  ufprintf(logfile, "- ");
	}

      if ((i>0) && (((i+1) % 16) == 0))
	{
	  if (i<17) 
	    {
	      t=i+1;
	    } else {
	      t=i+1;
	      s=s+1;
	    }

	  for (x=s;x<t;x++)
	    {
	      if ((hextodump[x] < 0x21) || (hextodump[x] > 0x7e))
		{
		  ufprintf(logfile, ".");
		} else {
		  bzero((char *)&chrstr, 1024);
		  sprintf((char *)&chrstr, "%c", hextodump[x]);
		  ufprintf(logfile, (char *)&chrstr);
		}
	    }

	  s = i;
	  ufprintf(logfile, "\n");
	}
    }

  if ((size % 16) > 0)
    {
      i = (16 - (size % 16));

      if (i>8) ufprintf(logfile, "  ");

      for (x=0;x<i;x++)
	{
	  ufprintf(logfile, "   ");
	}
      
      for (x=(s+1);x<size;x++)
	{
	  if ((hextodump[x] < 0x21) || (hextodump[x] > 0x7e))
	    {
	      ufprintf(logfile, ".");
	    } else {
	      bzero((char *)&chrstr, 1024);
	      sprintf((char *)&chrstr, "%c", hextodump[x]);
	      ufprintf(logfile, (char *)&chrstr);
	    }
	}
    }
  ufprintf(logfile, "\n");
}

/*************************************************
 *
 * Display some information.  But only if we are at a debug level that
 * should display it.
 *
 *************************************************/
void debug_printf(int level, char *fmt, ...)
{
  char dumpstr[2048], temp[2048];

  if ((level <= debug_level) && (fmt != NULL))
    {
      va_list ap;
      va_start(ap, fmt);

      bzero((char *)&dumpstr, 2048);
      bzero((char *)&temp, 2048);

      // Print out a tag that identifies the type of debug message being used.
      switch (level)
	{
	case DEBUG_NORMAL:
	  break;   
	  
	case DEBUG_CONFIG:
	  strcpy((char *)&dumpstr, "[CONFIG] ");
	  break;

	case DEBUG_STATE:
	  strcpy((char *)&dumpstr, "[STATE] ");
	  break;

	case DEBUG_AUTHTYPES:
	  strcpy((char *)&dumpstr, "[AUTH TYPE] ");
	  break;
	  
	case DEBUG_INT:
	  strcpy((char *)&dumpstr, "[INT] ");
	  break;

	case DEBUG_EVERYTHING:
	  strcpy((char *)&dumpstr, "[ALL] ");
	  break;
	}

      vsnprintf((char *)&temp, 2048, fmt, ap);
      
      strcat((char *)&dumpstr, (char *)&temp);

      if ((isdaemon == 2) || (logfile == NULL))
	{
	  printf("%s", dumpstr);
	} else {
	  fprintf(logfile, "%s", dumpstr);
	  fflush(logfile);
	}      

      va_end(ap);
    }
}

/*************************************************
 *
 * Display some information.  But only if we are at a debug level that
 * should display it.
 *
 *************************************************/
void debug_printf_nl(int level, char *fmt, ...)
{
  if ((level <= debug_level) && (fmt != NULL))
    {
      va_list ap;
      va_start(ap, fmt);

      if ((isdaemon == 2) || (logfile == NULL))
	{ 
	  vprintf(fmt, ap);
	} else {
	  vfprintf(logfile, fmt, ap);
	  fflush(logfile);
	}
	  
      va_end(ap);
    }
}
