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
 * File: xsup_driver.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: xsup_driver.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: xsup_driver.c,v $
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
 * Revision 1.39  2004/05/17 02:45:45  chessing
 *
 * Small cleanups prior to a final release.  (No bugs, or anything interesting.)
 *
 * Revision 1.38  2004/04/29 17:51:08  chessing
 *
 * Fix a logic error in xsup_debug.c.  Not defining a log file no longer segfaults.
 *
 * Revision 1.37  2004/04/26 20:51:12  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.36  2004/04/06 20:31:26  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.35  2004/04/05 17:19:16  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.34  2004/03/29 21:57:13  chessing
 *
 * Changed the socket number we use for communication with the daemon from 10240 (which seems like a bad choice) to 26798 (which seems a little more random ;).  Also changed our debug code so that it doesn't output to the console when we are running in daemon mode.  The only way to get debug info while in daemon mode is to set a log file!!!
 *
 * Revision 1.33  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.32  2004/03/26 21:34:51  chessing
 * Fixed problem with interface being down on startup causing xsupplicant to not read the proper configuration information when the interface is brought up.  Added/fixed code to rebuild userdata piece of structure when the essid changes.  Added code to avoid setting a key on an interface if the interface doesn't already have encryption enabled.  Added a little bit of debugging code to help find a solution to an IPC socket problem.
 *
 * Revision 1.31  2004/03/25 06:06:56  chessing
 *
 * Some debug code cleanups.  Fixed a bug with non-existant, or down interfaces defined in the allow_interfaces would loop forever.  Added calls to reset wireless keys to all 0s when we end up in disconnected, or held state.
 *
 * Revision 1.30  2004/03/24 08:21:01  galimorerpg
 * Added Pavel Roskin's "no_int" patch, which prevents xsupplicant from crashing when cleaning up on a system where no valid interfaces are present.
 *
 * Revision 1.29  2004/03/24 08:16:14  galimorerpg
 * Added Pavel Roskin's deny_first patch:
 *
 * If I put an interface to the deny list it means that I don't want xsupplicant to touch it in any way.  In particular, it should not be probed and validated, whatever it means.
 *
 * The attached patch swaps the order of the checks - deny list is checked before cardif_validate()
 *
 *
 * A small typo fix was also added to xsup_driver.c
 *
 * Revision 1.28  2004/03/24 07:42:33  galimorerpg
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
 * Revision 1.27  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.26  2004/03/20 05:38:38  chessing
 *
 * PID file fixed.  We now store the correct pid in the /var/run/xsupplicant pid file.
 *
 * Revision 1.25  2004/03/06 03:53:54  chessing
 *
 * We now send logoffs when the process is terminated.  Added a new option to the config file "wireless_control" which will allow a user to disable non-EAPoL key changes.  Added an update to destination BSSID checking that will reset the wireless key to all 0s when the BSSID changes.  (This is what "wireless_control" disables when it is set to no.)  Roaming should now work, but because we are resetting keys to 128 bit, there may be issues with APs that use 64 bit keys.  I will test this weekend.
 *
 * Revision 1.24  2004/02/28 01:26:38  chessing
 *
 * Several critical updates.  Fixed the HMAC failure on some keys. (This was due to a lot more than just an off-by-one.)  Fixed up the key decryption routine to identify key packets with no encrypted key, and use the peer key instead.  When using the peer key, we also can handle packets that are padded funny.  (Our Cisco AP1200 has two null pad bytes at the end of some key frames.)  Changed the response ID function to not add a 00 to the end of the ID.  The 00 byte shouldn't have been seen by the RADIUS server unless they were not paying attention to the EAP-Length.  So, this wasn't really a bug fix.  Started to add support for CN checking for TLS based protocols.
 *
 * Revision 1.23  2004/02/16 05:05:59  chessing
 *
 * Added support for the deny_interfaces, and allow_interfaces options in the config file.  (We should now have support for *EVERYTHING* in the new config file format!)  Updated EAP types other than SIM to use the new password prompt/delay code.  Phase 2 of TTLS still needs to be completed, along with the code that actually notifies the GUI.
 *
 * Revision 1.22  2004/02/13 05:51:32  chessing
 *
 * Removed pieces from sha1.c that were duplicates for OpenSSL calls.  Hopefully this will resolve the TLS issues that have been under discussion on the list.  Added support for a default path for the config file.  If a config file is not specified on the command line, xsupplicant will attempt to read it from /etc/xsupplicant.conf.  Moved code to request a password from each of the EAP types to interface.c/h.  Currently this change is only implemented in the EAP-SIM module.  The changes to the GUI prompt code now make more sense, and are easier to follow.  It will be updated in other EAP types soon.
 *
 * Revision 1.21  2004/02/07 07:19:37  chessing
 *
 * Fixed EAP-SIM so that it works with FreeRADIUS correctly.  Fixed a bunch of memory leaks in the EAP-SIM, and related code.
 *
 * Revision 1.20  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.19  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.18  2004/01/17 21:16:15  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.17  2004/01/15 23:45:10  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.16  2004/01/15 01:12:44  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.15  2004/01/14 22:07:25  chessing
 *
 * Fixes that were needed in order to allow us to authenticate correctly.  We should now be able to authenticate using only information provided by the config file!
 *
 * Revision 1.14  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.13  2004/01/13 01:55:55  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.12  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.11  2003/12/28 07:13:21  chessing
 *
 * Fixed a problem where we would segfault on an EAP type we didn't understand.  Added EAP-OTP.  EAP-OTP has been tested using the opie package, and Radiator 3.8.  EAP-OTP currently prompts for a passphrase, which it shouldn't do, so it should be considered *VERY* much in test mode until we finish the GUI.
 *
 * Revision 1.10  2003/12/19 06:29:56  chessing
 *
 * New code to determine if an interface is wireless or not.  Lots of IPC updates.
 *
 * Revision 1.9  2003/12/18 02:09:45  chessing
 *
 * Some small fixes, and working IPC code to get interface state.
 *
 * Revision 1.8  2003/12/14 06:11:03  chessing
 *
 * Fixed some stuff with SIM in relation to the new config structures.  Cleaned out CR/LF from LEAP source files.  Added user certificate support to TTLS and PEAP. Some additions to the IPC code. (Not tested yet.)
 *
 * Revision 1.7  2003/12/10 14:33:16  npetroni
 * removed segfault that occurs when calling program without an interface.
 *
 * Revision 1.6  2003/12/07 06:20:19  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 * Revision 1.5  2003/12/04 04:36:24  chessing
 *
 * Added support for multiple interfaces (-D now works), also added DEBUG_EXCESSIVE to help clean up some of the debug output (-d 6).
 *
 * Revision 1.4  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.3  2003/11/24 12:13:54  npetroni
 * Added catch for bad arguments
 *
 * Revision 1.2  2003/11/19 04:23:18  chessing
 *
 * Updates to fix the import
 *
 *
 *
 *******************************************************************/
/***
 *** This code implements 802.1X Authentication on a supplicant
 *** and supports multiple Authentication types.  
 *** See IEEE Draft P802.1X/D11, March 27, 2001 for more details
 ***/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <strings.h>
#include <string.h>

#include "profile.h"
#include "config.h"
#include "eap.h"
#include "statemachine.h"
#include "xsup_ipc.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "eapol.h"
#include "cmd_handler.h"
#include "cardif/cardif.h"

#define XVERSION "1.0pre2"

int wpa_keying = 0;
char pidfileName[25] = "/var/run/xsupplicant";
struct interface_data *int_list;
int dsd = 0;


/****************************************
 *
 * Create a PID file, and populate it with our PID, and the socket number
 * to be used to talk to the daemon.
 *
 ****************************************/
int create_pidfile(int socknum)
{
  FILE *pidfile;

  pidfile = fopen(pidfileName, "w");
  if (pidfile)
    {
      fprintf(pidfile, "%d", getpid());
      fclose(pidfile);
      return TRUE;
    }
  return FALSE;
}

/****************************************
 *
 * Delete a PID file.  Should only be called from global_deinit!
 *
 ****************************************/
int delete_pidfile()
{
  unlink(pidfileName);

  return TRUE;
}

/****************************************
 *
 * Test for a PID file, and return an error if something seems to be running.
 *
 ****************************************/
int is_other_xsup_running()
{
  FILE *pidfile;

  pidfile = fopen(pidfileName, "r");
  if (pidfile)
    {
      fclose(pidfile);
      return TRUE;
    }
  return FALSE;
}

/*********************************************
 *
 * When the alarm clock is called, we need to go through all interfaces, and
 * set "tick" to true.
 *
 *********************************************/
void alrmclock()
{
  struct interface_data *intcur;

  intcur = int_list;

  // Loop through all of the interfaces we are working with, and set the tick
  // value!
#ifdef RTL_WPA_CLIENT  
  if (intcur != NULL && intcur->statemachine != NULL)
    {
      intcur->statemachine->tick = TRUE;
    }
#else
  while (intcur != NULL)
    {
      intcur->statemachine->tick = TRUE;
      intcur = intcur->next;
    }
  alarm(1);
#endif  
}

/*********************************************
 *
 * Determine if the interface given is in the list of interfaces.
 *
 *********************************************/
int int_in_list(char *intName, struct config_string_list *strList)
{
  struct config_string_list *cur;

  if ((!intName) || (!strList))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to int_in_list()!\n");
      return XEMALLOC;
    }

  // Our check is case sensative!
  cur = strList;

  while ((cur != NULL) && (strcmp(intName, cur->name) != 0))
    {
      cur = cur->next;
    }

  if (cur == NULL)
    {
      return FALSE;    // The interface isn't in our list.
    } 

  return TRUE;
}

/*********************************************
 *
 * Add the interfaces that are in our allow list, that weren't already
 * discovered.  In general, this isn't too interesting, but there may be
 * circumstances where an interface isn't recognized where 802.1x should
 * happen.  An example might be authenticating to a switch that has 
 * multiple vlans, with each vlan requiring 802.1x authentication.  In this
 * case, subinterfaces for vlans will probably not be detected, and will
 * require manual definition in the config file.
 *
 *********************************************/
void add_other_allowed_interfaces(struct interface_data **myint,
				  struct daemon_conf *dcfg)
{
  struct config_string_list *allowints, *icur;
  struct interface_data *cur;

  if ((!myint) || (!dcfg))
    {
      return;
    }

  allowints = config_allowed_interfaces();

  // If there isn't anything to do, then just bail.
  if (allowints == NULL) return;

  icur = allowints;

  // If we don't have any interfaces in the list, we start by adding the 
  // first one outside the loop.
  if (*myint == NULL)
    {
      // This interface isn't in our list, so add it.
      *myint = (struct interface_data *)malloc(sizeof(struct interface_data));
      if (*myint == NULL) 
	{
	  debug_printf(DEBUG_NORMAL, "Error allocating memory!  Your allow list will be ignored!\n");
	  return;
	}
      cur = *myint;
      memset(cur, 0, sizeof(struct interface_data));
	  
      if (init_interface_struct(cur, icur->name, dcfg) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't initialize the interface struct!\n");
	  return;
	}

      cardif_init(cur);
      debug_printf(DEBUG_NORMAL, "Interface %s initalized!\n",cur->intName);

      cur->isWireless = FALSE;

      cur->userdata = config_build(cur->cur_essid);
      config_set_globals(cur);
      cur->next = NULL;
    }

  while (icur != NULL)
    {
      cur = *myint;

      // Check to see if this allowed interface is already set up.
      while ((cur != NULL) && (strcmp(icur->name, cur->intName) != 0))
	{
	  cur = cur->next;
	}

      if (cur == NULL)
	{
	  // This isn't in our list...
	  cur = *myint;

	  while (cur->next != NULL) cur = cur->next;

	  cur->next = (struct interface_data *)malloc(sizeof(struct interface_data));
	  if (cur->next == NULL)
	    {
	      debug_printf(DEBUG_NORMAL, "Memory allocation error!  Your allowed interfaces will not be added!\n");
	      return;
	    }

	  cur = cur->next;
	  memset(cur, 0, sizeof(struct interface_data));
	  
	  if (init_interface_struct(cur, icur->name, dcfg) != XENONE)
	    {
	      debug_printf(DEBUG_NORMAL, "Couldn't init interface struct for interface %s! Cannot continue!\n", icur->name);
	    }

	  cardif_init(cur);
	  debug_printf(DEBUG_NORMAL, "Interface %s initalized!\n",cur->intName);
      
	  cur->isWireless = FALSE;

	  cur->userdata = config_build(cur->cur_essid);
	  config_set_globals(cur);
	  cur->next = NULL;
	}
      icur = icur->next;
    }
}

/*********************************************
 *
 * Initialize all of the pieces that will be needed for our supplicant.
 * We need to initialize in the correct order, in order to make sure
 * that other pieces of the initialization happen with the correct 
 * information available.
 *
 * THIS FUNCTION SHOULD NEVER BE CALLED OUTSIDE OF THIS FILE!
 *
 *********************************************/
int global_init(int new_debug, int xdaemon, char *device, char *config,
		struct daemon_conf **dcfg)
{
  struct interface_data *intcur;
  struct config_string_list *denyints;
  int index, retVal, denyint;
  char intName[16];
  char *default_cfg = "/etc/xsupplicant.conf";

  if (!dcfg)
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to global_init()!\n");
      return XEMALLOC;
    }

  // Set our debug level.
  
  int_list = NULL;
  intcur = NULL;

  debug_setlevel(new_debug, xdaemon);

  if (config == NULL) 
    {
      printf("Using default config!\n");
      config = default_cfg;
    }

  // Build up our config information.
  switch(config_setup(config))
    {
    case XECONFIGFILEFAIL:
      debug_printf(DEBUG_NORMAL, "\tPlease ensure that \"%s\" contains a valid xsupplicant configuration.\n", config);
      exit(255);
      break;
    case XECONFIGPARSEFAIL:
      debug_printf(DEBUG_NORMAL, "There was a problem with the config file.  We cannot continue.\n");
      exit(255);
      break;
    }

  logfile_setup(config_get_logfile());

  // Get a list of interfaces we allow, and deny.
  denyints = config_denied_interfaces();

  if (xdaemon > 0)
    {
      // If we are a daemon, we ignore any passed in information,
      // enumerate interfaces, then build configs.
      index = 0;
      
      while (cardif_get_int(index, (char *)&intName) != XNOMOREINTS)
	{
	  // We know we have a valid int, so check and make sure it isn't in
	  // our list of denied interfaces.
	  denyint = FALSE;

	  if (denyints != NULL)
	    {
	      // Check to see if this interface is in our list of 
	      //  interfaces to ignore.
	      denyint = int_in_list(intName, denyints);
	    } else {
	      debug_printf(DEBUG_CONFIG, "List of denied interfaces is empty! All interfaces will be used!\n");
	    }

	  if (denyint == FALSE)
	    {
	      if (cardif_validate(intName) == TRUE)
		{
		  retVal = 0;
		  if (int_list == NULL)
		    {
		      int_list = (struct interface_data *)malloc(sizeof(struct interface_data));
		      if (int_list == NULL) return XEMALLOC;
		      memset(int_list, 0, sizeof(struct interface_data));
		      
		      if (init_interface_struct(int_list, (char *)&intName, *dcfg) != XENONE)
			{
			  debug_printf(DEBUG_NORMAL, "Couldn't init interface struct %s!!!! Cannot continue!\n");
			  exit(1);
			}

		      intcur = int_list;
		      
		    } else {
		      
		      intcur->next = (struct interface_data *)malloc(sizeof(struct interface_data));
		      if (intcur->next == NULL) return XEMALLOC;
		      memset(intcur->next, 0, sizeof(struct interface_data));
		      
		      intcur = intcur->next;
		      if (init_interface_struct(intcur, (char *)&intName, *dcfg) != XENONE)
			{
			  debug_printf(DEBUG_NORMAL, "Couldn't init interface stuct for interface %s!!  Cannot continue!\n", intName);
			  exit(1);
			}
		    }
		  intcur->next = NULL;

		  if (cardif_init(intcur) < 0)
		    {
		      retVal = XENOTINT;
		    } else {
		      debug_printf(DEBUG_NORMAL, "Interface %s initalized!\n",intcur->intName);

		      // If we don't know what kind of interface this is....
		      if (intcur->isWireless == -1)
			{
			  // Check to see if this interface is wireless.
			  if (cardif_int_is_wireless(intcur->intName) == TRUE)
			    {
			      intcur->isWireless = TRUE;
			      cardif_check_dest(intcur);
			    } else {
			      intcur->isWireless = FALSE;
			    }
			}
		      intcur->userdata = config_build(intcur->cur_essid);
		      config_set_globals(intcur);
		      intcur->next = NULL;
		    }
		} else {
		  debug_printf(DEBUG_NORMAL, "Invalid interface %s\n",intName);
		}
	    } else {
	      debug_printf(DEBUG_INT, "Interface %s will be ignored!\n", intName);
	    }
	  index++;
	  bzero(&intName, 16);
	} 

      // Here, we need to check, and add interfaces that are included in the
      // allow, but were not found already. 
      add_other_allowed_interfaces(&int_list, *dcfg);

    } else {

      // We don't check if the interface is in our allow, or deny list when
      //  we are only working with one interface.

      if (!device) {
	debug_printf(DEBUG_NORMAL, "No interface provided!\n");
	return XENOTINT;
      }
      int_list = (struct interface_data *)malloc(sizeof(struct interface_data));
      if (int_list == NULL) return XEMALLOC;
      memset(int_list, 0, sizeof(struct interface_data));

      // Start by setting up the structure, and assigning the interface.
      if (init_interface_struct(int_list, device, *dcfg) != XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't init interface struct for device %s!  Cannot continue!\n", device);
	  exit(1);
	}

      // Establish a handler to the interface.
      if (cardif_init(int_list) < 0) return XENOTINT;
      debug_printf(DEBUG_NORMAL, "Interface initalized!\n");
  
      // If we don't know what kind of interface this is....
      if (int_list->isWireless == -1)
	{
	  // Check to see if this interface is wireless.
	  if (cardif_int_is_wireless(int_list->intName) == TRUE)
	    {
	      int_list->isWireless = TRUE;
	      cardif_check_dest(int_list);
	    } else {
	      int_list->isWireless = FALSE;
	    }
	}
      int_list->userdata = config_build(int_list->cur_essid);
      config_set_globals(int_list);
      int_list->next = NULL;

      // Then, initialize EAPoL (which will initialize EAP methods).
    }

  return XENONE;
}

/****************************************
 *
 * Clean up any values that we have set up for use by the supplicant.  This
 * includes calling any clean up routines for other modules such as EAPoL
 * or EAP.
 *
 * THIS FUNCTION SHOULD NEVER BE CALLED OUTSIDE THIS FILE!
 *
 ****************************************/
#ifdef RTL_WPA_CLIENT
void global_deinit(int signum)
#else
void global_deinit()
#endif
{
  struct interface_data *intcur;
  char logoff[128];
  int logoffsize = 0;

  // First thing we need to do is kill the alarm clock, so it doesn't try
  // to do something while we are in the middle of quitting! ;)
  alarm(0);

  intcur = int_list;

  if (intcur)
    {
      xsup_ipc_cleanup(int_list);
      eapol_cleanup(int_list);
    }

  // We are going to want to send logoffs for each interface.  But, the
  // logoff frame will be the same, with different source/dest addresses.
  // Since sendframe() will fill in the source/dest, we only need one copy
  // of the logoff.
  txLogoff((char *)&logoff, &logoffsize);

  // We need to change this when we handle multple interfaces.
  while (intcur != NULL)
    {
      debug_printf(DEBUG_INT, "Sending Logoff for int %s!\n",intcur->intName);
      sendframe(intcur, (char *)&logoff, logoffsize);
      cardif_deinit(intcur);
      intcur=destroy_interface_struct(intcur);
    }

  config_destroy();

  logfile_cleanup();

  debug_printf(DEBUG_STATE, "Deleting PID File...\n");

  delete_pidfile();

  exit(0);
}


/****************************************
 *
 * Display our usage information.
 *
 ****************************************/
void usage(char *prog)
{
  debug_printf(DEBUG_NORMAL, "Usage: %s "
	       "[-W] "
	       "[-c config file] "
	       "[-i device] "
	       "[-d debug_level] "
	       "\n", prog);
}

/***************************************
 *
 * The main body of the program.  We should keep this simple!  Process any
 * command line options that were passed in, set any needed variables, and
 * enter the loop to handle sending an receiving frames.
 *
 ***************************************/
#ifdef RTL_WPA_CLIENT
int xsup_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif /* RTL_WPA_CLIENT */
{
  int op, pid, ssid, mac;
  char *theOpts = "c:i:d:Wf";
#ifdef RTL_WPA_CLIENT  
  // getopt can be called once only!! Second call don't work!
  static char *dstAddr = NULL, *config = NULL, *device = NULL, *netid = NULL;
  char *username = NULL, *password = NULL, *auth_method = NULL;
  static int xdaemon = 1, new_debug=0, firsttime = 0, framewaiting = 0;
#else  
  char *dstAddr = NULL, *config = NULL, *device = NULL, *netid = NULL;
  char *username = NULL, *password = NULL, *auth_method = NULL;
  int xdaemon = 1, new_debug, firsttime = 0, framewaiting = 0;
#endif  
  struct daemon_conf *dconf = NULL;
  struct interface_data *intcur = NULL;

#ifndef RTL_WPA_CLIENT  
  if (is_other_xsup_running() == TRUE)
    {
      debug_printf(DEBUG_NORMAL, "You can only run one instance of XSupplicant!\n");
      debug_printf(DEBUG_NORMAL, "If you are sure that no other copy of XSupplicant is running, please delete /var/run/xsupplicant!\n");
      exit(-1);
    } 

  new_debug = 0;
  config = NULL;
#endif  
  
#ifdef RTL_WPA_CLIENT  
//  	printf("1: xdaemon = %d, new_debug = %d, config = %s\n", xdaemon, new_debug, config);
#endif

  // Process any arguments we were passed in.
#ifdef RTL_WPA_CLIENT  
  while ((op = getopt(argc, argv, theOpts)) != EOF) 
    {
      switch (op)
	{
	case 'c':
	  // Path to config file.
	  config = optarg;
	  break;

	case 'i':
	  // Interface to use.
	  device = optarg;
	  xdaemon = 0;
	  break;

	case 'd':
	  // Set the debug level.
	  new_debug = atoi(optarg);
	  break;

	case 'W':
	  // Provide WPA keying material (PMK) to wpa_supplicant.
	  wpa_keying = 1;
	  break;

	case 'f':
	  // Force running in the foreground.
	  xdaemon = 2;
	  break;

	  // added by npetroni, need to do something with bad options.
	  // for now, I say exit.
	default:
	  usage(argv[0]);
	  exit(0);
	  break;
	}
    }
#endif

#ifdef RTL_WPA_CLIENT  
//  printf("2: xdaemon = %d, new_debug = %d, config = %s\n", xdaemon, new_debug, config);
#endif

  if ((xdaemon == 1) && ((dstAddr != NULL) || 
			(device != NULL) || (netid != NULL) || 
			(username != NULL) || (password != NULL) ||
			(auth_method != NULL)))
    {
      printf("You cannot override configuration file options when running\n");
      printf("in daemon mode!  Options will be ignored!\n");
    }

  if (xdaemon == 1)
    {
      printf("Starting XSupplicant v. %s!\n",XVERSION);
      // We should fork, and let the parent die.
#ifndef RTL_WPA_CLIENT      
      pid = fork();
#endif      
      if (pid > 0) 
	{
	  // If we are the parent, die.
	  exit(0);
	}
      
      // Otherwise, keep going.
    }

  // We have our options set, to initalize, then go in to our event loop.
  if (global_init(new_debug, xdaemon, device, config, &dconf) != 0)
    {
      printf("Couldn't initalize!!!!\n");
      exit(255);
    }

  if (int_list == NULL)
    {
      printf("No valid interface found!\n");
#ifndef RTL_WPA_CLIENT  
      global_deinit();
#endif      
      exit(255);
    }

#ifndef RTL_WPA_CLIENT  
  if (xsup_ipc_init(int_list) != 0)
    {
      printf("Couldn't initalize daemon socket!\n");
      global_deinit();
      exit(255);
    }

  // When we quit, cleanup.
  signal(SIGTERM, global_deinit);
  signal(SIGINT, global_deinit);
  signal(SIGQUIT, global_deinit);
  signal(SIGKILL, global_deinit);

  // Create our pidfile.
  // int_list->sockInt isn't really what we want to pass in here.  We *Really*
  // want to pass in the socket # that the client should talk to us on.  This
  // will allow us to be socket agnostic.
  if(!create_pidfile(int_list->sockInt))
    {
      printf("Couldn't create pid file!\n");
    }

  // Set up a handler, and start our timer.
  signal(SIGALRM, alrmclock);
  alarm(1);

  while (1!=0)
    {
      struct timeval tv;
      fd_set rfds;
      int maxfd = 0;
      intcur = int_list;

      xsup_ipc_process(intcur);

      FD_ZERO(&rfds);
      while (intcur != NULL)
	{
	  debug_printf(DEBUG_EVERYTHING, "Processing interface %s...\n",intcur->intName);

	  if (firsttime == 0)
	    {
	      // Execute our startup command before we do anything else.
	      cmd_handler_exec(intcur, config_get_startup_cmd());
	    }

	  // First, check our destination address, in case we have hopped APs.
	  mac = cardif_check_dest(intcur);
	  ssid = cardif_check_ssid(intcur);

	  if ((mac == TRUE) && (ssid != XNEWESSID))
	    {
	      debug_printf(DEBUG_CONFIG, "MAC address changed!  Updating config!\n");
	      intcur->userdata = config_build(intcur->cur_essid);
	    }

	  if (ssid == XNEWESSID)
	    {
	      // Our ESSID changed, we need to clear our config, so that
	      // we generate a new one on the way through the statemachine.
	      eap_clear_active_method(intcur);

	      // We also need to check to make sure we are pointing
	      // to the correct configuration information.
	      intcur->userdata = config_build(intcur->cur_essid);
	    }
	  eapol_execute(intcur);
	  FD_SET(intcur->sockInt, &rfds);
	  if (intcur->sockInt > maxfd)
	    maxfd = intcur->sockInt;
	  
	  // If we have a frame available on any interface, we won't
	  // sleep.  Instead we will keep looping through to keep things
	  // moving as fast as possible.
	  if (frameavail(intcur) == TRUE) framewaiting = 1;
	  intcur = intcur->next;
	}
      firsttime = 1;
      if (framewaiting == 0)
	{
	  tv.tv_sec = 0;
	  tv.tv_usec = 500000;
	  select(maxfd + 1, &rfds, NULL, NULL, &tv);
	}
      framewaiting = 0;
    }
#endif /* RTL_WPA_CLIENT */    

  return XENONE;
}
