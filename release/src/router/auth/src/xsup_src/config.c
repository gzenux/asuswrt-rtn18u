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
 * File: config.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: config.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: config.c,v $
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
 * Revision 1.32  2004/03/26 21:34:51  chessing
 * Fixed problem with interface being down on startup causing xsupplicant to not read the proper configuration information when the interface is brought up.  Added/fixed code to rebuild userdata piece of structure when the essid changes.  Added code to avoid setting a key on an interface if the interface doesn't already have encryption enabled.  Added a little bit of debugging code to help find a solution to an IPC socket problem.
 *
 * Revision 1.31  2004/03/26 03:52:46  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.30  2004/03/24 07:42:33  galimorerpg
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
 * Revision 1.29  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.28  2004/03/15 16:23:24  chessing
 *
 * Added some checks to TLS using EAP types to make sure the root certificate isn't set to NULL.  (If it is, we can't authenticate, so we bail out.)  Changed the user certificate settings in the config file to all start with user_.  So, "cert" is now "user_cert", "key" is now "user_key", and "key_pass" is now "user_key_pass".  The structures and other related variables were also updated to reflect this change.  THIS WILL PROBABLY BREAK CONFIG FILES FOR SOME USERS!  (Be prepared for complaints on the list!)  ;)
 *
 * Revision 1.27  2004/03/06 03:53:52  chessing
 *
 * We now send logoffs when the process is terminated.  Added a new option to the config file "wireless_control" which will allow a user to disable non-EAPoL key changes.  Added an update to destination BSSID checking that will reset the wireless key to all 0s when the BSSID changes.  (This is what "wireless_control" disables when it is set to no.)  Roaming should now work, but because we are resetting keys to 128 bit, there may be issues with APs that use 64 bit keys.  I will test this weekend.
 *
 * Revision 1.26  2004/03/05 23:58:45  chessing
 *
 * Added CN (sometimes called server name) checking to TTLS and PEAP.  This resulted in two new config options in the eap-ttls, and eap-peap blocks.  cncheck should be the name (or partial name) to match in the CN.  cnexact should be yes/no depending on if we want to match the CN exactly, or just see if our substring is in the CN.
 *
 * Revision 1.25  2004/02/16 05:05:59  chessing
 *
 * Added support for the deny_interfaces, and allow_interfaces options in the config file.  (We should now have support for *EVERYTHING* in the new config file format!)  Updated EAP types other than SIM to use the new password prompt/delay code.  Phase 2 of TTLS still needs to be completed, along with the code that actually notifies the GUI.
 *
 * Revision 1.24  2004/02/10 03:40:22  npetroni
 * updated config to include a phase 2 identity for PEAP
 *
 * Revision 1.23  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.22  2004/01/15 23:45:10  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.21  2004/01/15 01:12:44  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.20  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.19  2004/01/13 01:55:55  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.18  2004/01/06 23:35:06  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.17  2004/01/06 22:25:58  npetroni
 * added crl parameter to tls, ttls, and peap and user cert,key,key_pass to ttls,peap
 *
 * Revision 1.16  2003/12/31 16:16:35  npetroni
 * made some generalizations to the way config code works so that now
 * it is easy to let any method be put inside of PEAP with little effort.
 *
 * Added MD5, SIM to the PEAP config section.
 *
 * Added allow types for OTP and GTC- we still need configuration parameters
 *   for these methods though.
 *
 * this code is coming together I think.
 *
 * Revision 1.15  2003/12/31 07:03:47  npetroni
 * made a number of changes to the config code to generalize handling of EAP
 * methods and phase2. I still need to go back and make the parser work for
 * other phase2 type in PEAP, but the backend is there.
 *
 * Revision 1.14  2003/12/28 20:41:57  chessing
 *
 * Added support for EAP-GTC.  It is the exact same code as OTP, so only the EAP type and defines in eap.c were needed.
 *
 * Revision 1.13  2003/12/28 07:13:21  chessing
 *
 * Fixed a problem where we would segfault on an EAP type we didn't understand.  Added EAP-OTP.  EAP-OTP has been tested using the opie package, and Radiator 3.8.  EAP-OTP currently prompts for a passphrase, which it shouldn't do, so it should be considered *VERY* much in test mode until we finish the GUI.
 *
 * Revision 1.12  2003/12/19 23:19:11  npetroni
 * updated config code and test example. Fixed a couple things
 *   1. added new variables to globals:
 *      startup_command
 *      first_auth_command
 *      reauth_command
 *      auth_period
 *      held_period
 *      max_starts
 *      allow_interfaces
 *      deny_ineterfaces
 *
 *   2. added new variables to network:
 *      dest_mac
 *
 *   3. added new variables to ttls:
 *      phase2_type
 *
 *   4. added new variables to peap:
 *      allow_types
 *
 *   5. layed the groundwork for "preferred types" to be sent in Nak
 *
 * Revision 1.11  2003/12/14 06:11:03  chessing
 *
 * Fixed some stuff with SIM in relation to the new config structures.  Cleaned out CR/LF from LEAP source files.  Added user certificate support to TTLS and PEAP. Some additions to the IPC code. (Not tested yet.)
 *
 * Revision 1.10  2003/12/10 14:13:16  npetroni
 * updated configuration code to parse all types. example updated as well
 *
 * Revision 1.9  2003/12/07 06:20:19  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 * Revision 1.8  2003/12/04 04:36:24  chessing
 *
 * Added support for multiple interfaces (-D now works), also added DEBUG_EXCESSIVE to help clean up some of the debug output (-d 6).
 *
 * Revision 1.7  2003/11/29 04:46:02  chessing
 *
 * EAP-SIM changes : EAP-SIM will now try to use the IMSI as the username, when the preferred EAP type is SIM, and the username value is NULL.  Also, if simautogen is TRUE, then we will also build and attach a realm as specified in the RFC.
 *
 * Revision 1.6  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.5  2003/11/29 01:11:30  npetroni
 * Added first round of configuration code.
 * Structural Changes:
 *    added examle config file and finished config-parser to test configuration
 *    files and optionally dump the output
 *
 * Current Status:
 *   Have not added parameters for any other method than TLS so we can discuss
 *   the changes before doing so.
 *
 *   Did not update config_build() so chris can keep testing as before.
 *
 * Revision 1.4  2003/11/27 02:33:25  chessing
 *
 * Added LEAP code from Marios Karagiannopoulos.  Keying still needs to be completed.
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

#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>

#include "xsup_debug.h"
#include "xsup_err.h"
#include "config.h"

// there has GOT to be a better way than this...
#include "eap_types/md5/eapmd5.h"
#include "eap_types/tls/eaptls.h"
#include "eap_types/ttls/eapttls.h"
#include "eap_types/mschapv2/eapmschapv2.h"
#include "eap_types/peap/eappeap.h"
#include "eap_types/leap/eapleap.h"

#ifndef EAP_SIM_ENABLE
#define EAP_SIM_ENABLE
#endif 
#include "eap_types/sim/eapsim.h"



struct config_data *config_info = NULL; // the configuration data structure
int config_parse_debug = 0;
extern FILE *yyin;
extern int config_linenum;
extern int yyparse(void);

#define FREE_STRING(x) if (x != NULL) {free(x); x = NULL;}

/****************************************
 *
 * Load all of the configuration information in to memory.  We should
 * set a flag to make sure that we have loaded the config before we
 * call config_build().
 *
 ****************************************/
int config_setup(char *path_to_config)
{
  /* Make sure we got a parameter */
  if (path_to_config == NULL) {
    printf("Doing Debug...\n");
    debug_printf(DEBUG_NORMAL, "Configuration file not given\n");
    debug_printf(DEBUG_NORMAL, "This should NEVER happen!\n");
    return XECONFIGFILEFAIL;
  }

  /* check to see if we can really open this file */
  yyin = fopen(path_to_config, "r");
  if (yyin == NULL) {
    debug_printf(DEBUG_NORMAL, "Failed to open configuration %s\n\n", path_to_config);
    return XECONFIGFILEFAIL;
  }
  
  /* check to see if the configuration is already set */
  if (config_info) {
    debug_printf(DEBUG_NORMAL, "config_setup called, but configuration is already loaded. Call config_destroy\n");
    return XECONFIGFILEFAIL;
  }

  /* parse the file */
  if (config_parse() != XENONE) {
    delete_config_data(&config_info);
    return XECONFIGPARSEFAIL;
  }

  // set the file name
  if (config_info)
    config_info->config_fname = strdup(path_to_config);

  return XENONE;
}


struct config_network *config_find_network(struct config_network *nethead, 
					   char *matchname)
{
  struct config_network *cur;

  cur = nethead;

  if ((nethead == NULL) || (matchname == NULL))
    {
      debug_printf(DEBUG_EVERYTHING, "No match name to search!\n");
      return NULL;
    }

  while ((cur != NULL) && (strcmp(cur->name, matchname) != 0))
    {
      cur = cur->next;
    }
  
  // If we got a match, return it.
  if (cur != NULL)
    {
      return cur;
    }
  
  // Otherwise, look against the essid.
  cur = nethead;

  if ((cur != NULL) && (cur->ssid != NULL))
    {
      while ((cur != NULL) && (strcmp(cur->ssid, matchname) != 0))
	{
	  debug_printf(DEBUG_NORMAL, "%s ? %s\n", cur->ssid, matchname);
	  cur = cur->next;
	}
  
      // Do we have a match on ssid?
      if (cur != NULL)
	{
	  return cur;
	}
    }
  return NULL;
}

/****************************************
 *
 * Get configuration information out of memory, and populate the userdata
 * structure.
 *
 ****************************************/
struct config_network *config_build(char *network_name)
{
  struct config_network *result;

  if (config_info != NULL)
    {
      debug_printf(DEBUG_CONFIG, "Working from config file %s.\n",config_info->config_fname);

      // We were passed in a "network name".  First, look through the config
      // to see if it matches any friendly names.
      result = config_find_network(config_info->networks, network_name);

      if (result != NULL) return result;

      // This is not good.  We don't have any configuration information
      // for the requested network.  So, we need to return the default
      // information, and a warning.
      debug_printf(DEBUG_EVERYTHING, "No configuration information for network \"%s\" found.  Using default.\n", network_name);

      result = config_find_network(config_info->networks, 
				   config_info->globals->default_net);

      if (result != NULL) return result;

      // Uh oh..  We didn't find *anything*.
      debug_printf(DEBUG_NORMAL, "ERROR : No valid network profile could be located!  (Even tried default.)\n");

    } else {
      debug_printf(DEBUG_CONFIG, "config_info == NULL!  No config to update!\n");
    }
  return NULL;
}

/************************************
 *
 * Set statemachine/config related variables for this interface.
 *
 ************************************/
int config_set_globals(struct interface_data *myint)
{

  if (myint == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No configuration information is available!\n");
      return -1;
    }
  // Start by seeing if we need to set any global values.
  if ((CONFIG_GLOBALS_AUTH_PER & config_info->globals->flags) ==
      CONFIG_GLOBALS_AUTH_PER)
    {
      myint->statemachine->authPeriod = config_info->globals->auth_period;
    }

  if ((CONFIG_GLOBALS_HELD_PER & config_info->globals->flags) ==
      CONFIG_GLOBALS_HELD_PER)
    {
      myint->statemachine->heldPeriod = config_info->globals->held_period;
    }

  if ((CONFIG_GLOBALS_MAX_STARTS & config_info->globals->flags) ==
      CONFIG_GLOBALS_MAX_STARTS)
    {
      myint->statemachine->maxStart = config_info->globals->max_starts;
    }
 
  return 0;
}

/************************************
 *
 * Return a list of allowed interfaces.
 *
 ************************************/
struct config_string_list *config_allowed_interfaces()
{
  return config_info->globals->allow_interfaces;
}

/************************************
 *
 * Return a list of denied interfaces.
 *
 ************************************/
struct config_string_list *config_denied_interfaces()
{
  return config_info->globals->deny_interfaces;
}

/************************************
 *
 * Return the startup command we want to use.  The caller should *NOT* free
 * the resulting variable!
 *
 ************************************/
char *config_get_startup_cmd()
{
  if ((config_info == NULL) || (config_info->globals == NULL))
    {
      debug_printf(DEBUG_CONFIG, "(startup_cmd) No configuration information available!\n");
      return NULL;
    }

  return config_info->globals->startup_command;
}

char *config_get_first_auth_cmd()
{
  if ((config_info == NULL) || (config_info->globals == NULL))
    {
      debug_printf(DEBUG_CONFIG, "(first_auth_cmd) No configuration information available!\n");
      return NULL;
    }
  return config_info->globals->first_auth_command;
}

char *config_get_reauth_cmd()
{
  if ((config_info == NULL) || (config_info->globals == NULL))
    {
      debug_printf(DEBUG_CONFIG, "(reauth_cmd) No configuration information available!\n");
      return NULL;
    }
  return config_info->globals->reauth_command;
}

/**********************************************************************************
 * NOTE: Do *NOT* debug_printf() in this function or you'll cause a recursive loop.
 **********************************************************************************/
char *config_get_logfile()
{
  if ((config_info == NULL) || (config_info->globals == NULL))
    {
      return NULL;
    }
  return config_info->globals->logfile;
}

/************************************
 *
 * Clean up any memory that we have used to store the configuration information
 * 
 ************************************/
void config_destroy()
{
  /* close the input file */
  if (yyin)
    fclose(yyin);

  /* see if there really is something to cleanup */
  delete_config_data(&config_info);
}

/************************************
 *
 * Temporary test function for parsing
 *
 ************************************/
int config_parse()
{
  if (yyparse() != XENONE) {
    return XECONFIGPARSEFAIL;
  }
  return XENONE;
}


//****************************************
// CONFIG QUERIES
//****************************************

/******************************************
 *
 * See if the network config is currently in memory
 *
 ******************************************/
int config_contains_network(char *netname) 
{
  if (!config_info || !config_info->networks)
    return FALSE;
  return config_network_contains_net(config_info->networks, netname);
}

/******************************************
 *
 * See if network config is  allowed
 * 
 ******************************************/
int config_allows_network(struct config_data *conf, char *netname)
{
  struct config_string_list *current;
  // make sure we have a config and globals
  if (!conf || !conf->globals)
    return FALSE;

  current = conf->globals->allowed_nets;
  
  // lack of an allowed list means all nets are allowed
  if (current == NULL) 
    return TRUE;

  if (config_string_list_contains_string(current, netname))
    return TRUE;

  return FALSE;
}


//**********************************************
// Private functions for config parsing. Do 
// not call these from outside config code
//**********************************************

  /*******************/
 /* CONFIG_TLS      */
/*******************/

/* take a pointer to a config_eap_tls and cleanly delete the structure
   then make it NULL */
void delete_config_eap_tls(struct config_eap_tls **tmp_tls)
{
  if (*tmp_tls == NULL)
    return;

  FREE_STRING((*tmp_tls)->user_cert);
  FREE_STRING((*tmp_tls)->root_cert);
  FREE_STRING((*tmp_tls)->root_dir);  
  FREE_STRING((*tmp_tls)->crl_dir);  
  FREE_STRING((*tmp_tls)->user_key);
  FREE_STRING((*tmp_tls)->user_key_pass);
  FREE_STRING((*tmp_tls)->random_file);
  
  free (*tmp_tls);
  *tmp_tls = NULL;
}

/* take a pointer to a config_eap_tls and put a blank one there */
void initialize_config_eap_tls(struct config_eap_tls **tmp_tls)
{
  if (*tmp_tls != NULL) {
    delete_config_eap_tls(tmp_tls);
  }
  *tmp_tls = 
    (struct config_eap_tls *)malloc(sizeof(struct config_eap_tls));
  if (*tmp_tls)
    memset(*tmp_tls, 0, sizeof(struct config_eap_tls));
}

void dump_config_eap_tls(struct config_eap_tls *tls)
{
  if (!tls)
    return;
  debug_printf(DEBUG_NORMAL, "\t---------------eap-tls--------------\n");
  debug_printf(DEBUG_NORMAL, "\t  TLS Cert: \"%s\"\n", tls->user_cert);
  debug_printf(DEBUG_NORMAL, "\t  TLS Root Cert: \"%s\"\n", tls->root_cert);
  debug_printf(DEBUG_NORMAL, "\t  TLS Root Dir: \"%s\"\n", tls->root_dir);
  debug_printf(DEBUG_NORMAL, "\t  TLS CRL Dir: \"%s\"\n", tls->crl_dir);
  debug_printf(DEBUG_NORMAL, "\t  TLS Key: \"%s\"\n", tls->user_key);
  debug_printf(DEBUG_NORMAL, "\t  TLS Key Pass: \"%s\"\n", tls->user_key_pass);
  debug_printf(DEBUG_NORMAL, "\t  TLS Chunk Size: %d\n", tls->chunk_size);
  debug_printf(DEBUG_NORMAL, "\t  TLS Random Source: \"%s\"\n", 
	       tls->random_file);
  debug_printf(DEBUG_NORMAL, "\t  TLS Session Resumption: ");
  switch (tls->session_resume)
    {
    case RES_UNSET:
      debug_printf_nl(DEBUG_NORMAL, "UNSET\n");
      break;
    case RES_YES:
      debug_printf_nl(DEBUG_NORMAL, "YES\n");
      break;
    case RES_NO:
      debug_printf_nl(DEBUG_NORMAL, "NO\n");
      break;
    }
  debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
}


  /*******************/
 /* CONFIG_MD5      */
/*******************/
void delete_config_eap_md5(struct config_eap_md5 **tmp_md5)
{
  if (*tmp_md5 == NULL)
    return;

  FREE_STRING((*tmp_md5)->username);
  FREE_STRING((*tmp_md5)->password);

  free (*tmp_md5);
  *tmp_md5 = NULL;
}

void initialize_config_eap_md5(struct config_eap_md5 **tmp_md5)
{
  if (*tmp_md5 != NULL) {
    delete_config_eap_md5(tmp_md5);
  }
  *tmp_md5 = 
    (struct config_eap_md5 *)malloc(sizeof(struct config_eap_md5));  
  if (*tmp_md5)
    memset(*tmp_md5, 0, sizeof(struct config_eap_md5));
}

void dump_config_eap_md5(struct config_eap_md5 *md5, int level)
{
  if (!md5)
    return;
  if (level == 0) {
    debug_printf(DEBUG_NORMAL, "\t---------------eap-md5--------------\n");
    debug_printf(DEBUG_NORMAL, "\t  MD5 User: \"%s\"\n", md5->username);
    debug_printf(DEBUG_NORMAL, "\t  MD5 Pass: \"%s\"\n", md5->password);
    debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
  }else {
    debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  eap-md5  ^ ^ ^\n");
    debug_printf(DEBUG_NORMAL, "\t\t  MD5 User: \"%s\"\n", 
		 md5->username);
    debug_printf(DEBUG_NORMAL, "\t\t  MD5 Pass: \"%s\"\n", 
		 md5->password);
    debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");    
  }
  
}


  /*******************/
 /* CONFIG_TTLS     */
/*******************/

//--------
// PAP
//--------
void delete_config_pap(struct config_pap **tmp_pap)
{
  if (*tmp_pap == NULL)
    return;

  FREE_STRING((*tmp_pap)->username);
  FREE_STRING((*tmp_pap)->password);

  free (*tmp_pap);
  *tmp_pap = NULL;
}

void initialize_config_pap(struct config_pap **tmp_pap)
{
  if (*tmp_pap != NULL) {
    delete_config_pap(tmp_pap);
  }
  *tmp_pap = 
    (struct config_pap *)malloc(sizeof(struct config_pap));  
  if (*tmp_pap)
    memset(*tmp_pap, 0, sizeof(struct config_pap));
}

void dump_config_pap(struct config_pap *pap)
{
  if (!pap)
    return;
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  pap  ^ ^ ^\n");
  debug_printf(DEBUG_NORMAL, "\t\t  PAP User: \"%s\"\n", pap->username);
  debug_printf(DEBUG_NORMAL, "\t\t  PAP Pass: \"%s\"\n", pap->password);
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^\n");
}

//--------
// CHAP
//--------
void delete_config_chap(struct config_chap **tmp_chap)
{
  if (*tmp_chap == NULL)
    return;

  FREE_STRING((*tmp_chap)->username);
  FREE_STRING((*tmp_chap)->password);

  free (*tmp_chap);
  *tmp_chap = NULL;
}

void initialize_config_chap(struct config_chap **tmp_chap)
{
  if (*tmp_chap != NULL) {
    delete_config_chap(tmp_chap);
  }
  *tmp_chap = 
    (struct config_chap *)malloc(sizeof(struct config_chap));  
  if (*tmp_chap)
    memset(*tmp_chap, 0, sizeof(struct config_chap));
}

void dump_config_chap(struct config_chap *chap)
{
  if (!chap)
    return;
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  chap  ^ ^ ^\n");
  debug_printf(DEBUG_NORMAL, "\t\t  CHAP User: \"%s\"\n", chap->username);
  debug_printf(DEBUG_NORMAL, "\t\t  CHAP Pass: \"%s\"\n", chap->password);
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^\n");
}

//--------
// MSCHAP
//--------
void delete_config_mschap(struct config_mschap **tmp_mschap)
{
  if (*tmp_mschap == NULL)
    return;

  FREE_STRING((*tmp_mschap)->username);
  FREE_STRING((*tmp_mschap)->password);

  free (*tmp_mschap);
  *tmp_mschap = NULL;
}

void initialize_config_mschap(struct config_mschap **tmp_mschap)
{
  if (*tmp_mschap != NULL) {
    delete_config_mschap(tmp_mschap);
  }
  *tmp_mschap = 
    (struct config_mschap *)malloc(sizeof(struct config_mschap));  
  if (*tmp_mschap)
    memset(*tmp_mschap, 0, sizeof(struct config_mschap));
}

void dump_config_mschap(struct config_mschap *mschap)
{
  if (!mschap)
    return;
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  mschap  ^ ^ ^\n");
  debug_printf(DEBUG_NORMAL, "\t\t  MSCHAP User: \"%s\"\n", mschap->username);
  debug_printf(DEBUG_NORMAL, "\t\t  MSCHAP Pass: \"%s\"\n", mschap->password);
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^\n");
}

//--------
// MSCHAPV2
//--------
void delete_config_mschapv2(struct config_mschapv2 **tmp_mschapv2)
{
  if (*tmp_mschapv2 == NULL)
    return;

  FREE_STRING((*tmp_mschapv2)->username);
  FREE_STRING((*tmp_mschapv2)->password);

  free (*tmp_mschapv2);
  *tmp_mschapv2 = NULL;
}

void initialize_config_mschapv2(struct config_mschapv2 **tmp_mschapv2)
{
  if (*tmp_mschapv2 != NULL) {
    delete_config_mschapv2(tmp_mschapv2);
  }
  *tmp_mschapv2 = 
    (struct config_mschapv2 *)malloc(sizeof(struct config_mschapv2));  
  if (*tmp_mschapv2)
    memset(*tmp_mschapv2, 0, sizeof(struct config_mschapv2));
}

void dump_config_mschapv2(struct config_mschapv2 *mschapv2)
{
  if (!mschapv2)
    return;
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  mschapv2  ^ ^ ^\n");
  debug_printf(DEBUG_NORMAL, "\t\t  MSCHAPv2 User: \"%s\"\n", 
	       mschapv2->username);
  debug_printf(DEBUG_NORMAL, "\t\t  MSCHAPv2 Pass: \"%s\"\n", 
	       mschapv2->password);
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^\n");
}


//-------------
// TTLS_PHASE2
//------------
// Be SURE to call config_ttls_phase2_contains_phase2 BEFORE adding.
// no such check will be done here.
void add_config_ttls_phase2(struct config_ttls_phase2 **phase2,
			   ttls_phase2_type phase2_type, void *phase2_data)
{
  struct config_ttls_phase2 *tmp, *newphase2;

  if (!phase2_data)
    return;

  newphase2 = 
    (struct config_ttls_phase2 *)malloc(sizeof(struct config_ttls_phase2));
  if (newphase2 == NULL)
    return;
  memset(newphase2, 0, sizeof(struct config_ttls_phase2));
  newphase2->phase2_type = phase2_type;
  newphase2->phase2_data = phase2_data;
  
  if (*phase2 == NULL) {
    *phase2 = newphase2;
    return;
  }

  tmp = *phase2;

  while (tmp->next != NULL) {
    tmp = tmp->next;
  }
  tmp->next = newphase2;
}

int config_ttls_phase2_contains_phase2(struct config_ttls_phase2 *phase2,
				      ttls_phase2_type new_type)
{
  struct config_ttls_phase2 *tmp;

  if (!phase2)
    return 0;
  
  tmp = phase2;
  while (tmp) {
    if (tmp->phase2_type == new_type)
      return 1;
    tmp = tmp->next;
  }

  return 0;
}

void delete_config_ttls_phase2 (struct config_ttls_phase2 **phase2)
{
  if (*phase2 == NULL)
    return;
  switch ((*phase2)->phase2_type) {
  case TTLS_PHASE2_PAP:
    delete_config_pap((struct config_pap **)&(*phase2)->phase2_data);
    break;
  case TTLS_PHASE2_CHAP: 
    delete_config_chap((struct config_chap **)&(*phase2)->phase2_data);
    break;
  case TTLS_PHASE2_MSCHAP:
    delete_config_mschap((struct config_mschap **)&(*phase2)->phase2_data);
    break;
  case TTLS_PHASE2_MSCHAPV2:
    delete_config_mschapv2((struct config_mschapv2 **)&(*phase2)->phase2_data);
    break;
  default:
    debug_printf(DEBUG_NORMAL, "AAAH! Trying to delete an undefined config"
		 " type.\nNotify developers. Type: 0x%x\n", 
		 (*phase2)->phase2_type);
  }
  if ((*phase2)->next)
    delete_config_ttls_phase2(&(*phase2)->next);
}

void dump_config_ttls_phase2(struct config_ttls_phase2 *phase2) {
  if (phase2 == NULL)
    return;
  switch ((phase2)->phase2_type) {
  case TTLS_PHASE2_PAP:
    dump_config_pap((struct config_pap *)(phase2)->phase2_data);
    break;
  case TTLS_PHASE2_CHAP: 
    dump_config_chap((struct config_chap *)(phase2)->phase2_data);
    break;
  case TTLS_PHASE2_MSCHAP:
    dump_config_mschap((struct config_mschap *)(phase2)->phase2_data);
    break;
  case TTLS_PHASE2_MSCHAPV2:
    dump_config_mschapv2((struct config_mschapv2 *)(phase2)->phase2_data);
    break;
  default:
    debug_printf(DEBUG_NORMAL, "AAAH! Trying to dump an undefined config"
		 " type.\nNotify developers. Type: 0x%x\n", 
		 (phase2)->phase2_type);
  }
  if ((phase2)->next)
    dump_config_ttls_phase2((phase2)->next);
}

void delete_config_eap_ttls(struct config_eap_ttls **tmp_ttls)
{
  if (*tmp_ttls == NULL)
    return;

  FREE_STRING((*tmp_ttls)->user_cert);
  FREE_STRING((*tmp_ttls)->root_cert);
  FREE_STRING((*tmp_ttls)->root_dir);
  FREE_STRING((*tmp_ttls)->crl_dir);
  FREE_STRING((*tmp_ttls)->user_key);
  FREE_STRING((*tmp_ttls)->user_key_pass);
  FREE_STRING((*tmp_ttls)->random_file);  
  FREE_STRING((*tmp_ttls)->cncheck);
  if ((*tmp_ttls)->phase2) 
    delete_config_ttls_phase2(&(*tmp_ttls)->phase2);

  free (*tmp_ttls);
  *tmp_ttls = NULL;
}

void initialize_config_eap_ttls(struct config_eap_ttls **tmp_ttls)
{
  if (*tmp_ttls != NULL) {
    delete_config_eap_ttls(tmp_ttls);
  }
  *tmp_ttls = 
    (struct config_eap_ttls *)malloc(sizeof(struct config_eap_ttls));  
  if (*tmp_ttls == NULL)
    return;
  memset(*tmp_ttls, 0, sizeof(struct config_eap_ttls));
  (*tmp_ttls)->phase2_type = TTLS_PHASE2_UNDEFINED;
}

void dump_config_eap_ttls(struct config_eap_ttls *ttls)
{
  if (!ttls) {
    return;
  }
  debug_printf(DEBUG_NORMAL, "\t---------------eap-ttls--------------\n");
  debug_printf(DEBUG_NORMAL, "\t  TTLS Cert: \"%s\"\n", ttls->user_cert);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Root Cert: \"%s\"\n", ttls->root_cert);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Root Dir: \"%s\"\n", ttls->root_dir);
  debug_printf(DEBUG_NORMAL, "\t  TTLS CRL Dir: \"%s\"\n", ttls->crl_dir);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Key: \"%s\"\n", ttls->user_key);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Key Pass: \"%s\"\n", ttls->user_key_pass);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Chunk Size: %d\n", ttls->chunk_size);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Random Source: \"%s\"\n", 
	       ttls->random_file);
  debug_printf(DEBUG_NORMAL, "\t  TTLS CN to Check : \"%s\"\n", ttls->cncheck);
  debug_printf(DEBUG_NORMAL, "\t  TTLS Exact CN Match : %s\n",  
	       ttls->cnexact ? "yes" : "no"); 
  debug_printf(DEBUG_NORMAL, "\t  TTLS Session Resumption: ");
  switch (ttls->session_resume)
    {
    case RES_UNSET:
      debug_printf_nl(DEBUG_NORMAL, "UNSET\n");
      break;
    case RES_YES:
      debug_printf_nl(DEBUG_NORMAL, "YES\n");
      break;
    case RES_NO:
      debug_printf_nl(DEBUG_NORMAL, "NO\n");
      break;
    }
  switch (ttls->phase2_type) {
  case TTLS_PHASE2_PAP:
    debug_printf(DEBUG_NORMAL, "\t  TTLS phase2: pap\n");    
    break;
  case TTLS_PHASE2_CHAP:
    debug_printf(DEBUG_NORMAL, "\t  TTLS phase2: chap\n");    
    break;
  case TTLS_PHASE2_MSCHAP:
    debug_printf(DEBUG_NORMAL, "\t  TTLS phase2: mschap\n");    
    break;
  case TTLS_PHASE2_MSCHAPV2:
    debug_printf(DEBUG_NORMAL, "\t  TTLS phase2: mschapv2\n");        
    break;
  default:
    debug_printf(DEBUG_NORMAL, "\t  TTLS phase2: UNDEFINED\n");    
    break;
  }
  if (ttls->phase2) dump_config_ttls_phase2(ttls->phase2);
  debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
}

int check_config_eap_ttls(struct config_eap_ttls *tmp_ttls)
{
  int errno = 0;
  
  if (tmp_ttls->phase2_type == TTLS_PHASE2_UNDEFINED || !tmp_ttls->phase2) {
    debug_printf(DEBUG_NORMAL, "No phase2 defined for ttls\n");
    errno = -1;
  }
  
  if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2, 
					  tmp_ttls->phase2_type)) {
    debug_printf(DEBUG_NORMAL, "Phase2 type chosen, but not defined.\n");
    errno = -1;      
  }
  return errno;
}

  /*******************/
 /* CONFIG_LEAP     */
/*******************/
void delete_config_eap_leap(struct config_eap_leap **tmp_leap)
{
  if (*tmp_leap == NULL)
    return;

  FREE_STRING((*tmp_leap)->username);
  FREE_STRING((*tmp_leap)->password);

  free (*tmp_leap);
  *tmp_leap = NULL;
}

void initialize_config_eap_leap(struct config_eap_leap **tmp_leap)
{
  if (*tmp_leap != NULL) {
    delete_config_eap_leap(tmp_leap);
  }
  *tmp_leap = 
    (struct config_eap_leap *)malloc(sizeof(struct config_eap_leap));  
  if (*tmp_leap)
    memset(*tmp_leap, 0, sizeof(struct config_eap_leap));
}

void dump_config_eap_leap(struct config_eap_leap *leap)
{
  if (!leap)
    return;
  debug_printf(DEBUG_NORMAL, "\t---------------eap-leap--------------\n");
  debug_printf(DEBUG_NORMAL, "\t  LEAP User: \"%s\"\n", leap->username);
  debug_printf(DEBUG_NORMAL, "\t  LEAP Pass: \"%s\"\n", leap->password);
  debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
}

  /*******************/
 /* CONFIG_MSCHAPV2 */
/*******************/
void delete_config_eap_mschapv2(struct config_eap_mschapv2 **tmp_mschapv2)
{
  if (*tmp_mschapv2 == NULL)
    return;

  FREE_STRING((*tmp_mschapv2)->username);
  FREE_STRING((*tmp_mschapv2)->password);

  free (*tmp_mschapv2);
  *tmp_mschapv2 = NULL;
}

void initialize_config_eap_mschapv2(struct config_eap_mschapv2 **tmp_mschapv2)
{
  if (*tmp_mschapv2 != NULL) {
    delete_config_eap_mschapv2(tmp_mschapv2);
  }
  *tmp_mschapv2 = 
    (struct config_eap_mschapv2 *)malloc(sizeof(struct config_eap_mschapv2));  
  if (*tmp_mschapv2)
    memset(*tmp_mschapv2, 0, sizeof(struct config_eap_mschapv2));
}

void dump_config_eap_mschapv2(struct config_eap_mschapv2 *mschapv2, int level)
{
  if (!mschapv2)
    return;
  if (level == 0) {
    debug_printf(DEBUG_NORMAL, "\t---------------eap-mschapv2--------------\n");
    debug_printf(DEBUG_NORMAL, "\t  MSCHAPV2 User: \"%s\"\n", 
		 mschapv2->username);
    debug_printf(DEBUG_NORMAL, "\t  MSCHAPV2 Pass: \"%s\"\n", 
		 mschapv2->password);
    debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
  }else {
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  eap-mschapv2  ^ ^ ^\n");
    debug_printf(DEBUG_NORMAL, "\t\t  MSCHAPV2 User: \"%s\"\n", 
		 mschapv2->username);
    debug_printf(DEBUG_NORMAL, "\t\t  MSCHAPV2 Pass: \"%s\"\n", 
		 mschapv2->password);
  debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");
  }

}


  /*******************/
 /* CONFIG_PEAP     */
/*******************/
void delete_config_eap_peap(struct config_eap_peap **tmp_peap)
{
  if (*tmp_peap == NULL)
    return;

  FREE_STRING((*tmp_peap)->identity);
  FREE_STRING((*tmp_peap)->user_cert);
  FREE_STRING((*tmp_peap)->root_cert);
  FREE_STRING((*tmp_peap)->root_dir);
  FREE_STRING((*tmp_peap)->crl_dir);
  FREE_STRING((*tmp_peap)->user_key)
  FREE_STRING((*tmp_peap)->user_key_pass);
  FREE_STRING((*tmp_peap)->random_file);
  FREE_STRING((*tmp_peap)->cncheck);
  if ((*tmp_peap)->phase2)
    delete_config_eap_method(&(*tmp_peap)->phase2);

  free (*tmp_peap);
  *tmp_peap = NULL;
}

void initialize_config_eap_peap(struct config_eap_peap **tmp_peap)
{
  if (*tmp_peap != NULL) {
    delete_config_eap_peap(tmp_peap);
  }
  *tmp_peap = 
    (struct config_eap_peap *)malloc(sizeof(struct config_eap_peap));  
  if (*tmp_peap)
    memset(*tmp_peap, 0, sizeof(struct config_eap_peap));
}

void dump_config_eap_peap(struct config_eap_peap *peap)
{
  if (!peap)
    return;
  debug_printf(DEBUG_NORMAL, "\t---------------eap-peap--------------\n");
  debug_printf(DEBUG_NORMAL, "\t  PEAP phase2 identity: \"%s\"\n", 
	       peap->identity);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Cert: \"%s\"\n", peap->user_cert);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Root Cert: \"%s\"\n", peap->root_cert);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Root Dir: \"%s\"\n", peap->root_dir);
  debug_printf(DEBUG_NORMAL, "\t  PEAP CRL Dir: \"%s\"\n", peap->crl_dir);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Key: \"%s\"\n", peap->user_key);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Key Pass: \"%s\"\n", peap->user_key_pass);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Chunk Size: %d\n", peap->chunk_size);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Random Source: \"%s\"\n", 
	       peap->random_file);
  debug_printf(DEBUG_NORMAL, "\t  PEAP CN to Check : \"%s\"\n", peap->cncheck);
  debug_printf(DEBUG_NORMAL, "\t  PEAP Exact CN Match : %s\n",  
	       peap->cnexact ? "yes" : "no");  
  debug_printf(DEBUG_NORMAL, "\t  PEAP Session Resumption: ");
  switch (peap->session_resume)
    {
    case RES_UNSET:
      debug_printf_nl(DEBUG_NORMAL, "UNSET\n");
      break;
    case RES_YES:
      debug_printf_nl(DEBUG_NORMAL, "YES\n");
      break;
    case RES_NO:
      debug_printf_nl(DEBUG_NORMAL, "NO\n");
      break;
    }
  if (TEST_FLAG(peap->flags, CONFIG_PEAP_ALLOW_MSCV2))
    debug_printf(DEBUG_NORMAL,"\t   Allow Phase 2 Type: MSCHAPv2\n");
  if (TEST_FLAG(peap->flags, CONFIG_PEAP_ALLOW_MD5))
    debug_printf(DEBUG_NORMAL,"\t   Allow Phase 2 Type: MD5\n");
  if (TEST_FLAG(peap->flags, CONFIG_PEAP_ALLOW_SIM))
    debug_printf(DEBUG_NORMAL,"\t   Allow Phase 2 Type: SIM\n");
  if (TEST_FLAG(peap->flags, CONFIG_PEAP_ALLOW_GTC))
    debug_printf(DEBUG_NORMAL,"\t   Allow Phase 2 Type: GTC\n");
  if (TEST_FLAG(peap->flags, CONFIG_PEAP_ALLOW_OTP))
    debug_printf(DEBUG_NORMAL,"\t   Allow Phase 2 Type: OTP\n");
  if (peap->phase2) dump_config_eap_method(peap->phase2, 1);
  debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
}


  /*******************/
 /* CONFIG_SIM      */
/*******************/
void delete_config_eap_sim(struct config_eap_sim **tmp_sim)
{
  if (*tmp_sim == NULL)
    return;

  FREE_STRING((*tmp_sim)->username);
  FREE_STRING((*tmp_sim)->password);

  free (*tmp_sim);
  *tmp_sim = NULL;
}

void initialize_config_eap_sim(struct config_eap_sim **tmp_sim)
{
  if (*tmp_sim != NULL) {
    delete_config_eap_sim(tmp_sim);
  }
  *tmp_sim = 
    (struct config_eap_sim *)malloc(sizeof(struct config_eap_sim));  
  if (*tmp_sim)
    memset(*tmp_sim, 0, sizeof(struct config_eap_sim));
}

void dump_config_eap_sim(struct config_eap_sim *sim, int level)
{
  if (!sim)
    return;
  if (level == 0) {
    debug_printf(DEBUG_NORMAL, "\t---------------eap-sim--------------\n");
    debug_printf(DEBUG_NORMAL, "\t  SIM User: \"%s\"\n", sim->username);
    debug_printf(DEBUG_NORMAL, "\t  SIM Pass: \"%s\"\n", sim->password);
    debug_printf(DEBUG_NORMAL, "\t  SIM Auto Realm: %s\n",  
		 sim->auto_realm ? "yes" : "no");  
    debug_printf(DEBUG_NORMAL, "\t------------------------------------\n");
  } else {
    debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^  eap-sim  ^ ^ ^\n");
    debug_printf(DEBUG_NORMAL, "\t\t  SIM User: \"%s\"\n", 
		 sim->username);
    debug_printf(DEBUG_NORMAL, "\t\t  SIM Pass: \"%s\"\n", 
		 sim->password);
    debug_printf(DEBUG_NORMAL, "\t\t  SIM Auto Realm: %s\n",  
		 sim->auto_realm ? "yes" : "no");  
    debug_printf(DEBUG_NORMAL, "\t\t^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^\n");
  }
}


  /*********************/
 /* CONFIG_EAP_METHOD */
/*********************/

// Be SURE to call config_eap_method_contains_method BEFORE adding.
// no such check will be done here.
void add_config_eap_method(struct config_eap_method **method,
			   int method_num, void *method_data)
{
  struct config_eap_method *tmp, *newmethod;

  if (!method_data)
    return;

  newmethod = 
    (struct config_eap_method *)malloc(sizeof(struct config_eap_method));
  if (newmethod == NULL)
    return;
  memset(newmethod, 0, sizeof(struct config_eap_method));
  newmethod->method_num = method_num;
  newmethod->method_data = method_data;
  
  if (*method == NULL) {
    *method = newmethod;
    return;
  }

  tmp = *method;

  while (tmp->next != NULL) {
    tmp = tmp->next;
  }
  tmp->next = newmethod;
}

void delete_config_eap_method(struct config_eap_method **method)
{
  if (*method == NULL)
    return;
  switch ((*method)->method_num) {
  case EAP_TYPE_TLS:
    delete_config_eap_tls((struct config_eap_tls **)&((*method)->method_data));
    break;
  case EAP_TYPE_MD5:
    delete_config_eap_md5((struct config_eap_md5 **)&(*method)->method_data);
    break;
  case EAP_TYPE_PEAP:
    delete_config_eap_peap((struct config_eap_peap **)&(*method)->method_data);
    break;
  case EAP_TYPE_SIM:
    delete_config_eap_sim((struct config_eap_sim **)&(*method)->method_data);
    break;
  case EAP_TYPE_TTLS:
    delete_config_eap_ttls((struct config_eap_ttls **)&(*method)->method_data);
    break; 
  case EAP_TYPE_LEAP:
    delete_config_eap_leap((struct config_eap_leap **)&(*method)->method_data);
    break;
  case EAP_TYPE_MSCHAPV2:
    delete_config_eap_mschapv2((struct config_eap_mschapv2 **)&(*method)->method_data);
    break;
    
  default:
    debug_printf(DEBUG_NORMAL, "AAAH! Trying to delete an undefined config"
		 " type.\nNotify developers. Type: 0x%x\n", 
		 (*method)->method_num);
  }
  if ((*method)->next)
    delete_config_eap_method(&(*method)->next);
  
}

void dump_config_eap_method(struct config_eap_method *method, int dumplevel)
{
  if (method == NULL)
    return;
  switch ((method)->method_num) {
  case EAP_TYPE_TLS:
    dump_config_eap_tls((struct config_eap_tls *)((method)->method_data));
    break;
  case EAP_TYPE_MD5:
    dump_config_eap_md5((struct config_eap_md5 *)(method)->method_data, 
			dumplevel);
    break;
  case EAP_TYPE_PEAP:
    dump_config_eap_peap((struct config_eap_peap *)(method)->method_data);
    break;
  case EAP_TYPE_SIM:
    dump_config_eap_sim((struct config_eap_sim *)(method)->method_data,
			dumplevel);
    break;
  case EAP_TYPE_TTLS:
    dump_config_eap_ttls((struct config_eap_ttls *)(method)->method_data);
    break; 
  case EAP_TYPE_LEAP:
    dump_config_eap_leap((struct config_eap_leap *)(method)->method_data);
  case EAP_TYPE_MSCHAPV2:
    dump_config_eap_mschapv2((struct config_eap_mschapv2 *)(method)->method_data,
			     dumplevel);
    break;
    
  default:
    debug_printf(DEBUG_NORMAL, "AAAH! Trying to dump an undefined config"
		 " type\n.Notify developers. Type: 0x%x\n", 
		 (method)->method_num);
  }

  dump_config_eap_method(method->next, dumplevel);
}

int config_eap_method_contains_method(struct config_eap_method *method,
				      int new_num)
{
  struct config_eap_method *tmp;

  if (!method)
    return 0;
  
  tmp = method;
  while (tmp) {
    if (tmp->method_num == new_num)
      return 1;
    tmp = tmp->next;
  }

  return 0;
}

  /*******************/
 /* CONFIG_NETWORK  */
/*******************/
void delete_config_network(struct config_network **tmp_network)
{
  if (*tmp_network == NULL)
    return;

  FREE_STRING((*tmp_network)->name);
  FREE_STRING((*tmp_network)->ssid);
  FREE_STRING((*tmp_network)->identity);

  if ((*tmp_network)->methods)
    delete_config_eap_method(&(*tmp_network)->methods);

  if ((*tmp_network)->next)
    delete_config_network(&(*tmp_network)->next);
      
  free (*tmp_network);
  *tmp_network = NULL;
}

void initialize_config_network(struct config_network **tmp_network)
{
  if (*tmp_network != NULL) {
    delete_config_network(tmp_network);
  }
  *tmp_network = 
    (struct config_network *)malloc(sizeof(struct config_network));  
  if (*tmp_network)
    memset(*tmp_network, 0, sizeof(struct config_network));
}

int config_network_contains_net(struct config_network *net, char *netname)
{
  while (net != NULL) {
    if (strcmp(net->name, netname) == 0)
      return TRUE;
    net = net->next;
  }
  return FALSE;
}

void config_network_add_net(struct config_network **list, 
			    struct config_network *toadd)
{
  struct config_network **current = list;
  while (*current != NULL) {
    if (strcmp((*current)->name, toadd->name) == 0) {
      return;
    }
    current = &(*current)->next;
  }
  (*current) = toadd;
}

void dump_config_network(struct config_network *net)
{
  if (!net)
    return;
  debug_printf(DEBUG_NORMAL, "+-+-+-+-+  Network Name: \"%s\" +-+-+-+-+\n",
	       net->name);
  if (net->type == UNSET)
    debug_printf(DEBUG_NORMAL, "  Type: UNSET\n");
  else if (net->type == WIRED)
    debug_printf(DEBUG_NORMAL, "  Type: WIRED\n");
  else
    debug_printf(DEBUG_NORMAL, "  Type: WIRELESS\n");

  if (net->wireless_ctrl == CTL_UNSET)
    debug_printf(DEBUG_NORMAL, "  Wireless Control: UNSET\n");
  else if (net->wireless_ctrl == CTL_YES)
    debug_printf(DEBUG_NORMAL, "  Wireless Control: YES\n");
  else
    debug_printf(DEBUG_NORMAL, "  Wireless Control: NO\n");

  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_TLS))
    debug_printf(DEBUG_NORMAL, "  Allow Type: TLS\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_MD5))
    debug_printf(DEBUG_NORMAL, "  Allow Type: MD5\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_TTLS))
    debug_printf(DEBUG_NORMAL, "  Allow Type: TTLS\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_LEAP))
    debug_printf(DEBUG_NORMAL, "  Allow Type: LEAP\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_MSCV2))
    debug_printf(DEBUG_NORMAL, "  Allow Type: MSCHAPv2\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_PEAP))
    debug_printf(DEBUG_NORMAL, "  Allow Type: PEAP\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_SIM))
    debug_printf(DEBUG_NORMAL, "  Allow Type: SIM\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_GTC))
    debug_printf(DEBUG_NORMAL, "  Allow Type: GTC\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_ALLOW_OTP))
    debug_printf(DEBUG_NORMAL, "  Allow Type: OTP\n");

  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_TLS))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: TLS\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_MD5))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: MD5\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_TTLS))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: TTLS\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_LEAP))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: LEAP\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_MSCV2))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: MSCHAPv2\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_PEAP))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: PEAP\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_SIM))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: SIM\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_GTC))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: GTC\n");
  if (TEST_FLAG(net->flags, CONFIG_NET_PREFER_OTP))
    debug_printf(DEBUG_NORMAL, "  Prefer Type: OTP\n");

  debug_printf(DEBUG_NORMAL, "  SSID: \"%s\"\n", net->ssid);
  debug_printf(DEBUG_NORMAL, "  Identity: \"%s\"\n", net->identity);

  if (TEST_FLAG(net->flags, CONFIG_NET_DEST_MAC))
    debug_printf(DEBUG_NORMAL, "  DEST MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		 net->dest_mac[0], net->dest_mac[1], net->dest_mac[2],
		 net->dest_mac[3], net->dest_mac[4], net->dest_mac[5]);

  dump_config_eap_method(net->methods, 0);

  if (net->next)
    dump_config_network(net->next);
      
}


  /*****************************/
 /* CONFIG_STRING_LIST       */
/*****************************/
void delete_config_string_list(struct config_string_list **tmp_string_list)
{
  if (*tmp_string_list == NULL)
    return;

  free (*tmp_string_list);
  *tmp_string_list = NULL;
}

void initialize_config_string_list(struct config_string_list **tmp_string_list)
{
  if (*tmp_string_list != NULL) {
    delete_config_string_list(tmp_string_list);
  }
  *tmp_string_list = 
    (struct config_string_list *)malloc(sizeof(struct config_string_list));  
  if (*tmp_string_list)
    memset(*tmp_string_list, 0, sizeof(struct config_string_list));
}

int config_string_list_contains_string(struct config_string_list *net_list,
				     char *netname)
{
  // if there is a list, we need to search for the net
  while (net_list != NULL) {
    if (strcmp(net_list->name, netname) == 0)
      return TRUE;
    net_list = net_list->next;
  }
  return FALSE;
}

void config_string_list_add_string(struct config_string_list **net_list,
				 char *netname)
{
  struct config_string_list **current = net_list;

  while (*current != NULL) {
    if (strcmp((*current)->name, netname) == 0)
      return;
    current = &(*current)->next;
  }
  initialize_config_string_list(current);
  (*current)->name = netname;
}

void dump_config_string_list(struct config_string_list *stringlist, 
			     char *title)
{
  if (!stringlist) {
    return;
  }

  debug_printf(DEBUG_NORMAL, "%s: \"%s\"\n", title,  stringlist->name);
  if (stringlist->next)
    dump_config_string_list(stringlist->next, title);

}

  /*******************/
 /* CONFIG_GLOBALS  */
/*******************/
void delete_config_globals(struct config_globals **tmp_globals)
{
  if (*tmp_globals == NULL)
    return;

  if ((*tmp_globals)->default_net)
    free((*tmp_globals)->default_net);

  if ((*tmp_globals)->allowed_nets)
    delete_config_string_list(&(*tmp_globals)->allowed_nets);

  FREE_STRING((*tmp_globals)->startup_command);
  FREE_STRING((*tmp_globals)->first_auth_command);
  FREE_STRING((*tmp_globals)->reauth_command);
  FREE_STRING((*tmp_globals)->logfile);
  
  if ((*tmp_globals)->allow_interfaces)
    delete_config_string_list(&(*tmp_globals)->allow_interfaces);
  if ((*tmp_globals)->deny_interfaces)
    delete_config_string_list(&(*tmp_globals)->deny_interfaces);
  
  free (*tmp_globals);
  *tmp_globals = NULL;
}

void initialize_config_globals(struct config_globals **tmp_globals)
{
  if (*tmp_globals != NULL) {
    delete_config_globals(tmp_globals);
  }
  *tmp_globals = 
    (struct config_globals *)malloc(sizeof(struct config_globals));  
  if (*tmp_globals)
    memset(*tmp_globals, 0, sizeof(struct config_globals));
}

void dump_config_globals(struct config_globals *globals)
{
  if (!globals) {
    debug_printf(DEBUG_NORMAL, "No Globals\n");
    return;
  }
  debug_printf(DEBUG_NORMAL, "Default Net: \"%s\"\n", globals->default_net);
  if (globals->allowed_nets)
    dump_config_string_list(globals->allowed_nets, "Network Allowed");
  else 
    debug_printf(DEBUG_NORMAL, "Allowed Nets: ALL\n");

  if (globals->startup_command)
    debug_printf(DEBUG_NORMAL,
		 "Startup Command: '%s'\n", globals->startup_command);
  if (globals->first_auth_command)
    debug_printf(DEBUG_NORMAL,
		 "First Auth Command: '%s'\n", globals->first_auth_command);
  if (globals->reauth_command)
    debug_printf(DEBUG_NORMAL,
		 "Re-Auth Command: '%s'\n", globals->reauth_command);
  if (globals->logfile)
    debug_printf(DEBUG_NORMAL,
		 "Logfile: '%s'\n", globals->logfile);

  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_AUTH_PER))
    debug_printf(DEBUG_NORMAL, "Auth Period: %d\n", globals->auth_period);
  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_HELD_PER))
    debug_printf(DEBUG_NORMAL, "Held Period: %d\n", globals->held_period);
  if (TEST_FLAG(globals->flags, CONFIG_GLOBALS_MAX_STARTS))
    debug_printf(DEBUG_NORMAL,"Max Starts: %d\n", globals->max_starts);

  if (globals->allow_interfaces)
    dump_config_string_list(globals->allow_interfaces, "Interface Allowed");
  else 
    debug_printf(DEBUG_NORMAL, "Allowed Interfaces: ALL\n");

  if (globals->deny_interfaces)
    dump_config_string_list(globals->deny_interfaces, "Interface Denied");
  else 
    debug_printf(DEBUG_NORMAL, "Denied Interfaces: NONE\n");
}

  /*******************/
 /* CONFIG_DATA     */
/*******************/
void delete_config_data(struct config_data **tmp_data)
{
  if (*tmp_data == NULL)
    return;

  if ((*tmp_data)->config_fname)
    free((*tmp_data)->config_fname);
  if ((*tmp_data)->globals)
    delete_config_globals(&(*tmp_data)->globals);
  if ((*tmp_data)->networks)
    delete_config_network(&(*tmp_data)->networks);
  
  free (*tmp_data);
  *tmp_data = NULL;
}

void initialize_config_data(struct config_data **tmp_data)
{
  if (*tmp_data != NULL) {
    delete_config_data(tmp_data);
  }
  *tmp_data = 
    (struct config_data *)malloc(sizeof(struct config_data));  
  if (*tmp_data)
    memset(*tmp_data, 0, sizeof(struct config_data));
}

void dump_config_data(struct config_data *data)
{
  if (!data)
    return;
  debug_printf(DEBUG_NORMAL, "=-=-=-=-=-=-=-=-=-=-=-=-=\n");
  debug_printf(DEBUG_NORMAL, "Configuration File: %s\n", data->config_fname);
  dump_config_globals(data->globals);
  dump_config_network(data->networks);
  debug_printf(DEBUG_NORMAL, "=-=-=-=-=-=-=-=-=-=-=-=-=\n");
}
