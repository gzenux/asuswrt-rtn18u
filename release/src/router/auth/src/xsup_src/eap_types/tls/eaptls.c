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
 * EAPTLS (RFC 2716) Function implementations
 * 
 * File: eaptls.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eaptls.c,v 1.1.1.1 2007/08/06 10:04:43 root Exp $
 * $Date: 2007/08/06 10:04:43 $
 * $Log: eaptls.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:43  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:31  ysc
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
 * Revision 1.25  2004/04/14 21:09:32  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.24  2004/04/13 22:13:30  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.23  2004/03/28 20:37:10  chessing
 *
 * PEAP session resumption now works.
 *
 * Revision 1.22  2004/03/28 06:07:17  chessing
 * Added failure call to EAP methods to enable context resets for TLS based authentication protocols.  The resets are needed if an authentiction attempt fails, and we have session resumption enabled.  However, resetting it when we aren't using session resumption won't hurt anything, and probably isn't a bad idea.  The new failure handler can also be used to destroy passwords after a failed attempt, which will then cause xsupplicant to request another password from any listening GUIs. TLS session resumption is enabled (and works) for TLS and TTLS.  PEAP loops forever, and needs to be reviewed.
 *
 * Revision 1.21  2004/03/26 03:52:52  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.20  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.19  2004/03/19 23:43:57  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.18  2004/03/17 21:21:41  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.17  2004/03/15 16:23:24  chessing
 *
 * Added some checks to TLS using EAP types to make sure the root certificate isn't set to NULL.  (If it is, we can't authenticate, so we bail out.)  Changed the user certificate settings in the config file to all start with user_.  So, "cert" is now "user_cert", "key" is now "user_key", and "key_pass" is now "user_key_pass".  The structures and other related variables were also updated to reflect this change.  THIS WILL PROBABLY BREAK CONFIG FILES FOR SOME USERS!  (Be prepared for complaints on the list!)  ;)
 *
 * Revision 1.16  2004/03/05 23:58:45  chessing
 *
 * Added CN (sometimes called server name) checking to TTLS and PEAP.  This resulted in two new config options in the eap-ttls, and eap-peap blocks.  cncheck should be the name (or partial name) to match in the CN.  cnexact should be yes/no depending on if we want to match the CN exactly, or just see if our substring is in the CN.
 *
 * Revision 1.15  2004/03/02 01:03:53  chessing
 *
 * Added Jari Ahonen's SSL verification callback.  Added support to PEAP and TTLS to turn off certificate validation checking by setting the root_cert variable in the config to NONE.  (Case sensative!)  We will also display a warning when running in this mode.  Added initial hooks to support certificate CN checking.
 *
 * Revision 1.14  2004/02/16 05:06:01  chessing
 *
 * Added support for the deny_interfaces, and allow_interfaces options in the config file.  (We should now have support for *EVERYTHING* in the new config file format!)  Updated EAP types other than SIM to use the new password prompt/delay code.  Phase 2 of TTLS still needs to be completed, along with the code that actually notifies the GUI.
 *
 * Revision 1.13  2004/02/06 06:13:32  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.12  2004/01/20 05:57:06  chessing
 *
 * All EAP types except PEAP and TTLS now support having their passwords sent in via the command line program.  (This means no more gets() call in OTP!)  A config_eap_otp structure was created in config.h to support GTC/OTP.  We need to define an eap_otp and eap_gtc config section.  Since both require some kind of information be presented there are no attributes that need to be defined in their part of the configuration.
 *
 * Revision 1.11  2004/01/18 06:31:19  chessing
 *
 * A few fixes here and there.  Added support in EAP-TLS to wait for a password to be entered from a "GUI" interface.  Added a small CLI utility to pass the password in to the daemon. (In gui_tools/cli)  Made needed IPC updates/changes to support passing in of a generic password to be used.
 *
 * Revision 1.10  2004/01/15 23:45:12  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.9  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.8  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.7  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.6  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.5  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.4  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 * Revision 1.3  2003/11/22 06:10:39  chessing
 *
 * Changes to the eap type process calls, to remove a pointless parameter.
 *
 * Revision 1.2  2003/11/21 05:09:47  chessing
 *
 * PEAP now works!
 *
 * Revision 1.1.1.1  2003/11/19 04:13:25  chessing
 * New source tree
 *
 *
 *******************************************************************/

#include <string.h>
#include "profile.h"
#include "config.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "frame_structs.h"
#include "eap_types/tls/eaptls.h"
#include "eap_types/tls/tls_funcs.h"
#include "eap.h"
#include "interactive.h"

int eaptls_setup(struct generic_eap_data *thisint)
{
  struct tls_vars *mytls_vars;
  int retVal;
  struct config_eap_tls *userdata;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to eaptls_setup()!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_tls *)thisint->eap_conf_data;

  retVal = XENONE;

  // First, set up the structure to hold all of our instance specific
  // variables.
  thisint->eap_data = (char *)malloc(sizeof(struct tls_vars));
  if (!thisint->eap_data) return XEMALLOC;

  mytls_vars = (struct tls_vars *)thisint->eap_data;

  // Set our variables to NULL.
  mytls_vars->ctx = NULL;
  mytls_vars->ssl = NULL;
  mytls_vars->ssl_in = NULL;
  mytls_vars->ssl_out = NULL;
  mytls_vars->tlsoutdata = NULL;
  mytls_vars->tlsoutsize = 0;
  mytls_vars->tlsoutptr = 0;
  mytls_vars->cncheck = NULL;    // NO
  mytls_vars->cnexact = 0;
  mytls_vars->phase = 0;         // This has no meaning for TLS.
  mytls_vars->resume = userdata->session_resume;
  mytls_vars->resuming = 0;
  mytls_vars->quickResponse = FALSE;
  mytls_vars->cert_loaded = FALSE;
  mytls_vars->verify_mode = SSL_VERIFY_PEER;  // We don't want the option of
                                              // not checking certs here!  It
                                              // would be a *SERIOUSLY* bad
                                              // idea!

  mytls_vars->sessionkeyconst = (char *)malloc(TLS_SESSION_KEY_CONST_SIZE);
  if (mytls_vars->sessionkeyconst == NULL) return XEMALLOC;

  strncpy(mytls_vars->sessionkeyconst, TLS_SESSION_KEY_CONST,
	  TLS_SESSION_KEY_CONST_SIZE);

  mytls_vars->sessionkeylen = TLS_SESSION_KEY_CONST_SIZE;

  debug_printf(DEBUG_EVERYTHING, "(EAP-TLS) Initialized.\n");
  
  if ((retVal = tls_funcs_init(thisint))!=XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Error initializing TLS functions!\n");
      return retVal;
    }
 
  if ((retVal = tls_funcs_load_root_certs(thisint, userdata->root_cert,
					  userdata->root_dir, userdata->crl_dir))!=XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Error loading root certificate!\n");
      return retVal;
    }

//  if (userdata->user_key_pass != NULL)
    {
      if ((retVal = tls_funcs_load_user_cert(thisint, userdata->user_cert, 
					     userdata->user_key,
					     userdata->user_key_pass,
					     userdata->random_file))!=XENONE)
	{
	  debug_printf(DEBUG_NORMAL, "Error loading user certificate!\n");
	  return retVal;
	} else {

	  // Otherwise, the certificate is loaded.
	  mytls_vars->cert_loaded = TRUE;

	  // We really don't need to free tempPwd here, since TLS won't have
	  // a second phase.  But, we do it anyway, just to keep things
	  // consistant.
	  if (thisint->tempPwd != NULL)
	    {
	      free(thisint->tempPwd);
	      thisint->tempPwd = NULL;
	    }
	}
    }

  if (tls_funcs_load_random(thisint, userdata->random_file) != XENONE)
    {
      debug_printf(DEBUG_NORMAL, "Failed to load random data\n");
      return -1;
    }

  return XENONE;
}

int eaptls_process(struct generic_eap_data *thisint, u_char *dataoffs, 
		   int insize, u_char *outframe, int *outsize)
{
  struct config_eap_tls *userdata;
  struct tls_vars *mytls_vars;
  int retVal;

  if ((!thisint) || (!thisint->eap_conf_data) || (!outframe) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to eaptls_process()!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_tls *)thisint->eap_conf_data;
  mytls_vars = (struct tls_vars *)thisint->eap_data;

  // The state machine wants to know if we have anything else to say.
  // We may be waiting for the server to send us more information, or
  // we may need to send a request to the GUI for a password, and wait
  // for an answer.
  
  if (mytls_vars->cert_loaded == FALSE)
    {
      if ((userdata->user_key_pass == NULL) && (thisint->tempPwd != NULL))
	{
	  userdata->user_key_pass = thisint->tempPwd;
	  thisint->tempPwd = NULL;
	}

      if ((mytls_vars->cert_loaded == FALSE))
      {       
	// Load the user certificate.
	if ((retVal = tls_funcs_load_user_cert(thisint, userdata->user_cert, 
					       userdata->user_key,
					       userdata->user_key_pass,
					       userdata->random_file))!=XENONE)
	  {
	    debug_printf(DEBUG_NORMAL, "Error loading user certificate!\n");
	    return retVal;
	  } else {

	    // Otherwise, the certificate is loaded.
	    mytls_vars->cert_loaded = TRUE;
	  }
      }  
    }

  // Make sure we have something to process...
  if (dataoffs == NULL) return XENONE;
  
  retVal=tls_funcs_decode_packet(thisint, dataoffs, insize, outframe, outsize, 
				 NULL, userdata->chunk_size);

  return retVal;
}

int eaptls_get_keys(struct interface_data *thisint)
{
  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed to eaptls_get_keys()!\n");
      return -1;
    }

  if (thisint->keyingMaterial != NULL)
    {
      free(thisint->keyingMaterial);
    }

  thisint->keyingMaterial = tls_funcs_gen_keyblock(thisint->userdata->activemethod);
  
  if (thisint->keyingMaterial == NULL) return -1;
  return 0;
}

int eaptls_cleanup(struct generic_eap_data *thisint)
{
  struct tls_vars *mytls_vars;

  if ((!thisint) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to eaptls_cleanup()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;
  tls_funcs_cleanup(thisint);

  if (mytls_vars->sessionkeyconst) free(mytls_vars->sessionkeyconst);

  if (mytls_vars) free(mytls_vars);

  debug_printf(DEBUG_EVERYTHING, "(EAP-TLS) Cleaned up.\n");
  return XENONE;
}

int eaptls_failed(struct generic_eap_data *thisint)
{
  struct tls_vars *mytls_vars;

  if ((!thisint) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to eaptls_failed()!\n");
      return XEMALLOC;
    }

  mytls_vars = (struct tls_vars *)thisint->eap_data;
  tls_funcs_failed(thisint);

  debug_printf(DEBUG_EVERYTHING, "(EAP-TLS) Failed. Resetting.\n");
  return XENONE;
}
