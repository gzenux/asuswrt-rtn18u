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
 * File: eapotp.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eapotp.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eapotp.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
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
 * Revision 1.9  2004/04/06 20:31:26  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.8  2004/03/19 23:43:57  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.7  2004/02/16 05:06:00  chessing
 *
 * Added support for the deny_interfaces, and allow_interfaces options in the config file.  (We should now have support for *EVERYTHING* in the new config file format!)  Updated EAP types other than SIM to use the new password prompt/delay code.  Phase 2 of TTLS still needs to be completed, along with the code that actually notifies the GUI.
 *
 * Revision 1.6  2004/01/20 05:57:05  chessing
 *
 * All EAP types except PEAP and TTLS now support having their passwords sent in via the command line program.  (This means no more gets() call in OTP!)  A config_eap_otp structure was created in config.h to support GTC/OTP.  We need to define an eap_otp and eap_gtc config section.  Since both require some kind of information be presented there are no attributes that need to be defined in their part of the configuration.
 *
 * Revision 1.5  2004/01/15 23:45:11  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.4  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.3  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.2  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.1  2003/12/28 07:13:21  chessing
 *
 * Fixed a problem where we would segfault on an EAP type we didn't understand.  Added EAP-OTP.  EAP-OTP has been tested using the opie package, and Radiator 3.8.  EAP-OTP currently prompts for a passphrase, which it shouldn't do, so it should be considered *VERY* much in test mode until we finish the GUI.
 *
 *
 *******************************************************************/

#include <openssl/ssl.h>
#include <string.h>
#include <strings.h>

#include "config.h"
#include "profile.h"
#include "eap.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "frame_structs.h"
#include "eapotp.h"
#include "interactive.h"


/*****************************************************
 *
 * Setup to handle OTP EAP requests
 *
 *****************************************************/
int eapotp_setup(struct generic_eap_data *thisint)
{
  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed to eapotp_setup()!\n");
      return XEMALLOC;
    }

  thisint->eap_data = (int *)malloc(sizeof(int));
  if (thisint->eap_data == NULL) return XEMALLOC;

  // Do anything special that might be needed for this EAP type to work.
  debug_printf(DEBUG_EVERYTHING, "Initalized EAP-OTP!\n");

  return XENONE;
}


/*****************************************************
 *
 * Process OTP EAP Requests
 *
 *
 ******************************************************/
int eapotp_process(struct generic_eap_data *thisint, u_char *dataoffs, 
		   int insize, u_char *outframe, int *outsize)
{
  char *otp_chal;
  char resp[512];
  struct config_eap_otp *userdata;

  debug_printf(DEBUG_EVERYTHING, "(EAP-OTP) Processing.\n");

  if ((!thisint) || (!dataoffs) || (!outframe))
    {
      debug_printf(DEBUG_NORMAL, "Invalid paramaters passed to eapotp_process()!\n");
      return XEMALLOC;
    }

  if (!outsize)
    {
      debug_printf(DEBUG_NORMAL, "Invalid pointer to out size in eapotp_process()!\n");
      return XEMALLOC;
    }
  
  debug_printf(DEBUG_AUTHTYPES, "OTP/GTC packet dump : \n");
  debug_hex_printf(DEBUG_AUTHTYPES, dataoffs, insize);

  *outsize = 0;

  userdata = thisint->eap_conf_data;

  if (!userdata)
    {
      debug_printf(DEBUG_NORMAL, "Invalid configuration data in eapotp_process()!\n");
      return XENOUSERDATA;
    }

  if (thisint->tempPwd == NULL) 
    {
      otp_chal = (char *)malloc(insize+1);
      if (otp_chal == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't allocate memory for OTP/GTC challenge!\n");
	  *outsize = 0;
	  return 0;
	}

      bzero(otp_chal, insize+1);

      memcpy(otp_chal, dataoffs, insize);
      debug_printf(DEBUG_NORMAL, "Challenge : %s\n",otp_chal);

      // We need a password.
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-OTP/GTC");
      thisint->eapchallenge = otp_chal;

      *outsize = 0;
      return XENONE;
    }

  // Make sure we have something to process...
  if (dataoffs == NULL) return XENONE;


  /*  debug_printf(DEBUG_NORMAL, "Response : ");
      gets(&resp); */

  strcpy(outframe, resp);
  *outsize = strlen(resp);

  return *outsize;
}

/*******************************************************
 *
 * Return any keying material that we may have.
 *
 *******************************************************/
int eapotp_get_keys(struct interface_data *thisint)
{
  return -1;   // No keys to return;
}

/*******************************************************
 *
 * Clean up after ourselves.  This will get called when we get a packet that
 * needs to be processed requests a different EAP type.  It will also be 
 * called on termination of the program.
 *
 *******************************************************/
int eapotp_cleanup(struct generic_eap_data *thisint)
{
  // Clean up after ourselves.
  debug_printf(DEBUG_AUTHTYPES, "(EAP-OTP) Cleaning up.\n");
  return XENONE;
}

