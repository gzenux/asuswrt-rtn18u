%{
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
 * Grammar for configuration file
 * 
 * File: config_grammar.y
 *
 * Authors: bdpayne@cs.umd.edu, npetroni@cs.umd.edu
 *
 * $Id: config_grammar.y,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: config_grammar.y,v $
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
 * Revision 1.25  2004/03/26 03:52:47  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.24  2004/03/24 18:35:46  chessing
 *
 * Added a modified version of a patch from David Relson to fix a problem with some of the debug info in config_grammer.y.  Added some additional checks to eapol_key_type1 that will keep us from segfaulting under some *REALLY* strange conditions.  Changed the set key code in cardif_linux to double check that we aren't a wireless interface before returning an error.  This resolved a problem when XSupplicant was started when an interface was done.  Upon bringing up the interface, XSupplicant would sometimes think it wasn't wireless, and not bother trying to set keys.
 *
 * Revision 1.23  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.22  2004/03/15 16:23:24  chessing
 *
 * Added some checks to TLS using EAP types to make sure the root certificate isn't set to NULL.  (If it is, we can't authenticate, so we bail out.)  Changed the user certificate settings in the config file to all start with user_.  So, "cert" is now "user_cert", "key" is now "user_key", and "key_pass" is now "user_key_pass".  The structures and other related variables were also updated to reflect this change.  THIS WILL PROBABLY BREAK CONFIG FILES FOR SOME USERS!  (Be prepared for complaints on the list!)  ;)
 *
 * Revision 1.21  2004/03/06 03:53:54  chessing
 *
 * We now send logoffs when the process is terminated.  Added a new option to the config file "wireless_control" which will allow a user to disable non-EAPoL key changes.  Added an update to destination BSSID checking that will reset the wireless key to all 0s when the BSSID changes.  (This is what "wireless_control" disables when it is set to no.)  Roaming should now work, but because we are resetting keys to 128 bit, there may be issues with APs that use 64 bit keys.  I will test this weekend.
 *
 * Revision 1.20  2004/03/05 23:58:45  chessing
 *
 * Added CN (sometimes called server name) checking to TTLS and PEAP.  This resulted in two new config options in the eap-ttls, and eap-peap blocks.  cncheck should be the name (or partial name) to match in the CN.  cnexact should be yes/no depending on if we want to match the CN exactly, or just see if our substring is in the CN.
 *
 * Revision 1.19  2004/02/16 14:23:49  npetroni
 * updated config code to allow empty method fields in the config file. The format
 * is
 *
 * eap_method {
 *
 * }
 *
 * the semantics are to create a structure of that type and put it in the list for that network, but not to initialize any of the values (they remain NULL, 0, or whatever malloc gives us).
 *
 * Revision 1.18  2004/02/10 03:40:22  npetroni
 * updated config to include a phase 2 identity for PEAP
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
 * Revision 1.15  2003/12/31 07:03:48  npetroni
 * made a number of changes to the config code to generalize handling of EAP
 * methods and phase2. I still need to go back and make the parser work for
 * other phase2 type in PEAP, but the backend is there.
 *
 * Revision 1.14  2003/12/19 23:19:11  npetroni
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
 * Revision 1.13  2003/12/10 14:13:16  npetroni
 * updated configuration code to parse all types. example updated as well
 *
 * Revision 1.12  2003/11/29 01:11:30  npetroni
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
 *
 *******************************************************************/  
  
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
  
#include "config.h"
#include "xsup_err.h"
#include "xsup_debug.h"

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

#define CLEAN_EXIT cleanup_parse(); return XECONFIGPARSEFAIL

int yylex(void);  
int yyerror(char *err);
extern struct config_data *config_info;

extern int config_parse_debug;

struct config_data *tmp_config = NULL;

struct config_eap_tls *tmp_tls = NULL;
struct config_eap_md5 *tmp_md5 = NULL;
struct config_eap_ttls *tmp_ttls = NULL;
struct config_eap_leap *tmp_leap = NULL;
struct config_eap_mschapv2 *tmp_mschapv2 = NULL;
struct config_eap_peap *tmp_peap = NULL; 
struct config_eap_sim *tmp_sim = NULL;

struct config_pap *tmp_p2pap =NULL;
struct config_chap *tmp_p2chap = NULL;
struct config_mschap *tmp_p2mschap = NULL;
struct config_mschapv2 *tmp_p2mschapv2 = NULL;

struct config_network *tmp_network = NULL;



void set_current_tls() {
  if (tmp_tls == NULL) 
    initialize_config_eap_tls(&tmp_tls);
} 
void set_current_md5() {
  if (tmp_md5 == NULL) 
    initialize_config_eap_md5(&tmp_md5);
} 
void set_current_ttls() {
  if (tmp_ttls == NULL) 
    initialize_config_eap_ttls(&tmp_ttls);
} 
void set_current_leap() {
  if (tmp_leap == NULL) 
    initialize_config_eap_leap(&tmp_leap);
} 
void set_current_mschapv2() {
  if (tmp_mschapv2 == NULL) 
    initialize_config_eap_mschapv2(&tmp_mschapv2);
} 
void set_current_peap() {
  if (tmp_peap == NULL) 
    initialize_config_eap_peap(&tmp_peap);
} 
void set_current_sim() {
  if (tmp_sim == NULL) 
    initialize_config_eap_sim(&tmp_sim);
} 

void set_current_p2pap() {
  if (tmp_p2pap == NULL)
    initialize_config_pap(&tmp_p2pap);
}
void set_current_p2chap() {
  if (tmp_p2chap == NULL)
    initialize_config_chap(&tmp_p2chap);
}
void set_current_p2mschap() {
  if (tmp_p2mschap == NULL)
    initialize_config_mschap(&tmp_p2mschap);
}
void set_current_p2mschapv2() {
  if (tmp_p2mschapv2 == NULL)
    initialize_config_mschapv2(&tmp_p2mschapv2);
}

void set_current_config() {
  if (tmp_config == NULL) 
    initialize_config_data(&tmp_config);
} 

void set_current_globals() {
  set_current_config();
  if (!tmp_config->globals)
    initialize_config_globals(&(tmp_config->globals));
}   

void set_current_network() {
  if (tmp_network == NULL) 
    initialize_config_network(&tmp_network);
} 


void cleanup_parse()
{
  if (tmp_config)
    delete_config_data(&tmp_config);
  if (tmp_tls)
    delete_config_eap_tls(&tmp_tls);
  if (tmp_md5)
    delete_config_eap_md5(&tmp_md5);
  if (tmp_ttls)
    delete_config_eap_ttls(&tmp_ttls);
  if (tmp_leap)
    delete_config_eap_leap(&tmp_leap);
  if (tmp_mschapv2)
    delete_config_eap_mschapv2(&tmp_mschapv2);
  if (tmp_peap)
    delete_config_eap_peap(&tmp_peap);
  if (tmp_sim)
    delete_config_eap_sim(&tmp_sim);
  if (tmp_p2pap)
    delete_config_pap(&tmp_p2pap);
  if (tmp_p2chap)
    delete_config_chap(&tmp_p2chap);
  if (tmp_p2mschap)
    delete_config_mschap(&tmp_p2mschap);
  if (tmp_p2mschapv2)
    delete_config_mschapv2(&tmp_p2mschapv2);
  if (tmp_network)
    delete_config_network(&tmp_network);
}



/* function to check if debug is on and if so print the message */
void parameter_debug(char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (!config_parse_debug) return;

  vprintf(fmt, ap);
  va_end(ap);
}

%}

%union {
        char    *str;
        int     num;
}


%token        TK_NETWORK_LIST
%token        TK_DEFAULT_NETNAME
%token<str>   TK_NETNAME
%token        TK_STARTUP_COMMAND
%token        TK_FIRST_AUTH_COMMAND
%token        TK_REAUTH_COMMAND
%token        TK_LOGFILE
%token        TK_AUTH_PERIOD
%token        TK_HELD_PERIOD
%token        TK_MAX_STARTS
%token        TK_ALLOW_INTERFACES
%token        TK_DENY_INTERFACES
%token        TK_ALL
%token        TK_TYPE
%token        TK_ALLOW_TYPES
%token        TK_WIRELESS
%token        TK_WIRED
%token        TK_CONTROL_WIRELESS
%token        TK_IDENTITY
%token<str>   TK_IDENTITY_VAL
%token        TK_DEST_MAC
%token<str>   TK_MACADDRESS
%token        TK_SSID
%token<str>   TK_SSID_VAL
%token        TK_EAP_TLS
%token        TK_USER_CERT
%token        TK_USER_KEY
%token        TK_USER_KEY_PASS
%token        TK_SESSION_RESUME
%token        TK_CNCHECK
%token        TK_CNEXACT
%token        TK_ROOT_CERT
%token        TK_ROOT_DIR
%token        TK_CRL_DIR
%token        TK_CHUNK_SIZE
%token        TK_RANDOM_FILE
%token        TK_EAP_MD5
%token        TK_USERNAME
%token<str>   TK_USERNAME_VAL
%token        TK_PASSWORD
%token        TK_EAP_LEAP
%token        TK_EAP_TTLS
%token        TK_PHASE2_TYPE
%token        TK_PAP
%token        TK_CHAP
%token        TK_MSCHAP
%token        TK_MSCHAPV2
%token        TK_EAP_MSCHAPV2
%token        TK_EAP_PEAP
%token        TK_EAP_SIM
%token        TK_AUTO_REALM
%token        TK_YES
%token        TK_NO
%token        TK_EAP_GTC
%token        TK_EAP_OTP


%token<num>   TK_NUMBER
%token<str>   TK_FNAME
%token<str>   TK_PASS
%token<str>   TK_COMMAND



%%

configfile        : global_section network_section {
		     config_info = tmp_config; 
		     tmp_config = NULL;
                  }
                  | global_section { 
                      debug_printf(DEBUG_NORMAL, "Error: No networks defined.\n"); 
		      CLEAN_EXIT;
		    }
                  | network_section {
		      debug_printf(DEBUG_NORMAL, "Error: No globals defined.\n"); 
		      cleanup_parse();
		      return XECONFIGPARSEFAIL;
                    }
                  | error {
 		      cleanup_parse();
		      return XECONFIGPARSEFAIL; }
                  ;

global_section    : global_section global_statement
                  | global_statement
                  ;

network_section   : network_section  network_entry
                  | network_entry
                  ;

global_statement  : TK_NETWORK_LIST '=' TK_ALL {
                      set_current_globals();
                      parameter_debug("network_list: all\n");
		      // do nothing. leave null
                    } 
                  | TK_NETWORK_LIST '=' network_list {
		    // done below. nothing to do here
  		    }
                  | TK_DEFAULT_NETNAME '=' TK_NETNAME {
 		     set_current_globals();
		     parameter_debug("Default network: \"%s\"\n", $3);
		     if (tmp_config->globals->default_net)
		       free($3);
		     else
		       tmp_config->globals->default_net = $3;
		  }
                  | TK_STARTUP_COMMAND '=' TK_COMMAND {
 		     set_current_globals();
		     parameter_debug("Startup command: \"%s\"\n", $3);
		     if (tmp_config->globals->startup_command)
		       free($3);
		     else
		       tmp_config->globals->startup_command = $3;
		    }
                  | TK_FIRST_AUTH_COMMAND '=' TK_COMMAND {
 		     set_current_globals();
		     parameter_debug("First_Auth command: \"%s\"\n", $3);
		     if (tmp_config->globals->first_auth_command)
		       free($3);
		     else
		       tmp_config->globals->first_auth_command = $3;
		    }
                  | TK_REAUTH_COMMAND '=' TK_COMMAND {
 		     set_current_globals();
		     parameter_debug("Reauth command: \"%s\"\n", $3);
		     if (tmp_config->globals->reauth_command)
		       free($3);
		     else
		       tmp_config->globals->reauth_command = $3;
		    }
                  | TK_LOGFILE '=' TK_NETNAME {
		     set_current_globals();
		     parameter_debug("Logfile: \"%s\"\n", $3);
		     if (tmp_config->globals->logfile)
		       {
			 free($3);
			 tmp_config->globals->logfile = NULL;
		       }
		     else
		       tmp_config->globals->logfile = $3;
		    }
                  | TK_AUTH_PERIOD '=' TK_NUMBER {
		     set_current_globals();
		     if (!TEST_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_AUTH_PER)) {
		       SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_AUTH_PER);
		       tmp_config->globals->auth_period = $3;
		     }
                    }
                  | TK_HELD_PERIOD '=' TK_NUMBER {
		     set_current_globals();
		     if (!TEST_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_HELD_PER)) {
		       SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_HELD_PER);
		       tmp_config->globals->held_period = $3;
		     }
                    }
                  | TK_MAX_STARTS '=' TK_NUMBER {
		     set_current_globals();
		     if (!TEST_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_MAX_STARTS)) {
		       SET_FLAG(tmp_config->globals->flags, CONFIG_GLOBALS_MAX_STARTS);
		       tmp_config->globals->max_starts = $3;
		     }
                    }
                  | TK_ALLOW_INTERFACES '=' allow_interface_list {
                     // nothing to do here
                    }
                  | TK_DENY_INTERFACES '=' deny_interface_list {
                     // nothing to do here
                    }
                  ;

network_list      : network_list ',' TK_NETNAME {
                       parameter_debug("network_list: \"%s\"\n", $3);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allowed_nets,
							    $3))
			 free($3);
		       else 
			 config_string_list_add_string(&tmp_config->globals->allowed_nets,
						     $3);
                    }
                  | TK_NETNAME { 
                       parameter_debug("network_list: \"%s\"\n", $1);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allowed_nets,
							    $1))
			 free($1);
		       else 
			 config_string_list_add_string(&tmp_config->globals->allowed_nets,
						     $1);
                    }
                  ;

allow_interface_list      : allow_interface_list ',' TK_NETNAME {
                       parameter_debug("allow_interface_list: \"%s\"\n", $3);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allow_interfaces,
							      $3))
			 free($3);
		       else if (config_string_list_contains_string(tmp_config->globals->deny_interfaces,
								   $3)) {
			 debug_printf(DEBUG_NORMAL,
				      "Interface \"%s\" both allowed and denied\n", $3);
			 CLEAN_EXIT;
		       }
		       else 
			 config_string_list_add_string(&tmp_config->globals->allow_interfaces,
						     $3);
                    }
                  | TK_NETNAME { 
                       parameter_debug("allow_interface_list: \"%s\"\n", $1);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->allow_interfaces,
							    $1))
			 free($1);
		       else if (config_string_list_contains_string(tmp_config->globals->deny_interfaces,
								   $1)) {
			 debug_printf(DEBUG_NORMAL,
				      "Interface \"%s\" both allowed and denied\n", $1);
			 CLEAN_EXIT;
		       }
		       else 
			 config_string_list_add_string(&tmp_config->globals->allow_interfaces,
						     $1);
                    }
                  ;

deny_interface_list      : deny_interface_list ',' TK_NETNAME {
                       parameter_debug("deny_interface_list: \"%s\"\n", $3);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->deny_interfaces,
							      $3))
			 free($3);
		       else if (config_string_list_contains_string(tmp_config->globals->allow_interfaces,
								   $3)) {
			 debug_printf(DEBUG_NORMAL,
				      "Interface \"%s\" both allowed and denied\n", $3);
			 CLEAN_EXIT;
		       }
		       else 
			 config_string_list_add_string(&tmp_config->globals->deny_interfaces,
						     $3);
                    }
                  | TK_NETNAME { 
                       parameter_debug("deny_interface_list: \"%s\"\n", $1);
		       set_current_globals();
		       if (config_string_list_contains_string(tmp_config->globals->deny_interfaces,
							    $1))
			 free($1);
		       else if (config_string_list_contains_string(tmp_config->globals->allow_interfaces,
								   $1)) {
			 debug_printf(DEBUG_NORMAL,
				      "Interface \"%s\" both allowed and denied\n", $1);
			 CLEAN_EXIT;
		       }
		       else 
			 config_string_list_add_string(&tmp_config->globals->deny_interfaces,
						     $1);
                    }
                  ;

network_entry     : TK_NETNAME '{' network_statements '}' {
                      set_current_config();
		      tmp_network->name = $1;
		      // check if there is a networks field and that 
		      // the current tmp is not already listed
		      if ((!tmp_config->networks ||
			  !config_network_contains_net(tmp_config->networks,
						       tmp_network->name)) &&
			  config_allows_network(tmp_config, tmp_network->name))
		      {
			config_network_add_net(&(tmp_config->networks),
					       tmp_network);
		      }
		      // if we don't need it, delete it
		      else {
			delete_config_network(&tmp_network);
		      }
		      tmp_network = NULL;
                    }
                  ;

network_statements : network_statements network_parameter
                   | network_statements eap_type_statement
                   | network_parameter
                   | eap_type_statement
                   ;


network_parameter  : network_type_parameter
                   | network_identity_parameter
                   | network_dest_mac_parameter
                   | network_ssid_parameter
                   | network_allow_parameter
                   | network_control_wireless
                   ;

network_type_parameter : TK_TYPE '=' TK_WIRELESS {
                           parameter_debug("Type: Wireless\n");
			   set_current_network();
			   if (tmp_network->type == UNSET)
			     tmp_network->type = WIRELESS;
                         }
                         | TK_TYPE '=' TK_WIRED {
                           parameter_debug("Type: Wired\n");
			   set_current_network();
			   if (tmp_network->type == UNSET)
			     tmp_network->type = WIRED;
                         }
                       ;

network_control_wireless : TK_CONTROL_WIRELESS '=' TK_YES {
                           parameter_debug("Control Wireless = YES\n");
			   set_current_network();
			   if (tmp_network->wireless_ctrl == CTL_UNSET)
			     tmp_network->wireless_ctrl = CTL_YES;
                         }
                         | TK_CONTROL_WIRELESS '=' TK_NO {
			   parameter_debug("Control Wireless = NO\n");
			   set_current_network();
			   if (tmp_network->wireless_ctrl == CTL_UNSET)
			     tmp_network->wireless_ctrl = CTL_NO;
			 }
                       ;

network_identity_parameter : TK_IDENTITY '=' TK_IDENTITY_VAL {
                            parameter_debug("ID: \"%s\"\n", $3);
			    set_current_network();
			    if (!tmp_network->identity)
			      tmp_network->identity = $3;
			    else
			      free($3);
                          }
                           ;

network_ssid_parameter : TK_SSID '=' TK_SSID_VAL {
                            parameter_debug("SSID: \"%s\"\n", $3);
			    set_current_network();
			    if (!tmp_network->ssid)
			      tmp_network->ssid = $3;
			    else
			      free($3);
                         }
                       ;

network_dest_mac_parameter: TK_DEST_MAC '=' TK_MACADDRESS {
                            parameter_debug("Dest Mac: %s\n", $3);
			    set_current_network();
			    if (TEST_FLAG(tmp_network->flags, CONFIG_NET_DEST_MAC)) {
			      free($3);
			    }
			    else {
			      int tmp_dst_mac[CONFIG_MAC_LEN];
			      SET_FLAG(tmp_network->flags, CONFIG_NET_DEST_MAC);
			      sscanf($3, "%2x:%2x:%2x:%2x:%2x:%2x", 
				     &tmp_dst_mac[0], 
				     &tmp_dst_mac[1], 
				     &tmp_dst_mac[2], 
				     &tmp_dst_mac[3], 
				     &tmp_dst_mac[4], 
				     &tmp_dst_mac[5]);
			      tmp_network->dest_mac[0] = tmp_dst_mac[0];
			      tmp_network->dest_mac[1] = tmp_dst_mac[1];
			      tmp_network->dest_mac[2] = tmp_dst_mac[2];
			      tmp_network->dest_mac[3] = tmp_dst_mac[3];
			      tmp_network->dest_mac[4] = tmp_dst_mac[4];
			      tmp_network->dest_mac[5] = tmp_dst_mac[5];
			    }
                         }
                       ;

network_allow_parameter: TK_ALLOW_TYPES '=' TK_ALL {
                           parameter_debug("Allow Types: ALL\n");
			   set_current_network();
			   SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_ALL);
                       }
                       | TK_ALLOW_TYPES '=' eap_type_list
                       ;

eap_type_statement  : eap_tls_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_TLS)) {
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_TLS,
					       tmp_tls);
		       }
		       else 
			 delete_config_eap_tls(&tmp_tls);
		       tmp_tls = NULL;
                      }
                    | eap_md5_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_MD5))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_MD5,
					       tmp_md5);
		       else 
			 delete_config_eap_md5(&tmp_md5);
		       tmp_md5 = NULL;
                      }
                    | eap_ttls_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_TTLS))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_TTLS,
					       tmp_ttls);
		       else 
			 delete_config_eap_ttls(&tmp_ttls);
		       tmp_ttls = NULL;
                      }
                    | eap_leap_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_LEAP))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_LEAP,
					       tmp_leap);
		       else 
			 delete_config_eap_leap(&tmp_leap);
		       tmp_leap = NULL;
                      }
                    | eap_mschapv2_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_MSCHAPV2))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_MSCHAPV2,
					       tmp_mschapv2);
		       else 
			 delete_config_eap_mschapv2(&tmp_mschapv2);
		       tmp_mschapv2 = NULL;
                      }
                    | eap_peap_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_PEAP))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_PEAP,
					       tmp_peap);
		       else 
			 delete_config_eap_peap(&tmp_peap);
		       tmp_peap = NULL;
                      }
                    | eap_sim_statement {
                       set_current_network(); 
		       if (!config_eap_method_contains_method(tmp_network->methods,
							      EAP_TYPE_SIM))
			 add_config_eap_method(&(tmp_network->methods),
					       EAP_TYPE_SIM,
					       tmp_sim);
		       else 
			 delete_config_eap_sim(&tmp_sim);
		       tmp_sim = NULL;
                      }
                    ;

eap_type_list       : eap_type_list ',' eap_type 
                    | eap_type
                    ;

eap_type            : TK_EAP_TLS {
                        parameter_debug("Allow Type: TLS\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_TLS);
                      }
                    | TK_EAP_MD5 {
                        parameter_debug("Allow Type: MD5\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_MD5);
                      }
                    | TK_EAP_TTLS {
                        parameter_debug("Allow Type: TTLS\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_TTLS);
                      }
                    | TK_EAP_LEAP {
                        parameter_debug("Allow Type: LEAP\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_LEAP);
                      }
                    | TK_EAP_MSCHAPV2 {
                        parameter_debug("Allow Type: MSCHAPV2\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_MSCV2);
                      }
                    | TK_EAP_PEAP {
                        parameter_debug("Allow Type: PEAP\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_PEAP);
                      }
                    | TK_EAP_SIM {
                        parameter_debug("Allow Type: SIM\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_SIM);
                      }
                    | TK_EAP_GTC {
                        parameter_debug("Allow Type: GTC\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_GTC);
                      }
                    | TK_EAP_OTP {
                        parameter_debug("Allow Type: OTP\n");
			set_current_network();
			SET_FLAG(tmp_network->flags, CONFIG_NET_ALLOW_OTP);
                      }
                    ;

eap_tls_statement   : TK_EAP_TLS '{' eap_tls_params '}'  
                    | TK_EAP_TLS '{' '}' {
                        set_current_tls(); /* define an empty tls struct*/
                      }
                    ;

eap_tls_params      : eap_tls_params eap_tls_param
                    | eap_tls_param
                    ;

eap_tls_param       :  TK_USER_CERT '=' TK_FNAME {
                        parameter_debug("tls user cert: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_cert)
			  tmp_tls->user_cert = $3;
			else
			  free($3);
                      }
                    |  TK_USER_KEY '=' TK_FNAME {
	 	        parameter_debug("tls user key: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key)
			  tmp_tls->user_key = $3;
			else 
			  free($3);
        	      }
                    |  TK_USER_KEY_PASS '=' TK_PASS {
	 	        parameter_debug("tls user pass: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->user_key_pass)
			  tmp_tls->user_key_pass = $3;
			else
			  free($3);
        	      }
                    |  TK_SESSION_RESUME '=' TK_YES {
		        parameter_debug("Session Resumption = YES\n");
		        set_current_tls();
		        if (tmp_tls->session_resume == RES_UNSET)
			  tmp_tls->session_resume = RES_YES;
		      }
                    | TK_SESSION_RESUME '=' TK_NO {
			parameter_debug("Session Resumption = NO\n");
			set_current_tls();
			if (tmp_tls->session_resume == RES_UNSET)
			  tmp_tls->session_resume = RES_NO;
		      }
                    |  TK_ROOT_CERT  '=' TK_FNAME {
	 	        parameter_debug("tls root_cert: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->root_cert)
			  tmp_tls->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_DIR  '=' TK_FNAME {
	 	        parameter_debug("tls root_dir: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->root_dir)
			  tmp_tls->root_dir = $3;
			else
			  free($3);
        	      }
                    |  TK_CRL_DIR  '=' TK_FNAME {
	 	        parameter_debug("tls crl_dir: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->crl_dir)
			  tmp_tls->crl_dir = $3;
			else
			  free($3);
        	      }
                    |  TK_CHUNK_SIZE '=' TK_NUMBER {
 		        parameter_debug("tls chunk: %d\n", $3);
			set_current_tls();
			if (tmp_tls->chunk_size == 0)
			  tmp_tls->chunk_size = $3;
  		      }
                    |  TK_RANDOM_FILE '=' TK_FNAME {
	 	        parameter_debug("tls rand: \"%s\"\n", $3);
			set_current_tls();
			if (!tmp_tls->random_file)
			  tmp_tls->random_file = $3;
			else 
			  free($3);
        	      }
                    ;

eap_md5_statement   : TK_EAP_MD5 '{' eap_md5_params'}' 
                    | TK_EAP_MD5 '{' '}' {
                        set_current_md5(); /* define an empty md5 struct*/
                      }
                    ;

eap_md5_params     : eap_md5_params eap_md5_param
                   | eap_md5_param
                   ;

eap_md5_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("md5 username: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->username)
			 tmp_md5->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("md5 password: \"%s\"\n", $3);
		       set_current_md5();
		       if (!tmp_md5->password)
			 tmp_md5->password = $3;
		       else
			 free($3);
		     }
                   ;

eap_ttls_statement   : TK_EAP_TTLS '{' eap_ttls_params '}' 
                    | TK_EAP_TTLS '{' '}' {
                        set_current_ttls(); /* define an empty ttls struct*/
                      }
                    ;

eap_ttls_params      : eap_ttls_params eap_ttls_param
                    | eap_ttls_param
                    ;

eap_ttls_param       : TK_USER_CERT '=' TK_FNAME {
                        parameter_debug("ttls user cert: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_cert)
			  tmp_ttls->user_cert = $3;
			else
			  free($3);
                      }
                    |  TK_USER_KEY '=' TK_FNAME {
	 	        parameter_debug("ttls user key: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key)
			  tmp_ttls->user_key = $3;
			else 
			  free($3);
        	      }
                    |  TK_USER_KEY_PASS '=' TK_PASS {
	 	        parameter_debug("ttls user pass: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->user_key_pass)
			  tmp_ttls->user_key_pass = $3;
			else
			  free($3);
        	      }
                    |TK_ROOT_CERT  '=' TK_FNAME {
	 	        parameter_debug("ttls root_cert: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->root_cert)
			  tmp_ttls->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_DIR '=' TK_FNAME {
	 	        parameter_debug("ttls root_dir: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->root_dir)
			  tmp_ttls->root_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_CRL_DIR '=' TK_FNAME {
	 	        parameter_debug("ttls crl_dir: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->crl_dir)
			  tmp_ttls->crl_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_CHUNK_SIZE '=' TK_NUMBER {
 		        parameter_debug("ttls chunk: %d\n", $3);
			set_current_ttls();
			if (tmp_ttls->chunk_size == 0)
			  tmp_ttls->chunk_size = $3;
  		      }
                    |  TK_RANDOM_FILE '=' TK_FNAME {
	 	        parameter_debug("ttls rand: \"%s\"\n", $3);
			set_current_ttls();
			if (!tmp_ttls->random_file)
			  tmp_ttls->random_file = $3;
			else 
			  free($3);
        	      }
                    |  TK_SESSION_RESUME '=' TK_YES {
		        parameter_debug("Session Resumption = YES\n");
		        set_current_ttls();
		        if (tmp_ttls->session_resume == RES_UNSET)
			  tmp_ttls->session_resume = RES_YES;
		      }
                    | TK_SESSION_RESUME '=' TK_NO {
			parameter_debug("Session Resumption = NO\n");
			set_current_ttls();
			if (tmp_ttls->session_resume == RES_UNSET)
			  tmp_ttls->session_resume = RES_NO;
		      }
                    |  TK_CNCHECK '=' TK_FNAME {
		        parameter_debug("ttls CN check : \"%s\"\n", $3);
                        set_current_ttls();
                        if (!tmp_ttls->cncheck)
                          tmp_ttls->cncheck = $3;
                        else
                          free($3);
		      }
                    | TK_CNEXACT '=' TK_YES {
  		        parameter_debug("match CN exactly : \"yes\"\n");
		        set_current_ttls();
		        tmp_ttls->cnexact = 1;
		    }
                    | TK_CNEXACT '=' TK_NO {
  		        parameter_debug("match CN exactly : \"no\"\n");
		        set_current_ttls();
		        tmp_ttls->cnexact = 0;
		    }
                    |  TK_PHASE2_TYPE '=' TK_PAP {
	 	        parameter_debug("ttls phase2_type 'pap'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_PAP;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_CHAP {
	 	        parameter_debug("ttls phase2_type 'chap'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_CHAP;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_MSCHAP {
	 	        parameter_debug("ttls phase2_type 'mschap'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_MSCHAP;
        	      }
                    |  TK_PHASE2_TYPE '=' TK_MSCHAPV2 {
	 	        parameter_debug("ttls phase2_type 'mschapv2'\n");
			if (tmp_ttls && 
			    tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
			  cleanup_parse();
			  return XECONFIGPARSEFAIL;  
			}
			set_current_ttls();
			tmp_ttls->phase2_type = TTLS_PHASE2_MSCHAPV2;
        	      }
				   |  TK_PHASE2_TYPE '=' TK_EAP_MD5 {
                        parameter_debug("ttls phase2_type 'eap_md5'\n");
                        if (tmp_ttls &&
                            tmp_ttls->phase2_type != TTLS_PHASE2_UNDEFINED) {
                          cleanup_parse();
                          return XECONFIGPARSEFAIL;
                        }
                        set_current_ttls();
                        tmp_ttls->phase2_type = TTLS_PHASE2_EAP_MD5;
                     }
                    | eap_ttls_phase2_statement
                    ;

eap_ttls_phase2_statement  : phase2_pap_statement
                           | phase2_chap_statement
                           | phase2_mschap_statement
                           | phase2_mschapv2_statement
							| eap_ttls_phase2_eap_statement
                           ;

phase2_pap_statement   : TK_PAP '{' phase2_pap_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_PAP))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_PAP,
						tmp_p2pap);
		       else
			 delete_config_pap(&tmp_p2pap);
		       tmp_p2pap = NULL;
                      }
                    ;

phase2_pap_params     : phase2_pap_params phase2_pap_param
                   | phase2_pap_param
                   ;

phase2_pap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("pap username: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->username)
			 tmp_p2pap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("pap password: \"%s\"\n", $3);
		       set_current_p2pap();
		       if (!tmp_p2pap->password)
			 tmp_p2pap->password = $3;
		       else
			 free($3);
		     }
                   ;

phase2_chap_statement   : TK_CHAP '{' phase2_chap_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_CHAP))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_CHAP,
						tmp_p2chap);
		       else
			 delete_config_chap(&tmp_p2chap);
		       tmp_p2chap = NULL;
                      }
                    ;

phase2_chap_params     : phase2_chap_params phase2_chap_param
                   | phase2_chap_param
                   ;

phase2_chap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("chap username: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->username)
			 tmp_p2chap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("chap password: \"%s\"\n", $3);
		       set_current_p2chap();
		       if (!tmp_p2chap->password)
			 tmp_p2chap->password = $3;
		       else
			 free($3);
		     }
                   ;

phase2_mschap_statement   : TK_MSCHAP '{' phase2_mschap_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_MSCHAP))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_MSCHAP,
						tmp_p2mschap);
		       else
			 delete_config_mschap(&tmp_p2mschap);
		       tmp_p2mschap = NULL;
                      }
                    ;

phase2_mschap_params     : phase2_mschap_params phase2_mschap_param
                   | phase2_mschap_param
                   ;

phase2_mschap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("mschap username: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->username)
			 tmp_p2mschap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("mschap password: \"%s\"\n", $3);
		       set_current_p2mschap();
		       if (!tmp_p2mschap->password)
			 tmp_p2mschap->password = $3;
		       else
			 free($3);
		     }
                   ;


phase2_mschapv2_statement   : TK_MSCHAPV2 '{' phase2_mschapv2_params'}' {
                       set_current_ttls(); 
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
							       TTLS_PHASE2_MSCHAPV2))
			 add_config_ttls_phase2(&(tmp_ttls->phase2), 
						TTLS_PHASE2_MSCHAPV2,
						tmp_p2mschapv2);
		       else
			 delete_config_mschapv2(&tmp_p2mschapv2);
		       tmp_p2mschapv2 = NULL;
                      }
                    ;

phase2_mschapv2_params     : phase2_mschapv2_params phase2_mschapv2_param
                   | phase2_mschapv2_param
                   ;

phase2_mschapv2_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->username)
			 tmp_p2mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_p2mschapv2();
		       if (!tmp_p2mschapv2->password)
			 tmp_p2mschapv2->password = $3;
		       else
			 free($3);
		     }
                   ;
eap_ttls_phase2_eap_statement : eap_md5_statement {
		       set_current_ttls();
		       if (!config_ttls_phase2_contains_phase2(tmp_ttls->phase2,
                                                                 TTLS_PHASE2_EAP_MD5))
		         add_config_ttls_phase2(&(tmp_ttls->phase2),
			  	  	        TTLS_PHASE2_EAP_MD5,
					        tmp_md5);
		       else
		         delete_config_eap_md5(&tmp_md5);
		       tmp_p2mschapv2 = NULL;
                     }
                   ;

eap_leap_statement   : TK_EAP_LEAP '{' eap_leap_params'}' 
                    | TK_EAP_LEAP '{' '}' {
                        set_current_leap(); /* define an empty leap struct*/
                      }
                    ;

eap_leap_params     : eap_leap_params eap_leap_param
                   | eap_leap_param
                   ;

eap_leap_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("leap username: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->username)
			 tmp_leap->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("leap password: \"%s\"\n", $3);
		       set_current_leap();
		       if (!tmp_leap->password)
			 tmp_leap->password = $3;
		       else
			 free($3);
		     }
                   ;

eap_mschapv2_statement   : TK_EAP_MSCHAPV2 '{' eap_mschapv2_params'}'
                    | TK_EAP_MSCHAPV2 '{' '}' {
                        set_current_mschapv2(); /* define an empty mschapv2 struct*/
                      }
                         ;

eap_mschapv2_params     : eap_mschapv2_params eap_mschapv2_param
                   | eap_mschapv2_param
                   ;

eap_mschapv2_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("mschapv2 username: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->username)
			 tmp_mschapv2->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("mschapv2 password: \"%s\"\n", $3);
		       set_current_mschapv2();
		       if (!tmp_mschapv2->password)
			 tmp_mschapv2->password = $3;
		       else
			 free($3);
		     }
                   ;

eap_peap_statement   : TK_EAP_PEAP '{' eap_peap_params '}'
                    | TK_EAP_PEAP '{' '}' {
                        set_current_peap(); /* define an empty peap struct*/
                      }
                    ;

eap_peap_params      : eap_peap_params eap_peap_param
                    | eap_peap_param
                    ;

eap_peap_param       : TK_IDENTITY '=' TK_IDENTITY_VAL {
                            parameter_debug("ID: \"%s\"\n", $3);
			    set_current_peap();
			    if (!tmp_peap->identity)
			      tmp_peap->identity = $3;
			    else
			      free($3);
                          }
                    |   TK_USER_CERT '=' TK_FNAME {
                        parameter_debug("peap user cert: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_cert)
			  tmp_peap->user_cert = $3;
			else
			  free($3);
                      }
                    |  TK_USER_KEY '=' TK_FNAME {
	 	        parameter_debug("peap user key: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key)
			  tmp_peap->user_key = $3;
			else 
			  free($3);
        	      }
                    |  TK_USER_KEY_PASS '=' TK_PASS {
	 	        parameter_debug("peap user pass: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->user_key_pass)
			  tmp_peap->user_key_pass = $3;
			else
			  free($3);
        	      }
                    |TK_ROOT_CERT  '=' TK_FNAME {
	 	        parameter_debug("peap root_cert: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->root_cert)
			  tmp_peap->root_cert = $3;
			else
			  free($3);
        	      }
                    |  TK_ROOT_DIR '=' TK_FNAME {
	 	        parameter_debug("peap root_dir: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->root_dir)
			  tmp_peap->root_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_CRL_DIR '=' TK_FNAME {
	 	        parameter_debug("peap crl_dir: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->crl_dir)
			  tmp_peap->crl_dir = $3;
			else 
			  free($3);
        	      }
                    |  TK_SESSION_RESUME '=' TK_YES {
		        parameter_debug("Session Resumption = YES\n");
		        set_current_peap();
		        if (tmp_peap->session_resume == RES_UNSET)
			  tmp_peap->session_resume = RES_YES;
		      }
                    | TK_SESSION_RESUME '=' TK_NO {
			parameter_debug("Session Resumption = NO\n");
			set_current_peap();
			if (tmp_peap->session_resume == RES_UNSET)
			  tmp_peap->session_resume = RES_NO;
		      }
                    |  TK_CHUNK_SIZE '=' TK_NUMBER {
 		        parameter_debug("peap chunk: %d\n", $3);
			set_current_peap();
			if (tmp_peap->chunk_size == 0)
			  tmp_peap->chunk_size = $3;
  		      }
                    |  TK_CNCHECK '=' TK_FNAME {
		        parameter_debug("peap CN check : \"%s\"\n", $3);
                        set_current_peap();
                        if (!tmp_peap->cncheck)
                          tmp_peap->cncheck = $3;
                        else
                          free($3);
		      }
                    | TK_CNEXACT '=' TK_YES {
  		        parameter_debug("match CN exactly : \"yes\"\n");
		        set_current_peap();
		        tmp_peap->cnexact = 1;
		    }
                    | TK_CNEXACT '=' TK_NO {
  		        parameter_debug("match CN exactly : \"no\"\n");
		        set_current_peap();
		        tmp_peap->cnexact = 0;
       		    }
                    |  TK_RANDOM_FILE '=' TK_FNAME {
	 	        parameter_debug("peap rand: \"%s\"\n", $3);
			set_current_peap();
			if (!tmp_peap->random_file)
			  tmp_peap->random_file = $3;
			else 
			  free($3);
        	      }
                    | eap_peap_allow_parameter {}
                    | eap_peap_phase2_statement {}
                    ;

eap_peap_allow_parameter: TK_ALLOW_TYPES '=' TK_ALL {
                           parameter_debug("PEAP Allow Types: ALL\n");
			   set_current_peap();
			   SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_ALL);
                       }
                       | TK_ALLOW_TYPES '=' eap_peap_phase2_type_list
                       ;

eap_peap_phase2_type_list  : eap_peap_phase2_type_list ',' eap_peap_phase2_type 
                           | eap_peap_phase2_type
                           ;

eap_peap_phase2_type  : TK_EAP_MSCHAPV2 {
                          parameter_debug("PEAP Allow Type: MSCHAPV2\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_MSCV2);
                        }
                      | TK_EAP_MD5 {
                          parameter_debug("PEAP Allow Type: MD5\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_MD5);
                        }
                      | TK_EAP_SIM {
                          parameter_debug("PEAP Allow Type: SIM\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_SIM);
                        }
                      | TK_EAP_OTP {
                          parameter_debug("PEAP Allow Type: OTP\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_OTP);
                        }
                      | TK_EAP_GTC {
                          parameter_debug("PEAP Allow Type: GTC\n");
	  	  	  set_current_peap();
			  SET_FLAG(tmp_peap->flags, CONFIG_PEAP_ALLOW_GTC);
                        }
                       ;


eap_peap_phase2_statement : eap_mschapv2_statement {
                             set_current_peap(); 
	   	             if (!config_eap_method_contains_method(tmp_peap->phase2,
								    EAP_TYPE_MSCHAPV2))
			       add_config_eap_method(&(tmp_peap->phase2),
						     EAP_TYPE_MSCHAPV2,
						     tmp_mschapv2);
			     else
			       delete_config_eap_mschapv2(&tmp_mschapv2);
			     tmp_mschapv2 = NULL;
                            }
                          | eap_md5_statement {
                             set_current_peap(); 
	   	             if (!config_eap_method_contains_method(tmp_peap->phase2,
								    EAP_TYPE_MD5))
			       add_config_eap_method(&(tmp_peap->phase2),
						     EAP_TYPE_MD5,
						     tmp_md5);
			     else
			       delete_config_eap_md5(&tmp_md5);
			     tmp_md5 = NULL;
                            }
                          | eap_sim_statement {
                             set_current_peap(); 
	   	             if (!config_eap_method_contains_method(tmp_peap->phase2,
								    EAP_TYPE_SIM))
			       add_config_eap_method(&(tmp_peap->phase2),
						     EAP_TYPE_SIM,
						     tmp_sim);
			     else
			       delete_config_eap_sim(&tmp_sim);
			     tmp_sim = NULL;
                            }
                          ;

eap_sim_statement   : TK_EAP_SIM '{' eap_sim_params'}' 
                    | TK_EAP_SIM '{' '}' {
                        set_current_sim(); /* define an empty sim struct*/
                      }
                    ;

eap_sim_params     : eap_sim_params eap_sim_param
                   | eap_sim_param
                   ;

eap_sim_param      : TK_USERNAME '=' TK_USERNAME_VAL {
                       parameter_debug("sim username: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->username)
			 tmp_sim->username = $3;
		       else
			 free($3);
                     }
                   | TK_PASSWORD '=' TK_PASS {
		       parameter_debug("sim password: \"%s\"\n", $3);
		       set_current_sim();
		       if (!tmp_sim->password)
			 tmp_sim->password = $3;
		       else
			 free($3);
		     }
                   | TK_AUTO_REALM '=' TK_YES {
  		       parameter_debug("sim auto_realm: \"yes\"\n");
		       set_current_sim();
		       tmp_sim->auto_realm = 1;
		   }
                   | TK_AUTO_REALM '=' TK_NO {
  		       parameter_debug("sim auto_realm: \"no\"\n");
		       set_current_sim();
		       tmp_sim->auto_realm = 0;
		   }
                   ;
%%
