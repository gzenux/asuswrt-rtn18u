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
 * Tokens for configuration file
 * 
 * File: config_lexicon.l
 *
 * Authors: bdpayne@cs.umd.edu, npetroni@cs.umd.edu
 *
 * $Id: config_lexicon.l,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: config_lexicon.l,v $
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
 * Revision 1.11  2004/03/26 03:52:47  chessing
 *
 * Fixed a bug in xsup_debug that would cause config-parse to crash.  Added new key word for session resumption.  Added code to attempt session resumption.  So far, testing has not succeeded, but it is attempting resume. (Four TTLS packets are exchanged, and then we get a failure.)  More testing is needed.
 *
 * Revision 1.10  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.9  2004/03/15 16:23:24  chessing
 *
 * Added some checks to TLS using EAP types to make sure the root certificate isn't set to NULL.  (If it is, we can't authenticate, so we bail out.)  Changed the user certificate settings in the config file to all start with user_.  So, "cert" is now "user_cert", "key" is now "user_key", and "key_pass" is now "user_key_pass".  The structures and other related variables were also updated to reflect this change.  THIS WILL PROBABLY BREAK CONFIG FILES FOR SOME USERS!  (Be prepared for complaints on the list!)  ;)
 *
 * Revision 1.8  2004/03/06 03:53:54  chessing
 *
 * We now send logoffs when the process is terminated.  Added a new option to the config file "wireless_control" which will allow a user to disable non-EAPoL key changes.  Added an update to destination BSSID checking that will reset the wireless key to all 0s when the BSSID changes.  (This is what "wireless_control" disables when it is set to no.)  Roaming should now work, but because we are resetting keys to 128 bit, there may be issues with APs that use 64 bit keys.  I will test this weekend.
 *
 * Revision 1.7  2004/03/05 23:58:45  chessing
 *
 * Added CN (sometimes called server name) checking to TTLS and PEAP.  This resulted in two new config options in the eap-ttls, and eap-peap blocks.  cncheck should be the name (or partial name) to match in the CN.  cnexact should be yes/no depending on if we want to match the CN exactly, or just see if our substring is in the CN.
 *
 * Revision 1.6  2004/02/10 03:03:35  npetroni
 * fixed "-" in file names. can now use them
 *
 * Revision 1.5  2004/01/06 22:25:58  npetroni
 * added crl parameter to tls, ttls, and peap and user cert,key,key_pass to ttls,peap
 *
 * Revision 1.4  2003/12/31 16:16:35  npetroni
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
 * Revision 1.3  2003/12/19 23:19:11  npetroni
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
 * Revision 1.2  2003/12/10 14:13:16  npetroni
 * updated configuration code to parse all types. example updated as well
 *
 * Revision 1.1  2003/11/29 01:11:30  npetroni
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_grammar.h"
#include "config.h"
#include "xsup_debug.h"
#include "xsup_err.h"

int config_linenum = 1;
extern struct config_data config_info;
%}

HEXDIGIT    [0-9a-fA-F]

%x fname
%%
"network_list"      {return TK_NETWORK_LIST; }
"default_netname"   {return TK_DEFAULT_NETNAME; }
"all"               {return TK_ALL; }
"startup_command"   {return TK_STARTUP_COMMAND; }
"first_auth_command" {return TK_FIRST_AUTH_COMMAND; }
"reauth_command"    {return TK_REAUTH_COMMAND; }
"logfile"           {return TK_LOGFILE; }
"auth_period"       {return TK_AUTH_PERIOD; }
"held_period"       {return TK_HELD_PERIOD; }
"max_starts"        {return TK_MAX_STARTS; }
"allow_interfaces"  {return TK_ALLOW_INTERFACES; }
"deny_interfaces"   {return TK_DENY_INTERFACES; }

"type"              { return TK_TYPE; }
"allow_types"       { return TK_ALLOW_TYPES; }
"wireless"          { return TK_WIRELESS; }
"wired"             { return TK_WIRED; }
"identity"          { return TK_IDENTITY; }
"dest_mac"          { return TK_DEST_MAC; }
"ssid"              { return TK_SSID; }
"wireless_control"  { return TK_CONTROL_WIRELESS; }

"eap_tls"           { return TK_EAP_TLS; }
"eap-tls"           { return TK_EAP_TLS; }
"user_cert"          { BEGIN(fname); return TK_USER_CERT; }
"user_key"           { BEGIN(fname); return TK_USER_KEY; }
"user_key_pass"      { return TK_USER_KEY_PASS; }
"root_cert"          { BEGIN(fname); return TK_ROOT_CERT; }
"root_dir"          { BEGIN(fname); return TK_ROOT_DIR; }
"crl_dir"          { BEGIN(fname); return TK_CRL_DIR; }
"session_resume"   { return TK_SESSION_RESUME; }
"chunk_size"    { return TK_CHUNK_SIZE; }
"random_file"   { BEGIN(fname); return TK_RANDOM_FILE; }
"cncheck"       { BEGIN(fname); return TK_CNCHECK; }
"cnexact"       { return TK_CNEXACT; }


"eap_md5"           { return TK_EAP_MD5; }
"eap-md5"           { return TK_EAP_MD5; }
"username"          { return TK_USERNAME; }
"password"          { return TK_PASSWORD; }

"eap-ttls"          { return TK_EAP_TTLS; }
"eap_ttls"          { return TK_EAP_TTLS; }
"phase2_type"       { return TK_PHASE2_TYPE; }
"pap"               { return TK_PAP;  }
"chap"              { return TK_CHAP;  }
"mschap"            { return TK_MSCHAP;  }
"mschapv2"          { return TK_MSCHAPV2;  }

"eap-leap"          { return TK_EAP_LEAP; }
"eap_leap"          { return TK_EAP_LEAP; }

"eap-mschapv2"      { return TK_EAP_MSCHAPV2; }
"eap_mschapv2"      { return TK_EAP_MSCHAPV2; }

"eap-peap"          { return TK_EAP_PEAP; }
"eap_peap"          { return TK_EAP_PEAP; }

"eap-sim"           { return TK_EAP_SIM; }
"eap_sim"           { return TK_EAP_SIM; }
"auto_realm"        { return TK_AUTO_REALM; }
"yes"               { return TK_YES; }
"no"                { return TK_NO; }

"eap-gtc"           { return TK_EAP_GTC; }
"eap_gtc"           { return TK_EAP_GTC; }

"eap-otp"           { return TK_EAP_OTP; }
"eap_otp"           { return TK_EAP_OTP; }



<INITIAL,fname>"="  { return yytext[0];     }
"{"             { return yytext[0];     }
"}"             { return yytext[0];     }
","             { return yytext[0];     }


[0123456789]+   {
                    yylval.num = atoi(yytext);
                    return TK_NUMBER;
                }


[[:alnum:]\-\_\\/\.]+  {
                     yylval.str = strdup(yytext);
                     return TK_NETNAME;
                   }

{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2}":"{HEXDIGIT}{2} {
                     yylval.str = strdup(yytext);
                     return TK_MACADDRESS;
                   }

<fname>[[:alnum:]/_\-\\\.]+ {
                     yylval.str = strdup(yytext);
                     BEGIN(0);
                     return TK_FNAME;
                   }

"#".*          /* skip comments */  

<INITIAL,fname>[ \t]+          /* de nada  */

\n              { config_linenum++;             }


"<BEGIN_ID>".+"<END_ID>"  { int len = strlen(yytext)-10-8;
                            yylval.str = 
                             (char *)malloc(sizeof(char) * (len+1));
                            strncpy(yylval.str, yytext+10,len);
                            yylval.str[len] = '\0';
                            return TK_IDENTITY_VAL;}

"<BEGIN_SSID>".+"<END_SSID>"  { int len = strlen(yytext)-12-10;
                            yylval.str = 
                             (char *)malloc(sizeof(char) * (len+1));
                            strncpy(yylval.str, yytext+12,len);
                            yylval.str[len] = '\0';
                            return TK_SSID_VAL;}

"<BEGIN_PASS>".+"<END_PASS>"  { int len = strlen(yytext)-12-10;
                            yylval.str = 
                             (char *)malloc(sizeof(char) * (len+1));
                            strncpy(yylval.str, yytext+12,len);
                            yylval.str[len] = '\0';
                            return TK_PASS;}

"<BEGIN_UNAME>".+"<END_UNAME>"  { int len = strlen(yytext)-13-11;
                            yylval.str = 
                             (char *)malloc(sizeof(char) * (len+1));
                            strncpy(yylval.str, yytext+13,len);
                            yylval.str[len] = '\0';
                            return TK_USERNAME_VAL;}

"<BEGIN_COMMAND>".+"<END_COMMAND>"  { int len = strlen(yytext)-15-13;
                            yylval.str = 
                             (char *)malloc(sizeof(char) * (len+1));
                            strncpy(yylval.str, yytext+15,len);
                            yylval.str[len] = '\0';
                            return TK_COMMAND;}

%%

int
yywrap(void)
{
	return 1;
}

int
yyerror(char *e)
{
	debug_printf(DEBUG_NORMAL, 
		     "Error %s, %d: Unkown token '%s'\n",
		     config_info.config_fname,
		     config_linenum, yylval.str);
	return XECONFIGPARSEFAIL;
}
