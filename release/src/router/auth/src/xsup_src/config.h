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
 *******************************************************************/

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "profile.h"

#define SET_FLAG(var,flag)    (var |= flag)
#define UNSET_FLAG(var,flag)  (var &= !flag)
#define TEST_FLAG(var,flag)   (var & flag)

// if you change this, update the printing and parsing functions
// accordingly
#define CONFIG_MAC_LEN 6

typedef enum {RES_UNSET, RES_YES, RES_NO} sess_res;

/*** DEVELOPER CHECKLIST ****/
/* When adding a value to one of these structs you must
    1. update initialize_config_<struct>
    2. update delete_config_<struct>
    3. update dump_config_<struct> if it exists
    4. modify the grammar to account for the new fields (config_grammar.y)
    5. modify the lexicon for the new tokens (config_lexicon.l)
*/
struct config_eap_tls 
{
  char * user_cert;
  char *root_cert;
  char *root_dir;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  sess_res session_resume;
  int chunk_size;
  char * random_file;

};

struct config_eap_md5
{
  char *username;
  char *password;
};

typedef enum {TTLS_PHASE2_UNDEFINED,
	TTLS_PHASE2_PAP,
	TTLS_PHASE2_CHAP,
	TTLS_PHASE2_MSCHAP,
	TTLS_PHASE2_MSCHAPV2
//#ifdef RTL_TTLS_MD5_CLIENT
	,TTLS_PHASE2_EAP_MD5
//#endif
} ttls_phase2_type;

struct config_ttls_phase2  
{ 
  ttls_phase2_type phase2_type;
  void *phase2_data;
  struct config_ttls_phase2 *next;
};

struct config_pap
{
  char *username;
  char *password;
};

struct config_chap
{
  char *username;
  char *password;
};

struct config_mschap
{
  char *username;
  char *password;
};

struct config_mschapv2
{
  char *username;
  char *password;
};

struct config_eap_otp
{
  char *password;
};

struct config_eap_ttls
{
  char * user_cert;
  char *root_cert;
  char *root_dir;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  char *random_file;
  char *cncheck;
  sess_res session_resume;
  int  cnexact;
  int  chunk_size;

  ttls_phase2_type phase2_type; //the type to actually do
  struct config_ttls_phase2 *phase2; // all types with info defined
#ifdef RTL_TTLS_MD5_CLIENT
  struct generic_eap_data *phase2_eap_data;
#endif
  
};

struct config_eap_leap
{
  char *username;
  char *password;
};

struct config_eap_mschapv2
{
  char *username;
  char *password;
};

struct config_eap_peap
{
  char *identity; // phase2 identity
  char * user_cert;
  char *root_cert;
  char *root_dir;
  char *crl_dir;
  char * user_key;
  char * user_key_pass;
  char *random_file;
  char *cncheck;
  sess_res session_resume;
  int cnexact;
  int chunk_size;
#define CONFIG_PEAP_ALLOW_MSCV2   0x00000001
#define CONFIG_PEAP_ALLOW_MD5     0x00000002
#define CONFIG_PEAP_ALLOW_SIM     0x00000004
#define CONFIG_PEAP_ALLOW_GTC     0x00000008
#define CONFIG_PEAP_ALLOW_OTP     0x00000010
#define CONFIG_PEAP_ALLOW_ALL (CONFIG_PEAP_ALLOW_MSCV2| CONFIG_PEAP_ALLOW_MD5 \
                              |CONFIG_PEAP_ALLOW_SIM  | CONFIG_PEAP_ALLOW_GTC \
                              |CONFIG_PEAP_ALLOW_OTP  )
  int flags;
  struct config_eap_method *phase2; 
};

struct config_eap_sim
{
  char *username;
  char *password;
  int auto_realm;
};


/* A generic wrapper struct for above */
struct config_eap_method
{
  int method_num;
  void *method_data; // one of the structs above
  struct config_eap_method *next;
};

struct config_network
{
#define CONFIG_NET_ALLOW_TLS    0x00000001
#define CONFIG_NET_ALLOW_MD5    0x00000002
#define CONFIG_NET_ALLOW_TTLS   0x00000004
#define CONFIG_NET_ALLOW_LEAP   0x00000008
#define CONFIG_NET_ALLOW_MSCV2  0x00000010
#define CONFIG_NET_ALLOW_PEAP   0x00000020
#define CONFIG_NET_ALLOW_SIM    0x00000040
#define CONFIG_NET_ALLOW_GTC    0x00000080
#define CONFIG_NET_ALLOW_OTP    0x00000100
#define CONFIG_NET_ALLOW_ALL (CONFIG_NET_ALLOW_TLS  | CONFIG_NET_ALLOW_MD5  \
                             |CONFIG_NET_ALLOW_TTLS | CONFIG_NET_ALLOW_LEAP \
                             |CONFIG_NET_ALLOW_MSCV2| CONFIG_NET_ALLOW_PEAP \
                             |CONFIG_NET_ALLOW_SIM  | CONFIG_NET_ALLOW_GTC  \
                             |CONFIG_NET_ALLOW_OTP  )
#define CONFIG_NET_PREFER_TLS   0x00001000
#define CONFIG_NET_PREFER_MD5   0x00002000
#define CONFIG_NET_PREFER_TTLS  0x00004000
#define CONFIG_NET_PREFER_LEAP  0x00008000
#define CONFIG_NET_PREFER_MSCV2 0x00010000
#define CONFIG_NET_PREFER_PEAP  0x00020000
#define CONFIG_NET_PREFER_SIM   0x00040000
#define CONFIG_NET_PREFER_GTC   0x00080000
#define CONFIG_NET_PREFER_OTP   0x00100000
#define CONFIG_NET_PREFER_ALL (CONFIG_NET_PREFER_TLS  | CONFIG_NET_PREFER_MD5 \
                             |CONFIG_NET_PREFER_TTLS | CONFIG_NET_PREFER_LEAP \
                             |CONFIG_NET_PREFER_MSCV2| CONFIG_NET_PREFER_PEAP \
                             |CONFIG_NET_PREFER_SIM  | CONFIG_NET_PREFER_GTC  \
                             |CONFIG_NET_PREFER_OTP  )

  // indicates the variable below is set and should be used
#define CONFIG_NET_DEST_MAC     0x01000000

  char *name;
  int flags;
  enum {UNSET, WIRED, WIRELESS} type;
  char *ssid;
  char *identity;
  enum {CTL_UNSET, CTL_YES, CTL_NO}  wireless_ctrl;

  u_char  dest_mac[CONFIG_MAC_LEN];

  // EAP Methods that can be in the config file
  struct config_eap_method *methods; 
 
  // This is used to hook the currently active "phase 1" to.  It shouldn't
  // be given a value when the config is parsed!
  struct generic_eap_data *activemethod;

  struct config_network *next;
};


struct config_string_list 
{
  char *name;
  struct config_string_list *next;
};

struct config_globals
{
  char *default_net;
  struct config_string_list *allowed_nets;  
  char *startup_command;
  char *first_auth_command;
  char *reauth_command;
  char *logfile;
  // the following indicate the values below are set and should be used
#define CONFIG_GLOBALS_AUTH_PER    0x00000001
#define CONFIG_GLOBALS_HELD_PER    0x00000002
#define CONFIG_GLOBALS_MAX_STARTS  0x00000004
  int flags;
  int auth_period;
  int held_period;
  int max_starts;
  struct config_string_list *allow_interfaces;
  struct config_string_list *deny_interfaces;
  
};


struct config_data
{
  char *config_fname;
  struct config_globals *globals;
  struct config_network *networks;
};



int config_setup(char *);
struct config_network *config_build(char *);
void config_destroy();
int config_set_globals(struct interface_data *);
char *config_get_startup_cmd();
char *config_get_first_auth_cmd();
char *config_get_reauth_cmd();
char *config_get_logfile();
struct config_string_list *config_allowed_interfaces();
struct config_string_list *config_denied_interfaces();

int config_parse();
int config_contains_network(char *);
int config_allows_network(struct config_data *, char *);

// * private functions for config code
void initialize_config_eap_tls(struct config_eap_tls **);
void delete_config_eap_tls(struct config_eap_tls **);
void dump_config_eap_tls(struct config_eap_tls *);

void initialize_config_eap_md5(struct config_eap_md5 **);
void delete_config_eap_md5(struct config_eap_md5 **);
void dump_config_eap_md5(struct config_eap_md5 *, int);

void initialize_config_pap(struct config_pap **);
void delete_config_pap(struct config_pap **);
void dump_config_pap(struct config_pap *);

void initialize_config_chap(struct config_chap **);
void delete_config_chap(struct config_chap **);
void dump_config_chap(struct config_chap *);

void initialize_config_mschap(struct config_mschap **);
void delete_config_mschap(struct config_mschap **);
void dump_config_mschap(struct config_mschap *);

void initialize_config_mschapv2(struct config_mschapv2 **);
void delete_config_mschapv2(struct config_mschapv2 **);
void dump_config_mschapv2(struct config_mschapv2 *);

void add_config_ttls_phase2(struct config_ttls_phase2 **,
			    ttls_phase2_type, void *);
int  config_ttls_phase2_contains_phase2(struct config_ttls_phase2 *,
					ttls_phase2_type);
void delete_config_ttls_phase2(struct config_ttls_phase2 **);
void dump_config_ttls_phase2(struct config_ttls_phase2 *);

void initialize_config_eap_ttls(struct config_eap_ttls **);
void delete_config_eap_ttls(struct config_eap_ttls **);
void dump_config_eap_ttls(struct config_eap_ttls *);
int  check_config_eap_ttls(struct config_eap_ttls *);

void initialize_config_eap_leap(struct config_eap_leap **);
void delete_config_eap_leap(struct config_eap_leap **);
void dump_config_eap_leap(struct config_eap_leap *);

void initialize_config_eap_mschapv2(struct config_eap_mschapv2 **);
void delete_config_eap_mschapv2(struct config_eap_mschapv2 **);
void dump_config_eap_mschapv2(struct config_eap_mschapv2 *, int);

void initialize_config_eap_peap(struct config_eap_peap **);
void delete_config_eap_peap(struct config_eap_peap **);
void dump_config_eap_peap(struct config_eap_peap *);

void initialize_config_eap_sim(struct config_eap_sim **);
void delete_config_eap_sim(struct config_eap_sim **);
void dump_config_eap_sim(struct config_eap_sim *, int);

void add_config_eap_method(struct config_eap_method **,
			   int, void *);
void delete_config_eap_method(struct config_eap_method **);
int config_eap_method_contains_method(struct config_eap_method *, int);
void dump_config_eap_method(struct config_eap_method *, int);

void initialize_config_network(struct config_network **);
void delete_config_network(struct config_network **);
int  config_network_contains_net(struct config_network *, char *);
void config_network_add_net(struct config_network **, struct config_network *);
void dump_config_network(struct config_network *);

void initialize_config_string_list(struct config_string_list **);
void delete_config_string_list(struct config_string_list **);
int  config_string_list_contains_string(struct config_string_list *, char *);
void config_string_list_add_string(struct config_string_list **, char *);
void dump_config_string_list(struct config_string_list *, char *);

void initialize_config_globals(struct config_globals **);
void delete_config_globals(struct config_globals **);
void dump_config_globals(struct config_globals *);

void initialize_config_data(struct config_data **);
void delete_config_data(struct config_data **);
void dump_config_data(struct config_data *);

#endif
