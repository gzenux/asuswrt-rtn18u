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
 * File: eap.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _EAP_H_
#define _EAP_H_

#define EAP_REQUEST       1
#define EAP_RESPONSE      2
#define EAP_SUCCESS       3
#define EAP_FAILURE       4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_NOTIFY   2
#define EAP_TYPE_NAK      3

#define NO_EAP_AUTH      -1

struct generic_eap_data {
  void *eap_conf_data;       // Pointer to the configuration information for
                             // the EAP type we are going to use.

  void *eap_data;            // Pointer to EAP type specific state data.

  char *identity;            // Pointer to parent's ID

  char *tempPwd;             // Pointer to a temporary password.

  char *staleFrame;          // Pointer to an input frame that we will need
                             // later.  It is mainly for use when an EAP type
                             // needs to wait for a password to be entered.
                             // The last frame should be saved, and 
                             // resubmitted once we have a valid password.

  int staleSize;             // The size of the saved stale frame.

  int eapid;                 // The EAP ID of the packet we are working with.
  

  int need_password;         // The EAP method should set this to 1 when it
                             // requires a password, or other challenge data
                             // from a GUI interface.

  char *eaptype;             // When a password is needed, the EAP handler
                             // should identify itself by putting a text
                             // version of it's name here.  Otherwise, it 
                             // this variable should be NULL.

  char *eapchallenge;        // When an EAP method requires some sort of 
                             // challenge be displayed to the user in order 
                             // for them to generate the proper password data.
#ifdef RTL_TTLS_MD5_CLIENT
   int eapNum;                // The EAP type we are working with.
   char *intName;             // A pointer to the interface name that we are
                             // working with. (Mostly for IPC purposes.)
#endif
};

void eap_init(struct interface_data *);
void eap_cleanup(struct interface_data *);
void eap_process_header(struct interface_data *, char *, int);
void eap_request_id(struct interface_data *, char *, int *, int *);
int eap_request_auth(struct interface_data *, char *, int, char *, int *, int *);
int eap_clear_active_method(struct interface_data *);
int eap_get_keying_material(struct interface_data *);
int eap_do_fail(struct interface_data *);
#ifdef RTL_TTLS_MD5_CLIENT
int eap_create_active_method(struct generic_eap_data **, char *, char *, char *);
void eap_ttls_md5_request_id(char *identity, int eapid, char *outframe, 
		    int *eapsize);
#endif
#endif

