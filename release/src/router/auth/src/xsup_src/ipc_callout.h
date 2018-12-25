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
 *
 * File: ipc_callout.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _IPC_CALLOUT_H_
#define _IPC_CALLOUT_H_

#include <sys/socket.h>

// Username and password values.
#define USERNAME         1
#define PASSWORD         2

// Certificate related items.
#define USER_CERT        3
#define USER_KEY         4
#define ROOT_CERT        5
#define ROOT_DIR         6
#define CRL_DIR          7
#define CHUNK_SIZE       8
#define RANDOM_FILE      9

// Allowed types
#define ALLOWED_PHASE1  10
#define ALLOWED_PHASE2  11

// SIM/AKA Values
#define AUTO_REALM      12

// Global values to set.  (These will be processed by non-eap specific
// handlers.)
#define CONN_TYPE       13
#define DEST_MAC        14

#define NET_LIST        15
#define STARTUP_CMD     16
#define FIRST_AUTH_CMD  17
#define REAUTH_CMD      18
#define AUTH_PERIOD     19
#define HELD_PERIOD     20
#define MAX_STARTS      21
#define ALLOW_INTS      22
#define DENY_INTS       23


struct ipc_set_config
{
  char phase1type;     // EAP type for phase 1.
  char phase2type;     // EAP type for phase 2 (0 if there isn't one, 1-4
                       // for TTLS phase 2 types.)
  char setting;        // 0 to 255, tags the value to set.
  char length;         // Length of the string to follow.

  // The following (length) bytes are a string value to be set.  The values
  // will always be strings, so the command inteperator should know which ones
  // need to be converted to other values.
};


void ipc_callout_auth_state(struct interface_data *, int *, char *, int,
			    char *, int *);

void ipc_callout_process_conf(struct interface_data *, int *, char *, int,
			      char *, int *);

void ipc_callout_reg_client(struct interface_data *, int *, char *, int,
			    char *, int *, struct sockaddr *);

void ipc_callout_get_ints(struct interface_data *, struct interface_data *, 
			  int *, char *, int, char *, int *);

void ipc_callout_send_error(struct interface_data *, int *, char *, int, 
			    char *);

void ipc_callout_getset_profile(struct interface_data *, int *, char *, int,
				char *, int *);

void ipc_callout_set_password(struct interface_data *, int *, char *, int, 
			      char *, int *);

void ipc_callout_request_password(struct interface_data *, int *, char *, int,
				  char *, char *);
#endif
