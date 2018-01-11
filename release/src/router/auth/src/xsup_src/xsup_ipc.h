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
 * File: xsup_ipc.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _XSUP_IPC_H_
#define _XSUP_IPC_H_

#include <inttypes.h>
//#include "profile.h"

#define AUTH_STATE    1  // Get authentication state (get only!)
#define CONFIG        2  // Get or set a config value.
#define REGISTER      3  // Register client (set only!)
#define INTERFACES    4  // Get interface list (get only!)
#define PROFILE       5  // Get or Set a profile by name.
#define NOTIFY        6  // Send a notification message.
#define TEMPPASSWORD  7  // Get a password that was pushed in from a GUI client

#define ERROR_MSG   255  // Return an error message.

#define ACK           1
#define NACK          0

#define DONT_CLEAR    0
#define CLEAR         1

#define IPC_RESPONSE  0
#define IPC_GET       1
#define IPC_SET       2

struct ipc_header {
  uint8_t version;    // Version number spoken between client and daemon
  char interface[16]; // Interface name.
  uint8_t getset;     // Is this a get, or set request?
                      // (0=Response, 1=Get, 2=Set)
  uint8_t numcmds;    // How many commands are in this packet?
};

struct ipc_cmd {
  uint8_t attribute;
  uint8_t len;
  // Value comes after that.
};

struct registered_clients {
  struct sockaddr *addr;
  struct registered_clients *next;
};

struct ipc_struct {
  int sockid;
  struct registered_clients *reged;
};

int xsup_ipc_init(struct interface_data *);
int xsup_ipc_send_all_registered(struct interface_data *, char *, int);
void xsup_ipc_process(struct interface_data *);
void xsup_ipc_cleanup(struct interface_data *);

#endif
