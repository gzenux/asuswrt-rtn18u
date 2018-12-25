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
 * Hold information about each interface, state machine, and others.
 * File: profile.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _PROFILE_H_
#define _PROFILE_H_


#ifdef RTL_WPA_CLIENT
#include "1x_supp_pae.h"
extern Dot1x_Client            RTLClient;
#endif


#include "linux/if_packet.h"
#include <stdlib.h>

// Define some things to make the code more readable.
#define TRUE  1
#define FALSE 0

// Define our supplicant status values
#define UNAUTHORIZED 0
#define AUTHORIZED   1


struct dot1x_state
{
  // These variables are per the 802.1x documentation.
  /* These are defined as constants, but don't have to be.  We may want */
  /* the option of changing them in the future. */
  int authPeriod;
  int heldPeriod;
  int startPeriod;
  int maxStart;

  /* per 802.1x section 8.5.2.1 */
  int authWhile;
  int aWhile;
  int heldWhile;
  int quietWhile;
  int reAuthWhen;
  int startWhen;
  int txWhen;

  /* per 802.1x section 8.5.2.2 */
  int initialize;
  int suppStatus;

  /* per 802.1x section 8.5.3.1 port timers */
  int tick;

  /* per 802.1x section 8.5.10 Supplicant PAE */
  int userLogoff;
  int logoffSent;
  int reqId;
  int reqAuth;
  int eapSuccess;
  int eapFail;
  int startCount;
  int previousId;
  int receivedId;

  /* per 802.1x section 8.5.11 Key recieve */
  int rxKey;

  // This isn't in the spec, but is useful.
  int curState;
  int lastState;
  int portEnabled;
};

struct daemon_conf
{
  char *random_file;
  char *first_auth;
  char *after_auth;
};

struct interface_data
{
  char *intName;            // The name of this interface.

  // This part is going to be linux specific.
  int  sockInt;             // The socket we are using.
  int  isWireless;          // Is this a wireless interface?
  int  eapType;             // EAP type we are using.
  int  wasDown;             // Does the interface appear to be down?
  struct sockaddr_ll sll;   // Structure for physical interface.

  char source_mac[6];       // Source MAC address.
  char dest_mac[6];         // Destination MAC address.

  char *cur_essid;           // The current SSID we are using.

  struct dot1x_state *statemachine;  // State machine info
  struct config_network *userdata;
  struct daemon_conf *daemoncfg;     // We only store a single instance of the
                                     // daemon variables.  So, all daemoncfgs
                                     // will point to the same place.  This
                                     // variable is just to make things easier
                                     // to work with.

  int firstauth;                     // Is this the first time we have 
                                     // authenticated with this interface, on
                                     // this essid?

  struct ipc_struct *ipc;            // This should *ALWAYS* point to the same
                                     // IPC struct, no matter which interface
                                     // is in use!  This is just a shortcut
                                     // to that data!

  u_char *keyingMaterial;            // Hold any keying material generated by
                                     // an EAP type.  Should be NULL if there
                                     // isn't any!
  char *tempPassword;                // Temporary password.
  struct interface_data *next;       // Next interface we recognize.
};

int init_interface_struct(struct interface_data *, char *, 
			  struct daemon_conf *);
struct interface_data *destroy_interface_struct(struct interface_data *);
void profile_daemon_deinit(struct interface_data *workint);

#endif
