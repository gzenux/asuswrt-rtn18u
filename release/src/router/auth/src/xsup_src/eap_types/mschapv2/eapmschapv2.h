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
 * EAP-MSCHAPv2 Function Headers
 * 
 * File: eapmschapv2.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef _EAP_MSCHAPV2_H_
#define _EAP_MSCHAPV2_H_

#include <inttypes.h>
#include "profile.h"

#define EAP_TYPE_MSCHAPV2    0x1a

#define MS_CHAPV2_CHALLENGE     1
#define MS_CHAPV2_RESPONSE      2
#define MS_CHAPV2_SUCCESS       3
#define MS_CHAPV2_FAILURE       4
#define MS_CHAPV2_CHANGE_PWD    7

struct mschapv2_vars {
  char *AuthenticatorChallenge;
  char *PeerChallenge;
  char *NtResponse;
  char *keyingMaterial;
};

struct mschapv2_challenge {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t Value_Size;
  uint8_t Challenge[16];
  // Everything else in the packet should be the name of the RADIUS server.
};

struct mschapv2_response {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t Value_Size;
  uint8_t Peer_Challenge[16];
  uint8_t Reserved[8];
  uint8_t NT_Response[24];
  uint8_t Flags;
};

struct mschapv2_success_request {
  uint8_t OpCode;
  uint8_t MS_CHAPv2_ID;
  uint16_t MS_Length;
  uint8_t MsgField[42];   // S=<auth_string>
};

// A success response is a single byte 0x03, so we really don't need a 
// structure.

int eapmschapv2_setup(struct generic_eap_data *);
int eapmschapv2_process(struct generic_eap_data *, u_char *, int, u_char *, 
			int *);
int eapmschapv2_get_keys(struct interface_data *);
int eapmschapv2_cleanup(struct generic_eap_data *);
int eapmschapv2_failed(struct generic_eap_data *);

#endif
