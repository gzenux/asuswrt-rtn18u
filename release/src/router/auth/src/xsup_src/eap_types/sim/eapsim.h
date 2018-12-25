/**
 * A client-side 802.1x implementation supporting EAP
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2002 Chris Hessing & Terry Simons
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
 * EAPSIM Header
 *
 * File: eapsim.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/

#ifdef EAP_SIM_ENABLE

#ifndef _EAP_SIM_H_
#define _EAP_SIM_H_

#include <sys/types.h>

#define EAP_TYPE_SIM   18

// These are defined in section 18 of Haverinen-08
// EAP-SIM Subtype values.
#define SIM_START            10
#define SIM_CHALLENGE        11
#define SIM_NOTIFICATION     12
#define SIM_REAUTHENTICATION 13

// EAP-SIM Subtype Attribute values
#define AT_RAND               1
#define AT_PADDING            6
#define AT_NONCE_MT           7
#define AT_MAC_SRES           9
#define AT_PERMANENT_ID_REQ  10
#define AT_MAC               11
#define AT_NOTIFICATION      12
#define AT_ANY_ID_REQ        13
#define AT_IDENTITY          14
#define AT_VERSION_LIST      15
#define AT_SELECTED_VERSION  16
#define AT_FULLAUTH_ID_REQ   17
#define AT_COUNTER           19
#define AT_COUNTER_TOO_SMALL 20
#define AT_NONCE_S           21

#define AT_IV               129
#define AT_ENCR_DATA        130
#define AT_NEXT_PSEUDONYM   132
#define AT_NEXT_REAUTH_ID   133

// These are values that can be returned by AT_NOTIFICATION
// They are defined in section 16. (Section says 1024 has been defined too,
//  but I can't located the definition. ;)
#define USER_DENIED          1026
#define USER_NO_SUBSCRIPTION 1031

// The highest version of SIM we support...
#define EAPSIM_MAX_SUPPORTED_VER     1

struct triplets {
  char random[16];
  char response[4];
  char ckey[8];
};

struct eaptypedata {
  int workingversion;
  int numrands;
  char *nonce_mt;
  char *verlist;
  int verlistlen;
  struct triplets triplet[3];
  char *keyingMaterial;
};  

struct typelength {
  uint8_t type;
  uint8_t length;
};

struct typelengthres {
  uint8_t type;
  uint8_t length;
  uint16_t reserved;
};

// Get the IMSI as the username.
int eapsim_get_username(struct interface_data *);

// Initalizes Function for EAPOL package
int eapsim_setup(struct generic_eap_data *);

// Function to handle packets and manage state.
int eapsim_process(struct generic_eap_data *, u_char *, int, u_char *, int *);

// Return keying material.
int eapsim_get_keys(struct interface_data *);

//Clean up after ourselves.
int eapsim_cleanup(struct generic_eap_data *);

int eapsim_failed(struct generic_eap_data *);

#endif
#endif
