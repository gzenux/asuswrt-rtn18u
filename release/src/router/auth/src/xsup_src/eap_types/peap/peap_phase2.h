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
 * PEAP Phase 2 Function Headers
 * 
 * File: peap_phase2.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

#ifndef PEAP_PHASE2_H
#define PEAP_PHASE2_H

#define PEAP_EAP_EXTENSION    33

#define PEAP_SESSION_KEY_CONST         "client EAP encryption"
#define PEAP_SESSION_KEY_CONST_SIZE    21

#define PEAPv1_SESSION_KEY_CONST       "client PEAP encryption"
#define PEAPv1_SESSION_KEY_CONST_SIZE  22

#define PEAP_RESULT_TLV			0x03	
#define PEAP_CRYPTOBINDING_TLV     0x0C
#define PEAP_SOH_RESPONSE_TLV 	0x03

#define PEAP_RESULT_TLV_LEN		0x02
#define PEAP_CRYPTOBINDING_TLV_LEN	0x38


#define PEAP_RESULT_TLV_EXIST  (0x1<<0)
#define PEAP_CRYPTOBINDING_TLV_EXIST  (0x1<<1)
#define PEAP_SOH_RESPONSE_TLV_EXIST  (0x1<<2)

struct phase2_data {
  struct generic_eap_data *eapdata;
  int peap_version;
};

/*little endian ? FIXME*/
struct ext_tlv_header {
	unsigned short m_flag:1;
	unsigned short r_flag:1;
	unsigned short tlv_type:14;
	unsigned short tlv_length;
	unsigned char  value[0];
};

struct result_value {
	unsigned short result;
}; 

struct peap_extension {
	unsigned int flag;
	struct ext_tlv_header *pResult_TLV;	
	struct ext_tlv_header *pCryptobinding_TLV;
	struct ext_tlv_header *pSoH_TLV;
};
void peap_do_phase2(struct generic_eap_data *, u_char *, int, u_char *, int *);
int set_peap_version(struct phase2_data *,int);
void peap_phase2_failed(struct generic_eap_data *);
void peap_parse_extension(struct peap_extension *,u_char *,int);
void peap_build_extension(struct peap_extension *,u_char *,int *);
#endif
