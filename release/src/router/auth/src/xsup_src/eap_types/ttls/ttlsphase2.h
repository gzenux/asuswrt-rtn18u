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
 * EAPTTLS Phase 2 Function implementations
 *
 * File: ttlsphase2.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 ******************************************************************/

#ifndef _TTLS_PHASE2_H
#define _TTLS_PHASE2_H

// Phase 2 Types for TTLS
#define TTLS_PHASE2_UNDEFINED 0
#define TTLS_PHASE2_PAP       1
#define TTLS_PHASE2_CHAP      2
#define TTLS_PHASE2_MSCHAP    3
#define TTLS_PHASE2_MSCHAPv2  4
#ifdef RTL_TTLS_MD5_CLIENT
void ttls_do_bogus(struct generic_eap_data *, char *, int , char *, int *);
void ttls_do_pap(struct generic_eap_data *, char *, int , char *, int *);
void ttls_do_chap(struct generic_eap_data *, char *, int , char *, int *);
void ttls_do_mschap(struct generic_eap_data *, char *, int , char *, int *);
void ttls_do_mschapv2(struct generic_eap_data *, char *, int , char *, int *);
void ttls_do_phase2(struct generic_eap_data *,  char *, int , char *, int *);
void ttls_do_eap_md5(struct generic_eap_data *,  char *, int , char *, int *);
#else
void ttls_do_bogus(struct generic_eap_data *, char *, int *);
void ttls_do_pap(struct generic_eap_data *, char *, int *);
void ttls_do_chap(struct generic_eap_data *, char *, int *);
void ttls_do_mschap(struct generic_eap_data *, char *, int *);
void ttls_do_mschapv2(struct generic_eap_data *, char *, int *);
void ttls_do_phase2(struct generic_eap_data *, char *,int, char *, int *);

#endif

void ttls_phase2_failed(struct generic_eap_data *);

#endif
