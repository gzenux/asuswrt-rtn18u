/**
 * A client-side 802.1x implementation supporting EAP/SIM
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2003 Chris Hessing
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
* EAPOL Function implementations for supplicant
 * 
 * File: simd5.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: simd5.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: simd5.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:31  ysc
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
 * Revision 1.3  2004/04/13 22:13:30  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.2  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.1  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 *
 *******************************************************************/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/


#ifdef EAP_SIM_ENABLE

#include <inttypes.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include "config.h"
#include "profile.h"
#include "eap.h"
#include "eapsim.h"
#include "xsup_debug.h"
#include "xsup_err.h"

// Draft 5 (version 0) specific calls.

int do_v0_at_mac(struct generic_eap_data *thisint, char *K_int, char *indata, 
		 int in_size, int inoffset, char *resultmac)
{
  char *framecpy, *mac_calc;
  int saved_offset, i;
  uint16_t value16;

  if ((!thisint) || (!K_int) || (!indata) || (!resultmac))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to do_v0_at_mac()!\n");
      return XEMALLOC;
    }

  if (indata[inoffset] != AT_MAC)
    {
      printf("Error!  The offset passed in is not of type AT_MAC!\n");
      return -1;
    }
  
  inoffset++;
	      
  if (indata[inoffset] != 5) printf("AT_MAC length isn't 5!\n");
  inoffset+=2;  // Skip the reserved bytes.

  saved_offset = inoffset;

  framecpy = (char *)malloc(in_size+50);  // We need extra to
	                                  // reconstruct the eap 
	                                  // piece.
  if (framecpy == NULL)
    {
      printf("Couldn't allocate memory for framecpy!\n");
      return -1;
    }

  // Now, reconstruct the header for the EAP piece, so we can
  // calculate the MAC across all of it.
  framecpy[0] = 1;  // It was a request.
  framecpy[1] = thisint->eapid;
  value16 = in_size + 5;
  value16 = htons(value16);

  memcpy((char *)&framecpy[2], &value16, 2);
  framecpy[4] = 18;  // EAP-SIM
  
  memcpy((char *)&framecpy[5], (char *)&indata[0], in_size);

  // Now, zero out the MAC value.
  for (i=(saved_offset+5);i<=(in_size+5);i++)
    {
      framecpy[i] = 0x00;
    }

  debug_printf(DEBUG_AUTHTYPES, "Calculating MAC on : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, framecpy, (in_size+5));
  
  // We should now be ready to calculate the AT_MAC for 
  // ourselves.
  mac_calc = (char *)malloc(100);
  if (mac_calc == NULL) return -1;
  
  HMAC(EVP_sha1(), &K_int[0], 16, framecpy, (in_size+5), mac_calc, &i);

  memcpy(resultmac, mac_calc, 16);  // We get 20 back, but we only want 16.

  free(framecpy);
  framecpy = NULL;
  
  free(mac_calc);
  mac_calc = NULL;
  return 0;
}

#endif
