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
 * File: xsup_err.h
 *
 * Authors: Chris.Hessing@utah.edu
 *
 *******************************************************************/

/* Error codes that we can get for various pieces of xsupplicant. */

// If we return >=0 then there wasn't an error.
#define XPROMPT            2    // We asked the GUI to prompt for something.
#define XDATA              1    // There is data to return.
#define XNEWESSID          3    // We have a new ESSID.
#define XENONE             0

#define XNONEWWLANMAC	4	//Patch for 802.1x client when enable wlan mac clone: needn't to update wlan mac address.
#define XEWRONGWLANMAC	-140 //Patch for 802.1x client when enable wlan mac clone: wlan mac address is changed.

// Error numbers -1 to -10 are socket related errors.
#define XENOSOCK          -1
#define XESOCKOP          -2
#define XENOTINT          -3
#define XENOWIRELESS      -4
#define XENOFRAMES        -5
#define XEIGNOREDFRAME    -6
#define XGOODKEYFRAME      6
#define XEBADKEY          -7
#define XNOMOREINTS        2
#define XINVALIDINT        3  // This isn't an error.  It is for situations
                              // where an interface index of 0 is invalid.

// Error numbers -11 through -20 are for misc. errors.
#define XECONFIGFILEFAIL  -11
#define XECONFIGPARSEFAIL -12 
#define XENOTHING_TO_DO   -13
#define XEBADCONFIG       -14
#define XEBADPACKETSIZE   -15

// Error numbers -21 through -30 are memory related errors.
#define XEMALLOC          -21   // Malloc error.
#define XENOBUFFER        -22   // There was a buffer that was empty when it
                                // shouldn't have been!
#define XENOUSERDATA      -23   // Our userdata structure was NULL!

// Skip -31 through -40 for possible use later.

// Error numbers -41 through -50 are key generation errors.
#define XENOKEYSUPPORT    -41

// Error numbers -100 through -200 are EAP specific errors.
// Error messages for EAP-MD5
#define XEMD5LEN         -100

// Error messages for EAP-TLS
#define XETLSINIT        -105
#define XETLSSTARTFAIL   -106
#define XETLSBADFLAGS    -107
#define XETLSCERTLOAD    -108
#define XETLSNOCTX       -109
#define XTLSNEEDDATA      105

// Error message for TLS based methods other than EAP-TLS.
#define XEBADCN          -130

// Error messages for MS-CHAPv2
#define XEMSCHAPV2LEN     -110

// Error messages for EAP-SIM
#define XESIMNOATMAC      -115
#define XESIMBADLEN       -116
#define XESIMBADTYPE      -117
#define XESIMBADMAC       -118
#define XESIMBADCMD       -119

// Error message for LEAP
#define XELEAP            -120
