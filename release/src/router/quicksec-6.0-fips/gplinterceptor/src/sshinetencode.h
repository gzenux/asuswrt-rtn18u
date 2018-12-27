/**
   The following copyright and permission notice must be included in all
   copies, modified as well as unmodified, of this file.
  
   This file is free software: you may copy, redistribute and/or modify it  
   under the terms of the GNU General Public License as published by the  
   Free Software Foundation, either version 2 of the License, or (at your  
   option) any later version.  
    
   This file is distributed in the hope that it will be useful, but  
   WITHOUT ANY WARRANTY; without even the implied warranty of  
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  
   General Public License for more details.  
    
   You should have received a copy of the GNU General Public License  
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  
    
   This file incorporates work covered by the following copyright and  
   permission notice:  
    
   @copyright
   Copyright (c) 2010-2012, AuthenTec Inc, all rights reserved. 
  
 */ 

/*
 * sshinetencode.h
 *
 * Inet API: IP address encoding and decoding functions.
 *
 */

#ifndef SSHINETENCODE_H
#define SSHINETENCODE_H

#include "sshinet.h"

/* Decode IP-address from array. */
int ssh_decode_ipaddr_array(const unsigned char *buf, size_t bufsize,
			    void *ip);

/* Encode IP-address to array. Return 0 in case it does not fit to the buffer.
   NOTE, this is NOT a SshEncodeDatum Encoder, as the return values are
   different. */
size_t ssh_encode_ipaddr_array(unsigned char *buf, size_t bufsize,
			       const SshIpAddr ip);
size_t ssh_encode_ipaddr_array_alloc(unsigned char **buf_return,
				     const SshIpAddr ip);

#ifdef WITH_IPV6
/* type+mask+scopeid+content */
#define SSH_MAX_IPADDR_ENCODED_LENGTH (1+4+4+16)
#else  /* WITH_IPV6 */
/* type+mask+content */
#define SSH_MAX_IPADDR_ENCODED_LENGTH (1+4+16)
#endif /* WITH_IPV6 */

#endif /* SSHINETENCODE_H */
