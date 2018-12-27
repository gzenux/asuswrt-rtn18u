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
 * platform_interceptor.h
 *
 * Linux interceptor specific defines for the Interceptor API.
 *
 */

#ifndef SSH_PLATFORM_INTERCEPTOR_H

#define SSH_PLATFORM_INTERCEPTOR_H 1

#ifdef KERNEL
#ifndef KERNEL_INTERCEPTOR_USE_FUNCTIONS

#define ssh_interceptor_packet_len(pp) \
  ((size_t)((SshInterceptorInternalPacket)(pp))->skb->len)

#include "linux_params.h"
#include "linux_packet_internal.h"

#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */
#endif /* KERNEL */

#endif /* SSH_PLATFORM_INTERCEPTOR_H */
