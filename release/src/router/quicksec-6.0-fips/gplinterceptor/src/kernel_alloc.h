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
 * kernel_alloc.h
 *
 * Kernel memory allocation API.
 *
 */

#ifndef KERNEL_ALLOC_H
#define KERNEL_ALLOC_H

/* Allocate 'size' amount of memory, with the 'flag'
   parameters. Returns a NULL value if the allocation request cannot
   be satisfied for some reason.

   Notice: 'flag' is nothing more than a hint to the allocator. The
   allocator is free to ignore 'flag'. The allocatee is free to
   specify flag as ssh_rand() number, and the returned memory must still
   have the same semantics as any other memory block allocated. */
void *ssh_kernel_alloc(size_t size, SshUInt32 flag);

/* Flag is or-ed together of the following flags. */
#define SSH_KERNEL_ALLOC_NOWAIT 0x0000 /* allocation/use atomic. */
#define SSH_KERNEL_ALLOC_WAIT   0x0001 /* allow sleeping alloc/use. */
#define SSH_KERNEL_ALLOC_DMA    0x0002 /* allow DMA use. */
/* Other bits are usable for other purposes? */

/* Frees a previously allocated block of memory. */
void ssh_kernel_free(void *ptr);

#ifdef DEBUG_LIGHT
#define KERNEL_ALLOC_USE_FUNCTIONS
#endif /* DEBUG_LIGHT */

#endif /* KERNEL_ALLOC_H */
