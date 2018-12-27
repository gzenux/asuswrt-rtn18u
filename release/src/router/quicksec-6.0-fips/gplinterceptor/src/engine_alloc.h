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
 * engine_alloc.h
 *
 * Engine memory allocation API.
 *
 */

#ifndef ENGINE_ALLOC_H
#define ENGINE_ALLOC_H

void *ssh_malloc(size_t size);
void *ssh_malloc_flags(size_t size, SshUInt32 flags);
void *ssh_realloc(void *ptr, size_t old_size, size_t new_size);
void *ssh_realloc_flags(void *ptr, size_t old_size, size_t new_size,
                        SshUInt32 flags);
void *ssh_calloc(size_t nitems, size_t size);
void *ssh_calloc_flags(size_t nitems, size_t size, SshUInt32 flags);
void *ssh_strdup(const void *p);
void *ssh_memdup(const void *p, size_t len);
void ssh_free(void *ptr);

#endif /* ENGINE_ALLOC_H */
