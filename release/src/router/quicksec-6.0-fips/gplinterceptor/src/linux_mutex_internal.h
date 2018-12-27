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
 * linux_mutex_internal.h
 *
 * Linux interceptor internal defines for kernel mutex API.
 *
 */

#ifndef LINUX_MUTEX_INTERNAL_H
#define LINUX_MUTEX_INTERNAL_H

#include <linux/spinlock.h>
#include <asm/current.h>

typedef struct SshKernelMutexRec
{
  spinlock_t lock;
  unsigned long flags;

#ifdef DEBUG_LIGHT
  Boolean taken;
  unsigned long jiffies;
#endif
} SshKernelMutexStruct;

#ifdef CONFIG_PREEMPT

#include <linux/preempt.h>

#define icept_preempt_enable()  preempt_enable()
#define icept_preempt_disable() preempt_disable()

#else /* CONFIG_PREEMPT */

#define icept_preempt_enable()  do {;} while(0)
#define icept_preempt_disable() do {;} while(0)

#endif /* CONFIG_PREEMPT */

#endif /* LINUX_MUTEX_INTERNAL_H */
