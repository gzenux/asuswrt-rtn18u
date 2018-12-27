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
 * sshincludes.h
 *
 * Common include file.
 *
 */

#ifndef SSHINCLUDES_H
#define SSHINCLUDES_H

/* Defines related to segmented memory architectures. */
#ifndef NULL_FNPTR
#define NULL_FNPTR  NULL
#endif

/* Macros for giving branch prediction hints to the compiler. The
   result type of the expression must be an integral type. */
#if __GNUC__ >= 3
#define SSH_PREDICT_TRUE(expr) __builtin_expect(!!(expr), 1)
#define SSH_PREDICT_FALSE(expr) __builtin_expect(!!(expr), 0)
#else /* __GNUC__ >= 3 */
#define SSH_PREDICT_TRUE(expr) (!!(expr))
#define SSH_PREDICT_FALSE(expr) (!!(expr))
#endif /* __GNUC__ >= 3 */

/* Macros for marking functions to be placed in a special section. */
#if __GNUC__ >= 3
#define SSH_FASTTEXT __attribute__((__section__ (".text.fast")))
#else /* __GNUC__ >= 3 */
#define SSH_FASTTEXT
#endif /* __GNUC__ >= 3 */

/* Some generic pointer types. */
typedef char *SshCharPtr;
typedef void *SshVoidPtr;

#include "kernel_includes.h"

/* Some internal headers used in almost every file. */
#include "sshdebug.h"
#include "engine_alloc.h"

#endif /* SSHINCLUDES_H */
