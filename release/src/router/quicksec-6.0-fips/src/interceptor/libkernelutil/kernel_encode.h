/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Helper functions for encoding/decoding binary data.
*/

#ifndef KERNEL_ENCODE_H
#define KERNEL_ENCODE_H

#ifdef SSHDIST_PLATFORM_VXWORKS
/* VxWorks has effectively common namespace for engine (kernel) and
   policymanager (user mode) coder, therefore kernel_encode.c and
   sshencode.c SHOULD NOT define same symbols (they use different
   functions, kmalloc and xmalloc respectively).
   It could be allowed, but then we'd only rely on symbol ambiguity
   resolution, which generates warnigns.
   */
#ifdef VXWORKS
# define ssh_encode_buffer      kernel_ssh_encode_buffer
# define ssh_encode_buffer_va   kernel_ssh_encode_buffer_va
# define ssh_decode_buffer      kernel_ssh_decode_buffer
# define ssh_decode_buffer_va   kernel_ssh_decode_buffer_va
# define ssh_encode_array       kernel_ssh_encode_array
# define ssh_encode_array_va    kernel_ssh_encode_array_va
# define ssh_encode_array_alloc kernel_ssh_encode_array_alloc
# define ssh_encode_array_alloc_va kernel_ssh_encode_array_alloc_va
# define ssh_decode_array       kernel_ssh_decode_array
# define ssh_decode_array_va    kernel_ssh_decode_array_va
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

#include "sshencode.h"

#endif /* KERNEL_ENCODE_H */
