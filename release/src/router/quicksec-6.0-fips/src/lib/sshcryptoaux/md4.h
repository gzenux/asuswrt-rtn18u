/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef MD4_H
#define MD4_H

/* Compute a MD4 digest from the given buffer. */
void ssh_md4_of_buffer(unsigned char digest[16],
                       const unsigned char *buf,
                       size_t len);

#endif /* MD4_H */
