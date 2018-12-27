/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHSINGLEDES_H
#define SSHSINGLEDES_H

Boolean ssh_single_des_cbc(const unsigned char *key,
                           size_t keylen,
                           unsigned char *dest,
                           const unsigned char *src,
                           size_t len);

#endif /* SSHSINGLEDES_H */
