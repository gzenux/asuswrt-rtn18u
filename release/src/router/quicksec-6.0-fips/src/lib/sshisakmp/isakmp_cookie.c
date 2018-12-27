/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp anti-cloggin token (cookie) module.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkeCookie"

/*                                                              shade{0.9}
 * Create isakmp cookie. Generate completely random
 * cookie, as checking the cookie from the hash table is
 * about as fast or faster than hashing stuff together.
 * This also makes cookies movable against multiple machines
 * (high availability or checkpointing systems).
 * The return_buffer must be SSH_IKE_COOKIE_LENGTH
 * bytes long.                                                  shade{1.0}
 */
void ike_cookie_create(SshIkeContext isakmp_context,
                       unsigned char *cookie)
{
  int i;

  for (i = 0; i < SSH_IKE_COOKIE_LENGTH; i++)
    cookie[i] = ssh_random_get_byte();

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Cookie create"), cookie, 8);
}
