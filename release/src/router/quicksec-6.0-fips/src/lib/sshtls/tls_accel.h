/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   TLS crypto hardware acceleration interfaced.
*/

#ifndef TLS_ACCEL_H
#define TLS_ACCEL_H

void *tls_accel_init_key(
  Boolean encode, int cipher,
  const unsigned char *key, int keylen,
  const unsigned char *iv);

Boolean tls_accel_free_key(void *ctx);

Boolean tls_accel_cipher(void *ctx, void *usr_ctx, void *buff, int len);

Boolean tls_accel_open(void (*rd_cb)(unsigned int, void *));
void tls_accel_close(void);
int tls_accel_get_rd_fd(void);

#endif /* TLS_ACCEL_H */
