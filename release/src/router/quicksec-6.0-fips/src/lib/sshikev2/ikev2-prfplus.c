/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 PRF+ function.
*/

#include "sshincludes.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshIkev2PrfPlus"

/* Calculated prf+ from given prf, and key and data. The
   output will be stored to the `output' buffer, and this
   will generate `output_len' bytes of output. */
SshCryptoStatus ssh_prf_plus(const unsigned char *prf,
                             const unsigned char *key,
                             size_t key_len,
                             const unsigned char *data,
                             size_t data_len,
                             unsigned char *output,
                             size_t output_len)
{
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  SshCryptoStatus status;
  unsigned char ch;
  size_t mac_len;
  SshMac mac;

  /* Allocate mac. */
  status = ssh_mac_allocate(ssh_csstr(prf), key, key_len, &mac);
  if (status != SSH_CRYPTO_OK)
    return status;

  /* Get the MAC len. */
  mac_len = ssh_mac_length(ssh_csstr(prf));

  ch = 1;
  while (1)
    {
      ssh_mac_reset(mac);
      if (ch != 1)
        {
          ssh_mac_update(mac, buffer, mac_len);
        }
      ssh_mac_update(mac, data, data_len);
      ssh_mac_update(mac, &ch, 1);
      status = ssh_mac_final(mac, buffer);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_mac_free(mac);
          return status;
        }

      if (output_len < mac_len)
        {
          memcpy(output, buffer, output_len);
          break;
        }
      memcpy(output, buffer, mac_len);
      output_len -= mac_len;
      output += mac_len;

      if (ch == 255)
        {
          ssh_mac_free(mac);
          return SSH_CRYPTO_DATA_TOO_LONG;
        }
      ch++;
    }
  ssh_mac_free(mac);
  return SSH_CRYPTO_OK;
}
