/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshEKSoftKey"

#include "sshincludes.h"
#include "softprovideri.h"

/* Adds a key and certificate into the software provider. The key and
   the certificate is reported using the externalkey notification
   callback and the key and certificate is available for the
   application through the standard externakey API functions.

   This function may be called multiple times with the same key,
   possible with a different certificate. Each call, if succesfull,
   results into a call to the application specified notification
   callback.

   The ek points to an allocated externalkey provider.

   provider_short_name is a string identifying the software provider
   tobe used in this operation. If it is NULL, the first available
   software provider will be used.

   The priv is a software key returned from SSH cryptographic
   library.

   The key label is some printable label for the key, it will
   be provided in the notification callback. The label may be NULL.

   The cert points to a BER/DER encoded x.509 buffer. The cert_len is
   the length of the certificate data. The cert may be NULL.

   Returns SSH_EK_OK on success, or some other SshEkStatus enums on
   failure cases.

*/

SshEkStatus ssh_sk_add_key_and_cert(SshExternalKey ek,
                                    const char *provider_short_name,
                                    SshPrivateKey priv,
                                    const char *key_label,
                                    const unsigned char *cert,
                                    size_t cert_len)
{
  SshSoftAddKeyCert ctx;
  SshEkStatus status;

  if (ek == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_sk_add_key_and_cert called with NULL EK. "));
      return SSH_EK_FAILED;
    }

  /* No provider name specified.  We will try to find one. */
  if (provider_short_name == NULL)
    {
      SshUInt32 num_providers, i;
      SshEkProvider provider_array;

      memset(&provider_array, 0, sizeof(provider_array));

      (void) ssh_ek_get_providers(ek, &provider_array, &num_providers);
      for (i = 0; i < num_providers; i++)
        {
          if (strcmp(provider_array[i].type, "software") == 0)
            {
              provider_short_name = provider_array[i].short_name;
              break;
            }
        }
      ssh_free(provider_array);

      if (provider_short_name == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No software Provider available. "));
          return SSH_EK_PROVIDER_NOT_AVAILABLE;
        }
    }

  /* Now call the software provider with a message */
  ctx = ssh_xcalloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No memory"));
      return SSH_EK_NO_MEMORY;
    }
  ctx->priv = priv;
  ctx->cert = cert;
  ctx->cert_len = cert_len;
  ctx->key_label = key_label;
  ctx->status = SSH_EK_FAILED; /* Lets be pessimists. Not really, if
                                  the provider does not handle this
                                  message, the status is left to
                                  failed. */
  ssh_ek_send_message(ek, provider_short_name,
                      SSH_SOFTPROVIDER_ADD_KEY_AND_CERT_MESSAGE,
                      ctx,
                      sizeof(*ctx),
                      NULL_FNPTR,
                      NULL);
  status = ctx->status;
  ssh_free(ctx);
  return status;
}

