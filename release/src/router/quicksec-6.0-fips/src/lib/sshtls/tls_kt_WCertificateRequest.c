/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_write_server_certreq(SshTlsProtocolState s)
{
#ifdef SSHDIST_VALIDATOR
  int i, l;
  SshDNStruct dn;
  unsigned char *der;
  size_t der_len;

  if (s->kex.flags & SSH_TLS_KEX_ANONYMOUS_SERVER)
    {
      SSH_DEBUG(5, ("Anonymous server so cannot request client certificate."));
      s->kex.state = SSH_TLS_KEX_SEND_S_HELLODONE;
      return SSH_TLS_TRANS_OK;
    }

  if (!(s->conf.flags & SSH_TLS_CLIENTAUTH))
    {
      SSH_DEBUG(6, ("Client authentication not requested so do not request "
                    "client certificate."));
      s->kex.state = SSH_TLS_KEX_SEND_S_HELLODONE;
      return SSH_TLS_TRANS_OK;
    }

  s->kex.flags |= SSH_TLS_KEX_CLIENT_CERT_REQUESTED;

  if (s->conf.suggested_ca_distinguished_names == NULL ||
      s->conf.suggested_ca_distinguished_names[0] == NULL)
    {
      FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
           ("no suggested distinguished names for CAs"));
    }

  /* Currently, we support only the rsa_sign(1) certificate type. */

  SSH_DEBUG(6, ("Requesting client certificate."));

  /* Calculate the length of the name list and write header. */

  l = 0;

  for (i = 0; s->conf.suggested_ca_distinguished_names[i] != NULL; i++)
    {
      ssh_dn_init(&dn);
      ssh_dn_decode_ldap(s->conf.suggested_ca_distinguished_names[i], &dn);
      ssh_dn_encode_der(&dn, &der, &der_len, NULL);
      l += der_len + 2;
      ssh_free(der);
      ssh_dn_clear(&dn);
    }

  l += 2;

  ssh_tls_make_hs_header(s, SSH_TLS_HS_CERT_REQ, l + 2);

  {
    unsigned char tempbuf[2];

    /* Write certificate types */
    tempbuf[0] = 1;
    tempbuf[1] = SSH_TLS_CERTTYPE_RSA_SIGN;
    ssh_tls_add_to_kex_packet(s, tempbuf, 2);

    /* Write distinguished names */

    SSH_DEBUG(7, ("Enumerating the list of suggested CAs:"));

    SSH_PUT_16BIT(tempbuf, l - 2); ssh_tls_add_to_kex_packet(s, tempbuf, 2);

    for (i = 0; s->conf.suggested_ca_distinguished_names[i] != NULL; i++)
      {
        ssh_dn_init(&dn);
        ssh_dn_decode_ldap(s->conf.suggested_ca_distinguished_names[i], &dn);
        der_len = 0;
        ssh_dn_encode_der(&dn, &der, &der_len, NULL);
        l = der_len;

        SSH_DEBUG(7, ("(%d) CA `%s' (%d bytes der).",
                      i,
                      s->conf.suggested_ca_distinguished_names[i],
                      l));

        SSH_PUT_16BIT(tempbuf, l);
        ssh_tls_add_to_kex_packet(s, tempbuf, 2);
        ssh_tls_add_to_kex_packet(s,
                                  (unsigned char *)der,
                                  l);
        ssh_free(der);
        ssh_dn_clear(&dn);
      }
  }

  s->kex.state = SSH_TLS_KEX_SEND_S_HELLODONE;

#endif /* SSHDIST_VALIDATOR */

  /* At present the non SSHDIST_VALIDATOR distribution does not
     request certificates from the peer. */
  s->kex.state = SSH_TLS_KEX_SEND_S_HELLODONE;
  return SSH_TLS_TRANS_OK;
}
