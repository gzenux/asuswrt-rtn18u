/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

#ifndef SSHDIST_VALIDATOR
static SshTlsTransStatus write_cert(SshTlsProtocolState s)
{
  SshBufferStruct temp;
  unsigned char tempbuf[3];
  int l;
  unsigned char *ptr;

  if (s->kex.own_certs != NULL)
    {
      SshTlsBerCert ber_cert;
      unsigned char *buf;
      size_t len;

      ber_cert = s->kex.own_certs;
      ssh_buffer_init(&temp);

      while (ber_cert != NULL)
        {
          buf = ber_cert->ber_data;
          len = ber_cert->ber_data_len;

          SSH_DEBUG(6, ("BER data len is %d.", len));

          if (ssh_buffer_append_space(&temp, &ptr, 3 + len) == SSH_BUFFER_OK)
            {
              ptr[0] = (len >> 16) & 0xff;
              ptr[1] = (len >> 8)  & 0xff;
              ptr[2] = len & 0xff;
              memcpy(&ptr[3], buf, len);
            }

          ber_cert = ber_cert->next;
        }

      l = ssh_buffer_len(&temp);
      SSH_DEBUG(6, ("Buffer len %d bytes.", l));

      /* write the packet */
      ssh_tls_make_hs_header(s, SSH_TLS_HS_CERT, l + 3);
      tempbuf[0] = (unsigned char)(l >> 16);
      tempbuf[1] = (unsigned char)(l >> 8);
      tempbuf[2] = (unsigned char)l;
      ssh_tls_add_to_kex_packet(s, tempbuf, 3);
      ptr = ssh_buffer_ptr(&temp);
      ssh_tls_add_to_kex_packet(s, ptr, l);
      ssh_buffer_uninit(&temp);
    }
  else
    {
      ssh_tls_make_hs_header(s, SSH_TLS_HS_CERT, 3);
      tempbuf[0] = (unsigned char)0;
      tempbuf[1] = (unsigned char)0;
      tempbuf[2] = (unsigned char)0;
      ssh_tls_add_to_kex_packet(s, tempbuf, 3);
    }

  return SSH_TLS_TRANS_OK;
}
#endif /* !SSHDIST_VALIDATOR */


#ifdef SSHDIST_VALIDATOR
static SshTlsTransStatus write_cert(SshTlsProtocolState s)
{
  SshBufferStruct temp;
  unsigned char tempbuf[3];
  int l;
  unsigned char *ptr;

  if (s->kex.own_certificate_list != NULL)
    {
      SshCMCertificate c;
      unsigned char *buf;
      size_t len;

      ssh_buffer_init(&temp);
#ifdef DEBUG_LIGHT
      {
        SshCMCertificate t;
        SshX509Certificate x509;
        char *subject, *issuer;

        t = ssh_cm_cert_list_first(s->kex.own_certificate_list);
        while (t != NULL)
          {
            (void)ssh_cm_cert_get_x509(t, &x509);
            ssh_x509_cert_get_subject_name(x509, &subject);
            ssh_x509_cert_get_issuer_name(x509, &issuer);
            SSH_DEBUG(5, ("Subject: %s Issuer: %s", subject, issuer));
            ssh_free(subject); ssh_free(issuer);
            ssh_x509_cert_free(x509);
            t = ssh_cm_cert_list_next(s->kex.own_certificate_list);
          }
      }
#endif

      c = ssh_cm_cert_list_last(s->kex.own_certificate_list);

      while (c != NULL)
        {
          if (ssh_cm_cert_get_ber(c, &buf, &len) != SSH_CM_STATUS_OK)
            {
              SSH_DEBUG(5, ("BER encoding failed."));
              ssh_buffer_uninit(&temp);
              return SSH_TLS_TRANS_FAILED;
            }
          SSH_DEBUG(6, ("Inserting BER encoded certificate into a "
                        "temporary buffer."));
          if (ssh_buffer_append_space(&temp, &ptr, 3 + len) == SSH_BUFFER_OK)
            {
              ptr[0] = (len >> 16) & 0xff;
              ptr[1] = (len >> 8)  & 0xff;
              ptr[2] = len & 0xff;
              memcpy(&ptr[3], buf, len);
            }
          c = ssh_cm_cert_list_prev(s->kex.own_certificate_list);
        }

      l = ssh_buffer_len(&temp);
      SSH_DEBUG(6, ("Buffer len %d bytes.", l));

      /* write the packet */
      ssh_tls_make_hs_header(s, SSH_TLS_HS_CERT, l + 3);
      tempbuf[0] = (unsigned char)(l >> 16);
      tempbuf[1] = (unsigned char)(l >> 8);
      tempbuf[2] = (unsigned char)l;
      ssh_tls_add_to_kex_packet(s, tempbuf, 3);
      ptr = ssh_buffer_ptr(&temp);
      ssh_tls_add_to_kex_packet(s, ptr, l);
      ssh_buffer_uninit(&temp);
    }
  else
    {
      ssh_tls_make_hs_header(s, SSH_TLS_HS_CERT, 3);
      tempbuf[0] = (unsigned char)0;
      tempbuf[1] = (unsigned char)0;
      tempbuf[2] = (unsigned char)0;
      ssh_tls_add_to_kex_packet(s, tempbuf, 3);
    }

  return SSH_TLS_TRANS_OK;
}
#endif /* SSHDIST_VALIDATOR */


SshTlsTransStatus ssh_tls_trans_write_client_cert(SshTlsProtocolState s)
{
  s->kex.state = SSH_TLS_KEX_SEND_C_KEX;

  if (!(s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED))
    return SSH_TLS_TRANS_REPROCESS;

  return write_cert(s);
}

SshTlsTransStatus ssh_tls_trans_write_server_cert(SshTlsProtocolState s)
{
  s->kex.state = SSH_TLS_KEX_SEND_S_KEX;

  if (s->kex.flags & SSH_TLS_KEX_ANONYMOUS_SERVER)
    {
      SSH_DEBUG(6, ("This is anonymous key exchange so don't "
                    "send a certificate list."));
      return SSH_TLS_TRANS_OK;
    }

  return write_cert(s);
}
