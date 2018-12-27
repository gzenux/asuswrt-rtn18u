/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decoding CMP (RFC2510 and RFC2510bis) messages.
*/

#include "sshincludes.h"
#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "x509cmp.h"
#include "x509cmp-internal.h"
#include "sshstr.h"

#ifdef SSHDIST_CERT
/* Decoding. */

#define SSH_DEBUG_MODULE "SshX509CmpDecode"

static SshStr cmp_decode_freetext(SshAsn1Context context,
                                  SshAsn1Node freetext)
{
  SshStr text;
  SshCharset srctype = SSH_CHARSET_PRINTABLE;
  unsigned char *t;
  size_t t_len;
  SshUInt32 which;

  if (ssh_asn1_read_node(context, freetext,
                         "(choice"
                         "  (utf8-string ())"
                         "  (octet-string ())"
                         "  (teletex-string ())"
                         "  (universal-string ())"
                         "  (visible-string ())"
                         "  (ia5-string ())"
                         "  (printable-string ()))",
                         &which, &t, &t_len) == SSH_ASN1_STATUS_OK)
    {
      if (which == 0) srctype = SSH_CHARSET_UTF8;
      if (which == 1) srctype = SSH_CHARSET_ISO_8859_1;
      if (which == 2) srctype = SSH_CHARSET_T61;
      if (which == 3) srctype = SSH_CHARSET_UNIVERSAL;
      if (which == 4) srctype = SSH_CHARSET_VISIBLE;
      if (which == 5) srctype = SSH_CHARSET_US_ASCII;
      if (which == 6) srctype = SSH_CHARSET_PRINTABLE;

      text = ssh_str_make(srctype, t, t_len);
    }
  else
    text = NULL;

  return text;
}

static SshX509Status
cmp_decode_pki_status(SshAsn1Context context,
                      SshAsn1Node node,
                      SshCmpStatusInfo pki_status)
{
  SshAsn1Status status;
  SshWord stat;
  unsigned char *bitstring;
  size_t bitstring_len;
  SshAsn1Node freetext;
  Boolean freetext_found, failure_found;

  /* Decode the status. */
  status = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "   (integer-short ())"
                              "   (optional"
                              "     (sequence ()"
                              "       (any ())))"
                              "   (optional"
                              "      (bit-string ())))",
                              &stat,
                              &freetext_found, &freetext,
                              &failure_found, &bitstring, &bitstring_len);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  /* Check the range of the status. */
  if (stat > SSH_CMP_STATUS_KEY_UPDATE_WARNING)
    return SSH_X509_FAILURE;

  /* Assign the status. */
  pki_status->status = stat;

  if (freetext_found)
    pki_status->freetext = cmp_decode_freetext(context, freetext);
  else
    pki_status->freetext = NULL;

  /* Determine the bitstring values. */
  if (failure_found)
    {
      pki_status->failure = ssh_x509_bs_to_ui(bitstring, bitstring_len);
      ssh_free(bitstring);
    }

  return SSH_X509_OK;
}

static SshX509Status
cmp_decode_error_msg(SshAsn1Context context,
                     SshAsn1Node node,
                     SshCmpErrorMsg error)
{
  SshAsn1Status status;
  SshAsn1Node info, free_text;
  SshMPIntegerStruct code;
  Boolean code_found, free_found;
  SshX509Status rv;

  ssh_mprz_init(&code);
  status = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (any ())"
                              "  (optional"
                              "    (integer ()))"
                              "  (optional"
                              "    (sequence ()"
                              "      (any ()))))",
                              &info,
                              &code_found, &code,
                              &free_found, &free_text);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Decode the pki info. */
  rv = cmp_decode_pki_status(context, info, &error->status);
  if (rv != SSH_X509_OK)
    goto failed;

  if (code_found)
    ssh_mprz_set(&error->error_code, &code);

  if (free_found)
    error->details = cmp_decode_freetext(context, free_text);
  else
    error->details = NULL;

  rv = SSH_X509_OK;

 failed:
  ssh_mprz_clear(&code);
  return rv;
}

static SshX509Status
cmp_decode_cert(SshAsn1Context context,
                SshAsn1Node node,
                SshGList glist)
{
  SshGListNode gnode;
  SshCmpCertificate c;

  if ((c = ssh_malloc(sizeof(*c))) != NULL)
    {
      cmp_cert_init(c);
      if (ssh_asn1_node_get_data(node, &c->cert, &c->cert_len)
          == SSH_ASN1_STATUS_OK)
        {
          if ((gnode = ssh_glist_allocate_n(glist)) != NULL)
            {
              gnode->data = c;
              gnode->data_length = sizeof(*c);
              ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
              return SSH_X509_OK;
            }
          ssh_free(c->cert);
        }
      ssh_free(c);
    }
  return SSH_X509_FAILURE;
}

static SshX509Status
cmp_decode_key_pair(SshAsn1Context context,
                    SshAsn1Node node,
                    SshCmpCertificate pair)
{
  /* Handle the key pair. The sequence from the beginning has
     already been eaten out.*/
  if (node)
    {
      Boolean private_key_found, pub_info_found;
      SshAsn1Node cert, private_key, pub_info;
      int kind_of_cert;
      SshAsn1Status status;

      if ((status = ssh_asn1_read_node(context, node,
                                       "(choice"
                                       "  (any (e 0))"
                                       "  (any (e 1)))"
                                       "(optional"
                                       "  (any (e 0)))"
                                       "(optional"
                                       "  (any (e 1)))",
                                       &kind_of_cert, &cert, &cert,
                                       &private_key_found, &private_key,
                                       &pub_info_found, &pub_info))
          != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILURE;

      switch (kind_of_cert)
        {
        case 0: /* certificate */
        case 1: /* encrypted certificate */
          if (ssh_asn1_node_get_data(cert, &pair->cert, &pair->cert_len)
              != SSH_ASN1_STATUS_OK)
            return SSH_X509_FAILURE;
          else
            pair->encrypted = kind_of_cert;
          break;
        default:
          return SSH_X509_FAILURE;
        }

      if (private_key_found)
        {
          if (ssh_asn1_node_get_data(private_key,
                                     &pair->prvkey, &pair->prvkey_len)
              != SSH_ASN1_STATUS_OK)
            return SSH_X509_FAILURE;
        }

      return SSH_X509_OK;
    }
  return SSH_X509_FAILURE;
}

static SshX509Status
cmp_decode_extra_certs(SshAsn1Context context,
                       SshAsn1Node node,
                       SshGList glist)
{
  SshAsn1Status status;
  SshAsn1Node   list;

  status = ssh_asn1_read_node(context, node, "(sequence (*) (any ()))", &list);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  for (; list; list = ssh_asn1_node_next(list))
    cmp_decode_cert(context, list, glist);

  return SSH_X509_OK;
}

static SshX509Status
cmp_decode_protection(SshAsn1Context context,
                      SshAsn1Node node,
                      unsigned char **protection,
                      size_t *protection_len)
{
  SshAsn1Status status;

  *protection = NULL;
  status = ssh_asn1_read_node(context, node,
                              "(bit-string ())",
                              protection, protection_len);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;
  return SSH_X509_OK;
}

static SshX509Status
cmp_decode_protection_info(SshAsn1Context context,
                           SshAsn1Node node,
                           SshCmpProtectionInfo info)
{
  SshAsn1Status status;
  SshAsn1Node param;
  char *oid;

  status = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (object-identifier ())"
                              "  (any ()))",
                              &oid, &param);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  if (oid == NULL)
    return SSH_X509_FAILED_ASN1_DECODE;

  if (strcmp(oid, SSH_PSWBMAC_OID) == 0)
    {
      ssh_free(oid);
      info->pswbmac = ssh_pswbmac_decode_param(context, param);
      if (info->pswbmac == NULL)
        return SSH_X509_FAILED_ASN1_DECODE;
    }
  else
    {
      ssh_free(oid);
      /* Try to decode as a signature. */
      info->signature.pk_algorithm =
        ssh_x509_find_algorithm(context, node,
                                &info->signature.pk_type);
    }
  return SSH_X509_OK;
}

static SshX509Status
cmp_decode_general_infos(SshAsn1Context context,
                         SshAsn1Node node,
                         SshX509Attribute *attrs)
{
  SshAsn1Node list, value;
  SshX509Attribute head = NULL, attr = NULL;
  char *oid;

  if (ssh_asn1_read_node(context, node, "(sequence (*) (any ()))", &list)
      != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  for (; list; list = ssh_asn1_node_next(list))
    {
      if (ssh_asn1_read_node(context, list,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (any ()))",
                             &oid, &value)
          == SSH_ASN1_STATUS_OK)
        {
          if (head)
            {
              attr->next = ssh_calloc(1, sizeof(*attr));
              attr = attr->next;
            }
          else
            head = attr = ssh_calloc(1, sizeof(*attr));

          if (attr)
            {
              attr->oid = oid;
              ssh_asn1_node_get_data(value, &attr->data, &attr->len);
            }
        }
    }
  *attrs = head;
  return SSH_X509_OK;
}

static SshX509Status
cmp_decode_key_recovery_response(SshAsn1Context context,
                                 SshAsn1Node node,
                                 SshCmpRecResponse krr)
{
  Boolean new_sigcert_found, ca_certs_found, key_hist_found;
  SshAsn1Node new_sigcert_node, ca_certs_node, key_hist_node;
  SshAsn1Node statusnode;

  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (any ())"
                         "  (optional (any (0)))"
                         "  (optional (any (1)))"
                         "  (optional (any (2))))",
                         &statusnode,
                         &new_sigcert_found, &new_sigcert_node,
                         &ca_certs_found, &ca_certs_node,
                         &key_hist_found, &key_hist_node)
      == SSH_ASN1_STATUS_OK)
    {
      SshCmpCertificate c;
      SshGListNode gnode;
      SshAsn1Node list;

      if (cmp_decode_pki_status(context, statusnode, &krr->pki_status)
          != SSH_X509_OK)
        goto failed;

      if (new_sigcert_found)
        {
          if ((c = ssh_calloc(1, sizeof(*c))) == NULL)
            goto failed;
          cmp_cert_init(c);

          if (cmp_decode_key_pair(context, new_sigcert_node, c) == SSH_X509_OK)
            krr->newsigcert = c;
          else
            {
              cmp_cert_clear(c); ssh_free(c);
              goto failed;
            }
        }

      if (key_hist_found)
        {
          for (list = ssh_asn1_node_child(key_hist_node);
               list;
               list = ssh_asn1_node_next(list))
            {
              if ((c = ssh_calloc(1, sizeof(*c))) == NULL)
                goto failed;
              cmp_cert_init(c);

              if (cmp_decode_key_pair(context,
                                      ssh_asn1_node_child(list),
                                      c) == SSH_X509_OK)
                {
                  gnode = ssh_glist_allocate_n(krr->keypairhist);
                  if (gnode == NULL)
                    {
                      cmp_cert_clear(c); ssh_free(c);
                      goto failed;
                    }
                  gnode->data = c;
                  gnode->data_length = sizeof(*c);
                  ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
                }
              else
                {
                  cmp_cert_clear(c); ssh_free(c);
                  goto failed;
                }
            }
        }

      if (ca_certs_found)
        {
          for (list = ca_certs_node; list; list = ssh_asn1_node_next(list))
            {
              if ((c = ssh_calloc(1, sizeof(*c))) == NULL)
                goto failed;
              cmp_cert_init(c);

              if (cmp_decode_key_pair(context, list, c) == SSH_X509_OK)
                {
                  gnode = ssh_glist_allocate_n(krr->cacerts);
                  if (gnode == NULL)
                    {
                      cmp_cert_clear(c); ssh_free(c);
                      goto failed;
                    }

                  gnode->data = c;
                  gnode->data_length = sizeof(*c);
                  ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
                }
              else
                {
                  cmp_cert_clear(c); ssh_free(c);
                  goto failed;
                }
            }
        }
      return SSH_X509_OK;
    }

 failed:
  return SSH_X509_FAILURE;
}

static SshX509Status
cmp_decode_poll(SshAsn1Context context,
                SshAsn1Node node,
                SshGList poll_req_rep,
                Boolean is_response)
{
  SshGListNode gnode;
  SshCmpPollMsg pm;
  SshAsn1Node list, freetext;
  Boolean freetext_found, poll_when_found, content_found;

  if (ssh_asn1_read_node(context, node, "(sequence (*) (any ()))", &list)
      == SSH_ASN1_STATUS_OK)
    {
      content_found = FALSE;
      for (; list; list = ssh_asn1_node_next(list))
        {
          pm = ssh_malloc(sizeof(*pm));
          if (pm == NULL)
            return SSH_X509_FAILED_ASN1_DECODE;
          cmp_poll_init(pm);

          if (ssh_asn1_read_node(context, list,
                                 "(sequence ()"
                                 "  (integer ())"
                                 "  (optional (integer-short ()))"
                                 "  (optional (any ())))",
                                 &pm->request_id,
                                 &poll_when_found, &pm->poll_when,
                                 &freetext_found, &freetext)
              == SSH_ASN1_STATUS_OK)
            {
              if ((freetext_found || poll_when_found) && !is_response)
                {
                  cmp_poll_clear(pm);
                  ssh_free(pm);
                  return SSH_X509_FAILED_ASN1_DECODE;
                }
              if (freetext_found)
                pm->reason = cmp_decode_freetext(context, freetext);

              gnode = ssh_glist_allocate_n(poll_req_rep);
              if (gnode != NULL)
                {
                  gnode->data = pm;
                  gnode->data_length = sizeof(*pm);
                  ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
                  content_found = TRUE;
                }
              else
                {
                  cmp_poll_clear(pm);
                  ssh_free(pm);
                  return SSH_X509_FAILED_ASN1_DECODE;
                }
            }
          else
            {
              cmp_poll_clear(pm);
              ssh_free(pm);
            }
        }
      return content_found ? SSH_X509_OK : SSH_X509_FAILED_UNKNOWN_VALUE;
    }
  return SSH_X509_FAILED_ASN1_DECODE;
}

static SshX509Status
cmp_decode_revocation_response(SshAsn1Context context,
                               SshAsn1Node node,
                               SshCmpRevResponse *revos,
                               SshX509Config config)
{
  SshAsn1Node snode, cnode, crls, issuer;
  SshCmpRevResponse thisrev = NULL, rhead = NULL, prev = NULL;
  int nstatus = 0, nid = 0;
  Boolean cnode_found, crls_found;

  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (sequence () (any ()))"
                         "  (optional (sequence (e 0) (any ())))"
                         "  (optional (any ())))",
                         &snode, &cnode_found, &cnode, &crls_found, &crls)
      == SSH_ASN1_STATUS_OK)
    {
      for (; snode; snode = ssh_asn1_node_next(snode))
        {
          if (rhead)
            {
              prev->next = thisrev = ssh_calloc(1, sizeof(*thisrev));
              prev = thisrev;
            }
          else
            rhead = prev = thisrev = ssh_calloc(1, sizeof(*thisrev));

          if (thisrev == NULL)
            {
              goto failed;
            }

          cmp_rev_response_init(thisrev);
          if (cmp_decode_pki_status(context, snode, &thisrev->status)
              != SSH_X509_OK)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("CMP: decoding RP/Status failed"));
              goto failed;
            }
          nstatus += 1;
        }

      if (cnode_found)
        {
          thisrev = rhead;
          for (; cnode && thisrev; cnode = ssh_asn1_node_next(cnode))
            {
              if ((thisrev->id =
                   ssh_calloc(1, sizeof(*thisrev->id))) == NULL)
                {
                  goto failed;
                }

              ssh_mprz_init(&thisrev->id->serial_no);
              if (ssh_asn1_read_node(context, cnode,
                                     "(sequence () (any ()) (integer ()))",
                                     &issuer, &thisrev->id->serial_no)
                  != SSH_ASN1_STATUS_OK)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("CMP: decoding RP/CertID failed"));
                  ssh_mprz_clear(&thisrev->id->serial_no);
                  goto failed;
                }

              if (ssh_x509_decode_general_name(context,
                                               issuer,
                                               &thisrev->id->issuer,
                                               config)
                  != SSH_X509_OK)
                {
                  ssh_mprz_clear(&thisrev->id->serial_no);
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("CMP: decoding RP/CertID/Issuer failed"));
                  goto failed;
                }
              nid += 1;
              thisrev = thisrev->next;
            }
        }
      if (cnode_found && nid != nstatus)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("CMP: RP; # Status != # CertID"));
          goto failed;
        }

      *revos = rhead;
      return SSH_X509_OK;
    }
  SSH_DEBUG(SSH_D_NETGARB, ("CMP: decoding RP failed"));

 failed:
  cmp_rev_response_clear(rhead);
  return SSH_X509_FAILURE;
}


/* This decodes certificate responses from `node' to `resp' that has
   been allocated by the caller (or actually is part of the body
   structure) */
static SshX509Status
cmp_decode_cert_response(SshAsn1Context context,
                         SshAsn1Node node,
                         SshCmpCertResponse resp)
{
  SshCmpCertResponseNode prev;
  SshAsn1Status status;
  SshAsn1Node ca_pubs, response;
  Boolean ca_pubs_found;
  SshX509Status rv;
  SshMPIntegerStruct req_id;

  status = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (optional"
                              "     (any (e 1)))"
                              "  (sequence ()"
                              "    (any ())))",
                              &ca_pubs_found, &ca_pubs,
                              &response);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  if (ca_pubs_found)
    {
      /* Decode the CA pubs field. */
      rv = cmp_decode_extra_certs(context, ca_pubs, resp->ca_pubs);
      if (rv != SSH_X509_OK)
        goto failed;
    }

  /* Handle the list of responses. */
  ssh_mprz_init_set_si(&req_id, -1);
  for (prev = NULL; response; response = ssh_asn1_node_next(response))
    {
      SshAsn1Node status_node, pair_node;
      SshCmpCertResponseNode pki_response;
      unsigned char *rsp_info;
      size_t rsp_info_len;
      Boolean pair_found, rsp_found;

      status = ssh_asn1_read_node(context, response,
                                  "(sequence ()"
                                  "  (integer ())"
                                  "  (any ())"
                                  "  (optional"
                                  "     (sequence ()"
                                  "       (any ())))"
                                  "  (optional"
                                  "    (octet-string ())))",
                                  &req_id,
                                  &status_node,
                                  &pair_found, &pair_node,
                                  &rsp_found, &rsp_info, &rsp_info_len);

      if (status != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto failed;
        }

      /* Allocate a response. */
      if ((pki_response = ssh_calloc(1, sizeof(*pki_response))) == NULL)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto failed;
        }
      cmp_cert_response_node_init(pki_response);

      /* Handle the reg id. */
      ssh_mprz_set(&pki_response->request_id, &req_id);

      /* Decode the status node. */
      rv = cmp_decode_pki_status(context, status_node,
                                 &pki_response->pki_status);
      if (rv != SSH_X509_OK)
        {
          cmp_cert_response_node_clear(pki_response);
          ssh_free(pki_response);
          goto failed;
        }

      /* Handle the key pair. The sequence from the beginning has
         already been eaten out.*/
      if (pair_found)
        {
          if (cmp_decode_key_pair(context, pair_node, &pki_response->cert)
              != SSH_X509_OK)
            {
              cmp_cert_response_node_clear(pki_response);
              ssh_free(pki_response);
              goto failed;
            }
        }

      /* Handle the response info. */
      if (rsp_found)
        {
          pki_response->rsp_info = rsp_info;
          pki_response->rsp_info_len = rsp_info_len;
          rsp_info = NULL;
        }

      /* Add to the response structure. */
      if (prev == NULL)
        resp->list = pki_response;
      else
        prev->next = pki_response;

      prev = pki_response;
    }
  rv = SSH_X509_OK;

 failed:
  if (rv)
    cmp_cert_response_clear(resp);
  ssh_mprz_clear(&req_id);
  return rv;
}

/* Handle the header. */
static SshX509Status
cmp_decode_header(SshAsn1Context context,
                  SshAsn1Node header,
                  SshCmpHeader pki_header,
                  SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node sender, recipient, protection_alg, free_text, info;
  Boolean msg_time_found, prot_alg_found, sender_kid_found, recip_kid_found,
    sender_nonce_found, recip_nonce_found, free_text_found, info_found,
    trans_id_found;
  SshX509Status rv;

  status =
    ssh_asn1_read_node(context, header,
                       "(sequence ()"
                       "  (integer-short ())"   /* pvno */
                       "  (any ())"             /* sender */
                       "  (any ())"             /* recipient */
                       "  (optional"            /* message time */
                       "    (generalized-time (e 0)))"
                       "  (optional"            /* prot alg */
                       "    (any (e 1)))"
                       "  (optional"            /* skid */
                       "    (octet-string (e 2)))"
                       "  (optional"            /* rkid */
                       "    (octet-string (e 3)))"
                       "  (optional"            /* xid */
                       "    (octet-string (e 4)))"
                       "  (optional"            /* snonce */
                       "    (octet-string (e 5)))"
                       "  (optional"            /* rnonce */
                       "    (octet-string (e 6)))"
                       "  (optional"            /* freetext */
                       "    (any (7)))"
                       "  (optional"            /* info */
                       "    (sequence (8)"
                       "      (any ()))))",
                       &pki_header->pnvo,
                       &sender,
                       &recipient,
                       &msg_time_found, &pki_header->message_time,
                       &prot_alg_found, &protection_alg,
                       &sender_kid_found,
                       &pki_header->sender_kid,
                       &pki_header->sender_kid_len,
                       &recip_kid_found,
                       &pki_header->recip_kid,
                       &pki_header->recip_kid_len,
                       &trans_id_found,
                       &pki_header->transaction_id,
                       &pki_header->transaction_id_len,
                       &sender_nonce_found,
                       &pki_header->sender_nonce,
                       &pki_header->sender_nonce_len,
                       &recip_nonce_found,
                       &pki_header->recip_nonce,
                       &pki_header->recip_nonce_len,
                       &free_text_found, &free_text,
                       &info_found, &info);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Decode the sender. */
  rv = ssh_x509_decode_general_name(context,
                                    sender, &pki_header->sender,
                                    config);
  if (rv != SSH_X509_OK)
    goto failed;

  /* Decode the recipient. */
  rv = ssh_x509_decode_general_name(context,
                                    recipient, &pki_header->recipient,
                                    config);
  if (rv != SSH_X509_OK)
    goto failed;

  /* Decode the protection alg. */
  if (prot_alg_found)
    if ((rv = cmp_decode_protection_info(context, protection_alg,
                                         &pki_header->protection_info))
        != SSH_X509_OK)
      goto failed;

  /* TODO: Decode the free text. */
  if (free_text_found)
    pki_header->freetext = cmp_decode_freetext(context, free_text);
  else
    pki_header->freetext = NULL;

  if (info_found)
    if ((rv = cmp_decode_general_infos(context,
                                       info, &pki_header->general_infos))
        != SSH_X509_OK)
      goto failed;


  rv = SSH_X509_OK;
 failed:
  return rv;
}

static SshX509Status
cmp_decode_body(SshAsn1Context context,
                SshAsn1Node body_node,
                SshCmpBody body,
                SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node   request, response, pkcs10,
    pop_challenge, pop_response,
    key_rec_response, revoc_request, revoc_response,
    key_update, confirm, poll, nested,
    genm, error,
    list;
  SshX509Status rv;
  int which;

  status =
    ssh_asn1_read_node(context, body_node,
                       "(choice"
                       "  (any (e  0))"   /* Initialization request */
                       "  (any (e  1))"   /* Initialization response */
                       "  (any (e  2))"   /* Certification request */
                       "  (any (e  3))"   /* Certification response */
                       "  (any (e  4))"   /* Certification request (PKCS-10) */
                       "  (any (e  5))"   /* pop challenge */
                       "  (any (e  6))"   /* pop response */
                       "  (any (e  7))"   /* key update request */
                       "  (any (e  8))"   /* key update_response */
                       "  (any (e  9))"   /* key recovery request */
                       "  (any (e 10))"   /* key recovery response */
                       "  (any (e 11))"   /* revocation request */
                       "  (any (e 12))"   /* revocation response */
                       "  (any (e 13))"   /* cross-cert. request */
                       "  (any (e 14))"   /* cross-cert. response */
                       "  (any (e 15))"   /* CA key update announcement */
                       "  (any (e 16))"   /* certificate announcement */
                       "  (any (e 17))"   /* revocation announcement */
                       "  (any (e 18))"   /* CRL announcement */
                       "  (any (e 19))"   /* confirmation */
                       "  (any (e 20))"   /* nested message */
                       "  (any (e 21))"   /* general message */
                       "  (any (e 22))"   /* general response */
                       "  (any (e 23))"   /* error message */
                       "  (any (e 24))"   /* cert confirm */
                       "  (any (e 25))"   /* pollingRequest */
                       "  (any (e 26))"   /* pollingResponse */
                       ")",
                       &which,
                       &request, &response,
                       &request, &response,
                       &pkcs10,
                       &pop_challenge, &pop_response,
                       &request, &response,
                       &request, &key_rec_response,
                       &revoc_request, &revoc_response,
                       &request, &response,
                       &key_update,
                       &key_update,
                       &key_update,
                       &key_update,
                       &confirm,
                       &nested,
                       &genm, &genm,
                       &error,
                       &confirm,
                       &poll,
                       &poll);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  rv = SSH_X509_OK;

  body->type = (SshCmpBodyType)which;

  /* Make sure the switch below handles all the message types. Before
     that map any unknown messages to single value, thus avoiding use
     of default at the switch statement. */
  if (which > SSH_CMP_POLL_RESPONSE)
    which = SSH_CMP_MSG_UNKNOWN;

  switch (which)
    {
      /* Handle all the requests. */
    case SSH_CMP_INIT_REQUEST:
    case SSH_CMP_CERT_REQUEST:
    case SSH_CMP_KEY_UP_REQUEST:
    case SSH_CMP_KEY_REC_REQUEST:
    case SSH_CMP_CROSS_REQUEST:
      /* Note. The requests are not actually decoded hence this works. */
      rv = cmp_decode_extra_certs(context,
                                  request,
                                  body->cert_requests);
      break;

      /* Handle the pkcs10. */
    case SSH_CMP_PKCS10_REQUEST:
      break;

      /* Handle all the request responses. */
    case SSH_CMP_INIT_RESPONSE:
    case SSH_CMP_CERT_RESPONSE:
    case SSH_CMP_KEY_UP_RESPONSE:
    case SSH_CMP_CROSS_RESPONSE:
      rv = cmp_decode_cert_response(context, response, &body->cert_response);
      break;

      /* Confirmation. */
    case SSH_CMP_CONFIRM:
      status =
        ssh_asn1_read_node(context, confirm, "(null (*))");
      if (status != SSH_ASN1_STATUS_OK)
        rv = SSH_X509_FAILED_ASN1_DECODE;
      else
        rv = SSH_X509_OK;
      break;

      /* Error message. */
    case SSH_CMP_ERROR_MESSAGE:
      rv = cmp_decode_error_msg(context, error, &body->error_msg);
      break;

      /* Pop challenge. */
    case SSH_CMP_POP_CHALLENGE:
      break;

      /* Pop response. */
    case SSH_CMP_POP_RESPONSE:
      break;

      /* Key recovery response. */
    case SSH_CMP_KEY_REC_RESPONSE:
      rv = cmp_decode_key_recovery_response(context, key_rec_response,
                                            &body->rec_response);
      break;

      /* Revocation request. */
    case SSH_CMP_REVOC_REQUEST:
      break;

      /* Revocation response. */
    case SSH_CMP_REVOC_RESPONSE:
      rv = cmp_decode_revocation_response(context, revoc_response,
                                          &body->rev_response,
                                          config);
      break;

      /* CA key update ann. */
    case SSH_CMP_CA_KEY_UP_ANN:
      break;
      /* Certificate ann. */
    case SSH_CMP_CERT_ANN:
      break;
      /* Revocation ann. */
    case SSH_CMP_REVOC_ANN:
      break;
      /* CRL ann. */
    case SSH_CMP_CRL_ANN:
      break;
      /* Nested */
    case SSH_CMP_NESTED:
      if (body->nested_messages == NULL)
        {
          if ((body->nested_messages = ssh_glist_allocate()) == NULL)
            {
              rv = SSH_X509_FAILURE;
              break;
            }
        }

      if (ssh_asn1_read_node(context, nested, "(sequence (*) (any ()))", &list)
          != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          break;
        }

      for (; list; list = ssh_asn1_node_next(list))
        {
          unsigned char *data;
          SshCmpCertSet c;
          SshGListNode gnode;

          if ((c = ssh_calloc(1, sizeof(*c))) != NULL)
            {
              if (ssh_asn1_node_get_data(list, &data, &c->ber_len)
                  == SSH_ASN1_STATUS_OK)
                {
                  c->ber = data;

                  if ((gnode =
                       ssh_glist_allocate_n(body->nested_messages))
                      != NULL)
                    {
                      gnode->data = c;
                      gnode->data_length = sizeof(*c);
                      ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
                    }
                  else
                    {
                      ssh_free(data);
                      ssh_free(c);
                    }
                }
              else
                {
                  ssh_free(data);
                  ssh_free(c);
                }
            }
        }
      break;
      /* General message. */
    case SSH_CMP_GEN_MESSAGE:
    case SSH_CMP_GEN_RESPONSE:
      rv = cmp_decode_general_infos(context, genm, &body->general_infos);
      break;

      /* Certficate confirm. */
    case SSH_CMP_CERT_CONFIRM:
      break;

    case SSH_CMP_POLL_REQUEST:
      rv = cmp_decode_poll(context, poll, body->poll_req_rep, FALSE);
      break;

    case SSH_CMP_POLL_RESPONSE:
      rv = cmp_decode_poll(context, poll, body->poll_req_rep, TRUE);
      break;

    case SSH_CMP_MSG_UNKNOWN:
      rv = SSH_X509_FAILURE;
      break;

    }
  return rv;
}


static SshX509Status
cmp_decode_message(SshAsn1Context context,
                   SshAsn1Node    msg_node,
                   SshCmpMessage msg)
{
  SshAsn1Status status;
  SshAsn1Node   header, body, protection, extra_certs;
  SshX509Status rv;
  Boolean protection_found, extra_certs_found;

  /* Decode the message. */
  status =
    ssh_asn1_read_node(context, msg_node,
                       "(sequence ()"
                       "  (any ())"    /* header */
                       "  (any ())"    /* body   */
                       "  (optional (any (e 0)))"   /* protection */
                       "  (optional (any (e 1))))", /* extra_certs */
                       &header, &body,
                       &protection_found, &protection,
                       &extra_certs_found, &extra_certs);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  /* Decode the header. */
  rv = cmp_decode_header(context, header, &msg->header, &msg->config);
  if (rv != SSH_X509_OK)
    return rv;

  /* Decode the body. */
  rv = cmp_decode_body(context, body, &msg->body, &msg->config);
  if (rv != SSH_X509_OK)
    return rv;

  /* Build a suitable packet of the body and the header. */
  rv = cmp_encode_protection_data(context, header, body,
                                  &msg->protection, &msg->protection_len);
  if (rv != SSH_X509_OK)
    return rv;

  /* Decode the protection information. */
  if (protection_found)
    {
      unsigned char *data;
      size_t len;

      rv = cmp_decode_protection(context, protection, &data, &len);
      if (rv != SSH_X509_OK)
        return rv;

      if (msg->header.protection_info.signature.pk_type
          ==SSH_X509_PKALG_UNKNOWN)
        {
          msg->header.protection_info.signature.signature = data;
          msg->header.protection_info.signature.signature_len = len / 8;
        }
      else
        {
          msg->header.protection_info.signature.signature =
            ssh_x509_decode_signature(context, data, len,
                                      msg->header.protection_info.signature
                                          .pk_type,
                                     &msg->header.protection_info.signature
                                          .signature_len);
          ssh_free(data);
        }
    }

  if (extra_certs_found)
    {
      /* Decode the extra certs. */
      rv = cmp_decode_extra_certs(context, extra_certs, msg->certificates);
      if (rv != SSH_X509_OK)
        return rv;
    }

  return rv;
}

/* Decode the PKI message. */
SshX509Status ssh_cmp_decode(const unsigned char *buf,
                             size_t buf_len,
                             SshCmpMessage *message)
{
  SshAsn1Context context;
  SshAsn1Status  status;
  SshAsn1Tree    tree;
  SshX509Status  rv;

  /* Initialize the ASN.1 parser. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_X509_FAILURE;

  status = ssh_asn1_decode(context, buf, buf_len, &tree);

  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      /* Return with an error. */
      ssh_asn1_free(context);
      return SSH_X509_FAILURE;
    }

  /* Version will be overwritten later */
  *message = ssh_cmp_allocate(SSH_CMP_VERSION_1);
  rv = cmp_decode_message(context, ssh_asn1_get_root(tree), *message);
  if (rv != SSH_X509_OK)
    {
      ssh_cmp_free(*message);
      *message = NULL;
    }

  /* Free the ASN.1 context. */
  ssh_asn1_free(context);
  return rv;
}

/* eof */
#endif /* SSHDIST_CERT */
