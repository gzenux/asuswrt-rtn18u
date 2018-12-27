/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encoding CMP (RFC2510 and RFC2510bis) messages.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "x509cmp.h"
#include "x509cmp-internal.h"
#include "sshstr.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshX509CmpEncode"

SshX509Status
ssh_x509_crmf_encode_templatep(SshAsn1Context context,
                               SshX509Certificate cert,
                               SshPrivateKey issuer_key,
                               SshAsn1Node  *templatep);

static SshAsn1Node
cmp_encode_general_infos(SshAsn1Context context, SshX509Attribute attrs);

SshX509Status
cmp_encode_protection_data(SshAsn1Context context,
                           SshAsn1Node header, SshAsn1Node body,
                           unsigned char **buf, size_t *buf_len)
{
  SshAsn1Node node, tmp_header = NULL, tmp_body = NULL;
  SshAsn1Status status;

  /* Let us make copies of the input nodes so that they can be used
     later for other things. */
  if (ssh_asn1_copy_node(context, &tmp_header, header) != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  if (body &&
      ssh_asn1_copy_node(context, &tmp_body, body) != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  status = ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                "  (any ())"
                                "  (any ()))",
                                tmp_header,
                                tmp_body);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  /* Now make the BER encoded buffer. */
  if (ssh_asn1_encode_node(context, node) != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  /* Get the encoded blob. */
  ssh_asn1_node_get_data(node, buf, buf_len);
  return SSH_X509_OK;
}

/* Encoding. */

/* Encode a certificate list. */
static SshX509Status
cmp_encode_cert_list(SshAsn1Context context,
                     SshGList glist,
                     SshAsn1Node *cert_list)
{
  SshAsn1Status status;
  SshAsn1Node node, list;
  SshGListNode gnode;

  *cert_list = NULL;

  /* Check for trivial case. */
  if (glist->head == NULL)
    return SSH_X509_OK;

  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshCmpCertificate c;

      c = gnode->data;
      /* Open to ASN.1 */
      if (ssh_asn1_decode_node(context, c->cert, c->cert_len, &node)
          != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;

      list = ssh_asn1_add_list(list, node);
    }

  /* Encode the sequence. */
  status = ssh_asn1_create_node(context, cert_list,
                                "(sequence ()"
                                "  (any ()))", list);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  return SSH_X509_OK;
}

static SshX509Status
cmp_encode_cert(SshAsn1Context context,
                SshGList glist,
                SshAsn1Node *cert)
{
  SshGListNode  gnode;
  SshCmpCertificate c;

  gnode = glist->head;
  if (gnode == NULL)
    {
      *cert = NULL;
      return SSH_X509_OK;
    }

  c = gnode->data;
  /* Open to ASN.1 */
  if (ssh_asn1_decode_node(context, c->cert, c->cert_len, cert)
      != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  return SSH_X509_OK;
}

static SshX509Status
cmp_encode_pki_status(SshAsn1Context context,
                      SshCmpStatusInfo s,
                      SshAsn1Node *s_node)
{
  SshAsn1Status status;
  SshAsn1Node   failure, node, statusstring;
  SshX509Status rv;
  SshWord       s_info;

  /* Convert to SSH word. */
  s_info = s->status;

  if (s->freetext)
    {
      if (ssh_str_get_der(context, s->freetext, SSH_CHARSET_UTF8, &node))
        ssh_asn1_create_node(context, &statusstring,
                             "(sequence () (any ()))", node);
      else
        statusstring = NULL;
    }
  else
    statusstring = NULL;

  /* Build a suitable bit string if suitable error code available. */
  if (s->failure != 0)
    {
      unsigned char *buf;
      size_t         buf_len;

      status = SSH_ASN1_STATUS_OPERATION_FAILED;
      if ((buf = ssh_x509_ui_to_bs(s->failure, &buf_len)) != NULL)
        status = ssh_asn1_create_node(context, &failure,
                                      "(bit-string ())", buf, buf_len);
      ssh_free(buf);
      if (status != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }
    }
  else
    failure = NULL;

  status =
    ssh_asn1_create_node(context, s_node,
                         "(sequence ()"
                         "  (integer-short ())"
                         "  (any ())"
                         "  (any ()))", s_info, statusstring, failure);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  rv = SSH_X509_OK;
 failed:

  return rv;
}

static SshX509Status
cmp_encode_error_msg(SshAsn1Context context,
                     SshCmpErrorMsg errormsg,
                     SshAsn1Node *msg_node)
{
  SshAsn1Status status;
  SshAsn1Node   pki_status, code, node, details;
  SshX509Status rv;

  /* Encode the status information. */
  rv = cmp_encode_pki_status(context, &errormsg->status, &pki_status);
  if (rv != SSH_X509_OK)
    return rv;

  /* Encode the error code if available. */
  if (ssh_mprz_cmp_ui(&errormsg->error_code, 0) >= 0)
    {
      status =
        ssh_asn1_create_node(context, &code,
                             "(integer ())",
                             &errormsg->error_code);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;
    }
  else
    code = NULL;

  details = NULL;
  if (errormsg->details)
    {
      if (ssh_str_get_der(context, errormsg->details, SSH_CHARSET_UTF8, &node))
        ssh_asn1_create_node(context, &details,
                             "(sequence () (any ()))", node);
    }

  status =
    ssh_asn1_create_node(context, msg_node,
                         "(sequence ()"
                         "  (any ())"
                         "  (any ())"
                         "  (any ()))", pki_status, code, details);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_ENCODE;

  return SSH_X509_OK;
}

static SshX509Status
cmp_encode_key_pair(SshAsn1Context context,
                    SshCmpCertificate pair,
                    SshAsn1Node *node)
{
  /* Fill the key pair. */
  if (pair)
    {
      SshAsn1Node private_key = NULL, publication_info = NULL, cert;
      SshAsn1Node tmp_cert;
      SshAsn1Status status;




      status = ssh_asn1_decode_node(context,
                                    pair->cert, pair->cert_len,
                                    &tmp_cert);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if (!pair->encrypted)
        status = ssh_asn1_create_node(context, &cert, "(any (e 0))", tmp_cert);
      else
        status = ssh_asn1_create_node(context, &cert, "(any (e 1))", tmp_cert);

      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if (pair->prvkey == NULL
          || ssh_asn1_decode_node(context,
                                  pair->prvkey, pair->prvkey_len,
                                  &private_key) != SSH_ASN1_STATUS_OK)
        private_key = NULL;

      status =
        ssh_asn1_create_node(context, node,
                             "(sequence ()"
                             "  (any ())"
                             "  (any (e 0))"
                             "  (any (e 1)))",
                             cert, private_key, publication_info);

      if (status != SSH_ASN1_STATUS_OK)
          goto failed;

      return SSH_X509_OK;
    }

 failed:
  return SSH_X509_FAILURE;
}

static SshX509Status
cmp_encode_cert_response(SshAsn1Context context,
                         SshCmpCertResponse resp,
                         SshAsn1Node *resp_node)
{
  SshAsn1Status status;
  SshAsn1Node   ca_pubs, response_list, key_pair = NULL;
  SshCmpCertResponseNode cursor;
  SshX509Status rv;

  /* Encode the CA pubs. */
  rv = cmp_encode_cert_list(context, resp->ca_pubs, &ca_pubs);
  if (rv != SSH_X509_OK)
    return rv;

  /* Encode the response list. */
  response_list = NULL;

  for (cursor = resp->list; cursor; cursor = cursor->next)
    {
      SshAsn1Node node, pki_status, rsp_info;

      /* Encode PKI status. */
      rv = cmp_encode_pki_status(context,
                                 &cursor->pki_status, &pki_status);
      if (rv != SSH_X509_OK)
        {
          rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }

      if (cursor->pki_status.status == SSH_CMP_STATUS_GRANTED ||
          cursor->pki_status.status == SSH_CMP_STATUS_GRANTED_WITH_MODS)
        {
          if (cmp_encode_key_pair(context, &cursor->cert, &key_pair)
              != SSH_X509_OK)
            {
              rv = SSH_X509_FAILED_ASN1_ENCODE;
              goto failed;
            }
        }
      /* Encode the rsp info. */
      if (cursor->rsp_info)
        {
          status =
            ssh_asn1_create_node(context, &rsp_info,
                                 "(octet-string ())",
                                 cursor->rsp_info, cursor->rsp_info_len);
          if (status != SSH_ASN1_STATUS_OK)
            {
              rv = SSH_X509_FAILED_ASN1_ENCODE;
              goto failed;
            }
        }
      else
        rsp_info = NULL;

      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (integer ())"
                             "  (any ())"
                             "  (any ())"
                             "  (any ()))",
                             &cursor->request_id,
                             pki_status,
                             key_pair,
                             rsp_info);
      if (status != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }

      response_list = ssh_asn1_add_list(response_list, node);
    }

  status =
    ssh_asn1_create_node(context, resp_node,
                         "(sequence ()"
                         "  (any (e 1))"
                         "  (sequence ()"
                         "    (any ())))",
                         ca_pubs,
                         response_list);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }
  rv = SSH_X509_OK;

 failed:
  return rv;
}

/* Encode CertConfirm content. Returns valid Asn.1 node if all the
   elements at the argument list `conf' were successfully encoded, or
   NULL, if even one failed. */
static SshX509Status
cmp_encode_cert_confirm(SshAsn1Context context,
                        SshGList confs,
                        SshAsn1Node *node)
{
  SshAsn1Node list = NULL, tmp, statusnode;
  SshAsn1Status status;
  SshGListNode gnode;
  SshCmpCertConf conf;

  for (gnode = confs->head; gnode; gnode = gnode->next)
    {
      conf = gnode->data;
      if (cmp_encode_pki_status(context,
                                &conf->pki_status,
                                &statusnode) != SSH_X509_OK)
        return SSH_X509_FAILURE;

      if (conf->request_id_set)
        status = ssh_asn1_create_node(context, &tmp,
                                      "(sequence ()"
                                      "  (octet-string ())"
                                      "  (integer ())"
                                      "  (any ()))",
                                      conf->hash, conf->hash_len,
                                      &conf->request_id,
                                      statusnode);
      else
        status = ssh_asn1_create_node(context, &tmp,
                                      "(sequence ()"
                                      "  (octet-string ())"
                                      "  (any ()))",
                                      conf->hash, conf->hash_len,
                                      statusnode);
      if (status == SSH_ASN1_STATUS_OK)
        list = ssh_asn1_add_list(list, tmp);
    }
  if (list)
    {
      status = ssh_asn1_create_node(context, node,
                                    "(sequence () (any ()))", list);
      if (status != SSH_ASN1_STATUS_OK)
        *node = NULL;
    }
  else
    {
      *node = NULL;
    }
  return SSH_X509_OK;
}


static SshX509Status
cmp_encode_revocation_request(SshAsn1Context context,
                              SshGList revos,
                              SshAsn1Node *node)
{
  SshAsn1Node list = NULL, tmp, cert_template, crl_extensions;
  SshGListNode gnode;
  SshAsn1Status status;
  SshCmpRevRequest revo;

  for (gnode = revos->head; gnode; gnode = gnode->next)
    {
      revo = gnode->data;





      if (revo->crl_extensions)
        crl_extensions = NULL;
      else
        crl_extensions = NULL;

      /* here the cert_template may contain certificate or template
         not signed. Handle both cases. */
      if (revo->cert_template)
        {
          SshX509Certificate c;

          /* First check if it a certificate. If so, convert into
             cert_template node. */
          c = ssh_x509_cert_allocate(SSH_X509_PKIX_CRMF);
          if (ssh_x509_cert_decode(revo->cert_template->cert,
                                   revo->cert_template->cert_len,
                                   c) == SSH_X509_OK)
            {
              if (ssh_x509_crmf_encode_templatep(context,
                                                 c, NULL, &cert_template)
                  != SSH_X509_OK)
                cert_template = NULL;
            }
          else
            {
              (void)ssh_asn1_decode_node(context,
                                         revo->cert_template->cert,
                                         revo->cert_template->cert_len,
                                         &cert_template);
            }
          ssh_x509_cert_free(c);
        }
      else
        cert_template = NULL;

      /* Make RevDetails */
      status = ssh_asn1_create_node(context, &tmp,
                                    "(sequence ()"
                                    "  (any ())"
                                    "  (any ()))",
                                    cert_template, crl_extensions);
      if (status == SSH_ASN1_STATUS_OK)
        list = ssh_asn1_add_list(list, tmp);
    }

  /* Make RevReqContent */
  if (list)
    {
      status = ssh_asn1_create_node(context, node,
                                    "(sequence () (any ()))", list);
      if (status != SSH_ASN1_STATUS_OK)
        *node = NULL;
    }
  else
    {
      *node = NULL;
    }

  return SSH_X509_OK;
}


static SshAsn1Node
cmp_encode_protection_info(SshAsn1Context context,
                           SshCmpProtectionInfo info)
{
  SshAsn1Node node;

  if (info->prv_key)
    {
      node = ssh_x509_encode_sigalg(context, info->prv_key);
    }
  else
    {
      if (info->pswbmac)
        {
          node = ssh_pswbmac_encode_param(context, info->pswbmac);
        }
      else
        {
          return NULL;
        }
    }
  return node;
}

static SshAsn1Node
cmp_encode_general_infos(SshAsn1Context context, SshX509Attribute attrs)
{
  SshX509Attribute attr;
  SshAsn1Status status;
  SshAsn1Node list = NULL, node, value;

  for (attr = attrs; attr; attr = attr->next)
    {
      if ((ssh_asn1_decode_node(context, attr->data, attr->len, &value)
           == SSH_ASN1_STATUS_OK) &&
          (ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                "  (object-identifier ())"
                                "  (set () (any ())))", attr->oid, value)
           == SSH_ASN1_STATUS_OK))
        {
          list = ssh_asn1_add_list(list, node);
        }
    }
  if (list)
    {
      status = ssh_asn1_create_node(context, &node,
                                    "(sequence () (any ()))", list);
      if (status != SSH_ASN1_STATUS_OK)
        node = NULL;
    }
  else
    {
      node = NULL;
    }

  return node;
}

/* Pki body. */

static SshX509Status
cmp_encode_body(SshAsn1Context context,
                SshCmpBody body,
                SshAsn1Node *body_node,
                SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node node = NULL, tmp, list, freetext;
  SshX509Status rv = SSH_X509_OK;
  int which;
  SshGListNode gnode;
  unsigned char format[32];

  which = body->type;
  if (which > SSH_CMP_POLL_RESPONSE)
    which = SSH_CMP_MSG_UNKNOWN;

  switch (which)
    {
      /* Encode the requests. */
    case SSH_CMP_INIT_REQUEST:
    case SSH_CMP_CERT_REQUEST:
    case SSH_CMP_KEY_UP_REQUEST:
    case SSH_CMP_KEY_REC_REQUEST:
    case SSH_CMP_CROSS_REQUEST:
      rv = cmp_encode_cert_list(context, body->cert_requests, &node);
      break;
      /* Encode the response. */
    case SSH_CMP_INIT_RESPONSE:
    case SSH_CMP_CERT_RESPONSE:
    case SSH_CMP_KEY_UP_RESPONSE:
    case SSH_CMP_CROSS_RESPONSE:
      rv = cmp_encode_cert_response(context,
                                    &body->cert_response, &node);
      break;
      /* Encode the PKCS-10. */
    case SSH_CMP_PKCS10_REQUEST:
      rv = cmp_encode_cert(context,
                           body->cert_requests, &node);

      break;
      /* Encode the confirm message. */
    case SSH_CMP_CONFIRM:
      status = ssh_asn1_create_node(context, &node, "(null ())");
      if (status != SSH_ASN1_STATUS_OK)
        rv = SSH_X509_FAILED_ASN1_ENCODE;
      else
        rv = SSH_X509_OK;
      break;
      /* Error message. */
    case SSH_CMP_ERROR_MESSAGE:
      rv = cmp_encode_error_msg(context,
                                &body->error_msg, &node);
      break;
      /* Pop challenge. */
    case SSH_CMP_POP_CHALLENGE:
      break;
      /* Pop response. */
    case SSH_CMP_POP_RESPONSE:
      /* Key recovery response. */
    case SSH_CMP_KEY_REC_RESPONSE:
      break;
      /* Revocation request. */
    case SSH_CMP_REVOC_REQUEST:
      rv = cmp_encode_revocation_request(context,
                                         body->rev_requests, &node);
      break;
      /* Revocation response. */
    case SSH_CMP_REVOC_RESPONSE:
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

      list = NULL;
      if (body->nested_messages != NULL)
        for (gnode = body->nested_messages->head; gnode; gnode = gnode->next)
          {
            SshCmpCertSet c = gnode->data;

            (void)ssh_asn1_decode_node(context, c->ber, c->ber_len, &tmp);
            status = ssh_asn1_create_node(context, &node, "(any ())", tmp);
            if (status == SSH_ASN1_STATUS_OK)
              list = ssh_asn1_add_list(list, node);
          }
      if (list)
        {
          status = ssh_asn1_create_node(context, &node,
                                        "(sequence () (any ()))", list);
          if (status != SSH_ASN1_STATUS_OK)
            node = NULL;
        }
      else
        {
          node = NULL;
        }

      break;
      /* General message. */
    case SSH_CMP_GEN_MESSAGE:
    case SSH_CMP_GEN_RESPONSE:
      status = SSH_ASN1_STATUS_OK;
      node = cmp_encode_general_infos(context, body->general_infos);
      if (!node)
        status = ssh_asn1_create_node(context, &node,
                                      "(sequence () (null ()))");
      if (status != SSH_ASN1_STATUS_OK)
        rv = SSH_X509_FAILED_ASN1_ENCODE;
      else
        rv = SSH_X509_OK;
      break;
      /* Certficate confirm. */
    case SSH_CMP_CERT_CONFIRM:
      rv = cmp_encode_cert_confirm(context, body->cert_confirm, &node);
      break;

    case SSH_CMP_POLL_REQUEST:
    case SSH_CMP_POLL_RESPONSE:
      list = NULL;
      if (body->poll_req_rep)
        {
          for (gnode = body->poll_req_rep->head; gnode; gnode = gnode->next)
            {
              SshCmpPollMsg pm = gnode->data;
              if (pm->this_is_response)
                {
                  if (pm->reason)
                    {
                      if (ssh_str_get_der(context, pm->reason,
                                          SSH_CHARSET_UTF8,
                                          &freetext) == FALSE)
                        freetext = NULL;
                    }
                  else
                    freetext = NULL;

                  status = ssh_asn1_create_node(context, &tmp,
                                                "(sequence ()"
                                                "  (integer ())"
                                                "  (integer-short ())"
                                                "  (any ()))",
                                                &pm->request_id,
                                                pm->poll_when,
                                                freetext);
                }
              else
                {
                  status = ssh_asn1_create_node(context, &tmp,
                                                "(sequence () (integer ()))",
                                                &pm->request_id);
                }
              if (status == SSH_ASN1_STATUS_OK)
                list = ssh_asn1_add_list(list, tmp);
            }
        }
      if (list)
        {
         status = ssh_asn1_create_node(context, &node,
                                       "(sequence () (any ()))", list);
         if (status != SSH_ASN1_STATUS_OK)
           node = NULL;
        }
      else
        {
          node = NULL;
        }
      break;

      /* Unsupported cases. */
    case SSH_CMP_MSG_UNKNOWN:
      rv = SSH_X509_FAILURE;
      break;
    }

  if (rv != SSH_X509_OK)
    goto failed;

  ssh_snprintf(format, sizeof(format), "(any (e %d))", (int)which);
  status = ssh_asn1_create_node(context, body_node,
                                ssh_sstr(format), node);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

 failed:
  return rv;
}

/* Pki Header. */
static SshX509Status
cmp_encode_header(SshAsn1Context context,
                  SshCmpHeader hdr,
                  SshAsn1Node *header_node,
                  SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node   sender, recipient, message_time, sender_kid,
    recip_kid, transaction_id, sender_nonce, recip_nonce, protection_alg,
    info, freetext;
  SshX509Status rv = SSH_X509_FAILED_ASN1_ENCODE;

  /* Encode sender. */
  sender = ssh_x509_encode_general_name_list(context, hdr->sender, config);
  if (sender == NULL)
    {
      status = ssh_asn1_create_node(context,
                                    &sender,
                                    "(sequence (e 4) (any ()))", NULL);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
    }

  /* Encode recipient. */
  recipient = ssh_x509_encode_general_name_list(context, hdr->recipient,
                                                config);
  if (recipient == NULL)
    {
      status = ssh_asn1_create_node(context,
                                    &recipient,
                                    "(sequence (e 4) (any ()))", NULL);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
    }

  /* Set in the generalized message time. */
  if (ssh_ber_time_available(&hdr->message_time))
    {
      status = ssh_asn1_create_node(context, &message_time,
                                    "(generalized-time ())",
                                    &hdr->message_time);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
    }
  else
    message_time = NULL;

#define SETSTRING(context, which, which_len, where)                      \
do {                                                                     \
  SshAsn1Status _status;                                                 \
  if ((which) && ((which_len) > 0))                                      \
    {                                                                    \
      _status =                                                          \
        ssh_asn1_create_node((context), &(where),                        \
                             "(octet-string ())", (which), (which_len)); \
      if (_status != SSH_ASN1_STATUS_OK)                                 \
        goto failed;                                                     \
    }                                                                    \
  else                                                                   \
    (where) = NULL;                                                      \
} while (0)

  SETSTRING(context, hdr->sender_kid, hdr->sender_kid_len, sender_kid);
  SETSTRING(context, hdr->recip_kid, hdr->recip_kid_len, recip_kid);
  SETSTRING(context, hdr->sender_nonce, hdr->sender_nonce_len, sender_nonce);
  SETSTRING(context, hdr->recip_nonce, hdr->recip_nonce_len, recip_nonce);
  SETSTRING(context, hdr->transaction_id, hdr->transaction_id_len,
            transaction_id);

  /* Protection alg. */
  protection_alg =
    cmp_encode_protection_info(context, &hdr->protection_info);

  freetext = NULL;
  if (hdr->freetext)
    {
      SshAsn1Node node;

      if (ssh_str_get_der(context, hdr->freetext, SSH_CHARSET_UTF8, &node))
        ssh_asn1_create_node(context, &freetext,
                             "(sequence () (any ()))", node);
    }

  info = cmp_encode_general_infos(context, hdr->general_infos);

  /* Encode. */
  status =
    ssh_asn1_create_node(context, header_node,
                         "(sequence ()"
                         "  (integer-short ())" /* pnvo */
                         "  (any ())"           /* sender */
                         "  (any ())"           /* recipient */
                         "  (any (e 0))"        /* time */
                         "  (any (e 1))"        /* protection */
                         "  (any (e 2))"        /* skid */
                         "  (any (e 3))"        /* rkid */
                         "  (any (e 4))"        /* xid */
                         "  (any (e 5))"        /* snonce */
                         "  (any (e 6))"        /* rnonce */
                         "  (any (e 7))"        /* freetext */
                         "  (any (e 8)))",      /* info */
                         hdr->pnvo,
                         sender, recipient,
                         message_time, protection_alg,
                         sender_kid, recip_kid,
                         transaction_id,
                         sender_nonce, recip_nonce,
                         freetext, info);

  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = SSH_X509_OK;
 failed:
  return rv;
}

/* This structure holds the state during signature operation. */
typedef struct CmpEncodeContextRec
{
  SshCmpMessage message;
  SshAsn1Context asn1context;
  SshAsn1Node header;
  SshAsn1Node body;
  SshOperationHandle signature_op, encode_op;
  SshPrivateKey key;
  SshCmpEncodeCB callback;
  void *callback_context;
} *CmpEncodeContext, CmpEncodeContextStruct;


static void cmp_encode_abort(void *ctx)
{
  CmpEncodeContext context = ctx;

  ssh_operation_abort(context->signature_op);
  ssh_asn1_free(context->asn1context);
  ssh_free(context);
}

/* signature buffer length comes in bytes here */
static void
cmp_encode_done(SshCryptoStatus cstatus,
                const unsigned char *sig, size_t sig_len,
                void *ctx)
{
  CmpEncodeContext context = ctx;
  SshAsn1Status status;
  unsigned char *buf = NULL, *prot = NULL;
  size_t buf_len, prot_len;
  SshX509Status rv;
  SshAsn1Node protection = NULL, toplevel, extra_certs;
  SshAsn1Tree tree;

  if (cstatus != SSH_CRYPTO_OK)
    {
      (*context->callback)(SSH_X509_FAILED_PRIVATE_KEY_OPS,
                           NULL, 0, context->callback_context);
      goto cleanup;
    }

  if (context->key)
    prot = ssh_x509_encode_signature(context->asn1context,
                                     sig, sig_len, context->key, &prot_len);
  else
    {
      if ((prot = ssh_memdup(sig, sig_len)) == NULL)
        {
          (*context->callback)(SSH_X509_FAILED_SIGNATURE_ALGORITHM_ENCODE,
                               NULL, 0, context->callback_context);
          goto cleanup;
        }
      prot_len = sig_len * 8;
    }

  /* Build the protection node. */
  if (prot_len &&
      (status = ssh_asn1_create_node(context->asn1context,
                                     &protection,
                                     "(bit-string ())", prot, prot_len))
      != SSH_ASN1_STATUS_OK)
    {
      (*context->callback)(SSH_X509_FAILED_ASN1_ENCODE,
                           NULL, 0, context->callback_context);
      goto cleanup;
    }

  if ((rv = cmp_encode_cert_list(context->asn1context,
                                 context->message->certificates,
                                 &extra_certs))
      != SSH_X509_OK)
    {
      (*context->callback)(rv, NULL, 0, context->callback_context);
      goto cleanup;
    }

  /* Create the output. */
  status = ssh_asn1_create_node(context->asn1context, &toplevel,
                                "(sequence ()"
                                "  (any ())"
                                "  (any ())"
                                "  (any (e 0))"
                                "  (any (e 1)))",
                                context->header, context->body,
                                protection, extra_certs);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_ENCODE;
      (*context->callback)(SSH_X509_FAILED_ASN1_ENCODE,
                           NULL, 0, context->callback_context);
      goto cleanup;
    }

  /* Construct a tree out of the certificate. */

  if ((tree =
       ssh_asn1_init_tree(context->asn1context, toplevel, toplevel))
      == NULL ||
      (status = ssh_asn1_encode(context->asn1context, tree))
      != SSH_ASN1_STATUS_OK)
    {
      (*context->callback)(SSH_X509_FAILED_ASN1_ENCODE,
                           NULL, 0, context->callback_context);
      goto cleanup;
    }

  ssh_asn1_get_data(tree, &buf, &buf_len);
  (*context->callback)(SSH_X509_OK, buf, buf_len, context->callback_context);

 cleanup:
  if (prot) ssh_free(prot);
  if (buf) ssh_free(buf);
  if (context->encode_op)
    ssh_operation_unregister(context->encode_op);
  ssh_asn1_free(context->asn1context);
  ssh_free(context);
  return;
}

/* Encode the PKI message. */
SshOperationHandle
ssh_cmp_encode(SshCmpMessage message,
               SshPrivateKey signing_key,
               SshCmpEncodeCB callback, void *callback_context)
{
  SshAsn1Context asn1context;
  SshAsn1Node header, body;
  SshX509Status rv;
  SshOperationHandle signop = NULL;
  CmpEncodeContext context;
  unsigned char *prot;
  size_t prot_len;
  SshCmpProtectionInfo info;

  /* Initialize the ASN.1 allocation context. */
  if ((asn1context = ssh_asn1_init()) == NULL)
    {
      (*callback)(SSH_X509_FAILED_ASN1_ENCODE, NULL, 0, callback_context);
      return NULL;
    }

  info = &message->header.protection_info;
  info->prv_key = signing_key;

  SSH_TRACE(8, ("Signing key: %p", signing_key));

  /* First create the header and body for encoding protection. */
  if ((rv = cmp_encode_header(asn1context,
                              &message->header, &header,
                              &message->config))
      != SSH_X509_OK)
    {
      (*callback)(SSH_X509_FAILED_ASN1_ENCODE, NULL, 0, callback_context);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  if ((rv = cmp_encode_body(asn1context,
                            &message->body, &body,
                            &message->config))
      != SSH_X509_OK)
    {
      (*callback)(SSH_X509_FAILED_ASN1_ENCODE, NULL, 0, callback_context);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  /* Then encode the data to be protected. */
  if ((rv = cmp_encode_protection_data(asn1context,
                                       header, body,
                                       &prot, &prot_len))
      != SSH_X509_OK)
    {
      (*callback)(SSH_X509_FAILED_ASN1_ENCODE, NULL, 0, callback_context);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  if ((context = ssh_calloc(1, sizeof(*context))) == NULL)
    {
      (*callback)(SSH_X509_FAILED_ASN1_ENCODE, NULL, 0, callback_context);
      ssh_free(prot);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  context->message = message;
  context->asn1context = asn1context;
  context->header = header;
  context->body = body;
  context->callback = callback;
  context->callback_context = callback_context;
  context->key = signing_key;
  context->signature_op = NULL;

  /* And perform approriate protection calculation. */
  if (signing_key)
    {
      context->encode_op = ssh_operation_register(cmp_encode_abort, context);
      signop =
        ssh_private_key_sign_async(signing_key,
                                   prot, prot_len, cmp_encode_done, context);
      if (signop)
        context->signature_op = signop;
    }
  else if (info->pswbmac)
    {
      SshMac mac;

      if ((mac = ssh_pswbmac_allocate_mac(info->pswbmac,
                                          info->key, info->key_length))
          == NULL)
        {
          (*callback)(SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK,
                      NULL, 0,
                      callback_context);
          ssh_asn1_free(asn1context);
          ssh_free(context);
          ssh_free(prot);
          return NULL;
        }
      else
        {
          unsigned char *hmac;
          size_t hmac_len;

          hmac_len = ssh_mac_length(ssh_mac_name(mac));
          hmac = ssh_malloc(hmac_len);

          ssh_mac_update(mac, prot, prot_len);
          ssh_mac_final(mac, hmac);

          SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("Protected data, len %d is",
                                          prot_len),
                            prot, prot_len);
          SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Signature len %d is",
                                           hmac_len),
                            hmac, hmac_len);

          cmp_encode_done(SSH_CRYPTO_OK, hmac, hmac_len, context);

          ssh_mac_free(mac);
          ssh_free(hmac);
          ssh_free(prot);
          return NULL;
        }
    }
  else
    {
      cmp_encode_done(SSH_CRYPTO_OK, NULL, 0, context);
    }
  ssh_free(prot);
  return (signop != NULL)?(context->encode_op):(NULL);
}

/* eof */
#endif /* SSHDIST_CERT */
