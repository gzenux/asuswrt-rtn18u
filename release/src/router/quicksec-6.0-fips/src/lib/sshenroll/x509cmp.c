/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CMP (Certificate Management Protocol) API functions.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "x509.h"
#include "x509internal.h"
#include "x509cmp.h"
#include "x509cmp-internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshX509Cmp"

/* The main interface functions. */

/* The actual allocation and free. */
SshCmpMessage ssh_cmp_allocate(SshCmpVersion pnvo)
{
  SshCmpMessage message;
  SshX509Config pc;

  if ((message = ssh_calloc(1, sizeof(*message))) != NULL)
    {
      cmp_message_init(message);
      message->header.pnvo = pnvo;

      pc = ssh_x509_get_configuration();
      memmove(&message->config, pc, sizeof(*pc));
    }

  return message;
}

void ssh_cmp_free(SshCmpMessage message)
{
  if (message)
    {
      cmp_message_clear(message);
      ssh_free(message);
    }
}

SshCmpVersion ssh_cmp_version(SshCmpMessage message)
{
  return message->header.pnvo;
}

/* Set the name fields to the header. This function is required by the
   CMP draft. This function adds the names to the PKI message sender
   and recipient name lists. */
void
ssh_cmp_header_set_names(SshCmpMessage message,
                         SshX509Name sender, SshX509Name recipient)
{
  ssh_x509_name_push(&message->header.sender, sender);
  ssh_x509_name_push(&message->header.recipient, recipient);
}

void
ssh_cmp_header_get_names(SshCmpMessage message,
                         SshX509Name * const sender,
                         SshX509Name * const recipient)
{
  if (sender)
    *sender = message->header.sender;
  if (recipient)
    *recipient = message->header.recipient;
}

void
ssh_cmp_header_get_key_id(SshCmpMessage message,
                          const unsigned char **sender_kid,
                          size_t *sender_kid_len,
                          const unsigned char **recipient_kid,
                          size_t *recipient_kid_len)
{
  if (sender_kid)
    *sender_kid = message->header.sender_kid;
  if (sender_kid_len)
    *sender_kid_len = message->header.sender_kid_len;
  if (recipient_kid)
    *recipient_kid = message->header.recip_kid;
  if (recipient_kid_len)
    *recipient_kid_len = message->header.recip_kid_len;
}

void
ssh_cmp_header_set_key_id(SshCmpMessage message,
                          const unsigned char *sender_kid,
                          size_t sender_kid_len,
                          const unsigned char *recipient_kid,
                          size_t recipient_kid_len)
{
  if ((message->header.sender_kid =
       ssh_memdup(sender_kid, sender_kid_len)) != NULL)
    message->header.sender_kid_len = sender_kid_len;
  if ((message->header.recip_kid =
       ssh_memdup(recipient_kid, recipient_kid_len)) != NULL)
    message->header.recip_kid_len = recipient_kid_len;
}

void
ssh_cmp_header_set_pswbmac(SshCmpMessage message,
                           SshPSWBMac pswbmac,
                           const unsigned char *key, size_t key_len)
{
  message->header.protection_info.pswbmac = pswbmac;
  if ((message->header.protection_info.key = ssh_memdup(key, key_len)) != NULL)
    message->header.protection_info.key_length = key_len;
}


SshCmpProtectionType
ssh_cmp_header_protection_type(SshCmpMessage message)
{
  if (message->header.protection_info.pswbmac)
    return SSH_CMP_PROT_SHARED_SECRET;

  switch (message->header.protection_info.signature.pk_type)
    {
    case SSH_X509_PKALG_RSA:
      return SSH_CMP_PROT_SIGNATURE;
    case SSH_X509_PKALG_DSA:
      return SSH_CMP_PROT_SIGNATURE;
    case SSH_X509_PKALG_ELGAMAL:
      return SSH_CMP_PROT_SIGNATURE;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_X509_PKALG_ECDSA:
      return SSH_CMP_PROT_SIGNATURE;
#endif /* SSHDIST_CRYPT_ECP */
    case SSH_X509_PKALG_DH:
      return SSH_CMP_PROT_DH_KEY_PAIR;
    case SSH_X509_PKALG_UNKNOWN:
    default:
      break;
    }
  return SSH_CMP_PROT_UNKNOWN;
}

Boolean
ssh_cmp_header_verify_pswbmac(SshCmpMessage message,
                              const unsigned char *key, size_t key_len)
{
  SshMac mac;
  unsigned char *prot;
  size_t prot_len;

  if (message->header.protection_info.pswbmac == NULL)
    return FALSE;

  mac = ssh_pswbmac_allocate_mac(message->header.protection_info.pswbmac,
                                 key, key_len);
  if (mac == NULL)
    return FALSE;

  /* Compute the mac. */
  prot_len = ssh_mac_length(ssh_mac_name(mac));
  if ((prot = ssh_malloc(prot_len)) == NULL)
    {
      ssh_mac_free(mac);
      return FALSE;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("Protected data, len %d is",
                                  message->protection_len),
                    message->protection, message->protection_len);

  ssh_mac_update(mac, message->protection, message->protection_len);
  ssh_mac_final(mac, prot);
  ssh_mac_free(mac);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Signature at the message, len %d is",
                                   message->header.protection_info.
                                   signature.signature_len),
                    message->header.protection_info.signature.signature,
                    message->header.protection_info.signature.signature_len);

  /* Check that the protection matches. */
  if (prot_len == message->header.protection_info.signature.signature_len)
    {
      if (memcmp(prot, message->header.protection_info.signature.signature,
                 prot_len) == 0)
        {
          ssh_free(prot);
          return TRUE;
        }
    }
  ssh_free(prot);
  return FALSE;
}

typedef struct CmpVerifyContextRec
{
  SshOperationHandle signature_op;
  SshPublicKey key;
  const char *sign;
  SshCmpVerifyCB callback;
  void *callback_context;
  SshX509Status status;
  SshTimeoutStruct timeout;
} *CmpVerifyContext, CmpVerifyContextStruct;

static void cmp_verify_abort(void *ctx)
{
  CmpVerifyContext context = ctx;

  ssh_operation_abort(context->signature_op);
  (void) ssh_public_key_select_scheme(context->key,
                               SSH_PKF_SIGN, context->sign,
                               SSH_PKF_END);
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, context);
  ssh_free(context);
}

static void cmp_verify_complete_later(void *ctx)
{
  CmpVerifyContext context = ctx;

  (*context->callback)(context->status, context->callback_context);
  ssh_free(context);
}

static void cmp_verify_done(SshCryptoStatus status,
                            void *ctx)
{
  CmpVerifyContext context = ctx;

  context->status = (status == SSH_CRYPTO_OK) ?
    SSH_X509_OK : SSH_X509_FAILED_SIGNATURE_CHECK;
  (void) ssh_public_key_select_scheme(context->key,
                               SSH_PKF_SIGN, context->sign,
                               SSH_PKF_END);

  ssh_register_timeout(&context->timeout,
                       0L, 0L, cmp_verify_complete_later, context);
}

SshOperationHandle
ssh_cmp_header_verify_signature(SshCmpMessage message,
                                const SshPublicKey issuer_key,
                                SshCmpVerifyCB callback,
                                void *callback_context)
{
  const char *sign, *key_type;
  const SshX509PkAlgorithmDefStruct *algorithm;
  CmpVerifyContext context;
  SshOperationHandle op, signop;

  if ((issuer_key == NULL) ||
      (message->header.protection_info.signature.pk_algorithm == NULL) ||
      (ssh_public_key_get_info(issuer_key,
                               SSH_PKF_KEY_TYPE, &key_type,
                               SSH_PKF_SIGN, &sign,
                               SSH_PKF_END) != SSH_CRYPTO_OK))
    {
      (*callback)(SSH_X509_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  /* Check that this implementation supports the given algorithm and
     key type pair. */
  algorithm =
    ssh_x509_match_algorithm(key_type,
                             message->header.
                                      protection_info.
                                      signature.pk_algorithm,
                             NULL);
  if (algorithm == NULL)
    {
      (*callback)(SSH_X509_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(issuer_key,
                                   SSH_PKF_SIGN,
                                   message->header.
                                            protection_info.
                                            signature.pk_algorithm,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      (*callback)(SSH_X509_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  if ((context = ssh_calloc(1, sizeof(*context))) == NULL)
    {
      (*callback)(SSH_X509_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  context->callback = callback;
  context->callback_context = callback_context;
  context->key = issuer_key;
  context->sign = sign;

  if ((op = ssh_operation_register(cmp_verify_abort, context)) != NULL)
    {
      signop =
        ssh_public_key_verify_async(
            issuer_key,
            message->header.protection_info.signature.signature,
            message->header.protection_info.signature.signature_len,
            message->protection,
            message->protection_len,
            cmp_verify_done, context);

      if (context->signature_op == NULL)
        {
          ssh_operation_unregister(op);
          op = NULL;
        }
      else
        context->signature_op = signop;
    }
  else
    {
      (*callback)(SSH_X509_FAILED_PUBLIC_KEY_OPS, callback_context);
    }

  return op;
}


/* Set the message time. */
void
ssh_cmp_header_set_time(SshCmpMessage message, SshTime msg_time)
{
  ssh_ber_time_set_from_unix_time(&message->header.message_time, msg_time);
}

/* Get the message time if available. */
Boolean
ssh_cmp_header_get_time(SshCmpMessage message, SshTime *msg_time)
{
  if (ssh_ber_time_available(&message->header.message_time) == FALSE)
    return FALSE;

  *msg_time = ssh_ber_time_get_unix_time(&message->header.message_time);
  return TRUE;
}

void
ssh_cmp_header_set_transaction_id(SshCmpMessage message,
                                  const unsigned char *transaction_id,
                                  size_t transaction_id_len,
                                  const unsigned char *sender_nonce,
                                  size_t sender_nonce_len,
                                  const unsigned char *recip_nonce,
                                  size_t recip_nonce_len)
{
  if ((message->header.sender_nonce =
       ssh_memdup(sender_nonce, sender_nonce_len)) != NULL)
    message->header.sender_nonce_len = sender_nonce_len;

  if ((message->header.recip_nonce =
       ssh_memdup(recip_nonce, recip_nonce_len)) != NULL)
    message->header.recip_nonce_len = recip_nonce_len;

  if ((message->header.transaction_id =
       ssh_memdup(transaction_id, transaction_id_len)) != NULL)
    message->header.transaction_id_len = transaction_id_len;
}

void
ssh_cmp_header_get_transaction_id(SshCmpMessage message,
                                  const unsigned char **transaction_id,
                                  size_t *transaction_id_len,
                                  const unsigned char **sender_nonce,
                                  size_t *sender_nonce_len,
                                  const unsigned char **recip_nonce,
                                  size_t *recip_nonce_len)
{
  if (transaction_id)
    *transaction_id = message->header.transaction_id;
  if (transaction_id_len)
    *transaction_id_len = message->header.transaction_id_len;
  if (sender_nonce)
    *sender_nonce = message->header.sender_nonce;
  if (sender_nonce_len)
    *sender_nonce_len = message->header.sender_nonce_len;
  if (recip_nonce)
    *recip_nonce = message->header.recip_nonce;
  if (recip_nonce_len)
    *recip_nonce_len = message->header.recip_nonce_len;
}

#define LIST_APPEND(type, list, value)  \
do {                                    \
  type *tmp, *prev;                     \
  for (tmp = (list), prev = NULL;       \
       tmp != NULL;                     \
       prev = tmp, tmp = tmp->next)     \
    ;                                   \
  if (prev == NULL)                     \
    (list) = (value);                   \
  else                                  \
    prev->next = (value);               \
} while (0)

void
ssh_cmp_header_add_info(SshCmpMessage message, SshX509Attribute attrs)
{
  LIST_APPEND(SshX509AttributeStruct, message->header.general_infos, attrs);
}

void
ssh_cmp_header_get_info(SshCmpMessage message, SshX509Attribute * const attrs)
{
  if (attrs)
    *attrs = message->header.general_infos;
}

/* Extra certificates. */

/* Add extra certificate to the PKI message. This must be a valid X.509v3
   or compatible certificate. It is not decoded, nor analyzed by the
   library. */
Boolean
ssh_cmp_add_extra_cert(SshCmpMessage message,
                       const unsigned char *ber, size_t ber_len)
{
  SshGListNode gnode;
  SshCmpCertificate c;

  if ((c = ssh_malloc(sizeof(*c))) != NULL)
    {
      cmp_cert_init(c);
      if ((c->cert = ssh_memdup(ber, ber_len)) != NULL)
        {
          c->cert_len = ber_len;
          if ((gnode = ssh_glist_allocate_n(message->certificates)) != NULL)
            {
              gnode->data = c;
              gnode->data_length = sizeof(*c);
              ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
              return TRUE;
            }
          ssh_free(c->cert);
        }
      ssh_free(c);
    }
  return FALSE;
}

void
ssh_cmp_get_extra_certs(SshCmpMessage message,
                        SshUInt32 *ncerts, SshCmpCertSet *certs)
{
  *ncerts = cmp_get_certs(message->certificates, certs);
}

/* Create a body. */

/* Set the body type. This function should be called only once per PKI
   message to set the body type. This function implies what you need
   to call in following.

   For some types you do not need to do anything else, but for some
   others, e.g. certificate requests, you may need to add other
   information to the body.  */
void ssh_cmp_body_set_type(SshCmpMessage message,
                                SshCmpBodyType type)
{
  message->body.type = type;
}

SshCmpBodyType ssh_cmp_body_get_type(SshCmpMessage message)
{
  return message->body.type;
}


/* Add certificate request to the body. This function adds the
   BER/DER coded certificate request to the list. */
void
ssh_cmp_set_cert_request(SshCmpMessage message,
                         const unsigned char *ber, size_t ber_len)
{
  SshGListNode gnode;
  SshCmpCertificate c;

  if ((c = ssh_malloc(sizeof(*c))) != NULL)
    {
      cmp_cert_init(c);
      if ((c->cert = ssh_memdup(ber, ber_len)) != NULL)
        {
          c->cert_len = ber_len;

          if ((gnode =
               ssh_glist_allocate_n(message->body.cert_requests)) != NULL)
            {
              gnode->data = c;
              gnode->data_length = sizeof(*c);
              ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
              return;
            }
          ssh_free(c->cert);
        }
      ssh_free(c);
    }
}

void
ssh_cmp_get_cert_response_ca_certs(SshCmpMessage message,
                                   SshUInt32 *ncerts, SshCmpCertSet *certs)
{
  *ncerts = cmp_get_certs(message->body.cert_response.ca_pubs, certs);
}

/* Set one request response explicitly. The ber-blob contains the
   certificate per rfc2459, or per rfc2511 encrypted value. */
void
ssh_cmp_add_cert_response(SshCmpMessage message,
                          SshMPIntegerConst request_id,
                          const SshCmpStatusInfo status,
                          Boolean encrypted,
                          const unsigned char *ber, size_t ber_len,
                          const unsigned char *prvkey, size_t prvkey_len)
{
  SshCmpCertResponseNode node;

  if ((node = ssh_calloc(1, sizeof(*node))) == NULL)
    return;

  cmp_cert_response_node_init(node);

  if (request_id)
    ssh_mprz_init_set(&node->request_id, request_id);

  node->pki_status.status = status->status;
  if (status->failure != 0)
    node->pki_status.failure = status->failure;
  if (status->freetext)
    node->pki_status.freetext = ssh_str_dup(status->freetext);

  if (ber && !status->failure)
    {
      node->cert.encrypted = encrypted;
      node->cert.cert_len = ber_len;
      node->cert.cert = ssh_memdup(ber, node->cert.cert_len);
      if (prvkey)
        {
          node->cert.prvkey_len = prvkey_len;
          node->cert.prvkey = ssh_memdup(prvkey, prvkey_len);
        }
    }
  else
    node->cert.cert_len = 0;

  /* Put first in the list. */
  node->next = message->body.cert_response.list;
  message->body.cert_response.list = node;
}

void
ssh_cmp_get_recovery_response(SshCmpMessage message,
                              SshUInt32 *nresp, SshCmpCertStatusSet *resps,
                              SshCmpStatusInfo *info)
{
  SshCmpCertificate data;
  SshUInt32 ncerts = 0, i;
  SshCmpCertStatusSet r;
  SshGList list;
  SshGListNode node;

  *nresp = 0;
  *resps = NULL;

  if (info)
    *info = &(message->body.rec_response.pki_status);

  list = message->body.rec_response.keypairhist;
  for (node = list->head; node; node = node->next)
    ncerts++;

  if (ncerts == 0)
    return;

  if ((r = ssh_calloc(ncerts, sizeof(*r))) == NULL)
    return;

  for (i = 0, node = list->head; node; node = node->next, i++)
    {
      data = node->data;

      r[i].request_id = NULL;
      r[i].info = &message->body.rec_response.pki_status;
      r[i].encrypted = data->encrypted;
      r[i].cert = data->cert;
      r[i].cert_len = data->cert_len;
      r[i].prvkey = data->prvkey;
      r[i].prvkey_len = data->prvkey_len;
    }
  *nresp = ncerts;
  *resps = r;
}

void
ssh_cmp_get_cert_response(SshCmpMessage message,
                          SshUInt32 *nresp, SshCmpCertStatusSet *resps)
{
  SshCmpCertResponseNode node;
  SshUInt32 ncerts = 0, i;
  SshCmpCertStatusSet r;

  *nresp = 0;
  *resps = NULL;

  for (node = message->body.cert_response.list; node; node = node->next)
    ncerts++;

  if (ncerts == 0 ||
      (r = ssh_calloc(ncerts, sizeof(*r))) == NULL)
    return;

  for (i = 0, node = message->body.cert_response.list;
       node;
       node = node->next, i++)
    {
      r[i].request_id = &node->request_id;
      r[i].info = &node->pki_status;
      r[i].encrypted = node->cert.encrypted;
      r[i].cert = node->cert.cert;
      r[i].cert_len = node->cert.cert_len;
      r[i].prvkey = node->cert.prvkey;
      r[i].prvkey_len = node->cert.prvkey_len;
    }
  *nresp = ncerts;
  *resps = r;
}

/* Throw in an error message. */
void
ssh_cmp_set_error_msg(SshCmpMessage message,
                      const SshCmpStatusInfo status,
                      SshMPIntegerConst error_code,
                      const SshStr details)
{
  message->body.error_msg.status.status = status->status;
  if (status->failure != 0)
    message->body.error_msg.status.failure = status->failure;
  if (status->freetext)
    message->body.error_msg.status.freetext = ssh_str_dup(status->freetext);


  if (error_code)
    ssh_mprz_set(&message->body.error_msg.error_code, error_code);
  if (details)
    message->body.error_msg.details = ssh_str_dup(details);
}

/* Get the error message. */
void
ssh_cmp_get_error_msg(SshCmpMessage message,
                      SshCmpStatusInfo *info,
                      SshMPInteger error_code,
                      SshStr *details,
                      SshStr *instructions)
{
  if (error_code)
    ssh_mprz_set(error_code, &message->body.error_msg.error_code);

  if (info)
    *info = &message->body.error_msg.status;

  if (details)
    *details = message->body.error_msg.details;

  if (instructions)
    *instructions = message->header.freetext;
}

void
ssh_cmp_add_revocation_request(SshCmpMessage request,
                               const unsigned char *ber, size_t ber_len,
                               SshX509RevokedCerts extensions)
{
  SshGListNode gnode;
  SshCmpRevRequest revo;
  SshCmpCertificate ct = NULL;

  if ((revo = ssh_calloc(1, sizeof(*revo))) == NULL)
    return;

  if (ber && ber_len)
    {
      if ((ct = ssh_malloc(sizeof(*ct))) != NULL)
        {
          cmp_cert_init(ct);

          ct->encrypted = FALSE;
          ct->cert = ssh_memdup(ber, ber_len);
          ct->cert_len = ber_len;
          revo->cert_template = ct;
        }
    }

  revo->crl_extensions = extensions;

  if ((gnode = ssh_glist_allocate_n(request->body.rev_requests)) != NULL)
    {
      gnode->data = revo;
      gnode->data_length = sizeof(*revo);
      ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
      return;
    }
  if (ct) ssh_free(ct->cert);
  ssh_free(ct);
  ssh_free(revo);
}

void
ssh_cmp_add_gen_message(SshCmpMessage message, SshX509Attribute attrs)
{
  LIST_APPEND(SshX509AttributeStruct, message->body.general_infos, attrs);
}

void
ssh_cmp_get_gen_message(SshCmpMessage message,
                        SshX509Attribute * const attrs)
{
  if (attrs)
    *attrs = message->body.general_infos;
}

void
ssh_cmp_get_revocation_response(SshCmpMessage response,
                                SshUInt32 *nrevoked,
                                SshCmpRevokedSet *revoked)
{
  SshCmpRevResponse rp;
  SshUInt32 n = 0;

  *revoked = NULL;
  *nrevoked = 0;

  for (rp = response->body.rev_response; rp; rp = rp->next)
    n++;

  if (n)
    {
      if ((*revoked = ssh_calloc(n, sizeof(**revoked))) == NULL)
        return;

      *nrevoked = n;

      for (n = 0, rp = response->body.rev_response; rp; n++, rp = rp->next)
        {
          (*revoked)[n].status = &rp->status;
          if (rp->id)
            {
              (*revoked)[n].issuer = rp->id->issuer;
              (*revoked)[n].serial = &rp->id->serial_no;
            }
          (*revoked)[n].crl = rp->crl;
          (*revoked)[n].crl_len = rp->crl_len;
        }
    }
  else
    {
      *nrevoked = 0;
      *revoked = NULL;
    }
}

void
ssh_cmp_add_cert_confirm(SshCmpMessage confirm,
                         SshMPIntegerConst request_id,
                         const unsigned char *hash, size_t hash_len,
                         const SshCmpStatusInfo status)
{
  SshGListNode gnode;
  SshCmpCertConf conf;

  if ((conf = ssh_calloc(1, sizeof(*conf))) == NULL)
    return;

  if (status)
    {
      memmove(&conf->pki_status, status, sizeof(conf->pki_status));
      if (status->freetext)
        conf->pki_status.freetext = ssh_str_dup(status->freetext);
    }

  if ((conf->hash = ssh_memdup(hash, hash_len)) == NULL)
    {
    failed:
      ssh_str_free(conf->pki_status.freetext);
      ssh_free(conf->hash);
      ssh_free(conf);
      return;
    }

  conf->hash_len = hash_len;
  conf->request_id_set = FALSE;
  if (request_id)
    {
      conf->request_id_set = TRUE;
      ssh_mprz_init_set(&conf->request_id, request_id);
    }

  if ((gnode = ssh_glist_allocate_n(confirm->body.cert_confirm)) != NULL)
    {
      gnode->data = conf;
      gnode->data_length = sizeof(*conf);
      ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
    }
  else
    goto failed;
}

void
ssh_cmp_add_poll_response(SshCmpMessage response,
                          SshMPIntegerConst request_id,
                          SshUInt32 check_after_seconds,
                          const SshStr optional_reason)
{
  SshCmpPollMsg pm;
  SshGListNode gnode;

  if ((pm = ssh_calloc(1, sizeof(*pm))) != NULL)
    {
      if ((gnode =
           ssh_glist_allocate_n(response->body.poll_req_rep)) != NULL)
        {
          pm->this_is_response = (check_after_seconds != 0);
          ssh_mprz_init_set(&pm->request_id, request_id);
          pm->poll_when = check_after_seconds;
          if (optional_reason)
            pm->reason = ssh_str_dup(optional_reason);

          gnode->data = pm;
          gnode->data_length = sizeof(*pm);
          ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
          return;
        }
      ssh_free(pm);
    }
}

void
ssh_cmp_get_poll_responses(SshCmpMessage response,
                           SshUInt32 *nresponses,
                           SshMPInteger **request_ids,
                           SshUInt32 **check_after_seconds,
                           SshStr **optional_reasons)
{
  SshCmpPollMsg pm;
  SshUInt32 n = 0, i;
  SshGListNode gnode;

  for (gnode = response->body.poll_req_rep->head;
       gnode;
       gnode = gnode->next)
    n++;

  *nresponses = n;
  if (n)
    {
      if ((*request_ids = ssh_calloc(n, sizeof(**request_ids))) == NULL)
        {
          *nresponses = 0;
          return;
        }

      if (check_after_seconds)
        *check_after_seconds = ssh_calloc(n, sizeof(**check_after_seconds));
      if (optional_reasons)
        *optional_reasons = ssh_calloc(n, sizeof(**optional_reasons));

      for (i = 0, gnode = response->body.poll_req_rep->head;
           gnode;
           i++, gnode = gnode->next)
        {
          pm = gnode->data;
          (*request_ids)[i] = &pm->request_id;
          if (check_after_seconds && *check_after_seconds)
            (*check_after_seconds)[i] = pm->poll_when;
          if (optional_reasons && *optional_reasons)
            (*optional_reasons)[i] = pm->reason;
        }
    }
}

void
ssh_cmp_add_poll_request(SshCmpMessage request,
                         SshMPIntegerConst request_id)
{
  ssh_cmp_add_poll_response(request, request_id, 0, NULL);
}

void
ssh_cmp_get_poll_requests(SshCmpMessage request,
                          SshUInt32 *nrequest_ids,
                          SshMPInteger **request_ids)
{
  ssh_cmp_get_poll_responses(request, nrequest_ids, request_ids, NULL, NULL);
}

/* x509cmp.c */
#endif /* SSHDIST_CERT */
