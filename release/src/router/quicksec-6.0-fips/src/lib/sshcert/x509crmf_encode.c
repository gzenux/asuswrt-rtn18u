/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the certificate request message formats, as
   described in RFC-2511, March 1999.
*/

#include "sshincludes.h"
#include "sshasn1.h"
#include "oid.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertCrmf"


SshAsn1Node
ssh_x509_crmf_encode_publication_info(SshAsn1Context context,
                                      SshX509PublicationInfo pinfo,
                                      SshX509Config config)
{
  SshX509PublicationInfoNode nodes;
  SshAsn1Node node, pubinfo, nodelist = NULL;
  SshAsn1Status status;

  for (nodes = pinfo->nodes; nodes; nodes = nodes->next)
    {
      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (integer-short ())"
                             "  (any ()))",
                             nodes->publication_method,
                             ssh_x509_encode_general_name(context,
                                                          nodes->location,
                                                          config));
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;

      nodelist = ssh_asn1_add_list(nodelist, node);
    }

  status = ssh_asn1_create_node(context, &pubinfo,
                                "(sequence ()"
                                "  (integer-short ())"
                                "  (any ()))",
                                pinfo->action,
                                nodelist);

  if (status == SSH_ASN1_STATUS_OK)
    return pubinfo;
  else
    return NULL;
}


SshAsn1Node
ssh_x509_crmf_encode_archive_options(SshAsn1Context context,
                                     SshX509ArchiveOptions poptions)
{

  SshAsn1Node node, ednode;
  SshAsn1Status status = SSH_ASN1_STATUS_NOT_YET_IMPLEMENTED;

  if (poptions->encrypted_value)
    {
      unsigned char *data;
      size_t len;

      if (ssh_crmf_encode_encrypted_value(poptions->encrypted_value,
                                          &data, &len) == SSH_X509_OK)
        {
          (void) ssh_asn1_decode_node(context, data, len, &ednode);
          ssh_asn1_flag_changes(ednode);
          status = ssh_asn1_create_node(context, &node, "(any (e 0))", ednode);
          ssh_free(data);
        }
    }
  else if (poptions->keygen_parameters_len)
    status = ssh_asn1_create_node(context, &node,
                                  "(octet-string (1))",
                                  poptions->keygen_parameters,
                                  poptions->keygen_parameters_len);
  else if (poptions->archive_prv_key)
    status = ssh_asn1_create_node(context, &node,
                                  "(boolean (2))", poptions->archive_prv_key);

  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  else
    return node;
}


SshAsn1Node
ssh_x509_crmf_encode_controls(SshAsn1Context context,
                              SshX509Controls controls,
                              SshX509Config config)
{
  SshAsn1Node node = NULL, list, valuenode = NULL, gn, typenode;
  SshAsn1Status status;
  SshX509ControlsNode cursor;
  unsigned char *str;
  size_t str_len;
  char *oidstr = NULL;

  list = NULL;
  for (cursor = controls->node; cursor; cursor = cursor->next)
    {
      switch (cursor->type)
        {
        case SSH_X509_CTRL_REG_TOKEN:
          oidstr = "1.3.6.1.5.5.7.5.1.1";
          str = ssh_str_get(cursor->s.reg_token, &str_len);
          status = ssh_asn1_create_node(context, &valuenode,
                                        "(utf8-string ())", str, str_len);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
          break;
        case SSH_X509_CTRL_AUTHENTICATOR:
          oidstr = "1.3.6.1.5.5.7.5.1.2";
          str = ssh_str_get(cursor->s.authenticator, &str_len);
          status = ssh_asn1_create_node(context, &valuenode,
                                        "(utf8-string ())", str, str_len);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
          break;
        case SSH_X509_CTRL_PKI_INFO:
          oidstr = "1.3.6.1.5.5.7.5.1.3";
          valuenode =
            ssh_x509_crmf_encode_publication_info(context,
                                                  &cursor->s.pki_info,
                                                  config);
          break;
        case SSH_X509_CTRL_PKI_OPTIONS:
          oidstr = "1.3.6.1.5.5.7.5.1.4";
          valuenode =
            ssh_x509_crmf_encode_archive_options(context,
                                                 &cursor->s.pki_options);
          break;
        case SSH_X509_CTRL_OLD_CERT_ID:
          oidstr = "1.3.6.1.5.5.7.5.1.5";
          gn = ssh_x509_encode_general_name(context,
                                            cursor->s.old_cert_id.issuer,
                                            config);
          status = ssh_asn1_create_node(context, &valuenode,
                                        "(sequence ()"
                                        "  (any ())"
                                        "  (integer ()))",
                                        gn,
                                        &cursor->s.old_cert_id.serial_no);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
          break;
        case SSH_X509_CTRL_PUBLIC_KEY:
          oidstr = "1.3.6.1.5.5.7.5.1.6";
          valuenode = ssh_x509_encode_public_key(context,
                                                 &cursor->s.public_key);
          break;
        default:
          break;
        }

      if (valuenode == NULL)
        return NULL;

      status = ssh_asn1_create_node(context, &typenode,
                                    "(sequence ()"
                                    "  (object-identifier ())"
                                    "  (any ()))", oidstr, valuenode);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;

      list = ssh_asn1_add_list(list, typenode);
    }

  if (list)
    (void)ssh_asn1_create_node(context, &node, "(sequence () (any ()))", list);
  else
    node = NULL;

  return node;
}

/* Encoding. */

/* This struct is used to hold data during the asynchronous calls
   when creating the POP (proof of posessions) to crmf requests. */
typedef struct SshX509CRMFEncodeCtxRec
{
  SshX509Signature sig;
  SshX509CertEncodeContext encode_context;
  SshAsn1Node  reg_info;
  SshAsn1Node  pop;
  SshAsn1Node  cert_templatep;
  unsigned char *signed_data;
  SshAsn1Node keyinput;
} *SshX509CRMFEncodeCtx;

static void ssh_x509_crmf_encode_finalize(SshX509CRMFEncodeCtx crmf_context)
{

  SshAsn1Status status;
  SshX509CertEncodeContext encode_context;

  encode_context = crmf_context->encode_context;

  if (encode_context->rv != SSH_X509_OK)
    goto failed;

  /* Finally handle the reg info. This can be used for passing billing
     information or the RA can use it to pass information relevant to
     certReq content without having to invalidate the signature.

     CRMF optional Registration Information is not supported. */
  crmf_context->reg_info = NULL;

  /* Now finish it up. */
  status =
    ssh_asn1_create_node(encode_context->asn1_context,
                         &encode_context->cert_node,
                         "(sequence ()"
                         "  (any ())" /* cert templatep */
                         "  (any ())" /* pop */
                         "  (any ()))", /* reg info */
                         crmf_context->cert_templatep,
                         crmf_context->pop,
                         crmf_context->reg_info);
  if (status != SSH_ASN1_STATUS_OK)
    encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;

 failed:
  ssh_free(crmf_context);
  ssh_x509_cert_finalize_encode(encode_context);
}

SshAsn1Node ssh_x509_crmf_encode_null(SshAsn1Context context)
{
  SshAsn1Status status;
  SshAsn1Node   node;

  status = ssh_asn1_create_node(context, &node, "(null (0))");
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return node;
}


void ssh_x509_pop_sign_cb(SshCryptoStatus crypto_status,
                          const unsigned char *signature_buffer,
                          size_t signature_buffer_len,
                          void *context)
{
  SshX509CRMFEncodeCtx crmf_context = context;
  SshX509CertEncodeContext encode_context = crmf_context->encode_context;
  SshAsn1Node sigalg, output;
  const SshOidStruct *oid;

  encode_context->crypto_handle = NULL;

  if (crypto_status != SSH_CRYPTO_OK)
    {
      encode_context->rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
      goto failed;
    }

  crmf_context->sig->signature =
    ssh_x509_encode_signature(encode_context->asn1_context,
                              signature_buffer, signature_buffer_len,
                              encode_context->issuer_key,
                              &crmf_context->sig->signature_len);

  ssh_free(crmf_context->signed_data);

  /* Common for any Signature POP; encode POPOSigningKey */
  oid    = ssh_oid_find_by_alt_name_of_type(crmf_context->sig->pk_algorithm,
                                            SSH_OID_SIG);

  (void)ssh_asn1_create_node(encode_context->asn1_context,
                             &sigalg,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (null ()))",
                             oid->oid);
  (void)ssh_asn1_create_node(encode_context->asn1_context, &output,
                             "(sequence (1)"
                             "  (any (0))" /* keyinput */
                             "  (any ())" /* algorithm */
                             "  (bit-string ()))", /* signature */
                             crmf_context->keyinput,
                             sigalg,
                             crmf_context->sig->signature,
                             crmf_context->sig->signature_len);

  crmf_context->pop = output;

 failed:
  /* Now finalize the encoding. */
  ssh_x509_crmf_encode_finalize(crmf_context);

}


/* TODO. Implement a verification routine based on this. */
SshX509AsyncCallStatus
ssh_x509_pop_encode(SshX509CRMFEncodeCtx crmf_context)
{
  SshX509CertEncodeContext encode_context = crmf_context->encode_context;
  SshOperationHandle crypto_handle;
  SshAsn1Node output;
  SshX509Certificate cert = encode_context->cert;
  SshAsn1Status status;

  /* Deduce the POP value. */
  /* If RA has verified it then let us tell it to the recipient. */
  if (cert->pop.ra_verified)
    {
      crmf_context->pop =
        ssh_x509_crmf_encode_null(encode_context->asn1_context);

      ssh_x509_crmf_encode_finalize(crmf_context);
      return SSH_X509_ASYNC_CALL_COMPLETED;
    }

  if (cert->pop.subsequent_message ==
      SSH_X509_POP_SUBSEQ_ENCRYPT_CERT)
    {
      status = ssh_asn1_create_node(encode_context->asn1_context, &output,
                                    "(sequence (2) (integer-short (1)))",
                                    SSH_X509_POP_SUBSEQ_ENCRYPT_CERT);
      if (status != SSH_ASN1_STATUS_OK)
        goto error;
      crmf_context->pop = output;
      ssh_x509_crmf_encode_finalize(crmf_context);
      return SSH_X509_ASYNC_CALL_COMPLETED;
    }

  if (cert->pop.this_message)
    {
      status = ssh_asn1_create_node(encode_context->asn1_context, &output,
                                    "(sequence (2) (bit-string (0)))",
                                    cert->pop.this_message,
                                    cert->pop.this_message_len);
      if (status != SSH_ASN1_STATUS_OK)
        goto error;
      crmf_context->pop = output;
      ssh_x509_crmf_encode_finalize(crmf_context);
      return SSH_X509_ASYNC_CALL_COMPLETED;
    }

  /* Determine that we are doing signature pop properly. */
  if (encode_context->issuer_key)
    {
      SshAsn1Node authinfo, pubkey, gn;
      SshAsn1Status status;
      unsigned char *data;
      size_t data_len;
      const SshX509PkAlgorithmDefStruct *algorithm;

      crmf_context->sig = &cert->pop.signature;
      /* Find the issuer algorithm information. */
      algorithm = ssh_x509_private_key_algorithm(encode_context->issuer_key);

      if (algorithm == NULL)
        {
          encode_context->rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
          return SSH_X509_ASYNC_CALL_ERROR;
        }

      if (cert->subject_name &&
          cert->subject_pkey.pk_type != SSH_X509_PKALG_UNKNOWN)
        {
          /* Calculate signature over the encoded templatep before doing the
             pop calculation. */
          ssh_asn1_encode_node(encode_context->asn1_context,
                               crmf_context->cert_templatep);
          ssh_asn1_node_get_data(crmf_context->cert_templatep,
                                 &data, &data_len);
        }
      else
        {
          /* Encode POPOSigningKeyInput->authinfo */
          if (cert->pop.sender)
            {
              gn =
                ssh_x509_encode_general_name(encode_context->asn1_context,
                                             cert->pop.sender,
                                             &cert->config);
              status = ssh_asn1_create_node(encode_context->asn1_context,
                                            &authinfo, "(any (0))", gn);
              if (status != SSH_ASN1_STATUS_OK)
                goto error;
            }
          else
            {
              SshX509MacValue mac = &cert->pop.mac;
              SshAsn1Node macnode;

              if (mac == NULL || mac->pswbmac == NULL)
                {
                  encode_context->rv = SSH_X509_FAILED_UNKNOWN_STYLE;
                  return SSH_X509_ASYNC_CALL_ERROR;
                }

              if ((macnode =
                   ssh_pswbmac_encode_param(encode_context->asn1_context,
                                            mac->pswbmac))
                  != NULL)
                {
                  status =
                    ssh_asn1_create_node(encode_context->asn1_context,
                                         &authinfo,
                                         "(sequence ()"
                                         "  (any ())"
                                         "  (bit-string ()))",
                                         macnode,
                                         mac->value, mac->value_len);
                  if (status != SSH_ASN1_STATUS_OK)
                    authinfo = NULL;
                }
              else
                authinfo = NULL;
            }

          /* Encode POPOSigningKeyInput->pubkey */
          pubkey = ssh_x509_encode_public_key(encode_context->asn1_context,
                                              &cert->pop.pkey);

          /* Combine authinfo and public key to POPOSigningKeyInput */
          (void)ssh_asn1_create_node(encode_context->asn1_context,
                                     &crmf_context->keyinput,
                                     "(sequence ()"
                                     "  (any ())" /* authinfo */
                                     "  (any ()))", /* pubkey */
                                     authinfo, pubkey);

          /* Then compute the signature using PasswordBasedMac
             over the DER encoded POPOSigningKeyInput */
          ssh_asn1_node_get_data(crmf_context->keyinput, &data, &data_len);
        }


      /* Perform the signature operation. */

      crmf_context->sig->pk_algorithm = algorithm->sign;
      crmf_context->sig->pk_type      = algorithm->algorithm;
      crmf_context->signed_data       = data;

      crypto_handle =
        ssh_private_key_sign_async(encode_context->issuer_key, data,
                                   data_len, ssh_x509_pop_sign_cb,
                                   crmf_context);

      if (crypto_handle != NULL)
        {
          SSH_ASSERT(SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(encode_context));
          encode_context->crypto_handle = crypto_handle;
          return SSH_X509_ASYNC_CALL_PENDING;
        }
      return SSH_X509_ASYNC_CALL_COMPLETED;

    }

 error:
  /* TODO: Other pop fields: POPOPrivKey */
  encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
  return SSH_X509_ASYNC_CALL_ERROR;
}



SshAsn1Node ssh_x509_encode_optional_validity(SshAsn1Context context,
                                              SshBerTime     not_before,
                                              SshBerTime     not_after)
{
  SshAsn1Node not_before_node, not_after_node, node;
  SshAsn1Status status;

  /* Create ASN.1 nodes. */
  not_before_node = ssh_x509_encode_time(context, not_before);
  not_after_node  = ssh_x509_encode_time(context, not_after);

  if (not_before_node == NULL && not_after_node == NULL)
    return NULL;

  status =
    ssh_asn1_create_node(context, &node,
                         "(sequence ()"
                         "  (any (e 0))"
                         "  (any (e 1)))",
                         not_before_node, not_after_node);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return node;
}

SshX509Status
ssh_x509_crmf_encode_templatep(SshAsn1Context context,
                               SshX509Certificate cert,
                               SshPrivateKey issuer_key,
                               SshAsn1Node  *templatep)
{
  SshAsn1Status status;
  SshAsn1Node signing_alg = NULL,
    subject_name = NULL, subject_uid, issuer_name = NULL, issuer_uid,
    optional_time, public_key, extensions;
  SshMPIntegerStruct version, serial_number;
  SshX509Status rv = SSH_X509_OK;

  /* Note: currently this program generates always the
     version number and serial number. It is easy to remove this
     feature, but currently this is kept as is. */

  /* Set up the version number. */
  ssh_mprz_init_set_ui(&version, 2);

  /* Set the serial number. */
  ssh_mprz_init_set_ui(&serial_number, 0);
  if (ssh_mprz_cmp_ui(&cert->serial_number, 0) >= 0)
    ssh_mprz_set(&serial_number, &cert->serial_number);

  /* Encode subparts.

  Note: here we do not check on return values. However, it may be
  that error situations should be checked.  */

  /* Extensions. */
  if (ssh_x509_cert_encode_extension(context, cert, &extensions)
      != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_EXTENSION_ENCODE;
      goto failed;
    }

  /* Signing alg. */
  if (issuer_key)
    signing_alg = ssh_x509_encode_sigalg(context, issuer_key);

  /* Set up the public key. */
  public_key = ssh_x509_encode_public_key(context,
                                          &cert->subject_pkey);

  /* Set up the optional time. */
  optional_time = ssh_x509_encode_optional_validity(context,
                                                    &cert->not_before,
                                                    &cert->not_after);

  /* Encode the issuer name. */
  if (cert->issuer_name &&
      ssh_x509_name_find(cert->issuer_name,
                         SSH_X509_NAME_DISTINGUISHED_NAME))
    issuer_name = ssh_x509_encode_dn_name(context,
                                          SSH_X509_NAME_DISTINGUISHED_NAME,
                                          cert->issuer_name,
                                          &cert->config);

  /* Encode the subject name. */
  if (cert->subject_name &&
      ssh_x509_name_find(cert->subject_name,
                         SSH_X509_NAME_DISTINGUISHED_NAME))
    subject_name = ssh_x509_encode_dn_name(context,
                                           SSH_X509_NAME_DISTINGUISHED_NAME,
                                           cert->subject_name,
                                           &cert->config);

  /* Encode the issuer unique identifier. */

  {
    SshX509Name ui_name;
    ui_name = ssh_x509_name_find(cert->issuer_name, SSH_X509_NAME_UNIQUE_ID);
    if (ui_name)
      {
        status =
          ssh_asn1_create_node(context, &issuer_uid,
                               "(bit-string ())",
                               ui_name->data, ui_name->data_len*8);
        if (status != SSH_ASN1_STATUS_OK)
          {
            rv = SSH_X509_FAILED_UNIQUE_ID_ENCODE;
            goto failed;
          }
      }
    else
      issuer_uid = NULL;
  }

  /* Encode the subject unique identifier. */
  {
    SshX509Name ui_name;
    ui_name = ssh_x509_name_find(cert->subject_name, SSH_X509_NAME_UNIQUE_ID);
    if (ui_name)
      {
        status =
          ssh_asn1_create_node(context, &subject_uid,
                               "(bit-string ())",
                               ui_name->data, ui_name->data_len*8);
        if (status != SSH_ASN1_STATUS_OK)
          {
            rv = SSH_X509_FAILED_UNIQUE_ID_ENCODE;
            goto failed;
          }
      }
    else
      subject_uid = NULL;
  }

  /* Now we can finalize the templatep. */
  status =
    ssh_asn1_create_node(context, templatep,
                         "(sequence ()"
                         "  (integer (0))" /* version */
                         "  (integer (1))" /* serial number */
                         "  (any (2))"     /* signing alg. */
                         "  (any (e 3))"   /* name */
                         "  (any (4))"     /* optional validity */
                         "  (any (e 5))"   /* name */
                         "  (any (6))"     /* subject public key info */
                         "  (any (e 7))"   /* unique id. */
                         "  (any (e 8))"   /* unique id. */
                         "  (any (9)))", /* extensions */
                         &version, &serial_number,
                         signing_alg,
                         issuer_name,
                         optional_time,
                         subject_name,
                         public_key,
                         issuer_uid,
                         subject_uid,
                         extensions);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

 failed:
  ssh_mprz_clear(&version);
  ssh_mprz_clear(&serial_number);
  return rv;
}

static SshX509Status
ssh_x509_crmf_encode_request(SshAsn1Context context,
                             SshX509Certificate cert,
                             SshPrivateKey issuer_key,
                             SshAsn1Node *request)
{
  SshAsn1Node templatep, controls;
  SshAsn1Status status;

  if (ssh_x509_crmf_encode_templatep(context, cert, issuer_key, &templatep)
      == SSH_X509_OK)
    {
      controls = ssh_x509_crmf_encode_controls(context,
                                               &cert->controls,
                                               &cert->config);
      /* Build the request. */
      status = ssh_asn1_create_node(context, request,
                                    "(sequence ()"
                                    "  (integer ())"  /* cert req id. */
                                    "  (any ())"      /* templatep */
                                    "  (any ()))",    /* controls */
                                    &cert->request_id, templatep, controls);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;
      else
        return SSH_X509_OK;
    }
  else
    return SSH_X509_FAILURE;
}

/* Note: at the moment this may not follow all the possibilities of
   the CRMF format. In future more details will be added, however,
   currently this follows mainly the general framework that has been
   found to be ok with the PKCS-10 code.

   Current practice with us is to handle only requests with public
   keys and with signatures. This will modified to a more general
   approach in future, but for current state of the art it suffices.  */

SshX509AsyncCallStatus
ssh_x509_crmf_encode_asn1(void *context)
{
  SshX509CertEncodeContext encode_context = context;
  SshAsn1Node crequest, ctemplate;
  SshX509CRMFEncodeCtx crmf_context;
  Boolean have_pop = FALSE;
  SshX509Certificate cert = encode_context->cert;

  /* Encode the templatep. */
  if (encode_context->issuer_key
      || cert->pop.ra_verified
      || cert->pop.this_message
      || cert->pop.subsequent_message
      != SSH_X509_POP_SUBSEQ_UNDEF)
    have_pop = TRUE;

  if (have_pop ||
      cert->controls.node != NULL)
    {
      encode_context->rv =
        ssh_x509_crmf_encode_request(encode_context->asn1_context,
                                     cert,
                                     encode_context->issuer_key,
                                     &crequest);

      if (encode_context->rv != SSH_X509_OK)
        return SSH_X509_ASYNC_CALL_ERROR;

      if ((crmf_context = ssh_calloc(1, sizeof(*crmf_context))) != NULL)
        {
          crmf_context->encode_context = encode_context;
          crmf_context->cert_templatep = crequest;

          if (have_pop)
            {
              /* Handle encoding of the POP. For some methods for proof
                 this also computes the signature. */
              return ssh_x509_pop_encode(crmf_context);
            }
          else
            {
              ssh_x509_crmf_encode_finalize(crmf_context);
              return SSH_X509_ASYNC_CALL_COMPLETED;
            }
        }
      else
        return SSH_X509_ASYNC_CALL_ERROR;
    }
  else
    {
      encode_context->rv =
        ssh_x509_crmf_encode_templatep(encode_context->asn1_context,
                                       cert,
                                       encode_context->issuer_key,
                                       &ctemplate);

      if (encode_context->rv == SSH_X509_OK &&
          (ssh_asn1_encode_node(encode_context->asn1_context, ctemplate))
          == SSH_ASN1_STATUS_OK)
        {
          ssh_asn1_node_get_data(ctemplate,
                                 &(encode_context->buf),
                                 &(encode_context->buf_len));

          if (SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(encode_context))
            {
              (*encode_context->user_encode_cb)(encode_context->rv,
                                                encode_context->buf,
                                                encode_context->buf_len,
                                                encode_context->user_context);

              ssh_free(encode_context->buf);
              ssh_operation_abort(encode_context->operation_handle);
            }
        }
      else
        {
          ssh_operation_unregister(encode_context->operation_handle);
          return SSH_X509_ASYNC_CALL_ERROR;
        }
      return SSH_X509_ASYNC_CALL_COMPLETED;
    }
}




Boolean ssh_x509_control_push_oldcert(SshX509ControlsNode *list,
                                      SshX509Name issuer,
                                      SshMPIntegerConst serial)
{
  SshX509ControlsNode node = ssh_malloc(sizeof(*node));

  if (node)
    {
      node->next = NULL;
      node->type = SSH_X509_CTRL_OLD_CERT_ID;
      node->s.old_cert_id.issuer = ssh_x509_name_copy(issuer);
      ssh_mprz_init(&node->s.old_cert_id.serial_no);
      ssh_mprz_set(&node->s.old_cert_id.serial_no, serial);

      ssh_x509_control_push(list, node);
      return TRUE;
    }
  return FALSE;
}

void ssh_x509_control_push(SshX509ControlsNode *list,
                           SshX509ControlsNode node)
{
  SshX509ControlsNode s = node;

  if (node == NULL)
    return;

  for (; node->next; node = node->next)
    ;

  node->next = *list;
  *list = s;
}

void ssh_x509_cert_set_controls_nodes(SshX509Certificate c,
                                      SshX509ControlsNode nodes)
{
  ssh_x509_control_push(&c->controls.node, nodes);
}
#endif /* SSHDIST_CERT */
