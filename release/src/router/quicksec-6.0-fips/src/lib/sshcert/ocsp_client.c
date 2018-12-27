/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RFC2560 - Online Certificate Status Protocol.
*/

#include "sshincludes.h"
#include "sshocsp.h"
#include "ocsp_internal.h"
#include "x509internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshOcspClient"

/****************************************************************************
 * Client side - Request message construct and encode
 */

static void
ocsp_encode_abort(void *ctx)
{
  SshOcspEncodeContext context = (SshOcspEncodeContext) ctx;

  ssh_operation_abort(context->signature_op);
  ssh_asn1_free(context->asn1context);
  ssh_free(context);
}

/*  Signature operation done. Construct the final tree.  Signature
    buffer length comes in bytes here.  Allocated memory is freed. */
static void
ocsp_request_encode_done(SshCryptoStatus cstatus,
                         const unsigned char *sig, size_t sig_len,
                         void *ctx)
{
  SshOcspEncodeContext context = (SshOcspEncodeContext) ctx;
  unsigned char       *optional_signature = NULL;
  size_t              optional_signature_len = 0;
  unsigned char       *buf = NULL;
  size_t              buf_len = 0;
  SshAsn1Node         signature_algorithm = NULL;
  SshAsn1Node         signature = NULL;
  SshAsn1Node         certs = NULL;
  SshAsn1Node         top_level = NULL;
  SshAsn1Tree         tree = NULL;

  if (cstatus != SSH_CRYPTO_OK)
    {
      (*context->callback)(SSH_OCSP_STATUS_FAILED_PRIVATE_KEY_OPS,
                           NULL, 0,
                           context->callback_context);
      goto cleanup;
    }

  /* signature and signatureAlgorithm */
  if (context->key)
    {
      signature_algorithm = ssh_x509_encode_sigalg(context->asn1context,
                                                   context->key);

      optional_signature = ssh_x509_encode_signature(context->asn1context,
                                                     sig, sig_len,
                                                     context->key,
                                                     &optional_signature_len);
    }

  /* certs */
  if (ocsp_encode_cert_list(context->asn1context,
                            context->request->cert_list,
                            &certs)
      != SSH_X509_OK)
    {
      (*context->callback)(SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,
                           NULL, 0,
                           context->callback_context);
      goto cleanup;
    }

  /* Build the signature node. */
  if (optional_signature_len)
    {
      if (ssh_asn1_create_node(context->asn1context, &signature,
                               "(sequence ()"
                               "  (any ())"        /* signatureAlgorithm */
                               "  (bit-string ())" /* signature */
                               "  (any (e 0)))",   /* certs */
                               signature_algorithm,
                               optional_signature, optional_signature_len,
                               certs)
          != SSH_ASN1_STATUS_OK)
        {
          (*context->callback)(SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,
                               NULL, 0,
                               context->callback_context);
          goto cleanup;
        }
    }

  /* Create the output. */
  if (ssh_asn1_create_node(context->asn1context, &top_level,
                           "(sequence ()"
                           "  (any ())"      /* tbsRequest */
                           "  (any (e 0)))", /* optionalSignature */
                           context->tbs_message,
                           signature)
      != SSH_ASN1_STATUS_OK)
    {
      (*context->callback)(SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,
                           NULL, 0,
                           context->callback_context);
      goto cleanup;
    }

    /* Construct a tree out of the request. */
  if ((tree =
       ssh_asn1_init_tree(context->asn1context, top_level, top_level))
      == NULL ||
      ssh_asn1_encode(context->asn1context, tree) != SSH_ASN1_STATUS_OK)
    {
      (*context->callback)(SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,
                           NULL, 0,
                           context->callback_context);
      goto cleanup;
    }

  ssh_asn1_get_data(tree, &buf, &buf_len);
  (*context->callback)(SSH_OCSP_STATUS_OK,
                       buf, buf_len,
                       context->callback_context);
  ssh_free(buf);

cleanup:
  ssh_free(optional_signature);

  /* Unregister the operation and free the request. */
  ssh_operation_unregister(context->operation);
  ssh_ocsp_request_free(context->request);
  ssh_asn1_free(context->asn1context);
  ssh_free(context);
  return;
}


static SshOcspStatus
ocsp_encode_request(SshAsn1Context context,
                    SshOcspSingleRequest request,
                    SshAsn1Node *node)
{
  SshAsn1Node     requested_certificate = NULL;
  SshAsn1Node     single_request_extensions = NULL;
  SshOcspStatus   rv;

  /* Encode certID */
  if ((rv = ocsp_encode_cert_id(context, &requested_certificate,
                                &request->cert_id)) != SSH_OCSP_STATUS_OK)
    return rv;

  /* singleRequestExtensions */
  if ((rv = ocsp_encode_extensions(context,
                                   request->single_request_extensions,
                                   &single_request_extensions))
      != SSH_OCSP_STATUS_OK)
    return rv;

  if (ssh_asn1_create_node(context, node,
                           "(sequence ()"
                           "  (any ())"      /* reqCert */
                           "  (any (e 0)))", /* singleRequestExtensions */
                           requested_certificate,
                           single_request_extensions)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  return SSH_OCSP_STATUS_OK;
}

static SshOcspStatus
ocsp_encode_tbs_request(SshAsn1Context context,
                        SshOcspTbsRequest tbs_request,
                        SshAsn1Node *request_node)
{
  SshAsn1Node     requestor_name = NULL;
  SshAsn1Node     request_list = NULL;
  SshAsn1Node     request_list_node = NULL;
  SshAsn1Node     node = NULL;
  SshGListNode    gnode = NULL;

  /* extension stuff */
  SshAsn1Node      request_extensions = NULL;
  SshOcspStatus    rv = SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  /* requestorName */
  requestor_name =
    ssh_x509_encode_general_name_list(context,
                                      tbs_request->requestor_name,
                                      NULL);

  /* requestList */
  request_list = NULL;
  for (gnode = tbs_request->request_list->head;
       gnode;
       gnode = gnode->next)
    {
      if ((rv = ocsp_encode_request(context,
                                    (SshOcspSingleRequest) gnode->data,
                                    &node))
          != SSH_OCSP_STATUS_OK)
        return rv;

      request_list = ssh_asn1_add_list(request_list, node);
    }

  /* Encode the sequence. */
  if (ssh_asn1_create_node(context, &request_list_node,
                           "(sequence ()"
                           "  (any ()))",
                           request_list)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  /* requestExtensions */
  if ((rv = ocsp_encode_extensions(context,
                                   tbs_request->request_extensions,
                                   &request_extensions))
      != SSH_OCSP_STATUS_OK)
    return rv;

  if (ssh_asn1_create_node(context, request_node,
                           "(sequence ()"
                           "  (integer-short (e 0))"         /* version */
                           "  (any (e 1))"             /* requestorName */
                           "  (any ())"                      /* request */
                           "  (any (e 2)))",       /* requestExtensions */
                           tbs_request->version,
                           requestor_name,
                           request_list_node,
                           request_extensions)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  return SSH_OCSP_STATUS_OK;
}

SshOcspStatus
ocsp_encode_optional_signature(SshAsn1Context context,
                               SshAsn1Node tbs_request,
                               unsigned char **buf, size_t *buf_len)
{
  SshAsn1Node     node = NULL;
  SshAsn1Node     tmp_request = NULL;

  /* Let us make copies of the input nodes so that they can be used
     later for other things. */
  if (ssh_asn1_copy_node(context, &tmp_request, tbs_request)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_INTERNAL_ERROR;

  /* Now make the BER/DER encoded buffer. */
  node = tbs_request;
  if (ssh_asn1_encode_node(context, node) != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  ssh_asn1_node_get_data(node, buf, buf_len);
  return SSH_OCSP_STATUS_OK;
}

/* FIXME This function returns NULL both in case of success and failure. */
SshOperationHandle
ssh_ocsp_request_encode(SshOcspRequest message,
                        const SshPrivateKey key,
                        SshOcspEncodeCB callback,
                        void *callback_context)
{
  SshAsn1Context          asn1context = NULL;
  SshAsn1Node             request = NULL;
  SshOcspStatus           rv = SSH_OCSP_STATUS_OK;
  SshOperationHandle      op = NULL;
  SshOcspEncodeContext    context = NULL;
  SshOperationHandle      op_temp = NULL;

  unsigned char           *tobesigned = NULL;
  size_t                  tobesigned_len = 0;

  /* Initialize the ASN.1 allocation context. */
  if ((asn1context = ssh_asn1_init()) == NULL)
    {
      (*callback)(SSH_OCSP_STATUS_INTERNAL_ERROR, NULL, 0, callback_context);
      return NULL;
    }

    /* First create the tbsRequest. */
  if ((rv = ocsp_encode_tbs_request(asn1context, &message->tbs_request,
                                    &request))
      != SSH_OCSP_STATUS_OK)
    {
      ssh_asn1_free(asn1context);
      (*callback)(rv, NULL, 0, callback_context);
      return NULL;
    }

  SSH_DEBUG(5, ("tbs_request encoded."));

  /* Prepare the optionalSignature. */
  if ((rv = ocsp_encode_optional_signature(asn1context,
                                           request,
                                           &tobesigned, &tobesigned_len))
      != SSH_OCSP_STATUS_OK)
    {
      ssh_asn1_free(asn1context);
      (*callback)(SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,
                  NULL, 0,
                  callback_context);
      return NULL;
    }

  SSH_DEBUG(5, ("Optional signature prepared."));

  if ((context = ssh_calloc(1, sizeof(*context))) == NULL)
    {
      ssh_asn1_free(asn1context);
      (*callback)(SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,
                  NULL, 0,
                  callback_context);
      ssh_free(tobesigned);
      return NULL;
    }
  context->response = NULL;
  context->tbs_message = request;
  context->request = message;
  context->key = key;
  context->callback = callback;
  context->asn1context = asn1context;
  context->signature_op = NULL;
  context->callback_context = callback_context;
  context->operation = NULL;

  /* Start signing operation. */
  if (key)
    {
      op = ssh_operation_register(ocsp_encode_abort, context);
      context->operation = op;

      op_temp = ssh_private_key_sign_async(key,
                                           tobesigned, tobesigned_len,
                                           ocsp_request_encode_done, context);

      if (op_temp == NULL)
        op = NULL;
      else
        context->signature_op = op_temp;
    }
  else
    {
      SSH_DEBUG(5, ("Private key not available. Cannot sign. This is OK."));
      ocsp_request_encode_done(SSH_CRYPTO_OK, NULL, 0, context);
    }

  ssh_free(tobesigned);
  return op;
}

/****************************************************************************
 * Client side - Response message decode, validate and access
 */
static SshOcspStatus
ocsp_decode_cert_status(SshAsn1Context context,
                        SshAsn1Node node,
                        SshOcspCertStatus cert_status)
{
  SshAsn1Node     good = NULL;
  SshAsn1Node     revoked = NULL;
  SshAsn1Node     unknown = NULL;

  /* variables for revoked */
  SshAsn1Node     revocation_reason = NULL;
  Boolean         reason_found = FALSE;
  SshBerTimeStruct time;

  if (ssh_asn1_read_node(context, node,
                         "(choice"
                         "  (any (0))"    /* good (NULL) */
                         "  (any (1))"    /* revoked */
                         "  (any (2)))",  /* unknown (NULL for now) */
                         &cert_status->status,
                         &good,
                         &revoked,
                         &unknown)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  if (cert_status->status != SSH_OCSP_CERT_STATUS_GOOD &&
      cert_status->status != SSH_OCSP_CERT_STATUS_REVOKED &&
      cert_status->status != SSH_OCSP_CERT_STATUS_UNKNOWN)
    return SSH_OCSP_STATUS_UNKNOWN_CERT_STATUS;

  /* decode revoked info */
  if (cert_status->status == SSH_OCSP_CERT_STATUS_REVOKED)
    {
      if (ssh_asn1_read_node(context, revoked,
                             "(sequence (1)"
                             "  (generalized-time ())"    /* revoTime */
                             "  (optional (any (e 0))))", /* revoReason */
                             &time,
                             &reason_found, &revocation_reason)
          != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Error: cant'd decode revocation information."));
          return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
        }

      /* Store reason and time of revocation. */
      cert_status->statusinfo.revoked.revocation_time =
        ssh_ber_time_get_unix_time(&time);
      cert_status->statusinfo.revoked.reason_available = reason_found;

      if (reason_found)
        {
          if (ssh_x509_decode_crl_reason_code(context,
                                              revocation_reason,
                                              &cert_status->statusinfo.
                                              revoked.revocation_reason)
              != SSH_X509_OK)
            return SSH_OCSP_STATUS_INVALID_OPERAND;
        }
      else
        {
          cert_status->statusinfo.revoked.revocation_reason = 0;
        }
    }

  return SSH_OCSP_STATUS_OK;
}

static SshOcspStatus
ocsp_decode_single_response_extensions(SshAsn1Context context,
                                       SshAsn1Node list,
                                       SshX509Attribute *attrs)
{
  return ocsp_decode_extensions(context, list, attrs);
}

static SshOcspStatus
ocsp_decode_response_extensions(SshAsn1Context context,
                                SshAsn1Node node,
                                SshX509Attribute *attrs)
{
  return ocsp_decode_extensions(context, node, attrs);
}

static SshOcspStatus
ocsp_decode_single_response(SshAsn1Context context,
                            SshAsn1Node node,
                            SshOcspSingleResponse single_response)
{
  SshOcspStatus       rv = SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  SshAsn1Node         cert_id = NULL;
  SshAsn1Node         cert_status = NULL;
  SshBerTimeStruct    this_update;
  SshBerTimeStruct    next_update;
  SshAsn1Node         single_response_extensions = NULL;

  Boolean             next_update_found = FALSE;
  Boolean             extensions_found = FALSE;

  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (any ())"                             /* certID */
                         "  (any ())"                         /* certStatus */
                         "  (generalized-time ())"            /* thisUpdate */
                         "  (optional "
                         "     (generalized-time (e 0)))"     /* nextUpdate */
                         "  (optional (any (e 1))))",   /* singleExtensions */
                         &cert_id,
                         &cert_status,
                         &this_update,
                         &next_update_found, &next_update,
                         &extensions_found, &single_response_extensions)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  /* certID */
  if ((rv = ocsp_decode_cert_id(context, cert_id, &single_response->cert_id))
      != SSH_OCSP_STATUS_OK)
    return rv;

  /* certStatus */
  if ((rv = ocsp_decode_cert_status(context,
                                    cert_status,
                                    &single_response->status))
      != SSH_OCSP_STATUS_OK)
    return rv;

  /* thisUpdate and nextUpdate */
  single_response->this_update = this_update;
  ssh_ber_time_zero(&single_response->next_update);
  if (next_update_found)
    single_response->next_update = next_update;

  /* singleExtensions */
  if (extensions_found)
    {
      if ((rv =
           ocsp_decode_single_response_extensions(context,
                                                  single_response_extensions,
                                                  &single_response->
                                                  single_extensions))
           != SSH_OCSP_STATUS_OK)
        return rv;
    }

  return SSH_OCSP_STATUS_OK;
}

static SshOcspStatus
ocsp_decode_responder_id(SshAsn1Context context,
                         SshAsn1Node node,
                         SshOcspResponderId responder_id)
{
  SshAsn1Node     responder_name = NULL;
  unsigned int    type = 0;

  if (ssh_asn1_read_node(context, node,
                         "(choice"
                         "  (any (e 1))"                       /* by_name */
                         "  (octet-string (e 2)))",            /* by_key */
                         &type,
                         &responder_name,
                         &responder_id->id.ByKey.key_hash,
                         &responder_id->id.ByKey.hash_len)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  /* Note: choice counts from zero whereas first index is one. */
  responder_id->type = type + 1;
  if (responder_id->type != SSH_OCSP_RESPONDER_BY_NAME &&
      responder_id->type != SSH_OCSP_RESPONDER_BY_KEY)
    {
      return SSH_OCSP_STATUS_UNKNOWN_RESPONDERID_TYPE;
    }

  if (responder_id->type == SSH_OCSP_RESPONDER_BY_NAME)
    {
      if (ssh_x509_decode_dn_name(context,
                                  responder_name,
                                  SSH_X509_NAME_DN,
                                  &responder_id->id.ByName.name,
                                  NULL)
          != SSH_X509_OK)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Error: can't decode responder name."));
          return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
        }
    }
  return SSH_OCSP_STATUS_OK;
}

static SshOcspStatus
ocsp_decode_tbs_response_data(SshAsn1Context context,
                              SshAsn1Node node,
                              SshOcspTbsResponseData response_data)
{
  SshOcspStatus       rv = SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  Boolean             version_found = FALSE;
  SshAsn1Node         responder_id = NULL;
  SshBerTimeStruct    produced_at;
  SshAsn1Node         single_responses = NULL;
  SshAsn1Node         single_responses_list = NULL;
  SshAsn1Node         response_extensions = NULL;
  Boolean             extensions_found = FALSE;

  SshOcspSingleResponse single_response = 0;

  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (optional (integer-short (e 0)))"    /* version */
                         "  (any ())"                        /* responderID */
                         "  (generalized-time ())"            /* producedAt */
                         "  (any ())"                    /* singleResponses */
                         "  (optional (any (e 1))))", /* responseExtensions */
                         &version_found, &response_data->version,
                         &responder_id,
                         &produced_at,
                         &single_responses,
                         &extensions_found, &response_extensions)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  if (!version_found)
    response_data->version = SSH_OCSP_VERSION_V1;
  response_data->version_available = version_found;

  /* responderID */
  if ((rv = ocsp_decode_responder_id(context,
                                     responder_id,
                                     &response_data->responder_id))
      != SSH_OCSP_STATUS_OK)
    return rv;

  /* producedAt */
  response_data->produced_at = produced_at;

  /* sequence of singleResponses */
  if (ssh_asn1_read_node(context, single_responses,
                         "(sequence (*) (any ()))",
                         &single_responses_list)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  /* Typically there is only one response. */
  for (; single_responses_list;
       single_responses_list = ssh_asn1_node_next(single_responses_list))
    {
      if ((single_response = ssh_malloc(sizeof(*single_response))) != NULL)
        {
          single_response->single_extensions = NULL;

          /* Decode single response. */
          if ((rv = ocsp_decode_single_response(context,
                                                single_responses_list,
                                                single_response))
              != SSH_OCSP_STATUS_OK)
            {
              ssh_free(single_response);
              return rv;
            }

          /* Add decoded response to the list */
          ssh_glist_add_item(response_data->response_list,
                             single_response,
                             SSH_GLIST_TAIL);
        }
    }

  /* responseExtensions */
  if (extensions_found)
    {
      if ((rv = ocsp_decode_response_extensions(context,
                                                response_extensions,
                                                &response_data->
                                                response_extensions))
          != SSH_OCSP_STATUS_OK)
        return rv;
    }

  if (ssh_asn1_node_get_data(node,
                             &response_data->data, &response_data->data_len)
      == SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_OK;
  else
    return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
}

static SshOcspStatus
ocsp_decode_basic_response(SshAsn1Context context,
                           SshAsn1Node node,
                           SshOcspBasicResponse response)
{
  SshAsn1Status       status = SSH_ASN1_STATUS_OK;
  SshOcspStatus       rv = SSH_OCSP_STATUS_FAILED_ASN1_DECODE;

  SshAsn1Node         tbs_response_data = NULL;
  unsigned char       *signature_algorithm = NULL;
  unsigned char       *signature = NULL;
  size_t              signature_len = 0;
  SshX509PkAlgorithm  signature_type = SSH_X509_PKALG_UNKNOWN;
  const SshOidStruct  *oids;
  SshAsn1Node         algorithm_parameters = NULL;
  Boolean             certs_found = FALSE;
  SshAsn1Node         certs = NULL;

  status =
    ssh_asn1_read_node(context, node,
                       "(sequence ()"
                       "  (any ())"                    /* tbsResponseData */
                       "  (sequence ()"
                       "    (object-identifier ())"    /* signatureAlgorithm */
                       "    (any ()))"                 /* parameters (NULL) */
                       "  (bit-string ())"             /* signature */
                       "  (optional (any (e 0))))",    /* certs */
                       &tbs_response_data,
                       &signature_algorithm, &algorithm_parameters,
                       &signature, &signature_len,
                       &certs_found, &certs);

  if (status != SSH_ASN1_STATUS_OK)
    {
      return rv;
    }

  /* tbsResponseData */
  if (ocsp_decode_tbs_response_data(context,
                                    tbs_response_data,
                                    &response->tbs_response_data)
      != SSH_OCSP_STATUS_OK)
    {
      SSH_DEBUG(7, ("Decoding tbsResponseData failed."));
      return rv;
    }

  /* signatureAlgorithm */
  oids = ssh_oid_find_by_oid_of_type(signature_algorithm, SSH_OID_SIG);
  ssh_free(signature_algorithm);

  if (oids)
    {
      response->signature_algorithm = oids->name;
    }
  else
    {
      response->signature_algorithm = NULL;
      return SSH_OCSP_STATUS_UNKNOWN_SIGNATURE_ALGORITHM;
    }
  signature_type = oids->extra_int;

  /* signature */
  if (signature_type == SSH_X509_PKALG_UNKNOWN)
    {
      response->signature = signature;
      response->signature_len = signature_len / 8;
    }
  else
    {
      response->signature =
        ssh_x509_decode_signature(context,
                                  signature, signature_len,
                                  signature_type,
                                  &response->signature_len);
      ssh_free(signature);
    }

  /* decode sequence of certificates */
  if (certs_found)
    {
      ocsp_decode_cert_list(context, certs, response->cert_list);
    }

  return SSH_OCSP_STATUS_OK;
}

static SshOcspStatus
ocsp_decode_response_message(SshAsn1Context context,
                             SshAsn1Node node,
                             SshOcspResponse response)
{
  SshOcspStatus   rv = SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
  SshAsn1Node     response_bytes = NULL;
  Boolean         bytes_found = FALSE;
  SshMPIntegerStruct response_status;
  SshAsn1Tree     tree = NULL;
  char           *response_type = NULL;

  ssh_mprz_init(&response_status);

  /* Read responseStatus and responseBytes */
  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (enum ())"                /* responseStatus */
                         "  (optional (any (e 0))))", /* responseBytes */
                         &response_status,
                         &bytes_found, &response_bytes)
      != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&response_status);
      SSH_DEBUG(SSH_D_NETFAULT, ("OCSP Error: can't decode response."));
      return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
    }

  response->response_status = ssh_mprz_get_ui(&response_status);
  ssh_mprz_clear(&response_status);

  /* if query was not successful, other information is not set */
  if (response->response_status != SSH_OCSP_SUCCESSFUL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Recevived OCSP error response %d",
                             response->response_status));
      return SSH_OCSP_STATUS_OK;
    }

  /* Decode responseBytes information */
  if (ssh_asn1_read_node(context, response_bytes,
                         "(sequence ()"
                         "  (object-identifier ())"   /* responseType */
                         "  (octet-string ()))",      /* response */
                         &response_type,
                         &response->response_bytes, &response->response_len)
      != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_NETFAULT, ("OCSP Error: can't decode response-bytes."));
      return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
    }

  /* check responseType (is supported or not) */
  if (strcmp(response_type, SSH_OCSP_OID_RESPONSE_TYPE_BASIC) != 0)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Error: Unknown response type %s.", response_type));
      return SSH_OCSP_STATUS_UNKNOWN_RESPONSE_TYPE;
    }
  else
    {
      response->response_type = SSH_OCSP_RESPONSE_TYPE_BASIC;
    }

  ssh_free(response_type);

  if (ssh_asn1_decode(context,
                      response->response_bytes, response->response_len,
                      &tree)
      != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Error: can't decode basic response Asn.1."));
      return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
    }

  if ((rv = ocsp_decode_basic_response(context,
                                       ssh_asn1_get_root(tree),
                                       &response->response))
      != SSH_OCSP_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Error: malformed basic response."));
      return rv;
    }

  if ((response->verification =
       ssh_memdup(response->response.tbs_response_data.data,
                  response->response.tbs_response_data.data_len)) == NULL)
    return SSH_OCSP_STATUS_INTERNAL_ERROR;
  response->verification_len  = response->response.tbs_response_data.data_len;

  /* If we get this far, the unauthenticated response status can be
     considered a success regardless of what the value was on the
     envelope. Note that signature over the response will be checked
     by the application later. */
  response->response_status = SSH_OCSP_SUCCESSFUL;
  return SSH_OCSP_STATUS_OK;
}

SshOcspStatus
ssh_ocsp_response_decode(const unsigned char *der,
                         size_t der_len,
                         SshOcspResponse *message)
{
  SshAsn1Context  context = NULL;
  SshAsn1Tree     tree = NULL;
  SshAsn1Status   status = 0;
  SshOcspStatus   rv;

  /* Initialize the ASN.1 parser mallocation. */
  *message = NULL;
  if ((context = ssh_asn1_init()) != NULL)
    {
      status = ssh_asn1_decode(context, der, der_len, &tree);
      if (status != SSH_ASN1_STATUS_OK &&
          status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
          status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
        {
          ssh_asn1_free(context);
          return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
        }

      /* Allocate the response. The information given will be overwritten
         while at decoder. */
      if ((*message =
           ssh_ocsp_response_allocate(SSH_OCSP_VERSION_V1,
                                      SSH_OCSP_SUCCESSFUL,
                                      SSH_OCSP_RESPONSE_TYPE_BASIC,
                                      NULL)) != NULL)
        {
          if ((rv = ocsp_decode_response_message(context,
                                                 ssh_asn1_get_root(tree),
                                                 *message))
              != SSH_OCSP_STATUS_OK)
            {
              ssh_ocsp_response_free(*message);
              *message = NULL;
            }
          ssh_asn1_free(context);
          return rv;
        }
      ssh_asn1_free(context);
    }

  return SSH_OCSP_STATUS_INTERNAL_ERROR;
}

/*****************************************************************************
 * Access functions
 */
static void
ocsp_init_tbs_request(SshOcspTbsRequest request)
{
  request->requestor_name = NULL;
  request->request_list = ssh_glist_allocate();

  request->request_extensions = NULL;
}

static void
ocsp_init_request(SshOcspRequest message)
{
  ocsp_init_tbs_request(&message->tbs_request);

  message->optional_signature = NULL;
  message->signature_len = 0;

  message->cert_list = ssh_glist_allocate();
}


/* Allocate memory for the message, initialize the message and set the
   version number. */
SshOcspRequest
ssh_ocsp_request_allocate(SshOcspVersion version,
                          const SshX509Name requestor_name,
                          SshX509Attribute extensions)
{
  SshOcspRequest message = NULL;

  if ((message = ssh_calloc(1, sizeof(*message))) != NULL)
    {
      ocsp_init_request(message);
      message->tbs_request.version = version;
      if (requestor_name)
        message->tbs_request.requestor_name =
          ssh_x509_name_copy(requestor_name);
      message->tbs_request.request_extensions = extensions;
    }
  return message;
}

/* Deallocators */

static void
ocsp_cert_free_glist(SshGListNode node, void *context)
{
  SshOcspEncodedCert c = node->data;

  ssh_free(c->ber);
  ssh_free(c);
}

static void
ocsp_free_cert_id(SshOcspCertID cert_id)
{
  ssh_free(cert_id->hash_algorithm);
  ssh_free(cert_id->issuer_key_hash);
  ssh_free(cert_id->issuer_name_hash);
  ssh_mprz_clear(&cert_id->serial_number);
}

static void
ocsp_free_extensions(SshX509Attribute attr)
{
  SshX509Attribute temp = attr;

  for (temp = attr; temp; temp = attr)
    {
      attr = temp->next;

      ssh_free(temp->data);
      ssh_free(temp->oid);
      ssh_free(temp);
    }
}

void ssh_ocsp_request_free(SshOcspRequest request)
{
  SshGListNode gnode = NULL;

  /* Free single requests */
  for (gnode = request->tbs_request.request_list->head; gnode;)
    {
      SshOcspSingleRequest sreq = (SshOcspSingleRequest)gnode->data;

      gnode = gnode->next;

      ocsp_free_cert_id(&sreq->cert_id);
      ocsp_free_extensions(sreq->single_request_extensions);
      ssh_free(sreq);
    }

  ssh_glist_free(request->tbs_request.request_list);

  /* and the rest of the stuff */
  if (request->tbs_request.requestor_name)
    ssh_x509_name_free(request->tbs_request.requestor_name);

  ssh_free(request->optional_signature);
  ssh_free(request->verification);
  ocsp_free_extensions(request->tbs_request.request_extensions);
  ssh_glist_free_with_iterator(request->cert_list, ocsp_cert_free_glist, NULL);
  ssh_free(request);
}


SshOcspStatus
ssh_ocsp_request_add_single(SshOcspRequest message,
                            const char *hash_algorithm,
                            const SshX509Certificate issuer_certificate,
                            SshMPIntegerConst subject_serial,
                            SshX509Attribute single_request_extensions)
{
  SshOcspSingleRequest  request = NULL;

  if (issuer_certificate == NULL)
    return SSH_OCSP_STATUS_INVALID_CERTIFICATE;

  if (subject_serial == NULL)
    return SSH_OCSP_STATUS_INVALID_SERIAL_NUMBER;

  if ((request = ssh_calloc(1, sizeof(*request))) != NULL)
    {
      SshOcspStatus status;

      if ((status = ocsp_create_cert_id(&request->cert_id,
                                        hash_algorithm,
                                        issuer_certificate,
                                        subject_serial))
          != SSH_OCSP_STATUS_OK)
        {
          ssh_free(request);
          return status;
        }
      request->single_request_extensions = single_request_extensions;
    }
  else
    {
      return SSH_OCSP_STATUS_INTERNAL_ERROR;
    }

  /* add request to the list */
  ssh_glist_add_item(message->tbs_request.request_list, request,
                     SSH_GLIST_TAIL);
  return SSH_OCSP_STATUS_OK;
}


SshOcspStatus
ssh_ocsp_request_add_cert(SshOcspRequest message,
                          const unsigned char *ber, size_t ber_len)
{
  return ocsp_add_cert(message->cert_list, ber, ber_len);
}



/********************** response functions *************************/

SshOcspResponseStatus ssh_ocsp_response_get_status(SshOcspResponse response)
{
  return response->response_status;
}

SshOcspResponseType
ssh_ocsp_response_get_response_type(SshOcspResponse response)
{
  return response->response_type;
}

SshOcspVersion ssh_ocsp_response_get_version(SshOcspResponse response)
{
  return response->response.tbs_response_data.version;
}

SshOcspResponderIDType
ssh_ocsp_response_get_responder_id_type(SshOcspResponse response)
{
  return response->response.tbs_response_data.responder_id.type;
}

SshX509Name
ssh_ocsp_response_get_responder_name(SshOcspResponse response)
{
  if (response->response.tbs_response_data.responder_id.type
      == SSH_OCSP_RESPONDER_BY_NAME)
    {
      return response->response.tbs_response_data.responder_id.id.ByName.name;
    }
  else
    {
      return NULL;
    }
}

const unsigned char *
ssh_ocsp_response_get_responder_key(SshOcspResponse response,
                                    size_t *key_len)
{
  if (response->response.tbs_response_data.responder_id.type
      == SSH_OCSP_RESPONDER_BY_KEY)
    {
      *key_len =
        response->response.tbs_response_data.responder_id.id.ByKey.hash_len;
      return
        response->response.tbs_response_data.responder_id.id.ByKey.key_hash;
    }
  else
    {
      return NULL;
    }
}

SshTime ssh_ocsp_response_get_production_time(SshOcspResponse response)
{
  return ssh_ber_time_get_unix_time(&response->response.
                                    tbs_response_data.produced_at);
}

SshX509Attribute
ssh_ocsp_response_get_extensions(SshOcspResponse response)
{
  return response->response.tbs_response_data.response_extensions;
}

void ssh_ocsp_response_get_signature(SshOcspResponse response,
                                     const char **signature_algorithm,
                                     const unsigned char **signature,
                                     size_t *signature_len)
{
  *signature = response->response.signature;
  *signature_len = response->response.signature_len;
  *signature_algorithm = response->response.signature_algorithm;
}


/* Free memory allocated for the response message */
void ssh_ocsp_response_free(SshOcspResponse message)
{
  SshGListNode gnode = NULL;

  for (gnode = message->response.tbs_response_data.response_list->head;
       gnode;)
    {
      SshOcspSingleResponse response = (SshOcspSingleResponse) gnode->data;

      gnode = gnode->next;

      ocsp_free_cert_id(&response->cert_id);
      ocsp_free_extensions(response->single_extensions);
      ssh_free(response);
    }

  ssh_glist_free(message->response.tbs_response_data.response_list);
  ssh_free(message->response.tbs_response_data.data);
  if (message->response.tbs_response_data.responder_id.type ==
      SSH_OCSP_RESPONDER_BY_NAME)
    ssh_x509_name_free(message->response.tbs_response_data.
                       responder_id.id.ByName.name);
  else
    ssh_free(message->response.tbs_response_data.
              responder_id.id.ByKey.key_hash);

  ocsp_free_extensions(message->
                       response.tbs_response_data.response_extensions);
  ssh_free(message->response.signature);
  ssh_free(message->response_bytes);
  ssh_free(message->verification);
  ssh_glist_free_with_iterator(message->response.cert_list,
                               ocsp_cert_free_glist,
                               NULL);
  ssh_free(message);
}

static Boolean
ocsp_init_response_data(SshOcspTbsResponseData response)
{
  ssh_ber_time_zero(&response->produced_at);

  response->responder_id.type = SSH_OCSP_RESPONDER_BY_KEY;
  response->responder_id.id.ByKey.key_hash = NULL;
  response->responder_id.id.ByKey.hash_len = 0;
  response->response_extensions = NULL;
  response->response_list = ssh_glist_allocate();
  response->data = NULL;
  response->data_len = 0;
  return response->response_list != NULL;
}

static Boolean
ocsp_init_basic_response(SshOcspBasicResponse response)
{
  Boolean rv;
  if ((response->cert_list = ssh_glist_allocate()) == NULL)
    return FALSE;

  response->signature_algorithm = NULL;
  response->signature = NULL;
  response->signature_len = 0;
  if ((rv = ocsp_init_response_data(&response->tbs_response_data)) != TRUE)
    ssh_glist_free(response->cert_list);
  return rv;
}

static Boolean
ocsp_response_init_message(SshOcspResponse message)
{
  message->response_type = SSH_OCSP_RESPONSE_TYPE_BASIC;
  message->response_bytes = NULL;
  message->response_len = 0;
  message->response_status = 0;

  return ocsp_init_basic_response(&message->response);
}

SshOcspResponse
ssh_ocsp_response_allocate(SshOcspVersion version,
                           SshOcspResponseStatus status,
                           SshOcspResponseType response_type,
                           SshX509Attribute extensions)
{
  SshOcspResponse message = NULL;

  /* Check that the parameters are valid. Other response types than
     basic are only allowed when the response is not successful (then
     the response type is not used at all). */
  if (version != SSH_OCSP_VERSION_V1 ||
      (response_type != SSH_OCSP_RESPONSE_TYPE_BASIC &&
       status == SSH_OCSP_SUCCESSFUL))
    {
      return NULL;
    }

  if ((message = ssh_calloc(1, sizeof(*message))) != NULL)
    {
      message->response.tbs_response_data.version = version;
      message->response.tbs_response_data.version_available = TRUE;
      if (!ocsp_response_init_message(message))
        {
          ssh_free(message);
          return NULL;
        }

      message->response_status = status;
      if (response_type == SSH_OCSP_RESPONSE_TYPE_BASIC)
        message->response_type = response_type;
      else
        message->response_type = SSH_OCSP_RESPONSE_TYPE_BASIC;
      message->response.tbs_response_data.response_extensions = extensions;
    }
  return message;
}



SshOcspStatus
ssh_ocsp_response_get_responses(SshOcspResponse message,
                                SshOcspBasicSingleResponse *responses,
                                size_t *num_responses)
{
  int i = 0;
  SshGListNode node = NULL;
  SshGList response_list =
    message->response.tbs_response_data.response_list;

  *num_responses = response_list->num_n;
  *responses = NULL;

  if (*num_responses > 0 && response_list->head != NULL)
    {
      /* Allocate memory */
      if ((*responses = ssh_malloc(*num_responses * sizeof(**responses)))
          == NULL)
        return SSH_OCSP_STATUS_INTERNAL_ERROR;
    }

  for (node = response_list->head; node; node = node->next, i++)
    {
      SshOcspSingleResponse single_response = node->data;

      if (*responses == NULL)
        return SSH_OCSP_STATUS_INTERNAL_ERROR;

      (*responses)[i].cert_id = single_response->cert_id;
      (*responses)[i].this_update =
        ssh_ber_time_get_unix_time(&single_response->this_update);

      if (ssh_ber_time_available(&single_response->next_update))
        {
          (*responses)[i].next_update =
            ssh_ber_time_get_unix_time(&single_response->next_update);
          (*responses)[i].next_update_available = TRUE;
        }
      else
        {
          (*responses)[i].next_update = 0;
          (*responses)[i].next_update_available = FALSE;
        }

      (*responses)[i].single_response_extensions =
        single_response->single_extensions;
      (*responses)[i].status = single_response->status;
    }

  return SSH_OCSP_STATUS_OK;
}


void
ssh_ocsp_response_get_certs(SshOcspResponse message,
                            SshOcspEncodedCert *certs, size_t *ncerts)
{
  *ncerts = ocsp_get_certs(message->response.cert_list, certs);
}


/* This function verifies the signature based authentication
   from the message. The signature is checked using the
   public key. The `callback' is called when the public key operation
   is completed. */

SshOperationHandle
ssh_ocsp_response_verify_signature(SshOcspResponse response,
                                   const SshPublicKey public_key,
                                   SshOcspVerifyCB callback,
                                   void *callback_context)
{
  return ocsp_verify_signature(response->response.signature_algorithm,
                               response->response.signature,
                               response->response.signature_len,
                               response->verification,
                               response->verification_len,
                               public_key,
                               callback, callback_context);
}

/* end of ocsp_client.c */
#endif /* SSHDIST_CERT */
