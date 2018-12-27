/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SCEP protocol, client side.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshinet.h"
#include "sshasn1.h"
#include "sshfsm.h"

#include "x509.h"
#include "x509internal.h"

#include "sshpkcs7.h"
#include "x509scep.h"
#include "scep-internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshX509Scep"

SSH_FSM_STEP(scep_encode_request);
SSH_FSM_STEP(scep_encode_selfsigned);
SSH_FSM_STEP(scep_encode_pkcs7);
SSH_FSM_STEP(scep_encode_done);
SSH_FSM_STEP(scep_encode_poll);

/* FSM thread context used to store various data structures while
   encoding SCEP request using asynchronous private key operations.
   When freeing something from this context remember to set the value
   to NULL, as finishing routines will free non-null pointers. */

typedef struct SshScepEncodeRec
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
  SshPkcs7RecipientInfo recipient;

  char type[3];

  /* NOTE: the request is not freed by the library. It is constant by
     nature. */
  SshX509Certificate request_x509;
  SshX509Certificate selfsigned_x509;
  SshX509Name subjectname, caname;

  unsigned char *selfsigned; size_t selfsigned_len;
  unsigned char *request; size_t request_len;
  unsigned char *kid; size_t kid_len;
  unsigned char snonce[16];

  SshPkcs7 sdp;

  SshOperationHandle op;
  SshFSMThread thread;

  SshScepStatus status;
  SshScepClientResultCB callback;
  void *callback_context;

  SshX509ConfigStruct config;

} *SshScepEncode, SshScepEncodeStruct;


/* REQUEST */
static void
scep_encode_request_done(SshX509Status status,
                         const unsigned char *der, size_t der_len,
                         void *context)
{
  SshScepEncode tdata = context;

  if (status == SSH_X509_OK)
    {
      tdata->request = ssh_memdup(der, der_len);
      tdata->request_len = der_len;
    }
  else
    {
      tdata->status = SSH_SCEP_FAILURE;
      ssh_fsm_set_next(tdata->thread, scep_encode_done);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(tdata->thread);
}

SSH_FSM_STEP(scep_encode_request)
{
  SshScepEncode tdata = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(scep_encode_selfsigned);
  SSH_FSM_ASYNC_CALL({
    tdata->op = ssh_x509_cert_encode_async(tdata->request_x509,
                                           tdata->prvkey,
                                           scep_encode_request_done, tdata);
  });
}

/* SELFSIGNED */
static void
scep_encode_selfsigned_done(SshX509Status status,
                            const unsigned char *der, size_t der_len,
                            void *context)
{
  SshScepEncode tdata = context;

  if (status == SSH_X509_OK)
    {
      tdata->selfsigned = ssh_memdup(der, der_len);
      tdata->selfsigned_len = der_len;
    }
  else
    {
      tdata->status = SSH_SCEP_FAILURE;
      ssh_fsm_set_next(tdata->thread, scep_encode_done);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(tdata->thread);
}

SSH_FSM_STEP(scep_encode_selfsigned)
{
  SshBerTimeStruct from, to;
  SshMPIntegerStruct serialno;
  SshX509Certificate selfsigned;
  unsigned char *kid;
  size_t kid_len;
  SshScepEncode tdata = ssh_fsm_get_tdata(thread);

  selfsigned = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  ssh_ber_time_set_from_unix_time(&from, (ssh_time() - 900));
  ssh_ber_time_set(&to, &from);
  ssh_ber_time_add_secs(&to, 900 + (3600 * 24 * 7)); /* week */
  ssh_x509_cert_set_validity(selfsigned, &from, &to);
  ssh_x509_cert_set_public_key(selfsigned, tdata->pubkey);
  ssh_x509_cert_set_key_usage(selfsigned, SSH_X509_UF_DIGITAL_SIGNATURE, TRUE);
  selfsigned->issuer_name = ssh_x509_name_copy(tdata->subjectname);
  selfsigned->subject_name = ssh_x509_name_copy(tdata->subjectname);

  ssh_mprz_init(&serialno);
  kid = ssh_x509_cert_compute_key_identifier(selfsigned, "md5", &kid_len);
  if (kid)
    {
      ssh_mprz_set_buf(&serialno, kid, kid_len);
     ssh_x509_cert_set_serial_number(selfsigned, &serialno);
    }
  ssh_mprz_clear(&serialno);

  SSH_FSM_SET_NEXT(scep_encode_pkcs7);
  SSH_FSM_ASYNC_CALL({
    tdata->kid = kid;
    tdata->kid_len = kid_len;
    tdata->selfsigned_x509 = selfsigned;
    tdata->op = ssh_x509_cert_encode_async(selfsigned,
                                           tdata->prvkey,
                                           scep_encode_selfsigned_done, tdata);
  });
}

/* SCEP PKCS#7 ENVELOPE */
static void
scep_encode_pkcs7_done(SshPkcs7Status status,
                       SshPkcs7 sdp,
                       void *context)
{
  SshScepEncode tdata = context;

  ssh_pkcs7_add_certificate(sdp, tdata->selfsigned, tdata->selfsigned_len);
  ssh_free(tdata->selfsigned);
  tdata->selfsigned = NULL;

  tdata->sdp = sdp;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(tdata->thread);
}

SSH_FSM_STEP(scep_encode_pkcs7)
{
  SshPkcs7 dp1, dp2, edp;
  SshPkcs7SignerInfo signer = NULL;
  SshX509Attribute authattrs;
  size_t i, ber_len;
  unsigned char *ber;
  SshScepEncode tdata = ssh_fsm_get_tdata(thread);

  dp1 = ssh_pkcs7_create_data(tdata->request, tdata->request_len);
  ssh_free(tdata->request);
  tdata->request = NULL;

  edp = ssh_pkcs7_create_enveloped_data(dp1, "des-cbc", tdata->recipient);
  tdata->recipient = NULL;
  if (edp == NULL || ssh_pkcs7_encode(edp, &ber, &ber_len) != SSH_PKCS7_OK)
    {
      if (edp != NULL)
        ssh_pkcs7_free(edp);
      tdata->status = SSH_SCEP_FAILURE;
      SSH_FSM_SET_NEXT(scep_encode_done);
      return SSH_FSM_CONTINUE;
    }

  ssh_pkcs7_free(edp);
  dp2 = ssh_pkcs7_create_data(ber, ber_len);
  ssh_free(ber);

  for (i = 0; i < sizeof(tdata->snonce); i++)
    tdata->snonce[i] = ssh_random_get_byte();

  authattrs = scep_add_attributes(tdata->type,
                                  NULL, NULL,
                                  tdata->snonce, sizeof(tdata->snonce),
                                  NULL, 0, tdata->kid, tdata->kid_len);

  signer = ssh_pkcs7_create_signer("md5", "rsaEncryption",
                                   tdata->prvkey, tdata->selfsigned_x509,
                                   authattrs, NULL,
                                   NULL);

  ssh_x509_cert_free(tdata->selfsigned_x509);
  tdata->selfsigned_x509 = NULL;

  SSH_FSM_SET_NEXT(scep_encode_done);
  SSH_FSM_ASYNC_CALL({
    tdata->op = ssh_pkcs7_create_signed_data_async(dp2, signer,
                                                   scep_encode_pkcs7_done,
                                                   tdata);
  });
}

/* DONE */
SSH_FSM_STEP(scep_encode_done)
{
  unsigned char *ber = NULL;
  size_t ber_len;
  struct SshScepTransactionAndNonceRec txnonce;
  SshScepEncode tdata = ssh_fsm_get_tdata(thread);

  if (tdata->status == SSH_SCEP_OK &&
      ssh_pkcs7_encode(tdata->sdp, &ber, &ber_len) == SSH_PKCS7_OK)
    {
      memmove(txnonce.transaction_id, tdata->kid, tdata->kid_len);
      memmove(txnonce.nonce, tdata->snonce, sizeof(tdata->snonce));
      (*tdata->callback)(tdata->status, 0L,
                         &txnonce, ber, ber_len, tdata->callback_context);

      ssh_free(ber);
    }
  else
    {
      (*tdata->callback)(tdata->status, 0L,
                         NULL, NULL, 0, tdata->callback_context);
    }

  if (tdata->selfsigned_x509)
    ssh_x509_cert_free(tdata->selfsigned_x509);

  ssh_private_key_free(tdata->prvkey);
  ssh_public_key_free(tdata->pubkey);
  ssh_pkcs7_free_recipient_info(tdata->recipient);

  ssh_x509_cert_free(tdata->selfsigned_x509);
  ssh_x509_name_free(tdata->subjectname);
  ssh_x509_name_free(tdata->caname);

  ssh_free(tdata->selfsigned);
  ssh_free(tdata->request);
  ssh_free(tdata->kid);

  ssh_pkcs7_free(tdata->sdp);
  ssh_free(tdata);
  ssh_fsm_destroy(ssh_fsm_get_fsm(thread));
  return SSH_FSM_FINISH;
}

SshScepStatus
ssh_scep_create_request(const SshPrivateKey private_key,
                        const SshX509Certificate req,
                        const SshX509Certificate cara_encryption,
                        SshScepClientResultCB result_callback,
                        void *context)
{
  SshFSM fsm;
  SshScepEncode tdata;
  SshFSMThread thread = NULL;

  fsm = ssh_fsm_create(NULL);
  if (fsm)
    {
      if ((tdata = ssh_calloc(1, sizeof(*tdata))) != NULL)
        thread = ssh_fsm_thread_create(fsm,
                                       scep_encode_request,
                                       NULL_FNPTR, NULL_FNPTR,
                                       tdata);
      if (thread && tdata)
        {
          strcpy(tdata->type, "19");

          /* This does not get used after initial step, which happens
             synchronously. */
          tdata->request_x509 = req;
          tdata->subjectname = ssh_x509_name_copy(req->subject_name);
          tdata->caname = NULL;
          tdata->thread = thread;
          tdata->callback = result_callback;
          tdata->callback_context = context;
          tdata->recipient =
            ssh_pkcs7_create_recipient("rsaEncryption", cara_encryption, NULL);
          ssh_private_key_copy(private_key, &tdata->prvkey);
          ssh_public_key_copy(req->subject_pkey.public_key, &tdata->pubkey);

          memmove(&tdata->config, &req->config, sizeof(tdata->config));

          return SSH_SCEP_OK;
        }
      ssh_fsm_destroy(fsm);
      ssh_free(tdata);
    }
  return SSH_SCEP_ERROR;
}

SSH_FSM_STEP(scep_encode_poll)
{
  unsigned char *is_data = NULL;
  size_t is_data_len = 0;
  SshAsn1Node ca_dn_node, subject_dn_node, issuersubject;
  SshAsn1Context asn1context;
  SshScepEncode tdata = ssh_fsm_get_tdata(thread);

  if ((asn1context = ssh_asn1_init()) == NULL)
    goto failure;

  ssh_x509_name_reset(tdata->subjectname);
  ca_dn_node = ssh_x509_encode_dn_name(asn1context,
                                       SSH_X509_NAME_DISTINGUISHED_NAME,
                                       tdata->subjectname,
                                       &tdata->config);
  ssh_x509_name_reset(tdata->caname);
  subject_dn_node = ssh_x509_encode_dn_name(asn1context,
                                            SSH_X509_NAME_DISTINGUISHED_NAME,
                                            tdata->caname,
                                            &tdata->config);
  if (ssh_asn1_create_node(asn1context, &issuersubject,
                           "(sequence ()"
                           " (any ())"
                           " (any ()))",
                           ca_dn_node, subject_dn_node)
      == SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_encode_node(asn1context, issuersubject);
      ssh_asn1_node_get_data(issuersubject, &is_data, &is_data_len);
      ssh_asn1_free(asn1context);
      SSH_FSM_SET_NEXT(scep_encode_selfsigned);
    }
  else
    {
      ssh_asn1_free(asn1context);
    failure:
      tdata->status = SSH_SCEP_ERROR;
      SSH_FSM_SET_NEXT(scep_encode_done);
    }

  tdata->request = is_data;
  tdata->request_len = is_data_len;
  return SSH_FSM_CONTINUE;
}

SshScepStatus
ssh_scep_create_poll(const SshPrivateKey private_key,
                     const SshX509Certificate req,
                     const SshX509Certificate cara_encryption,
                     SshScepClientResultCB result_callback,
                     void *context)
{
  SshFSM fsm;
  SshScepEncode tdata;
  SshFSMThread thread = NULL;

  fsm = ssh_fsm_create(NULL);
  if (fsm)
    {
      if ((tdata = ssh_calloc(1, sizeof(*tdata))) != NULL)
        thread = ssh_fsm_thread_create(fsm,
                                       scep_encode_poll,
                                       NULL_FNPTR, NULL_FNPTR,
                                       tdata);
      if (tdata && thread)
        {
          tdata = ssh_fsm_get_tdata(thread);
          memset(tdata, 0, sizeof(*tdata));
          strcpy(tdata->type, "20");

          /* This does not get used after initial step, which happens
             synchronously. */
          tdata->request_x509 = req;
          tdata->subjectname = ssh_x509_name_copy(req->subject_name);
          tdata->caname = ssh_x509_name_copy(cara_encryption->subject_name);
          tdata->thread = thread;
          tdata->callback = result_callback;
          tdata->callback_context = context;
          tdata->recipient =
            ssh_pkcs7_create_recipient("rsaEncryption", cara_encryption, NULL);
          ssh_private_key_copy(private_key, &tdata->prvkey);
          ssh_public_key_copy(req->subject_pkey.public_key, &tdata->pubkey);

          return SSH_SCEP_OK;
        }
      ssh_fsm_destroy(fsm);
      ssh_free(tdata);
    }
  return SSH_SCEP_ERROR;
}

static SSH_FSM_STEP(scep_rep_done);
static SSH_FSM_STEP(scep_rep_decrypt);
static SSH_FSM_STEP(scep_rep_verify);
static SSH_FSM_STEP(scep_rep_get_keys);

static SSH_FSM_STEP(scep_rep_done)
{
  SSH_DEBUG(SSH_D_FAIL,
            ("SCEP; response parsing done: "
             "application callback already called with reason indicator."));
  return SSH_FSM_FINISH;
}

static void
scep_rep_decrypt_done(SshPkcs7Status status, SshPkcs7 content, void *context)
{
  ScepUserQueryContext uq = context;
  SshPkcs7 plaintext, tmp = NULL;
  const unsigned char *data;
  unsigned char **bers = NULL;
  size_t len, *ber_lens, ncerts;

  if (status == SSH_PKCS7_OK)
    {
      plaintext = ssh_pkcs7_get_content(content);

      /* It is now either data containing degenerated signed data, or
         the degenerated signed data directly. */
      if (ssh_pkcs7_get_content_type(plaintext) == SSH_PKCS7_DATA)
        {
          /* It may contain data that contains encoded enveloped data */
          ssh_pkcs7_content_data(plaintext, &data, &len);
          if (ssh_pkcs7_decode(data, len, &tmp) == SSH_PKCS7_OK)
            {
              SSH_ASSERT(tmp != NULL);
              plaintext = tmp;
            }
          else
            goto failure;
        }

      if (ssh_pkcs7_get_content_type(plaintext) != SSH_PKCS7_SIGNED_DATA)
        goto failure;

      ncerts = ssh_pkcs7_get_certificates(plaintext, &bers, &ber_lens);
      if (ncerts == 0)
        goto failure;

      (*uq->client_result_callback)(SSH_SCEP_OK, 0,
                                    &uq->txnonce,
                                    bers[0], ber_lens[0],
                                    uq->result_callback_context);

      if (tmp) ssh_pkcs7_free(tmp);
      ssh_pkcs7_free(content);
      ssh_free(bers);
      ssh_free(ber_lens);
    }
  else
    {
    failure:
      (*uq->client_result_callback)(SSH_SCEP_ERROR, SSH_SCEP_FINFO_BAD_CHECK,
                                    &uq->txnonce,
                                    NULL, 0, uq->result_callback_context);
      ssh_pkcs7_free(content);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&uq->thread);
}

static SSH_FSM_STEP(scep_rep_decrypt)
{
  ScepUserQueryContext uq = ssh_fsm_get_tdata(thread);
  SshPkcs7RecipientInfo *recipients = NULL;
  SshPkcs7 content, top;
  SshX509Attribute auth_attrs, attr;
  char *status = NULL, *finfo = NULL;
  const unsigned char *data;
  size_t status_len, finfo_len, len;
  SshUInt32 nrecipients;
  SshAsn1Context asn1context;

  SSH_FSM_SET_NEXT(scep_rep_done);

  top = uq->content;
  content = ssh_pkcs7_get_content(top);

  ssh_pkcs7_signer_get_attributes(uq->signer, NULL, NULL, &auth_attrs, NULL);

  if ((asn1context = ssh_asn1_init()) != NULL)
    {
      for (attr = auth_attrs; attr; attr = attr->next)
        {
          if (strcmp(attr->oid, SCEP_STATUS) == 0)
            DECODE_STRING(asn1context, attr, status, &status_len);
          if (strcmp(attr->oid, SCEP_FINFO) == 0)
            DECODE_STRING(asn1context, attr, finfo, &finfo_len);
        }
      ssh_asn1_free(asn1context);
    }

  if (status == NULL)
    {
      ssh_free(finfo);
      goto failure;
    }

  if (strncasecmp(status, "3", status_len) == 0)
    {
      (*uq->client_result_callback)(SSH_SCEP_PENDING, 0,
                                    &uq->txnonce, NULL, 0,
                                    uq->result_callback_context);
      ssh_free(status);
      ssh_free(finfo);
      return SSH_FSM_CONTINUE;
    }

  if (strncasecmp(status, "2", status_len) == 0)
    {
      (*uq->client_result_callback)(SSH_SCEP_FAILURE, finfo ? atoi(finfo): 0,
                                    &uq->txnonce, NULL, 0,
                                    uq->result_callback_context);
      ssh_free(status);
      ssh_free(finfo);
      return SSH_FSM_CONTINUE;
    }

  if (strncasecmp(status, "0", status_len) == 0)
    {
      ssh_free(status);
      ssh_free(finfo);
      if (ssh_pkcs7_get_content_type(content) == SSH_PKCS7_DATA)
        {
          /* It may contain data that contains encoded enveloped data */
          ssh_pkcs7_content_data(content, &data, &len);
          if (ssh_pkcs7_decode(data, len, &content) == SSH_PKCS7_OK)
            {
              ssh_pkcs7_free(top);
              uq->top = NULL;
              top = content;
            }
          else
            goto failure;
        }

      if (ssh_pkcs7_get_content_type(content) != SSH_PKCS7_ENVELOPED_DATA)
        goto failure;

      nrecipients = ssh_pkcs7_get_recipients(content, &recipients);
      if (nrecipients == 0 || nrecipients > 1)
        {
          if (nrecipients) ssh_free(recipients);
          goto failure;
        }

      SSH_FSM_ASYNC_CALL({
        ssh_pkcs7_content_decrypt_async(content,
                                        recipients[0], uq->private_key,
                                        scep_rep_decrypt_done, uq);
        ssh_free(recipients);
      });
    }
  /* NOTREACHED */

 failure:
  (*uq->client_result_callback)(SSH_SCEP_ERROR, SSH_SCEP_FINFO_BAD_ALG,
                                &uq->txnonce,
                                NULL, 0, uq->result_callback_context);
  return SSH_FSM_CONTINUE;
}

static void
scep_rep_verify_done(SshPkcs7Status status, SshPkcs7 content, void *context)
{
  ScepUserQueryContext uq = context;

  if (status != SSH_PKCS7_OK)
    {
      ssh_fsm_set_next(&uq->thread, scep_rep_done);
      (*uq->client_result_callback)(SSH_SCEP_ERROR, SSH_SCEP_FINFO_BAD_CHECK,
                                    &uq->txnonce,
                                    NULL, 0, uq->result_callback_context);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(&uq->thread);
}

static SSH_FSM_STEP(scep_rep_verify)
{
  ScepUserQueryContext uq = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(scep_rep_decrypt);
  SSH_FSM_ASYNC_CALL({
    ssh_pkcs7_content_verify_async(uq->content,
                                   uq->signer, uq->ca_public_key,
                                   scep_rep_verify_done, uq);
  });
}

static void
scep_rep_request_done(const SshX509Certificate ca,
                      const SshPrivateKey private_key,
                      void *context)
{
  ScepUserQueryContext uq = context;

  if (private_key == NULL ||
      ca == NULL || !ssh_x509_cert_get_public_key(ca, &uq->ca_public_key))
    {
      ssh_fsm_set_next(&uq->thread, scep_rep_done);
      (*uq->client_result_callback)(SSH_SCEP_ERROR, SSH_SCEP_FINFO_BAD_CHECK,
                                    &uq->txnonce,
                                    NULL, 0, uq->result_callback_context);
    }
  else
    {
      ssh_private_key_copy(private_key, &uq->private_key);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&uq->thread);
}

static SSH_FSM_STEP(scep_rep_get_keys)
{
  ScepUserQueryContext uq = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(scep_rep_verify);
  SSH_FSM_ASYNC_CALL({
    (*uq->client_request_callback)(&uq->txnonce,
                                   scep_rep_request_done, uq,
                                   uq->result_callback_context);
  });
}

static void scep_rep_thread_destroy(SshFSM fsm, void *context)
{
  ScepUserQueryContext uq = context;

  if (uq->top)
    ssh_pkcs7_free(uq->top);

  ssh_public_key_free(uq->ca_public_key);
  ssh_private_key_free(uq->private_key);
  ssh_fsm_destroy(uq->fsm);
  ssh_free(uq);
}

SshScepStatus
ssh_scep_parse_response(const unsigned char *response, size_t response_len,
                        SshScepClientCertAndKeyReq request_callback,
                        SshScepClientResultCB result_callback,
                        void *shared_callback_context)
{
  SshPkcs7 sdp;
  SshPkcs7SignerInfo *signers = NULL;
  ScepUserQueryContext uq;
  unsigned char *txid = NULL, *rnonce = NULL;
  char *txtype = NULL;
  size_t txid_len, txtype_len, nsigners, rnonce_len;
  SshX509Attribute auth_attrs, attr;
  SshAsn1Context context;

  if (ssh_pkcs7_decode(response, response_len, &sdp) != SSH_PKCS7_OK)
    return SSH_SCEP_ERROR;

  if (ssh_pkcs7_get_content_type(sdp) != SSH_PKCS7_SIGNED_DATA)
    {
      ssh_pkcs7_free(sdp);
      return SSH_SCEP_ERROR;
    }

  /* It will always have exactly one signer (scep, not only pkcs7) */
  nsigners = ssh_pkcs7_get_signers(sdp, &signers);
  if (nsigners == 0 || nsigners > 1)
    {
      ssh_pkcs7_free(sdp);
      ssh_free(signers);
      return SSH_SCEP_ERROR;
    }

  /* Get transaction type from the authenticated attributes. We will
     check it now. If it was a fake, we'll notice it later, when
     validating response. */
  if (!ssh_pkcs7_signer_get_attributes(signers[0],
                                       NULL, NULL, &auth_attrs, NULL))
    {
      ssh_pkcs7_free(sdp);
      ssh_free(signers);
      return SSH_SCEP_ERROR;
    }

  if ((context = ssh_asn1_init()) != NULL)
    {
      for (attr = auth_attrs; attr; attr = attr->next)
        {
          if (strcmp(attr->oid, SCEP_RNONCE) == 0)
            DECODE_STRING(context, attr, rnonce, &rnonce_len);
          if (strcmp(attr->oid, SCEP_TXID) == 0)
            DECODE_STRING(context, attr, txid, &txid_len);
          if (strcmp(attr->oid, SCEP_TXTYPE) == 0)
            DECODE_STRING(context, attr, txtype, &txtype_len);
        }
      ssh_asn1_free(context);
      context = NULL;
    }
  /* For unicert; assume transaction type 3. It is not set on the response. */
  if (txtype == NULL)
    txtype = ssh_strdup("3");
  if (strcmp(txtype, "3") != 0)
    {
    failure:
      ssh_pkcs7_free(sdp);
      ssh_free(signers);
      ssh_free(rnonce);
      ssh_free(txid);
      ssh_free(txtype);
      if (context) ssh_asn1_free(context);
      return SSH_SCEP_ERROR;
    }

  /* Start FSM to perform validation and decryption. */
  if ((uq = ssh_calloc(1, sizeof(*uq))) == NULL ||
      (uq->fsm = ssh_fsm_create(NULL)) == NULL)
    {
      ssh_free(uq);
      goto failure;
    }

  uq->signer = signers[0];
  ssh_free(signers);

  uq->top = sdp;
  uq->content = sdp;
  uq->client_result_callback = result_callback;
  uq->client_request_callback = request_callback;
  uq->result_callback_context = shared_callback_context;
  uq->data = response;
  uq->data_len = response_len;

  /* M$ certsrv does not set this for pending replies */
  if (rnonce)
    memmove(uq->txnonce.nonce,
            rnonce,
            sizeof(uq->txnonce.nonce) > rnonce_len
            ? rnonce_len
            : sizeof(uq->txnonce.nonce));
  uq->txnonce.nonce_len = rnonce_len;

  /* nor this */
  if (txid)
    memmove(uq->txnonce.transaction_id,
            txid, sizeof(uq->txnonce.transaction_id));
  uq->txnonce.transaction_id_len = txid_len;

  ssh_free(rnonce);
  ssh_free(txid);
  ssh_free(txtype);

  ssh_fsm_thread_init(uq->fsm, &uq->thread,
                      scep_rep_get_keys, NULL_FNPTR, scep_rep_thread_destroy,
                      uq);
  return SSH_SCEP_OK;
}

/* eof */
#endif /* SSHDIST_CERT */
