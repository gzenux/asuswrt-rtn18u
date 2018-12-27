/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CMPv2 (RFC2510bis) client.

   Key-pair generation, End Entity Initialization, Certificate
   requests, key updates, and Certificate Revocation.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshfileio.h"
#include "sshexternalkey.h"
#include "sshgetopt.h"
#include "x509.h"
#include "x509cmp.h"
#include "sshfsm.h"
#include "sshurl.h"
#include "sshglobals.h"
#include "sshdsprintf.h"
#include "sshcrmf.h"
#include "sshnameserver.h"

#include "au-ek.h"
#include "ec-cmp.h"

#include "iprintf.h"

extern int brokenflags;

/* Global variable */
char * prog;


/*
  ssh-cmpclient

        initialize      psk keyspec template
        enroll          certpair keyspec template
        update          certpair [keyspec]

                        -B
                        -x message-prefix

        recover         psk template
        recover         certpair template
        revoke          psk template
        revoke          certpair template

--- begin not yet
        send            message-prefix
        info
--- end not yet
                        -o output-prefix default "subject"
                        -r state-file
                        -S socks-url
                        -C CA certificate

                        access-point-url
                        [recipient-name] if not -C

        psk             = -p kid:key
                        = -i iteration count default 1024
        certpair        = -k private-key-path -c certificate-path
        keyspec         = -P private-key-path (EK/generate/file, PIN incl'd)
        template        = -T certificate or request
                        = -s LDAP-name[;type=value]
                        = -u key-usage-name[;key-usage-name]
                        = -U extented-key-usage-name[;extented-key-usage-name]

        -h help

        template =
        `send' is a special form for testing purposes.

*/

#define SSH_DEBUG_MODULE "SshCmpClient"

#define D(x) ssh_warning((x))

typedef struct
SshCmpEnrollClientRec *SshCmpEnrollClient, SshCmpEnrollClientStruct;

typedef struct SshCmpEnrollCaRec
{
  SshCmpVersion protocol_version;
  Boolean transport_level_poll;
  const unsigned char *name; /* or */
  const char *cert_file; unsigned char *cert; size_t cert_len;

  const unsigned char *socks_url;
  const unsigned char *access_url;
  const unsigned char *proxy_url;
  Boolean has_psk;
  const unsigned char *psk_userid;
  size_t psk_userid_len;
  const unsigned char *psk_password;
  size_t psk_password_len;
  unsigned int count;

  Boolean rfc2511_compatibility;
  Boolean prefer_sha256;
} *SshCmpEnrollCa, SshCmpEnrollCaStruct;

typedef struct SshCmpEnrollCertRec
{
  const char *prvkey_path;
  SshPrivateKey prvkey;

  const char *cert_path;
  unsigned char *cert; size_t cert_len;
  SshX509Certificate certtemp;

  Boolean do_backup;
  SshPrivateKey protocol_encryption_key;
  SshCmpEnrollClient client;
} *SshCmpEnrollCert, SshCmpEnrollCertStruct;

struct SshCmpEnrollClientRec
{
  char *save_prefix;
  char *output_prefix;
  char *statefile;
  Boolean encryption_pop;

  SshCmpEnrollCaStruct ca;
  SshCmpEnrollCertStruct current;
  SshCmpEnrollCertStruct subject;

  /* Certs that the server might need when processing ir or kur. */
  size_t num_extra_certs;
  SshEcCertStruct *extra_certs;

  SshCmpBodyType opcode;
  SshFSMThread thread;
  SshExternalKey ek;

  SshEcCmpCertRepCB reply;
  void *reply_context;
  int reply_ncerts;

  SshUInt32 num_poll_ids;
  SshMPIntegerStruct *poll_ids;

  Boolean yes_mode;

  int retval;
};

void
ec_cmp_add_cert(SshEcCertStruct **extra_certs_ret, size_t *num_extra_certs_ret,
                const unsigned char *der, size_t der_len)
{
  size_t new_size = *num_extra_certs_ret + 1;
  *extra_certs_ret = ssh_xrealloc(*extra_certs_ret,
                                  new_size * sizeof(SshEcCertStruct));
  (*extra_certs_ret)[new_size - 1].ber = ssh_xmemdup(der, der_len);
  (*extra_certs_ret)[new_size - 1].ber_len = der_len;
  *num_extra_certs_ret = new_size;
  SSH_TRACE(2, ("Currently sending %ld extra certificate%s.", new_size,
                new_size == 1 ? "" : "s"));
}

/* CMP: start; fetch subject key pair. */
SSH_FSM_STEP(ec_cmp_get_subject_keys);
/* CMP: have subject; fetch auth key pair. */
SSH_FSM_STEP(ec_cmp_get_auth_keys);
/* CMP: have keys, enroll with CA, wait. */
SSH_FSM_STEP(ec_cmp_enroll);
/* CMP: enrollment done. */
SSH_FSM_STEP(ec_cmp_cleanup);

static void
ec_cmp_get_keys_done(SshEkStatus status,
                     SshPrivateKey prv,
                     SshPublicKey pub,
                     const unsigned char *cert, size_t cert_len,
                     void *context)
{
  SshCmpEnrollCert k = context;

  if (status == SSH_EK_OK && prv && pub)
    {
      k->prvkey = prv;

      if (k->certtemp)
        {
          ssh_x509_cert_set_public_key(k->certtemp, pub);
        }
      else
        {
          k->certtemp = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
          if (ssh_x509_cert_decode(cert, cert_len, k->certtemp) != SSH_X509_OK)
            {
              ssh_x509_cert_free(k->certtemp);
              k->certtemp = NULL;
            }
        }
      if (cert && cert_len && !(k->cert))
        {
          k->cert = ssh_xmemdup(cert, cert_len);
          k->cert_len = cert_len;
        }
      ssh_public_key_free(pub);
    }
  else
    {
      switch (status)
        {
        case SSH_EK_KEY_BAD_FORMAT:
          ssh_warning("Failed to read keys: bad key format");
          break;
        case SSH_EK_KEY_FILE_NOT_FOUND:
          ssh_warning("Failed to read keys: %s", strerror(errno));
          break;
        case SSH_EK_TOKEN_ERROR:
          ssh_warning("Failed to read keys: device error");
          break;
        case SSH_EK_KEY_ACCESS_DENIED:
          ssh_warning("Failed to read keys: access denied");
          break;
        default:
          ssh_warning("Failed to get keypair: reason %d.", status);
          break;
        }
      if (k->certtemp) ssh_x509_cert_free(k->certtemp);
      ssh_fsm_set_next(k->client->thread, ec_cmp_cleanup);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(k->client->thread);
}

SSH_FSM_STEP(ec_cmp_get_subject_keys)
{
  SshCmpEnrollClient c = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(ec_cmp_get_auth_keys);
  if (c->subject.prvkey_path && c->opcode != SSH_CMP_REVOC_REQUEST)
    {
      SSH_FSM_ASYNC_CALL({
        au_ek_get_keypair(c->ek,
                          c->subject.prvkey_path,
                          c->subject.cert_path,
                          ec_cmp_get_keys_done,
                          &c->subject);
      });
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ec_cmp_get_auth_keys)
{
  SshCmpEnrollClient c = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(ec_cmp_enroll);
  if (c->current.prvkey_path)
    {
      SSH_FSM_ASYNC_CALL({
        au_ek_get_keypair(c->ek,
                          c->current.prvkey_path,
                          c->current.cert_path,
                          ec_cmp_get_keys_done,
                          &c->current);
      });
    }
  else
    return SSH_FSM_CONTINUE;
}

static void
ec_cmp_process_revoke(SshCmpRevokedSet certs, unsigned int ncerts,
                      void *context)
{
  int i;
  SshCmpRevokedSet c;

  for (i = 0; i < ncerts; i++)
    {
      c = &certs[i];

      if (c->status->status == SSH_CMP_STATUS_GRANTED)
        {
          printf("Certificate %d was revoked.\n", i);
        }
      else
        {
          SshStr n;
          unsigned char *text;
          size_t text_len;

          if (c->status->freetext &&
              (n = ssh_str_charset_convert(c->status->freetext,
                                           SSH_CHARSET_ISO_8859_1))
              != NULL)
            {
              text = ssh_str_get(n, &text_len);
              ssh_str_free(n);
            }
          else
            text = ssh_xstrdup("no reason specified");

          ssh_warning("Certificate %d was NOT revoked: %s.", i, text);
          ssh_xfree(text);
        }
    }
}

static char *ec_cmp_status_as_string(SshCmpStatus status) {
  switch (status)
    {
    case SSH_CMP_STATUS_UNDEF:
      return "Undefined";
    case SSH_CMP_STATUS_GRANTED:
      return "Granted without modifications";
    case SSH_CMP_STATUS_GRANTED_WITH_MODS:
      return "Granted with modifications";
    case SSH_CMP_STATUS_REJECTION:
      return "Rejected";
    case SSH_CMP_STATUS_WAITING:
      return "Pending";
    case SSH_CMP_STATUS_REVOCATION_WARNING:
      return "Revocation warning";
    case SSH_CMP_STATUS_REVOCATION_NOTIFICATION:
      return "Revocation notification";
    case SSH_CMP_STATUS_KEY_UPDATE_WARNING:
      return "Key update warning";
    default:
      return "Unknown status";
    }
}

static char *ec_cmp_failure_as_string(SshCmpFailure failure) {
  switch (failure)
    {
    case SSH_CMP_FINFO_BAD_ALG:
      return "Bad algorithm";
    case SSH_CMP_FINFO_BAD_MESSAGE_CHECK:
      return "Bad message check";
    case SSH_CMP_FINFO_BAD_REQUEST:
      return "Bad_request";
    case SSH_CMP_FINFO_BAD_TIME:
      return "Bad time";
    case SSH_CMP_FINFO_BAD_CERT_ID:
      return "Bad cert id";
    case SSH_CMP_FINFO_BAD_DATA_FORMAT:
      return "Bad data format";
    case SSH_CMP_FINFO_WRONG_AUTHORITY:
      return "Wrong authority";
    case SSH_CMP_FINFO_INCORRECT_DATA:
      return "Incorrect data";
    case SSH_CMP_FINFO_MISSING_TIME_STAMP:
      return "Missing time stamp";
    case SSH_CMP_FINFO_BAD_POP:
      return "Bad PoP";
    case SSH_CMP_FINFO_CERT_REVOKED:
      return "Cert revoked";
    case SSH_CMP_FINFO_CERT_CONFIRMED:
      return "Cert confirmed";
    case SSH_CMP_FINFO_WRONG_INTEGRITY:
      return "Wrong integrity";
    case SSH_CMP_FINFO_BAD_RNONCE:
      return "Bad rnonce";
    case SSH_CMP_FINFO_TIME_NOT_AVAILABLE:
      return "Time not available";
    case SSH_CMP_FINFO_UNACCEPTED_POLICY:
      return "Unaccepted policy";
    case SSH_CMP_FINFO_UNACCEPTED_EXTENSION:
      return "Unaccepted extension";
    case SSH_CMP_FINFO_ADDINFO_UNAVAILABLE:
      return "Addinfo unavailable";
    case SSH_CMP_FINFO_BAD_SNONCE:
      return "Bad snonce";
    case SSH_CMP_FINFO_BAD_TEMPLATE:
      return "Bad template";
    case SSH_CMP_FINFO_SIGNER_NOTRUST:
      return "Signer notrust";
    case SSH_CMP_FINFO_TRANSACTION_INUSE:
      return "Transaction in use";
    case SSH_CMP_FINFO_BAD_VERSION:
      return "Bad version";
    case SSH_CMP_FINFO_NOT_AUTHORIZED:
      return "Not authorized";
    case SSH_CMP_FINFO_SYSTEM_UNAVAIL:
      return "System unavailable";
    case SSH_CMP_FINFO_SYSTEM_FAILURE:
      return "System failure";
    case SSH_CMP_FINFO_DUPLICATE_REQUEST:
      return "Duplicate request";
    default:
      return "Unknown failure";
    }
}

static void
ec_cmp_error(SshCmpStatus status,
             unsigned int pollid, unsigned int pollwhen,
             SshStr status_string, /* freetext in PKIStatus */
             SshStr error_reason,  /* freetext in ErrorMsg */
             SshStr human_instructions, /* freetext in PKIheader */
             void *context)
{
  SshCmpEnrollClient c = context;
  if (status == SSH_CMP_STATUS_WAITING)
    {
      printf("PKI transaction is pending.\n"
                  "    Poll again after %u seconds "
                  "with transaction ID %u.\n", pollwhen, pollid);
    }
  else
    {
      unsigned char *error_details, *status_message, *instructions;
      size_t error_details_len, status_message_len, instructions_len;

      c->retval = status + 10;
      error_details = ssh_str_get(error_reason, &error_details_len);
      status_message = ssh_str_get(status_string, &status_message_len);
      instructions= ssh_str_get(human_instructions, &instructions_len);

      ssh_warning("PKI transaction failed.\n"
                  "    Status: %s (%d)\n"
                  "    Status message: %s\n"
                  "    Error details: %s\n"
                  "    Instructions: %s",
                  ec_cmp_status_as_string(status), status,
                  status_message ? (char *)status_message : "none",
                  error_details ? (char *)error_details : "none",
                  instructions ? (char *)instructions: "none");
      ssh_xfree(error_details);
      ssh_xfree(status_message);
      ssh_xfree(instructions);
    }
}

static void
ec_cmp_finalize(void *context)
{
  SshCmpEnrollClient c = context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

static void
ec_cmp_decrypt_done(SshX509EncryptedValue ciphered,
                    SshX509EncryptedValue plaintext,
                    void *context)
{
  SshCmpEnrollClient c = context;
  char outfile[128];

  if (plaintext)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Encrypted %s key received: %s",
                 plaintext->intended_alg,
                 plaintext->value_hint));

      ssh_snprintf(outfile, sizeof(outfile), "%s-0.prv",
                   c->output_prefix);
      ssh_write_file(outfile,
                     plaintext->encrypted_value,
                     plaintext->encrypted_value_len);
      ssh_crmf_encrypted_value_free(plaintext);
    }
  ssh_crmf_encrypted_value_free(ciphered);
}

static SshOperationHandle
ec_cmp_process_certs(SshCmpStatus status,
                     SshCmpCertStatusSet certs, unsigned int ncerts,
                     SshCmpCertSet extra_certs, unsigned int nextra_certs,
                     SshEcCmpCertRepCB reply, void *reply_context,
                     void *context)
{
  SshCmpEnrollClient c = context;
  SshX509Certificate opencert;
  SshCmpStatus *statii;
  int i;
  char outfile[128], *reqid;
  CuCertKind kind;
  const char *kindname;

  if (status == SSH_CMP_STATUS_GRANTED ||
      status == SSH_CMP_STATUS_GRANTED_WITH_MODS)
    {
      statii = ssh_xcalloc(ncerts, sizeof(*statii));
      for (i = 0; i < ncerts; i++)
        {
          reqid = ssh_mprz_get_str(certs[i].request_id, 10);
          switch (certs[i].info->status)
            {
            case SSH_CMP_STATUS_GRANTED:
            case SSH_CMP_STATUS_GRANTED_WITH_MODS:

              if ((opencert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT))
                  != NULL)
                {
                  if (ssh_x509_cert_decode(certs[i].cert,
                                           certs[i].cert_len,
                                           opencert) == SSH_X509_OK)
                    {
                      kind = cu_determine_cert_kind(opencert);
                      if (kind & CU_CERT_KIND_CA)
                        {
                          kindname = "CA";
                          ssh_snprintf(outfile, sizeof(outfile), "%s-%d.ca",
                                       c->output_prefix, i);
                        }
                      else
                        {
                          kindname = "user";
                          ssh_snprintf(outfile, sizeof(outfile), "%s-%d.crt",
                                       c->output_prefix, i);
                        }

                      if (ssh_usstrcmp(c->ca.access_url, "-") != 0)
                        {
                          char answer[8];
                          if (c->opcode == SSH_CMP_KEY_REC_REQUEST ||
                              c->yes_mode)
                            {
                              answer[0] = 'y'; answer[1] = '\0';
                            }
                          else
                            {
                              cu_dump_cert(opencert,
                                           certs[i].cert, certs[i].cert_len,
                                           SSH_X509_PKIX_CERT,
                                           SSH_CHARSET_ISO_8859_1, FALSE, 10,
                                           TRUE);
                              fflush(stdout); fflush(stderr);
                              printf("Do you accept the certificate above? ");
                              fflush(stdout);
                              fgets(answer, sizeof(answer), stdin);
                              answer[strlen(answer)-1] = '\000';
                            }
                          if (!strcasecmp(answer, "yes") ||
                              !strcasecmp(answer, "y"))
                            {
                              printf("Accepted %s certificate; "
                                     "saving into file %s.\n",
                                     kindname, outfile);
                              cu_dump_fingerprints(certs[i].cert,
                                                   certs[i].cert_len);

                              ssh_write_file(outfile,
                                             certs[i].cert, certs[i].cert_len);
                              statii[i] = SSH_CMP_STATUS_GRANTED;
                            }
                          else
                            {
                              statii[i] = SSH_CMP_STATUS_REJECTION;
                            }
                        }
                      else
                        {
                          ssh_write_file(outfile,
                                         certs[i].cert, certs[i].cert_len);
                        }
                    }
                  else /* Can't decode */
                    {
                      statii[i] = SSH_CMP_STATUS_REJECTION;
                    }
                  ssh_x509_cert_free(opencert);
                }
              else /* Can't allocate */
                {
                  statii[i] = SSH_CMP_STATUS_GRANTED;
                }

              if (statii[i] == SSH_CMP_STATUS_GRANTED &&
                  certs[i].prvkey_len > 0)
                {
                  SshX509EncryptedValue ev;

                  ssh_snprintf(outfile, sizeof(outfile), "%s-%d.prv",
                               c->output_prefix, i);
                  if (ssh_crmf_decode_encrypted_value(certs[i].prvkey,
                                                      certs[i].prvkey_len,
                                                      &ev)
                      == SSH_X509_OK)
                    {
                      printf("Recovered private key; "
                                  "saving into file %s.\n", outfile);
                      ssh_crmf_decrypt_encrypted_value(ev,
                                                       c->subject.
                                                       protocol_encryption_key,
                                                       ec_cmp_decrypt_done,
                                                       c);
                    }
                  else
                    {
                      ssh_warning("Failed to decrypt recoverd private key.");
                    }
                }

              break;
            case SSH_CMP_STATUS_WAITING:
              printf("PKI transaction is pending.\n"
                     "    Poll again with transaction ID %s.\n",
                     reqid);
              statii[i] = SSH_CMP_STATUS_GRANTED;
              break;

            default:
              if (certs[i].info->failure)
                {
                  c->retval |= 2;
                  ssh_warning("Certificate request %d was rejected: %s",
                              i,
                              ec_cmp_failure_as_string(certs[i].info->
                                                       failure));
                  {
                    SshStr n;
                    if (certs[i].info->freetext &&
                        (n = ssh_str_charset_convert(certs[i].info->freetext,
                                                     SSH_CHARSET_ISO_8859_1))
                        != NULL)
                      {
                        unsigned char *text;
                        size_t text_len;
                        text = ssh_str_get(n, &text_len);
                        ssh_str_free(n);
                        ssh_warning("Note: %s", text);
                        ssh_xfree(text);
                      }
                  }
                }
              else
                printf("Certificate request %d was rejected.\n", i);
              statii[i] = SSH_CMP_STATUS_REJECTION;
            }

          ssh_free(reqid);
        }
      if (reply)
        (*reply)(statii, reply_context);

      for (i = 0; i < nextra_certs; i++)
        {
          ssh_snprintf(outfile, sizeof(outfile), "%s-extra-%d.crt",
                       c->output_prefix, i);

          printf("Received additional certificate; saving into file %s.\n",
                 outfile);
          cu_dump_fingerprints(extra_certs[i].ber, extra_certs[i].ber_len);
          ssh_write_file(outfile, extra_certs[i].ber, extra_certs[i].ber_len);
        }
    }
  return NULL;
}

SSH_FSM_STEP(ec_cmp_enroll)
{
  SshCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshEcCmpCA ca;
  SshEcCmpAuth auth;
  SshEcCmpKeyPair keypair;
  char *key = NULL, *kid = NULL;
  size_t key_len = 0, kid_len = 0;

  SSH_FSM_SET_NEXT(ec_cmp_cleanup);

  ca = ssh_xcalloc(1, sizeof(*ca));
  ca->address = c->ca.access_url ? ssh_xstrdup(c->ca.access_url) : NULL;
  ca->socks   = c->ca.socks_url ? ssh_xstrdup(c->ca.socks_url) : NULL;
  ca->proxy   = c->ca.proxy_url ? ssh_xstrdup(c->ca.proxy_url) : NULL;
  ca->protocol_version = c->ca.protocol_version;
  ca->transport_level_poll = c->ca.transport_level_poll;
  ca->rfc2511_compatibility = c->ca.rfc2511_compatibility;
  ca->prefer_sha256 = c->ca.prefer_sha256;

  if (c->ca.cert && c->ca.cert_len > 0)
    {
      ca->identity_type = SSH_EC_CA_ID_CERT;
      ca->id_cert = ssh_xmemdup(c->ca.cert, c->ca.cert_len);
      ca->id_cert_len = c->ca.cert_len;
    }
  else
    {
      ca->identity_type = SSH_EC_CA_ID_NAME;
      ca->identity.name = ssh_xstrdup(c->ca.name);
    }

  auth = ssh_xcalloc(1, sizeof(*auth));
    if (c->current.cert_len > 0)
      {
        auth->identity_type = SSH_EC_EE_ID_CERT;
        auth->id_cert = ssh_xmemdup(c->current.cert, c->current.cert_len);
        auth->id_cert_len = c->current.cert_len;
        ssh_private_key_copy(c->current.prvkey, &auth->id_prvkey);
      }
    else
      {
        if (c->ca.has_psk)
          {
            kid = ssh_memdup(c->ca.psk_userid, c->ca.psk_userid_len);
            kid_len = c->ca.psk_userid_len;
            key = ssh_memdup(c->ca.psk_password, c->ca.psk_password_len);
            key_len = c->ca.psk_password_len;
          }

        auth->identity_type = SSH_EC_EE_ID_PSK;
        auth->id_count = c->ca.count;
        auth->id_kid = (unsigned char *)kid;
        auth->id_key = (unsigned char *)key;

        auth->id_kid_len = kid_len;
        auth->id_key_len = key_len;
        auth->id_name = NULL;
      }

  switch (c->opcode)
    {
    case SSH_CMP_INIT_REQUEST:
    case SSH_CMP_CERT_REQUEST:
    case SSH_CMP_KEY_UP_REQUEST:
      keypair = ssh_xcalloc(1, sizeof(*keypair));
      keypair->prvkey = c->subject.prvkey;
      ssh_x509_cert_get_public_key(c->subject.certtemp, &keypair->pubkey);

        {
          SSH_FSM_ASYNC_CALL({
            ssh_ec_cmp_enroll(c->opcode,
                              ca, auth, keypair, c->subject.do_backup,
                              c->encryption_pop,
                              c->subject.certtemp,
                              c->num_extra_certs, c->extra_certs,
                              ec_cmp_process_certs,
                              ec_cmp_finalize,
                              ec_cmp_error,
                              c);
          });
        }
      break;
    case SSH_CMP_REVOC_REQUEST:
      SSH_FSM_ASYNC_CALL({
        ssh_ec_cmp_revoke(ca, auth, c->subject.certtemp,
                          ec_cmp_process_revoke,
                          ec_cmp_finalize,
                          ec_cmp_error,
                          c);
      });
      break;
    case SSH_CMP_KEY_REC_REQUEST:
      SSH_FSM_ASYNC_CALL({
        SshPublicKey pubkey;
        SshCryptoStatus status;
        status =
          ssh_private_key_derive_public_key(c->subject.
                                            protocol_encryption_key, &pubkey);
        SSH_ASSERT(status == SSH_CRYPTO_OK);
        ssh_ec_cmp_recover(ca, auth, c->subject.certtemp,
                           pubkey,
                           ec_cmp_process_certs,
                           ec_cmp_finalize,
                           ec_cmp_error,
                           c);
      });
      break;

    case SSH_CMP_POLL_REQUEST:
      SSH_FSM_ASYNC_CALL({
        ssh_ec_cmp_poll(ca, auth,
                        c->num_poll_ids, c->poll_ids,
                        ec_cmp_process_certs,
                        ec_cmp_finalize,
                        ec_cmp_error,
                        c);
        ssh_x509_cert_free(c->subject.certtemp);
      });
      break;

    default:
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ec_cmp_cleanup)
{
  ssh_name_server_uninit();
  ssh_fsm_destroy(ssh_fsm_get_fsm(thread));
  return SSH_FSM_FINISH;
}


/* This is the workhorse, a small state machine that fetches the
   subject and authentication key pairs from the key paths, then it
   does one step to perform the actual CMP transaction. */

static void cmp_enroll_start(SshExternalKey ek, void *context)
{
  SshCmpEnrollClient c = context, tdata;
  SshFSM fsm;
  SshFSMThread thread;

  c->ek = ek;

  fsm = ssh_fsm_create(NULL);
  thread = ssh_fsm_thread_create(fsm,
                                 ec_cmp_get_subject_keys,
                                 NULL_FNPTR, NULL_FNPTR,
                                 c);
  c->thread = thread;
  /* Last things to do. */
  tdata = ssh_fsm_get_tdata(thread);
  memmove(tdata, c, sizeof(*c));
}


static SshOperationHandle
cmp_ek_auth_cb(const char *keypath, const char *label, SshUInt32 try_number,
               SshEkAuthenticationStatus authentication_status,
               SshEkAuthenticationReplyCB reply_cb, void *reply_context,
               void *context)
{
  (*reply_cb)(NULL, 0, reply_context);
  return NULL;
}

static void
cmp_ek_notify_cb(SshEkEvent event, const char *keypath,
                 const char *label, SshEkUsageFlags flags,
                 void *context)
{
  switch (event)
    {
    case SSH_EK_EVENT_TOKEN_INSERTED:
    case SSH_EK_EVENT_TOKEN_REMOVED:
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EK device %s %s.",
                 label,
                 event==SSH_EK_EVENT_TOKEN_REMOVED? "removed": "inserted"));
      break;
    case SSH_EK_EVENT_KEY_AVAILABLE:
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EK key %s with label %s available.", keypath, label));
      break;
    case SSH_EK_EVENT_KEY_UNAVAILABLE:
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EK key %s with label %s is now gone.", keypath, label));
      break;
    case SSH_EK_EVENT_PROVIDER_FAILURE:
    case SSH_EK_EVENT_TOKEN_REMOVE_DETECTED:
      break;
    default:
      SSH_NOTREACHED;
    }
}

static void
stir(char *entropy_file_name)
{
  if (entropy_file_name)
    {
      unsigned char *buffer;
      size_t buffer_len;

      if (FALSE == ssh_read_file(entropy_file_name, &buffer, &buffer_len))
        {
          ssh_fatal("Cannot read file %s.", entropy_file_name);
          return;
        }
      ssh_random_add_noise(buffer, buffer_len, 8 * buffer_len);
      memset(buffer, 0, buffer_len);
      ssh_xfree(buffer);
    }
  ssh_random_stir();
  return;
}

static void usage(int code)
{

  D("usage: ssh-cmpclient command [options] access [name]\n");
  D("where command is one of the following:\n");
  D("\t INITIALIZE psk keypair template");
  D("\t ENROLL certs keypair template");
  D("\t UPDATE certs [keypair]");
  D("\t POLL psk|certs id\n");
  D("\t RECOVER psk|certs template");
  D("\t REVOKE psk|certs template\n");
  D("most commands can accept the following options:");
  D("\t -B\t\t Perform key backup for subject keys.");
  D("\t -o prefix\t Save result into filex with prefix.");
  D("\t -C file\t CA certificate from this file.");
  D("\t -S URL\t\t Use this socks server to access CA.");
  D("\t -H URL\t\t Use this HTTP proxy to access CA.");
  D("\t -e\t\t PoP by encryption (need CA-cert).");
  D("\t -R cert\t Operate in RA mode. RA private key given with '-k'.");
  D("\t -v number\t Protocol version 1|2 of the CA platform. Default is 2.\n");
  D("\t -y \t\t Non-interactive mode. All questions answered with 'y'.\n");
  D("the following identifiers are used to specify options:");
  D("\tpsk\t -p reference-number:key");
  D("\tpsk\t -q kid:key");
  D("\t\t\tkid and key are in hexadecimal and passed ");
  D("\t\t\tin binary to the peer.");
  D("\t\t -i iteration count (default 1024)");
  D("\t\t -N specifies file to stir to random pool.");
  D("\tcerts\t -k private-key-URL -c certificate-path");
  D("\tkeypair\t -P private-key-path");
  D("\tid\t -I number");
  D("\ttemplate -T cert-or-request-path");
  D("\t\t -s subject-ldap[;type=value]");
  D("\t\t -u key-usage-name[;key-usage-name]");
  D("\t\t -U ext-key-usage-name[;ext-key-usage-name]");
  D("\taccess\t URL where the CA listens for requests.");
  D("\tname\t LDAP name for the issuing CA (if -C is not given).\n");

  D("key URL's are either valid external key paths or in format:");
  D("\t \"generate://savetype:passphrase@keytype:size/save-file-prefix\"");
  D("\t \"file://passphrase/absolute-key-file-path\"");
  D("\t \"file:/absolute-key-file-path\"");
  D("\t \"file:relative-key-file-path\"");
  D("\t \"any-key-file-path\"");
  D("\tsavetypes are: "
    "secsh|secsh1|secsh2|ssh1|ssh2|pkcs1|x509|pkcs8|pkcs8s\n");
  D(" -h prints this usage message");
  D(" -F prints key usage extension and keytype instructions");
  D(" --prefer-sha256");
  D("\tEnables use of SHA-256 instead of SHA-1 in PasswordBasedMac (psk) ");
  D("\tand signatures where applicable.");
  D(" --rfc2511-compatibility");
  D("\tEnables RFC2511 backwards compatibility where applicable.");
  D(" --extra-certificate CERT");
  D("\tAdds CERT to extraCerts in the request.  Mainly useful in adding ");
  D("\tthe initial certificate for key update requests, and adding certs of ");
  D("\tintermediate CAs to help the server in the processing of the request.");

#undef D
  if (code > -1)
    {
      ssh_util_uninit();
      exit(code);
    }
}

static unsigned char *
hexdecode(const char *value, size_t *buf_len_ret)
{
  size_t value_len, buf_len;
  unsigned char *buf = NULL;
  int ii;

  value_len = strlen(value);

  if (value_len % 2 != 0)
    {
      ssh_warning("value length must be even.");
      return NULL;
    }

  buf_len = value_len / 2;

  buf = ssh_calloc(buf_len, 1);

  if (buf == NULL)
    {
      ssh_warning("Memory allocation failed");
      goto error;
    }

  for (ii = 0; ii < buf_len; ii++)
    {
      int cur_value = 0;
      int ret = sscanf(&value[ii*2], "%2x", &cur_value);
      if (ret <= 0)
        {
          ssh_warning("Failed to convert value to binary.");
          goto error;
        }
      SSH_POSTCOND(cur_value >= 0 && cur_value <= 255);
      buf[ii] = cur_value;
    }

  if (buf_len_ret)
    {
      *buf_len_ret = buf_len;
    }

  return buf;

 error:
  ssh_free(buf);
  return NULL;
}

#define OPT_RFC2511 0x100
#define OPT_EXTRA_CERT 0x101
#define OPT_PREFER_SHA256 0x102

struct SshLongOptionRec longopts[] = {
  { "rfc2511-compatibility", SSH_GETOPT_LONG_NO_ARGUMENT, NULL, OPT_RFC2511 },
  { "prefer-sha256", SSH_GETOPT_LONG_NO_ARGUMENT, NULL, OPT_PREFER_SHA256 },
  { "extra-certificate",
    SSH_GETOPT_LONG_REQUIRED_ARGUMENT, NULL, OPT_EXTRA_CERT },
  { NULL, 0, NULL, 0}
};

int main(int ac, char **av)
{
  SshCmpBodyType opcode = 0;
  char *op = "";
  const char *new_cert_path = NULL, *new_cert_subject = NULL;
  const char *new_cert_usage = NULL, *new_cert_ext_usage = NULL;
  int opt, numproviders = 0, rv = 1, i;
  SshCmpEnrollClient c;
  SshAuProvider providers = NULL;
  unsigned char *der;
  size_t der_len;
  SshX509Certificate opencert;

  Boolean psk_in_hex = FALSE;
  SshX509ConfigStruct x509_config[1] = { { { 0 } } };
  char *secretval = NULL, *key = NULL;

  prog = av[0];

  if (ac > 1)
    {
      op = av[1];
      if (!strncasecmp(op, "ini", 3)) opcode = SSH_CMP_INIT_REQUEST;
      else if (!strncasecmp(op, "enr", 3)) opcode = SSH_CMP_CERT_REQUEST;
      else if (!strncasecmp(op, "upd", 3)) opcode = SSH_CMP_KEY_UP_REQUEST;
      else if (!strncasecmp(op, "rec", 3)) opcode = SSH_CMP_KEY_REC_REQUEST;
      else if (!strncasecmp(op, "rev", 3)) opcode = SSH_CMP_REVOC_REQUEST;
      else if (!strncasecmp(op, "inf", 3)) opcode = SSH_CMP_GEN_MESSAGE;
      else if (!strncasecmp(op, "sen", 3)) opcode = SSH_CMP_NESTED;
      else if (!strncasecmp(op, "pol", 3)) opcode = SSH_CMP_POLL_REQUEST;
      else
        {
          usage(1);
        }
    }
  else
    {
      usage(0);
    }

  ac--;
  av++;

  ssh_global_init();

  x509_config->ec.allow_ee_basic_constraints = TRUE;
  ssh_x509_library_initialize(x509_config);

  c = ssh_xcalloc(1, sizeof(*c));
  c->opcode = opcode;

  c->subject.client = c;
  c->current.client = c;
  c->encryption_pop = FALSE;
  c->ca.protocol_version = SSH_CMP_VERSION_2;
  c->ca.transport_level_poll = FALSE;

  while ((opt =
          ssh_getopt_long(ac, av,
                          "x:o:r:d:S:H:T:s:u:U:i:C:P:k:c:yBep:q:X:hR:I:v:N:OF",
                          longopts, NULL, NULL))
         != EOF)
    {
      switch (opt)
        {
        case 'x': c->save_prefix = ssh_optarg; break;
        case 'o': c->output_prefix = ssh_optarg; break;
        case 'r': c->statefile = ssh_optarg; break;
        case 'd': ssh_debug_set_level_string(ssh_optarg); break;
        case 'S': c->ca.socks_url = ssh_custr(ssh_optarg); break;
        case 'H': c->ca.proxy_url = ssh_custr(ssh_optarg); break;
        case 'T': new_cert_path = ssh_optarg; break;
        case 's': new_cert_subject = ssh_optarg; break;
        case 'u': new_cert_usage = ssh_optarg; break;
        case 'U': new_cert_ext_usage = ssh_optarg; break;

        case 'i': c->ca.count = atoi(ssh_optarg); break;
        case 'C': c->ca.cert_file = ssh_optarg; break;
        case 'P': c->subject.prvkey_path = ssh_optarg; break;

        case 'k': c->current.prvkey_path = ssh_optarg; break;
        case 'c': c->current.cert_path = ssh_optarg; break;
        case 'B': c->subject.do_backup = TRUE; break;
        case 'e': c->encryption_pop = TRUE; break;
        case 'N': stir(ssh_optarg); break;
        case 'y': c->yes_mode = TRUE; break;
        case 'I':
          c->poll_ids =
            ssh_xrealloc(c->poll_ids,
                         (c->num_poll_ids + 1) * sizeof(*c->poll_ids));
          ssh_mprz_init(&c->poll_ids[c->num_poll_ids]);
          ssh_mprz_set_str(&c->poll_ids[c->num_poll_ids], ssh_optarg, 0);
          c->num_poll_ids += 1;
          break;

        case 'q':
          psk_in_hex = TRUE;
          /* PASSTHROUGH */
        case 'p':
          if (!strchr(ssh_optarg, ':'))
            {
              ssh_warning("%s: -p key requires colon to separate kid and key",
                          prog);
              usage(-1);
              goto cleanup_and_exit;
            }
          c->ca.has_psk = TRUE;

          secretval = ssh_xstrdup(ssh_optarg);
          key = strchr(secretval, ':');
          *key = '\0';
          key++;
          if (psk_in_hex)
            {
              c->ca.psk_userid = hexdecode(secretval, &c->ca.psk_userid_len);
              c->ca.psk_password = hexdecode(key, &c->ca.psk_password_len);
              ssh_free(secretval);
              if (!c->ca.psk_userid || !c->ca.psk_password)
                {
                  ssh_warning("%s: -q requires valid hexadecimal input "
                              "for kid and key",
                              prog);
                  usage(-1);
                  goto cleanup_and_exit;
                }
              SSH_DEBUG_HEXDUMP(5, ("kid:"),
                                c->ca.psk_userid, c->ca.psk_userid_len);
              SSH_DEBUG_HEXDUMP(5, ("key:"),
                                c->ca.psk_password, c->ca.psk_password_len);
            }
          else
            {
              c->ca.psk_userid = ssh_ustr(secretval);
              c->ca.psk_userid_len = strlen(ssh_csstr(c->ca.psk_userid));
              c->ca.psk_password = ssh_xstrdup(key);
              c->ca.psk_password_len = strlen(ssh_csstr(c->ca.psk_password));
              SSH_DEBUG(5, ("kid: %.*s, key: %.*s",
                            c->ca.psk_userid_len, c->ca.psk_userid,
                            c->ca.psk_password_len, c->ca.psk_password));
            }
          psk_in_hex = FALSE;
          break;

        case 'X': brokenflags = atoi(ssh_optarg); break;

        case 'v': c->ca.protocol_version = atoi(ssh_optarg); break;
        case 'O': c->ca.transport_level_poll = TRUE; break;
        case 'h':
          usage(-1);
          goto cleanup_and_exit;

        case 'F':
          au_help_keytypes(); ssh_warning("");
          au_help_extensions(); ssh_warning("");
          au_help_subject(); ssh_warning("");
          goto cleanup_and_exit;

        case OPT_RFC2511:
          c->ca.rfc2511_compatibility = TRUE;
          break;

        case OPT_PREFER_SHA256:
          c->ca.prefer_sha256 = TRUE;
          break;

        case OPT_EXTRA_CERT:
          if (au_read_certificate(ssh_optarg, &der, &der_len, NULL))
            {
              ec_cmp_add_cert(&c->extra_certs, &c->num_extra_certs,
                              der, der_len);
            }
          else
            {
              ssh_warning("%s: %s; can't read extra  from %s.",
                          prog, op, ssh_optarg);
            }
          ssh_free(der);
          break;

        default:
          ssh_warning("%s: unknown option `%c'", prog, (char)opt);
          ssh_x509_library_uninitialize();
          ssh_free(c);
          usage(1);
        }
    }

  ac -= ssh_optind;
  av += ssh_optind;

  if (!c->output_prefix)
    c->output_prefix = "subject";

  if (c->statefile)
    {
      if (new_cert_subject || new_cert_path
          || new_cert_usage || new_cert_ext_usage)
        {
          ssh_warning("%s: %s; options TsuUgl not compatible with -r.",
                      prog, op);
          goto cleanup_and_exit;
        }

      goto state_file_given;
    }

  if (ac > 2)
    {
      ssh_warning("%s: Extra arguments on command-line: %s ...",
                  prog, av[2]);
      goto cleanup_and_exit;
    }

  if (ac > 0)
    {
      c->ca.access_url = ssh_custr(av[0]);
      if (ac > 1)
        {
          SshDNStruct dn[1] = { { 0 } };
          Boolean valid;
          ssh_dn_init(dn);
          valid = ssh_dn_decode_ldap(ssh_custr(av[1]), dn);
          ssh_dn_clear(dn);
          if (!valid)
            {
              ssh_warning("%s: Given DN '%s' not valid", prog, av[1]);
              goto cleanup_and_exit;
            }
          c->ca.name = ssh_custr(av[1]);
        }
      else
        {
          c->ca.name = NULL;
        }
    }
  else
    {
      ssh_warning("%s: CA access point not given", prog);
      usage(-1);
      goto cleanup_and_exit;
    }

  if (!c->ca.cert_file && !c->ca.name)
    {
      ssh_warning("%s: CA name or certificate needed", prog);
      usage(-1);
      goto cleanup_and_exit;
    }
  else
    {
      if (c->ca.cert_file)
        {
          if (au_read_certificate(c->ca.cert_file, &der, &der_len, NULL))
            {
              c->ca.cert = der;
              c->ca.cert_len = der_len;
              ec_cmp_add_cert(&c->extra_certs, &c->num_extra_certs,
                              der, der_len);
            }
          else
            {
              ssh_warning("%s: %s; can't read in CA certificate from %s.",
                          prog, op, c->ca.cert_file);
              goto cleanup_and_exit;
            }
        }
    }

  /* Now process options and check combinations. */
  if (c->opcode == SSH_CMP_INIT_REQUEST)
    {
      if (!c->current.prvkey_path && !c->ca.has_psk)
        {
          ssh_warning("%s: init; requires external identity private key (-k) "
                      "or pre-shared key.",
                      prog);
          goto cleanup_and_exit;
        }

      if (!new_cert_subject && !new_cert_path)
        {
          ssh_warning("%s: init; requires template or subject name.",
                      prog);
          goto cleanup_and_exit;
        }
    }

  if (c->opcode == SSH_CMP_CERT_REQUEST)
    {
      if (!c->current.prvkey_path || !c->current.cert_path)
        {
          ssh_warning("%s: enroll; requires cert and private key.",
                      prog);
          goto cleanup_and_exit;
        }
      if (!c->subject.prvkey_path)
        {
          ssh_warning("%s: enroll; requires private key or keygen params.",
                      prog);
          goto cleanup_and_exit;
        }
      if (!new_cert_subject && !new_cert_path)
        {
          ssh_warning("%s: enroll; requires template or subject name.",
                      prog);
          goto cleanup_and_exit;
        }
    }

  if (c->opcode == SSH_CMP_POLL_REQUEST)
    {
      if (!c->ca.has_psk && !c->current.cert_path)
        {
          ssh_warning("%s: poll; requires PSK or CERT", prog);
          goto cleanup_and_exit;
        }
      if (c->num_poll_ids == 0)
        {
          ssh_warning("%s: enroll; requires polling id (-I).",
                      prog);
          goto cleanup_and_exit;
        }
    }

  if (c->subject.do_backup)
    {
      if (c->opcode == SSH_CMP_INIT_REQUEST ||
          c->opcode == SSH_CMP_CERT_REQUEST ||
          c->opcode == SSH_CMP_KEY_UP_REQUEST)
        {
          if (!c->ca.cert_file)
            {
              ssh_warning("%s: %s; "
                          "with key backup requires CA certificate.",
                          prog, op);
              goto cleanup_and_exit;
            }
        }
      else
        {
          ssh_warning("%s: %s; "
                      "key backup is not meaningful with this operation.",
                      prog, op);
          goto cleanup_and_exit;
        }

      if (c->opcode == SSH_CMP_KEY_UP_REQUEST)
        {
          if (c->current.prvkey_path == NULL ||
              c->current.cert_path == NULL)
            {
              ssh_warning("%s: %s; requires old private key and old cert.",
                          prog, op);
              goto cleanup_and_exit;

            }
          if (c->subject.prvkey_path == NULL)
            c->subject.prvkey_path = c->current.prvkey_path;
        }
    }

  if (c->opcode == SSH_CMP_KEY_REC_REQUEST ||
      c->opcode == SSH_CMP_REVOC_REQUEST)
    {
      if (c->ca.has_psk
          || (c->current.prvkey_path && c->current.cert_path))
        {
          if (!new_cert_subject && !new_cert_path)
            {
              ssh_warning("%s: %s; requires template or subject name.",
                          prog, op);
              goto cleanup_and_exit;
            }
        }
      else
        {
          ssh_warning("%s: %s; requires PSK or cert and private key.",
                      prog, op);
          goto cleanup_and_exit;
        }

      if (c->opcode == SSH_CMP_KEY_REC_REQUEST)
        {
          if (ssh_private_key_generate(&c->subject.protocol_encryption_key,
                                       "if-modn{"
                                       "encrypt{rsa-pkcs1-none},"
                                       "sign{rsa-pkcs1-md5}}",
                                       SSH_PKF_SIZE, 1024,
                                       SSH_PKF_END)
              != SSH_CRYPTO_OK)
            {
              ssh_warning("%s: %s; can't generate protocol encryption "
                          "key for CMP key recovery.",
                          prog, op);
              goto cleanup_and_exit;
            }
        }
    }
  /* Parse new_ somethings, and create keys needed. */

      if (new_cert_path || /* the -T cert */
          c->opcode == SSH_CMP_KEY_UP_REQUEST) /* Old cert as template */
        {
          const char *template_path;
          template_path = new_cert_path ? new_cert_path : c->current.cert_path;
          if (au_read_certificate(template_path, &der, &der_len, &opencert))
            {
              c->subject.cert = der;
              c->subject.cert_len = der_len;
              c->subject.certtemp = opencert;
            }
          else
            {
              ssh_warning("%s: %s; can't read in template certificate "
                          "from %s: %s.", prog, op, template_path,
                          strerror(errno));
              goto cleanup_and_exit;
            }
        }
      else
        c->subject.certtemp = ssh_x509_cert_allocate(SSH_X509_PKIX_CRMF);

  if (new_cert_usage)
    au_cert_set_key_usage(c->subject.certtemp, new_cert_usage);

  if (new_cert_ext_usage)
    au_cert_set_ext_key_usage(c->subject.certtemp, new_cert_ext_usage);

  if (new_cert_subject)
    au_cert_set_subject(c->subject.certtemp,
                        SSH_CHARSET_ISO_8859_1, new_cert_subject);

 state_file_given:
  /* Then start external key, continue enrollment when it is
     ready. */
  ssh_event_loop_initialize();

  ssh_au_ek_init(providers, numproviders,
                 cmp_ek_auth_cb, cmp_ek_notify_cb, c,
                 cmp_enroll_start, c);

  /* Enter the event loop. */
  ssh_event_loop_run();
  ssh_event_loop_uninitialize();

  rv = c->retval;

 cleanup_and_exit:
  ssh_xfree(c->subject.cert);
  if (c->subject.protocol_encryption_key)
    ssh_private_key_free(c->subject.protocol_encryption_key);
  ssh_xfree(c->ca.cert);

  if (c->extra_certs != NULL)
    {
      for (i = 0; i < c->num_extra_certs; i++)
        ssh_xfree((void *)c->extra_certs[i].ber);
      ssh_xfree(c->extra_certs);
    }

  ssh_x509_cert_free(c->current.certtemp);
  ssh_xfree(c->current.cert);
  if (c->current.prvkey)
    ssh_private_key_free(c->current.prvkey);

  if (c->ca.psk_userid != NULL)
    ssh_free((void *)c->ca.psk_userid);

  if (c->ca.psk_password != NULL)
    ssh_free((void *) c->ca.psk_password);

  ssh_ek_free(c->ek, NULL_FNPTR, NULL);
  ssh_xfree(c);

  ssh_x509_library_uninitialize();
  ssh_util_uninit();
  return rv;
}
