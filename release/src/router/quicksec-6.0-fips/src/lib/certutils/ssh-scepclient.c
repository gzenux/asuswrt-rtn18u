/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SCEP (draft-nource-scep-02) client.

   Authenticates CA (or CA chain), and enrolls certificates
   from there. Also can poll a certificate from CA.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshfileio.h"
#include "sshurl.h"
#include "sshexternalkey.h"
#include "sshgetopt.h"
#include "x509.h"
#include "oid.h"
#include "x509cmp.h"
#include "sshenroll.h"
#include "sshfsm.h"
#include "sshglobals.h"
#include "sshnameserver.h"

#include "au-ek.h"
#include "ec-cep.h"
#include "iprintf.h"

#define SSH_DEBUG_MODULE "SshScepClient"

extern int brokenflags;

enum {
  SCEP_GET_CA,
  SCEP_GET_CERT,
  SCEP_GET_CA_CHAIN,
  SCEP_ENROLL,
  SCEP_POLL
};

#define D(x) ssh_warning((x))

typedef struct
SshCepEnrollClientRec *SshCepEnrollClient, SshCepEnrollClientStruct;

typedef struct SshCepEnrollCaRec
{
  const unsigned char *name; /* or */

  const char *cert_file; unsigned char *cert; size_t cert_len;
  const char *encr_cert_file;
  unsigned char *encr_cert; size_t encr_cert_len;
  const char *sign_cert_file;
  unsigned char *sign_cert; size_t sign_cert_len;

  const unsigned char *socks_url;
  const unsigned char *proxy_url;
  const unsigned char *access_url;
  const unsigned char *psk;
} *SshCepEnrollCa, SshCepEnrollCaStruct;

typedef struct SshCepEnrollCertRec
{
  const char *prvkey_path;
  SshPrivateKey prvkey;

  const char *cert_path;
  unsigned char *cert; size_t cert_len;
  SshX509Certificate certtemp;

  SshCepEnrollClient client;
} *SshCepEnrollCert, SshCepEnrollCertStruct;

struct SshCepEnrollClientRec
{
  char *save_prefix;
  char *output_prefix;
  char *statefile;
  unsigned char *state; size_t state_len;

  SshCepEnrollCaStruct ca;
  SshCepEnrollCertStruct current;
  SshCepEnrollCertStruct subject;

  int opcode;
  char *opname;

  char *progname;
  SshExternalKey ek;
  SshFSMThread thread;
  int retval;
};

SSH_FSM_STEP(ec_cep_get_subject_keys);
SSH_FSM_STEP(ec_cep_enroll);
SSH_FSM_STEP(ec_cep_cleanup);

static void
ec_cep_get_keys_done(SshEkStatus status,
                     SshPrivateKey prv,
                     SshPublicKey pub,
                     const unsigned char *cert, size_t cert_len,
                     void *context)
{
  SshCepEnrollCert k = context;

  if (status == SSH_EK_OK)
    {
      k->prvkey = prv;
      ssh_x509_cert_set_public_key(k->certtemp, pub);
      ssh_public_key_free(pub);
      k->cert = ssh_xmemdup(cert, cert_len);
      k->cert_len = cert_len;
    }
  else
    {
      ssh_warning("Can't acquire key pair from \"%s\"",
                  k->prvkey_path);

      if (k->certtemp) ssh_x509_cert_free(k->certtemp);
      ssh_fsm_set_next(k->client->thread, ec_cep_cleanup);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(k->client->thread);
}

SSH_FSM_STEP(ec_cep_get_subject_keys)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(ec_cep_enroll);
  SSH_FSM_ASYNC_CALL({
    au_ek_get_keypair(c->ek,
                      c->subject.prvkey_path,
                      c->subject.cert_path,
                      ec_cep_get_keys_done,
                      &c->subject);
  });
  return SSH_FSM_SUSPENDED;
}

static void
ec_cep_names_uninit(void *context)
{
  ssh_name_server_uninit();
}

static void
ec_cep_process_certs(SshX509Status status,
                     SshEcCepCert certs, unsigned int ncerts,
                     void *context)
{
  SshCepEnrollClient c = context;
  SshX509Certificate opencert;
  int i;
  char outfile[128];

  if (status == SSH_X509_OK)
    {
      for (i = 0; i < ncerts; i++)
        {
          if (certs[i].data_is_state)
            {
              ssh_snprintf(outfile, sizeof(outfile),
                           "%s.state",
                           c->output_prefix);
              printf("SCEP request state (for polling a pending "
                          "PKI request) was saved\nto file %s\n",
                          outfile);
              ssh_write_file(outfile, certs[i].data, certs[i].len);
              continue;
            }

          if ((opencert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT))
              != NULL)
            {
              if (ssh_x509_cert_decode(certs[i].data, certs[i].len,
                                       opencert) == SSH_X509_OK)
                {
                  CuCertKind kind = cu_determine_cert_kind(opencert);
                  const char *kindname;

                  if (c->opcode == SCEP_ENROLL ||
                      c->opcode == SCEP_POLL)
                    {
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

                    }
                  else /* authenticating CA */
                    {
                      if (kind & CU_CERT_KIND_CA)
                        {
                          kindname = "CA";
                          ssh_snprintf(outfile, sizeof(outfile), "%s-%d.ca",
                                       c->output_prefix, i);
                        }
                      else
                        {
                          if (kind & CU_CERT_KIND_SIGNATURE)
                            {
                              kindname = "RA verification";
                              ssh_snprintf(outfile, sizeof(outfile),
                                           "%s-%d-ra-signature.crt",
                                           c->output_prefix, i);
                            }
                          else if (kind & CU_CERT_KIND_ENCRYPTION)
                            {
                              kindname = "RA encryption";
                              ssh_snprintf(outfile, sizeof(outfile),
                                           "%s-%d-ra-encryption.crt",
                                           c->output_prefix, i);
                            }
                          else
                            {
                              kindname = "RA";
                              ssh_snprintf(outfile, sizeof(outfile),
                                           "%s-%d-ra.crt",
                                           c->output_prefix, i);
                            }
                        }
                      /* Come here directly without going thru FSM */
                      ssh_name_server_uninit();
                    }

                  printf("%s %s certificate; saving into file %s.\n",
                              (c->opcode == SCEP_ENROLL) ?
                                 "Enrolled" : "Received",
                              kindname, outfile);
                  cu_dump_fingerprints(certs[i].data, certs[i].len);

                  ssh_write_file(outfile, certs[i].data, certs[i].len);
                }
              else
                {
                  ssh_snprintf(outfile, sizeof(outfile),
                               "%s-%d.crt",
                               c->output_prefix, i);

                  ssh_warning("%s certificate which we can not decode."
                              "Saving to file %s.",
                              (c->opcode == SCEP_ENROLL) ?
                              "Enrolled" : "Received",
                              outfile);
                  ssh_write_file(outfile, certs[i].data, certs[i].len);
                }
              ssh_x509_cert_free(opencert);
            }
          else
            {
              ssh_warning("%s certificate which we have no space for.",
                          (c->opcode == SCEP_ENROLL) ?
                          "Enrolled" : "Received");
            }
        }
    }
  else
    {
      /* Cannot perform this uninitialisation synchronously, since
         our nameserver lib does not like that. */
      ssh_register_timeout(NULL, 1, 0, ec_cep_names_uninit, NULL);
      c->retval = status;
    }
}

static void
ec_cep_process_certs_state(SshX509Status status,
                           SshEcCepCert certs, unsigned int ncerts,
                           void *context)
{
  SshCepEnrollClient c = context;

  ec_cep_process_certs(status, certs, ncerts, context);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(ec_cep_enroll)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);
  SshEcCepCA ca;
  SshEcCepAuth auth;
  SshEcCepKeyPair keypair;

  ca = ssh_xcalloc(1, sizeof(*ca));
  if (!c->state)
    {
      ca->address = c->ca.access_url ? ssh_xstrdup(c->ca.access_url) : NULL;
      ca->socks   = c->ca.socks_url ? ssh_xstrdup(c->ca.socks_url) : NULL;
      ca->proxy   = c->ca.proxy_url ? ssh_xstrdup(c->ca.proxy_url) : NULL;
    }

  if (c->ca.sign_cert == NULL && c->ca.encr_cert == NULL)
    {
      ca->identity_type = SSH_EC_CA_TYPE_CA;
      ca->ca_cert = ssh_xmemdup(c->ca.cert, c->ca.cert_len);
      ca->ca_cert_len = c->ca.cert_len;
    }
  else
    {
      ca->identity_type = SSH_EC_CA_TYPE_RA;
      if (c->ca.encr_cert)
        {
          ca->ra_encr = ssh_xmemdup(c->ca.encr_cert, c->ca.encr_cert_len);
          ca->ra_encr_len = c->ca.encr_cert_len;
        }

      if (c->ca.sign_cert)
        {
          ca->ra_sign = ssh_xmemdup(c->ca.sign_cert, c->ca.sign_cert_len);
          ca->ra_sign_len = c->ca.sign_cert_len;
        }
    }

  /* Add challenge password. */
  auth = NULL;
  if (c->ca.psk)
    {
      auth = ssh_xcalloc(1, sizeof(*auth));
      auth->id_key_len = ssh_ustrlen(c->ca.psk);
      if (auth->id_key_len)
        auth->id_key = ssh_xstrdup(c->ca.psk);
    }

  keypair = ssh_xcalloc(1, sizeof(*keypair));
  ssh_private_key_copy(c->subject.prvkey, &keypair->prvkey);
  ssh_x509_cert_get_public_key(c->subject.certtemp, &keypair->pubkey);

  SSH_FSM_SET_NEXT(ec_cep_cleanup);

  switch (c->opcode)
    {
    case SCEP_ENROLL:
      SSH_FSM_ASYNC_CALL({
        ssh_ec_cep_enroll(ca, auth, keypair, c->subject.certtemp,
                          ec_cep_process_certs_state, c);
      });
      break;
    case SCEP_POLL:
      SSH_FSM_ASYNC_CALL({
        ssh_x509_cert_free(c->subject.certtemp);
        ssh_ec_cep_poll(ca,
                        keypair,
                        (char *)c->state,
                        ec_cep_process_certs_state, c);
      });
      break;

    default:
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ec_cep_cleanup)
{
  ssh_name_server_uninit();
  ssh_fsm_destroy(ssh_fsm_get_fsm(thread));
  return SSH_FSM_FINISH;
}

/* This is the workhorse, a small state machine that fetches the
   subject and authentication key pairs from the key paths, then it
   does one step to perform the actual CMP transaction. */

static void cep_enroll_start(SshExternalKey ek, void *context)
{
  SshCepEnrollClient c = context, tdata;
  SshFSM fsm;
  SshFSMThread thread;

  c->ek = ek;

  fsm = ssh_fsm_create(NULL);
  thread = ssh_fsm_thread_create(fsm,
                                 ec_cep_get_subject_keys,
                                 NULL_FNPTR, NULL_FNPTR,
                                 c);
  c->thread = thread;
  /* Last things to do. */
  tdata = ssh_fsm_get_tdata(thread);
  memmove(tdata, c, sizeof(*c));
}

static SshOperationHandle
cep_ek_auth_cb(const char *keypath, const char *label, SshUInt32 try_number,
               SshEkAuthenticationStatus authentication_status,
               SshEkAuthenticationReplyCB reply_cb, void *reply_context,
               void *context)
{
  (*reply_cb)(NULL, 0, reply_context);
  return NULL;
}

static void
cep_ek_notify_cb(SshEkEvent event, const char *keypath,
                 const char *label,
                 SshEkUsageFlags flags,
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
          ssh_warning("Cannot read file %s.", entropy_file_name);
          exit(1);
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
  D("Usage: ssh-scepclient command [options] access [name]\n");
  D("where command is one of the following:\n");

  D("\t GET-CA");
  D("\t GET-CHAIN");
  /*  D("\t GET-CERT keypair template"); */
  D("\t ENROLL keypair ca psk template");
  D("\t POLL keypair ca -r state-file\n");

  D("most commands can accept the following options:");
  D("\t -o prefix\t save result into files with prefix.");
  D("\t -S URL\t\t Use this socks server to access CA.");
  D("\t -H URL\t\t Use this HTTP proxy to access CA.\n");

  D("the following identifiers are used to specify options:");

  D("\tpsk\t -p key, used as revocationPassword or challengePassword.");
  D("\tkeypair\t -P private-key-path");
  D("\tca\t -C file\t CA certificate.");
  D("\t\t -E file\t RA encryption certificate.");
  D("\t\t -V file\t RA validation certificate.");
  D("\ttemplate -T cert-or-request-file");
  D("\t\t -s subject-ldap[;type=value]");
  D("\t\t -u key-usage-name[;key-usage-name]");
  D("\t\t -U ext-key-usage-name[;ext-key-usage-name]");

  D("\taccess\t URL where the CA listens for requests.");

  D("\nGET-CA and GET-CHAIN take name argument, that is something ");
  D("interpreted by the CA to specify a CA entity managed by the responder.");

  D("\nkey URL's are either valid external key paths or in format:");
  D("\t \"generate://savetype:password@keytype:size/save-file-prefix\"");
  D("\t \"file://savetype:password@/file-prefix\"");
  D("\t \"file://passphrase/file-prefix\"");
  D("\t \"file:/file-prefix\"");
  D("\t \"key-filename\"");

  D("\tkeytype for the SCEP protocol has to be RSA\n");
  D("\tsavetypes are: ssh|ssh1|ssh2|pkcs1|x509|pkcs8|pkcs8s\n");

#undef D
  if (code > -1)
    {
      ssh_util_uninit();
      exit(code);
    }
}

int main(int ac, char **av)
{
  char *op = "", *prog;
  const char *new_cert_path = NULL, *new_cert_subject = NULL;
  const char *new_cert_usage = NULL, *new_cert_ext_usage = NULL;
  int opt, numproviders = 0, opcode = 0;
  SshCepEnrollClient c;
  SshAuProvider providers = NULL;
  SshX509Certificate opencert;
  unsigned char *der;
  size_t der_len;
  int retval = 0;

  prog = av[0];

  if (ac > 1)
    {
      op = av[1];
      if (!strncasecmp(op, "get-ca", 6)) opcode = SCEP_GET_CA;
      else if (!strncasecmp(op, "get-ce", 6)) opcode = SCEP_GET_CERT;
      else if (!strncasecmp(op, "get-ch", 6)) opcode = SCEP_GET_CA_CHAIN;
      else if (!strncasecmp(op, "enr", 3))    opcode = SCEP_ENROLL;
      else if (!strncasecmp(op, "pol", 3))    opcode = SCEP_POLL;
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
  ssh_x509_library_initialize(NULL);

  c = ssh_xcalloc(1, sizeof(*c));
  c->progname = prog;
  c->opcode = opcode;
  c->opname = op;

  c->subject.client = c;
  c->current.client = c;

  while ((opt = ssh_getopt(ac, av,
                           "o:r:d:S:H:T:s:u:U:C:P:p:X:hE:V:N:",
                           NULL))
         != EOF)
    {
      switch (opt)
        {
        case 'o': c->output_prefix = ssh_optarg; break;
        case 'r': c->statefile = ssh_optarg; break;
        case 'd': ssh_debug_set_level_string(ssh_optarg); break;

        case 'S': c->ca.socks_url = ssh_custr(ssh_optarg); break;
        case 'H': c->ca.proxy_url = ssh_custr(ssh_optarg); break;

        case 'T': new_cert_path = ssh_optarg; break;
        case 's': new_cert_subject = ssh_optarg; break;
        case 'u': new_cert_usage = ssh_optarg; break;
        case 'U': new_cert_ext_usage = ssh_optarg; break;

        case 'C': c->ca.cert_file = ssh_optarg; break;
        case 'V': c->ca.sign_cert_file = ssh_optarg; break;
        case 'E': c->ca.encr_cert_file = ssh_optarg; break;

        case 'P': c->subject.prvkey_path = ssh_optarg; break;
        case 'p': c->ca.psk = ssh_custr(ssh_optarg); break;

        case 'X': brokenflags = atoi(ssh_optarg); break;
        case 'N': stir(ssh_optarg); break;
        case 'h':
        default:
          ssh_warning("%s: unknown option `%c'", prog, (char)opt);
          ssh_x509_library_uninitialize();
          ssh_free(c);
          usage(1);
          break;
        }
    }

  ssh_event_loop_initialize();

  ac -= ssh_optind;
  av += ssh_optind;

  if (!c->output_prefix)
    c->output_prefix = "subject";


  /* Verify the keytype is RSA */
  if (c->subject.prvkey_path)
    {
      unsigned char *scheme = NULL, *type = NULL, *size = NULL, *kind = NULL,
        *pass = NULL, *path = NULL;

      if (!ssh_url_parse((unsigned char *)c->subject.prvkey_path,
                         &scheme, &type, &size, &kind, &pass, &path))
        {
          ssh_warning("Cannot parse private key path: %s",
                      c->subject.prvkey_path);
          ssh_xfree(scheme); ssh_xfree(type); ssh_xfree(size);
          ssh_xfree(kind); ssh_xfree(pass); ssh_xfree(path);
          goto cleanup;
        }

      if (type && !ssh_usstrcmp(type, "dsa"))
        {
          ssh_warning("SCEP does not support DSA keys (%s)",
                      c->subject.prvkey_path);
          ssh_xfree(scheme); ssh_xfree(type); ssh_xfree(size);
          ssh_xfree(kind); ssh_xfree(pass); ssh_xfree(path);
          goto cleanup;
        }

      ssh_xfree(scheme); ssh_xfree(type); ssh_xfree(size);
      ssh_xfree(kind); ssh_xfree(pass); ssh_xfree(path);
    }

  if (ac > 0)
    {
      c->ca.access_url = ssh_custr(av[0]);
      if (ac > 1)
        {
          if (opcode == SCEP_ENROLL)
            c->ca.cert_file = av[1];
          else
            c->ca.name = ssh_custr(av[1]);
        }
    }
  else if (opcode != SCEP_POLL)
    {
      ssh_warning("%s: CA access point not given", prog);
      goto cleanup;
    }

  if (opcode == SCEP_GET_CA_CHAIN || opcode == SCEP_GET_CA)
    {
      SshEcCepCA ca;

      if (c->ca.name == NULL)
        {
          ssh_warning("%s: %s; operation requires CA name.", prog, op);
          goto cleanup;
        }
      ca = ssh_xcalloc(1, sizeof(*ca));
      ca->name    = ssh_xstrdup(c->ca.name);
      ca->address = c->ca.access_url ? ssh_xstrdup(c->ca.access_url) : NULL;
      ca->socks   = c->ca.socks_url ? ssh_xstrdup(c->ca.socks_url) : NULL;
      ca->proxy   = c->ca.proxy_url ? ssh_xstrdup(c->ca.proxy_url) : NULL;
      ca->identity_type =
        (opcode == SCEP_GET_CA) ? SSH_EC_CA_TYPE_CA : SSH_EC_CA_TYPE_RA;
      ca->ca_cert = NULL;
      ca->ca_cert_len = 0;
#ifdef SSHDIST_VALIDATOR_HTTP
      ssh_ec_cep_authenticate(ca, ec_cep_process_certs, c);
#endif /* SSHDIST_VALIDATOR_HTTP */
    }

  if (opcode == SCEP_POLL)
    {
      if (!c->subject.prvkey_path)
        {
          ssh_warning("%s: %s; requires private key.", prog, op);
          exit(1);
        }

      if (c->ca.cert_file == NULL)
        {
          if (c->ca.sign_cert_file == NULL || c->ca.encr_cert_file == NULL)
            {
              ssh_warning("%s:\n"
                          "CA certificate or both RA certificates needed.\n"
                          "In case of a single RA certificate, it is used "
                          "both as encryption and\nvalidation certificate.",
                          prog);
              usage(-1);
              goto cleanup;
            }
        }

      if (c->statefile)
        {
          if (ssh_read_file(c->statefile, &c->state, &c->state_len))
            {
              /* This jumps into if(SCEP_ENROLL) branch */
              c->subject.certtemp = ssh_x509_cert_allocate(SSH_X509_PKCS_10);
              goto state_file_given;
            }
          else
            {
              ssh_warning("%s: %s; state file '%s' is not readable.",
                          prog, op, c->statefile);
              goto cleanup;
            }
        }
      else
        {
          ssh_warning("%s: %s; state file not given for poll request.",
                      prog, op);
          goto cleanup;
        }
    }

  /* Now process options and check combinations. */
  if (opcode == SCEP_ENROLL)
    {
      if (c->ca.cert_file == NULL)
        {
          if (c->ca.sign_cert_file == NULL || c->ca.encr_cert_file == NULL)
            {
              ssh_warning("%s:\n"
                          "CA certificate or both RA certificates needed.\n"
                          "In case of a single RA certificate, it is used "
                          "both as encryption and\nvalidation certificate.",
                          prog);
              usage(-1);
              goto cleanup;
            }
        }
      else
        {
          if (c->ca.sign_cert_file || c->ca.encr_cert_file)
            {
              ssh_warning("%s: "
                          "Both CA certificate and RA certificates given.",
                          prog);
              usage(-1);
              goto cleanup;
            }
        }

      if (!c->ca.psk)
        {
          ssh_warning("%s: enroll; "
                      "revocationPassword (Challenge) was not given.", prog);
        }
      if (!c->subject.prvkey_path)
        {
          ssh_warning("%s: enroll; "
                      "requires private key or generation parameters.", prog);
          goto cleanup;
        }
      if (!new_cert_subject && !new_cert_path)
        {
          ssh_warning("%s: enroll; "
                      "requires certificate template or subject name.", prog);
          goto cleanup;
        }

      /* Parse new_ somethings, and create keys needed. */
      if (new_cert_path)
        {
          if (au_read_certificate(new_cert_path, &der, &der_len, &opencert))
            {
              c->subject.cert = der;
              c->subject.cert_len = der_len;
              c->subject.certtemp = opencert;
            }
          else
            {
              ssh_warning("%s: %s; "
                          "can't read in template certificate from %s.",
                          prog, op, new_cert_path);
              goto cleanup;
            }
        }
      else
        c->subject.certtemp = ssh_x509_cert_allocate(SSH_X509_PKCS_10);

      /* We'll always have subject template allocated now. */

      if (new_cert_usage)
        au_cert_set_key_usage(c->subject.certtemp, new_cert_usage);

      if (new_cert_ext_usage)
        au_cert_set_ext_key_usage(c->subject.certtemp, new_cert_ext_usage);

      if (new_cert_subject)
        {
          char *name;
          au_cert_set_subject(c->subject.certtemp,
                              SSH_CHARSET_ISO_8859_1,
                              new_cert_subject);
          if (!ssh_x509_cert_get_subject_name(c->subject.certtemp, &name))
            {
              ssh_x509_cert_free(c->subject.certtemp);
              ssh_warning("%s: %s; "
                          "subject DN has to be given. "
                          "subjectAlternative names are not enough.",
                          prog, op);
              goto cleanup;
            }
          ssh_free(name);
        }

    state_file_given:
      if (c->ca.cert_file)
        {
          if (au_read_certificate(c->ca.cert_file, &der, &der_len, NULL))
            {
              c->ca.cert = der;
              c->ca.cert_len = der_len;
            }
          else
            {
              ssh_x509_cert_free(c->subject.certtemp);
              ssh_warning("%s: %s; can't read in CA certificate from %s.",
                          prog, op, c->ca.cert_file);
              goto cleanup;
            }
        }

      if (c->ca.encr_cert_file)
        {
          if (!au_read_certificate(c->ca.encr_cert_file,
                                   &c->ca.encr_cert,
                                   &c->ca.encr_cert_len,
                                   NULL))
            {
              ssh_x509_cert_free(c->subject.certtemp);
              ssh_warning("%s: %s; can't read in RA encryption certificate "
                          "from %s.",
                          prog, op, c->ca.encr_cert_file);
              goto cleanup;
            }
        }

      if (c->ca.sign_cert_file)
        {
          if (!au_read_certificate(c->ca.sign_cert_file,
                                   &c->ca.sign_cert,
                                   &c->ca.sign_cert_len,
                                   NULL))
            {
              ssh_x509_cert_free(c->subject.certtemp);
              ssh_warning("%s: %s; can't read in RA signature certificate "
                          "from %s.",
                          prog, op, c->ca.sign_cert_file);
              goto cleanup;
            }
        }

      /* Then start external key, continue enrollment when it is
         ready. */
      ssh_au_ek_init(providers, numproviders,
                     cep_ek_auth_cb, cep_ek_notify_cb, c,
                     cep_enroll_start, c);

    } /* end if SCEP_ENROLL */

  /* Enter the event loop. */
  ssh_event_loop_run();

 cleanup:
  ssh_event_loop_uninitialize();
  retval = c->retval;
  if (c->subject.prvkey)
    ssh_private_key_free(c->subject.prvkey);

  ssh_x509_cert_free(c->current.certtemp);
  ssh_xfree(c->subject.cert);
  ssh_xfree(c->ca.cert);
  if (c->ek)
    ssh_ek_free(c->ek, NULL_FNPTR, NULL);
  ssh_xfree(c->ca.sign_cert);
  ssh_xfree(c->ca.encr_cert);
  ssh_xfree(c->state);
  ssh_xfree(c);


  ssh_x509_library_uninitialize();
  ssh_util_uninit();

  return retval;
}
