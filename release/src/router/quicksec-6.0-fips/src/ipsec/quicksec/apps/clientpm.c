/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A simple QuickSec policy manager that uses directly the policy
   management API for a minimal policy configuration.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "quicksec_pm.h"
#include "sshglobals.h"
#include "sshgetopt.h"
#include "sshfileio.h"
#ifdef SSHDIST_CERT
#include "x509.h"
#include "cmi.h"
#endif /* SSHDIST_CERT */

#define SSH_DEBUG_MODULE "ClientPm"

#include "pad_auth_domain.h"

static SshPm ipm = NULL;
static SshAuditContext audit = NULL;
static char *audit_file = NULL;
static char *peer = NULL;
#ifdef SSHDIST_EXTERNALKEY
static char *ek_type = NULL;
static char *ek_init_info = NULL;
#endif /* SSHDIST_EXTERNALKEY */
static char *kernel_debug = NULL;
static char *ca = NULL;
static char *identity = NULL;
Boolean no_crls = FALSE;
static SshPmIdentityType ike_id_type = SSH_PM_IDENTITY_ANY;
static SshPmSecretEncoding ike_id_encoding = SSH_PM_ENCODING_UNKNOWN;
static SshPmIdentityType ca_id_type = SSH_PM_IDENTITY_ANY;
static SshPmSecretEncoding ca_id_encoding = SSH_PM_ENCODING_UNKNOWN;

/*************** Some glue code for the user-mode interceptor ***************/


/* Policy manager destroy call-back */
static void stop_cb(void *context)
{
  ipm = NULL;
}

/* Policy configuration call-back */
static void
status_cb(SshPm pm, Boolean success, void *context)
{
  if (success)
    {
      printf("Policy rules loaded\n");
      return;
    }
  else
    {
      ssh_warning("Could not configure rules");
      /* Destroy policy manager. */
      ssh_pm_destroy(ipm, stop_cb, NULL);
    }
}

/* Policy manager create call-back */
static void
create_cb(SshPm pm, void *context)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshUInt32 ca_flags = 0;
  Boolean ca_added = FALSE;
  unsigned char *buf;
  size_t buf_len;
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_EXTERNALKEY
  SshExternalKey ek;
  SshEkStatus status;
#endif /* SSHDIST_EXTERNALKEY */
  SshPmTunnel tunnel = NULL;
  SshPmRule rule;
  SshIpAddrStruct dummy;
  SshUInt32 tunnel_flags = 0;

  if (pm == NULL)
    {
      ssh_warning("Could not connect to the packet processing engine");
      return;
    }

  ipm = pm;

#ifndef VXWORKS
  if (kernel_debug)
    ssh_pm_set_kernel_debug_level(ipm, kernel_debug);
#endif /* VXWORKS */

  audit = ssh_pm_create_audit_module(ipm, SSH_AUDIT_FORMAT_DEFAULT,
                                     audit_file);

  if (!audit)
    {
      ssh_warning("Cannot create audit module");
      goto error;
    }

  if (!ssh_pm_attach_audit_module(ipm, SSH_PM_AUDIT_ALL, audit))
    {
      ssh_warning("Cannot attach audit module");
      goto error;
    }

#ifdef SSHDIST_EXTERNALKEY
  if (ek_type)
    {
      ek = ssh_pm_get_externalkey(ipm);
      SSH_ASSERT(ek != NULL);

      status = ssh_ek_add_provider(ek, ek_type, ek_init_info,
                                   NULL, 0, NULL);
      if (status != SSH_EK_OK)
        {
          ssh_warning("Could not add externalkey provider `%s': %s",
                      ek_type, ssh_ek_get_printable_status(status));
          goto error;
        }
    }
#endif /* SSHDIST_EXTERNALKEY */

#ifdef SSHDIST_IKE_CERT_AUTH
  if (no_crls)
    ca_flags |= SSH_PM_CA_NO_CRL;

  /* Try first to read the CA as a file */
  if (ssh_read_gen_file(ca, &buf, &buf_len))
    {
      if (!ssh_pm_auth_domain_add_ca(ipm, NULL, buf, buf_len, ca_flags))
        {
          SSH_DEBUG_HEXDUMP(SSH_D_MY, ("CA cert"), buf, buf_len);
          ssh_warning("Cannot add CA certificate from file");
          ssh_free(buf);
          goto error;
        }
      ca_added = TRUE;
      ssh_free(buf);
    }

  if (!ca_added)
    {
      /* Try to guess the identity type if not specified. This is primitive,
         will not always work and does not support KEY_ID type of identity.
         To do this properly the identity type should be specified to the
         program. */
      if (ca_id_type == SSH_PM_IDENTITY_ANY)
        {
          if (strchr(ca, '@'))
            ca_id_type = SSH_PM_IDENTITY_RFC822;
          else if (ssh_ipaddr_parse(&dummy, ca))
            ca_id_type = SSH_PM_IDENTITY_IP;
          else if (strchr(ca, '.'))
            ca_id_type = SSH_PM_IDENTITY_FQDN;
          else
            ca_id_type = SSH_PM_IDENTITY_DN;
        }

      ca_flags |= (ca_id_type << 16);
      if (!ssh_pm_auth_domain_add_ca(ipm, NULL,
                                     ssh_custr(ca), strlen(ca), ca_flags))
        {
          SSH_DEBUG_HEXDUMP(SSH_D_MY, ("CA cert"), ssh_custr(ca), strlen(ca));
          ssh_warning("Cannot add CA certificate from identity");
          goto error;
        }
    }
#else /* SSHDIST_IKE_CERT_AUTH */
  ssh_warning("No authentication possible due to missing certificate "
              "functionality.");
  goto error;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  tunnel_flags |= SSH_PM_TI_CFGMODE;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Create a tunnel object. */
  tunnel = ssh_pm_tunnel_create(ipm,
                                SSH_PM_CRYPT_AES     |
                                SSH_PM_CRYPT_AES_CTR |
                                SSH_PM_CRYPT_3DES    |
                                SSH_PM_MAC_HMAC_MD5  |
                                SSH_PM_MAC_HMAC_SHA1 |
                                SSH_PM_MAC_XCBC_AES  |
                                SSH_PM_IPSEC_ESP,
                                tunnel_flags,
                                ssh_custr("tunnel"));
  if (tunnel == NULL)
    {
      ssh_warning("Could not create tunnel");
      goto error;
    }

  /* Add our IKE peer. */
  if (!ssh_pm_tunnel_add_peer(tunnel, (unsigned char *)peer))
    {
      ssh_warning("Could not add IKE peer");
      goto error;
   }

  /* Try to guess the identity type. This is primitive, will not
     always work and does not support KEY_ID type of identity. To do
     this properly the identity type should be specified to the program. */
  if (ike_id_type == SSH_PM_IDENTITY_ANY)
    {
      if (strchr(identity, '@'))
        ike_id_type = SSH_PM_IDENTITY_RFC822;
      else if (ssh_ipaddr_parse(&dummy, identity))
        ike_id_type = SSH_PM_IDENTITY_IP;
      else if (strchr(identity, '.'))
        ike_id_type = SSH_PM_IDENTITY_FQDN;
      else
        ike_id_type = SSH_PM_IDENTITY_DN;

      ike_id_encoding = SSH_PM_BINARY;
    }

  /* Tunnel identity */
  if (!ssh_pm_tunnel_set_local_identity(tunnel,
                                        0,
                                        ike_id_type,
                                        ike_id_encoding,
                                        ssh_custr(identity),
                                        strlen(identity),
                                        1))
    {
      ssh_warning("Could not configure IKE identity");
      goto error;
    }

  /* Create a rule to send all traffic from the local stack to the tunnel. */
  rule = ssh_pm_rule_create(ipm, 100, SSH_PM_RULE_PASS, NULL, tunnel, NULL);
  if (rule == NULL)
    {
      ssh_warning("Could not create rule");
      goto error;
    }
  ssh_pm_rule_set_local_stack(rule, SSH_PM_FROM);

  if (ssh_pm_rule_add(ipm, rule) == SSH_IPSEC_INVALID_INDEX)
    {
      ssh_warning("Could not add rule");
      goto error;
    }

  /* Create a rule to pass everything else in plain-text. */
  rule = ssh_pm_rule_create(ipm, 99, SSH_PM_RULE_PASS, NULL, NULL, NULL);
  if (rule == NULL)
    {
      ssh_warning("Could not create rule");
      goto error;
    }

  if (ssh_pm_rule_add(ipm, rule) == SSH_IPSEC_INVALID_INDEX)
    {
      ssh_warning("Could not add rule");
      goto error;
    }

  /* We do not need the tunnel anymore. */
  ssh_pm_tunnel_destroy(pm, tunnel);

  /* Start using our new policy. */
  ssh_pm_commit(ipm, status_cb, NULL);
  return;


  /* Error handling. */

 error:
  ssh_warning("Error encountered");

  /* Free the possibly allocated tunnel object.  The
     ssh_pm_tunnel_destroy() function can be called with NULL argument
     as well. */
  ssh_pm_tunnel_destroy(pm, tunnel);

  /* Abort possible new rules added to the system.  The ssh_pm_abort()
     function can be called even if we did not add any rules, e.g. the
     current modification batch is empty. */
  ssh_pm_abort(ipm);

  /* Destroy the policy manager.  This will cause the
     ssh_event_loop_run() to return. */
  ssh_pm_destroy(ipm, stop_cb, NULL);
}

#ifdef __linux__
# ifdef USERMODE_ENGINE
  char *machine_context = "/proc/quicksec-usermode/engine";
# else /* USERMODE_ENGINE */
  char *machine_context = "/proc/quicksec/engine";
# endif /* USERMODE_ENGINE */
#else /* not __linux__ */
# ifdef WIN32
  char *machine_context = "\\\\.\\QuickSec";
# else /* not WIN32 */
#  ifdef __sun
#   ifdef USERMODE_ENGINE
  char *machine_context = "/devices/pseudo/sshpmdev@0:sshengine-usermode";
#   else /* USERMODE_ENGINE */
  char *machine_context = "/devices/pseudo/sshpmdev@0:sshengine";
#   endif /* USERMODE_ENGINE */
#  else /* not __sun */
#   ifdef USERMODE_ENGINE
  char *machine_context = "/dev/sshengine-usermode";
#   else /* USERMODE_ENGINE */
  char *machine_context = "/dev/sshengine";
#   endif /* USERMODE_ENGINE */
#  endif /* not __sun */
# endif /* not WIN32 */
#endif /* not __linux__ */

/* SIGINT handler for tIpsec */
static void
quit_handler(int sig, void *context)
{
  if (ipm)
    ssh_pm_destroy(ipm, stop_cb, NULL);
}

/* Show short usage text. */
static void
usage(Boolean help)
{
  printf("\
Usage: [OPTION]...\n\
  -g=GATEWAY_ADDRESS    (Mandatory)       IKE peer address\n\
  -i=IDENTITY           (Mandatory)       Local IKE identity\n\
  -I=IDENTITY_TYPE                        Local IKE identity type\n\
  -c=CA_CERT            (Mandatory)       CA certificate\n\
  -C=CA_CERT_ENCODING                     CA certificate encoding\n\
  -p=NUM:NUM                              IKE normal and NAT-T ports\n\
  -a=AUDIT_FILE                           Audit file\n");
#ifdef SSHDIST_EXTERNALKEY
  printf("\
  -e=EK_TYPE                              Externalkey type\n\
  -E=EK_INIT_INFO                         Externalkey init info\n");
#endif /* SSHDIST_EXTERNALKEY */
  printf("\
  -r                                      Disable CRL's\n\
  -D=DEBUG_STRING                         Debug string\n\
  -K=DEBUG_STRING                         Kernel debug string\n\
  -h                                      Print this help and exit\n");

  if (help)
    {
      printf("\
Description:\n\
    clientpm is a program that uses the quicksec_pm.h policy manager API\n\
    for configuring a simple IPsec client. The default policy is to send\n\
    all traffic from the local host to an IPsec tunnel. For some IPsec\n\
    client applications, no further configuration may be needed other than\n\
    what is is specified here.\n\n");
      printf("\
    This program only supports certification authentication in IKE.\n\
    There are three mandatory parameters that must be supplied to this\n\
    program. The IP address of the security gateway must be specified by\n\
    the -g option. The local IKE identity must be specified by the -i\n\
    option, optionally the IKE identity type may be specified by the -I\n\
    option. The trust anchor CA certificate must be specified by the -c\n\
    option. The CA certificate may be specified either as a file or by the\n\
    subject (alternative) name of the CA certificate. If the CA is specified\n\
    by it's name, the -C parameter specifies the type of the subject\n\
    alternative name. The possible values of the -I and -C options are \n\
    'ip', 'dn', 'fqdn', 'email' and 'key-id'. \n\n");
      printf("\
Example command line parameters: \n\n\
   ./clientpm  -i user@ipsec.com \n\
               -I email\n\
               -g 172.30.4.81\n\
               -c /usr/local/certs/rsaca.ca\n\
               -e software \n\
               -E 'directory(/usr/local/certs)'\n");

      printf("\
   In this example the security gateway should have the IP address\n\
   172.30.4.81. The local IKE identity is 'user@ipsec.com' and the\n\
   identity type is explicitly specified as email. The CA certificate is \n\
   specified as a file located at /usr/local/certs/rsaca.ca. The external \n\
   key provider is the softprovider which is initialized with private keys \n\
   and certificates from the /usr/local/certs directory.\n\
   \n\
   ./clientpm  -i user@ipsec.com\n\
               -g 172.30.4.81 \n\
               -c 'C=FI, O=INSIDE Secure, CN=Test RSA CA' \n\n");

      printf("\
   In this example the security gateway is the same as in the first \n\
   example. The local IKE identity is also unchanged. The identity type\n\
   is left implicit, in this case the program will try to guess the identity\n\
   type from the supplied identity string. The CA certificate is specified\n\
   by its subject name. In this example no externalkey provider is \n\
   specified, it is expected that the local private key can be obtained\n\
   from a certificate cache configured independently of externalkey,\n\
   as is the case when using Microsoft MSCAPI support.\n");

    }
}

Boolean get_id_encoding(const char *id,
                        SshPmIdentityType *id_type,
                        SshPmSecretEncoding *secret_encoding)
{
  *secret_encoding = SSH_PM_BINARY;

  if (!strcmp(id, "dn"))
    *id_type = SSH_PM_IDENTITY_DN;
  else if (!strcmp(id, "ip"))
    *id_type = SSH_PM_IDENTITY_IP;
  else if (!strcmp(id, "fqdn"))
    *id_type = SSH_PM_IDENTITY_FQDN;
  else if (!strcmp(id, "email"))
    *id_type = SSH_PM_IDENTITY_RFC822;
#ifdef SSHDIST_IKE_ID_LIST
  else if (!strcmp(id, "idlist"))
    *id_type = SSH_PM_IDENTITY_ID_LIST;
#endif /* SSHDIST_IKE_ID_LIST */
  else if (!strcmp(id, "keyid"))
    {
      *id_type = SSH_PM_IDENTITY_KEY_ID;
      *secret_encoding =  SSH_PM_HEX;
    }
  else
    return FALSE;

  return TRUE;
}


static void
clientpm_log_callback(SshLogFacility facility,
                      SshLogSeverity severity,
                      const char *message,
                      void *context)
{
  printf("%s\n", message);
}

/* Policy manager */
#ifdef VXWORKS
static int
clientpm(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
  SshPmParamsStruct params;
  char *engine_dev;
  int c;

  engine_dev = machine_context;

  memset(&params, 0, sizeof(params));

  ssh_global_init();

  while ((c = ssh_getopt(argc, argv, "i:I:c:C:g:p:a:e:E:D:K:hr",
                         NULL))
         != EOF)
    {
      switch (c)
        {
        case 'p':
          {
            int local_ike_port, local_ike_natt_port;
            int remote_ike_port, remote_ike_natt_port;
            char none;
            if (sscanf(ssh_optarg, "%d:%d,%d:%d%c",
                       &local_ike_port, &local_ike_natt_port,
                       &remote_ike_port, &remote_ike_natt_port,
                       &none) == 4)
              {
                ;
              }
            else if (sscanf(ssh_optarg, "%d:%d%c",
                            &local_ike_port, &local_ike_natt_port,
                            &none) == 2)
              {
                remote_ike_port = local_ike_port;
                remote_ike_natt_port = local_ike_natt_port;
              }
            else
              {
                printf("Malformed IKE ports '%s'\n", ssh_optarg);
                goto error;
              }
            if (local_ike_port == local_ike_natt_port
                || (local_ike_port <= 1024 && local_ike_port != 500)
                || local_ike_natt_port == 500
                || local_ike_port == 4500
                || local_ike_natt_port <= 1024
                || local_ike_port > 65535
                || local_ike_natt_port > 65535
                || remote_ike_port == remote_ike_natt_port
                || (remote_ike_port <= 1024 && remote_ike_port != 500)
                || remote_ike_natt_port == 500
                || remote_ike_port == 4500
                || remote_ike_natt_port <= 1024
                || remote_ike_port > 65535
                || remote_ike_natt_port > 65535)
              {
                printf("Invalid IKE ports '%s'\n", ssh_optarg);
                goto error;
              }
            if (params.num_ike_ports >= SSH_IPSEC_MAX_IKE_PORTS)
              {
                printf("Too many IKE ports '%d'; %d allowed\n",
                        params.num_ike_ports + 1,
                        SSH_IPSEC_MAX_IKE_PORTS);
                goto error;
              }
            params.local_ike_ports[params.num_ike_ports] = local_ike_port;
            params.local_ike_natt_ports[params.num_ike_ports] =
              local_ike_natt_port;
            params.remote_ike_ports[params.num_ike_ports] = remote_ike_port;
            params.remote_ike_natt_ports[params.num_ike_ports] =
              remote_ike_natt_port;
            params.num_ike_ports++;
          }
          break;
        case 'i': identity = ssh_strdup(ssh_optarg);break;
        case 'c': ca = ssh_strdup(ssh_optarg);break;
        case 'a': audit_file = ssh_strdup(ssh_optarg); break;
        case 'g': peer = ssh_strdup(ssh_optarg); break;
#ifdef SSHDIST_EXTERNALKEY
        case 'e': ek_type = ssh_strdup(ssh_optarg); break;
        case 'E': ek_init_info = ssh_strdup(ssh_optarg); break;
#endif /* SSHDIST_EXTERNALKEY */
        case 'D': ssh_debug_set_level_string(ssh_optarg); break;
        case 'K': kernel_debug = ssh_strdup(ssh_optarg); break;
        case 'r': no_crls = TRUE; break;
        case 'h': usage(TRUE); exit(0);
        case 'I':
          if (!get_id_encoding(ssh_optarg, &ike_id_type, &ike_id_encoding))
            {
              printf("Unsupported ID type %s\n", ssh_optarg);
              goto error;
            }
          break;
        case 'C':
          if (!get_id_encoding(ssh_optarg, &ca_id_type, &ca_id_encoding))
            {
              printf("Unsupported ID type %s\n", ssh_optarg);
              goto error;
            }
          break;
        }
    }

  if (argc - ssh_optind != 0)
    {
      usage(FALSE);
      goto error;
    }

  if (peer == NULL)
    {
      ssh_warning("No peer address specified");
      goto error;
    }

  if (ca == NULL)
    {
      ssh_warning("No CA certificate specified");
      goto error;
    }

  if (identity == NULL)
    {
      ssh_warning("No local IKE identity specified");
      goto error;
    }

#ifdef SSHDIST_CERT
  /* Initialize the certificate library, this will initialize crypto
     as well. */
  {
    printf("Initializing certificate library...\n");

    if (!ssh_x509_library_initialize_framework(NULL))
      {
        ssh_warning("Could not initialize the certificate library.");
        goto error;
      }

    if (!ssh_x509_library_register_functions(SSH_X509_PKIX_CERT,
                                             ssh_x509_cert_decode_asn1,
                                             NULL_FNPTR))
      {
        ssh_x509_library_uninitialize();
        ssh_warning("Could not register x509 library functions.");
        goto error;

      }
  }
#else /* SSHDIST_CERT */
  {
    printf("Initializing crypto library...\n");

    if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
      {
        ssh_warning("Could not initialize the crypto library.");
        goto error;
      }
  }
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */




  ssh_event_loop_initialize();
  ssh_pm_library_init();

  ssh_register_signal(SIGINT, quit_handler, NULL);

  ssh_pm_create(engine_dev, NULL, create_cb, NULL);

  ssh_log_register_callback(clientpm_log_callback, NULL);
  ssh_event_loop_run();

  ssh_pm_library_uninit();
  ssh_event_loop_uninitialize();

#ifdef SSHDIST_CERT
  ssh_x509_library_uninitialize();
#endif /* SSHDIST_CERT */
  ssh_crypto_library_uninitialize();

  ssh_free(kernel_debug);
  ssh_free(peer);
  ssh_free(audit_file);
  ssh_free(ca);
  ssh_free(identity);
#ifdef SSHDIST_EXTERNALKEY
  ssh_free(ek_type);
  ssh_free(ek_init_info);
#endif /* SSHDIST_EXTERNALKEY */

  ssh_debug_uninit();
  ssh_global_uninit();
  return 0;

 error:
  ssh_free(kernel_debug);
  ssh_free(peer);
  ssh_free(audit_file);
  ssh_free(ca);
  ssh_free(identity);
#ifdef SSHDIST_EXTERNALKEY
  ssh_free(ek_type);
  ssh_free(ek_init_info);
#endif /* SSHDIST_EXTERNALKEY */

  return 1;
}

#ifdef VXWORKS
/* Start policy manager. To start Quicksec from VxWorks shell:
   -> sshipsec
   -> sshclientstart
*/
int sshclientstart()
{
  int stacksize = 32*1024;
  int priority = 20;
  int options = VX_FP_TASK;

  return taskSpawn("tIpsec", priority, options, stacksize,
                     (FUNCPTR)clientpm,
                     0,0,0, 0, 0, 0, 0, 0, 0, 0);
}

/* Stop policy manager and interceptor */
void sshclientstop()
{
  /* Signal policy manager to exit */
  int taskid=taskNameToId("tIpsec");
  if (taskid == ERROR){
    printf("Cannot get task ID\n");
    return;
  }
  kill(taskid, SIGINT);

  /* Wait until tIpsec exists */
  while (taskNameToId("tIpsec") != ERROR)
    taskDelay(10);

  taskDelay(100);

  /* Unbind interceptor from all interfaces */
  ssh_unload_vxworks();
}
#endif /* VXWORKS */
