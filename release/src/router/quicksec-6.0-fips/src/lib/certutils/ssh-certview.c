/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A viewing program for:
   - X.509 certificates
   - CRLs
   - PKCS#10 requests,
   - private keys in various formats (PKCS#1,PKCS#8,SSH2,others)
   - other miscellenious PKI file formats.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "sshbase64.h"
#include "x509.h"
#include "dn.h"
#include "oid.h"
#include "sshpsystem.h"
#include "sshfileio.h"
#include "sshpkcs1.h"
#include "sshpkcs8.h"
#include "x509cmp.h"
#include "sshbuffer.h"
#include "iprintf.h"
#include "sshprvkey.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "ssh-certview"


static void copyright(void)
{

  iprintf("X.509 v3 certificate and v2 crl viewer.\n"
          "Copyright (c) 2002 - 2014, INSIDE Secure Oy."
          "  All rights reserved.\n");

  return;
}

static int base     = 10;
static int ldap_dns = 0;
static int skip_bytes = 0;
static SshCharset output_charset = SSH_CHARSET_ISO_8859_1;

char *passphrase = NULL;
static int verbose = 1;

#define ciprintf(l, s) if (verbose > l) { iprintf(s); fflush(stdout);}
#define ciprintf2(l, f,p) if (verbose > l) { iprintf(f,p);fflush(stdout);}



#define OP_AUTO 0
#define OP_CRL 1
#define OP_CRT 2
#define OP_REQ 3
#define OP_PRV 4
#define OP_CMP 5
#define OP_SCEP 6
#define OP_CRMF 8
#define OP_PUB 9

const char *x509_error_table[] =
{
  "success",
  "generic",
  "private key related operation",
  "public key related operation",
  "ASN.1 decoding",
  "ASN.1 encoding",
  "version check",
  "version encoding",
  "distinguished name check",
  "distinguished name encoding",
  "unique identifier encode",
  "signature algorithm check",
  "signature algorithm encoding",
  "signature check",
  "signature related operation",
  "validity encoding",
  "time decoding",
  "time encoding",
  "duplicate extension detected",
  "invalid extension detected",
  "extension encoding",
  "unknown style",
  "unknown critical extension",
  "unknown value",
  NULL,
  NULL
};

const char *x509_status(SshX509Status rv)
{
  if (rv > 25)
    return "failure; error code too large!";
  return x509_error_table[rv];
}

Boolean read_file(const char *file,
                  unsigned char **buf, size_t *buf_len,
                  unsigned char **outer_buf, size_t *outer_buf_len)
{
  int i, j;
  ciprintf2(1, "Reading file %s\n", file);
  if (!ssh_read_gen_file(file, buf, buf_len))
    {
      ssh_warning("ssh-certview: Could not read file %s\n", file);
      return FALSE;
    }

  if (file[0] != ':')
    {
      for (i = 0; isspace((*buf)[i]) && i < *buf_len; i++)
        ;

      for (j = i; j + 10 < *buf_len; j++)
        {
          if (memcmp((*buf + j), "-----BEGIN", 10) == 0)
            {
              /* Try pem format. */
              ciprintf2(1, "Looks like pem file %s\n", file);
              ssh_free(*buf);
              if (!ssh_read_file_base64(file, buf, buf_len))
                {
                  ssh_warning("ssh-certview: Could not read file as"
                              " base64 %s\n", file);
                  if (!ssh_read_file(file, buf, buf_len))
                    {
                      ssh_warning("ssh-certview: Could not read file %s\n",
                                  file);
                      return FALSE;
                    }
                }
              break;
            }
        }
      if (i < *buf_len && isxdigit((*buf)[i]) &&
          j + 10 == *buf_len)
        {
          for(; isxdigit((*buf)[i]) && i < *buf_len; i++)
            ;

          if ((*buf)[i] == ':')
            {
              /* Try hexl format. */
              ciprintf2(1, "Looks like hexl file %s\n", file);
              ssh_free(*buf);
              if (!ssh_read_file_hexl(file, buf, buf_len))
                {
                  ssh_warning("ssh-certview: "
                              "Could not read hexl encoded file %s", file);
                  if (!ssh_read_file(file, buf, buf_len))
                    {
                      ssh_warning("ssh-certview: Could not read file %s\n",
                                  file);
                      return FALSE;
                    }
                }
            }
        }
    }

  if (skip_bytes)
    {
      if (*buf_len <= skip_bytes)
        {
          ssh_warning("ssh-certview: File %s is shorter than given offset %d",
                      file, skip_bytes);
          return FALSE;
        }
      memmove (*buf, *buf + skip_bytes, *buf_len - skip_bytes);
      *buf_len -= skip_bytes;
    }
  if (*buf_len > 0)
    return TRUE;
  else
    return FALSE;
}


static Boolean
handle_cert_or_req(unsigned char *buf, size_t buf_len,
                   SshX509CertType cert_type, Boolean verify)
{
  SshX509Certificate c;
  SshX509Status rv;

  ciprintf2(1, "Trying to decode the %s - ",
                 cert_type == SSH_X509_PKIX_CERT ? "certificate" :
                 cert_type == SSH_X509_PKIX_CRMF ? "CRMF certificate request" :
                 cert_type == SSH_X509_PKCS_10 ? "PKCS#10"
                 " certificate request" : "");

  c = ssh_x509_cert_allocate(cert_type);
  if ((rv = ssh_x509_cert_decode(buf, buf_len, c)) != SSH_X509_OK)
    {
      ciprintf2(1, "failed #I[%s]#i.\n", x509_status(rv));
      ssh_x509_cert_free(c);
      return FALSE;
    }
  ciprintf(1, "success.\n");

  if (!cu_dump_cert(c,
                    buf, buf_len,
                    cert_type, output_charset, ldap_dns, base, verify))
    {
      ssh_x509_cert_free(c);
      return FALSE;
    }

  ssh_x509_cert_free(c);
  return TRUE;
}

Boolean handle_crl(unsigned char *buf, size_t buf_len)
{
  SshX509Crl c;
  SshX509Status rv;

  ciprintf(1, "Trying to decode the CRL - ");
  c = ssh_x509_crl_allocate();
  if ((rv = ssh_x509_crl_decode(buf, buf_len, c)) != SSH_X509_OK)
    {
      ciprintf2(1, "failed #I[%s]#i.\n", x509_status(rv));
      ssh_x509_crl_free(c);
      return FALSE;
    }
  ciprintf(1, "success.\n");
  if (cu_dump_crl(c, output_charset, ldap_dns, base))
    {
      ssh_x509_crl_free(c);
      return TRUE;
    }
  ssh_x509_crl_free(c);
  return FALSE;
}

/* Returns 0 on success, 1 on failure, -1 on failure which means
 * that autodetect can bail out, ie. there is no point in guessing anymore.
 */
int handle_prv(unsigned char *buf, size_t buf_len,
               unsigned char *outer_buf, size_t outer_buf_len)
{
  SshPrivateKey prv;
  SshSKBType kind;
  char *comment, *cipher, *hash;
  const char *type_str;
  Boolean needs_secret;
  char retry = 0;
  int rv = 1;

  ciprintf(1, "Trying to determine private key type - ");

  if (outer_buf)
    retry = 1;
  else
    outer_buf = buf, outer_buf_len = buf_len, retry = 0;

  do
    {
      comment = NULL;
      if ((ssh_skb_get_info(outer_buf, outer_buf_len,
                            &cipher, &hash,
                            NULL, NULL, &kind, &comment) ==
           SSH_CRYPTO_OK)
          && ssh_skb_get_type_info(kind,
                                    &needs_secret,
                                    &type_str))
        {
          ciprintf2(1, "success.\n"
                         "Private key type = #I%s#i\n", type_str);
          if (comment)
            iprintf("Comment = #I%s#i\n", comment);
          ssh_xfree(comment);

          if (needs_secret && passphrase == NULL)
            {
              ciprintf(0,
                       "This private key is encrypted. Please "
                       "provide a passphrase with option -pass.\n");
              ssh_free(cipher);
              ssh_free(hash);
              return -1;
            }
          ciprintf(1, "Trying to decode private key - ");
          if (ssh_skb_decode(kind,
                             outer_buf, outer_buf_len,
                             cipher, hash,
                             (unsigned char *)
                             (passphrase == NULL ? "" : passphrase),
                             passphrase == NULL ? 0  : strlen(passphrase),
                             &prv) == SSH_CRYPTO_OK)
            {
              ciprintf(1, "success.\n");
              if (!cu_dump_prv(prv, base))
                {
                  ssh_private_key_free(prv);
                  rv = 1;
                }
              else
                {
                  ssh_private_key_free(prv);
                  rv = 0;
                }
            }
          ssh_free(cipher);
          ssh_free(hash);
          return rv;
        }
    } while (outer_buf = buf, outer_buf_len = buf_len, retry--);

  ciprintf(1, "failed.\n");
  return 1;
}

Boolean handle_pub(unsigned char *buf, size_t buf_len,
                   unsigned char *outer_buf, size_t outer_buf_len)
{
    return FALSE;
}

Boolean handle_cmp(unsigned char *buf, size_t buf_len)
{
  return FALSE;
}

Boolean handle_scep(unsigned char *buf, size_t buf_len)
{
  return FALSE;
}

Boolean handle_autodetect(unsigned char *buf, size_t buf_len,
                          unsigned char *outer_buf, size_t outer_buf_len,
                          Boolean verify)
{
  ciprintf(1, "Trying to decode the object...\n");

  /* Test for certificate. */
  ciprintf(1, "assuming it is a certificate ... ");
  if (handle_cert_or_req(buf, buf_len, SSH_X509_PKIX_CERT, verify))
    return TRUE;

  /* Test for PKCS-10. */
  ciprintf(1, "assuming it is a PKCS-10 request ... ");
  if (handle_cert_or_req(buf, buf_len, SSH_X509_PKCS_10, verify))
    return TRUE;

  /* Test for CRL. */
  ciprintf(1, "assuming it is a CRL ... ");
  if (handle_crl(buf, buf_len))
    return TRUE;

  /* Check for an SSH2 public key */
  ciprintf(1, "assuming it is an SSH2 public key ... ");

  if (handle_pub(buf, buf_len, outer_buf, outer_buf_len))
    return TRUE;


  /* Check whether it is a private key. */
  ciprintf(1, "assuming it is a private key ... ");

  switch (handle_prv(buf, buf_len, outer_buf, outer_buf_len))
    {
    case 0: return TRUE;
    case -1: return FALSE;
    }

#ifdef SSHDIST_CERT_CRMF
  /* Test for CRMF. */
  ciprintf(1, "assuming it is a PKIX CRMF ... ");
  if (handle_cert_or_req(buf, buf_len, SSH_X509_PKIX_CRMF, verify))
    return TRUE;
#endif /* SSHDIST_CERT_CRMF */

  ssh_warning("ssh-certview: Failed to autodetect the object type.");
  return FALSE;
}

int main(int argc, char *argv[])
{
  int pos;
  int next_op;
  int ret = 0;
  int filecount = 0;
  unsigned char *buf,*outer_buf;
  size_t buf_len, outer_buf_len;
  Boolean verify = TRUE;


  ssh_global_init();
  ssh_x509_library_initialize(NULL);
#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */


  for (next_op = OP_AUTO, pos = 1; pos < argc; pos++)
    {
      if (strcmp(argv[pos], "-h") == 0)
        {
          copyright();
          iprintf("Usage: ssh-certview [options] file [options] file ...\n"
                  "options:\n"
                  "#I"
                  "-h         this help\n"
                  "-verbose   more diagnostic output.\n"
                  "-debug f   debug output.\n"
                  "-quiet     no diagnostic output.\n"
                  "-auto      next item type is autodeteted (default).\n"
                  "-cert      next item is a certificate.\n"
                  "-crl       next item is a CRL.\n"
                  "-prv       next item is a private key.\n"
                  "-req       next item is a PKCS10 certificate request.\n"
                  "-pass p    passphrase used to encrypt the private key.\n"
                  "-autoenc   determine pem/der automatically (default).\n"
                  "-pem       assume pem-like format.\n"
                  "-der       assume der-like format.\n"
                  "-hexl      assume hexl-like format.\n"
                  "-skip n    skip n bytes from beginning of input.\n"
                  "-ldap      print names in LDAP order.\n"
                  "-utf8      print names in UTF8.\n"
                  "-latin1    print names in ISO-8859-1.\n"
                  "-base10    output big numbers in base 10 (default).\n"
                  "-base16    output big numbers in base 16.\n"
                  "-base64    output big numbers in base 64.\n"
                  "-width w   set output width.\n"
                  "-noverify  don't check the validity of the signature"
                  " on the input certificate.\n"
                  "#i");
          continue;
        }
      if ((strcmp(argv[pos], "-verbose") == 0) ||
          (strcmp(argv[pos], "-v") == 0))
        {
          verbose++;
          continue;
        }
      if ((strcmp(argv[pos], "-debug") == 0) ||
          (strcmp(argv[pos], "-d") == 0))
        {
          if (pos + 1 < argc)
            ssh_debug_set_level_string(argv[++pos]);
          continue;
        }
      if ((strcmp(argv[pos], "-quiet") == 0) || (strcmp(argv[pos], "-q") == 0))
        {
          verbose = 0;
          continue;
        }
      if (strcmp(argv[pos], "-auto") == 0)
        {
          next_op = OP_AUTO;
          continue;
        }
      if (strcmp(argv[pos], "-noverify") == 0)
        {
          verify = FALSE;
          continue;
        }
      if (strcmp(argv[pos], "-cert") == 0)
        {
          next_op = OP_CRT;
          continue;
        }
      if (strcmp(argv[pos], "-req") == 0)
        {
          next_op = OP_REQ;
          continue;
        }
      if (strcmp(argv[pos], "-crl") == 0)
        {
          next_op = OP_CRL;
          continue;
        }
      if (strcmp(argv[pos], "-prv") == 0)
        {
          next_op = OP_PRV;
          continue;
        }
      if (strcmp(argv[pos], "-ldap") == 0)
        {
          ldap_dns = 1;
          continue;
        }
      if (strcmp(argv[pos], "-utf8") == 0)
        {
          output_charset = SSH_CHARSET_UTF8;
          continue;
        }

      if (strcmp(argv[pos], "-latin1") == 0)
        {
          output_charset = SSH_CHARSET_ISO_8859_1;
          continue;
        }

      if (strcmp(argv[pos], "-base10") == 0)
        {
          base=10;
          continue;
        }
      if (strcmp(argv[pos], "-base16") == 0)
        {
          base=16;
          continue;
        }
      if (strcmp(argv[pos], "-base64") == 0)
        {
          base=64;
          continue;
        }

      if (strcmp(argv[pos], "-width") == 0 && pos + 1 < argc)
        {
          pos++;
          iprintf_set(atoi(argv[pos]), 0, 0);
          continue;
        }

      if (strcmp(argv[pos], "-skip") == 0 || strcmp(argv[pos], "-pos") == 0)
        {
          pos++;
          if (pos < argc)
            skip_bytes = atoi(argv[pos]);
          continue;
        }

      if (strcmp(argv[pos], "-p") == 0 || strcmp(argv[pos], "-pass") == 0)
        {
          pos++;
          if (pos < argc)
            passphrase = argv[pos];
          continue;
        }

      if ((++filecount == 1) && (verbose > 1))
        copyright();
      outer_buf = buf = NULL, outer_buf_len = buf_len = 0;

      if (read_file(argv[pos],
                    &buf, &buf_len,
                    &outer_buf, &outer_buf_len))
        {
          switch (next_op)
            {
            case OP_AUTO:
              if (!handle_autodetect(buf, buf_len, outer_buf, outer_buf_len,
                                     verify))
                ret++;
              break;
            case OP_CRL:
              if (!handle_crl(buf, buf_len))
                ret++;
              break;
            case OP_CRT:
              if (!handle_cert_or_req(buf, buf_len, SSH_X509_PKIX_CERT,
                                      verify))
                ret++;
              break;
            case OP_REQ:
              if (!handle_cert_or_req(buf, buf_len, SSH_X509_PKCS_10, verify))
                ret++;
              break;
            case OP_PRV:
              if (0 != handle_prv(buf, buf_len, outer_buf, outer_buf_len))
                ret++;
              break;
            default:
              SSH_ASSERT(0);
              break;
            }
          ssh_xfree(buf);
          ssh_xfree(outer_buf);
        }
    }

  ciprintf(1, "\n");

  if (ret == 0)
    {
      ciprintf(1, "Finished successfully.\n");
    }
  else
    {
      ciprintf(1, "Finished with an error.\n");
    }

  ssh_x509_library_uninitialize();
  ssh_util_uninit();
  return ret;
}
