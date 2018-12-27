/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI

#include "sshproxykey.h"
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32")

#define SSH_DEBUG_MODULE "SshPmMsCapi"

static HCERTSTORE root_store;
static HCERTSTORE user_store;
static HCERTSTORE temp_store;

static char error_buf[256];
static TCHAR error_tbuf[256];

static const char *
ssh_pm_mscapi_last_error(void)
{
  DWORD error, error_len, error_tlen, error_tchars;

  error = GetLastError();
  if (!error)
    return "";

  error_len = sizeof error_buf / sizeof error_buf[0];
  error_tlen = sizeof error_tbuf / sizeof error_tbuf[0];

  if ((error_tchars = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS,
                                   NULL,
                                   error,
                                   0,
                                   error_tbuf,
                                   error_tlen,
                                   NULL)) >= 2)
    {
      /* Overwrite the trailing newline with a null and print ASCII. */
      error_tbuf[error_tchars - 2] = TEXT('\0');
#ifdef UNICODE
      _snprintf(error_buf, error_len, ": %ls", error_tbuf);
#else /* UNICODE */
      _snprintf(error_buf, error_len, ": %s", error_tbuf);
#endif /* UNICODE */
    }
  else
    {
      /* Probably no message DB available, print numeric error code. */
      _snprintf(error_buf, error_len, ": error %x", (unsigned)error);
    }
  error_buf[error_len - 1] = '\0';
  return error_buf;
}

static SshIkev2PayloadID
ssh_pm_mscapi_binary_to_id(SshIkev2IDType type, PBYTE buf, DWORD len)
{
  SshIkev2PayloadID id;

  id = ssh_malloc(sizeof *id);
  id->id_data = ssh_malloc(len);
  if (id == NULL || id->id_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate IKE ID"));
      if (id)
        ssh_free(id);
      return NULL;
    }

  id->id_type = type;
  memcpy(id->id_data, buf, len);
  id->id_data_size = len;
  return id;
}

static SshIkev2PayloadID
ssh_pm_mscapi_unicode_to_id(SshIkev2IDType type, PWSTR str)
{
  SshIkev2PayloadID id;
  SshUInt32 len = wcslen(str);

  id = ssh_malloc(sizeof *id);
  id->id_data = ssh_malloc(len + 1);
  if (id == NULL || id->id_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate IKE ID"));
      if (id)
        ssh_free(id);
      return NULL;
    }

  id->id_type = type;
  _snprintf(id->id_data, len, "%ls", str);
  id->id_data[len] = '\0';
  id->id_data_size = len;
  return id;
}

static void
ssh_pm_mscapi_free_id(SshIkev2PayloadID id)
{
  if (id)
    {
      if (id->id_data)
        ssh_free(id->id_data);
      ssh_free(id);
    }
}

Boolean
ssh_pm_mscapi_init(void)
{
  DWORD store_flags;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Using local machine certificate stores"));
  store_flags = CERT_SYSTEM_STORE_LOCAL_MACHINE;

  if (!root_store)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Opening trusted certificate store"));
      if (!(root_store = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                       0,
                                       0,
                                       store_flags |
                                       CERT_STORE_READONLY_FLAG,
                                       L"ROOT")))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Cannot open root certificate store%s",
                                  ssh_pm_mscapi_last_error()));
          return FALSE;
        }
    }

  if (!user_store)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Opening user certificate store"));
      if (!(user_store = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                       0,
                                       0,
                                       store_flags |
                                       CERT_STORE_READONLY_FLAG,
                                       L"MY")))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Cannot open user certificate store%s",
                                  ssh_pm_mscapi_last_error()));
          CertCloseStore(root_store, 0);
          root_store = NULL;
          return FALSE;
        }
    }

  if (!temp_store)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Opening temp certificate store"));
      if (!(temp_store = CertOpenStore(CERT_STORE_PROV_MEMORY,
                                       0,
                                       0,
                                       store_flags,
                                       L"YOURS")))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Cannot open temp certificate store%s",
                                  ssh_pm_mscapi_last_error()));
          CertCloseStore(user_store, 0);
          user_store = NULL;
          CertCloseStore(root_store, 0);
          root_store = NULL;
          return FALSE;
        }
    }

  return TRUE;
}

void
ssh_pm_mscapi_uninit(void)
{
  if (temp_store)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Closing temp certificate store"));
      if (!CertCloseStore(temp_store, CERT_CLOSE_STORE_CHECK_FLAG))
        {
          if (GetLastError() == CRYPT_E_PENDING_CLOSE)
            SSH_DEBUG(SSH_D_ERROR, ("All certificates not freed "
                                    "when closing temp certificate store"));
          else
            SSH_DEBUG(SSH_D_ERROR, ("Cannot close temp certificate store%s",
                                    ssh_pm_mscapi_last_error()));
        }
      temp_store = NULL;
    }

  if (user_store)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Closing user certificate store"));
      if (!CertCloseStore(user_store, CERT_CLOSE_STORE_CHECK_FLAG))
        {
          if (GetLastError() == CRYPT_E_PENDING_CLOSE)
            SSH_DEBUG(SSH_D_ERROR, ("All certificates not freed "
                                    "when closing user certificate store"));
          else
            SSH_DEBUG(SSH_D_ERROR, ("Cannot close user certificate store%s",
                                    ssh_pm_mscapi_last_error()));
        }
      user_store = NULL;
    }

  if (root_store)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Closing trusted certificate store"));
      if (!CertCloseStore(root_store, CERT_CLOSE_STORE_CHECK_FLAG))
        {
          if (GetLastError() == CRYPT_E_PENDING_CLOSE)
            SSH_DEBUG(SSH_D_ERROR, ("All certificates not freed "
                                    "when closing root certificate store"));
          else
            SSH_DEBUG(SSH_D_ERROR, ("Cannot close root certificate store%s",
                                    ssh_pm_mscapi_last_error()));
        }
      root_store = NULL;
    }
}

SshCertificate
ssh_pm_mscapi_cert_chain_next(SshCertificateChain chain,
                              SshCertificate prev)
{
  PCERT_SIMPLE_CHAIN schain;
  SshUInt32 i;

  if (chain->cChain < 1)
    return NULL;

  schain = chain->rgpChain[0];

  if (!prev)
    {
      if (schain->cElement > 0)
        return schain->rgpElement[0]->pCertContext;
      else
        return NULL;
    }
  else
    {
      for (i = 0; i < schain->cElement; i++)
        {
          if (schain->rgpElement[i]->pCertContext == prev &&
              i + 1 < schain->cElement)
            return schain->rgpElement[i + 1]->pCertContext;
        }
      return NULL;
    }
}

Boolean
ssh_pm_mscapi_is_ca_cert(SshCertificate cert)
{
  BYTE key_usage;

  SSH_DEBUG(SSH_D_MIDSTART, ("Checking if certificate %p is a CA certificate",
                             (void *)cert));

  if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING,
                               cert->pCertInfo,
                               &key_usage,
                               sizeof key_usage))
    {
      if (GetLastError())
        SSH_DEBUG(SSH_D_FAIL, ("Cannot get certificate key usage%s",
                               ssh_pm_mscapi_last_error()));
      return FALSE;
    }

  if ((key_usage & CERT_KEY_CERT_SIGN_KEY_USAGE))
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Certificate %p is a CA certificate",
                              (void *)cert));
      return TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Certificate %p is not a CA certificate",
                              (void *)cert));
      return FALSE;
    }
}

Boolean
ssh_pm_mscapi_export_local_cert(SshCertificate cert,
                                unsigned char **buf, size_t *len)
{
  PBYTE encoding_buf;

  SSH_DEBUG(SSH_D_MIDSTART, ("Exporting certificate %p", (void *)cert));

  encoding_buf = ssh_malloc(cert->cbCertEncoded);
  if (encoding_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate encoding"));
      return FALSE;
    }

  memcpy(encoding_buf, cert->pbCertEncoded, cert->cbCertEncoded);
  *buf = encoding_buf;
  *len = cert->cbCertEncoded;
  SSH_DEBUG(SSH_D_MIDOK, ("Exported certificate %p", (void *)cert));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Exported data:"), *buf, *len);
  return TRUE;
}

Boolean
ssh_pm_mscapi_import_remote_cert(const unsigned char *buf, size_t len,
                                 SshCertificate *cert)
{
  SshCertificate cert_context = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("Importing certificate"));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Data to import:"), buf, len);

  if (!temp_store)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Certificate store not available"));
      return FALSE;
    }

  if (!CertAddEncodedCertificateToStore(temp_store,
                                        X509_ASN_ENCODING,
                                        buf,
                                        len,
                                        CERT_STORE_ADD_ALWAYS,
                                        &cert_context))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot add certificate to store%s",
                             ssh_pm_mscapi_last_error()));
      return FALSE;
    }

  *cert = cert_context;
  SSH_DEBUG(SSH_D_MIDOK, ("Imported certificate %p", (void *)*cert));
  return TRUE;
}

Boolean
ssh_pm_mscapi_cert_subject(SshCertificate cert,
                           unsigned char **buf, size_t *len)
{
  PBYTE name_buf = NULL;
  DWORD name_len = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Getting subject name of certificate %p",
                             (void *)cert));

  name_len = cert->pCertInfo->Subject.cbData;
  name_buf = ssh_malloc(name_len);
  if (name_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate subject name"));
      return FALSE;
    }
  memcpy(name_buf, cert->pCertInfo->Subject.pbData, name_len);

  *buf = name_buf;
  *len = name_len;
  SSH_DEBUG(SSH_D_MIDOK, ("Got subject name of certificate %p", (void *)cert));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Name:"), *buf, *len);
  return TRUE;
}

Boolean
ssh_pm_mscapi_cert_issuer(SshCertificate cert,
                          unsigned char **buf, size_t *len)
{
  PBYTE name_buf = NULL;
  DWORD name_len = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Getting issuer name of certificate %p",
                             (void *)cert));

  name_len = cert->pCertInfo->Issuer.cbData;
  name_buf = ssh_malloc(name_len);
  if (name_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate issuer name"));
      return FALSE;
    }
  memcpy(name_buf, cert->pCertInfo->Issuer.pbData, name_len);

  *buf = name_buf;
  *len = name_len;
  SSH_DEBUG(SSH_D_MIDOK, ("Got issuer name of certificate %p", (void *)cert));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Name:"), *buf, *len);
  return TRUE;
}

Boolean
ssh_pm_mscapi_cert_key_id(SshCertificate cert,
                          unsigned char **buf, size_t *len)
{
  PBYTE hash_buf = NULL;
  DWORD hash_len = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Computing key id of certificate %p",
                             (void *)cert));

  hash_len = 20;

  hash_buf = ssh_malloc(hash_len);
  if (hash_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate key id"));
      return FALSE;
    }

  if (!CryptHashPublicKeyInfo(0,
                              CALG_SHA1,
                              0,
                              X509_ASN_ENCODING,
                              &cert->pCertInfo->SubjectPublicKeyInfo,
                              hash_buf,
                              &hash_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot compute SHA-1 key id%s",
                             ssh_pm_mscapi_last_error()));
      ssh_free(hash_buf);
      return FALSE;
    }

  if (hash_len != 20)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Length of certificate key id is not 20"));
      ssh_free(hash_buf);
      return FALSE;
    }

  *buf = hash_buf;
  *len = hash_len;
  SSH_DEBUG(SSH_D_MIDOK, ("Computed key id of certificate %p", (void *)cert));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Key id:"), *buf, *len);
  return TRUE;
}

SshIkev2PayloadID
ssh_pm_mscapi_str_to_dn(const unsigned char *str)
{
  size_t len           = strlen(str);
  WCHAR *tstr          = NULL;
  DWORD tstr_len       = 0;
  PBYTE dn_buf         = NULL;
  DWORD dn_len         = 0;
  SshIkev2PayloadID id = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("Parsing distinguished name string `%s'", str));

  if ((tstr_len = MultiByteToWideChar(CP_UTF8, 0, str, -1,
                                      NULL, 0)) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Multibyte conversion failed"));
      goto fail;
    }

  tstr = ssh_malloc((tstr_len) * sizeof *tstr);
  if (tstr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse DN string"));
      goto fail;
    }

  if ((MultiByteToWideChar(CP_UTF8, 0, str, -1,
                           tstr, tstr_len)) == 0)

    {
      SSH_DEBUG(SSH_D_FAIL, ("Multibyte conversion failed"));
      goto fail;
    }

  if (!CertStrToNameW(X509_ASN_ENCODING,
                      tstr,
                      CERT_OID_NAME_STR  |
                      CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG,
                      NULL,
                      NULL,
                      &dn_len,
                      NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse DN string"));
      goto fail;
    }

  dn_buf = ssh_malloc(dn_len);
  if (dn_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate DN"));
      goto fail;
    }

  if (!CertStrToNameW(X509_ASN_ENCODING,
                      tstr,
                      CERT_OID_NAME_STR |
                      CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG,
                      NULL,
                      dn_buf,
                      &dn_len,
                      NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse DN string"));
      goto fail;
    }

  id = ssh_malloc(sizeof *id);
  if (id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate IKE ID"));
      goto fail;
    }

  id->id_type = SSH_IKEV2_ID_TYPE_ASN1_DN;
  id->id_data = dn_buf;
  id->id_data_size = dn_len;

  SSH_DEBUG(SSH_D_MIDOK, ("Returning distinguished name `%@'",
                          ssh_pm_ike_id_render, id));
  ssh_free(tstr);
  return id;

 fail:
  if (id)
    ssh_free(id);
  if (dn_buf)
    ssh_free(dn_buf);
  if (tstr)
    ssh_free(tstr);
  return NULL;
}

char *
ssh_pm_mscapi_dn_to_str(SshIkev2PayloadID id)
{
  CERT_NAME_BLOB name_blob;
  WCHAR *tstr_buf = NULL;
  char *str_buf = NULL;
  DWORD str_len = 0;
  DWORD tstr_len = 0;

  if (id->id_type != SSH_IKEV2_ID_TYPE_ASN1_DN)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse DN (wrong id type)"));
      goto fail;
    }

  name_blob.pbData = id->id_data;
  name_blob.cbData = id->id_data_size;

  if ((tstr_len =
       CertNameToStrW(X509_ASN_ENCODING,
                     &name_blob,
                     CERT_X500_NAME_STR,
                     NULL,
                     0)) <= 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse DN"));
      goto fail;
    }

  /* tstr_len includes the terminating NULL */
  tstr_buf = ssh_malloc(tstr_len * sizeof *tstr_buf);
  if (tstr_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate DN string"));
      goto fail;
    }

  if (CertNameToStrW(X509_ASN_ENCODING,
                     &name_blob,
                     CERT_X500_NAME_STR,
                     tstr_buf,
                     tstr_len) <= 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse DN"));
      goto fail;
    }
   str_len = WideCharToMultiByte(CP_UTF8, 0, (tstr_buf), -1, NULL,
                                 0, NULL, NULL);

   str_buf = ssh_malloc(str_len * sizeof *str_buf);
   if (str_buf == NULL)
     {
       goto fail;
     }

   WideCharToMultiByte(CP_UTF8, 0, (tstr_buf), -1, (str_buf),
                       (str_len), NULL, NULL);

  ssh_free(tstr_buf);
  return str_buf;

 fail:
  if (str_buf)
    ssh_free(str_buf);
  if (tstr_buf)
    ssh_free(tstr_buf);
  return NULL;
}

static SshCertificate
ssh_pm_mscapi_get_cert(HCERTSTORE store,
                       SshIkev2PayloadID id, SshCertificate prev)
{
  CERT_NAME_BLOB name_blob;
  CERT_NAME_BLOB hash_blob;
  PCCERT_CONTEXT cert = NULL;
  PCERT_EXTENSION altname_ext;
#define SSH_PM_MSCAPI_MAX_ALTNAME_INFO_SIZE 4096
  PCERT_ALT_NAME_INFO altname_info = NULL;
  DWORD altname_info_size = 0, i;
  wchar_t *altname_wstr = NULL;

  if (!store)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Certificate store not available"));
      goto fail;
    }

  if (id->id_type == SSH_IKEV2_ID_TYPE_ASN1_DN)
    {
      name_blob.pbData = id->id_data;
      name_blob.cbData = id->id_data_size;

      SSH_DEBUG(SSH_D_LOWSTART, ("Getting certificate by DN"));
      if (!(cert = CertFindCertificateInStore(store,
                                              X509_ASN_ENCODING,
                                              0,
                                              CERT_FIND_SUBJECT_NAME,
                                              &name_blob,
                                              prev)))
        {
          if (GetLastError() != CRYPT_E_NOT_FOUND)
            SSH_DEBUG(SSH_D_FAIL, ("Error searching certificate%s",
                                   ssh_pm_mscapi_last_error()));
        }
      if (prev)
        CertFreeCertificateContext(prev);
      if (cert)
        SSH_DEBUG(SSH_D_MIDOK, ("Returning certificate %p", (void *)cert));
      else
        SSH_DEBUG(SSH_D_MIDOK, ("Certificate not found"));
      return cert;
    }
  else if (id->id_type == SSH_IKEV2_ID_TYPE_KEY_ID)
    {
      hash_blob.pbData = id->id_data;
      hash_blob.cbData = id->id_data_size;

      SSH_DEBUG(SSH_D_LOWSTART, ("Getting certificate by key id"));
      if (!(cert = CertFindCertificateInStore(store,
                                              X509_ASN_ENCODING,
                                              0,
                                              CERT_FIND_KEY_IDENTIFIER,
                                              &hash_blob,
                                              prev)))
        {
          if (GetLastError() != CRYPT_E_NOT_FOUND)
            SSH_DEBUG(SSH_D_FAIL, ("Error searching certificate%s",
                                   ssh_pm_mscapi_last_error()));
        }
      if (prev)
        CertFreeCertificateContext(prev);
      if (cert)
        SSH_DEBUG(SSH_D_MIDOK, ("Returning certificate %p", (void *)cert));
      else
        SSH_DEBUG(SSH_D_MIDOK, ("Certificate not found"));
      return cert;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Doing sequential certificate search "
                                 "by subjectAltName"));
      if (id->id_type == SSH_IKEV2_ID_TYPE_FQDN ||
          id->id_type ==  SSH_IKEV2_ID_TYPE_RFC822_ADDR)
        {
          altname_wstr =
            ssh_malloc((id->id_data_size + 1) * sizeof altname_wstr[0]);
          if (altname_wstr == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate subjectAltName"));
              goto fail;
            }
          _snwprintf(altname_wstr, id->id_data_size, L"%hs", id->id_data);
          altname_wstr[id->id_data_size] = TEXT('\0');
        }

      altname_info = ssh_malloc(SSH_PM_MSCAPI_MAX_ALTNAME_INFO_SIZE);
      if (altname_info == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot alloc subjectAltName buffer"));
          goto fail;
        }

      cert = prev;
      prev = NULL;
      while ((cert = CertEnumCertificatesInStore(store, cert)))
        {
          if (!(altname_ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                                                cert->pCertInfo->cExtension,
                                                cert->pCertInfo->rgExtension)))
            continue;

          altname_info_size = SSH_PM_MSCAPI_MAX_ALTNAME_INFO_SIZE;
          if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                                   X509_ALTERNATE_NAME,
                                   altname_ext->Value.pbData,
                                   altname_ext->Value.cbData,
                                   0,
                                   NULL,
                                   altname_info,
                                   &altname_info_size))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot decode subjectAltName%s",
                                     ssh_pm_mscapi_last_error()));
              continue;
            }

          for (i = 0; i < altname_info->cAltEntry; i++)
            {
              PCERT_ALT_NAME_ENTRY entry = &altname_info->rgAltEntry[i];

              switch (entry->dwAltNameChoice)
                {
                case CERT_ALT_NAME_IP_ADDRESS:
                  if ((id->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR ||
                       id->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR) &&
                      id->id_data_size == entry->IPAddress.cbData &&
                      !memcmp(entry->IPAddress.pbData, id->id_data,
                              id->id_data_size))
                    goto out;
                  break;

                case CERT_ALT_NAME_DNS_NAME:
                  if (id->id_type == SSH_IKEV2_ID_TYPE_FQDN &&
                      !wcscmp(entry->pwszDNSName, altname_wstr))
                    goto out;
                  break;

                case CERT_ALT_NAME_RFC822_NAME:
                  if (id->id_type == SSH_IKEV2_ID_TYPE_RFC822_ADDR &&
                      !wcscmp(entry->pwszRfc822Name, altname_wstr))
                    goto out;
                  break;

                default:
                  break;
                }
            }
        out:
          if (i < altname_info->cAltEntry)
              break;
        }

      ssh_free(altname_info);
      altname_info = NULL;

      if (altname_wstr)
        ssh_free(altname_wstr);

      if (prev)
        CertFreeCertificateContext(prev);
      if (cert)
        SSH_DEBUG(SSH_D_MIDOK, ("Returning certificate %p", (void *)cert));
      else
        SSH_DEBUG(SSH_D_MIDOK, ("Certificate not found"));
      return cert;
    }

 fail:
  if (altname_info)
    ssh_free(altname_info);
  if (altname_wstr)
    ssh_free(altname_wstr);
  if (cert)
    CertFreeCertificateContext(cert);
  if (prev)
    CertFreeCertificateContext(prev);
  return NULL;
}

SshCertificate
ssh_pm_mscapi_get_trusted_cert(SshIkev2PayloadID id)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Searching for trusted certificate of `%@'",
                             ssh_pm_ike_id_render, id));

  if (!CertControlStore(root_store,
                        0,
                        CERT_STORE_CTRL_RESYNC,
                        NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to sync root certificate store%s",
                             ssh_pm_mscapi_last_error()));
    }

  return ssh_pm_mscapi_get_cert(root_store, id, NULL);
}

SshCertificate
ssh_pm_mscapi_get_local_cert(SshIkev2PayloadID id, SshCertificate prev)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Searching for local certificate of `%@'",
                             ssh_pm_ike_id_render, id));

  if (!CertControlStore(user_store,
                        0,
                        CERT_STORE_CTRL_RESYNC,
                        NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to sync user certificate store%s",
                             ssh_pm_mscapi_last_error()));
    }

  return ssh_pm_mscapi_get_cert(user_store, id, prev);
}

SshCertificate
ssh_pm_mscapi_get_remote_cert(SshIkev2PayloadID id, SshCertificate prev)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Searching for remote certificate of `%@'",
                             ssh_pm_ike_id_render, id));

  return ssh_pm_mscapi_get_cert(temp_store, id, prev);
}

SshCertificateChain
ssh_pm_mscapi_get_cert_chain(SshCertificate cert, SshUInt32 *ret_error)
{
  CERT_CHAIN_PARA chain_para;
  PCCERT_CHAIN_CONTEXT cert_chain;
  DWORD trust_error;

  SSH_DEBUG(SSH_D_MIDSTART, ("Getting certificate chain for certificate %p",
                             (void *)cert));

  memset(&chain_para, 0, sizeof chain_para);
  chain_para.cbSize = sizeof chain_para;

  if (!CertGetCertificateChain(NULL,
                               cert,
                               NULL,
                               cert->hCertStore,
                               &chain_para,
                               CERT_CHAIN_REVOCATION_CHECK_CHAIN,
                               NULL,
                               &cert_chain))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot build certificate chain%s",
                             ssh_pm_mscapi_last_error()));
      return NULL;
    }

  trust_error = cert_chain->rgpChain[0]->TrustStatus.dwErrorStatus;
  trust_error &= ~(CERT_TRUST_IS_NOT_TIME_NESTED |
                   CERT_TRUST_REVOCATION_STATUS_UNKNOWN);

  if (trust_error)
    {
      if ((trust_error & (CERT_TRUST_IS_PARTIAL_CHAIN |
                          CERT_TRUST_IS_UNTRUSTED_ROOT)))
        SSH_DEBUG(SSH_D_FAIL, ("No trusted CA for certificate"));
      else if ((trust_error & CERT_TRUST_IS_NOT_TIME_VALID))
        SSH_DEBUG(SSH_D_FAIL, ("Certificate or CA certificate expired"));
      else
        SSH_DEBUG(SSH_D_FAIL, ("Certificate chain is not valid"));

      /* Return the trust_error to the caller function for logging information,
         when certificates having any issue. */
      *ret_error = trust_error;

      CertFreeCertificateChain(cert_chain);
      return NULL;
    }


  SSH_DEBUG(SSH_D_MIDOK, ("Returning certificate chain %p for certificate %p",
                          (void *)cert_chain, (void *)cert));
  return cert_chain;
}

/* Proxy key context for public and private keys. */
typedef struct SshPmMsCapiKeyCtxRec
{
  HCRYPTPROV crypto_context;     /* MS crypto context aka key container */
  HCRYPTKEY key_handle;          /* MS key handle */
  ALG_ID key_algid;              /* Keypair algorithm */
} SshPmMsCapiKeyCtxStruct, *SshPmMsCapiKeyCtx;

/* Hash algorithms to try when verifying a signature. */
static ALG_ID ssh_pm_mscapi_hash_algids[] =
  {
    CALG_SHA1,
    CALG_MD5
  };
static const SshUInt32 ssh_pm_mscapi_hash_algids_num =
sizeof ssh_pm_mscapi_hash_algids / sizeof ssh_pm_mscapi_hash_algids[0];

/* Swap the byte order of an array. */
static void
ssh_pm_mscapi_swap_byte_order(unsigned char *s, size_t len)
{
  unsigned char t;
  size_t i;

  for (i = 0; i < len / 2; i ++)
    {
      t = s[i];
      s[i] = s[len -i - 1];
      s[len - i - 1] = t;
    }
}

/* Proxy public key operation callback. */
static SshOperationHandle
ssh_pm_mscapi_public_key_operation(SshProxyOperationId operation_id,
                                   SshProxyRGFId rgf_id,
                                   SshProxyKeyHandle handle,
                                   const unsigned char *input_data,
                                   size_t input_data_len,
                                   SshProxyReplyCB reply_cb,
                                   void *reply_context,
                                   void *context)
{
  SshPmMsCapiKeyCtx key_ctx = context;
  unsigned char *data, *signature;
  size_t data_len, signature_len;
  ALG_ID hash_algid;
  HCRYPTHASH hash_handle = 0;
  DWORD verify_flags = 0;
  Boolean okay = FALSE, no_hash = FALSE;
  SshUInt32 i;

  /* Decode the input buffer to obtain the data and the signature. */
  if (ssh_decode_array(input_data, input_data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&data, &data_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&signature,&signature_len),
                       SSH_FORMAT_END) != input_data_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot decode input data"));
      goto finish;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Data:"), data, data_len);
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Signature:"),
                    signature, signature_len);

  /* Convert signature into little-endian format. RSA signature is one
     number, DSA signature is the concatenation of two equal-length
     numbers. */
  if (operation_id == SSH_RSA_PUB_VERIFY)
    {
      ssh_pm_mscapi_swap_byte_order(signature, signature_len);
    }
  else
    {
      ssh_pm_mscapi_swap_byte_order(signature, signature_len / 2);
      ssh_pm_mscapi_swap_byte_order(signature + signature_len / 2,
                                    signature_len / 2);
    }

  /* Check algorithm. */
  switch (operation_id)
    {
    case SSH_DSA_PUB_VERIFY:
      switch (key_ctx->key_algid)
        {
        case CALG_DSS_SIGN:
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Verifying DSA signature with public key %p",
                     (void *)key_ctx));
          break;
        default:
          SSH_DEBUG(SSH_D_FAIL, ("Public key is not a DSA key"));
          goto finish;
        }
      break;
    case SSH_RSA_PUB_VERIFY:
      switch (key_ctx->key_algid)
        {
        case CALG_RSA_SIGN:
        case CALG_RSA_KEYX:
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Verifying RSA signature with public key %p",
                     (void *)key_ctx));
          break;
        default:
          SSH_DEBUG(SSH_D_FAIL, ("Public key is not an RSA key"));
          goto finish;
        }
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported public key operation %d",
                             (int)operation_id));
      goto finish;
    }

  /* Determine hash algorithm to use. */
  switch (rgf_id)
    {
    case SSH_DSA_NIST_SHA1:
    case SSH_RSA_PKCS1_SHA1:
    case SSH_DSA_MD5:
    case SSH_RSA_PKCS1_MD5:
      /* Can't rely on these. The real algorithm is encoded in the
         encrypted DigestInfo which we cannot decrypt so we will have
         to try both hashes. */
      hash_algid = 0;
      break;
    case SSH_RSA_PKCS1_NONE:
      verify_flags |= CRYPT_NOHASHOID;
      /* fall through to next case */
    case SSH_DSA_NONE_NONE:
      no_hash = TRUE;
      if (data_len == 16)
        {
          hash_algid = CALG_MD5;
        }
      else if (data_len == 20)
        {
          hash_algid = CALG_SHA1;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid digest length for RGF id %d",
                                 (int)rgf_id));
          goto finish;
        }
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported RGF id %d", (int)rgf_id));
      goto finish;
    }

  /* If the input data is already in the form of a hash then verify
     it. */
  if (no_hash)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Verifying given hash with alg id %d",
                                 (int)hash_algid));
      if (!CryptCreateHash(key_ctx->crypto_context,
                           hash_algid,
                           0, 0,
                           &hash_handle))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot create hash%s",
                                 ssh_pm_mscapi_last_error()));
          goto finish;
        }
      if (!CryptSetHashParam(hash_handle,
                             HP_HASHVAL,
                             data,
                             0))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot set hash value%s",
                                 ssh_pm_mscapi_last_error()));
          goto finish;
        }
      if (!CryptVerifySignature(hash_handle,
                                signature,
                                signature_len,
                                key_ctx->key_handle,
                                NULL,
                                verify_flags))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Signature verification failed"));
          goto finish;
        }
    }
  else
    {
      /* Input data is the message itself, not a hash. Unfortunately
         we cannot decrypt the signature with MS CAPI to obtain the
         hash algorithm from there. Instead try all hash
         algorithms. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Hashing and verifying data"));
      for (i = 0; i < ssh_pm_mscapi_hash_algids_num; i++)
        {
          hash_algid = ssh_pm_mscapi_hash_algids[i];

          SSH_DEBUG(SSH_D_LOWSTART, ("Trying hash alg id %d",(int)hash_algid));

          /* Destroy hash created during previous iteration. */
          if (hash_handle)
            {
              CryptDestroyHash(hash_handle);
              hash_handle = 0;
            }

          /* Create a hash object associated with the crypto context
             of the key. */
          if (!CryptCreateHash(key_ctx->crypto_context,
                               hash_algid,
                               0, 0,
                               &hash_handle))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot create hash%s",
                                     ssh_pm_mscapi_last_error()));
              goto finish;
            }

          /* Calculate hash value. */
          if (!CryptHashData(hash_handle, data, data_len, 0))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot update hash%s",
                                     ssh_pm_mscapi_last_error()));
              goto finish;
            }

          /* Compute signature and quit loop if it matches. */
          if (CryptVerifySignature(hash_handle,
                                   signature,
                                   signature_len,
                                   key_ctx->key_handle,
                                   NULL,
                                   0))
            break;

          /* Fail on other failure than signature mismatch. */
          if (GetLastError() != NTE_BAD_SIGNATURE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot verify signature%s",
                                     ssh_pm_mscapi_last_error()));
              goto finish;
            }
        }

      /* Check if we succeeded in verifying the signature or not. */
      if (i >= ssh_pm_mscapi_hash_algids_num)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Signature verification failed"));
          goto finish;
        }
    }

  /* All ok. */
  SSH_DEBUG(SSH_D_MIDOK, ("Signature verification succeeded"));
  okay = TRUE;

 finish:
  if (okay)
    (*reply_cb)(SSH_CRYPTO_OK, NULL, 0, reply_context);
  else
    (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);

  if (hash_handle)
    CryptDestroyHash(hash_handle);

  return NULL;
}

/* Proxy public key free callback. */
static void
ssh_pm_mscapi_public_key_free(void *context)
{
  SshPmMsCapiKeyCtx key_ctx = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Freeing public key %p", (void *)key_ctx));
  CryptDestroyKey(key_ctx->key_handle);
  CryptReleaseContext(key_ctx->crypto_context, 0);
  ssh_free(key_ctx);
}

SshPublicKey
ssh_pm_mscapi_get_public_key(SshCertificate cert)
{
  PCERT_PUBLIC_KEY_INFO key_info;
  HCRYPTPROV crypto_context = 0;
  HCRYPTKEY key_handle = 0;
  ALG_ID key_algid;
  DWORD key_size, key_size_size;
  SshProxyKeyTypeId key_type;
  SshPmMsCapiKeyCtx key_ctx = NULL;
  SshPublicKey public_key = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("Getting public key of certificate %p",
                             (void *)cert));

  key_info = &cert->pCertInfo->SubjectPublicKeyInfo;

  /* Check key algorithm object id and set algorithm id and proxy key
     type accordingly. */
  if (!strcmp(key_info->Algorithm.pszObjId, szOID_X957_DSA))
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Key is a DSA key"));
      key_algid = CALG_DSS_SIGN;
      key_type = SSH_PROXY_DSA;
    }
  else if (!strcmp(key_info->Algorithm.pszObjId, szOID_RSA_RSA))
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Key is an RSA key"));
      key_algid = CALG_RSA_SIGN;
      key_type = SSH_PROXY_RSA;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported public key algorithm object id `%s'",
                 key_info->Algorithm.pszObjId));

      ssh_log_event(SSH_LOGFACILITY_AUTH,
                    SSH_LOG_INFORMATIONAL,
                    "Unsupported algorithm");
      goto fail;
    }

  /* Get unnamed crypto context (key container) for the key. */
  if (!CryptAcquireContext(&crypto_context,
                           NULL,
                           NULL,
                           key_algid == CALG_RSA_SIGN ?
                           PROV_RSA_FULL : PROV_DSS_DH,
                           CRYPT_VERIFYCONTEXT))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get crypto context for public key"));
      goto fail;
    }

  /* Import the key from the cert into the CSP and get handle to it as
     well as its parameters. */
  key_size_size = sizeof key_size;
  if (!CryptImportPublicKeyInfoEx(crypto_context,
                                  X509_ASN_ENCODING,
                                  key_info,
                                  key_algid,
                                  0,
                                  NULL,
                                  &key_handle) ||
      !CryptGetKeyParam(key_handle,
                        KP_KEYLEN,
                        (PBYTE)&key_size,
                        &key_size_size,
                        0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get public key for certificate%s",
                             ssh_pm_mscapi_last_error()));
      goto fail;
    }

  /* Allocate proxy key context. */
  key_ctx = ssh_calloc(1, sizeof *key_ctx);
  if (key_ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate proxy key context"));
      goto fail;
    }

  key_ctx->crypto_context = crypto_context;
  key_ctx->key_handle = key_handle;
  key_ctx->key_algid = key_algid;

  /* Register the proxy key. */
  if (!(public_key =
        ssh_public_key_create_proxy(key_type,
                                    key_size,
                                    ssh_pm_mscapi_public_key_operation,
                                    ssh_pm_mscapi_public_key_free,
                                    key_ctx)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot create proxy public key"));
      goto fail;
    }

  /* Select a valid scheme to make the key work. The scheme is not
     actually used for anything useful later. */
  if (ssh_public_key_select_scheme(public_key,
                                   SSH_PKF_SIGN,
                                   key_algid == CALG_RSA_SIGN ?
                                   "rsa-pkcs1-sha1" : "dsa-nist-sha1",
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot select public key scheme"));
      goto fail;
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("Returning public key %p (%p) for certificate %p",
                             (void *)key_ctx, (void *)public_key,
                             (void *)cert));
  return public_key;

fail:
  if (key_ctx)
    ssh_free(key_ctx);
  if (key_handle)
    CryptDestroyKey(key_handle);
  if (crypto_context)
    CryptReleaseContext(crypto_context, 0);
  return NULL;
}

/* Proxy private key operation callback. */
static SshOperationHandle
ssh_pm_mscapi_private_key_operation(SshProxyOperationId operation_id,
                                    SshProxyRGFId rgf_id,
                                    SshProxyKeyHandle handle,
                                    const unsigned char *input_data,
                                    size_t input_data_len,
                                    SshProxyReplyCB reply_cb,
                                    void *reply_context,
                                    void *context)
{
  SshPmMsCapiKeyCtx key_ctx = context;
  ALG_ID hash_algid;
  DWORD key_spec;
  HCRYPTHASH hash_handle = 0;
  PBYTE output_data = NULL;
  DWORD output_data_len, sign_flags = 0;
  Boolean okay = FALSE, no_hash = FALSE;

  /* Check algorithm and set key spec to be used with CryptSignHash()
     accordingly. */
  switch (operation_id)
    {
    case SSH_DSA_PRV_SIGN:
      switch (key_ctx->key_algid)
        {
        case CALG_DSS_SIGN:
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Creating DSA signature with private key %p",
                     (void *)key_ctx));
          key_spec = AT_SIGNATURE;
          break;
        default:
          SSH_DEBUG(SSH_D_FAIL, ("Private key is not a DSA key"));
          goto finish;
        }
      break;
    case SSH_RSA_PRV_SIGN:
      switch (key_ctx->key_algid)
        {
        case CALG_RSA_SIGN:
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Creating RSA signature with private key %p",
                     (void *)key_ctx));
          key_spec = AT_SIGNATURE;
          break;
        case CALG_RSA_KEYX:
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Creating RSA signature with private key %p",
                     (void *)key_ctx));
          key_spec = AT_KEYEXCHANGE;
          break;
        default:
          SSH_DEBUG(SSH_D_FAIL, ("Private key is not an RSA key"));
          goto finish;
        }
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported private key operation %d",
                             (int)operation_id));
      goto finish;
    }

  /* Determine hash algorithm to use. */
  switch (rgf_id)
    {
    case SSH_DSA_NIST_SHA1:
    case SSH_RSA_PKCS1_SHA1:
      hash_algid = CALG_SHA1;
      break;
    case SSH_DSA_MD5:
    case SSH_RSA_PKCS1_MD5:
      hash_algid = CALG_MD5;
      break;
    case SSH_RSA_PKCS1_NONE:
      sign_flags |= CRYPT_NOHASHOID;
      /* fall through to next case */
    case SSH_DSA_NONE_NONE:
      no_hash = TRUE;
      if (input_data_len == 16)
        {
          hash_algid = CALG_MD5;
        }
      else if (input_data_len == 20)
        {
          hash_algid = CALG_SHA1;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid digest length for RGF id %d",
                                 (int)rgf_id));
          goto finish;
        }
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported RGF id %d", (int)rgf_id));
      goto finish;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Using hash alg id %d", (int)hash_algid));

  /* Create a hash object associated with the crypto context of the
     key. */
  if (!CryptCreateHash(key_ctx->crypto_context,
                       hash_algid,
                       0, 0,
                       &hash_handle))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot create hash%s",
                             ssh_pm_mscapi_last_error()));
      goto finish;
    }

  if (no_hash)
    {
      /* Use input data as the hash value. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Signing given hash"));
      if (!CryptSetHashParam(hash_handle,
                             HP_HASHVAL,
                             input_data,
                             0))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot set hash value%s",
                                 ssh_pm_mscapi_last_error()));
          goto finish;
        }
    }
  else
    {
      /* Calculate hash value. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Hashing and signing data"));
      if (!CryptHashData(hash_handle, input_data, input_data_len, 0))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot update hash%s",
                                 ssh_pm_mscapi_last_error()));
          goto finish;
        }
    }

  /* Generate signature. */
  output_data_len = 0;
  if (!CryptSignHash(hash_handle,
                     key_spec,
                     NULL,
                     sign_flags,
                     NULL,
                     &output_data_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot sign hash%s",
                             ssh_pm_mscapi_last_error()));
      goto finish;
    }

  output_data = ssh_malloc(output_data_len);
  if (output_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate signature"));
      goto finish;
    }

  if (!CryptSignHash(hash_handle,
                     key_spec,
                     NULL,
                     sign_flags,
                     output_data,
                     &output_data_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot sign hash%s",
                             ssh_pm_mscapi_last_error()));
      goto finish;
    }

  /* Convert signature into little-endian format. RSA signature is one
     number, DSA signature is the concatenation of two equal-length
     numbers. */
  if (operation_id == SSH_RSA_PRV_SIGN)
    {
      ssh_pm_mscapi_swap_byte_order(output_data, output_data_len);
    }
  else
    {
      ssh_pm_mscapi_swap_byte_order(output_data, output_data_len / 2);
      ssh_pm_mscapi_swap_byte_order(output_data + output_data_len / 2,
                                    output_data_len / 2);
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Created signature"));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Data:"),
                    input_data, input_data_len);
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Signature:"),
                    output_data, output_data_len);
  okay = TRUE;

 finish:
  if (okay)
    (*reply_cb)(SSH_CRYPTO_OK, (unsigned char *)output_data,
                (size_t)output_data_len, reply_context);
  else
    (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);

  if (output_data)
    ssh_free(output_data);
  if (hash_handle)
    CryptDestroyHash(hash_handle);

  return NULL;
}

/* Proxy private key free callback. */
static void
ssh_pm_mscapi_private_key_free(void *context)
{
  SshPmMsCapiKeyCtx key_ctx = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Freeing private key %p", (void *)key_ctx));
  CryptDestroyKey(key_ctx->key_handle);
  CryptReleaseContext(key_ctx->crypto_context, 0);
  ssh_free(key_ctx);
}

SshPrivateKey
ssh_pm_mscapi_get_private_key(SshCertificate cert)
{
  HCRYPTPROV crypto_context = 0;
  HCRYPTKEY key_handle = 0;
  ALG_ID key_algid;
  DWORD key_spec = 0, key_size, key_size_size, key_algid_size;
  BOOL caller_free_prov;
  SshProxyKeyTypeId key_type;
  SshPmMsCapiKeyCtx key_ctx = NULL;
  SshPrivateKey private_key = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("Getting private key of certificate %p",
                             (void *)cert));

  /* Get private key context, handle and parameters. */
  key_size_size = sizeof key_size;
  key_algid_size = sizeof key_algid;
  if (!CryptAcquireCertificatePrivateKey(cert,
                                         0,
                                         NULL,
                                         &crypto_context,
                                         &key_spec,
                                         &caller_free_prov) ||
      !CryptGetUserKey(crypto_context,
                       key_spec,
                       &key_handle) ||
      !CryptGetKeyParam(key_handle,
                        KP_KEYLEN,
                        (PBYTE)&key_size,
                        &key_size_size,
                        0) ||
      !CryptGetKeyParam(key_handle,
                        KP_ALGID,
                        (PBYTE)&key_algid,
                        &key_algid_size,
                        0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get private key for certificate%s",
                             ssh_pm_mscapi_last_error()));
      goto fail;
    }

  /* Check algorithm and set proxy key type accordingly. We have to
     allow signing with both signature and key exchange keys because
     private keys associated with certificates may be imported either
     way. */
  switch (key_algid)
    {
    case CALG_DSS_SIGN:
      SSH_DEBUG(SSH_D_LOWSTART, ("Key is a DSA key"));
      key_type = SSH_PROXY_DSA;
      break;
    case CALG_RSA_SIGN:
    case CALG_RSA_KEYX:
      SSH_DEBUG(SSH_D_LOWSTART, ("Key is an RSA key"));
      key_type = SSH_PROXY_RSA;
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Private key is not an RSA or DSA key"));
      goto fail;
    }

  /* Allocate proxy key context. */
  key_ctx = ssh_calloc(1, sizeof *key_ctx);
  if (key_ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate proxy key context"));
      goto fail;
    }

  key_ctx->crypto_context = crypto_context;
  key_ctx->key_handle = key_handle;
  key_ctx->key_algid = key_algid;

  /* Register the proxy key. */
  if (!(private_key =
        ssh_private_key_create_proxy(key_type,
                                     key_size,
                                     ssh_pm_mscapi_private_key_operation,
                                     ssh_pm_mscapi_private_key_free,
                                     key_ctx)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot create proxy private key"));
      goto fail;
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("Returning private key %p (%p) for "
                             "certificate %p", (void *)key_ctx,
                             (void *)private_key, (void *)cert));
  return private_key;

fail:
  if (key_ctx)
    ssh_free(key_ctx);
  if (key_handle)
    CryptDestroyKey(key_handle);
  if (crypto_context)
    CryptReleaseContext(crypto_context, 0);
  return NULL;
}

Boolean
ssh_pm_mscapi_get_altname(SshCertificate cert, SshPmIdentityType type,
                          unsigned char **buf, size_t *len)
{
  PBYTE name_buf = NULL;
  DWORD name_len = 0;
  PCERT_EXTENSION altname_ext;
#define SSH_PM_MSCAPI_MAX_ALTNAME_INFO_SIZE 4096
  PCERT_ALT_NAME_INFO altname_info = NULL;
  DWORD altname_info_size = 0, i;

  SSH_DEBUG(SSH_D_MIDSTART, ("Getting subject name of certificate %p",
                             (void *)cert));


  altname_info = ssh_malloc(SSH_PM_MSCAPI_MAX_ALTNAME_INFO_SIZE);
  if (altname_info == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot alloc subjectAltName buffer"));
      return FALSE;
    }

  if (!(altname_ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                                        cert->pCertInfo->cExtension,
                                        cert->pCertInfo->rgExtension)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot retrieve subjectAltNames"));
      ssh_free(altname_info);
      return FALSE;
    }

  altname_info_size = SSH_PM_MSCAPI_MAX_ALTNAME_INFO_SIZE;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           X509_ALTERNATE_NAME,
                           altname_ext->Value.pbData,
                           altname_ext->Value.cbData,
                           0,
                           NULL,
                           altname_info,
                           &altname_info_size))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot decode subjectAltName%s",
                             ssh_pm_mscapi_last_error()));
      ssh_free(altname_info);
      return FALSE;
    }

  for (i = 0; i < altname_info->cAltEntry; i++)
    {
      PCERT_ALT_NAME_ENTRY entry = &altname_info->rgAltEntry[i];

      if (entry->dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS &&
          type == SSH_PM_IDENTITY_IP)
        {
          name_len = entry->IPAddress.cbData;
          name_buf = ssh_malloc(name_len);
          if (name_buf == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate subject "
                                     "alternative name"));
              ssh_free(altname_info);
              return FALSE;
            }

          memcpy(name_buf, entry->IPAddress.pbData, name_len);
          break;
        }
      if (entry->dwAltNameChoice == CERT_ALT_NAME_DNS_NAME &&
          type == SSH_PM_IDENTITY_FQDN)
        {
          name_len =
            (wcslen(entry->pwszDNSName) + 1) * (sizeof(*entry->pwszDNSName));

          name_buf = ssh_malloc(name_len);
          if (name_buf == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate subject "
                                     "alternative name"));
              ssh_free(altname_info);
              return FALSE;
            }
          WideCharToMultiByte(CP_ACP, 0, (entry->pwszDNSName), -1, (name_buf),
                              (name_len), NULL, NULL);
        break;
        }

      if (entry->dwAltNameChoice == CERT_ALT_NAME_RFC822_NAME &&
          type == SSH_PM_IDENTITY_RFC822)
        {
          name_len =
            (wcslen(entry->pwszRfc822Name) + 1) *
            (sizeof(*entry->pwszRfc822Name));
          name_buf = ssh_malloc(name_len);
          if (name_buf == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate certificate subject "
                                     "alternative name"));
              ssh_free(altname_info);
              return FALSE;
            }
          WideCharToMultiByte(CP_ACP, 0, (entry->pwszRfc822Name), -1,
                              (name_buf), (name_len), NULL, NULL);
          break;
        }
    }

  *len = name_len;
  if (*len > 0)
    {
      *buf = name_buf;
      ssh_free(altname_info);
      return TRUE;
    }

  ssh_free(altname_info);
  return FALSE;
}

void
ssh_pm_mscapi_free_cert(SshCertificate cert)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Freeing certificate %p", (void *)cert));
  CertFreeCertificateContext(cert);
}

void
ssh_pm_mscapi_free_cert_chain(SshCertificateChain cert_chain)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Freeing certificate chain %p",
                             (void *)cert_chain));
  CertFreeCertificateChain(cert_chain);
}

Boolean
ssh_pm_mscapi_compare_ca(SshPm pm, SshPmCa ca1, SshPmCa ca2)
{
  if (ca1->flags != ca2->flags)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("CA flags do not match"));
      return FALSE;
    }

  if (ca1->cert_subject_dn_len != ca2->cert_subject_dn_len
      || memcmp(ca1->cert_subject_dn, ca2->cert_subject_dn,
                ca1->cert_subject_dn_len) != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("CA subject names do not match"));
      return FALSE;
    }

  if (ca1->cert_issuer_dn_len != ca2->cert_issuer_dn_len
      || memcmp(ca1->cert_issuer_dn, ca2->cert_issuer_dn,
                ca1->cert_issuer_dn_len) != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("CA issuer names do not match"));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("CAs match"));
  return TRUE;
}

#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
