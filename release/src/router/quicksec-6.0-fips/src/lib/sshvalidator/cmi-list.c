/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Validator result list management.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMi"

/************ CM Cert DB List handling ***********/

/* Following functions do not contain debugging information due they
   are use probably a lot and would dump useless information to the
   application (I might be wrong of course). It is also possible that
   the certificate database system could dump out information so this
   would not serve many purposes anyway. */

Boolean ssh_cm_cert_list_empty(SshCMCertList list)
{
  return ssh_certdb_entry_list_empty(list);
}

SshCMCertificate ssh_cm_cert_list_first(SshCMCertList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_first(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CERTIFICATE)
    ssh_fatal("ssh_cm_cert_list_first: failure, non-certificate found.");
  return entry->context;
}

SshCMCertificate ssh_cm_cert_list_current(SshCMCertList list)
{
  if (list == NULL || list->current == NULL)
    return NULL;
  return list->current->entry->context;
}

SshCMCertificate ssh_cm_cert_list_last(SshCMCertList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_last(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CERTIFICATE)
    ssh_fatal("ssh_cm_cert_list_last: failure, non-certificate found.");
  return entry->context;
}

SshCMCertificate ssh_cm_cert_list_next(SshCMCertList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_next(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CERTIFICATE)
    ssh_fatal("ssh_cm_cert_list_last: failure, non-certificate found.");
  return entry->context;
}

SshCMCertificate ssh_cm_cert_list_prev(SshCMCertList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_prev(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CERTIFICATE)
    ssh_fatal("ssh_cm_cert_list_last: failure, non-certificate found.");
  return entry->context;
}

void ssh_cm_cert_list_free(SshCMContext cm, SshCMCertList list)
{
  ssh_certdb_entry_list_free_all(cm->db, list);
}

Boolean ssh_cm_crl_list_empty(SshCMCrlList list)
{
  return ssh_certdb_entry_list_empty(list);
}

SshCMCrl ssh_cm_crl_list_first(SshCMCrlList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_first(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CRL)
    ssh_fatal("ssh_cm_crl_list_first: failure, non-certificate found.");
  return entry->context;
}

SshCMCrl ssh_cm_crl_list_current(SshCMCrlList list)
{
  if (list == NULL || list->current == NULL)
    return NULL;
  return list->current->entry->context;
}

SshCMCrl ssh_cm_crl_list_last(SshCMCrlList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_last(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CRL)
    ssh_fatal("ssh_cm_crl_list_last: failure, non-certificate found.");
  return entry->context;
}

SshCMCrl ssh_cm_crl_list_next(SshCMCrlList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_next(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CRL)
    ssh_fatal("ssh_cm_crl_list_last: failure, non-certificate found.");
  return entry->context;
}

SshCMCrl ssh_cm_crl_list_prev(SshCMCrlList list)
{
  SshCertDBEntry *entry;

  entry = ssh_certdb_entry_list_prev(list);
  if (entry == NULL)
    return NULL;

  if (entry->tag != SSH_CM_DATA_TYPE_CRL)
    ssh_fatal("ssh_cm_crl_list_last: failure, non-certificate found.");
  return entry->context;
}

void ssh_cm_crl_list_free(SshCMContext cm, SshCMCrlList list)
{
  ssh_certdb_entry_list_free_all(cm->db, list);
}
#endif /* SSHDIST_CERT */
