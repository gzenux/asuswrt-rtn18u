/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This library implements that basic external database interface. This
   interface can be used to add new databases to the certificate
   manager.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "sshurl.h"
#include "sshencode.h"
#include "sshadt.h"
#include "sshadt_map.h"
#include "sshbase64.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertEdb"

typedef struct SshEdbNegaCacheNodeRec
{
  SshADTMapHeaderStruct adt_header;

  /* The time when valid again. */
  SshBerTimeStruct valid;

  unsigned int tag;
  unsigned char *name;
  size_t name_len;
} *SshEdbNegaCacheNode, SshEdbNegaCacheNodeStruct;

struct SshEdbNegaCacheRec
{
  /* The node information. */
  unsigned int tag_count;
  unsigned int object_count;
  unsigned int max_object_count;

  /* The secs information. */
  unsigned int invalid_secs;

  /* We have ADT here as well */
  SshADTContainer map;
};

static SshUInt32
cm_nc_object_hash(const void *object, void *context)
{
  SshEdbNegaCacheNode n = (SshEdbNegaCacheNode) object;
  SshUInt32 h = n->tag, i;

  for (i = 0; i < n->name_len; i++)
    h = n->name[i] ^ ((h << 7) | (h >> 26));

  return h;
}

static int
cm_nc_object_compare(const void *object1, const void *object2,
                     void *context)
{
  SshEdbNegaCacheNode n1 = (SshEdbNegaCacheNode) object1;
  SshEdbNegaCacheNode n2 = (SshEdbNegaCacheNode) object2;

  if (n1->tag == n2->tag)
    {
      if (n1->name_len == n2->name_len)
        return memcmp(n1->name, n2->name, n1->name_len);
      else if (n1->name_len < n2->name_len)
        return -1;
      else
        return 1;
    }
  else if (n1->tag < n2->tag)
    return -1;
  else
    return 1;
}

static void
cm_nc_object_destroy(void *object, void *context)
{
  SshEdbNegaCacheNode n = (SshEdbNegaCacheNode) object;

  ssh_free(n->name);
  ssh_free(n);
}

SshEdbNegaCache
ssh_edb_nega_cache_allocate(unsigned int max_objects,
                            unsigned int max_tag_numbers,
                            unsigned int invalid_secs)
{
  SshEdbNegaCache nc = ssh_malloc(sizeof(*nc));

  if (nc)
    {
      /* Check the input values. */
      if (max_objects < 64)
        max_objects = 64;
      if (max_objects > 1024)
        max_objects = 1024;

      /* Initialize. */
      nc->object_count = 0;
      nc->tag_count    = max_tag_numbers;
      nc->max_object_count = max_objects;
      nc->invalid_secs = invalid_secs;

      if ((nc->map =
           ssh_adt_create_generic(SSH_ADT_MAP,
                                  SSH_ADT_HASH,    cm_nc_object_hash,
                                  SSH_ADT_COMPARE, cm_nc_object_compare,
                                  SSH_ADT_DESTROY, cm_nc_object_destroy,
                                  SSH_ADT_HEADER,
                                  SSH_ADT_OFFSET_OF(SshEdbNegaCacheNodeStruct,
                                                    adt_header),
                                  SSH_ADT_ARGS_END)) == NULL)
        {
          ssh_free(nc);
          nc = NULL;
        }
    }
  return nc;
}

/* Free the NegaCache here. */
void ssh_edb_nega_cache_free(SshEdbNegaCache nc)
{
  /* Check for trivial NULL pointer. */
  if (nc == NULL)
    return;

  ssh_adt_destroy(nc->map);
  ssh_free(nc);
}

void ssh_edb_nega_cache_add(SshEdbNegaCache nc,
                            unsigned int tag,
                            unsigned char *name,
                            size_t name_length,
                            SshBerTime current_time)
{
  SshEdbNegaCacheNode node;

  if (tag > nc->tag_count)
    return;

  /* If out of memory, or for every 32'nd object we'll cleanup
     old and expired objects. */
  if (nc->object_count > nc->max_object_count ||
      nc->object_count % 32 == 0)
    {
      SshADTHandle handle, next;
      for (handle = ssh_adt_enumerate_start(nc->map);
           handle != SSH_ADT_INVALID;
           handle = next)
        {
          next = ssh_adt_enumerate_next(nc->map, handle);
          node = ssh_adt_get(nc->map, handle);
          if (ssh_ber_time_cmp(&node->valid, current_time) < 0)
            {
              ssh_adt_delete(nc->map, handle);
              nc->object_count -= 1;
              SSH_DEBUG(SSH_D_LOWOK,
                        ("NC: cleanup; %d nodes left", nc->object_count));
            }
        }
    }

  if (nc->object_count > nc->max_object_count)
    return;

  if ((node = ssh_calloc(1, sizeof(*node))) == NULL)
    return;

  if ((node->name = ssh_memdup(name, name_length)) == NULL)
    {
      ssh_free(node);
      return;
    }

  nc->object_count += 1;

  node->tag = tag;
  node->name_len = name_length;
  ssh_ber_time_set(&node->valid, current_time);
  ssh_ber_time_add_secs(&node->valid, nc->invalid_secs);

  SSH_DEBUG(SSH_D_LOWOK,
            ("NC: insert; %d nodes in the cache", nc->object_count));

  ssh_adt_insert(nc->map, node);
}

Boolean ssh_edb_nega_cache_check(SshEdbNegaCache nc,
                                 unsigned int tag,
                                 unsigned char *name,
                                 size_t name_length,
                                 SshBerTime current_time)
{
   /* First compute the hash. */
  SshEdbNegaCacheNodeStruct node, *found;
  SshADTHandle handle;
  Boolean rv = FALSE;

  /* Check the tag for valid range. */
  if (tag < nc->tag_count)
    {
      node.tag = tag;
      node.name_len = name_length;
      node.name = name;

      if ((handle = ssh_adt_get_handle_to_equal(nc->map, &node))
          != SSH_ADT_INVALID)
        {
          found = ssh_adt_get(nc->map, handle);

          if (ssh_ber_time_cmp(&found->valid, current_time) <= 0)
            rv = FALSE;
          else
            rv = TRUE;
        }
    }
  SSH_DEBUG(SSH_D_LOWOK,
            ("NC: check; %d nodes in the cache -> %d", nc->object_count, rv));
  return rv;
}

Boolean ssh_cm_edb_init(SshCMDatabases *dbs)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("EDB: Initializing databases."));

  /* Allocate an empty database list. */
  dbs->dbs             = ssh_glist_allocate();

  if (dbs->dbs == NULL)
    return FALSE;

  /* Generate default local network. */
  dbs->local_net.socks = NULL;
  dbs->local_net.proxy = NULL;
  dbs->local_net.timeout_msecs = 1000;

#ifdef SSHDIST_VALIDATOR_OCSP
  if (!ssh_cm_ocsp_init(&dbs->ocsp))
    {
      ssh_glist_free(dbs->dbs);
      return FALSE;
    }

#endif /* SSHDIST_VALIDATOR_OCSP */
  return TRUE;
}
void ssh_cm_edb_free(SshCMDatabases *dbs)
{
  SshGListNode node;

  SSH_DEBUG(SSH_D_HIGHSTART, ("EDB: Freeing databases."));

  for (node = dbs->dbs->head; node; node = node->next)
    {
      SshCMSearchDatabase *db = node->data;

      /* Free the database. */
      if (db->functions->free)
        (*db->functions->free)(db);

      /* Free the database entry. */
      ssh_free(db);
    }
  ssh_glist_free(dbs->dbs);

  /* Free the local network information. */
  ssh_free(dbs->local_net.socks);
  ssh_free(dbs->local_net.proxy);
  dbs->local_net.timeout_msecs = 0;

#ifdef SSHDIST_VALIDATOR_OCSP
  ssh_cm_ocsp_free(&dbs->ocsp);
#endif /* SSHDIST_VALIDATOR_OCSP */
}

void ssh_cm_edb_stop(SshCMDatabases *dbs)
{
  SshGListNode node;

  SSH_DEBUG(SSH_D_HIGHSTART, ("EDB: Stopping databases."));

  for (node = dbs->dbs->head; node; node = node->next)
    {
      SshCMSearchDatabase *db = node->data;

      if (db->functions->stop)
        (*db->functions->stop)(db);
    }
#ifdef SSHDIST_VALIDATOR_OCSP
  ssh_cm_ocsp_stop(&dbs->ocsp);
#endif /* SSHDIST_VALIDATOR_OCSP */
}

SshCMDBDistinguisher *
ssh_cm_edb_distinguisher_allocate(SshCMDataType data_type,
                                  SshCMKeyType key_type,
                                  unsigned char *key_data,
                                  size_t key_len)
{
  SshCMDBDistinguisher *distinguisher;

  if ((distinguisher = ssh_calloc(1, sizeof(*distinguisher))) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EDB: Can't allocate query distinguisher."));
      return NULL;
    }

  distinguisher->key = ssh_memdup(key_data, key_len);
  if (distinguisher->key == NULL)
    {
      ssh_free(distinguisher);
      SSH_DEBUG(SSH_D_FAIL,
                ("EDB: Can't allocate key for query distinguisher."));
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("EDB: Allocating query distinguisher."));

  distinguisher->data_type  = data_type;
  distinguisher->key_type   = key_type;
  distinguisher->key_length = key_len;
  distinguisher->server_url = NULL;
  distinguisher->password   = NULL;
  distinguisher->reference_count = 0;
  distinguisher->direct_access_id = -1;
  return distinguisher;
}

void ssh_cm_edb_distinguisher_free(SshCMDBDistinguisher *distinguisher)
{

  if (distinguisher->reference_count)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("EDB: Dereferencing query distinguisher %p to ref %d",
                 distinguisher, distinguisher->reference_count - 1));
      distinguisher->reference_count--;
      return;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("EDB: Freeing query distinguisher %p",
                             distinguisher));

  ssh_free(distinguisher->key);
  ssh_free(distinguisher->server_url);
  ssh_free(distinguisher->password);
  ssh_free(distinguisher);
}

void ssh_cm_edb_distinguisher_lock(SshCMDBDistinguisher *distinguisher)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("EDB: Taking refence to query distinguisher %p to ref %d",
             distinguisher, distinguisher->reference_count + 1));
  distinguisher->reference_count++;
}

Boolean
ssh_cm_edb_distinguisher_hash(SshCMDBDistinguisher *db_distinguisher,
                              const char *db_identifier,
                              unsigned char *ret_digest,
                              size_t ret_digest_len)
{
  SshHash hash;
  unsigned char  digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t         key_digest_length;
  unsigned char  tag_str[4];

  /* Compute a hash of all the data. */

  if (ssh_hash_allocate(SSH_CM_HASH_ALGORITHM, &hash) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Can't allocate distinguished hash %s",
                              SSH_CM_HASH_ALGORITHM));
      return FALSE;
    }

  /* Compute the hash of the details. */
  ssh_hash_reset(hash);
  if (db_distinguisher)
    {
      ssh_hash_update(hash,
                      db_distinguisher->key, db_distinguisher->key_length);
      /* Convert the tag into char string. */
      SSH_PUT_32BIT(tag_str, db_distinguisher->data_type);
      ssh_hash_update(hash, tag_str, 4);
    }
  ssh_hash_update(hash, (unsigned char *)db_identifier, strlen(db_identifier));
  ssh_hash_final(hash, digest);

  /* Copy the digest. */
  key_digest_length = ssh_hash_digest_length(ssh_hash_name(hash));

  /* Free the hash algorithm. */
  ssh_hash_free(hash);

  /* Copy to the output. */
  if (key_digest_length < ret_digest_len)
    {
      memset(ret_digest, 0, ret_digest_len);
      memcpy(ret_digest, digest, key_digest_length);
    }
  else
    memcpy(ret_digest, digest, ret_digest_len);

  return TRUE;
}


SshCMLocalNetwork ssh_cm_edb_get_local_network(SshCMContext cm)
{
  return &cm->edb.local_net;
}

void ssh_cm_edb_set_local_network(SshCMContext cm,
                                  SshCMLocalNetwork local_net)
{
  SshCMLocalNetwork net = &cm->edb.local_net;

  /* Free the old stuff. */
  ssh_free(net->socks);
  ssh_free(net->proxy);
  /* Copy the given information. */
  if (local_net->socks)
    net->socks = ssh_strdup(local_net->socks);
  else
    net->socks = NULL;
  if (local_net->proxy)
    net->proxy = ssh_strdup(local_net->proxy);
  else
    net->proxy = NULL;
  if (local_net->timeout_msecs)
    net->timeout_msecs = local_net->timeout_msecs;
}

/* This function returns the database by given database identifier. */
SshCMSearchDatabase *ssh_cm_edb_lookup_database(SshCMContext cm,
                                                const char *db_identifier)
{
  SshGListNode         node;

  /* Check all the databases. */
  for (node = cm->edb.dbs->head; node; node = node->next)
    {
      SshCMSearchDatabase *tmp_db = node->data;
      if (strcmp(tmp_db->functions->db_identifier, db_identifier) == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("EDB/DblookUp: Found database %s", db_identifier));
          return tmp_db;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("EDB/DblookUp: Unknown database %s", db_identifier));
  return NULL;
}

/* Add a new database for the certificate manager. This should usually
   be done before anything else. However, certainly the operation
   is valid at runtime. */
Boolean ssh_cm_edb_add_database(SshCMContext cm,
                                const SshCMSearchFunctionsStruct *db_functions,
                                void *context)
{
  SshGListNode         node;
  SshCMSearchDatabase *db;

  /* Check if there already exist the same database. */
  if (ssh_cm_edb_lookup_database(cm, db_functions->db_identifier))
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB: Adding database: %s: already exists.",
                 db_functions->db_identifier));
      return FALSE;
    }


  /* Allocate a database entry. */
  if ((db = ssh_calloc(1, sizeof(*db))) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("EDB: Adding database: %s: no space.",
                 db_functions->db_identifier));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("EDB: Adding database: %s", db_functions->db_identifier));

  /* Fill in the blanks. */
  db->functions = db_functions;
  db->context   = context;

  /* Add to the list of all supported search methods. */
  if ((node = ssh_glist_allocate_n(cm->edb.dbs)) != NULL)
    {
      node->data = db;
      ssh_glist_add_n(node, NULL, SSH_GLIST_TAIL);
      return TRUE;
    }
  else
    {
      ssh_free(db);
      return FALSE;
    }
}

/* This function removes all the databases that can be identified by
   the given database identifier. */
Boolean ssh_cm_edb_remove_database(SshCMContext cm,
                                   const char *db_identifier)
{
  SshGListNode         node, next;
  SshCMSearchDatabase *db;
  Boolean removed = FALSE;

  for (node = cm->edb.dbs->head; node; node = next)
    {
      SshCMSearchDatabase *tmp_db = node->data;
      next = node->next;

      if (strcmp(tmp_db->functions->db_identifier, db_identifier) == 0)
        {
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("EDB: Removing database: %s", db_identifier));

          /* Remove node. */
          ssh_glist_remove_n(node);
          /* Take the database information. */
          db = node->data;
          /* Free the node. */
          ssh_glist_free_n(node);

          /* Now acknowledge the database code of this operation. */
          (*db->functions->free)(db);

          /* Free the database entry. */
          ssh_free(db);

          /* Note! Current searches cannot be terminated. They will
             run until eventloop terminates. This is unfortunate, but
             can hardly be avoided. */
          removed = TRUE;
        }
    }

  return removed;
}


/* The functions that do the searching. */

void ssh_cm_edb_ban_add(SshCMContext cm,
                        SshCMDBDistinguisher *db_distinguisher,
                        const char *db_identifier)
{
  unsigned char  digest[SSH_CM_HASH_LENGTH];
  SshBerTimeStruct     current_time;

  /* Compute a hash value of the distinguisher. */
  if (ssh_cm_edb_distinguisher_hash(db_distinguisher,
                                    db_identifier,
                                    digest, SSH_CM_HASH_LENGTH))
    {
      ssh_ber_time_set_from_unix_time(&current_time,
                                      (*cm->config->time_func)
                                      (cm->config->time_context));

      /* Add to the negacache. */
      ssh_edb_nega_cache_add(cm->negacache,
                             db_distinguisher ?
                             db_distinguisher->data_type :
                             SSH_CM_DATA_TYPE_CRL,
                             digest,
                             SSH_CM_HASH_LENGTH,
                             &current_time);
      SSH_DEBUG(SSH_D_MIDOK,
                ("EDB: Adding ban to some distinguisher at database: %s",
                 db_identifier));
    }
}

void ssh_cm_edb_ban_add_ctx(void *ctx,
                            SshCMDBDistinguisher *dg,
                            const char *db_identifier)
{
  SshCMSearchContext *context = ctx;
  ssh_cm_edb_ban_add(context->cm, dg, db_identifier);
}

Boolean ssh_cm_edb_ban_check(SshCMContext cm,
                             SshCMDBDistinguisher *db_distinguisher,
                             const char *db_identifier)
{
  unsigned char  digest[SSH_CM_HASH_LENGTH];
  SshBerTimeStruct     current_time;

  /* Compute a hash value of the distinguisher. */
  if (ssh_cm_edb_distinguisher_hash(db_distinguisher,
                                    db_identifier,
                                    digest, SSH_CM_HASH_LENGTH))
    {
      /* Generate current time. */
      ssh_ber_time_set_from_unix_time(&current_time,
                                      (*cm->config->time_func)
                                      (cm->config->time_context));

      /* Check the negacache. */
      return ssh_edb_nega_cache_check(cm->negacache,
                                      db_distinguisher ?
                                      db_distinguisher->data_type :
                                      SSH_CM_DATA_TYPE_CRL,
                                      digest,
                                      SSH_CM_HASH_LENGTH,
                                      &current_time);
    }
  return FALSE;
}

/* Reply function. */

void ssh_cm_edb_move_to_first(SshCMContext cm, SshCMSearchDatabase *db)
{
  SshGListNode node, node_next;
  for (node = cm->edb.dbs->head; node; node = node_next)
    {
      node_next = node->next;
      if (node->data == (void *)db)
        {
          /* Move to head. */
          ssh_glist_add_n(node, NULL, SSH_GLIST_HEAD);
          break;
        }
    }
}

static Boolean cm_edb_reply_pem_to_binary(const unsigned char *pem_data,
                                          size_t pem_data_length,
                                          unsigned char **bin_data,
                                          size_t *bin_data_length)
{
  size_t base64_start;
  size_t base64_end;
  unsigned char *clean;
  size_t clean_len;
  unsigned char *ber;
  size_t ber_len;

  *bin_data = NULL;
  *bin_data_length = 0;

  /* Remove extra headers. */
  if (!ssh_base64_remove_headers(pem_data, pem_data_length, &base64_start,
                                 &base64_end))
    {
      return FALSE;
    }

  /* Remove whitespace. */
  clean = ssh_base64_remove_whitespace(pem_data + base64_start,
                                       base64_end - base64_start);
  if (clean == NULL)
    {
      /* Out of memory. */
      return FALSE;
    }

  /* Check if it is base64 encoded. */
  clean_len = strlen((char *)clean);
  if (ssh_is_base64_buf(clean, clean_len) != clean_len)
    {
      /* Not base64. */
      ssh_free(clean);
      return FALSE;
    }

  /* Decode base64. */
  ber = ssh_base64_to_buf(clean, &ber_len);
  if (ber == NULL)
    {
      /* Out of memory. */
      ssh_free(clean);
      return FALSE;
    }

  /* We do not need the cleaned base64 blob anymore. */
  ssh_free(clean);

  /* Return the result. */
  *bin_data = ber;
  *bin_data_length = ber_len;

  return TRUE;
}


static Boolean
cm_edb_reply_add_certificate(SshCMContext cm,
                             const unsigned char *cert, size_t cert_len,
                             const char *dbi,
                             SshCMDBDistinguisher *dg)
{
  SshCMCertificate cm_cert;
  SshCertDBKey *list = NULL;
  SshCMStatus status;

  SSH_DEBUG(SSH_D_LOWOK, ("Attempting to add EDB reply certificate"));

  cm_cert = ssh_cm_cert_allocate(cm);
  if (cm_cert == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate CM certificate"));
      goto error;
    }

  if (ssh_cm_cert_set_ber(cm_cert, cert, cert_len) != SSH_CM_STATUS_OK)
    {
      unsigned char *bin;
      size_t bin_len;

      SSH_DEBUG(SSH_D_LOWOK, ("Attempting to base64 decode input data"));
      if (cm_edb_reply_pem_to_binary(cert, cert_len, &bin, &bin_len) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to base64 decode input data"));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Input data: length %d", (int) cert_len),
                            cert, cert_len);
          goto error;
        }

      if (ssh_cm_cert_set_ber(cm_cert, bin, bin_len) != SSH_CM_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to decode certificate"));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Decoded input data: length %d", (int) bin_len),
                            bin, bin_len);
          ssh_free(bin);
          goto error;
        }

      ssh_free(bin);
    }

  ssh_certdb_key_push(&list, dg->key_type, ssh_memdup(dg->key, dg->key_length),
                      dg->key_length, FALSE);

  status = ssh_cm_add_with_bindings(cm_cert, list);
  if (status == SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB: Adding cert from %s to cache.", dbi));
      return TRUE;
    }
  else if (status == SSH_CM_STATUS_ALREADY_EXISTS)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB: Cert from %s already in the cache.", dbi));
      ssh_cm_cert_free(cm_cert);
      return TRUE;
    }

 error:
  SSH_DEBUG(SSH_D_FAIL, ("EDB: Cert from %s not cached", dbi));
  if (cm_cert != NULL)
    ssh_cm_cert_free(cm_cert);
  return FALSE;
}


static Boolean
cm_edb_reply_add_crl(SshCMContext cm,
                     const unsigned char *crl, size_t crl_len,
                     const char *dbi,
                     SshCMDBDistinguisher *dg)
{
  SshCMCrl cm_crl;
  SshCertDBKey *list = NULL;
  SshCMStatus status;

  SSH_DEBUG(SSH_D_LOWOK, ("Attempting to add EDB reply CRL"));

  cm_crl = ssh_cm_crl_allocate(cm);
  if (cm_crl == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate CM crl"));
      goto error;
    }

  if (ssh_cm_crl_set_ber(cm_crl, crl, crl_len) != SSH_CM_STATUS_OK)
    {
      unsigned char *bin;
      size_t bin_len;

      SSH_DEBUG(SSH_D_LOWOK, ("Attempting to base64 decode input data"));
      if (cm_edb_reply_pem_to_binary(crl, crl_len, &bin, &bin_len) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to base64 decode input data"));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Input data: length %d", (int) crl_len),
                            crl, crl_len);
          goto error;
        }

      if (ssh_cm_crl_set_ber(cm_crl, bin, bin_len) != SSH_CM_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to decode crl"));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Decoded input data: length %d", (int) bin_len),
                            bin, bin_len);
          ssh_free(bin);
          goto error;
        }

      ssh_free(bin);
    }

  ssh_certdb_key_push(&list, dg->key_type, ssh_memdup(dg->key, dg->key_length),
                      dg->key_length, TRUE);

  status = ssh_cm_add_crl_with_bindings(cm_crl, list);
  if (status == SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB: Adding CRL from %s to cache.", dbi));
      return TRUE;
    }
  else if (status == SSH_CM_STATUS_ALREADY_EXISTS)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB: CRL from %s already in the cache.", dbi));
      ssh_cm_crl_free(cm_crl);
      return TRUE;
    }

 error:
  if (cm_crl != NULL)
    ssh_cm_crl_free(cm_crl);
  return FALSE;
}

static Boolean
cm_edb_reply_add_bundle(SshCMContext cm,
                        const unsigned char *data, size_t data_length,
                        const char *dbi,
                        SshCMDBDistinguisher *dg)
{
  SshAsn1Context asn1;
  SshAsn1Node cp, node, list;
  unsigned char *cert;
  size_t cert_len;
  int which;
  Boolean success = FALSE;

  SSH_DEBUG(SSH_D_LOWOK, ("Attempting to add EDB reply bundle"));

  /* No success as vanilla certificate, now try certificate
     pair and certificate bundle, in this order. */
  asn1 = ssh_asn1_init();
  if (asn1 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate ASN1 context"));
      goto out;
    }

  if (ssh_asn1_decode_node(asn1, data, data_length, &cp) != SSH_ASN1_STATUS_OK)
    {
      unsigned char *bin;
      size_t bin_len;

      ssh_asn1_free(asn1);
      asn1 = NULL;

      SSH_DEBUG(SSH_D_LOWOK, ("Attempting to base64 decode input data"));
      if (cm_edb_reply_pem_to_binary(data, data_length, &bin, &bin_len)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to base64 decode input data"));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Input data: length %d", (int) data_length),
                            data, data_length);
          goto out;
        }

      asn1 = ssh_asn1_init();
      if (asn1 == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate ASN1 context"));
          ssh_free(bin);
          goto out;
        }

      if (ssh_asn1_decode_node(asn1, bin, bin_len, &cp) != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ASN1 decode failed"));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Decoded input data: length %d", (int) bin_len),
                            bin, bin_len);
          ssh_free(bin);
          goto out;
        }

      ssh_free(bin);
    }

  /* The following is somewhat peculiar due to format for
     certbundle and crosspair. Crosspair elements are
     (sequence (any (e 0))) or (sequence (any (e 1))) for
     the forward and reverse. Certificate bundles are
     (sequence (choice (any (e 0)) (any (e 1)))) where 0
     stands for cert, and 1 for crl. Here traverse whole
     list and first try 1 as cert, and if that fails,
     fallback to crl. */
  if (ssh_asn1_read_node(asn1, cp, "(sequence () (any ()))", &list)
      == SSH_ASN1_STATUS_OK)
    {
      while (list != NULL)
        {
          if (ssh_asn1_read_node(asn1, list,
                                 "(choice (any (e 0)) (any (e 1)))",
                                 &which, &node, &node)
              == SSH_ASN1_STATUS_OK)
            {
              ssh_asn1_node_get_data(node, &cert, &cert_len);

              if (which == 0)
                {
                  success = cm_edb_reply_add_certificate(cm,
                                                         cert, cert_len,
                                                         dbi, dg);
                }
              else if (which == 1)
                {
                  success = cm_edb_reply_add_certificate(cm,
                                                         cert, cert_len,
                                                         dbi, dg);
                  if (success == FALSE)
                    success = cm_edb_reply_add_crl(cm,
                                                   cert, cert_len,
                                                   dbi, dg);
                }
              ssh_free(cert);
            }

          list = ssh_asn1_node_next(list);
        }
    }

 out:
  if (asn1 != NULL)
    ssh_asn1_free(asn1);

  if (success == FALSE)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("EDB: Can not decode certificate, cross certificate pair or "
                 "certificate bundle from %s.", dbi));
      return FALSE;
    }

  return TRUE;
}

static Boolean
cm_edb_reply_add_pkcs7(SshCMContext cm,
                       const unsigned char *data, size_t data_length,
                       const char *dbi,
                       SshCMDBDistinguisher *dg)
{
  SshPkcs7 pkcs7 = NULL;
  SshPkcs7Status pkcs7_status;
  SshUInt32 num_items, i;
  unsigned char **bers = NULL;
  size_t *ber_lens = NULL;
  unsigned char *bin = NULL;
  size_t bin_len = 0;
  Boolean success = FALSE;

  SSH_DEBUG(SSH_D_LOWOK, ("Attempting to add EDB reply PKCS#7"));

  if (cm_edb_reply_pem_to_binary(data, data_length, &bin, &bin_len))
    {
      /* Assume PEM-encoding */
      pkcs7_status = ssh_pkcs7_decode(bin, bin_len, &pkcs7);
      ssh_free(bin);
    }
  else
    {
      /* Assume binary-encoding */
      pkcs7_status = ssh_pkcs7_decode(data, data_length, &pkcs7);
    }

  if (pkcs7_status == SSH_PKCS7_OK)
    {
      num_items = ssh_pkcs7_get_certificates(pkcs7, &bers, &ber_lens);

      SSH_DEBUG(SSH_D_LOWOK,
                ("Found %u certificates from PKCS#7 bundle",
                 (unsigned int) num_items));

      for (i = 0; i < num_items; i++)
        {
          success = cm_edb_reply_add_certificate(cm,
                                                 bers[i], ber_lens[i],
                                                 dbi, dg);
        }

      ssh_free(bers);
      ssh_free(ber_lens);

      bers = NULL;
      ber_lens = NULL;

      num_items = ssh_pkcs7_get_crls(pkcs7, &bers, &ber_lens);

      SSH_DEBUG(SSH_D_LOWOK,
                ("Found %u CRLs from PKCS#7 bundle",
                 (unsigned int) num_items));

      for (i = 0; i < num_items; i++)
        {
          success = cm_edb_reply_add_crl(cm,
                                         bers[i], ber_lens[i],
                                         dbi, dg);
        }

      ssh_free(bers);
      ssh_free(ber_lens);

    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Bundle not PKCS#7-encoded, error code: %u",
                 (unsigned int) pkcs7_status));
    }

  if (pkcs7 != NULL)
    ssh_pkcs7_free(pkcs7);

  return success;
}

void ssh_cm_edb_reply(SshCMSearchDatabase *db,
                      void *ctx,
                      SshCMDBDistinguisher *dg,
                      const unsigned char *data, size_t data_length)
{
  SshCMSearchContext *context = ctx;
  const char *dbi = db->functions->db_identifier;

  if (dg->direct_access_id != -1)
    {
      if (context->end_cert->access[dg->direct_access_id].pending)
        {
          context->end_cert->access[dg->direct_access_id].done = 1;
          context->end_cert->access[dg->direct_access_id].pending = 0;
        }
    }

  /* Check if waiting for anything. */
  if (context->waiting == 0)
    SSH_NOTREACHED;

  if (data == NULL || data_length == 0)
    return;

  /* Handle the data, e.g. throw it into cache. */
  switch (dg->data_type)
    {
    case SSH_CM_DATA_TYPE_CERTIFICATE:
      /* Try to add it as plain certificate */
      if (cm_edb_reply_add_certificate(context->cm, data, data_length, dbi, dg)
          == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Added EDB reply certificate"));
          ssh_cm_edb_move_to_first(context->cm, db);
          break;
        }

      /* Try adding as a certificate bundle/crosspair. */
      if (cm_edb_reply_add_bundle(context->cm, data, data_length, dbi, dg)
          == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Added EDB reply bundle"));
          break;
        }

      /* Try pkcs7 bundle */
      if (cm_edb_reply_add_pkcs7(context->cm, data, data_length, dbi, dg)
          == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Added EDB reply PKCS#7 bundle"));
          break;
        }

      /* Failed to decode reply */
      ssh_cm_error_set(context,
                       SSH_CM_SSTATE_CERT_DECODE_FAILED,
                       SSH_CM_ERROR_CERT_DECODE_FAILED,
                       NULL,
                       NULL);
      break;

    case SSH_CM_DATA_TYPE_CRL:
      if (cm_edb_reply_add_crl(context->cm, data, data_length, dbi, dg)
          == TRUE)
        {
          ssh_cm_edb_move_to_first(context->cm, db);
        }
      else
        {
          ssh_cm_error_set(context,
                           SSH_CM_SSTATE_CRL_DECODE_FAILED,
                           SSH_CM_ERROR_CRL_DECODE_FAILED,
                           NULL,
                           NULL);
        }
      break;

    default:
      SSH_NOTREACHED;
      break;
    }
}

/* Result function. */

void ssh_cm_edb_result(SshCMSearchDatabase *database,
                       SshCMDBStatus        db_status,
                       void *ctx,
                       SshCMDBDistinguisher *dg)
{
  SshCMSearchContext *context = ctx;
  SshCMContext cm = context->cm;

  SSH_ASSERT(context->waiting != 0);

  if (context->waiting)
    context->waiting--;

  if (dg->direct_access_id != -1)
    {
      context->end_cert->access[dg->direct_access_id].done = 1;
      context->end_cert->access[dg->direct_access_id].pending = 0;
    }

  switch (db_status)
    {
    case SSH_CMDB_STATUS_OK:
      break;
    case SSH_CMDB_STATUS_TIMEOUT:
      ssh_cm_error_set(context,
                       SSH_CM_SSTATE_DB_METHOD_TIMEOUT,
                       SSH_CM_ERROR_EDB_METHOD_TIMEOUT,
                       NULL,
                       NULL);
      break;
    case SSH_CMDB_STATUS_DISCONNECTED:
      ssh_cm_error_set(context,
                       SSH_CM_SSTATE_DB_METHOD_TIMEOUT,
                       SSH_CM_ERROR_EDB_METHOD_DISCONNECTED,
                       NULL,
                       NULL);
      break;
    case SSH_CMDB_STATUS_FAILED:
      ssh_cm_error_set(context,
                       SSH_CM_SSTATE_DB_METHOD_FAILED,
                       SSH_CM_ERROR_EDB_METHOD_FAILED,
                       NULL,
                       NULL);
      break;
    default:
      SSH_NOTREACHED;
      break;
    }

  /* Set up a timeout for the CMi. */
  SSH_DEBUG(SSH_D_LOWOK, ("EDB: Search will continue from timeout."));
  if (!cm->control_timeout_active)
    {
      cm->control_timeout_active = TRUE;
      ssh_register_timeout(&cm->control_timeout,
                           cm->config->timeout_seconds,
                           cm->config->timeout_microseconds,
                           ssh_cm_timeout_control, cm);
    }
  /* Free the distinguisher. */
  ssh_cm_edb_distinguisher_free(dg);
}

void ssh_cm_edb_mark_search_init_start(SshCMSearchDatabase *database,
                                       void                *ctx,
                                       SshCMDBDistinguisher *dg)
{
  SshCMSearchContext *context = ctx;

  /* Lock the distinguisher. */
  ssh_cm_edb_distinguisher_lock(dg);

  /* Make the context waiting (for one search). */
  context->waiting++;
}

void ssh_cm_edb_mark_search_init_end(SshCMSearchDatabase  *database,
                                     void                 *ctx,
                                     SshCMDBDistinguisher *dg,
                                     Boolean              finished)
{
  SshCMSearchContext *context = ctx;

  /* Check if the waiting is now over. */
  if (finished && context->waiting != 0)
    {
      /* Unlock the distinguisher. */
      ssh_cm_edb_distinguisher_free(dg);

      /* Unlock the context. */
      context->waiting--;
    }

  if (finished == FALSE && context->waiting == 0)
    SSH_NOTREACHED;
}

/* General search function from external databases. */
static SshCMEdbStatus
cm_edb_search_any(SshCMSearchContext *context,
                  SshCMDBDistinguisher *db_distinguisher,
                  SshCMSearchFunctionClass sclass)
{
  SshGListNode node;
  SshCMContext cm = context->cm;
  SshCMSearchMode mode;
  Boolean searching = FALSE;
  int numdbs = 0;
  SshCMSearchDatabase *db = NULL;
#ifdef DEBUG_LIGHT
  const char *dbi = NULL;
#endif /* DEBUG_LIGHT */

  for (node = context->cm->edb.dbs->head; node; node = node->next)
    {
      db = node->data;
      if (db == NULL || db->functions == NULL ||
          db->functions->type != sclass)
        continue;
      numdbs++;
    }

  if (numdbs == 0)
    return SSH_CMEDB_NOT_FOUND;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Looking from %s databases: %@",
             sclass == SSH_CM_SCLASS_LOCAL ? "local": "external",
             ssh_cm_edb_distinguisher_render, db_distinguisher));

  /* Try searching. */
  for (node = context->cm->edb.dbs->head; node; node = node->next)
    {
      db = node->data;

      /* Only search from given database class. */
      if (db == NULL || db->functions == NULL ||
          db->functions->type != sclass)
        continue;

#ifdef DEBUG_LIGHT
      dbi = db->functions->db_identifier;
#endif /* DEBUG_LIGHT */

      /* Run the search. */
      mode = (*db->functions->search)(db, cm, context, db_distinguisher);
      switch (mode)
        {
        case SSH_CM_SMODE_SEARCH:
          /* Search launched, hence we'd better return to the caller. */
          SSH_DEBUG(SSH_D_HIGHOK, ("%s [running].", dbi));
          return SSH_CMEDB_SEARCHING;

        case SSH_CM_SMODE_DONE:
          /* Performed the search already. No waiting necessary. */
          SSH_DEBUG(SSH_D_HIGHOK, ("%s [finished].", dbi));
          return SSH_CMEDB_OK;

        case SSH_CM_SMODE_DELAYED:
          /* Either uncertain that can retrieve result quickly, or for
             some other reason wants to continue with another
             searching method for support. */
          SSH_DEBUG(SSH_D_HIGHOK, ("%s [delayed].", dbi));
          searching = TRUE;
          break;

        case SSH_CM_SMODE_FAILED:
          /* Failed to find anything. */
          SSH_DEBUG(SSH_D_HIGHOK, ("%s [failed].", dbi));
          break;

        default:
          SSH_NOTREACHED;
          break;
        }
    }

  if (searching)
    return SSH_CMEDB_DELAYED;

  /* Finished ok. */
  return SSH_CMEDB_NOT_FOUND;
}

/* Main function that launches internal searches. */

SshCMEdbStatus
ssh_cm_edb_search_local(SshCMSearchContext *context,
                        SshCMDBDistinguisher *db_distinguisher)
{
  return cm_edb_search_any(context, db_distinguisher,SSH_CM_SCLASS_LOCAL);
}

SshCMEdbStatus
ssh_cm_edb_search(SshCMSearchContext *context,
                  SshCMDBDistinguisher *db_distinguisher)
{
  return cm_edb_search_any(context, db_distinguisher,SSH_CM_SCLASS_SERVER);
}


/* Operation routines. */
unsigned char *ssh_cm_edb_operation_name(SshCMDBDistinguisher *dg,
                                         const char *db_identifier,
                                         size_t *name_length)
{
  unsigned char *buf;

  *name_length =
    ssh_encode_array_alloc(&buf,
                           SSH_ENCODE_UINT32_STR(dg->key, dg->key_length),
                           SSH_ENCODE_UINT32(dg->data_type),
                           SSH_ENCODE_UINT32_STR(ssh_custr(db_identifier),
                                                 strlen(db_identifier)),
                           SSH_FORMAT_END);

  return buf;
}

Boolean ssh_cm_edb_operation_check(void *ctx,
                                   SshCMDBDistinguisher *dg,
                                   const char *db_identifier)
{
  SshCMSearchContext *context = ctx;
  SshCMContext cm = context->cm;
  unsigned char *name;
  size_t         name_length;
  Boolean rv;

  name = ssh_cm_edb_operation_name(dg, db_identifier, &name_length);
  rv   = ssh_cm_map_check(cm->op_map, name, name_length);
  ssh_free(name);

  return rv;
}

typedef struct
{
  void *context;
  Boolean replied;
  SshCMDBDistinguisher *dg;
  SshCMSearchDatabase  *db;
  const char *db_identifier;
  void *search_data;
  SshCMEdbSearchCB search_cb;
  Boolean freed;
} SshCMEdbSearchCtx;

SshCMMapState ssh_cm_edb_operation_invoke(SshCMMap map,
                                          void *msg,
                                          void *context,
                                          void *ob_context)
{
  SshCMDBStatus status = (SshCMDBStatus)msg;
  SshCMEdbSearchCtx *search = context;

  ssh_cm_edb_result(search->db, status, ob_context, search->dg);
  search->replied = TRUE;
  return SSH_CM_MAP_STATE_FREE;
}

void ssh_cm_edb_operation_free_op(SshCMMap map,
                                  void *context,
                                  void *ob_context)
{
  SshCMEdbSearchCtx *search = context;

  /* Check if we are about to be freed anyway. */
  if (search->freed)
    return;

  search->freed = TRUE;

  if (search->search_cb)
    (*search->search_cb)(ob_context, search->search_data);
  else
    SSH_NOTREACHED;

  /* Do the reply here if not done yet. */
  if (!search->replied)
    {
      SSH_ASSERT(search->dg->reference_count >= 1);

      /* The only possibility is timeout, namely the search did not
         receive answer in due time. Observe that this generates
         most likely a chain reaction that will terminate all the
         searches for this object (as it should). */
      ssh_cm_edb_result(search->db, SSH_CMDB_STATUS_TIMEOUT, ob_context,
                        search->dg);
      search->replied = TRUE;
    }

  ssh_cm_edb_distinguisher_free(search->dg);
  ssh_free(search);
}

SshCMMapState ssh_cm_edb_operation_state(SshCMMap map,
                                         void    *context,
                                         void    *ob_context)
{
  SshCMEdbSearchCtx *search = context;

  return search->replied ? SSH_CM_MAP_STATE_FREE : SSH_CM_MAP_STATE_KEEP;
}

void ssh_cm_edb_operation_free_ob(SshCMMap map,
                                  void *ob_context)
{
  SshCMSearchContext *ctx = ob_context;
  ctx->edb_op_locator = 0;
}

Boolean
ssh_cm_edb_operation_link(void *ctx,
                          SshCMDBDistinguisher *dg,
                          SshCMSearchDatabase  *db,
                          const char *db_identifier,
                          SshCMEdbSearchCB      free_ctx_cb,
                          void *search_context)
{
  SshCMSearchContext *context = ctx;
  SshCMContext cm = context->cm;
  SshCMEdbSearchCtx *search;
  unsigned char *name;
  size_t name_length;

  if ((search = ssh_calloc(1, sizeof(*search))) != NULL)
    {
      search->context = ctx;
      search->dg      = dg;
      ssh_cm_edb_distinguisher_lock(dg);

      search->db      = db;
      search->db_identifier = db_identifier;
      search->search_data = search_context;
      search->search_cb   = free_ctx_cb;

      /* linking steals the name */
      name = ssh_cm_edb_operation_name(dg, db_identifier, &name_length);
      if (!ssh_cm_map_link_op(cm->op_map,
                              name, name_length,
                              cm->config->op_delay_msecs,
                              context->edb_op_locator,
                              search))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Cannot link a search."));
          return FALSE;
        }
      else
        return TRUE;
    }
  else
    return FALSE;
}

void ssh_cm_edb_operation_msg(void *ctx,
                              SshCMDBDistinguisher *dg,
                              const char  *db_identifier,
                              SshCMDBStatus status)
{
  SshCMSearchContext *context = ctx;
  SshCMContext cm = context->cm;
  unsigned char *name;
  size_t name_length;

  name = ssh_cm_edb_operation_name(dg, db_identifier, &name_length);
  ssh_cm_map_invoke(cm->op_map, name, name_length, (void *)status);
  ssh_free(name);
}

const SshCMMapOp ssh_cm_edb_operation_table =
{
  ssh_cm_edb_operation_state,
  ssh_cm_edb_operation_invoke,
  ssh_cm_edb_operation_free_ob,
  ssh_cm_edb_operation_free_op
};

void ssh_cm_edb_operation_add_ob(SshCMContext cm,
                                 SshCMSearchContext *context)
{
  context->edb_op_locator = ssh_cm_map_add_ob(cm->op_map,
                                              &ssh_cm_edb_operation_table,
                                              context);
}

Boolean ssh_cm_edb_operation_remove_ob(SshCMContext cm,
                                       SshCMSearchContext *context)
{
  Boolean rv;

  if (context->edb_op_locator == 0)
    return TRUE;

  rv = ssh_cm_map_remove_ob(cm->op_map,
                            context->edb_op_locator);
  context->edb_op_locator = 0;
  return rv;
}

void ssh_cm_edb_operation_add(SshCMContext cm,
                              SshCMSearchContext *context)
{
  ssh_cm_edb_operation_add_ob(cm, context);
#ifdef SSHDIST_VALIDATOR_OCSP
  ssh_cm_ocsp_operation_add_ob(cm, context);
#endif /* SSHDIST_VALIDATOR_OCSP */
}

Boolean ssh_cm_edb_operation_remove(SshCMContext cm,
                                    SshCMSearchContext *context)
{
  Boolean rv;

  rv =
    ssh_cm_edb_operation_remove_ob(cm, context)
#ifdef SSHDIST_VALIDATOR_OCSP
    && ssh_cm_ocsp_operation_remove_ob(cm, context)
#endif /* SSHDIST_VALIDATOR_OCSP */
    ;

  return rv ? TRUE : FALSE;
}


/* cmi-edb.c */
#endif /* SSHDIST_CERT */
