/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate database and memory cache. Used through cmi interface.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cert-db.h"
#include "cmi-internal.h"
#include "sshadt.h"
#include "sshadt_map.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertDB"

struct SshCertDBRec
{
  /* LRU list containing all entries in memory. */
  SshCertDBEntry *lru_head, *lru_tail;

  /* List of all entries in database. */
  SshCertDBEntry **entries;
  int num_entry_classes;

  /* Free list for entries. */
  SshCertDBEntry *free_list;

  /* Hash tables storing actual objects for and names for quick
     access. */
  SshADTContainer name_mapping;
  SshADTContainer id_mapping;

  /* Callbacks to transform the information between memory and disk
     representation. */
  SshCertDBLinearizeObject linearize_object;
  SshCertDBDelinearizeObject delinearize_object;
  SshCertDBFreeObject free_object;

  /* Next unallocated entry id. */
  unsigned int next_unallocated_entry;

  /* Configuration parameters. */
  unsigned int memory_limit;
  unsigned int entry_limit;
  unsigned int default_memlock;

  /* Statistics. */
  unsigned int num_entries;
  unsigned int memory_usage;

  unsigned int num_free;
  unsigned int num_lru;
  unsigned int num_locked;
  unsigned int num_timelocked;

  SshCMNotifyEvents notify;
  void *notify_context;
};

#define SSH_CERTDB_ENTRY_TAKE_REF(__entry)                           \
do                                                                   \
  {                                                                  \
    ++((__entry)->reference_count);                                  \
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Taking ref to entry %p to %d",     \
                                 (__entry),                          \
                                 ((__entry)->reference_count)));     \
  } while (0)

#define SSH_CERTDB_ENTRY_REMOVE_REF(__entry)                       \
do                                                                 \
  {                                                                \
    SSH_ASSERT((__entry)->reference_count > 0);                    \
    --((__entry)->reference_count);                                \
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing ref to entry %p to %d",  \
                                 (__entry),                        \
                                 ((__entry)->reference_count)));   \
  } while (0)

typedef enum
{
  SSH_CERTDB_KEY_IDNUMBER,
  SSH_CERTDB_KEY_BYTE_STRING,
  SSH_CERTDB_MAX_SEARCH_METHOD
} SshCertDBKeyType;

void ssh_certdb_lru_add(SshCertDB db, SshCertDBEntry *e)
{
  SSH_ASSERT(e != NULL);
  SSH_ASSERT(!(e->internal_flags & (SSH_CDBF_LOCKED | SSH_CDBF_LRU)));

  if (e->reference_count > 0)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("%d not added to lru, reference count is %d",
                 e->id, e->reference_count));
      return;
    }

  if (e->memlock_time > 0)
    {
      if (e->memlock_time <= ssh_time())
        e->memlock_time = 0;
      else
        {
          db->num_timelocked++;
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("entry %d timelocked for %d seconds.",
                     e->id, (int) (e->memlock_time - ssh_time())));
        }
    }

  /* Add entry to lru list.  Normally the entry is inserted at the
     head of lru list.  However if the DEPRECATE flag has been set
     the entry is inserted in the tail of the list. */
  if (e->internal_flags & SSH_CDBF_CACHE_DEPRECATE)
    {
      e->lru_next = NULL;
      e->lru_prev = db->lru_tail;
      if (db->lru_tail)
        db->lru_tail->lru_next = e;
      else
        db->lru_head = e;
      db->lru_tail = e;
    }
  else
    {
      e->lru_next = db->lru_head;
      e->lru_prev = NULL;
      if (db->lru_head)
        db->lru_head->lru_prev = e;
      else
        db->lru_tail = e;
      db->lru_head = e;
    }

  e->internal_flags |= SSH_CDBF_LRU;
  db->num_lru++;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("entry %d added to lru.",
             e->id));
}

void ssh_certdb_lru_remove(SshCertDB db, SshCertDBEntry *e)
{
  SSH_ASSERT(!(e->internal_flags & SSH_CDBF_LOCKED));
  SSH_ASSERT(e->internal_flags & SSH_CDBF_LRU);

  if (e->memlock_time > 0)
    db->num_timelocked--;

  /* Remove entry from lru. */
  if (e->lru_next == NULL)
    db->lru_tail = e->lru_prev;
  else
    e->lru_next->lru_prev = e->lru_prev;
  if (e->lru_prev == NULL)
    db->lru_head = e->lru_next;
  else
    e->lru_prev->lru_next = e->lru_next;

  e->internal_flags &= ~SSH_CDBF_LRU;
  db->num_lru--;

  SSH_DEBUG(SSH_D_LOWSTART, ("entry %d removed from lru.", e->id));
}

/* Get free entry from LRU */
SshCertDBEntry *ssh_certdb_get_lru_entry(SshCertDB db)
{
  SshCertDBEntry *e;
  SshTime curtime = ssh_time();
  int count = 0;

  /* Scan lru for free items. All entries which are still memlocked
     must be skipped, as well as items having references to them. */

  for (e = db->lru_tail; e != NULL; e = e->lru_prev, count++)
    {
      if (e->reference_count > 1)
        continue;

      if (e->memlock_time == 0 || curtime > e->memlock_time)
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Flushing entry %d from lru after scanning %d.",
                     e->id, count));
          ssh_certdb_lru_remove(db, e);
          e->memlock_time = 0;
          return e;
        }
    }
  return NULL;
}


void ssh_certdb_set_entry_class_internal(SshCertDB db, SshCertDBEntry *e,
                                         int entry_class)
{
  void *new_entry_classes = NULL;
  int old_num_entry_classes = 0;

  SSH_ASSERT(db != NULL && e != NULL);

  if (e->entry_class == entry_class)
    return;

  if (entry_class >= db->num_entry_classes)
    {
      old_num_entry_classes = db->num_entry_classes;
      db->num_entry_classes = entry_class + 1;

      if ((new_entry_classes =
           ssh_realloc(db->entries,
                       (old_num_entry_classes * sizeof(*db->entries)),
                       (db->num_entry_classes - old_num_entry_classes)
                       * sizeof(*db->entries)))
          == NULL)
        {
          db->num_entry_classes = old_num_entry_classes;
          return;
        }
    }

  /* If entry is already in some class list, remove it first. */
  if (e->entry_class != -1)
    {
      if (e->prev_entry != NULL)
        e->prev_entry->next_entry = e->next_entry;
      else
        db->entries[e->entry_class] = e->next_entry;
      if (e->next_entry != NULL)
        e->next_entry->prev_entry = e->prev_entry;
    }

  e->entry_class = entry_class;

  /* Expand with new entry classes now */
  if (new_entry_classes)
    {
      db->entries = new_entry_classes;
      memset(&db->entries[old_num_entry_classes], 0,
             (db->num_entry_classes - old_num_entry_classes) *
             sizeof(*db->entries));
    }

  /* And set the target class */
  if (entry_class != -1)
    {
      e->next_entry = db->entries[entry_class];
      if (db->entries[entry_class] != NULL)
        db->entries[entry_class]->prev_entry = e;
      db->entries[entry_class] = e;
      e->prev_entry = NULL;
    }
}

void ssh_certdb_set_entry_class(SshCertDB db, SshCertDBEntry *entry,
                                int entry_class)
{
  SSH_ASSERT(db != NULL && entry != NULL && entry_class >= 0);

  ssh_certdb_set_entry_class_internal(db, entry, entry_class);
}

int ssh_certdb_get_entry_class(SshCertDB db, SshCertDBEntry *entry)
{
  SSH_ASSERT(db != NULL && entry != NULL);

  return entry->entry_class;
}

int ssh_certdb_get_next_entry_class(SshCertDB db, int entry_class)
{
  SSH_ASSERT(db != NULL && entry_class >= 0 &&
             entry_class < db->num_entry_classes);

  /* Move forward by one. */
  entry_class++;

  /* Then look for non-empty entry. */
  for (; entry_class < db->num_entry_classes; entry_class++)
    {
      if (db->entries[entry_class] != NULL)
        {
          return entry_class;
        }
    }
  /* The invalid class. */
  return -1;
}

/* Iterate through the chain of entries in the chosen entry class.
   If invalid class (-1) is given, all objects in every class are
   iterated. */
SshCertDBEntry *ssh_certdb_iterate_entry_class(SshCertDB db, int entry_class,
                                               SshCertDBEntry *last_entry)
{
  SSH_ASSERT(db != NULL && entry_class >= -1 &&
             entry_class < db->num_entry_classes);

  if (last_entry == NULL)
    {
      if (entry_class == -1)
        return db->entries[0];
      else
        return db->entries[entry_class];
    }

  if (entry_class == -1 && last_entry->next_entry == NULL)
    {
      int cur_class;

      for (cur_class = last_entry->entry_class + 1;
           cur_class < db->num_entry_classes;
           cur_class++)
        {
          if (db->entries[cur_class] != NULL)
            return db->entries[cur_class];
        }
      return NULL;
    }

  return last_entry->next_entry;
}

void ssh_certdb_debug_info(SshCertDB db)
{
  SSH_DEBUG(0, ("%d entries in cache "
                "(memory: %d  entries: %d  lru: %d  locked: %d  "
                "timelocked: %d  free: %d)",
                db->num_lru + db->num_locked,
                db->memory_usage, db->num_entries, db->num_lru,
                db->num_locked, db->num_timelocked, db->num_free));
}

void ssh_certdb_sanity_check_dump(SshCertDB db)
{
  ssh_certdb_debug_info(db);
}

SshUInt32
cdb_map_key_hash(const void *object, void *context)
{
  SshCertDBKey *k = (SshCertDBKey *) object;
  SshUInt32 h = k->type, i;

  for (i = 0; i < k->data_len; i++)
    h = k->data[i] + (h << 17) + (h >> 15);
  return h;
}

int
cdb_map_key_compare(const void *object1, const void *object2,
                    void *context)
{
  SshCertDBKey *k1 = (SshCertDBKey *) object1;
  SshCertDBKey *k2 = (SshCertDBKey *) object2;

  if (k1->data_len == k2->data_len)
    return memcmp(k1->data, k2->data, k1->data_len);
  else if (k1->data_len < k2->data_len)
    return -1;
  else
    return 1;
}

SshUInt32
cdb_map_entry_id_hash(const void *object, void *context)
{
  SshCertDBEntry *c = (SshCertDBEntry *) object;

  return c->id;
}

int
cdb_map_entry_id_compare(const void *object1, const void *object2,
                         void *context)
{
  SshCertDBEntry *c1 = (SshCertDBEntry *) object1;
  SshCertDBEntry *c2 = (SshCertDBEntry *) object2;

  if (c1->id == c2->id)
    return 0;
  else if (c1->id < c2->id)
    return -1;
  else
    return 1;
}

typedef struct SshCDBContainerRec
{
  SshCertDBEntry *entry;
  struct SshCDBContainerRec *next;
} *SshCDBContainer, SshCDBContainerStruct;


static Boolean
cdb_sm_add(SshCertDB db, SshCertDBKey *key, SshCertDBEntry *entry)
{
  SshCertDBKey *tmp;
  SshADTHandle handle;
  SshCDBContainer c, e, p;

  SSH_DEBUG(SSH_D_LOWOK,
            ("CDB: Add key: %@", ssh_cm_render_cert_db_key, key));

  if ((c = ssh_malloc(sizeof(*c))) == NULL)
    return FALSE;

  c->entry = entry;
  c->next = NULL;

  if ((handle = ssh_adt_get_handle_to_equal(db->name_mapping, key))
      != SSH_ADT_INVALID)
    {
      /* Key already exists in the mapping. Add this entry to list of
         entries for that particular key. */
      tmp = ssh_adt_get(db->name_mapping, handle);

      for (p = e = (SshCDBContainer) tmp->entries;
           e != NULL;
           p = e, e = e->next)
        {
          if (e->entry == entry)
            {
              ssh_free(c);
              return FALSE;
            }
        }

      SSH_ASSERT(p != NULL);

      p->next = c;
    }
  else
    {
      if ((tmp = ssh_calloc(1, sizeof(*tmp))) != NULL)
        {
          tmp->type = key->type;
          if ((tmp->data = ssh_memdup(key->data, key->data_len)) != NULL)
            {
              tmp->data_len = key->data_len;
            }
          else
            {
              ssh_free(tmp);
              ssh_free(c);
              return FALSE;
            }
          tmp->next = NULL;
          tmp->entries = c;
          ssh_adt_insert(db->name_mapping, tmp);
        }
      else
        {
          ssh_free(c);
          return FALSE;
        }
    }
  return TRUE;
}

static Boolean
cdb_sm_id_add(SshCertDB db, SshCertDBEntry *e)
{
  SshCertDBKey idname;
  SshUInt32 idvalue = e->id;

  idname.type = SSH_CM_KEY_TYPE_IDNUMBER;
  idname.data = (unsigned char *) &idvalue;
  idname.data_len = sizeof(idvalue);
  idname.next = NULL;
  return cdb_sm_add(db, &idname, e);
}

static Boolean
cdb_sm_remove(SshCertDB db, SshCertDBKey *key, SshCertDBEntry *entry)
{
  SshCertDBKey *tmp;
  SshADTHandle handle;
  SshCDBContainer e, p;
  Boolean rv = FALSE;

  SSH_DEBUG(SSH_D_LOWOK,
            ("CDB: Remove key: %@", ssh_cm_render_cert_db_key, key));

  if ((handle = ssh_adt_get_handle_to_equal(db->name_mapping, key))
      != SSH_ADT_INVALID)
    {
      tmp = ssh_adt_get(db->name_mapping, handle);

      for (p = e = (SshCDBContainer)tmp->entries;
           e != NULL;
           p = e, e = e->next)
        {
          if (e->entry == entry)
            {
              rv = TRUE;
              if (e == p)
                {
                  SSH_DEBUG(SSH_D_LOWSTART,
                            ("cdb_sm_remove: removing key's first entry."));
                  tmp->entries = e->next;
                  ssh_free(e);
                  break;
                }
              else
                {
                  SSH_DEBUG(SSH_D_LOWSTART,
                            ("cdb_sm_remove: removing key's entry."));
                  p->next = e->next;
                  ssh_free(e);
                  break;
                }
            }
        }

      if (!tmp->entries)
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("cdb_sm_remove: no entries left, removing key."));
          ssh_adt_detach(db->name_mapping, handle);
          ssh_free(tmp->data);
          ssh_free(tmp);
        }
    }
  return rv;
}


static Boolean
cdb_sm_id_remove(SshCertDB db, SshCertDBEntry *e)
{
  SshCertDBKey idname;
  SshUInt32 idvalue = e->id;

  idname.type = SSH_CM_KEY_TYPE_IDNUMBER;
  idname.data = (unsigned char *) &idvalue;
  idname.data_len = sizeof(idvalue);
  idname.next = NULL;
  return cdb_sm_remove(db, &idname, e);
}


static SshCertDBEntryList *
cdb_sm_get(SshCertDB db,
           unsigned int method, unsigned int tag,
           void *key, size_t klen)
{
  SshCertDBEntry *e;
  SshCertDBKeyStruct name = { 0 };
  SshCertDBKey *tmp;
  SshCertDBEntryList *list;
  SshCertDBEntryListNode node, next;
  SshADTHandle handle;
  SshCDBContainer p;

  name.type = method;
  name.data = key;
  name.data_len = klen;

  if (tag == SSH_CM_DATA_TYPE_CRL)
    name.crl_uri = TRUE;

  SSH_DEBUG(SSH_D_LOWOK,
            ("CDB: Get key: %@",
             ssh_cm_render_cert_db_key, &name));

  if ((handle = ssh_adt_get_handle_to_equal(db->name_mapping, &name))
      != SSH_ADT_INVALID)
    {
      tmp = ssh_adt_get(db->name_mapping, handle);
    }
  else
    {
      return NULL;
    }

  list = NULL;

  for (p = (SshCDBContainer) tmp->entries; p != NULL; p = p->next)
    {
      e = p->entry;

      if (e->tag != tag || (e->internal_flags & SSH_CDBF_REMOVE))
        continue;

      /* Allocate a new list head, if not done so already. */
      if (!list)
        {
          if ((list = ssh_calloc(1, sizeof(*list))) == NULL)
            return NULL;
        }

      if ((node = ssh_malloc(sizeof(*node))) == NULL)
        {
          for (node = list->head; node; node = next)
            {
              next = node->next;
              SSH_CERTDB_ENTRY_REMOVE_REF(node->entry);
              ssh_free(node);
            }
          ssh_free(list);
          return NULL;
        }

      node->prev = list->tail;
      node->next = NULL;
      if (list->tail == NULL)
        list->head = node;
      else
        list->tail->next = node;
      list->tail = node;

      node->list = list;
      node->entry = e;

      /* Increment the reference count. */
      SSH_CERTDB_ENTRY_TAKE_REF(e);
      if (e->internal_flags & SSH_CDBF_LRU)
        ssh_certdb_lru_remove(db, e);
    }

  if (list)
    list->current = list->head;

  return list;
}


SshCDBError ssh_certdb_init(SshCertDBLinearizeObject linearize_cb,
                            SshCertDBDelinearizeObject delinearize_cb,
                            SshCertDBFreeObject free_cb,
                            unsigned int max_cache_entries,
                            unsigned int max_cache_bytes,
                            unsigned int default_memlock,
                            SshCMNotifyEvents notify, void *notify_context,
                            SshCertDB *db_return)
{
  SshCertDB db;

  SSH_DEBUG(SSH_D_HIGHSTART, ("initializing cert-db."));

  (*db_return) = NULL;

  if ((db = ssh_malloc(sizeof(*db))) == NULL)
    return SSH_CDBET_ERROR;

  memset(db, 0, sizeof(*db));

  db->num_entry_classes = 5;
  db->notify = notify;
  db->notify_context = notify_context;

  if ((db->entries =
       ssh_calloc(1, sizeof(*db->entries) * db->num_entry_classes)) == NULL)
    {
      db->num_entry_classes = 0;
      ssh_certdb_free(db);
      return SSH_CDBET_ERROR;
    }

  if ((db->id_mapping =
       ssh_adt_create_generic(SSH_ADT_MAP,
                              SSH_ADT_HASH,    cdb_map_entry_id_hash,
                              SSH_ADT_COMPARE, cdb_map_entry_id_compare,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshCertDBEntryStruct,
                                                adt_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_certdb_free(db);
      return SSH_CDBET_ERROR;
    }

  if ((db->name_mapping =
       ssh_adt_create_generic(SSH_ADT_MAP,
                              SSH_ADT_HASH,    cdb_map_key_hash,
                              SSH_ADT_COMPARE, cdb_map_key_compare,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshCertDBKeyStruct,
                                                adt_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_certdb_free(db);
      return SSH_CDBET_ERROR;
    }

  /* Callback pointers. */
  db->linearize_object = linearize_cb;
  db->delinearize_object = delinearize_cb;
  db->free_object = free_cb;

  /* Copy configuration parameters. */
  db->memory_limit = max_cache_bytes;
  db->entry_limit = max_cache_entries;
  db->default_memlock = default_memlock;

  db->num_entries = 0;
  db->memory_usage = 0;

  db->next_unallocated_entry = 1;

  db->lru_head = NULL;
  db->lru_tail = NULL;

  (*db_return) = db;

  return SSH_CDBET_OK;
}

void ssh_certdb_remove_entry_internal(SshCertDB db, SshCertDBEntry *e)
{
  SshCertDBKey *name, *next;
  SshADTHandle handle;

  if (e->id && db->notify)
    {
      if (e->tag == SSH_CM_DATA_TYPE_CERTIFICATE)
        {
          if (db->notify->certificate)
            (*db->notify->certificate)(db->notify_context,
                                       SSH_CM_EVENT_CERT_FREE,
                                       e->context);
        }
      else
        {
          if (db->notify->crl)
            (*db->notify->crl)(db->notify_context,
                               SSH_CM_EVENT_CRL_FREE,
                               e->context);
        }
    }

  /* Remove names from index. */
  while ((name = e->names) != NULL)
    {
      next  = name->next;

      if (!cdb_sm_remove(db, name, e))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Can't remove name."));
        }

      /* Free the name here. */
      if (!(e->internal_flags & SSH_CDBF_UNINITIALIZED))
        db->memory_usage -= sizeof(*name) + name->data_len;

      ssh_free(name->data);
      ssh_free(name);

      e->names = next;
    }
  e->names = NULL;

  /* Remove id from names. */
  cdb_sm_id_remove(db, e);

  /* Remove the unique id number mapping. */
  if ((handle = ssh_adt_get_handle_to_equal(db->id_mapping, e))
      != SSH_ADT_INVALID)
    ssh_adt_detach(db->id_mapping, handle);

  /* Remove entry from lru. */
  if (e->internal_flags & SSH_CDBF_LRU)
    ssh_certdb_lru_remove(db, e);

  /* Call freeing callback for dynamic data context. */
  if (db->free_object && e->context != NULL)
    {
      db->free_object(e->tag, e->context);
      e->context = NULL;
    }

  /* Remove entry from class array. */
  ssh_certdb_set_entry_class_internal(db, e, -1);
}


void ssh_certdb_free(SshCertDB db)
{
  SshCertDBEntry *e, *t;
  unsigned int i;

  SSH_DEBUG(SSH_D_HIGHSTART, ("free'ing cert-db"));

  if (db == NULL)
    return;

  /* Free all entries in memory database. */
  for (i = 0; i < db->num_entry_classes; i++)
    {
      for (e = db->entries[i]; e != NULL; e = t)
        {
          t = e->next_entry;

          if (e->reference_count > 0)
            SSH_DEBUG(SSH_D_MIDSTART,
                      ("freeing entry with %d active references",
                       e->reference_count));

          e->reference_count = 0;
          ssh_certdb_remove_entry_internal(db, e);

          db->memory_usage -= sizeof(*e);
          ssh_free(e);
        }
    }
  ssh_free(db->entries);

  for (e = db->free_list; e != NULL; e = t)
    {
      t = e->lru_next;

      e->reference_count = 0;
      ssh_certdb_remove_entry_internal(db, e);

      db->memory_usage -= sizeof(*e);
      ssh_free(e);
    }

  ssh_adt_destroy(db->name_mapping);
  ssh_adt_destroy(db->id_mapping);

  /* Sanity check. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("memory left %d", db->memory_usage));

  ssh_free(db);
  return;
}


SshCDBError ssh_certdb_alloc_entry(SshCertDB db,
                                   unsigned int tag, void *context,
                                   SshCertDBEntry **entry_return)
{
  SshCertDBEntry *e;
  SshCDBError err;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("allocate entry for tag %s",
             ssh_find_keyword_name(ssh_cm_edb_data_types, tag)));

  /* Get a new entry. If free list is not empty, take it from there.
     If memory limits haven't been reached yet, allocate new entry.
     Otherwise take one entry from lru list. */
  if (db->free_list != NULL)
    {
      SSH_DEBUG(SSH_D_MIDSTART,
                ("FreeList Entry (%d, %d)", db->num_lru, db->num_locked));

      e = db->free_list;
      db->free_list = e->lru_next;
      SSH_ASSERT(e->internal_flags & SSH_CDBF_FREE);
      db->num_free--;
    }
  else
    {
      if ((db->memory_limit == 0 || (db->memory_usage < db->memory_limit))
          && (db->entry_limit == 0 || (db->num_lru + db->num_locked <
                                       db->entry_limit)))
        {
          if ((e = ssh_calloc(1, sizeof(*e))) == NULL)
            return SSH_CDBET_ERROR;

          db->memory_usage += sizeof(*e);

          SSH_DEBUG(SSH_D_MIDSTART,
                    ("New Entry (%d, %d)", db->num_lru, db->num_locked));

          /* Add entry to list. */
          e->entry_class = -1;
          db->num_entries++;
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("LRU Entry (%d, %d)", db->num_lru, db->num_locked));

          if ((e = ssh_certdb_get_lru_entry(db)) == NULL)
            {
              SSH_DEBUG(SSH_D_HIGHOK,
                        ("Cache full, failed to allocate new entry."));
              return SSH_CDBET_DB_FULL;
            }

          err = ssh_certdb_remove_entry(db, e);
          if (err != SSH_CDBET_OK)
            {
              SSH_DEBUG(SSH_D_HIGHOK,
                        ("Failed to remove entry, err = %d", err));
              return err;
            }

          SSH_ASSERT(db->free_list != NULL);

          e = db->free_list;
          db->free_list = e->lru_next;
          db->num_free--;
        }
    }

  /* Initialize the entry. */
  ssh_certdb_set_entry_class_internal(db, e, 0);
  e->internal_flags = SSH_CDBF_UNINITIALIZED;
  e->reference_count = 0;
  SSH_CERTDB_ENTRY_TAKE_REF(e);
  e->names = NULL;
  e->session_id = 0;
  if (db->default_memlock > 0)
    e->memlock_time = ssh_time() + db->default_memlock;
  else
    e->memlock_time = 0;
  e->disklock_time = ~0;

  /* Copy user data to entry. */
  e->tag = tag;
  e->context = context;

  (*entry_return) = e;

  return SSH_CDBET_OK;
}

void ssh_certdb_take_reference(SshCertDBEntry *entry)
{
  SSH_ASSERT(entry != NULL);
  SSH_CERTDB_ENTRY_TAKE_REF(entry);
}

void ssh_certdb_set_flags(SshCertDB db, SshCertDBEntry *entry,
                          unsigned int flags)
{
  SSH_ASSERT(entry->reference_count > 0);

  entry->flags |= flags;

  if (entry->internal_flags & SSH_CDBF_UNINITIALIZED)
    return;

  entry->internal_flags |= SSH_CDBF_CHANGED;
}

void ssh_certdb_clr_flags(SshCertDB db, SshCertDBEntry *entry,
                          unsigned int flags)
{
  SSH_ASSERT(entry->reference_count > 0);

  entry->flags &= ~flags;

  if (entry->internal_flags & SSH_CDBF_UNINITIALIZED)
    return;

  entry->internal_flags |= SSH_CDBF_CHANGED;
}

unsigned int ssh_certdb_get_flags(SshCertDB db, SshCertDBEntry *entry)
{
  return entry->flags;
}


/* Add a key to the entry. */
Boolean ssh_certdb_add_key(SshCertDB db,
                           SshCertDBEntry *entry,
                           unsigned int data_type,
                           unsigned char *data,
                           size_t data_length)
{
  SshCertDBKey *name;

  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                    ("add new key; keytype %d, klen %d",
                     data_type, data_length), data, data_length);

  /* Allocate and initialize a new name. */
  if ((name = ssh_malloc(sizeof(*name))) != NULL)
    {
      name->type = data_type;
      name->data = data;
      name->data_len = data_length;

      /* Add it to the entry. */
      name->next = entry->names;
      entry->names = name;
      return TRUE;
    }
  return FALSE;
}

void ssh_certdb_entry_add_keys(SshCertDB db, SshCertDBEntry *entry,
                               SshCertDBKey *name_list)
{
  SshCertDBKey *prev, *start;
  start = name_list;

  /* Perform comparison here between the entry keys and the input keys
     to detect collisions between keys. */
  for (prev = NULL; name_list; name_list = name_list->next)
    prev = name_list;
  if (prev == NULL)
    {
      return;
    }
  /* Add the list to the entry. */
  prev->next = entry->names;
  entry->names = start;
}

/* Allocate, initialize and add a key to key list. */
Boolean ssh_certdb_key_push(SshCertDBKey **key,
                            unsigned int data_type,
                            unsigned char *data,
                            size_t data_length,
                            Boolean crl_uri)
{
  SshCertDBKey *k;

  if (data == NULL || data_length == 0)
    return FALSE;

  /* Allocate and initialize a new name. */
  if ((k = ssh_calloc(1, sizeof(*k))) != NULL)
    {
      k->type = data_type;
      k->data = data;
      k->data_len = data_length;
      k->crl_uri = crl_uri;

      if ((*key) != NULL)
        k->next = *key;
      else
        k->next = NULL;
      (*key) = k;

      SSH_DEBUG(SSH_D_LOWOK,
                ("CDB: Push key: %@", ssh_cm_render_cert_db_key, k));

      return TRUE;
    }
  else
    {
      SshCertDBKeyStruct tmp;

      tmp.type = data_type;
      tmp.data = data;
      tmp.data_len = data_length;

      SSH_DEBUG(SSH_D_LOWOK,
                ("CDB: Push key failed: %@",
                 ssh_cm_render_cert_db_key, &tmp));

      ssh_free(data);
      return FALSE;
    }
}

/* Free a key list. */
void ssh_certdb_key_free(SshCertDBKey *key)
{
  SshCertDBKey *next;

  for (; key != NULL; key = next)
    {
      ssh_free(key->data);
      next = key->next;
      ssh_free(key);
    }
}

SshCDBError ssh_certdb_add(SshCertDB db, SshCertDBEntry *e)
{
  SshCertDBKey *name;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("inserting tag %s",
             ssh_find_keyword_name(ssh_cm_edb_data_types, e->tag)));

  SSH_ASSERT(e->internal_flags == SSH_CDBF_UNINITIALIZED);

  e->internal_flags = 0;
  e->id = db->next_unallocated_entry++;

  /* Add entry object */
  ssh_adt_insert(db->id_mapping, e);

  /* Add internal entry ID key to names mapping. */
  cdb_sm_id_add(db, e);

  /* Add names to index */
  for (name = e->names; name != NULL; name = name->next)
    {
      if (!cdb_sm_add(db, name, e))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Can't add name to index."));
        }
      db->memory_usage += sizeof(*name) + name->data_len;
    }

  if (e->id && db->notify)
    {
      if (e->tag == SSH_CM_DATA_TYPE_CERTIFICATE)
        {
          if (db->notify->certificate)
            (*db->notify->certificate)(db->notify_context,
                                       SSH_CM_EVENT_CERT_NEW,
                                       e->context);
        }
      else
        {
          if (db->notify->crl)
            (*db->notify->crl)(db->notify_context,
                               SSH_CM_EVENT_CRL_NEW,
                               e->context);
        }
    }

  return SSH_CDBET_OK;
}


SshCertDBEntryList *ssh_certdb_entry_list_allocate(SshCertDB db)
{
  SshCertDBEntryList *list;

  if ((list = ssh_malloc(sizeof(*list))) != NULL)
    {
      list->head = NULL;
      list->tail = NULL;
      list->current = NULL;
    }
  return list;
}


SshCertDBEntry *ssh_certdb_entry_list_next(SshCertDBEntryList *list)
{
  SSH_ASSERT(list != NULL);

  if (list->head == NULL)
    return NULL;

  if (list->current->next == NULL)
    return NULL;

  list->current = list->current->next;

  return list->current->entry;
}

SshCertDBEntry *ssh_certdb_entry_list_prev(SshCertDBEntryList *list)
{
  SSH_ASSERT(list != NULL);

  if (list->head == NULL)
    return NULL;

  if (list->current->prev == NULL)
    return NULL;

  list->current = list->current->prev;

  return list->current->entry;
}

SshCertDBEntry *ssh_certdb_entry_list_first(SshCertDBEntryList *list)
{
  SSH_ASSERT(list != NULL);

  if (list->head == NULL)
    return NULL;

  list->current = list->head;

  return list->current->entry;
}

SshCertDBEntry *ssh_certdb_entry_list_last(SshCertDBEntryList *list)
{
  SSH_ASSERT(list != NULL);

  if (list->head == NULL)
    return NULL;

  list->current = list->tail;

  return list->current->entry;
}


Boolean ssh_certdb_entry_list_add(SshCertDB db,
                                  SshCertDBEntryList *list,
                                  SshCertDBEntry *entry)
{
  SshCertDBEntryListNode node;

  if (list && (node = ssh_malloc(sizeof(*node))) != NULL)
    {
      node->entry = entry;
      node->list = list;
      node->prev = NULL;
      node->next = list->head;

      if (list->head)
        list->head->prev = node;
      else
        list->tail = node;

      list->head = node;

      /* Update the current pointer if it not set already. */
      if (list->current == NULL)
        list->current = node;

      /* Increase the reference count. */
      SSH_CERTDB_ENTRY_TAKE_REF(entry);
      return TRUE;
    }
  return FALSE;
}

Boolean
ssh_certdb_entry_list_add_head(SshCertDB db,
                               SshCertDBEntryList *list,
                               SshCertDBEntry *entry)
{
  return ssh_certdb_entry_list_add(db, list, entry);
}

Boolean ssh_certdb_entry_list_add_tail(SshCertDB db,
                                       SshCertDBEntryList *list,
                                       SshCertDBEntry *entry)
{
  SshCertDBEntryListNode node;

  if (list && (node = ssh_malloc(sizeof(*node))) != NULL)
    {
      node->entry = entry;
      node->list = list;
      node->prev = list->tail;
      node->next = NULL;

      if (list->tail)
        list->tail->next = node;
      else
        list->head = node;
      list->tail = node;

      /* Increase the reference count. */
      SSH_CERTDB_ENTRY_TAKE_REF(entry);
      return TRUE;
    }
  return FALSE;
}

void ssh_certdb_entry_list_move(SshCertDBEntryList *to_list,
                                SshCertDBEntryListNode node)
{
  SSH_ASSERT(to_list != NULL);
  SSH_ASSERT(node != NULL);

  /* Remove the node from it's old list. */
  if (node->prev)
    node->prev->next = node->next;
  else
    node->list->head = node->next;
  if (node->next)
    node->next->prev = node->prev;
  else
    node->list->tail = node->prev;

  /* Update current pointer if necessary. */
  if (node->list->current == node)
    node->list->current = node->next;

  /* Add it to the 'to_list'. */
  node->prev = NULL;
  node->next = to_list->head;
  if (to_list->head)
    to_list->head->prev = node;
  else
    to_list->tail = node;
  to_list->head = node;
  node->list = to_list;
}

SshCertDBEntry *ssh_certdb_entry_list_remove(SshCertDB db,
                                             SshCertDBEntryListNode node)
{
  SshCertDBEntry *entry;

  SSH_ASSERT(node != NULL);

  entry = node->entry;

  /* Remove the node from it's list. */
  if (node->prev)
    node->prev->next = node->next;
  else
    node->list->head = node->next;
  if (node->next)
    node->next->prev = node->prev;
  else
    node->list->tail = node->prev;

  /* Update current pointer if necessary. */
  if (node->list->current == node)
    node->list->current = node->next;

  /* Free the node and return the entry pointer. */
  ssh_free(node);

  return entry;
}

/* Makes a union of two lists. All entries in 'list2' but not in
   'list1' are moved to it. */
void ssh_certdb_entry_list_union(SshCertDB db,
                                 SshCertDBEntryList *list1,
                                 SshCertDBEntryList *list2)
{
  SshCertDBEntryListNode l1, l2, next;

  SSH_ASSERT(list1 != NULL);
  SSH_ASSERT(list2 != NULL);

  /* Loop through all entries in 'isect' list. */
  for (l1 = list2->head; l1 != NULL; l1 = next)
    {
      next = l1->next;

      /* For each entry, loop though the 'list'. If current 'isect'
         entry is not on 'list', remove it from 'isect'. */
      for (l2 = list1->head; l2 != NULL; l2 = l2->next)
        {
          if (l2->entry == l1->entry)
            break;
        }
      if (l2 == NULL)
        ssh_certdb_entry_list_move(list1, l1);
    }
}

/* Copies the list and returns pointer to a new list. */
SshCertDBEntryList *ssh_certdb_entry_list_copy(SshCertDB db,
                                               SshCertDBEntryList *list)
{
  SshCertDBEntryList *new_list;
  SshCertDBEntryListNode n;

  SSH_ASSERT(list != NULL);

  if ((new_list = ssh_certdb_entry_list_allocate(db)) != NULL)
    {
      /* Go through all entries in original list in reverse order. */
      for (n = list->tail; n != NULL; n = n->prev)
        if (!ssh_certdb_entry_list_add(db, new_list, n->entry))
          {
            ssh_certdb_entry_list_free_all(db, new_list);
            return NULL;
          }
    }
  return new_list;
}

/* Forms intersection between two database entry lists.
   As a result, 'list' is left untouched and all entries not in it
   are removed (and released) from 'isect'.  */
void ssh_certdb_entry_list_intersect(SshCertDB db,
                                     SshCertDBEntryList *isect,
                                     SshCertDBEntryList *list)
{
  SshCertDBEntryListNode l1, l2, next;

  SSH_ASSERT(list != NULL);
  SSH_ASSERT(isect != NULL);

  /* Loop through all entries in 'isect' list. */
  for (l1 = isect->head; l1 != NULL; l1 = next)
    {
      next = l1->next;

      /* For each entry, loop though the 'list'. If current 'isect'
         entry is not on 'list', remove it from 'isect'. */
      for (l2 = list->head; l2 != NULL; l2 = l2->next)
        {
          if (l2->entry == l1->entry)
            break;
        }
      if (l2 == NULL)
        {
          /* Entry was not found in 'list', remove it from 'isect'. */
          if (next)
            next->prev = l1->prev;
          else
            isect->tail = l1->prev;
          if (l1->prev)
            l1->prev->next = next;
          else
            isect->head = next;

          /* Update current pointer if necessary. */
          if (isect->current == l1)
            isect->current = next;

          /* Release the entry and free the node. */
          ssh_certdb_release_entry(db, l1->entry);
          ssh_free(l1);
        }
    }
}


/* Removes the list entry from entry list and releases it. */
void ssh_certdb_entry_list_free(SshCertDB db,
                                SshCertDBEntryListNode node)
{
  SshCertDBEntry *entry;

  SSH_ASSERT(node != NULL);

  entry = ssh_certdb_entry_list_remove(db, node);
  ssh_certdb_release_entry(db, entry);
}

/* Frees all entries in a list. All references to actual database entries are
   released as well. */
void ssh_certdb_entry_list_free_all(SshCertDB db,
                                    SshCertDBEntryList *list)
{
  SshCertDBEntryListNode node, next;

  /* Null list pointer is another way to say empty list. */
  if (list == NULL)
    return;

  /* Free all list nodes and release their entires. */
  for (node = list->head; node != NULL; node = next)
    {
      next = node->next;
      ssh_certdb_release_entry(db, node->entry);
      ssh_free(node);
    }

  /* Free the list head. */
  ssh_free(list);
}

/* Test if given list is empty. Returns TRUE if list is empty
   or if 'list' pointer is null. Otherwise FALSE is returned. */
Boolean ssh_certdb_entry_list_empty(SshCertDBEntryList *list)
{
  if (list == NULL || list->head == NULL)
    return TRUE;
  return FALSE;
}


SshCDBError ssh_certdb_find(SshCertDB db,
                            SshCMDataType type,
                            unsigned int key_type,
                            unsigned char *key, size_t key_length,
                            SshCertDBEntryList **list_return)
{
  SshCertDBEntryList *list;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("CDB: Looking from cache (%s)",
             ssh_find_keyword_name(ssh_cm_edb_data_types, type)));

  /* Get the first matching entry. */
  list = cdb_sm_get(db, key_type, type, (void *)key, key_length);

  /* Then return the first entry. */
  (*list_return) = list;

  return SSH_CDBET_OK;
}

void *ssh_certdb_get_context(SshCertDB db, SshCertDBEntry *entry)
{
  return entry->context;
}

/* Used to set all optional entry parameters. Tag specifies the option
   that is set and data is pointer to option specific value
   (usually an unsigned int, representing an boolean value).
   Default values can be specified with NULL data pointer.
   Supported tag values are:

     SSH_CERTDB_OPTION_CACHE_DEPRECATE, unsigned int
        - If set to true (1) the entry is inserted at the tail of the
          lru list in cache and therefor flushed out first. Default value
          is false (0). Default is true.
     SSH_CERTDB_OPTION_MEMORY_LOCK, unsigned int
        - Locks the entry into memory cache for limited time. If time value
          is set to 0 , the entry is not locked at all.
          If time is set to ~0, entry is locked until it is explicitely
          freed. Otherwise entry is in memory atleast the specified
          ammount of seconds. Default is ~0.
     SSH_CERTDB_OPTION_MEMORY_UNLOCK, null
        - Set memory lock to 0. Equivalent to previous case with 0 data.
     SSH_CERTDB_OPTION_DISK_LOCK, unsigned int
        - Same as SSH_CERTDB_OPTION_MEMORY_LOCK, but for disk based
          entries instead.  Default is ~0, otherwise the entry can
          be permanently removed from the database after the time limit
          has expired.
     SSH_CERTDB_OPTION_DISK_UNLOCK, null
        - Set disk lock limit to 0. Equivalent to previous case
          with 0 data.
*/
SshCDBError ssh_certdb_set_option(SshCertDB db, SshCertDBEntry *entry,
                                  SshCertDBOptionTag tag, void *data)
{
  unsigned int limit = 0;
  SshTime curtime;

  switch (tag)
    {
    case SSH_CERTDB_OPTION_CACHE_DEPRECATE:
      {
        unsigned int flag;

        if (data != NULL)
          flag = *((unsigned int *)data);
        else
          flag = 1;

        if (flag == 0 &&
            (entry->internal_flags & SSH_CDBF_CACHE_DEPRECATE))
          {
            entry->internal_flags &= ~SSH_CDBF_CACHE_DEPRECATE;
            SSH_ASSERT(entry->internal_flags & SSH_CDBF_LRU);
            return SSH_CDBET_OK;
          }

        if (flag == 1 &&
            !(entry->internal_flags & SSH_CDBF_CACHE_DEPRECATE))
          {
            entry->internal_flags |= SSH_CDBF_CACHE_DEPRECATE;
            SSH_ASSERT(entry->internal_flags & SSH_CDBF_LRU);
            return SSH_CDBET_OK;
          }
        return SSH_CDBET_ERROR;
      }
    break;

    case SSH_CERTDB_OPTION_MEMORY_LOCK:
      if (data != NULL)
        limit = *((unsigned int *)data);
      else
        limit = ~((unsigned int)0);
      /* Fall through. */

    case SSH_CERTDB_OPTION_MEMORY_UNLOCK:

      if (limit == 0)
        {
          if (entry->internal_flags & SSH_CDBF_LOCKED)
            {
              entry->internal_flags &= ~SSH_CDBF_LOCKED;
              SSH_CERTDB_ENTRY_REMOVE_REF(entry);

              SSH_DEBUG(SSH_D_HIGHOK, ("entry unlocked in cache"));
              entry->memlock_time = 0;
              db->num_locked--;
            }
          if (entry->memlock_time > 0)
            {
              if (entry->internal_flags & SSH_CDBF_LRU)
                ssh_certdb_lru_remove(db, entry);
              entry->memlock_time = 0;
            }
          if (!(entry->internal_flags & SSH_CDBF_LRU))
            ssh_certdb_lru_add(db, entry);
          return SSH_CDBET_OK;
        }

      if (limit == ~((unsigned int)0))
        {
          if (!(entry->internal_flags & SSH_CDBF_LOCKED))
            {
              if (entry->internal_flags & SSH_CDBF_LRU)
                ssh_certdb_lru_remove(db, entry);
              entry->internal_flags |= SSH_CDBF_LOCKED;
              SSH_CERTDB_ENTRY_TAKE_REF(entry);

              db->num_locked++;
              SSH_DEBUG(SSH_D_HIGHOK, ("entry locked in cache"));
            }
          entry->memlock_time = 0;

          return SSH_CDBET_OK;
        }

      if (entry->internal_flags & SSH_CDBF_LOCKED)
        {
          entry->internal_flags &= ~SSH_CDBF_LOCKED;
          SSH_CERTDB_ENTRY_REMOVE_REF(entry);
          db->num_locked--;
          SSH_DEBUG(SSH_D_HIGHOK, ("entry locked in cache"));
        }
      else
        {
          if (entry->internal_flags & SSH_CDBF_LRU)
            ssh_certdb_lru_remove(db, entry);
        }
      curtime = ssh_time();
      entry->memlock_time = curtime + limit;
      ssh_certdb_lru_add(db, entry);

      return SSH_CDBET_OK;

    case SSH_CERTDB_OPTION_DISK_LOCK:
      if (data != NULL)
        limit = *((unsigned int *)data);
      else
        limit = ~((unsigned int)0);
      /* Fall through. */

    case SSH_CERTDB_OPTION_DISK_UNLOCK:
      if (limit == 0)
        {
          if (entry->disklock_time > 0)
            entry->disklock_time = 0;
          return SSH_CDBET_OK;
        }

      if (limit == ~((unsigned int)0))
        {
          entry->disklock_time = -1;
          return SSH_CDBET_OK;
        }

      curtime = ssh_time();
      entry->disklock_time = curtime + limit;

      return SSH_CDBET_OK;

    default:
      SSH_NOTREACHED;
      break;
    }

  return SSH_CDBET_OK;
}

SshCDBError ssh_certdb_get_option(SshCertDB db, SshCertDBEntry *entry,
                                  SshCertDBOptionTag tag,
                                  void *data_return)
{
  switch (tag)
    {
    case SSH_CERTDB_OPTION_CACHE_DEPRECATE:
      if (entry->internal_flags & SSH_CDBF_CACHE_DEPRECATE)
        (*((unsigned int *) data_return)) = 1;
      else
        (*((unsigned int *) data_return)) = 0;
      break;

    case SSH_CERTDB_OPTION_MEMORY_LOCK:
      {
        unsigned int *limit = ((unsigned int *)data_return);
        SshTime curtime;

        if (entry->internal_flags & SSH_CDBF_LOCKED)
          {
            (*limit) = ~((unsigned int) 0);
            return SSH_CDBET_OK;
          }

        if (entry->memlock_time == 0)
          {
            (*limit) = 0;
            return SSH_CDBET_OK;
          }

        curtime = ssh_time();
        if (curtime > entry->memlock_time)
          (*limit) = 0;
        else
          /* TODO. Modify the limit to use SshUInt64. */
          (*limit) = (unsigned int)(entry->memlock_time - curtime);
        return SSH_CDBET_OK;
      }

    case SSH_CERTDB_OPTION_DISK_LOCK:
      {
        unsigned int *limit = ((unsigned int *)data_return);
        SshTime curtime;

        if (entry->disklock_time == 0)
          {
            (*limit) = 0;
            return SSH_CDBET_OK;
          }

        if (entry->disklock_time == -1)
          {
            (*limit) = ~0;
            return SSH_CDBET_OK;
          }

        curtime = ssh_time();
        if (curtime > entry->disklock_time)
          (*limit) = 0;
        else
          /* TODO. Modify the limit to use SshUInt64. */
          (*limit) = (unsigned int)(entry->disklock_time - curtime);
        return SSH_CDBET_OK;
      }
    break;

    default:
      SSH_NOTREACHED;
      break;
    }

  return SSH_CDBET_OK;
}

unsigned int ssh_certdb_get_entry_tag(SshCertDBEntry *entry)
{
  return entry->tag;
}

unsigned int ssh_certdb_get_unique_id(SshCertDBEntry *entry)
{
  return entry->id;
}

unsigned int ssh_certdb_get_session_id(SshCertDBEntry *entry)
{
  return entry->session_id;
}

void ssh_certdb_set_session_id(SshCertDBEntry *entry, unsigned int id)
{
  entry->session_id = id;
}

/* Marks entry as updated. If 'new_buffer' (and 'buflen') is given,
   the old linearized buffer in entry is replaced with it. Otherwise
   it is just freed and linarization callback is called if necessary. */

SshCDBError ssh_certdb_update(SshCertDB db, SshCertDBEntry *entry,
                              unsigned char *new_buffer, size_t buflen,
                              int flags)
{

  if (flags & SSH_CDBF_LOCKED && !(entry->internal_flags & SSH_CDBF_LOCKED))
    {
      /* Remove entry from lru and make it locked in cache. */
      if (entry->internal_flags & SSH_CDBF_LRU)
        ssh_certdb_lru_remove(db, entry);

      entry->internal_flags |= SSH_CDBF_LOCKED;
      SSH_CERTDB_ENTRY_TAKE_REF(entry);
    }
  else
    if (!(flags & SSH_CDBF_LOCKED) && entry->internal_flags & SSH_CDBF_LOCKED)
      {
        /* Clear entry's locked status and add it to lru list. */
        entry->flags &= ~SSH_CDBF_LOCKED;
        SSH_CERTDB_ENTRY_REMOVE_REF(entry);
        ssh_certdb_lru_add(db, entry);
      }

  entry->internal_flags |= SSH_CDBF_CHANGED;
  return SSH_CDBET_OK;
}


SshCDBError ssh_certdb_release_entry(SshCertDB db, SshCertDBEntry *entry)
{
  SSH_ASSERT(entry->reference_count > 0);

  /* Decrement the reference count. */
  SSH_CERTDB_ENTRY_REMOVE_REF(entry);
  if (entry->reference_count == 0)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("reference count is %d, remove entry",
                 entry->reference_count));
      if (entry->internal_flags & (SSH_CDBF_UNINITIALIZED | SSH_CDBF_REMOVE))
        ssh_certdb_remove_entry(db, entry);
      else
        {
          if (!(entry->internal_flags & SSH_CDBF_LOCKED))
            ssh_certdb_lru_add(db, entry);

        }
    }

  return SSH_CDBET_OK;
}


SshCDBError ssh_certdb_remove_entry(SshCertDB db, SshCertDBEntry *e)
{
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("remove entry tag %s",
             ssh_find_keyword_name(ssh_cm_edb_data_types, e->tag)));

  if (e->internal_flags & SSH_CDBF_LOCKED)
    return SSH_CDBET_OK;

  if (e->reference_count > 1)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Reference count in remove entry %u", e->reference_count));
      e->internal_flags |= SSH_CDBF_REMOVE;
      SSH_CERTDB_ENTRY_REMOVE_REF(e);

      return SSH_CDBET_OK;
    }

  ssh_certdb_remove_entry_internal(db, e);

  /* Add entry to free list. */
  e->lru_next = db->free_list;
  db->free_list = e;
  db->num_free++;
  e->internal_flags = SSH_CDBF_FREE;
  e->reference_count = 0;

  return SSH_CDBET_OK;
}
#endif /* SSHDIST_CERT */
