/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate database and memory cache that is used through the cmi
   interface.
*/

#ifndef SSH_CERT_DB_H
#define SSH_CERT_DB_H

#include "cmi-edb.h"
#include "sshadt.h"
#include "sshadt_map.h"

/* Representation of one entry and it's properties in database. */
typedef struct SshCertDBEntryRec SshCertDBEntry, SshCertDBEntryStruct;
typedef struct SshCertDBRec *SshCertDB, SshCertDBStruct;

/* Database key type.
   Each key at the mapping stores a list of entries having this same
   key. Note, this is typedef'd in the cmi.h */
struct SshCertDBKeyRec {
  unsigned int type;
  unsigned char *data;
  size_t data_len;

  /* This is URI key which contains CRL. */
  Boolean crl_uri;

  /* This key is an access hint and it should not be compared
     strictly when looking up certificates from the local cache. */
  Boolean access_hint;

  struct SshCertDBKeyRec *next;

  /* The two last fields are intented for certificate database
     internal use. Beware, changing these will yield into a
     catastrophe. */
  void *entries;
  SshADTMapHeaderStruct adt_header;
};

#define SSH_CERTDB_ENTRY_CLASS_ZERO 0


/* Flags for entry. */
typedef unsigned int SshCertDBEntryFlags;
#define SSH_CDBF_LOCKED           (1 <<  0)
#define SSH_CDBF_CHANGED          (1 <<  1)
#define SSH_CDBF_LRU              (1 <<  2)
#define SSH_CDBF_UNINITIALIZED    (1 <<  3)
#define SSH_CDBF_FREE             (1 <<  4)
#define SSH_CDBF_REMOVE           (1 <<  5)
#define SSH_CDBF_CACHE_DEPRECATE  (1 <<  6)

/* Representation of one entry and it's properties in database. There
   is exactly one entry per each object in the database. This entry is
   accessible via several indices(keys). */
struct SshCertDBEntryRec
{
  /***********************************************************************
   * Public information that can be seen outside the database.
   */
  /* Type of the stored information. */
  unsigned int tag;

  /* Pointer to 'open' entry structure (Certificate or CRL, that is).
     Used only outside the database or with callbacks. */
  void *context;

  /* Flags for outside use. */
  unsigned int flags;

  /* Used by CM. */
  unsigned int session_id;

  /***********************************************************************
   * Public read-only information. Do not directly change these.
   */

  /* Internal unique id number for this certificate in this database. */
  unsigned int id;

  /* Defining names. */
  SshCertDBKey *names;

  /***********************************************************************
   * Private information. No unauthorized access allowed, or else...
   */
  SshADTMapHeaderStruct adt_header;

  /* Pointers for lru list. */
  SshCertDBEntry *lru_next, *lru_prev;

  /* Internal list of all entries. */
  int entry_class;
  SshCertDBEntry *next_entry;
  SshCertDBEntry *prev_entry;

  /* Flags for internal use. */
  SshCertDBEntryFlags internal_flags;

  /* Reference count for the entry. This being non zero means that
     somewere outside the database were is a valid active reference
     to this entry. */
  int reference_count;

  /* This entry mast be kept in memory cache at least until the given
     time. */
  SshTime memlock_time;

  /* This entry must be kept in memory or in permanent storage for
     the given time. */
  SshTime disklock_time;
};

/* Error conditions for database functions. */
typedef enum {
  SSH_CDBET_OK,             /* All is OK. */
  SSH_CDBET_ERROR,          /* Generic unspecified error. */
  SSH_CDBET_DB_FULL,        /* Database is full. */
  SSH_CDBET_DOES_NOT_EXIST, /* Certificate does not exist. */
  SSH_CDBET_IO_REQUIRED,    /* Can't comply with current IO restrictions. */
  SSH_CDBET_DISK_CORRUPT    /* Physical database has been corrupted. */
} SshCDBError;

typedef struct SshCertDBEntryListRec
{
  /* Head and tail pointers to actual list node structures. */
  struct SshCertDBEntryListNodeRec *head;
  struct SshCertDBEntryListNodeRec *tail;

  /* Pointer to 'current' entry in list. Used when walking through the
     list. */
  struct SshCertDBEntryListNodeRec *current;
} SshCertDBEntryList, SshCertDBEntryListStruct;


typedef struct SshCertDBEntryListNodeRec
{
  struct SshCertDBEntryListNodeRec *next;
  struct SshCertDBEntryListNodeRec *prev;

  SshCertDBEntryList *list;

  SshCertDBEntry *entry;
} *SshCertDBEntryListNode;

/* Callback definition. System can use this callback to transform
   dynamic memory structure representing a entry to a byte string for
   disk based storage. 'Buffer' must be allocated with ssh_xmalloc and
   is automatically freed by certdb. This function should return 0 if
   linearization was succesful and 1 otherwise. */

typedef int (*SshCertDBLinearizeObject)(unsigned int tag, void *context,
                                        unsigned char **buffer_return,
                                        size_t *size_return);

/* Callback definition. System can use this callback to transform
   linearized byte string to it's dynamic memory structure
   representation This function should return 0 if linearization was
   succesful and 1 otherwise. */
typedef int (*SshCertDBDelinearizeObject)(unsigned int tag,
                                          unsigned char *buffer,
                                          size_t size,
                                          SshCertDBEntry *entry,
                                          void **context);

/* Callback definition. System calls this function when entry is
   flushed from memory cache ant it should take necessary measures to
   free the context. */
typedef void (*SshCertDBFreeObject)(unsigned int tag, void *context);

/* Initializies certificate database with parameters specified in
   SshCertDBConfig structure. Pointer to allocated database object is
   returned in 'db_return'.  Callbacks 'linearize_cb' and
   'delinearize_cb' transform the information between memory and disk
   representation. 'Linearize_cb' transforms the dynamic memory
   structure into a byte string.  'Delinearize_cb' opens linearized
   byte string object and allocates necessary dynamic memory
   structures for it.  'Free_cb' is used to free object contexts when
   they are removed from cache.

   'Max_cache_entries' and 'max_cache_bytes' specify limits to memory
   cache. If either (or both) can be set to 0, the corresponding
   limit is not used. Setting this to a too small value can cause
   failures if too many entries are locked in cache simultaneously.

   'key_types' is a pointer to array (with 'num_key_types' entries) of
   wanted searchable key types. These types (indexes in array) can
   later be used in ssh_certdb_add_key of ssh_certdb_find as data_type
   arguments. */
SshCDBError ssh_certdb_init(SshCertDBLinearizeObject linearize_cb,
                            SshCertDBDelinearizeObject delinearize_cb,
                            SshCertDBFreeObject free_cb,
                            unsigned int max_cache_entries,
                            unsigned int max_cache_bytes,
                            unsigned int default_memlock,
                            SshCMNotifyEvents notify,
                            void *notify_context,
                            SshCertDB *db_return);

/* Frees certificate database object previously allocated with
   ssh_certdb_init(). */
void ssh_certdb_free(SshCertDB db);


/*** Functions to allocate and manipulate database entries. */

/* Allocates certificate entry. This entry is initialized on upper level
   and then added to the database with ssh_certdb_add. */
SshCDBError ssh_certdb_alloc_entry(SshCertDB db,
                                   unsigned int tag, void *context,
                                   SshCertDBEntry **entry_return);

/* Add a key to the entry. 'Data' must point to memory allocated with
   ssh_xmalloc and is freed automatically in certdb.  Key data must
   not be changed after this call. Return true if successful. */
Boolean ssh_certdb_add_key(SshCertDB db,
                           SshCertDBEntry *entry,
                           unsigned int data_type,
                           unsigned char *data, size_t data_length);

/* Allocate, initialize and add a key to key list. When first key is added,
   'key' pointer is expected to be null. 'Data' must point to memory
   allocated with ssh_xmalloc and is freed automatically in certdb.
   Key data must not be changed after this call. */
Boolean
ssh_certdb_key_push(SshCertDBKey **key,
                    unsigned int data_type,
                    unsigned char *data,
                    size_t data_length,
                    Boolean crl_uri);

/* Free a key list. */
void ssh_certdb_key_free(SshCertDBKey *key);

/* Add many, many keys to the entry. */
void ssh_certdb_entry_add_keys(SshCertDB db,
                               SshCertDBEntry *entry,
                               SshCertDBKey *keys);


/*** Entry list management functions. */

/* Allocates empty entry list. */
SshCertDBEntryList *ssh_certdb_entry_list_allocate(SshCertDB db);

/* Adds an entry to the list. */
Boolean ssh_certdb_entry_list_add(SshCertDB db,
                                  SshCertDBEntryList *list,
                                  SshCertDBEntry *entry);

/* Returns the first element in an entry list. Also resets the
   current element to the start of the list. */
SshCertDBEntry *ssh_certdb_entry_list_first(SshCertDBEntryList *list);

/* Returns the last element in an entry list. Also resets the
   current element to the end of the list. */
SshCertDBEntry *ssh_certdb_entry_list_last(SshCertDBEntryList *list);

/* Moves the current pointer in a list to next entry and returns it's
   value. If current entry is last in the list, this returns NULL pointer
   and the current pointer is not moved. */
SshCertDBEntry *ssh_certdb_entry_list_next(SshCertDBEntryList *list);

/* Moves the current pointer in a list to previous entry and returns it's
   value. If current entry is first in the list, this returns NULL pointer
   and the current pointer is not moved. */
SshCertDBEntry *ssh_certdb_entry_list_prev(SshCertDBEntryList *list);

/* Adds an entry to beginning of the list. Same as functions
   ssh_certdb_entry_list_add. */
Boolean ssh_certdb_entry_list_add_head(SshCertDB db,
                                       SshCertDBEntryList *list,
                                       SshCertDBEntry *entry);

/* Adds an entry to the end of the list. */
Boolean ssh_certdb_entry_list_add_tail(SshCertDB db,
                                       SshCertDBEntryList *list,
                                       SshCertDBEntry *entry);

/* Moves one entry from another list to 'to_list'. */
void ssh_certdb_entry_list_move(SshCertDBEntryList *to_list,
                                SshCertDBEntryListNode node);

/* Removes an entry node from the list. Entry itself is not freed
   or released, only it's list node. */
SshCertDBEntry *ssh_certdb_entry_list_remove(SshCertDB db,
                                             SshCertDBEntryListNode node);

/* Calculates union between two lists. Moves entries not in 'list1' from
   'list2'. */
void ssh_certdb_entry_list_union(SshCertDB db,
                                 SshCertDBEntryList *list1,
                                 SshCertDBEntryList *list2);

/* Copies the list and returns pointer to a new list. */
SshCertDBEntryList *ssh_certdb_entry_list_copy(SshCertDB db,
                                               SshCertDBEntryList *list);

/* Forms intersection between two database entry lists.
   As a result, 'list' is left untouched and all entries not in it
   are removed (and released) from 'isect'.  */
void ssh_certdb_entry_list_intersect(SshCertDB db,
                                     SshCertDBEntryList *isect,
                                     SshCertDBEntryList *list);


/* Removes the list entry from entry list and releases it. */
void ssh_certdb_entry_list_free(SshCertDB db,
                                SshCertDBEntryListNode node);

/* Frees all entries in a list. All references to actual database entries are
   released as well. */
void ssh_certdb_entry_list_free_all(SshCertDB db,
                                    SshCertDBEntryList *list);

/* Test if given list is empty. Returns TRUE if list is empty
   or if 'list' pointer is null. Otherwise FALSE is returned. */
Boolean ssh_certdb_entry_list_empty(SshCertDBEntryList *list);


/*** Main database interface. */

/* Adds a new certificate to the database 'db'. 'entry' is filled on
   upper level and it's contents are copied to the database. */
SshCDBError ssh_certdb_add(SshCertDB db, SshCertDBEntry *entry);

/* Retrieves one entry from the database 'db'. 'Key' is a
   used to search the correct entry. If several entries match the key,
   the first is returned and additional entries are linked together
   with next field in entry structure. */
SshCDBError ssh_certdb_find(SshCertDB db,
                            SshCMDataType type,
                            unsigned int key_type,
                            unsigned char *key, size_t key_length,
                            SshCertDBEntryList **list_return);

/* Increase reference count in entry. */
void ssh_certdb_take_reference(SshCertDBEntry *entry);

/* Returns the context pointer from entry. This pointer most not
   be touched anyway other than through this interface as
   a valid antry does not necessarily contain valid context pointer. */
void *ssh_certdb_get_context(SshCertDB db, SshCertDBEntry *entry);

/* Set all indicated (by 'flags' bitmask) flags in entry structure.
   Changing some flags will actually update the database entry. */
void ssh_certdb_set_flags(SshCertDB db, SshCertDBEntry *entry,
                          unsigned int flags);

/* Clears specified flags from entry. */
void ssh_certdb_clr_flags(SshCertDB db, SshCertDBEntry *entry,
                          unsigned int flags);

/* Returns bitmask representing current flags in database entry. */
unsigned int ssh_certdb_get_flags(SshCertDB db, SshCertDBEntry *entry);

typedef enum
{
  SSH_CERTDB_OPTION_CACHE_DEPRECATE,
  SSH_CERTDB_OPTION_MEMORY_LOCK,
  SSH_CERTDB_OPTION_MEMORY_UNLOCK,
  SSH_CERTDB_OPTION_DISK_LOCK,
  SSH_CERTDB_OPTION_DISK_UNLOCK
} SshCertDBOptionTag;



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
                                  SshCertDBOptionTag tag, void *data);

/* Function to request the current option value from entry.
   'data_return' must point to data type corresponding to option
   tag value. */
SshCDBError ssh_certdb_get_option(SshCertDB db, SshCertDBEntry *entry,
                                  SshCertDBOptionTag tag,
                                  void *data_return);

/* Get entry's tag number. */
unsigned int ssh_certdb_get_entry_tag(SshCertDBEntry *entry);

/* Get entry's unique id number. */
unsigned int ssh_certdb_get_unique_id(SshCertDBEntry *entry);

/* Get entry's session id number. */
unsigned int ssh_certdb_get_session_id(SshCertDBEntry *entry);

/* Set entry's session id number. */
void ssh_certdb_set_session_id(SshCertDBEntry *entry, unsigned int id);

/* Marks entry as updated. If 'new_buffer' (and 'buflen') is given,
   the old linearized buffer in entry is replaced with it. Otherwise
   it is just freed and linarization callback is called if necessary. */
SshCDBError ssh_certdb_update_entry(SshCertDB db, SshCertDBEntry *entry,
                                    unsigned char *new_buffer, size_t buflen,
                                    int flags);

/* Releases the entry reference taken with ssh_certdb_alloc_entry or
   ssh_certdb_find. */
SshCDBError ssh_certdb_release_entry(SshCertDB db, SshCertDBEntry *entry);

/* Removes the specified entry from the 'db'. 'entry' must be a structure
   returned by ssh_certdb_find. Also releases the entry. */
SshCDBError ssh_certdb_remove_entry(SshCertDB db, SshCertDBEntry *entry);

/* Set the entry class to the specified entry. The entry class must not be
   negative (this is reserved for the cert db code itself). */
void ssh_certdb_set_entry_class(SshCertDB db, SshCertDBEntry *entry,
                                int entry_class);

/* Get the entry class of the supplied entry. The entry class will not
   be negative for valid entries. */
int ssh_certdb_get_entry_class(SshCertDB db, SshCertDBEntry *entry);

/* Get the next entry that has been defined and contains more than zero
   entries currently. This function can be used to traverse through all
   available entries in the cache. */
int ssh_certdb_get_next_entry_class(SshCertDB db, int entry_class);

/* Iterate through the chain of entries in the chosen entry class.
   If invalid class (-1) is given, all objects in every class are iterated. */
SshCertDBEntry *ssh_certdb_iterate_entry_class(SshCertDB db, int entry_class,
                                               SshCertDBEntry *last_entry);

#ifdef DEBUG_LIGHT
void ssh_certdb_sanity_check_dump(SshCertDB db);
void ssh_certdb_debug_info(SshCertDB db);
#endif /* DEBUG_LIGHT */

#endif /* SSH_CERT_DB_H */
