/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The external database implementation interface.
*/

#ifndef CMI_EDB_H
#define CMI_EDB_H

/****************************************************************************/

/* The database method pointer. */
typedef struct SshCMSearchDatabaseRec SshCMSearchDatabase;
/* and distinguisher. */
typedef struct SshCMDBDistinguisherRec  SshCMDBDistinguisher;

/* Edb Conversion function.

   If this returns false then search should fail immediately (no
   conversion operation available). If this returns true then if new
   distinguisher is allocated in the new_dg pointer then it is used
   instead of dg. If there isn't any new_dg then use the old dg. The
   new_dg must be freed when this search finishes. The data is
   database specific information structure containing more information
   about the search. */
typedef Boolean
(*SshCMEdbConversionFunction)(SshCMSearchDatabase *db,
                              SshCMContext cm,
                              SshCMDBDistinguisher *dg,
                              SshCMDBDistinguisher **new_dg,
                              void *edb_conversion_ctx);

/* The external search callback implementation data structures,
   definitions, and useful function prototypes. */

typedef enum
{
  /* This database is local, and hence fast. Can be used more often
     and without much hesitation. */
  SSH_CM_SCLASS_LOCAL,

  /* Server based system. */
  SSH_CM_SCLASS_SERVER
} SshCMSearchFunctionClass;

typedef enum
{
  /* Indicates that certain number of searches were launched (the
     number should not be zero). */
  SSH_CM_SMODE_SEARCH,
  /* Indicates that search was finished successfully immediately. */
  SSH_CM_SMODE_DONE,
  /* Indicates that searches were launched, but heuristic arguments
     imply that other methods should be launched too. It may be argued
     that in some cases the method may know of problems and hence
     suggest trying with other methods too. Use with caution. */
  SSH_CM_SMODE_DELAYED,
  /* Indicates that the search did not succeed (finished
     immediately). This may be because the method remembers that the
     search cannot work, or that it is fast enough to determine it
     immediately. */
  SSH_CM_SMODE_FAILED

} SshCMSearchMode;

/* Key types for searching. */

typedef enum
{
  /* Identification number at cache, not given to EDB's. */
  SSH_CM_KEY_TYPE_IDNUMBER         = 0,
  /* Hash of the BER encoding (using the default hash algorithm). */
  SSH_CM_KEY_TYPE_BER_HASH         = 1,
  /* Directory name. */
  SSH_CM_KEY_TYPE_DIRNAME          = 2,
  /* Distinguished name. */
  SSH_CM_KEY_TYPE_DISNAME          = 3,
  /* IP address. */
  SSH_CM_KEY_TYPE_IP               = 4,
  /* DNS name. */
  SSH_CM_KEY_TYPE_DNS              = 5,
  /* URI (unique resource identifier). */
  SSH_CM_KEY_TYPE_URI              = 6,
  /* X.400 name. */
  SSH_CM_KEY_TYPE_X400             = 7,
  /* Serial number. */
  SSH_CM_KEY_TYPE_SERIAL_NO        = 8,
  /* Unique identifier. */
  SSH_CM_KEY_TYPE_UNIQUE_ID        = 9,
  /* RFC822 name (email address). */
  SSH_CM_KEY_TYPE_RFC822           = 10,
  /* Other name (given as BER encoded blob, see PKIX) */
  SSH_CM_KEY_TYPE_OTHER            = 11,
  /* RID (registered identifier). */
  SSH_CM_KEY_TYPE_RID              = 12,
  /* Public key identifier (hashed public key). */
  SSH_CM_KEY_TYPE_PUBLIC_KEY_ID    = 13,
  /* Hash of the serial number and issuer name. */
  SSH_CM_KEY_TYPE_SI_HASH          = 14,
  /* PKIX style public key identifier as described in RFC 2459. */
  SSH_CM_KEY_TYPE_X509_KEY_IDENTIFIER = 15,
  /* Certificate HASH over DER of certificate. */
  SSH_CM_KEY_TYPE_CERT_HASH = 16,

  /* The last type, not used. */
  SSH_CM_KEY_TYPE_NUM
} SshCMKeyType;

/* Data types for searching. */

typedef enum
{
  /* User certificate. */
  SSH_CM_DATA_TYPE_CERTIFICATE    = 0,
  /* End user CRL. */
  SSH_CM_DATA_TYPE_CRL            = 1,
  /* Last type not used. */
  SSH_CM_DATA_TYPE_NUM
} SshCMDataType;

struct SshCMDBDistinguisherRec
{
  /* The key type given. Certainly this is one of the most important
     pieces of information for the database to handle. It may not be
     able to locate data by some particular key. Each search procedure
     must be able to handle at least one key type, and report quickly
     if it cannot handle the particular type. */
  SshCMKeyType         key_type;

  /* The key of the data to be searched. This is in the CM format, and
     must be convert to the DB format by the search procedure. */
  unsigned char       *key;
  size_t               key_length;

  /* Data type of the search. Usually one is searching for
     certificates, but sometimes other data types may interest
     e.g. CRLs. */
  SshCMDataType        data_type;

  /* Further information, that is CM depended it may give it or not.
     The search procedure should take advantage of this, as these
     usually lead directly to the solution. However, as these point to
     large servers usually they may be heuristically overrun by local
     databases. */
  char *server_url;
  char *password;

  /* Further issues. */

  /* The following data is private in the sense that the application
     should not change it. It may observe it, but changing will make
     the code work in undefined ways. */

  /* Reference counting, value 0 means that no one has a reference to
     this object. Unlocking distinguisher with reference count 0 leads
     to a fatal error. */
  unsigned int reference_count;

  /* Entry index at constraints->access, -1 if not set. */
  int direct_access_id;
};

/* Method definition. */
typedef struct
{
  /* The unique string identifying the database method. */
  const char *db_identifier;

  /* Class of database, gives some rudimentary information for the
     EDB about how to handle the method. */
  SshCMSearchFunctionClass type;

  /* Search for a certain data element with a certain key. The
     'waiting' denotes the number a searches launches, and must be
     exact. E.g. if failure happens before any searches were launched
     it must return 0. */
  SshCMSearchMode (*search)(SshCMSearchDatabase  *database,
                            SshCMContext          cm,
                            void                 *context,
                            SshCMDBDistinguisher *distinguisher);

  /* Stop database, e.g stop everything that utilizes event loop. */
  void (*stop)(SshCMSearchDatabase *database);

  /* Free a database context (if necessary). Doesn't free the actual
     memory area for the database. */
  void (*free)(SshCMSearchDatabase *database);
} *SshCMSearchFunctions, SshCMSearchFunctionsStruct;

struct SshCMSearchDatabaseRec
{
  /* It is assumed that functions are defined in non-constant buffer.
     However, I don't like it. Nevertheless, this is how it is
     currently done. */
  Boolean functions_allocated;

  const SshCMSearchFunctionsStruct *functions;

  /* Context for the database to store information. */
  void *context;
};

typedef enum
{
  SSH_CMDB_STATUS_OK,
  SSH_CMDB_STATUS_TIMEOUT,
  SSH_CMDB_STATUS_DISCONNECTED,
  SSH_CMDB_STATUS_FAILED
} SshCMDBStatus;

/* Following routines are mainly useful for those applications that
   implement external databases. */

/* This is the reply callback that the database method calls. Every
   found item is given to the certificate manager through this
   interface. */

void ssh_cm_edb_reply(SshCMSearchDatabase  *database,
                      void                 *context,
                      SshCMDBDistinguisher *distinguisher,
                      const unsigned char  *data, size_t data_length);

/* This is the result callback that the database method calls. After
   all found items are send to the EDB this function is called. As
   this function returns the caller may free the search. */

void ssh_cm_edb_result(SshCMSearchDatabase  *database,
                       SshCMDBStatus         db_status,
                       void                 *context,
                       SshCMDBDistinguisher *distinguisher);

/* Distinguishers are used to give information about names of objects
   that are searched. Further they may contain information about the
   location that might be used to start the search. The
   implementations may ignore the extra information. */

/* Routine to allocate and initialize a distinguisher. */
SshCMDBDistinguisher *
ssh_cm_edb_distinguisher_allocate(SshCMDataType data_type,
                                  SshCMKeyType key_type,
                                  unsigned char *key_data,
                                  size_t key_len);

/* Routine to free a distinguisher. Method needs to call this when
   it is deleted and has still active searches. */
void ssh_cm_edb_distinguisher_free(SshCMDBDistinguisher *distinguisher);

/* Reference counting. All locks must be unlocked or the distinguisher
   will never be freed. All must be in pairs, too many unlocks causes
   an fatal call (e.g. program dies). */
void ssh_cm_edb_distinguisher_lock(SshCMDBDistinguisher *distinguisher);
void ssh_cm_edb_distinguisher_unlock(SshCMDBDistinguisher *distinguisher);

/* The protection functions for securing the initialization of the
   search in the application search functions. These are necessary to
   make the library understand special cases. The application
   must detect the 'finished' situation, e.g. when the search
   finished before end of the initialization of the search. */
void ssh_cm_edb_mark_search_init_start(SshCMSearchDatabase  *database,
                                       void                 *context,
                                       SshCMDBDistinguisher *distinguisher);
void ssh_cm_edb_mark_search_init_end(SshCMSearchDatabase  *database,
                                     void                 *context,
                                     SshCMDBDistinguisher *distinguisher,
                                     Boolean               finished);

/* Routines for handling the banning of searches, these bans are only
   temporary and the interval is selected in configuration. The
   functions related to nega cache are relevant here. Application may
   use its own banning routines, but these are often
   reasonable. However, they are global and application may need to
   write special handling of situations when same data item is
   searched by multiple instances at the same time. */

/* Add a ban to the distinguisher (the key) and the db identifier. */
void ssh_cm_edb_ban_add(SshCMContext cm,
                        SshCMDBDistinguisher *db_distinguisher,
                        const char *db_identifier);

/* Equivalent to function above but uses the context which is given as
   argument to the search callback function. */
void ssh_cm_edb_ban_add_ctx(void *ctx,
                            SshCMDBDistinguisher *dg,
                            const char *db_identifier);

/* Check a ban. Returns TRUE if banned, FALSE if not. */
Boolean ssh_cm_edb_ban_check(SshCMContext cm,
                             SshCMDBDistinguisher *db_distinguisher,
                             const char *db_identifier);

/* Operation management functions. These ensure that timeouts and
   related are called at the correct moment. */

/* Check if we are already performing operation for the
   disdinguisher on given database. */
Boolean ssh_cm_edb_operation_check(void *ctx,
                                   SshCMDBDistinguisher *dg,
                                   const char *db_identifier);

/* Link current distinguisher to operation performed, thus we'll get
   response when the operation also identified by the distinguisher
   completes. */
typedef void (*SshCMEdbSearchCB)(void *context, void *search_ctx);
Boolean
ssh_cm_edb_operation_link(void *ctx,
                          SshCMDBDistinguisher *dg,
                          SshCMSearchDatabase  *db,
                          const char           *db_identifier,
                          SshCMEdbSearchCB      free_ctx_cb,
                          void *search_context);

/* Message completion of operation identified by distinguisher. */
void ssh_cm_edb_operation_msg(void *ctx,
                              SshCMDBDistinguisher *dg,
                              const char  *db_identifier,
                              SshCMDBStatus status);

/***** Default database methods. */

/* These routines handle the databases. */

/* Add a new database method. The database method must be fully
   defined, as it will be valid immediately after call to this. This
   means that CM will start using it immediately.

   If a database already exists with the same identifier the database
   is not added. */

Boolean ssh_cm_edb_add_database(SshCMContext cm,
                                const SshCMSearchFunctionsStruct *db_functions,
                                void *context);

/* Look up the search database with the given identifier. */
SshCMSearchDatabase *ssh_cm_edb_lookup_database(SshCMContext cm,
                                                const char *db_identifier);

/* Remove a database method.  */
Boolean ssh_cm_edb_remove_database(SshCMContext cm,
                                   const char *db_identifier);

#include "sshber.h"

typedef struct SshEdbNegaCacheRec *SshEdbNegaCache;

/* Allocate the negative cache. The 'max_object' denotes the number of
   objects can be stored for each tag. The 'max_tag_numbers' denotes
   the maximum number of tags available. The 'invalid_secs' denotes
   the number a object inserted to the NegaCache is atleast invalid.

   This system is heuristic, that is it doesn't really do more than
   stores fixed number of elements within and if it happens that a
   collision occurs then the older one is simply destroyed. */
SshEdbNegaCache
ssh_edb_nega_cache_allocate(unsigned int max_objects,
                            unsigned int max_tag_numbers,
                            unsigned int invalid_secs);

void ssh_edb_nega_cache_free(SshEdbNegaCache nc);

/* Add a new name to the NegaCache, with a current time to be time
   stamped. */
void ssh_edb_nega_cache_add(SshEdbNegaCache nc,
                            unsigned int tag,
                            unsigned char *name,
                            size_t name_length,
                            SshBerTime current_time);

/* Check if the name is available or not. If not then simply continue
   without this information. */
Boolean ssh_edb_nega_cache_check(SshEdbNegaCache nc,
                                 unsigned int tag,
                                 unsigned char *name,
                                 size_t name_length,
                                 SshBerTime current_time);

#endif /* CMI_EDB_H */
