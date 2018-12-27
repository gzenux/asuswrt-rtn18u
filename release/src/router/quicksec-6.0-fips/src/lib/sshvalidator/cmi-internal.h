/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal, but intra module, data structures.
*/

#ifndef CMI_INTERNAL_H
#define CMI_INTERNAL_H

#include "sshtimeouts.h"
#include "sshglist.h"
#include "sshhttp.h"
#include "cert-db.h"
#include "cmi-map.h"
#include "cmi-edb.h"
#include "cmi-debug.h"
#include "sshadt.h"
#include "sshfsm.h"

#ifdef SSHDIST_CERT

#define SSH_CM_HASH_LENGTH 10

/**** Data structures for the CMi. */

struct SshCMSearchConstraintsRec
{
  /* The minimum time interval when the found certificate should be valid. */
  SshBerTimeStruct not_before, not_after;
  /* The subject's keys that are looked after. */
  SshCertDBKey *keys;
  /* The path length, maximum for this search. */
  size_t max_path_length;
  /* The key usage flags. */
  SshX509UsageFlags key_usage_flags;
  /* The public key algorithm type. */
  SshX509PkAlgorithm pk_algorithm;

  /* Rule by which the names are matched. */
  SshCMSearchRule rule;

  /* Information about the trusted CA's. */
  struct {
    SshMPIntegerStruct trusted_set;
    SshBerTimeStruct   trusted_not_after;
  } trusted_roots;

  /* Group searches find all the end user certificates, but doesn't return
     any of the CA's and so no paths. */
  Boolean group;

  /* Full search to the closest trusted root. */
  Boolean upto_root;

  /* Forcing local searches. */
  struct {
    Boolean cert, crl;
  } local;

  /* Perhaps also the issuers keys? Not yet implemented, and probably
     never will. */
  SshCertDBKey *issuer_keys;
#ifdef SSHDIST_VALIDATOR_OCSP
  SshCMOcspMode ocsp_mode;
  char *ocsp_responder_url;
#endif /* SSHDIST_VALIDATOR_OCSP */
  Boolean check_revocation;

  SshUInt32 inhibit_any_policy;
  SshUInt32 inhibit_policy_mapping;
  SshUInt32 policy_mapping;
  SshUInt32 explicit_policy;

  char **user_initial_policy_set;
  size_t user_initial_policy_set_size;

  /* Per search resource access url. */
  int num_access;
  struct {
    char *url;
    unsigned int pending : 1;
    unsigned int done : 1;
  } *access;
};

typedef enum
{
  SSH_CM_VS_OK,
  SSH_CM_VS_HOLD,
  SSH_CM_VS_REVOKED
} SshCMValidityStatus;





struct SshCMCertificateRec
{
  /* A pointer to the main CM data structure. */
  SshCMContext cm;

  unsigned int initialization_flags;
#define SSH_CM_CERT_IF_LOCKED  ((unsigned int)1 << 0)
#define SSH_CM_CERT_IF_TRUSTED ((unsigned int)1 << 1)

  /*** Basic trust information, shared on the initialization flags
       bit field ***/

  /* 1. New certificate, CRL has not been checked. */
  unsigned int not_checked_against_crl:1;

  /* 2. Does the extension claim this is v3 CA certificate. */
  unsigned int is_ca:1;

  /* 3. If has ever acted as a CA certificate (with or without the
     explicit CA basic constraint). This is used to optimize the
     certificate revocation (e.g. you don't need to start all trust
     computation from scratch if you have only revoked a end user
     certificate or a certificate which has never been visited in
     authentication path searches. */
  unsigned int acting_ca:1;

  /* 4. Defines whether this certificate is a CRL issuer or not. All
     certificates that are CA's must be certificate issuers for
     correct validation. */
  unsigned int crl_issuer:1;

  /* 5. This certificate is self-signed? */
  unsigned int self_signed:1;

  /* 6. Is this issued to self; does not mean self-signed but same
     subject and issuer names. */
  unsigned int self_issued:1;

  /* 7. Defines whether CRLs are used when validating this
     certificate. */
  unsigned int crl_user:1;

  /* 8. Was the revocator 'trusted root'. */
  unsigned int revocator_was_trusted:1;

  /* Status flags. */
  unsigned int status_flags;

  /* Knowledge of the underlying entry. */
  SshCertDBEntry *entry;

  /* The certificate in opened form. */
  SshX509Certificate cert;

  /* Certificate code in ber. */
  unsigned char *ber;
  size_t         ber_length;

  /* The private data. */
  void *private_data;
  SshCMPrivateDataDestructor private_data_destructor;

  struct {
#ifdef SSHDIST_VALIDATOR_OCSP
    SshOcspResponse ocsp;
#endif /* SSHDIST_VALIDATOR_OCSP */
  } inspection;

  /* The time after CRL must be refetched and applied. This
     information is stored to the CA. Note that this requires that the
     CRL when first time introduced to the cache is applied to all
     certificates in the cache. */
  SshBerTimeStruct crl_recompute_after;

#ifdef SSHDIST_VALIDATOR_OCSP
  /* The OCSP information validity time, after which the OCSP
     information must be refetched. This information is for the
     subject itself. */
  SshBerTimeStruct ocsp_valid_not_before;
  SshBerTimeStruct ocsp_valid_not_after;
#endif /* SSHDIST_VALIDATOR_OCSP */

  /* Information is for most part just cached here to be available more
     quickly for the path validation. */

  /* Is the certificate a 'trusted root' e.g. it is trusted unless two
     conditions are satisfied:
       a) the validity period of the certificate comes up
       b) the certificate is revoked by the authority which has
          issued the certificate (and we trust that authority too?).
     */

  /* Is the certificate verified? That is, is the signature of the
     certificate verified by the CA public key. After some time
     this might become invalid. */
  struct {
    unsigned int     trusted_issuer_id;

    SshMPIntegerStruct   trusted_set;

    Boolean          trusted;
    Boolean          trusted_root;
    Boolean          trusted_signature;

    SshBerTimeStruct trusted_not_after;
    SshBerTimeStruct trusted_computed;

    /* Validity time as last computed. */
    SshBerTimeStruct valid_not_before;
    SshBerTimeStruct valid_not_after;

    size_t           path_length;
  } trusted;

  /*** Revocation information ***/

  /* Is this certificate revoked? */
  SshCMValidityStatus status;
};

/* The certificate revocation list information. */
struct SshCMCrlRec
{
  /* The main CM context. */
  SshCMContext cm;
  /* Status flags. */
  unsigned int status_flags;
  /* This flag indicates that the found CRL in the cache is actually
     invalid (or expired) and should not be used for validation. This
     also implies that one should not give it to the application as
     it should not be of any real value.
     */
#define SSH_CM_CRL_FLAG_SKIP 1

  /* The Entry. */
  SshCertDBEntry *entry;

  /* The opened CRL. */
  SshX509Crl crl;
  /* The ber encoded CRL. */
  unsigned char *ber;
  size_t ber_length;

  /* Time this CRL appeared on the system. This time is updated in
     case the same CRL is re-inserted. */
  SshBerTimeStruct fetch_time;

  /* A mapping for the CRLs by the serial numbers. */
  SshADTContainer revoked;
  /* Signature verified flag. */
  Boolean trusted;
};

/**** Data structures for the EDB. */

typedef enum
{
  SSH_CMEDB_OK,
  SSH_CMEDB_SEARCHING,
  SSH_CMEDB_DELAYED,
  SSH_CMEDB_NOT_FOUND,
  SSH_CMEDB_REMOVE_FAILED
} SshCMEdbStatus;

#ifdef SSHDIST_VALIDATOR_OCSP
/**** OCSP */

typedef struct SshCMOcspRec
{
  /* A list of responders and servers. The order is meaningful! */
  SshGList servers;

#ifdef SSHDIST_VALIDATOR_HTTP
  SshHttpClientContext http_context;
#else /* SSHDIST_VALIDATOR_HTTP */
  SshADTContainer responses;
  SshGList all_responses;
#endif /* SSHDIST_VALIDATOR_HTTP */

  /* Next unique identifier. */
  unsigned int next_id;

} SshCMOcsp;
#endif /* SSHDIST_VALIDATOR_OCSP */

/* The data structure tha manages the CM databases. */
typedef struct SshCMDatabasesRec
{
  /* List for "generic" databases (in order of preference). */
  SshGList dbs;

  /* Information about local network. */
  SshCMLocalNetworkStruct local_net;

#ifdef SSHDIST_VALIDATOR_OCSP
  /* OCSP interface. */
  SshCMOcsp ocsp;
#endif /* SSHDIST_VALIDATOR_OCSP */

  /* What else? */
} SshCMDatabases;

/**** Main CMi data structures. */

struct SshCMConfigRec
{
  /* Basic information */

  /* The time function to be used. */
  SshCMTimeFunc        time_func;
  void                *time_context;

  /* Maximum path length of certificate paths. */
  size_t max_path_length;

  /* The maximum number of recursion levels in one operation control
     call. */
  unsigned int max_operation_depth;

  /* The maximum number of restarts allowed for searching. */
  unsigned int max_restarts;

  /* Allowed databases. */
  Boolean local_db_allowed;

  /* The writable flags of databases. */
  Boolean local_db_writable;

  /* Granularity for the time control. */
  SshUInt32 granularity_msecs;
  SshUInt32 op_delay_msecs;

  /* Timeout values. These are used in operation control to make sure that
     applications that need timely response and use the event loop
     will get answers quickly. */
  long timeout_seconds, timeout_microseconds;

  /*** Local database information ***/
  size_t max_cache_bytes;
  unsigned int max_cache_entries;

  /* Maximum number of seconds a certificate needs to be valid. */
  unsigned int max_validity_secs;

  /* Minimum number of seconds CRL is considered valid after time it
     was issued, unless next-update specifies an earlier time.  This
     tries to pervent fetching CRL too often if the issuer does not
     fill in next-update times. */
  unsigned int min_crl_validity_secs;

  /* Maximum number of seconds CRL is considered valid after time it
     was introduced to the system. New CRL will be fetched at
     next-update, or after this many seconds, which ever occurs
     first. */
  unsigned int max_crl_validity_secs;

#ifdef SSHDIST_VALIDATOR_OCSP
  unsigned int min_ocsp_validity_secs;
   SshCMOcspResponderFlags ocsp_responder_flags;
#endif /* SSHDIST_VALIDATOR_OCSP */

  /* Default name lock to the local database. */
  unsigned int default_time_lock;

  /* NegaCache information. */
  unsigned int nega_cache_size;
  unsigned int nega_cache_invalid_secs;

  /*** Notify callbacks. */
  const SshCMNotifyEventsStruct *notify_events;
  void                    *notify_context;

  /* Various external object size limitations */
  size_t max_certificate_length;
  size_t max_crl_length;
  size_t max_ldap_response_length;
  size_t max_ocsp_response_length;

  /* Restrictions for algorithm sets and minimum key strength */
  SshUInt32 allowed_hash_functions;
  SshUInt32 allowed_keys;

  /* If to keep LDAP connections open. If idle_timeout is nonzero
     connection to ldap server will be closed approximately after this
     many seocnds. */
  SshUInt32 ldap_connection_idle_timeout;

  /* How many seconds a search can take. Zero indicates there is not
     limit */
  SshUInt32 search_expire_timer;

  SshCMAccessCB access_callback;
  void *access_callback_context;

  /* TCP connection establishment timeout in seconds. Zero indicates
     use of underlying operating system TCP stack default value. */
  SshUInt32 tcp_connect_timeout;
};


struct SshCMSearchSignatureFailureRec {
  unsigned int issuer_id;
  unsigned int subject_id;
};
typedef struct SshCMSearchSignatureFailureRec *SshCMSearchSignatureFailure;

/* The main searching information. */

typedef struct SshCMSearchContextRec
{
  /* We have a list of these. */
  struct SshCMSearchContextRec *next;

  /* Status of the context. */
  SshCMStatus status;

  /* Status of the search. A bit mask that gives some information about
     the current search. */
  SshCMSearchState state;

  /* Primary error. */
  SshCMError error;
  unsigned char *error_string;
  int error_string_len;

  /* TRUE if OCSP based check failed. */
  Boolean ocsp_check_failed;

  /* The context for general policy and database information. */
  SshCMContext cm;

  /* The timeout manager for external database searches. */
  SshCMMapLocator  edb_op_locator;
  SshCMMapLocator  ocsp_op_locator;

  /* Search contexts to figure out the end user and the CA to find
     for. */
  SshCMSearchConstraints end_cert;

  /* The list of CA certificates available, of the correct name and
     every thing. */
  SshCertDBEntryList *ca_cert;

  /* Time of current validity, computed from validity information and
     from the current time got by the time() function. */
  SshBerTimeStruct valid_time_start;
  SshBerTimeStruct valid_time_end;

  /* Current time (as of start of the search, or restart). */
  SshBerTimeStruct max_cert_validity_time;
  SshBerTimeStruct max_crl_validity_time;
  SshBerTimeStruct cur_time;

  SshTime   started;

  /* Is this search yet terminated or not. */
  Boolean   terminated;

  /* Some information about the current asynchronous operations. */
  Boolean   async_completed;
  Boolean   async_ok;
  SshOperationHandle async_op;

  SshUInt16 async_numops;
  SshUInt16 waiting;

  /* Statistics. */

  /* The number of restarts, there is a maximum defined in CM context
     and if one too many then the operation will be terminated. */
  SshUInt16 restarts;


  /* Callback and application information context. */
  SshCMSearchResult   callback;
  void               *search_context;

  /* Array of signature validation failed for this search */
  size_t failure_list_size;
  SshCMSearchSignatureFailure failure_list;

} SshCMSearchContext;

struct SshCMContextRec
{
  Boolean stopping;
  SshCMDestroyedCB stopped_callback;
  void *stopped_callback_context;

  /*** Configuration information */
  SshCMConfig     config;

  /*** Current information for the searching. */

  /* The current operation recursion depth. */
  unsigned int operation_depth;

  /* The session id integer. A monotonously increasing integer for the
     full uptime of this particular program. It is estimated that
     one 32-bit integer should last for years. However, if this is not
     so, then one can try to make it larger. Idea is to avoid
     need to go through all entries too many times, however, this
     approach might be too complicated? This information is not
     saved to disk. */
  unsigned int session_id;

  /* Last date of CA revocation. */
  SshBerTimeStruct ca_last_revoked_time;


  /*** Information of allowed keys. */
  unsigned int local_db_keys_allowed;

  /*** State */
  Boolean      searching;
  unsigned int in_callback;
  /*** List of searching contexts. */
  SshCMSearchContext *current, *last;

  /*** NegaCache. */

  SshEdbNegaCache negacache;

  /*** The operation table. */
  SshCMMap     op_map;

  /*** Databases */

  /* The local certificate database. */
  SshCertDB      db;

  /* External sources of certificate information. */
  SshCMDatabases  edb;

  SshTimeoutStruct control_timeout; Boolean control_timeout_active;
  SshTimeoutStruct map_timeout; Boolean map_timeout_active;

  SshTimeoutStruct op_expire_timeout;
  SshTime next_op_expire_timeout;

  SshFSMStruct fsm[1];
};

/* Function prototypes that are internal to CMi (or EDB). */

/* Set error and state of the search. */
void
ssh_cm_error_set(SshCMSearchContext *serach,
                 unsigned int state,
                 SshCMError error,
                 SshCMCertificate cm_cert_primary,
                 SshCMCertificate cm_cert_secondary);

/* Add a CRL to the cache with additional bindings. */
SshCMStatus ssh_cm_add_crl_with_bindings(SshCMCrl crl,
                                         SshCertDBKey *bindings);

SshCMStatus ssh_cm_add_with_bindings(SshCMCertificate cert,
                                     SshCertDBKey *bindings);

/* Initialize the external database system. This function is called by
   the CMi. */
Boolean ssh_cm_edb_init(SshCMDatabases *edb);
/* Free the external database system. This function is called by the CMi. */
void ssh_cm_edb_free(SshCMDatabases *edb);
void ssh_cm_edb_stop(SshCMDatabases *edb);

/* Free a particular search database entry. Called by the CMi. */
void ssh_cm_edb_search_database_free(SshCMSearchDatabase *db);

Boolean
ssh_cm_check_db_collision(SshCMContext cm,
                          SshCMDataType type,
                          const unsigned char *ber, size_t ber_length,
                          SshCertDBKey **key,
                          unsigned int *entry_id);

/* The routines that are used to search things through this general
   interface.

   Issues related to searching. First, the distinguisher is included to
   allow extra information to be used when deciding the method of
   searching. For example, the CM might know which server to use to
   fetch the information, the search code should use this information. */

SshCMEdbStatus
ssh_cm_edb_search_local(SshCMSearchContext *context,
                        SshCMDBDistinguisher *db_distinguisher);


SshCMEdbStatus
ssh_cm_edb_search(SshCMSearchContext *context,
                  SshCMDBDistinguisher *db_distinguisher);


/* Timeout callable function. */
void ssh_cm_timeout_control(void *context);

/* OCSP search start. */
SshCMStatus ssh_cm_ocsp_check_status(SshCMSearchContext *context,
                                     SshCMCertificate subject,
                                     SshCMCertificate issuer);


void ssh_cm_ocsp_operation_add_ob(SshCMContext cm,
                                  SshCMSearchContext *context);
Boolean ssh_cm_ocsp_operation_remove_ob(SshCMContext cm,
                                        SshCMSearchContext *context);

void ssh_cm_edb_operation_add(SshCMContext cm,
                                 SshCMSearchContext *context);

Boolean ssh_cm_edb_operation_remove(SshCMContext cm,
                                       SshCMSearchContext *context);
unsigned char *
ssh_cm_get_canonical_dn_der(SshX509Name names, size_t *out_len);

unsigned char *
ssh_cm_get_issuer_serial_hash(SshHash hash,
                              SshMPInteger serial_no,
                              unsigned char *name_der, size_t name_der_len,
                              unsigned char *digest);

Boolean ssh_cm_key_match(SshCertDBKey *op1, SshCertDBKey *op2);
Boolean ssh_cm_key_push_keys(SshCertDBKey **key, SshCertDBKey *list);

#ifdef SSHDIST_VALIDATOR_OCSP
/* Initializes the OCSP data structure. */
Boolean ssh_cm_ocsp_init(SshCMOcsp *ocsp);

/* Frees the data inside the OCSP structure. */
void ssh_cm_ocsp_free(SshCMOcsp *ocsp);

void ssh_cm_ocsp_stop(SshCMOcsp *ocsp);

#endif /* SSHDIST_VALIDATOR_OCSP */

/* Calculate a key identifier based on the public key. */
Boolean ssh_cm_key_kid_create(SshPublicKey public_key,
                              Boolean ike,
                              unsigned char **buf_ret,
                              size_t *len_ret);


Boolean
ssh_cm_cert_check_signature_algorithm(SshCMConfig config, const char *sign);

Boolean
ssh_cm_cert_check_key_length(SshCMConfig config, SshPublicKey pub);

Boolean
ssh_cm_cert_check_allowed_algorithms(SshCMConfig config,
                                     SshX509Certificate cert);

/***********************************************************************
 * TRUST
 */
void ssh_cm_trust_init(SshCMCertificate subject);
void ssh_cm_trust_clear(SshCMCertificate subject);

Boolean
ssh_cm_trust_check_set(SshMPInteger op1, SshMPInteger op2);

void
ssh_cm_trust_make_root(SshCMCertificate subject,
                       SshCMSearchContext *context);
void
ssh_cm_trust_make_user(SshCMCertificate subject,
                       SshCMSearchContext *context);
Boolean
ssh_cm_trust_is_root(SshCMCertificate subject, SshCMSearchContext *context);


void
ssh_cm_trust_mark_signature_ok(SshCMCertificate subject,
                               SshCMCertificate issuer,
                               SshCMSearchContext *context);

Boolean
ssh_cm_trust_in_signature_predicate(SshCMCertificate subject,
                                    SshCMSearchContext *context);

void
ssh_cm_trust_update_validity(SshCMCertificate subject,
                             SshCMCertificate ca,
                             SshBerTimeStruct *not_before,
                             SshBerTimeStruct *not_after,
                             SshCMSearchContext *context);
void
ssh_cm_trust_computed(SshCMCertificate subject,
                      SshCMSearchContext *context);

Boolean
ssh_cm_trust_is_valid(SshCMCertificate c, SshCMSearchContext *context);

Boolean
ssh_cm_trust_check(SshCMCertificate subject,
                   SshCMCertificate ca,
                   SshCMSearchContext *context);

/* Policy constraint processing */
typedef struct SshCMPolicyTreeRec *SshCMPolicyTree;

SshCMPolicyTree ssh_cm_ptree_alloc(void);
void ssh_cm_ptree_free(SshCMPolicyTree tree);

Boolean
ssh_cm_policy_init(SshCMCertificate cmcert,
                   SshCMPolicyTree *ptree,
                   int depth, int level,
                   SshUInt32 *policy_mapping,
                   SshUInt32 *inhibit_policy_mapping,
                   SshUInt32 *inhibit_any_policy,
                   SshUInt32 *explicit_policy);

Boolean
ssh_cm_policy_prepare(SshCMCertificate cmcert,
                      SshCMPolicyTree *ptree,
                      int depth, int level,
                      SshUInt32 *policy_mapping,
                      SshUInt32 *inhibit_policy_mapping,
                      SshUInt32 *inhibit_any_policy,
                      SshUInt32 *explicit_policy);
Boolean
ssh_cm_policy_wrapup(SshCMCertificate cmcert,
                     SshCMPolicyTree *ptree,
                     int depth, int level,
                     char **initial_policy_set, size_t initial_policy_set_size,
                     SshUInt32 *policy_mapping,
                     SshUInt32 *inhibit_policy_mapping,
                     SshUInt32 *inhibit_any_policy,
                     SshUInt32 *explicit_policy);


Boolean cm_name_equal(SshX509Name n1, SshX509Name n2);
unsigned char *
cm_canon_der(const unsigned char *der, size_t der_len, size_t *canon_der_len);

Boolean
cm_verify_issuer_name(SshCMCertificate subject, SshCMCertificate issuer);
Boolean
cm_verify_issuer_id(SshCMCertificate subject, SshCMCertificate issuer);


/* This callback is called when a certificate is revoked. The idea is
   to allow the application to keep track of certificates which have
   been revoked, without the need to search them all the time.
   Further the application can figure out easily when its own
   certificates get invalidated, etc.

   The SshCMCertificate given should not be modified nor freed, only
   viewed and looked at. After the callback returns the certificate is
   no longer valid.

   NOTE: In future this function may be extended in
   behaviour. However, this is only in our drawing board. */

typedef SshCMStatus
(*SshCMRevocationNotifyCallback)(void            *context,
                                 SshCMCertificate cert);


#endif /* SSHDIST_CERT */

#endif /* CMI_INTERNAL_H */
