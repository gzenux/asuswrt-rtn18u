/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS RRset cache layer
   This layer will cache RRsets received from the name server.
   It will be used first, and if data is not available here, then it is
   fetched from the real nameserver. This is also used to combine
   identical requests, and to create search history for the request.
*/

#ifndef SSHDNSRRSETCACHE_H
#define SSHDNSRRSETCACHE_H

/* Cache context structure. */
typedef struct SshDNSRRsetCacheRec *SshDNSRRsetCache;

/**********************************************************************/
/* DNS RRset cache layer. This will store the RRset entries. */

/* Types of the cache entries. */
typedef enum {
  /* Authorative cached data that the entry does not exists. */
  SSH_DNS_RRSET_NODATA = 1,

  /* Authenticated authorative cached data that the entry
     does not exists. The entry was authenticated by dnssec. */
  SSH_DNS_RRSET_NODATA_DNSSEC = 2,

  /* Operation is still in progress, to fetch this data.
     After the data is available the cache will call the
     notify callbacks to inform waiters. */
  SSH_DNS_RRSET_IN_PROGRESS = 3,

  /* Last request for the rrset failed because of temporary
     error. This can be processed identically to the
     SSH_DNS_RRSET_NODATA, i.e. return no name error. This
     state will be automatically cleared after ttl expires (i.e.
     the ttl should be set to quite short). */
  SSH_DNS_RRSET_FAILURE = 4,

  /* Non-authorative data, i.e. from the additinal section
     from the reply. This data can only be used as hints,
     and will not be returned by the resolver directly. */
  SSH_DNS_RRSET_NON_AUTHORATIVE = 5,

  /* Authorative data. This is the normal authorative answer
     for the data. Note, that the number_of_rrs might still
     be zero, which means that the name exists, but there is
     no resource records of that type. */
  SSH_DNS_RRSET_AUTHORATIVE = 6,

  /* Authenticatede authorative data. This is the normal
     authorative answer for the data which is also
     authenticated with dnssec. Note, that the number_of_rrs
     might still be zero, which means that the name exists,
     but there is no resource records of that type. */
  SSH_DNS_RRSET_AUTHORATIVE_DNSSEC = 7
} SshDNSRRsetState;

/* Is the state such that we can accept it. */
#define SSH_DNS_RRSET_OK(rrset) \
  (((rrset)->state == SSH_DNS_RRSET_NODATA) || \
   ((rrset)->state == SSH_DNS_RRSET_NODATA_DNSSEC) || \
   ((rrset)->state == SSH_DNS_RRSET_AUTHORATIVE) || \
   ((rrset)->state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC))

/* Is the state such that we can accept it. */
#define SSH_DNS_RRSET_HINT_OK(rrset) \
  (((rrset)->state == SSH_DNS_RRSET_NODATA) || \
   ((rrset)->state == SSH_DNS_RRSET_NODATA_DNSSEC) || \
   ((rrset)->state == SSH_DNS_RRSET_NON_AUTHORATIVE) || \
   ((rrset)->state == SSH_DNS_RRSET_AUTHORATIVE) || \
   ((rrset)->state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC))

/* Is the state such that we can accept it. */
#define SSH_DNS_RRSET_HINT_DATA_OK(rrset) \
  (((rrset)->state == SSH_DNS_RRSET_NON_AUTHORATIVE) || \
   ((rrset)->state == SSH_DNS_RRSET_AUTHORATIVE) || \
   ((rrset)->state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC))

/* Is the rrset expire at time t. */
#define SSH_DNS_RRSET_EXPIRED(rrset, t) \
  (((rrset)->cached_time + (rrset)->ttl) < t)

/* RRset structure. */
typedef struct SshDNSRRsetRec *SshDNSRRset;

/* Notification callback. The rrset is the new rrset containing the requested
   data, but it might also be NULL, in case the data was never put into the
   cache (not enough memory etc). */
typedef void (*SshDNSRRsetNotifyCB)(SshDNSRRset rrset, void *context);

/* Notification list structure. */
typedef struct SshDNSRRsetNotifyRec *SshDNSRRsetNotify;

/* RRset structure, only for reading, DO NOT MODIFY. */
struct SshDNSRRsetRec {
  /* The host_bag_header must be first item, so we can cast the SshADTHandle to
     the SshDNSRRset structure. */
  SshADTBagHeaderStruct rrset_bag_header;
  SshADTListHeaderStruct free_list_header;

  SshDNSRRsetState state;       /* Type of this entry. If this is negative
                                   cache entry, then number_of_rrs is 0. */
  unsigned char *name;          /* Owner name of the rrset. This is in
                                   dns-format. */
  SshDNSRRType type;            /* RR type. */
  SshUInt32 ttl;                /* Time to live. */
  SshUInt32 number_of_rrs;      /* Number of RRs in this record. */
  size_t *array_of_rdlengths;   /* Array of lengths of records. */
  unsigned char **array_of_rdata; /* Array of pointers to the rr record data.
                                     Items here are NUL terminated. */

  /* Internal cache data. */
  SshUInt32 reference_count;    /* Number of references out of this entry. */
  Boolean valid;                /* This tells whether the entry is valid or
                                   not. If it is not valid then the entry is
                                   freed after the reference_count goes to
                                   zero. If it is not valid, it also means that
                                   it is not in the rrset_bag. */
  SshTime cached_time;          /* Time when the data was inserted to the
                                   cache. The data will expire from the cache
                                   after cached_time + max(ttl,
                                   minimum_lifetime). It can be removed from
                                   the cache after it has been in the cache for
                                   the minimum_lifetime seconds. */
  struct SshDNSRRsetRec *parent;/* Parent pointer. This is the pointer to the
                                   RRset which was used to fetch this entry.
                                   This can be used to verify the path
                                   used later (for example for dnssec).
                                   This can also be NULL if the parent
                                   has expired from cache. */
  struct SshDNSRRsetRec *next_sibling;/* Circular list of siblings. */
  struct SshDNSRRsetRec *prev_sibling;/* Circular list of siblings. */
  struct SshDNSRRsetRec *childs;/* Childs of this item (pointer to the one
                                   child, other can be reached by the siblings
                                   pointer). */

  SshDNSRRsetNotify notify;     /* First notify callback structure.
                                   Notifications are sent when the data is
                                   available in the cache. */
};

/* RRset structure. */
typedef struct SshDNSRRsetRec SshDNSRRsetStruct;

/* Allocate rrset cache. The cache will be allocated using
   default configuration. This will return NULL if out of
   memory. */
SshDNSRRsetCache
ssh_dns_rrset_cache_allocate(void);

/* RRset cache configuration structure. */
typedef struct SshDNSRRsetCacheConfigRec {
  /* Maximum number of total memory used by cache. Default
     is 64 kB. This includes memory used for rrsets and
     other control structures. */
  size_t max_memory;

  /* Number of rrsets to keep even when not used. Default is
     256. Note, that the cache is cleared only when some
     query is finished, thus the cache size might
     temporarely go over this. */
  SshUInt32 keep_rrsets;

  /* Maximum number of rrsets. Default is 512. */
  SshUInt32 max_rrsets;

  /* Each rrset entry will be in the cache at least this
     many seconds. Default is 30 seconds. This is trying to
     make sure that the entries needed to finish the name
     resolution process are not cleared from the cache too
     early. */
  SshUInt32 minimum_lifetime;

  /* Maximum TTL which is allowed. Default is 864000 (10 days). */
  SshUInt32 maximum_ttl;
} *SshDNSRRsetCacheConfig, SshDNSRRsetCacheConfigStruct;

/* Configure rrset cache. This returns true if the operation
   was successful, and FALSE if it run out of memory during
   the configure. In case of memory error some of the
   operations might have been done, and some may still be
   using old values. The rrset cache will still be usable even
   if memory error is received. */
Boolean
ssh_dns_rrset_cache_configure(SshDNSRRsetCache rrset_cache,
                              SshDNSRRsetCacheConfig config);

/* Free rrset cache. There must not be any locked entries
   when this is called. */
void
ssh_dns_rrset_cache_free(SshDNSRRsetCache rrset_cache);

/* Find rrset from cache. This will automatically allocate
   reference to the rrset returned. Returns NULL if no item
   found from cache. When the reference is no longer needed,
   remove it by calling ssh_dns_rrset_cache_unlock. The name
   is in the dns-format. */
SshDNSRRset
ssh_dns_rrset_cache_get(SshDNSRRsetCache rrset_cache,
                        const unsigned char *name,
                        SshDNSRRType type);

/* Add notify callback to RRset. This can only be called if
   the RRset is in SSH_DNS_RRSET_IN_PROGRESS state. The
   callback will be called when the data is available in the
   cache (or the operation requesting data timed out). This
   returns operation handle if the operation was successfully
   registerd or NULL if error happened (out of memory).
   After this is called, there is no need keep the rrset
   locked, this will automatically lock it until the data
   is available. Note, that the rrset structure given to the
   callback will be different than what is given to this,
   as the IN_PROGRESS entry in the cache has been replaced
   with new entry. */
SshOperationHandle
ssh_dns_rrset_cache_add_notify(SshDNSRRsetCache cache,
                               SshDNSRRset rrset,
                               SshDNSRRsetNotifyCB callback,
                               void *context);

/* Increment reference count for rrset. */
void
ssh_dns_rrset_cache_lock(SshDNSRRsetCache cache,
                         SshDNSRRset rrset);

/* Decrement reference count for rrset. */
void
ssh_dns_rrset_cache_unlock(SshDNSRRsetCache cache,
                           SshDNSRRset rrset);

/* Allocate new rrset and put it to the cache. Return NULL
   in case of out of memory. The rdata must be uncompressed
   before inserted to the cache, but otherwise it is in
   plain dns wire format. If the item is already in the cache,
   then the entries are combined (i.e. if the entries are identical,
   then cached_time is updated, and ttl is copied). Note,
   more trusted entries overwrite the less trusted ones
   (i.e. *_DNSSEC overwrites everything without _DNSSEC,
   AUTHORATIVE overwrites NON_AUTHORATIVE, and everything
   overwrites IN_PROGRESS and FAILURE states. The name
   is in the dns-format. The entry returned will have
   one reference taken, so the caller must unlock it
   after it is no longer needed. */
SshDNSRRset
ssh_dns_rrset_cache_add(SshDNSRRsetCache rrset_cache,
                        const unsigned char *name,
                        SshDNSRRsetState state,
                        SshDNSRRType type,
                        SshUInt32 ttl,
                        SshUInt32 number_of_rrs,
                        size_t array_of_rdlengths[],
                        unsigned char **array_of_rdata,
                        SshDNSRRset parent);

/* Remove name with type from the cache. This is mainly used
   to clear out the IN_PROGRESS entries from the cache. */
void
ssh_dns_rrset_cache_remove(SshDNSRRsetCache rrset_cache,
                           const unsigned char *name,
                           SshDNSRRType type);

/* Map state to string. */
const char *ssh_dns_rrsetstate_string(SshDNSRRsetState code);

/* Clean up cache. This can be called now and then to make the cache
   smaller. */
void ssh_dns_rrset_cache_clean(SshDNSRRsetCache rrset_cache);

/* Render function to render rrsetfor %@ format string for ssh_e*printf */
int ssh_dns_rrset_render(unsigned char *buf, int buf_size, int precision,
                         void *datum);

/* Enumerate the cache of valid host names. The return
   status is the handle of the item (or SSH_ADT_INVALID if
   last item), and the `rrset' is to the item itself (or
   NULL if last item). This function does not lock the
   entries in anyways, and during this there cannot be any
   calls to any of the dns library except rendering etc.
   */
SshADTHandle
ssh_dns_rrset_cache_enumerate_start(SshDNSRRsetCache rrset_cache,
                                    SshDNSRRset *rrset);
SshADTHandle
ssh_dns_rrset_cache_enumerate_next(SshDNSRRsetCache rrset_cache,
                                   SshDNSRRset *rrset,
                                   SshADTHandle prev_handle);

#endif /* SSHDNSRRSETCACHE_H */
