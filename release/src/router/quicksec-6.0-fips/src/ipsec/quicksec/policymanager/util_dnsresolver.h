/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   util_dnsresolver.h
*/

#ifndef PM_DNSRESOLVER_H
#define PM_DNSRESOLVER_H

#ifdef SSHDIST_IPSEC_DNSPOLICY
typedef enum {
  SSH_PM_DNS_OC_NONE,
  SSH_PM_DNS_OC_R_INTERFACE,
  SSH_PM_DNS_OC_R_LOCAL,
  SSH_PM_DNS_OC_R_REMOTE,
  SSH_PM_DNS_OC_T_PEER,
  SSH_PM_DNS_OC_T_LOCAL
} SshPmDnsObjectClass;

typedef struct SshPmDnsCacheRec     *SshPmDnsCache;
typedef struct SshPmDnsCacheRec      SshPmDnsCacheStruct;

typedef struct SshPmDnsReferenceRec *SshPmDnsReference;
typedef struct SshPmDnsReferenceRec  SshPmDnsReferenceStruct;

typedef struct SshPmDnsObjectRec    *SshPmDnsObject;
typedef struct SshPmDnsObjectRec     SshPmDnsObjectStruct;

typedef struct SshPmDnsQueryRec     *SshPmDnsQuery;

SshPmDnsQuery ssh_pm_dns_query_pool_allocate(SshUInt16 nentries);
void ssh_pm_dns_query_pool_free(SshPmDnsQuery pool);

SshPmDnsCache ssh_pm_dns_cache_create(void);
void ssh_pm_dns_cache_destroy(SshPmDnsCache cache);

SshPmDnsReference
ssh_pm_dns_cache_insert(SshPmDnsCache cache,
                        const char *address,
                        SshPmDnsObjectClass object_class, void *object);

SshPmDnsReference
ssh_pm_dns_cache_copy(SshPmDnsCache cache, SshPmDnsReference reference,
                      void *object);

void
ssh_pm_dns_cache_remove(SshPmDnsCache cache,
                        SshPmDnsReference reference);

Boolean
ssh_pm_dns_cache_compare(SshPmDnsReference r1, SshPmDnsReference r2);

SshPmDnsStatus
ssh_pm_dns_cache_status(SshPmDnsReference reference);
#endif /* SSHDIST_IPSEC_DNSPOLICY */
#endif /* PM_DNSRESOLVER_H */
