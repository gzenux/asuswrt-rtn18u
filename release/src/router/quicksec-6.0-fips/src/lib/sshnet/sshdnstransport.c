/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS Transport layer
   This layer will send one packet using specified transport. It does not
   retransmit packets. It will wait reply for specified time and call
   callback when reply is received.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshadt_intmap.h"
#include "sshobstack.h"
#include "sshfsm.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshrand.h"
#include "sshudp.h"
#include "sshtcp.h"

#define SSH_DEBUG_MODULE "SshDnsTransport"

SSH_FSM_STEP(ssh_dns_transport_fsm_wait);
SSH_FSM_STEP(ssh_dns_transport_fsm_open_start);
SSH_FSM_STEP(ssh_dns_transport_fsm_open_done);
SSH_FSM_STEP(ssh_dns_transport_fsm_error);
SSH_FSM_STEP(ssh_dns_transport_fsm_send);
SSH_FSM_STEP(ssh_dns_transport_fsm_close);

#ifdef DEBUG_LIGHT
SSH_RODATA
SshFSMStateDebugStruct ssh_dns_transport_host_fsm_names[] =
{
  SSH_FSM_STATE("transport_wait", "Waiting for request",
                ssh_dns_transport_fsm_wait)
  SSH_FSM_STATE("transport_open", "Opening connection",
                ssh_dns_transport_fsm_open_start)
  SSH_FSM_STATE("transport_open_done", "Connection open done",
                ssh_dns_transport_fsm_open_done)
  SSH_FSM_STATE("transport_error", "Something went wrong",
                ssh_dns_transport_fsm_error)
  SSH_FSM_STATE("transport_send", "Sending packets to remote end",
                ssh_dns_transport_fsm_send)
  SSH_FSM_STATE("transport_close", "Closing the connection",
                ssh_dns_transport_fsm_close)
};

const int ssh_dns_transport_host_fsm_names_count =
  SSH_FSM_NUM_STATES(ssh_dns_transport_host_fsm_names);
#endif /* DEBUG_LIGHT */

/* Operation structure. */
typedef struct SshDNSTransportOpRec {
  /* Linked list of operations on the host. */
  struct SshDNSTransportOpRec *next;

  /* Operation handle. */
  SshOperationHandleStruct operation_handle[1];

  /* Timeout structure. */
  SshTimeoutStruct timeout[1];

  /* Pointer back to the host. */
  SshDNSTransportHost host;

  /* Callback and context to return result. */
  SshDNSTransportCallback callback;
  void *context;

  /* Length of the stored packet. */
  size_t packet_length;

#define SSH_DNS_TRANSPORT_OPERATION_FLAG_SENDING        0x4000000
#define SSH_DNS_TRANSPORT_OPERATION_FLAG_REQUEST_SENT   0x8000000
  /* Flags */
  SshUInt32 flags;

  /* This must be the last entry, it is used to store the packet. Its size is 1
     as some compilers do not like arrays of 0 items. The actual size is the
     packet_length bytes. */
  unsigned char packet[1];
} *SshDNSTransportOp, SshDNSTransportOpStruct;

/* Host state machine state. */
typedef enum {
  SSH_DNS_TRANSPORT_HOST_STATE_IDLE = 1,
  SSH_DNS_TRANSPORT_HOST_STATE_OPENING = 2,
  SSH_DNS_TRANSPORT_HOST_STATE_OPEN = 3
} SshDNSTransportHostState;

typedef union SshDNSTransportImplRec {
  unsigned long long_data;      /* Make sure this is aligned to be suitable */
  double double_data;           /* for any data. */
  void *pointer_data;
} *SshDNSTransportImpl, SshDNSTransportImplUnion;

/* Host structure. */
struct SshDNSTransportHostRec {
  /* The host_bag_header must be first item, so we can cast the SshADTHandle to
     the SshDNSTransportHost structure. */
  SshADTBagHeaderStruct host_bag_header;
  SshADTListHeaderStruct free_list_header;

  SshDNSTransport transport;

  /* Thread handle. */
  SshFSMThreadStruct thread[1];

  /* Timeout structure, used for the timer which will close the connection
     after some idle time. */
  SshTimeoutStruct timeout[1];

  /* Lower layer operation handle. */
  SshOperationHandle handle;

  /* Source and destination IP. */
  SshIpAddrStruct from_ip[1];
  SshIpAddrStruct to_ip[1];

  /* Name of the connection. "ipaddr -> ipaddr". Used for debugging prints,
     this is not mallocated, but instead it is allocated after the main
     structure. */
  unsigned char *name;

  /* Reference count. */
  SshUInt32 ref_cnt;

  /* State of the connection. */
  SshDNSTransportHostState state;

  /* List of operations waiting to be processed. Immediately when the request
     has been sent out then the request is removed from this list. */
  SshDNSTransportOp operations;

  /* Error code to return to aborted connections. */
  SshDNSResponseCode error;

  /* This must be the last entry, it is used to store the implementation
     specific data. Its size will depend on the implementation, and it is
     always padded to be suitable for any data. */
  SshDNSTransportImplUnion implementation_data[1];
};

typedef struct SshDNSTransportHostRec SshDNSTransportHostStruct;

/* Transport structure. */
struct SshDNSTransportRec {
  /* Implementation functions. */
  SshDNSTransportSpecStruct spec;
  /* Implementation specific helper data. */
  void *spec_context;

  /* Close timeout. I.e. how long to keep the connection open and idle after
     operation in useconds. */
  SshUInt32 close_timeout_us;

  /* Maximum number of total memory used by transport. Default is 16 kB. This
     includes memory used for host structures and queued packets waiting to be
     sent. */
  size_t max_memory;
  size_t memory_used;

  /* Number of hosts to keep even when not used (will not affect at all if
     smaller than prealloc). Default is 4. */
  SshUInt32 keep_hosts;

  /* Maximum number of hosts. Default is 64. */
  SshUInt32 max_hosts;

  /* Total number of allocated hosts. */
  SshUInt32 total_hosts;

  /* Current id, this is the next id which will be given out. */
  SshUInt16 current_id;

  /* Container containing mapping from ID to the operation structure, or NULL
     if there is no operation ongoing with that ID. */
  SshADTContainer id_intmap;

  /* Container containing the mapping from the source and destination IP to the
     host structure. The key is the from_ip and to_ip. */
  SshADTContainer host_bag;

  /* List of free entries in the host_bag. These entries are still valid,
     but they can be reused at will. */
  SshADTContainer free_list;

  /* FSM for operations. */
  SshFSMStruct fsm[1];

  /* Random number generator to use in dns library. By default
     this is ssh_rand, but it should be switched to ssh_random_get_uint32
     by the application program by calling
     ssh_dns_resolver_register_random_func after crypto library has been
     initialized. */
  SshUInt32 (*rand_func)(void);
};

/* Hash function for hosts. */
SshUInt32 ssh_dns_transport_host_adt_hash(void *ptr, void *ctx)
{
  SshDNSTransportHost host = ptr;
  return SSH_IP_HASH(host->from_ip) ^ SSH_IP_HASH(host->to_ip);
}

/* Compare function for hosts. */
int ssh_dns_transport_host_adt_cmp(void *ptr1, void *ptr2, void *ctx)
{
  SshDNSTransportHost host1 = ptr1;
  SshDNSTransportHost host2 = ptr2;
  int ret;

  ret = SSH_IP_CMP(host1->from_ip, host2->from_ip);
  if (ret != 0)
    return ret;
  return SSH_IP_CMP(host1->to_ip, host2->to_ip);
}

/**********************************************************************/
/* Transport layer. This layer takes care of the transport
   protocols TCP/UDP. There is only one transport per each
   protocol allocated for given application. */

/* Allocate transport handle. This operation is normally
   done only once during the initialization of the library.
   The caches etc are allocated using default sizes, and
   normally application will call ssh_dns_transport_configure
   immediately after this to configure the caches sizes.
   This will return NULL if out of memory. */
SshDNSTransport
ssh_dns_transport_allocate(const SshDNSTransportSpecStruct *specification)
{
  SshDNSTransport transport;

  transport = ssh_calloc(1, sizeof(*transport));
  if (transport == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating transport %s",
                             specification->name));
      return NULL;
    }
  SSH_DEBUG(SSH_D_HIGHSTART, ("Transport %s allocated",
                              specification->name));

  transport->spec = *specification;
  /* Adjust the size_of_implemenation_structure to contain the size of the host
     structure + size_of_implemenation_structure. */
  transport->spec.size_of_implemenation_structure +=
    sizeof(SshDNSTransportHostStruct) - sizeof(SshDNSTransportImplUnion);
  transport->close_timeout_us = 30000000; /* 30 seconds. */
  transport->max_memory = 16384;
  transport->memory_used = sizeof(*transport);
  transport->keep_hosts = 4;
  transport->max_hosts = 64;
  transport->total_hosts = 0;
  transport->current_id = 0;
  transport->rand_func = ssh_rand;
  transport->id_intmap = ssh_adt_create_intmap();
  transport->host_bag =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HASH,
                           ssh_dns_transport_host_adt_hash,
                           SSH_ADT_COMPARE,
                           ssh_dns_transport_host_adt_cmp,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSTransportHostStruct,
                                             host_bag_header),
                           SSH_ADT_ARGS_END);
  transport->free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSTransportHostStruct,
                                             free_list_header),
                           SSH_ADT_ARGS_END);

  ssh_fsm_init(transport->fsm, transport);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(transport->fsm,
                               ssh_dns_transport_host_fsm_names,
                               ssh_dns_transport_host_fsm_names_count);
#endif /* DEBUG_LIGHT */
  if (transport->id_intmap == NULL || transport->host_bag == NULL ||
      transport->free_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating adt maps"));
      ssh_dns_transport_free(transport);
      return NULL;
    }
  return transport;
}

/* Allocate host. */
SshDNSTransportHost
ssh_dns_transport_host_allocate(SshDNSTransport transport,
                                SshIpAddr from_ip,
                                SshIpAddr to_ip)
{
  SshDNSTransportHost host;
  SshADTHandle h;
  unsigned char tmp[80];
  size_t len;

  ssh_snprintf(tmp, sizeof(tmp), "%s %@ -> %@",
               transport->spec.name,
               ssh_ipaddr_render, from_ip,
               ssh_ipaddr_render, to_ip);
  len = ssh_ustrlen(tmp) + 1;

  if (transport->total_hosts >= transport->max_hosts)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate host %s because of max_hosts limit",
                 tmp));
      return NULL;
    }

  if (transport->memory_used + len +
      transport->spec.size_of_implemenation_structure > transport->max_memory)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate host %s because of max_memory limit",
                 tmp));
      return NULL;
    }

  host = ssh_calloc(1, transport->spec.size_of_implemenation_structure + len);
  if (host == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate host because of out of memory"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Allocating new transport host %s", tmp));

  *host->from_ip = *from_ip;
  *host->to_ip = *to_ip;
  host->name = (unsigned char *)host +
    transport->spec.size_of_implemenation_structure;
  ssh_ustrcpy(host->name, tmp);

  h = ssh_adt_insert(transport->host_bag, host);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while inserting to host bag"));
      ssh_free(host);
      return NULL;
    }
  host->ref_cnt = 0;
  host->transport = transport;

  ssh_fsm_thread_init(transport->fsm,
                      host->thread,
                      ssh_dns_transport_fsm_wait,
                      NULL, NULL, host);
#ifdef DEBUG_LIGHT
  ssh_fsm_set_thread_name(host->thread, ssh_sstr(host->name));
#endif /* DEBUG_LIGHT */
  host->state = SSH_DNS_TRANSPORT_HOST_STATE_IDLE;
  transport->total_hosts++;
  transport->memory_used += transport->spec.size_of_implemenation_structure;
  return host;
}

/* Return name. This is valid as long as the host structure is valid. */
const unsigned char *ssh_dns_transport_host_name(SshDNSTransportHost host)
{
  return host->name;
}

/* Free host. */
void
ssh_dns_transport_host_free(SshDNSTransport transport,
                            SshDNSTransportHost host)
{
  ssh_adt_detach_object(transport->host_bag, host);
  /* Cancel the close timeout. */
  ssh_cancel_timeout(host->timeout);
  /* Abort the lower level async operation. */
  if (host->handle != NULL)
    ssh_operation_abort(host->handle);
  /* There should not be any active operations, as if there is operation
     active, it should also have the reference taken. */
  SSH_ASSERT(host->operations == NULL);

  /* Close the lower level connection if it is open. */
  if (host->state == SSH_DNS_TRANSPORT_HOST_STATE_OPEN)
    transport->spec.close_function(host, (void *) host->implementation_data);

  ssh_fsm_kill_thread(host->thread);
  transport->memory_used -= transport->spec.size_of_implemenation_structure;
  transport->total_hosts--;
  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing host %s", host->name));
  ssh_free(host);
}

/* Verify that limits are matched, i.e. free extra host items etc. */
void
ssh_dns_transport_verify_limits(SshDNSTransport transport)
{
  SshDNSTransportHost host;

  SSH_DEBUG(SSH_D_LOWSTART, ("Verifying the %s transport cache limits",
                             transport->spec.name));

  if ((transport->total_hosts >= transport->keep_hosts * 9 / 10 ||
       transport->memory_used >= transport->max_memory * 9 / 10) &&
      ssh_adt_num_objects(transport->free_list) > 0)
    {
      while((transport->total_hosts >= transport->keep_hosts * 8 / 10 ||
             transport->memory_used >= transport->max_memory * 8 / 10) &&
            ssh_adt_num_objects(transport->free_list) > 0)
        {
          host = ssh_adt_detach_from(transport->free_list,
                                     SSH_ADT_BEGINNING);
          SSH_ASSERT(host != NULL);
          if (SSH_FSM_IS_THREAD_RUNNING(host->thread))
            {
              /* We cannot remove the host while it is
                 running, so put it back to the list. */
              /* Insert it back to the list at the end. */
              ssh_adt_insert(transport->free_list, host);
              /* Stop the process now. */
              break;
            }
          ssh_dns_transport_host_free(transport, host);
        }
      /* No more entries in the free list, we cannot
         free more entries now. Must wait until there are
         more free entries before we can fullfill the new
         max_host limit. */
    }
}

/* Reconfigure cache etc information for the transport. This
   can be called at any time, and this will clear all the
   caches and automatically abort all active operations
   (with timeout). This returns true if the operation was
   successful, and FALSE if it run out of memory during the
   configure. In case of memory error some of the operations
   might have been done, and some may still be using old
   values. The transport will still be usable even if memory
   error is received. */
Boolean
ssh_dns_transport_configure(SshDNSTransport transport,
                            SshDNSTransportConfig config)
{
  SshDNSTransportHostStruct host[1];
  SshDNSTransportHost hostptr;
  SshIpAddrStruct from_ip[1];
  SshIpAddrStruct to_ip[1];
  int cnt;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Reconfiguring %s transport",
                              transport->spec.name));

  if (config == NULL)
    {
      transport->close_timeout_us = 0;
      transport->max_memory = 0;
      transport->keep_hosts = 0;
      transport->max_hosts = 0;
    }
  else
    {
      transport->close_timeout_us = config->close_timeout_us;
      transport->max_memory = config->max_memory;
      transport->keep_hosts = config->keep_hosts;
      transport->max_hosts = config->max_hosts;
    }

  if (transport->keep_hosts == 0)
    transport->keep_hosts = 4;
  if (transport->max_hosts == 0)
    transport->max_hosts = 64;
  if (transport->max_memory == 0)
    transport->max_memory = 16384;
  if (transport->close_timeout_us == 0)
    transport->close_timeout_us = 30000000;

  if (transport->keep_hosts >= transport->max_hosts)
    transport->keep_hosts = transport->max_hosts;
  if (config != NULL && config->prealloc_hosts >= transport->max_hosts)
    transport->max_hosts = config->prealloc_hosts;

  memset(from_ip, 0xff, sizeof(*from_ip));
  memset(to_ip, 0, sizeof(*to_ip));
  memset(host, 0, sizeof(*host));
  SSH_IP_UNDEFINE(from_ip);
  cnt = 0;
  if (config != NULL)
    {
      while (config->prealloc_hosts > transport->total_hosts)
        {
          SSH_INT_TO_IP4(to_ip, cnt);
          *host->from_ip = *from_ip;
          *host->to_ip = *to_ip;
          if (ssh_adt_get_handle_to_equal(transport->host_bag, host) ==
              SSH_ADT_INVALID)
            {
              hostptr =
                ssh_dns_transport_host_allocate(transport, from_ip, to_ip);
              if (hostptr == NULL)
                return FALSE;
              ssh_adt_insert(transport->free_list, hostptr);
            }
          cnt++;
        }
    }
  ssh_dns_transport_verify_limits(transport);
  return TRUE;
}

void ssh_dns_transport_shutdown(SshDNSTransport transport)
{
  SshUInt32 keep_hosts;

  if (transport->host_bag != NULL && transport->free_list != NULL)
    {
      keep_hosts = transport->keep_hosts;
      transport->keep_hosts = 0;
      ssh_dns_transport_verify_limits(transport);
      transport->keep_hosts = keep_hosts;
    }
}

/* Free transport. There MUST not be any host structures
   allocated when this is called. */
void ssh_dns_transport_free(SshDNSTransport transport)
{
  SshADTHandle h;
  SshDNSTransportHost host;

  /* First we need to cancel all hosts which are in opening state. They do have
     one extra reference, thus will not be freed otherwise. */
  if (transport->host_bag != NULL)
    {
      h = ssh_adt_enumerate_start(transport->host_bag);
      while (h != SSH_ADT_INVALID)
        {
          host = ssh_adt_get(transport->host_bag, h);
          /* Check if we are in the opening state. */
          if (host->state == SSH_DNS_TRANSPORT_HOST_STATE_OPENING)
            {
              /* Abort the lower level operation. */
              if (host->handle != NULL)
                ssh_operation_abort(host->handle);
              host->handle = NULL;
              /* And free the extra reference taken during opening. */
              ssh_dns_transport_host_unlock(host);
              host->state = SSH_DNS_TRANSPORT_HOST_STATE_IDLE;
              SSH_DEBUG(SSH_D_ERROR,
                        ("Entry name %s still in opening phase, abortted",
                         host->name));
            }
          h = ssh_adt_enumerate_next(transport->host_bag, h);
        }
    }

  /* This will free everything on the free list, as we move everything there.
     Note, that we cannot have any requests out when this is called, thus after
     this the total_hosts should be 0. */
  if (transport->host_bag != NULL && transport->free_list != NULL)
    {
      transport->keep_hosts = 0;
      ssh_dns_transport_verify_limits(transport);
    }
  if (transport->host_bag != NULL)
    {
#ifdef DEBUG_LIGHT
      h = ssh_adt_enumerate_start(transport->host_bag);
      while (h != SSH_ADT_INVALID)
        {
          host = ssh_adt_get(transport->host_bag, h);
          SSH_DEBUG(SSH_D_ERROR, ("Entry name %s still in bag ref_cnt = %d",
                                  host->name,
                                  (int) host->ref_cnt));
          h = ssh_adt_enumerate_next(transport->host_bag, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(transport->host_bag) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(transport->host_bag);
    }
  if (transport->free_list != NULL)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle h;
      SshDNSTransportHost host;

      h = ssh_adt_enumerate_start(transport->free_list);
      while (h != SSH_ADT_INVALID)
        {
          host = ssh_adt_get(transport->free_list, h);
          SSH_DEBUG(SSH_D_ERROR,
                    ("Entry name %s still in free_list ref_cnt = %d",
                     host->name, (int) host->ref_cnt));
          h = ssh_adt_enumerate_next(transport->free_list, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(transport->free_list) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(transport->free_list);
    }
  if (transport->id_intmap != NULL)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle h;
      void *ptr;

      h = ssh_adt_enumerate_start(transport->id_intmap);
      while (h != SSH_ADT_INVALID)
        {
          ptr = ssh_adt_get(transport->id_intmap, h);
          SSH_DEBUG(SSH_D_ERROR, ("Entry with ptr %p still in intmap",
                                  ptr));
          h = ssh_adt_enumerate_next(transport->id_intmap, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(transport->id_intmap) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(transport->id_intmap);
    }
  ssh_fsm_uninit(transport->fsm);
  /* Free the lower layer specific data as well */
  if (transport->spec_context)
    ssh_free(transport->spec_context);
  SSH_DEBUG(SSH_D_HIGHSTART, ("%s Transport freed", transport->spec.name));
  ssh_free(transport);
}

/* Allocate unique ID for the request. This will be global
   to the transport protocol. */
SshUInt16 ssh_dns_transport_id(SshDNSTransport transport)
{
  /* Note, we cannot use cryptographically strong random numbers directly here,
     as we cannot make forward reference from util library to the crypto
     library. We use random number callback here, which by default is ssh_rand,
     but which can be changed to ssh_random_get_uint32 by the application by
     calling ssh_dns_resolver_register_random_func function.  */
  transport->current_id = (*transport->rand_func)() & 0xffff;
  while (ssh_adt_intmap_exists(transport->id_intmap,
                               (SshUInt32) transport->current_id))
    transport->current_id =  (*transport->rand_func)() & 0xffff;
  ssh_adt_intmap_add(transport->id_intmap,
                     (SshUInt32) transport->current_id,
                     NULL);
  SSH_DEBUG(SSH_D_LOWSTART, ("Allocate new ID %d from %s transport",
                             transport->current_id,
                             transport->spec.name));
  return transport->current_id;
}

/* Free unique ID. */
void
ssh_dns_transport_id_free(SshDNSTransport transport, SshUInt16 id)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Free ID %d to %s",
                             id, transport->spec.name));
  SSH_ASSERT(ssh_adt_intmap_exists(transport->id_intmap, (SshUInt32) id));
  SSH_ASSERT(ssh_adt_intmap_get(transport->id_intmap, (SshUInt32) id) == NULL);
  ssh_adt_intmap_remove(transport->id_intmap, (SshUInt32) id);
}


/* Register random number generator to the DNS library. By default the dns
   library uses ssh_rand (which needs to be seeded externally before dns
   library is used), but that is not safe enough for high security
   applications. High security applications needs to initialize the
   cryptolibrary and register the ssh_random_get_uint32 as random number
   function to the dns library. */
void ssh_dns_transport_register_random_func(SshDNSTransport transport,
                                            SshUInt32 (*rand_func)(void))
{
  transport->rand_func = rand_func;
}

/* Return random number using configure random number function. */
SshUInt32 ssh_dns_transport_random_number(SshDNSTransportHost host)
{
  return (*host->transport->rand_func)();
}

/**********************************************************************/
/* Transport host layer. This is the host specific structure
   allocated from the pool of host structures. The DNS
   should only keep minimum amount of hosts allocated at one
   time, i.e. it should free the host immediately when not
   needed any more. The hosts structures are reference
   counted, thus there is no need to try to combine the
   hosts in the upper layer, instead allocate new host for
   each packet. Even when the reference count goes to zero,
   the host is not immediately freed, but only after some
   time, so if the same host is needed again soon, the old
   entry is reused. */

/* Fetch host entry for the pool, or if not found allocate
   new one. This will allocate reference to the entry. The
   port number is implicit to the transport layer, and is
   not given here. This will return NULL if out of memory.
   If from_ip is NULL then IP_ADDR_ANY is used. The source
   port is always any port. */
SshDNSTransportHost
ssh_dns_transport_host_get(SshDNSTransport transport,
                           SshIpAddr from_ip,
                           SshIpAddr to_ip)
{
  SshDNSTransportHostStruct host[1];
  SshDNSTransportHost hostptr;
  SshADTHandle h;

  SSH_DEBUG(SSH_D_LOWSTART, ("Get host %@ -> %@",
                             ssh_ipaddr_render, from_ip,
                             ssh_ipaddr_render, to_ip));
  memset(host, 0, sizeof(*host));
  if (from_ip)
    *host->from_ip = *from_ip;
  else
    memset(&(host->from_ip), 0, sizeof(SshIpAddrStruct));
  *host->to_ip = *to_ip;
  /* Search from the mapping. */
  h = ssh_adt_get_handle_to_equal(transport->host_bag, host);
  if (h == SSH_ADT_INVALID)
    {
      /* Verify limits. */
      ssh_dns_transport_verify_limits(transport);

      /* Allocate new. */
      hostptr = ssh_dns_transport_host_allocate(transport,
                                                host->from_ip,
                                                host->to_ip);

      /* Could not allocate new entry, return NULL. */
      if (hostptr == NULL)
        return NULL;

      hostptr->ref_cnt = 1;
    }
  else
    {
      hostptr = ssh_adt_get(transport->host_bag, h);
      ssh_dns_transport_host_lock(hostptr);
    }
  return hostptr;
}

/* Return host back to the pool and deallocate reference. */
void
ssh_dns_transport_host_put(SshDNSTransportHost host)
{
  host->ref_cnt--;
  if (host->ref_cnt == 0)
    {
      ssh_adt_insert(host->transport->free_list, host);
      SSH_DEBUG(SSH_D_LOWSTART, ("Putting host %s back to free list",
                                 host->name));
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Putting host %s back", host->name));
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Ref_cnt for %s is now %d",
                          ssh_dns_transport_host_name(host),
                          (int) host->ref_cnt));
  ssh_dns_transport_verify_limits(host->transport);
}

/* Take a reference to the host. */
void
ssh_dns_transport_host_lock(SshDNSTransportHost host)
{
  if (host->ref_cnt == 0)
    {
      /* Remove it from the free list. */
      ssh_adt_detach_object(host->transport->free_list, host);
      SSH_DEBUG(SSH_D_LOWOK,
                ("Found old entry from freelist, reusing it"));
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Found old entry, reusing it"));
    }
  host->ref_cnt++;
  SSH_DEBUG(SSH_D_LOWOK, ("Ref_cnt for %s is now %d",
                          ssh_dns_transport_host_name(host),
                          (int) host->ref_cnt));
}

/* Unlock reference. */
void
ssh_dns_transport_host_unlock(SshDNSTransportHost host)
{
  ssh_dns_transport_host_put(host);
}

/* Remove the operation structure from the id_map and free the operation
   structure. */
void ssh_dns_transport_operation_free(SshDNSTransportOp operation)
{
  SSH_ASSERT(operation->next == NULL);
  SSH_DEBUG(SSH_D_LOWOK, ("Freeing operation from %s",
                          operation->host->name));

  ssh_adt_intmap_set(operation->host->transport->id_intmap,
                     (SshUInt32) SSH_GET_16BIT(operation->packet), NULL);
  ssh_free(operation);
}

/* Remove the operation from the operations list, if it is there. */
void
ssh_dns_transport_remove_from_operations_queue(SshDNSTransportOp
                                               operation)
{
  SshDNSTransportHost host;
  SshDNSTransportOp *op;

  SSH_DEBUG(SSH_D_LOWOK, ("Removing operations from %s queue",
                          operation->host->name));

  host = operation->host;
  op = &host->operations;

  while (*op != NULL)
    {
      if (*op == operation)
        {
          *op = operation->next;
          operation->next = NULL;
          break;
        }
      op = &((*op)->next);
    }
  return;
}

/* Call the final callback, and free the operation. Cancel timeout, unregister
   operation, call callback and free the operation. The operation cannot be on
   the operations list, thus no need to remove it from there. */
void ssh_dns_transport_operation_callback(SshDNSTransportOp operation,
                                          SshDNSResponseCode error,
                                          const unsigned char *received_packet,
                                          size_t packet_length)
{
  SshDNSTransportCallback callback;
  void *context;

  SSH_DEBUG(SSH_D_LOWOK, ("Calling callback for %s",
                          operation->host->name));

  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);
  /* Unregister the operation. */
  ssh_operation_unregister(operation->operation_handle);

  callback = operation->callback;
  context = operation->context;

  /* Free the operation. */
  ssh_dns_transport_operation_free(operation);
  /* Call callback. */
  callback(error, received_packet, packet_length, context);
}

/* Operation timed out. We need to remove it from the queue, and then
   unregister operation, call callback and free the operation. We must not
   cancel the timeout. */
void ssh_dns_transport_host_timeout(void *context)
{
  SshDNSTransportOp operation = context;
  SshDNSTransportCallback callback;
  void *callback_context;

  SSH_DEBUG(SSH_D_LOWOK, ("Operation timed out %s", operation->host->name));

  /* Check if we are sending this exact operation, and if so, then abort
     the sending. */
  if (operation->flags & SSH_DNS_TRANSPORT_OPERATION_FLAG_SENDING)
    {
      if (operation->host->handle != NULL)
        ssh_operation_abort(operation->host->handle);
    }

  /* Remove from the operations queue. */
  ssh_dns_transport_remove_from_operations_queue(operation);
  /* Unregister the operation. */
  ssh_operation_unregister(operation->operation_handle);

  callback = operation->callback;
  callback_context = operation->context;

  /* Free the operation. */
  ssh_dns_transport_operation_free(operation);
  /* Call callback. */
  callback(SSH_DNS_TIMEOUT, NULL, 0, callback_context);
}

/* Operation aborted, we cannot unregister the operation, but we must cancel
   timeout, remove operation from the operations queue, if there, and do NOT
   call callback and then free the operation. */
void ssh_dns_transport_host_abort(void *context)
{
  SshDNSTransportOp operation = context;

  SSH_DEBUG(SSH_D_LOWOK, ("Operation was aborted %s", operation->host->name));

  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);
  /* Remove from the operations queue. */
  ssh_dns_transport_remove_from_operations_queue(operation);
  /* Free the operation. */
  ssh_dns_transport_operation_free(operation);
}

/* Send packet using transport protocol to destination host
   tied to the transport host. If no reply is received after
   timeout_in_us microseconds then the operation times out.
   The callback is always called (unless operation is
   canceled). The first 16 bits of the packet is the DNS ID,
   and it is used to tie the return packets to this reply.
   Unique DNS ID is allocated with ssh_dns_transport_id
   function. The ID is global to the transport protocol, and
   will stay same for retransmissions to same and other
   hosts. */
SshOperationHandle
ssh_dns_transport_host_send(SshDNSTransportHost host,
                            const unsigned char *packet,
                            size_t packet_length,
                            SshUInt32 timeout_in_us,
                            SshUInt32 flags,
                            SshDNSTransportCallback callback,
                            void *context)
{
  SshDNSTransportOp operation;
  SshUInt16 id;

  if (host->transport->memory_used + sizeof(*operation) +
      packet_length > host->transport->max_memory)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate operation for %s because of memory limit",
                 host->name));
      callback(SSH_DNS_MEMORY_ERROR, NULL, 0, context);
      return NULL;
    }
  operation = ssh_calloc(1, sizeof(*operation) + packet_length);

  if (operation == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating operation %s",
                             host->name));
      callback(SSH_DNS_MEMORY_ERROR, NULL, 0, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting operation to %s (sending packet)",
                             host->name));

  ssh_operation_register_no_alloc(operation->operation_handle,
                                  ssh_dns_transport_host_abort,
                                  operation);

  operation->packet_length = packet_length;
  operation->flags = flags;
  memcpy(operation->packet, packet, packet_length);
  operation->callback = callback;
  operation->context = context;
  operation->host = host;

  id = SSH_GET_16BIT(packet);
  SSH_ASSERT(ssh_adt_intmap_exists(host->transport->id_intmap,
                                   (SshUInt32) id));
  SSH_ASSERT(ssh_adt_intmap_get(host->transport->id_intmap,
                                (SshUInt32) id) == NULL);
  ssh_adt_intmap_set(host->transport->id_intmap, (SshUInt32) id, operation);

  /* Attach the packet to the operations list. */
  operation->next = host->operations;
  host->operations = operation;

  /* If we are not currently doing async operation, continue the state
     machine. */
  if (host->handle == NULL)
    ssh_fsm_continue(host->thread);
  if (host->state == SSH_DNS_TRANSPORT_HOST_STATE_IDLE)
    ssh_fsm_set_next(host->thread, ssh_dns_transport_fsm_open_start);

  ssh_register_timeout(operation->timeout,
                       0, timeout_in_us,
                       ssh_dns_transport_host_timeout,
                       operation);

  return operation->operation_handle;
}

/* This function is called by the lower layer when it receives a packet. This
   can also be called with error code, which means there was an error. The
   upper layer will automatically close the connection after receiving error
   code. If the error is anything else than SSH_DNS_OK then received_packet
   will be NULL and packet_length will be zero. The received_packet must be
   complete dns packet as received from the transport, i.e. the lower layer
   must wait until it gets one complete packet, and remove any outer wrappings
   from the packet before giving it out. This function can only be called when
   the connection is open. The received_packet needs only be valid during the
   call to this function. */
void ssh_dns_transport_receive(SshDNSResponseCode error,
                               const unsigned char *received_packet,
                               size_t packet_length,
                               SshDNSTransportHost host)
{
  SshDNSTransportOp operation;

  SSH_DEBUG(SSH_D_LOWSTART, ("Received packet from %s, error code = %s (%d)",
                             host->name, ssh_dns_response_code_string(error),
                             error));

  /* Check for error. */
  if (error != SSH_DNS_OK)
    {
      /* Move the state machine to error state. */
      ssh_fsm_set_next(host->thread, ssh_dns_transport_fsm_error);
      host->error = error;
      ssh_fsm_continue(host->thread);
      return;
    }

  SSH_ASSERT(received_packet != NULL);

  /* Do some sanity checks. */
  if (packet_length < 12)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Packet from %s ignored, length %d less than 12 bytes.",
                 host->name, packet_length));
      return;
    }
  if ((received_packet[2] & 0x80) == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Packet from %s ignored, QR is zero (== request).",
                 host->name));
      return;
    }

  /* Received packet, search for the operation. */
  operation = ssh_adt_intmap_get(host->transport->id_intmap,
                                 (SshUInt32) SSH_GET_16BIT(received_packet));

  if (operation == NULL)
    {
      /* Unknown request, or no operation waiting for it anymore, ignore. */
      SSH_DEBUG(SSH_D_NETGARB,
                ("Packet from %s ignored, id %d unknown",
                 host->name, SSH_GET_16BIT(received_packet)));
      return;
    }

  if (!(operation->flags & SSH_DNS_TRANSPORT_OPERATION_FLAG_REQUEST_SENT))
    {
      /* This must be unknown request, as we haven't yet sent the request
         out, ignore the packet. */
      SSH_DEBUG(SSH_D_NETGARB,
                ("Packet from %s ignored, we haven't sent the request "
                 "yet %d unknown",
                 host->name, SSH_GET_16BIT(received_packet)));
      return;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Received packet from %s with id %d",
                                  host->name, SSH_GET_16BIT(received_packet)),
                    received_packet, packet_length);
  /* Call the callback, and free operation. */
  ssh_dns_transport_operation_callback(operation, error,
                                       received_packet, packet_length);

  return;
}

/**********************************************************************/
/* State machine. */

/* Wait for the new operation, i.e. connection is closed and idle. */
SSH_FSM_STEP(ssh_dns_transport_fsm_wait)
{
  SSH_FSM_SET_NEXT(ssh_dns_transport_fsm_open_start);
  return SSH_FSM_SUSPENDED;
}

/* Connection open callback from the lower layer. */
void ssh_dns_transport_fsm_open_cb(SshDNSResponseCode error,
                                   void *context)
{
  SshDNSTransportHost host = context;

  host->handle = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(host->thread);
  /* Error, abort all operations. */
  if (error != SSH_DNS_OK)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Open failed, return error"));
      ssh_fsm_set_next(host->thread, ssh_dns_transport_fsm_error);
      host->error = error;
      /* Free the reference taken in
         ssh_dns_transport_fsm_open_start, we need to do
         this after all others, as this might cause the host
         to disappear. */
      host->state = SSH_DNS_TRANSPORT_HOST_STATE_IDLE;
      ssh_dns_transport_host_unlock(host);
    }
  return;
}

/* Start opening the connection. */
SSH_FSM_STEP(ssh_dns_transport_fsm_open_start)
{
  SshDNSTransport transport = fsm_context;
  SshDNSTransportHost host = thread_context;

  host->state = SSH_DNS_TRANSPORT_HOST_STATE_OPENING;
  SSH_FSM_SET_NEXT(ssh_dns_transport_fsm_open_done);

  /* We need to take a reference here, so that if the
     operation times out we will not abort this connection
     attempt, but instead allow the connection to be
     established. */
  ssh_dns_transport_host_lock(host);
  SSH_FSM_ASYNC_CALL(host->handle =
                     transport->spec.
                     open_function(host, (void *) host->implementation_data,
                                   host->from_ip, host->to_ip,
                                   ssh_dns_transport_fsm_open_cb,
                                   host));
}

/* Open done, send all data into the host. */
SSH_FSM_STEP(ssh_dns_transport_fsm_open_done)
{
  SshDNSTransportHost host = thread_context;

  host->state = SSH_DNS_TRANSPORT_HOST_STATE_OPEN;
  /* Free the reference taken in
     ssh_dns_transport_fsm_open_start, as we have now marked
     the host to be open, the proper close callback will be
     called.. */
  ssh_dns_transport_host_unlock(host);

  SSH_FSM_SET_NEXT(ssh_dns_transport_fsm_send);
  return SSH_FSM_CONTINUE;
}

void ssh_dns_transport_fsm_send_cb(SshDNSResponseCode error,
                                   void *context)
{
  SshDNSTransportOp operation = context;
  SshDNSTransportHost host = operation->host;

  host->handle = NULL;
  /* Error, abort all operations. */
  if (error != SSH_DNS_OK)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Send failed, return error"));
      ssh_fsm_set_next(host->thread, ssh_dns_transport_fsm_error);
      host->error = error;
    }
  operation->flags &= ~(SSH_DNS_TRANSPORT_OPERATION_FLAG_SENDING);
  operation->flags |= SSH_DNS_TRANSPORT_OPERATION_FLAG_REQUEST_SENT;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(host->thread);
  return;
}

void ssh_dns_transport_fsm_close_timeout(void *context)
{
  SshDNSTransportHost host = context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Close timeout elapsed closing connection"));
  /* Timeout, start close. */
  ssh_fsm_set_next(host->thread, ssh_dns_transport_fsm_close);
  ssh_fsm_continue(host->thread);
  return;
}

/* Send one packet to the other end. Note, that we do only one send operation
   at time, but we do not wait for the response packet, but we do wait until
   the lower layer has managed to send the packet out. */
SSH_FSM_STEP(ssh_dns_transport_fsm_send)
{
  SshDNSTransport transport = fsm_context;
  SshDNSTransportHost host = thread_context;
  SshDNSTransportOp operation;

  /* Cancel close timeout. */
  ssh_cancel_timeout(host->timeout);

  /* If we do not have any operations, suspend the sender thread. */
  if (host->operations == NULL)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("No more operations, registering close timeout"));
      ssh_register_timeout(host->timeout,
                           0, host->transport->close_timeout_us,
                           ssh_dns_transport_fsm_close_timeout,
                           host);
      return SSH_FSM_SUSPENDED;
    }

  /* Take the operation from queue. */
  operation = host->operations;
  host->operations = operation->next;
  operation->next = NULL;
  operation->flags |= SSH_DNS_TRANSPORT_OPERATION_FLAG_SENDING;

  SSH_FSM_ASYNC_CALL(host->handle =
                     transport->spec.
                     send_function(host, (void *) host->implementation_data,
                                   operation->packet,
                                   operation->packet_length,
                                   operation->flags,
                                   ssh_dns_transport_fsm_send_cb,
                                   operation));
}

/* Error occurred. Abort all operations with error, and close connection. */
SSH_FSM_STEP(ssh_dns_transport_fsm_error)
{
  SshDNSTransportHost host = thread_context;
  SshDNSTransportOp operation;

  ssh_cancel_timeout(host->timeout);
  while (host->operations != NULL)
    {
      /* Take the operation from queue. */
      operation = host->operations;
      host->operations = operation->next;
      operation->next = NULL;

      /* Call callback. */
      ssh_dns_transport_operation_callback(operation, host->error, NULL, 0);
    }
  SSH_FSM_SET_NEXT(ssh_dns_transport_fsm_close);
  return SSH_FSM_CONTINUE;
}

/* Close the connection. */
SSH_FSM_STEP(ssh_dns_transport_fsm_close)
{
  SshDNSTransport transport = fsm_context;
  SshDNSTransportHost host = thread_context;

  if (host->state == SSH_DNS_TRANSPORT_HOST_STATE_OPEN)
    transport->spec.close_function(host, (void *) host->implementation_data);
  SSH_FSM_SET_NEXT(ssh_dns_transport_fsm_wait);
  host->state = SSH_DNS_TRANSPORT_HOST_STATE_IDLE;
  return SSH_FSM_CONTINUE;
}

/* Return implementation data for the lower level transport. */
void *ssh_dns_transport_implementation_data(SshDNSTransportHost host)
{
  return (void *) host->implementation_data;
}

Boolean
ssh_dns_transport_set_udp_listener_param(SshDNSTransport transport,
                                         void *udp_param)
{
  SshUdpListenerParams param = NULL;

  if (udp_param != NULL)
    {
      param = ssh_memdup(udp_param, sizeof (SshUdpListenerParamsStruct));
      if (param == NULL)
        return FALSE;
    }

  if (transport->spec_context != NULL)
    ssh_free(transport->spec_context);

  transport->spec_context = param;
  return TRUE;
}

Boolean
ssh_dns_transport_set_tcp_connect_param(SshDNSTransport transport,
                                        void *tcp_param)
{
  SshTcpConnectParams param = NULL;

  if (tcp_param != NULL)
    {
      param = ssh_memdup(tcp_param, sizeof (SshTcpConnectParamsStruct));
      if (param == NULL)
        return FALSE;
    }

  if (transport->spec_context != NULL)
    ssh_free(transport->spec_context);

  transport->spec_context = param;
  return TRUE;
}

void *
ssh_dns_transport_get_transport_param(SshDNSTransportHost host)
{
  SSH_ASSERT(host != NULL);
  SSH_ASSERT(host->transport != NULL);

  return host->transport->spec_context;
}
