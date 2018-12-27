/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS query layer. This layer is used to send one query to name servers
   (given as a list of name servers and their ip-addresses).
   It will wait for the reply, or until the timeout expires.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshtimeouts.h"
#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "SshDnsQuery"

/* Query layer context structure. */
struct SshDNSQueryLayerRec {
  SshDNSTransport tcp_transport;
  SshADTContainer tcp_users;
  SshDNSTransport udp_transport;
  SshADTContainer udp_users;
  SshUInt32 initial_retransmit_time_us;
  SshUInt32 max_retransmit_time_us;
};

/* Transport of the operation. */
typedef enum {
  SSH_DNS_QUERY_UDP = 1,        /* Use UDP transport. */
  SSH_DNS_QUERY_TCP = 2         /* Use TCP transport. */
} SshDNSQueryTransport;

/* Query operation. */
typedef struct SshDNSQueryOperationRec {
  /* List of operations for each transport. */
  SshADTListHeaderStruct list_header;

  /* Transport type */
  SshDNSQueryTransport transport;

  /* Pointer to to the query layer. */
  SshDNSQueryLayer query_layer;

  /* Number of name servers to try. */
  SshUInt32 number_of_nameservers;

  /* Array of name servers. */
  SshDNSNameServer *array_of_nameservers;

  /* Array of the ip_indexes for each server. */
  SshUInt32 *ip_indexes;

  /* The index of the name server we are just now trying. */
  SshUInt32 nameserver_index;

  /* Current IP-address. */
  SshIpAddrStruct ip_address[1];

  /* Host structure where are just now sending packet. */
  SshDNSTransportHost host;

  /* Current timeout in us. */
  SshUInt32 timeout_in_us;

  /* Current operation. */
  SshOperationHandle handle;

  /* Packet to send, this have the unique ID already allocated and set. */
  unsigned char *packet;

  /* Length of the packet. */
  size_t packet_length;

  /* Flags */
  SshUInt32 flags;

  /* Callback and context to call after the operation. */
  SshDNSQueryCallback callback;
  void *context;

  /* Timeout structure, this is used to time out the operation. */
  SshTimeoutStruct timeout[1];

  /* Operation handle. */
  SshOperationHandleStruct operation_handle[1];

  /* Timer to calculate the round trip times. */
  SshTimeMeasureStruct timer[1];

  /* Zero timeout structure, this is used to go to bottom of event loop before
     going to the next round of operation. */
  SshTimeoutStruct zero_timeout[1];

} *SshDNSQueryOperation, SshDNSQueryOperationStruct;

void ssh_dns_query_send_next(void *operation);

/* Allocate query layer. This will not automatically
   allocate any transports, thus you need to call
   ssh_dns_query_layer_configure to configure and allocate
   the transport layers. This will return NULL if out of
   memory. */
SshDNSQueryLayer
ssh_dns_query_layer_allocate(void)
{
  SshDNSQueryLayer query_layer;

  query_layer = ssh_calloc(1, sizeof(*query_layer));
  if (query_layer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating query layer"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Query layer allocated"));

  query_layer->tcp_users =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSQueryOperationStruct,
                                             list_header),
                           SSH_ADT_ARGS_END);

  query_layer->udp_users =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSQueryOperationStruct,
                                             list_header),
                           SSH_ADT_ARGS_END);

  query_layer->initial_retransmit_time_us = 1000000;
  query_layer->max_retransmit_time_us = 10000000;
  if (query_layer->udp_users == NULL ||
      query_layer->tcp_users == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating query layer"));
      ssh_dns_query_layer_free(query_layer);
      return NULL;
    }
  return query_layer;
}

/* Clear all operations from the adt list. */
void ssh_dns_query_operations_clear(SshDNSQueryLayer query_layer,
                                    SshADTContainer users)
{
  SshDNSQueryOperation operation;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Clearing all operations"));

  while (ssh_adt_num_objects(users) > 0)
    {
      operation = ssh_adt_detach_from(users, SSH_ADT_BEGINNING);

      /* Cancel timeout. */
      ssh_cancel_timeout(operation->timeout);
      ssh_cancel_timeout(operation->zero_timeout);

      /* Cancel active operation. */
      if (operation->handle != NULL)
        ssh_operation_abort(operation->handle);

      /* Unregister the operation. */
      ssh_operation_unregister(operation->operation_handle);

      /* Call the callback. */
      operation->callback(SSH_DNS_UNREACHABLE, NULL, NULL, 0,
                          operation->context);

      /* Free the operation. */
      ssh_free(operation);
    }
}

/* Configure the query layer and udp and tcp transports.
   This returns true if the operation was successful, and
   FALSE if it run out of memory during the configure. In
   case of memory error some of the operations might have
   been done, and some may still be using old values. The
   query layer will still be usable even if memory error is
   received (provided it has managed to allocate at least
   one transport). */
Boolean
ssh_dns_query_layer_configure(SshDNSQueryLayer query_layer,
                              SshDNSQueryLayerConfig config)
{
  Boolean error = TRUE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Reconfiguring query layer"));

  if ((config == NULL || config->enable_udp)
      && query_layer->udp_transport == NULL)
    query_layer->udp_transport =
      ssh_dns_transport_allocate(ssh_dns_transport_spec_udp);

  if ((config == NULL || config->enable_tcp)
      && query_layer->tcp_transport == NULL)
    query_layer->tcp_transport =
      ssh_dns_transport_allocate(ssh_dns_transport_spec_tcp);

  if (config && !config->enable_udp && query_layer->udp_transport != NULL)
    {
      ssh_dns_query_operations_clear(query_layer,
                                     query_layer->udp_users);
      ssh_dns_transport_free(query_layer->udp_transport);
      query_layer->udp_transport = NULL;
    }

  if (config && !config->enable_tcp && query_layer->tcp_transport != NULL)
    {
      ssh_dns_query_operations_clear(query_layer,
                                     query_layer->udp_users);
      ssh_dns_transport_free(query_layer->tcp_transport);
      query_layer->tcp_transport = NULL;
    }

  if (config == NULL || config->enable_udp)
    {
      if (query_layer->udp_transport == NULL)
        {
          error = FALSE;
        }
      else
        {
          if (!ssh_dns_transport_configure(query_layer->udp_transport,
                                           config == NULL ? NULL :
                                           &(config->udp_config)))
            error = FALSE;
        }
    }

  if (config == NULL || config->enable_tcp)
    {
      if (query_layer->tcp_transport == NULL)
        {
          error = FALSE;
        }
      else
        {
          if (!ssh_dns_transport_configure(query_layer->tcp_transport,
                                           config == NULL ? NULL :
                                           &(config->tcp_config)))
            error = FALSE;
        }
    }

  if (config == NULL || config->initial_retransmit_time_us == 0)
    query_layer->initial_retransmit_time_us = 1000000;
  else
    query_layer->initial_retransmit_time_us =
      config->initial_retransmit_time_us;

  if (config == NULL || config->max_retransmit_time_us == 0)
    query_layer->max_retransmit_time_us = 10000000;
  else
    query_layer->max_retransmit_time_us = config->max_retransmit_time_us;

  return error;
}

void
ssh_dns_query_layer_shutdown(SshDNSQueryLayer query_layer)
{
  if (query_layer->udp_transport != NULL)
    ssh_dns_transport_shutdown(query_layer->udp_transport);
  if (query_layer->tcp_transport != NULL)
    ssh_dns_transport_shutdown(query_layer->tcp_transport);
}

/* Free query layer. There must not be any operations in
   active when this is called. */
void
ssh_dns_query_layer_free(SshDNSQueryLayer query_layer)
{
  if (query_layer->udp_transport)
    ssh_dns_transport_free(query_layer->udp_transport);
  if (query_layer->tcp_transport)
    ssh_dns_transport_free(query_layer->tcp_transport);
  if (query_layer->udp_users)
    ssh_adt_destroy(query_layer->udp_users);
  if (query_layer->tcp_users)
    ssh_adt_destroy(query_layer->tcp_users);
  SSH_DEBUG(SSH_D_HIGHSTART, ("Query Layer freed"));

  ssh_free(query_layer);
}


/* Set transport specific paramaters. */
Boolean
ssh_dns_query_layer_set_transport_params(SshDNSQueryLayer query_layer,
                                         void *udp_params,
                                         void *tcp_params)
{
  Boolean status = TRUE;

  if (query_layer->udp_transport != NULL)
    status =
        ssh_dns_transport_set_udp_listener_param(query_layer->udp_transport,
                                                 udp_params);
  if (query_layer->tcp_transport != NULL)
    status =
       ssh_dns_transport_set_tcp_connect_param(query_layer->tcp_transport,
                                               tcp_params);
  return status;
}

/* Free ID and detach from the queue. */
void ssh_dns_query_operation_free(SshDNSQueryOperation operation)
{
  /* Return host back to the pool. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing operation for ID %d",
                             SSH_GET_16BIT(operation->packet)));
  if (operation->host)
    {
      ssh_dns_transport_host_put(operation->host);
      operation->host = NULL;
    }

  switch (operation->transport)
    {
    case SSH_DNS_QUERY_UDP:
      ssh_adt_detach(operation->query_layer->udp_users,
                     (SshADTHandle) operation);
      ssh_dns_transport_id_free(operation->query_layer->udp_transport,
                                SSH_GET_16BIT(operation->packet));
      break;
    case SSH_DNS_QUERY_TCP:
      ssh_adt_detach(operation->query_layer->tcp_users,
                     (SshADTHandle) operation);
      ssh_dns_transport_id_free(operation->query_layer->tcp_transport,
                                SSH_GET_16BIT(operation->packet));
      break;
    }

  /* Free the operation. */
  ssh_free(operation);
}

/* Move to the next name server or ip address. */
void ssh_dns_query_set_next(SshDNSQueryOperation operation)
{
  Boolean next_round = FALSE;

  /* Move to the next name-server. */
  while (operation->nameserver_index++ < operation->number_of_nameservers)
    {
      if (operation->array_of_nameservers[operation->nameserver_index] !=
          NULL)
        break;
    }
  if (operation->nameserver_index >= operation->number_of_nameservers)
    {
      for(operation->nameserver_index = 0;
          operation->nameserver_index < operation->number_of_nameservers;
          operation->nameserver_index++)
        {
          if (operation->array_of_nameservers[operation->nameserver_index] !=
              NULL)
            break;
        }
      /* This has been checked earlier. */
      SSH_ASSERT(operation->nameserver_index !=
                 operation->number_of_nameservers);
      next_round = TRUE;
      operation->timeout_in_us *= 2;
    }
  else
    {
      operation->timeout_in_us += operation->timeout_in_us / 8;
    }
  if (operation->timeout_in_us >
      operation->query_layer->max_retransmit_time_us)
    operation->timeout_in_us = operation->query_layer->max_retransmit_time_us;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Moving to next name server %d for ID %d, timeout = %d",
             (int) operation->nameserver_index,
             SSH_GET_16BIT(operation->packet),
             (int) operation->timeout_in_us));

  /* We cannot call the send_next directly here, as
     otherwise we might end up in the loop, where we never
     go to the bottom of event loop, thus we will never call
     any other timers. So lets insert the timeout with very
     short time period here, so we allow other timeouts to
     be run too. */
  ssh_register_timeout(operation->zero_timeout, 0,
                       next_round ? operation->timeout_in_us : 0,
                       ssh_dns_query_send_next, operation);
}

/* Parse the result from the transport layer. */
void ssh_dns_query_result(SshDNSResponseCode error,
                          const unsigned char *return_packet,
                          size_t packet_length,
                          void *context)
{
  SshDNSQueryOperation operation = context;
  SshUInt64 round_trip_time_us;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Got result from name server %d for ID %d, error = %s (%d)",
             (int) operation->nameserver_index,
             SSH_GET_16BIT(operation->packet),
             ssh_dns_response_code_string(error), error));

  /* Stop timer. */
  ssh_time_measure_stop(operation->timer);

  /* Operation done, clear handle. */
  operation->handle = NULL;

  /* Return host back to the pool. */
  ssh_dns_transport_host_put(operation->host);
  operation->host = NULL;

  /* Set statistics. */
  round_trip_time_us =
    ssh_time_measure_stamp(operation->timer,
                           SSH_TIME_GRANULARITY_MICROSECOND);
  ssh_dns_name_server_cache_put_stats(operation->
                                      array_of_nameservers[operation->
                                                          nameserver_index],
                                      operation->ip_indexes[operation->
                                                           nameserver_index],
                                      operation->ip_address,
                                      (SshUInt32) round_trip_time_us,
                                      (error == SSH_DNS_OK));

  if (error != SSH_DNS_OK)
    {
      /* Error, try next name server or next ip. */
      ssh_dns_query_set_next(operation);
      return;
    }

  /* Return result. */
  /* Call the callback. */
  operation->callback(SSH_DNS_OK, operation->
                      array_of_nameservers[operation->nameserver_index],
                      return_packet, packet_length,
                      operation->context);

  /* Unregister the operation. */
  ssh_operation_unregister(operation->operation_handle);

  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);
  ssh_cancel_timeout(operation->zero_timeout);

  /* Free operation. */
  ssh_dns_query_operation_free(operation);
}

/* Send next packet. */
void
ssh_dns_query_send_next(void *context)
{
  SshDNSQueryOperation operation = context;
  SshDNSTransport transport = NULL;
  SshUInt32 round_trip_time_us;

  switch (operation->transport)
    {
    case SSH_DNS_QUERY_UDP:
      transport = operation->query_layer->udp_transport;
      break;
    case SSH_DNS_QUERY_TCP:
      transport = operation->query_layer->tcp_transport;
      break;
    }
  SSH_ASSERT(transport != NULL);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Sending packet to next server %d for ID %d",
             (int) operation->nameserver_index,
             SSH_GET_16BIT(operation->packet)));

  /* Get next ip. */
  ssh_dns_name_server_cache_get_ip(operation->
                                   array_of_nameservers[operation->
                                                       nameserver_index],
                                   &(operation->ip_indexes[operation->
                                                          nameserver_index]),
                                   operation->ip_address,
                                   &round_trip_time_us);

  /* If the round_trip_time_us is much longer than what we should wait,
     ignore this item, and continue to next. */
  if (operation->timeout_in_us < round_trip_time_us / 10)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Skip this ip %d, timeout too long %d",
                 (int) operation->nameserver_index,
                 (int) operation->timeout_in_us));
      ssh_dns_query_set_next(operation);
      return;
    }
  /* If the round_trip_time_us is somewhat longer than what we should wait
     then adjust it to average of the current and estimated. */
  if (operation->timeout_in_us < round_trip_time_us / 2)
    {
      round_trip_time_us = round_trip_time_us / 2 +
        operation->timeout_in_us / 2;
    }
  else if (operation->timeout_in_us >
           round_trip_time_us + round_trip_time_us / 2)
    {
      /* If the time we should wait is longer than round_trip_time_us, use
         it. */
      round_trip_time_us = operation->timeout_in_us;
    }
  else
    {
      /* Otherwise use the round_trip_time_us * 1.5 as an estimate for
         the timeout. */
      round_trip_time_us += round_trip_time_us / 2;
    }
  SSH_ASSERT(operation->host == NULL);
  operation->host = ssh_dns_transport_host_get(transport,
                                               NULL,
                                               operation->ip_address);
  if (operation->host == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot send packet to %s, memory allocation"
                             "failed",
                             ssh_dns_transport_host_name(operation->host)));
      return;
    }

  SSH_DEBUG(SSH_D_MIDOK,
                ("Send packet to %s, timeout %d",
                 ssh_dns_transport_host_name(operation->host),
                 (int) round_trip_time_us));

  ssh_time_measure_reset(operation->timer);
  ssh_time_measure_start(operation->timer);

  operation->handle = ssh_dns_transport_host_send(operation->host,
                                                  operation->packet,
                                                  operation->packet_length,
                                                  round_trip_time_us,
                                                  operation->flags,
                                                  ssh_dns_query_result,
                                                  operation);
}

/* Query timed out. */
void ssh_dns_query_timeout(void *context)
{
  SshDNSQueryOperation operation = context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Operation timed out for ID %d",
                             SSH_GET_16BIT(operation->packet)));

  /* Cancel active operation. */
  if (operation->handle != NULL)
    ssh_operation_abort(operation->handle);

  /* Unregister the operation. */
  ssh_operation_unregister(operation->operation_handle);

  /* Call the callback. */
  operation->callback(SSH_DNS_TIMEOUT, NULL, NULL, 0,
                      operation->context);

  ssh_cancel_timeout(operation->zero_timeout);

  /* Free operation. */
  ssh_dns_query_operation_free(operation);
}

/* Query was aborted. */
void ssh_dns_query_abort(void *context)
{
  SshDNSQueryOperation operation = context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Operation aborted for ID %d",
                             SSH_GET_16BIT(operation->packet)));

  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);
  ssh_cancel_timeout(operation->zero_timeout);

  /* Cancel active operation. */
  if (operation->handle != NULL)
    ssh_operation_abort(operation->handle);

  /* Free operation. */
  ssh_dns_query_operation_free(operation);
}

/* Do query to the given array of name servers. The
   array_of_nameservers is the array of pointers to the name
   servers and its size is number_of_nameservers entries.
   The packet is already formatted suitable for the DNS
   query to the packet buffer, and the ID field in the
   packet must be 0. If no reply is received before the
   timeout then the operation is aborted with error code
   SSH_DNS_TIMEOUT. The upper layer must make sure that the
   actual SshDNSNameServer entries are not freed during this
   operation (i.e. they must be locked to the cache).

   This function will copy the array itself and the packet,
   so they can be freed or modified immediately after
   this call. */
SshOperationHandle
ssh_dns_query_layer_query(SshDNSQueryLayer query_layer,
                          SshUInt32 number_of_nameservers,
                          SshDNSNameServer *array_of_nameservers,
                          const unsigned char *packet,
                          size_t packet_length,
                          SshUInt32 timeout_in_us,
                          SshUInt32 flags,
                          SshDNSQueryCallback callback,
                          void *context)
{
  SshDNSQueryOperation operation;
  SshUInt32 i;
  SshUInt16 id = 0;
  size_t len;

  len = sizeof(*operation) +
    number_of_nameservers * (sizeof(SshDNSNameServer) +
                             sizeof(SshUInt32)) +
    packet_length;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Starting operation, number of name servers = %d",
             (int) number_of_nameservers));

  if (flags & SSH_DNS_FLAGS_QUERY_USE_TCP)
    {
      if (query_layer->tcp_transport == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Operation ID %d tried to use TCP, which is not enabled",
                     SSH_GET_16BIT(packet)));
          /* Error, TCP requested, no TCP configured. */
          callback(SSH_DNS_UNREACHABLE, NULL, NULL, 0, context);
          return NULL;
        }
    }
  else if (query_layer->udp_transport == NULL)
    {
      /* Error, UDP requested, no UDP configured. */
      SSH_DEBUG(SSH_D_FAIL,
                ("Operation ID %d tried to use UDP, which is not enabled",
                 SSH_GET_16BIT(packet)));
      callback(SSH_DNS_UNREACHABLE, NULL, NULL, 0, context);
      return NULL;
    }

  operation = ssh_calloc(1, len);
  if (operation == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while starting ID %d",
                             SSH_GET_16BIT(packet)));
      callback(SSH_DNS_MEMORY_ERROR, NULL, NULL, 0, context);
      return NULL;
    }
  operation->nameserver_index =
    ssh_dns_name_server_cache_get_server(number_of_nameservers,
                                         array_of_nameservers);
  if (operation->nameserver_index == -1)
    {
      ssh_free(operation);
      callback(SSH_DNS_INTERNAL_ERROR, NULL, NULL, 0, context);
      return NULL;
    }

  if (flags & SSH_DNS_FLAGS_QUERY_USE_TCP)
    operation->transport = SSH_DNS_QUERY_TCP;
  else
    operation->transport = SSH_DNS_QUERY_UDP;

  ssh_operation_register_no_alloc(operation->operation_handle,
                                  ssh_dns_query_abort,
                                  operation);

  operation->query_layer = query_layer;
  operation->number_of_nameservers = number_of_nameservers;
  operation->array_of_nameservers = (void *)
    ((unsigned char *) operation + sizeof(*operation));
  memcpy(operation->array_of_nameservers, array_of_nameservers,
         number_of_nameservers * sizeof(SshDNSNameServer));
  operation->ip_indexes = (void *)
    ((unsigned char *) operation +
     sizeof(*operation) + number_of_nameservers * sizeof(SshDNSNameServer));
  for (i = 0; i < number_of_nameservers; i++)
    operation->ip_indexes[i] = SSH_DNS_NAME_SERVER_FIRST;
  operation->packet = (unsigned char *) operation + sizeof(*operation) +
    number_of_nameservers * (sizeof(SshDNSNameServer) + sizeof(SshUInt32));
  memcpy(operation->packet, packet, packet_length);
  operation->packet_length = packet_length;
  operation->flags = flags;
  operation->callback = callback;
  operation->context = context;
  operation->timeout_in_us = query_layer->initial_retransmit_time_us;
  ssh_time_measure_init(operation->timer);

  switch (operation->transport)
    {
    case SSH_DNS_QUERY_UDP:
      ssh_adt_insert(query_layer->udp_users, operation);
      id = ssh_dns_transport_id(query_layer->udp_transport);
      break;
    case SSH_DNS_QUERY_TCP:
      ssh_adt_insert(query_layer->tcp_users, operation);
      id = ssh_dns_transport_id(query_layer->tcp_transport);
      break;
    }
  SSH_PUT_16BIT(operation->packet, id);

  SSH_DEBUG(SSH_D_LOWOK, ("Operation id = %d", id));

  ssh_register_timeout(operation->timeout, 0, timeout_in_us,
                       ssh_dns_query_timeout, operation);

  ssh_dns_query_send_next(operation);
  return operation->operation_handle;
}

/* Register random number generator to the DNS library. By default the dns
   library uses ssh_rand (which needs to be seeded externally before dns
   library is used), but that is not safe enough for high security
   applications. High security applications needs to initialize the
   cryptolibrary and register the ssh_random_get_uint32 as random number
   function to the dns library. */
void ssh_dns_query_layer_register_random_func(SshDNSQueryLayer query_layer,
                                              SshUInt32 (*rand_func)(void))
{
  if (query_layer->tcp_transport)
    ssh_dns_transport_register_random_func(query_layer->tcp_transport,
                                           rand_func);
  if (query_layer->udp_transport)
    ssh_dns_transport_register_random_func(query_layer->udp_transport,
                                           rand_func);
}
