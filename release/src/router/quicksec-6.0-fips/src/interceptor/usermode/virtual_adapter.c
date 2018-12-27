/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Virtual adapters for the user-mode interceptor.
*/





#include "sshincludes.h"
#include "usermodeinterceptor.h"
#include "usermodeinterceptor_internal.h"
#include "sshthreadedmbox.h"
#include "sshinetencode.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshUserModeInterceptorVirtualAdapter"

/******************** Allocation and freeing operations *********************/

static SshInterceptorVirtualAdapterOp
alloc_virtual_adapter_op(SshInterceptor interceptor)
{
  SshInterceptorVirtualAdapterOp op;

  op = ssh_calloc(1, sizeof(*op));
  if (op == NULL)
    return NULL;

  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);
  op->id = interceptor->virtual_adapter_op_id++;

  op->next = interceptor->virtual_adapter_operations;
  interceptor->virtual_adapter_operations = op;
  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  return op;
}


static void
free_virtual_adapter_op(SshInterceptor interceptor,
                        SshInterceptorVirtualAdapterOp op)
{
  SshInterceptorVirtualAdapterOp op_ptr, prev;

  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);

  /* Remove the operation from the list of pending operations. */
  for (prev = NULL, op_ptr = interceptor->virtual_adapter_operations;
       op_ptr && op_ptr != op;
       prev = op_ptr, op_ptr = op_ptr->next)
    ;

  if (op_ptr != NULL)
    {
      if (prev)
        prev->next = op_ptr->next;
      else
        interceptor->virtual_adapter_operations = op_ptr->next;
    }

  ssh_free(op);
  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);
}


static SshInterceptorVirtualAdapterOp
lookup_virtual_adapter_op(SshInterceptor interceptor, SshUInt32 operation_id)
{
  SshInterceptorVirtualAdapterOp op;

  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);

  /* Lookup the operation from the list of pending operations. */
  for (op = interceptor->virtual_adapter_operations;
       op && op->id != operation_id;
       op = op->next)
    ;

  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  return op;
}


static void
virtual_adapter_operation_abort(void *operation_context)
{
  SshInterceptorVirtualAdapterOp op = operation_context;

  op->aborted = TRUE;
  op->handle = NULL;
}


/********************** Virtual adapter API functions ***********************/

/* Engine to interceptor */

void
ssh_virtual_adapter_send(SshInterceptor interceptor,
                            SshInterceptorPacket pp)
{
  unsigned char *packetptr, *packetbuf, *internal;
  size_t packet_len, internal_len;

  packet_len = ssh_interceptor_packet_len(pp);

#ifdef SSH_USERMODE_INTERCEPTOR_ENABLE_TESTS
  /* Linearize the packet. */
  packetbuf = ssh_usermode_interceptor_packet_copy_to_buf(pp, &packet_len);
  if (!packetbuf)
    {
      /* Free the original packet object. */
      ssh_interceptor_packet_free(pp);
      return;
    }
  packetptr = packetbuf;
#else /* SSH_USERMODE_INTERCEPTOR_ENABLE_TESTS */
  /* Avoid unnecessary copying of packet data, as the internal packet
     data buffer is already linearized. */
  packetptr = ssh_usermode_interceptor_packet_ptr(pp, &packet_len);
  SSH_ASSERT(packetptr != NULL);
  packetbuf = NULL;
#endif /* SSH_USERMODE_INTERCEPTOR_ENABLE_TESTS */

  internal = NULL;
  if (!ssh_interceptor_packet_export_internal_data(pp, &internal,
                                                   &internal_len))
    {
      ssh_free(packetbuf);
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending send request for virtual adapter %d to forwarder.",
             (int) pp->ifnum_out));

  /* Send the packet to the kernel forwarder module. */
  ssh_usermode_interceptor_send_encode(
                        interceptor,
                        SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_SEND,
                        SSH_FORMAT_UINT32, pp->ifnum_in,
                        SSH_FORMAT_UINT32, pp->ifnum_out,
                        SSH_FORMAT_UINT32, pp->protocol,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                        SSH_FORMAT_UINT16, pp->route_selector,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                        SSH_FORMAT_UINT16, (SshUInt16) 0,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                        SSH_FORMAT_UINT32_STR, packetptr, packet_len,
                        SSH_FORMAT_UINT32_STR, internal, internal_len,
                        SSH_FORMAT_END);

  /* Free the linearized packet. */
  ssh_free(packetbuf);

  /* Free internal data buffer. */
  ssh_free(internal);

  /* Free the original packet object. */
  ssh_interceptor_packet_free(pp);
}


void
ssh_virtual_adapter_attach(SshInterceptor interceptor,
                           SshInterceptorIfnum adapter_ifnum,
                           SshVirtualAdapterPacketCB packet_cb,
                           SshVirtualAdapterDetachCB detach_cb,
                           void *adapter_context,
                           SshVirtualAdapterStatusCB callback,
                           void *context)
{
  SshInterceptorVirtualAdapterOp op;

  /* Initialize an operation handle. */
  op = alloc_virtual_adapter_op(interceptor);
  if (op == NULL)
    goto fail;

  op->status_cb = callback;
  op->context = context;
  op->attach = TRUE;

  /* Operation data. */
  op->packet_cb = packet_cb;
  op->detach_cb = detach_cb;
  op->adapter_context = adapter_context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending attach request for virtual adapter %d to forwarder.",
             (int) adapter_ifnum));

  /* Send a message to the kernel forwarder module. */
  ssh_usermode_interceptor_send_encode(
                        interceptor,
                        SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_ATTACH,
                        SSH_FORMAT_UINT32, op->id,
                        SSH_FORMAT_UINT32, adapter_ifnum,
                        SSH_FORMAT_END);

  op->handle = ssh_operation_register(virtual_adapter_operation_abort, op);
  return;

 fail:
  if (callback != NULL_FNPTR)
    (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED, NULL,
                context);
}

void
ssh_virtual_adapter_detach(SshInterceptor interceptor,
                           SshInterceptorIfnum adapter_ifnum,
                           SshVirtualAdapterStatusCB status_cb,
                           void *context)
{
  SshInterceptorVirtualAdapterOp op;
  SshInterceptorVirtualAdapter va, prev_va;

  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);

  /* Remove it from the interceptor's list of active virtual adapters. */
  for (prev_va = NULL, va = interceptor->virtual_adapters;
       va;
       prev_va = va, va = va->next)
    if (va->adapter_ifnum == adapter_ifnum)
      break;

  if (va)
    {
      if (prev_va)
        prev_va->next = va->next;
      else
        interceptor->virtual_adapters = va->next;

      /* Call destruction callback */
      if (va->detach_cb)
        (*va->detach_cb)(va->adapter_context);

      /* Free the adapter. */
      ssh_free(va);
    }

  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  /* Initialize an operation handle. */
  op = alloc_virtual_adapter_op(interceptor);
  if (op == NULL)
    goto fail;

  op->status_cb = status_cb;
  op->context = context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending detach request for virtual adapter %d to forwarder.",
             (int) adapter_ifnum));

  /* Send a message to the engine. */
  ssh_usermode_interceptor_send_encode(
                        interceptor,
                        SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH,
                        SSH_FORMAT_UINT32, op->id,
                        SSH_FORMAT_UINT32, adapter_ifnum,
                        SSH_FORMAT_END);

  op->handle = ssh_operation_register(virtual_adapter_operation_abort, op);
  return;

 fail:
  if (status_cb != NULL_FNPTR)
    (*status_cb)(SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                 adapter_ifnum, NULL, SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                 NULL, context);
}


void
ssh_virtual_adapter_detach_all(SshInterceptor interceptor)
{
  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);

  /* Remove all active virtual adapters. */
  while (interceptor->virtual_adapters)
    {
      SshInterceptorVirtualAdapter va;

      va = interceptor->virtual_adapters;
      interceptor->virtual_adapters = va->next;

      /* Call destruction callback */
      if (va->detach_cb)
        (*va->detach_cb)(va->adapter_context);

      ssh_free(va);
    }

  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending detach all request to forwarder."));

  /* Send a message to the engine. */
  ssh_usermode_interceptor_send_encode(
                        interceptor,
                        SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH_ALL,
                        SSH_FORMAT_END);
}

void
ssh_virtual_adapter_configure(SshInterceptor interceptor,
                              SshInterceptorIfnum adapter_ifnum,
                              SshVirtualAdapterState adapter_state,
                              SshUInt32 num_addresses,
                              SshIpAddr addresses,
                              SshVirtualAdapterParams params,
                              SshVirtualAdapterStatusCB callback,
                              void *context)
{
  SshInterceptorVirtualAdapter va;
  SshInterceptorVirtualAdapterOp op;
  SshBufferStruct ip_buffer;
  unsigned char *param_ptr = NULL;
  size_t param_len;
  SshUInt32 i;
  SshVirtualAdapterError error = SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR;
  SshIpAddrStruct undefined_ip;

  ssh_buffer_init(&ip_buffer);

  /* Assert that this virtual adapter exists. */
  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);
  for (va = interceptor->virtual_adapters; va; va = va->next)
    if (va->adapter_ifnum == adapter_ifnum)
      break;
  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);
  SSH_ASSERT(va != NULL);

  /* Encode "clear all addresses" as one undefined address. */
  if (num_addresses == 0 && addresses != NULL)
    {
      SSH_IP_UNDEFINE(&undefined_ip);
      addresses = &undefined_ip;
      num_addresses = 1;
    }

  /* Encode IP addresses. */
  for (i = 0; i < num_addresses; i++)
    {
      if (!ssh_encode_ipaddr_buffer(&ip_buffer, &addresses[i]))
        {
          error = SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE;
          goto error;
        }
    }

  /* Encode params. */
  param_ptr = NULL;
  param_len = 0;
  if (params)
    {
      if (!ssh_virtual_adapter_param_encode(params, &param_ptr, &param_len))
        {
          error = SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE;
          goto error;
        }
    }

  /* Initialize an operation handle. */
  op = alloc_virtual_adapter_op(interceptor);
  if (op == NULL)
    {
      error = SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  op->status_cb = callback;
  op->context = context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending configure request for virtual adapter %d to forwarder.",
             (int) adapter_ifnum));

  /* Send a message to the kernel forwarder module. */
  ssh_usermode_interceptor_send_encode(
                  interceptor,
                  SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_CONFIGURE,
                  SSH_FORMAT_UINT32, op->id,
                  SSH_FORMAT_UINT32, adapter_ifnum,
                  SSH_FORMAT_UINT32, adapter_state,
                  SSH_FORMAT_UINT32, num_addresses,
                  SSH_FORMAT_UINT32_STR,
                  ssh_buffer_ptr(&ip_buffer), ssh_buffer_len(&ip_buffer),
                  SSH_FORMAT_UINT32_STR, param_ptr, param_len,
                  SSH_FORMAT_END);

  op->handle = ssh_operation_register(virtual_adapter_operation_abort, op);
  ssh_buffer_uninit(&ip_buffer);
  ssh_free(param_ptr);
  return;

 error:
  ssh_buffer_uninit(&ip_buffer);
  ssh_free(param_ptr);

  (*callback)(error, adapter_ifnum, NULL, SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
              NULL, context);
}


void ssh_virtual_adapter_get_status(SshInterceptor interceptor,
                                    SshInterceptorIfnum adapter_ifnum,
                                    SshVirtualAdapterStatusCB callback,
                                    void *context)
{
  SshInterceptorVirtualAdapterOp op = NULL;

  /* Initialize an operation handle. */
  op = alloc_virtual_adapter_op(interceptor);
  if (op == NULL)
    goto fail;

  op->status_cb = callback;
  op->context = context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending get status request for virtual adapter %d to forwarder.",
             (int) adapter_ifnum));

  /* Send a message to the kernel forwarder module. */
  ssh_usermode_interceptor_send_encode(
                        interceptor,
                        SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_GET_STATUS,
                        SSH_FORMAT_UINT32, op->id,
                        SSH_FORMAT_UINT32, adapter_ifnum,
                        SSH_FORMAT_END);

  op->handle = ssh_operation_register(virtual_adapter_operation_abort, op);
  return;

 fail:
  if (callback != NULL_FNPTR)
    (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                adapter_ifnum, NULL, SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED, NULL,
                context);
}


/******** Handle virtual adapter messages from the forwarder module *********/

/* Interceptor to engine. */

static void
receive_virtual_adapter_packet_cb(SshInterceptor interceptor,
                                  const unsigned char *data, size_t len)
{
  SshUInt32 flags;
  SshUInt32 ifnum_in, ifnum_out;
  SshUInt32 protocol;
  const unsigned char *packet, *internal;
  size_t packet_len, internal_len;
  SshInterceptorVirtualAdapter va;
  SshInterceptorPacket pp;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &flags,
                       SSH_FORMAT_UINT32, &ifnum_in,
                       SSH_FORMAT_UINT32, &ifnum_out,
                       SSH_FORMAT_UINT32, &protocol,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &packet, &packet_len,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &internal, &internal_len,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR, ("bad virtual adapter receive message"),
                        data, len);
      return;
    }

  /* Find the virtual adapter of this receive operation. */
  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);
  for (va = interceptor->virtual_adapters; va; va = va->next)
    if (va->adapter_ifnum == ifnum_in)
      break;
  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  if (va == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("virtual adapter receive for unknown adapter %d",
                 (int) ifnum_in));
      return;
    }

  if (va->packet_cb == NULL_FNPTR)
    return;

  /* Assert that the interface numbers fit into SshInterceptorIfnum. */
  SSH_ASSERT(ifnum_in <= SSH_INTERCEPTOR_MAX_IFNUM);
  SSH_ASSERT(ifnum_out <= SSH_INTERCEPTOR_MAX_IFNUM);

  /* Allocate a packet object. */
  pp = ssh_interceptor_packet_alloc(interceptor,
                                    SSH_PACKET_FROMADAPTER,
                                    protocol,
                                    (SshInterceptorIfnum) ifnum_in,
                                    (SshInterceptorIfnum) ifnum_out,
                                    packet_len);

  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("could not allocate packet for virtual adapter receive"));
      return;
    }

  if (!ssh_interceptor_packet_import_internal_data(pp, internal, internal_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("import failed"));
      return;
    }

  pp->flags = flags;

  if (!ssh_interceptor_packet_copyin(pp, 0, packet, packet_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("received packet callback for virtual adapter %d from forwarder.",
             (int) ifnum_in));

  /* Pass the packet to the user-supplied packet callback. */
  (*va->packet_cb)(interceptor, pp, va->adapter_context);
}

static void
receive_virtual_adapter_attach_cb(SshInterceptor interceptor,
                                  SshVirtualAdapterError error,
                                  SshInterceptorIfnum adapter_ifnum,
                                  unsigned char *adapter_name,
                                  SshVirtualAdapterState adapter_state,
                                  SshInterceptorVirtualAdapterOp op)
{
  SshInterceptorVirtualAdapter va;

  /* Is the operation aborted? */
  if (op->aborted)
    {
      /* The operation was successful but aborted. Let's just destroy the
         created adapter. */
      if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
        ssh_virtual_adapter_detach(interceptor, adapter_ifnum,
                                   NULL_FNPTR, NULL);

      /* Destroy the adapter context */
      if (op->detach_cb)
        (*op->detach_cb)(op->adapter_context);

      /* Free operation context. */
      free_virtual_adapter_op(interceptor, op);
      return;
    }

  if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
    {
      /* Register that we know this virtual adapter.
         This cannot fail, thus xmalloc. */
      va = ssh_xcalloc(1, sizeof(*va));

      va->adapter_ifnum = adapter_ifnum;
      va->packet_cb = op->packet_cb;
      va->detach_cb = op->detach_cb;
      va->adapter_context = op->adapter_context;

      SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);
      va->next = interceptor->virtual_adapters;
      interceptor->virtual_adapters = va;
      SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);
    }
  else
    {
      /* Destroy the context if not successful */
      if (op->detach_cb)
        (*op->detach_cb)(op->adapter_context);
      op->adapter_context = NULL;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("received attach callback for virtual adapter %d from forwarder, "
             "error %d", (int) adapter_ifnum, (int) error));

  /* Call the completion function. */
  if (op->status_cb)
    (*op->status_cb)((SshVirtualAdapterError) error,
                     (SshInterceptorIfnum) adapter_ifnum, adapter_name,
                     (SshVirtualAdapterState) adapter_state,
                     op->adapter_context, op->context);

  /* Unregister operation handle and free operation context. */
  ssh_operation_unregister(op->handle);
  free_virtual_adapter_op(interceptor, op);
}

static void
receive_virtual_adapter_status_cb(SshInterceptor interceptor,
                                  const unsigned char *data,
                                  size_t len)
{
  SshUInt32 operation_id;
  SshUInt32 error;
  SshUInt32 adapter_ifnum;
  char *adapter_name;
  SshUInt32 adapter_state;
  SshInterceptorVirtualAdapterOp op;
  SshInterceptorVirtualAdapter va;
  void *adapter_context;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &operation_id,
                       SSH_FORMAT_UINT32, &error,
                       SSH_FORMAT_UINT32, &adapter_ifnum,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &adapter_name, NULL,
                       SSH_FORMAT_UINT32, &adapter_state,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR, ("bad virtual adapter status message"),
                        data, len);
      return;
    }

  /* Lookup the pending operation. */
  op = lookup_virtual_adapter_op(interceptor, operation_id);
  if (op == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("unknown virtual adapter operation ID %d",
                              (int) operation_id));
      return;
    }

  /* Handle attach operations separately. */
  if (op->attach)
    {
      receive_virtual_adapter_attach_cb(interceptor, error,
                                        adapter_ifnum, adapter_name,
                                        adapter_state, op);
      return;
    }

  /* Is the operation aborted? */
  if (op->aborted)
    {
      /* Free the operation context. */
      free_virtual_adapter_op(interceptor, op);
      return;
    }

  /* Lookup virtual adapter. */
  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);
  for (va = interceptor->virtual_adapters; va; va = va->next)
    if (va->adapter_ifnum == adapter_ifnum)
      break;
  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  /* Take adapter context from virtual adapter, if it was found. */
  if (va == NULL)
    adapter_context = op->adapter_context;
  else
    adapter_context = va->adapter_context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("received status callback for virtual adapter %d from forwarder, "
             "error %d", (int) adapter_ifnum, (int) error));

  /* Call the completion function. */
  if (op->status_cb)
    (*op->status_cb)((SshVirtualAdapterError) error,
                     (SshInterceptorIfnum) adapter_ifnum, adapter_name,
                     (SshVirtualAdapterState) adapter_state,
                     adapter_context, op->context);

  /* Free operation context if there will be no more status callbacks
     to this operation. */
  if (error != SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE)
    {
      /* Unregister operation handle and free operation context. */
      ssh_operation_unregister(op->handle);
      free_virtual_adapter_op(interceptor, op);
    }
}


typedef struct {
  SshPacketType type;
  const unsigned char *data;
  size_t len;
} *SshReceiveVaContext;

/* Thread-boundary mbox */
extern SshThreadedMbox thread_mbox;

void
wrapper_va_receive(void *context)
{
  SshReceiveVaContext  ctx  = (SshReceiveVaContext) context;
  const unsigned char *data = ctx->data;
  size_t               len  = ctx->len;
  SshInterceptor       interceptor   = ssh_usermode_interceptor;

  SSH_ASSERT_THREAD();
  switch (ctx->type)
    {
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_STATUS_CB:
      receive_virtual_adapter_status_cb(interceptor, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_PACKET_CB:
      receive_virtual_adapter_packet_cb(interceptor, data, len);
      break;

    default:
      SSH_DEBUG(SSH_D_ERROR, ("unknown packet type %d from kernel",
                              (int) ctx->type));
      break;
    }
  ssh_free(ctx);
}

void
ssh_kernel_receive_virtual_adapter(SshPacketType type,
                                   const unsigned char *data, size_t len)
{
  SshReceiveVaContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    return;

  ctx->type = type;
  ctx->data = data;
  ctx->len  = len;

  SSH_VERIFY(ssh_threaded_mbox_send_to_thread(thread_mbox, wrapper_va_receive,
                                              ctx) == TRUE);
}
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
