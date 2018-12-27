/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit event handling.
*/

#include "sshincludes.h"
#include "sshaudit.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshAudit"

/* An audit context structure. */
struct SshAuditContextRec
{
  /* Declares which events are allowed */
  SshUInt32 event_disabled[SSH_AUDIT_MAX_VALUE / 32 + 1];

  /* A place-holder for audit arguments. */
  SshAuditArgument arguments;
  SshUInt32 arguments_allocated;

  /* Callback function and its context. */
  SshAuditCB audit_callback;
  SshAuditDestroyCB destroy_callback;
  void *callback_context;
};


/****************** Creating and destroying audit contexts ******************/


SshAuditContext ssh_audit_create(SshAuditCB audit_callback,
                                 SshAuditDestroyCB destroy_callback,
                                 void *context)
{
  SshAuditContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate audit context"));
      return NULL;
    }

  /* Allocate a decent amount of arguments already in the
     beginning. */
  ctx->arguments_allocated = 10;
  ctx->arguments = ssh_malloc(ctx->arguments_allocated
                              * sizeof(*ctx->arguments));
  if (ctx->arguments == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate array for audit arguments"));
      ssh_free(ctx);
      return NULL;
    }

  ctx->audit_callback = audit_callback;
  ctx->destroy_callback = destroy_callback;
  ctx->callback_context = context;

  return ctx;
}

void
ssh_audit_destroy(SshAuditContext context)
{
  if (context == NULL)
    return;

  if (context->destroy_callback)
    (*context->destroy_callback)(context->callback_context);

  ssh_free(context->arguments);
  ssh_free(context);
}


/************************** Handling audit events ***************************/

void
ssh_audit_event_va(SshAuditContext context, SshAuditEvent event, va_list ap)
{
  SshUInt32 argc = 0;

  SSH_ASSERT(1 <= event && event < SSH_AUDIT_MAX_VALUE);

  if (context == NULL || context->audit_callback == NULL_FNPTR)
    return;

  /* Is event disabled? */
  if (context->event_disabled[event / 32] & ((SshUInt32) 1 << (event % 32)))
    /* Yes it is. */
    return;

  /* Convert aguments into an array. */

  while (1)
    {
      SshAuditArgumentType type;
      SshAuditArgument arg;

      type = va_arg(ap, SshAuditArgumentType);

      if (type == SSH_AUDIT_ARGUMENT_END)
        /* All done. */
        break;

      /* Do we need more space for our arguments array? */
      if (argc >= context->arguments_allocated)
        {
          SshAuditArgument na;

          /* Yes. */
          na = ssh_realloc(context->arguments,
                           context->arguments_allocated * sizeof(*na),
                           (context->arguments_allocated + 10) * sizeof(*na));
          if (na == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not expand argument array: event dropped"));
              return;
            }

          context->arguments = na;
          context->arguments_allocated += 10;
        }
      SSH_ASSERT(argc < context->arguments_allocated);

      arg = &context->arguments[argc];
      arg->type = type;

      switch (type)
        {
        case SSH_AUDIT_COMMAND:
        case SSH_AUDIT_DATA_READ:
        case SSH_AUDIT_DATA_WRITTEN:
        case SSH_AUDIT_DESTINATION_ADDRESS:
        case SSH_AUDIT_DESTINATION_PORT:
        case SSH_AUDIT_ERROR_CODE:
        case SSH_AUDIT_FILE_NAME:
        case SSH_AUDIT_FTP_COMMAND:
        case SSH_AUDIT_ICMP_TYPECODE:
        case SSH_AUDIT_IPPROTO:
        case SSH_AUDIT_IPV4_OPTION:
        case SSH_AUDIT_IPV6ICMP_TYPECODE:
        case SSH_AUDIT_IPV6_FLOW_ID:
        case SSH_AUDIT_KEY_LENGTH:
        case SSH_AUDIT_SEQUENCE_NUMBER:
        case SSH_AUDIT_SESSION_ID:
        case SSH_AUDIT_SOCKS_SERVER_IP:
        case SSH_AUDIT_SOCKS_SERVER_PORT:
        case SSH_AUDIT_SOCKS_VERSION:
        case SSH_AUDIT_SOURCE_ADDRESS:
        case SSH_AUDIT_SOURCE_PORT:
        case SSH_AUDIT_SPI:
        case SSH_AUDIT_SUB_ID:
        case SSH_AUDIT_TARGET_IP:
        case SSH_AUDIT_TARGET_PORT:
        case SSH_AUDIT_TCP_FLAGS:
        case SSH_AUDIT_TOTAL_LENGTH:
        case SSH_AUDIT_TRANSMIT_BYTES:
        case SSH_AUDIT_TRANSMIT_DIGEST:
        case SSH_AUDIT_ETH_SOURCE_ADDRESS:
        case SSH_AUDIT_ETH_DESTINATION_ADDRESS:
        case SSH_AUDIT_ETH_TYPE:
        case SSH_AUDIT_SNORT_SIG_GENERATOR:
        case SSH_AUDIT_SNORT_SIG_ID:
        case SSH_AUDIT_SNORT_SIG_REV:
        case SSH_AUDIT_SNORT_CLASSIFICATION:
        case SSH_AUDIT_SNORT_PRIORITY:
        case SSH_AUDIT_SNORT_EVENT_ID:
        case SSH_AUDIT_SNORT_EVENT_REFERENCE:
        case SSH_AUDIT_SNORT_PACKET_FLAGS:
        case SSH_AUDIT_PACKET_DATA:
        case SSH_AUDIT_PACKET_LEN:

          arg->data = va_arg(ap, unsigned char *);
          arg->data_len = (size_t)va_arg(ap, int);

          /* If the length is zero, then this argument is ignored. */
          if (arg->data_len == 0)
            continue;

#ifdef DEBUG_LIGHT
          /* Special checks for IP addresses. */
          if (type == SSH_AUDIT_SOURCE_ADDRESS
              || type == SSH_AUDIT_DESTINATION_ADDRESS
              || type == SSH_AUDIT_SOCKS_SERVER_IP
              || type == SSH_AUDIT_TARGET_IP)
            SSH_ASSERT(arg->data_len == 4 || arg->data_len == 16);
          /* Check ICMP typecode length */
          if (type == SSH_AUDIT_ICMP_TYPECODE
              || type == SSH_AUDIT_IPV6ICMP_TYPECODE)
            SSH_ASSERT(arg->data_len == 2);
          if (type == SSH_AUDIT_TCP_FLAGS)
            SSH_ASSERT(arg->data_len == 1);

          /* Special checks for Ethernet addresses. */
          if (type == SSH_AUDIT_ETH_SOURCE_ADDRESS
              || type == SSH_AUDIT_ETH_DESTINATION_ADDRESS)
            SSH_ASSERT(arg->data_len == 6);
#endif /* DEBUG_LIGHT */
          break;

        case SSH_AUDIT_SOURCE_INTERFACE:
        case SSH_AUDIT_DESTINATION_INTERFACE:
        case SSH_AUDIT_PACKET_ATTACK:
        case SSH_AUDIT_PACKET_CORRUPTION:
        case SSH_AUDIT_SOURCE_ADDRESS_STR:
        case SSH_AUDIT_DESTINATION_ADDRESS_STR:
        case SSH_AUDIT_TXT:
        case SSH_AUDIT_USER:
        case SSH_AUDIT_REMOTE_USER:
        case SSH_AUDIT_HTTP_METHOD:
        case SSH_AUDIT_REQUEST_URI:
        case SSH_AUDIT_HTTP_VERSION:
        case SSH_AUDIT_RULE_NAME:
        case SSH_AUDIT_RULE_ACTION:
        case SSH_AUDIT_EVENT_SOURCE:
        case SSH_AUDIT_SOURCE_HOST:
        case SSH_AUDIT_DESTINATION_HOST:
        case SSH_AUDIT_CIFS_DOMAIN:
        case SSH_AUDIT_CIFS_ACCOUNT:
        case SSH_AUDIT_CIFS_COMMAND:
        case SSH_AUDIT_CIFS_SUBCOMMAND:
        case SSH_AUDIT_CIFS_DIALECT:
        case SSH_AUDIT_NBT_SOURCE_HOST:
        case SSH_AUDIT_NBT_DESTINATION_HOST:
        case SSH_AUDIT_USERNAME:
        case SSH_AUDIT_TOTUNNEL_ID:
        case SSH_AUDIT_FROMTUNNEL_ID:
        case SSH_AUDIT_SNORT_CLASSIFICATION_STR:
        case SSH_AUDIT_SNORT_REFERENCE:
        case SSH_AUDIT_SNORT_ACTION_TYPE:

          arg->data = va_arg(ap, unsigned char *);

          /* If the pointer is NULL, then this argument is ignored. */
          if (arg->data == NULL)
            continue;

          arg->data_len = strlen((char *) arg->data);
          break;

        default:
          ssh_fatal("Invalid audit argument type %d: "
                    "maybe SSH_AUDIT_ARGUMENT_END is missing???",
                    type);
          break;
        }

      /* One more argument parsed. */
      argc++;
    }

  /* And pass the event to the user. */
  (*context->audit_callback)(event, argc, context->arguments,
                             context->callback_context);
}

void
ssh_audit_event(SshAuditContext context, SshAuditEvent event, ...)
{
  va_list ap;

  va_start(ap, event);

  ssh_audit_event_va(context, event, ap);

  va_end(ap);
}

void
ssh_audit_event_array(SshAuditContext context, SshAuditEvent event,
                      SshUInt32 argc, SshAuditArgument argv)
{
  SshUInt32 i;

  SSH_ASSERT(1 <= event && event < SSH_AUDIT_MAX_VALUE);

  if (context == NULL || context->audit_callback == NULL_FNPTR)
    return;

  /* Is event disabled? */
  if (context->event_disabled[event / 32] & ((SshUInt32) 1 << (event % 32)))
    /* Yes it is. */
    return;

  /* Fix null-terminated arguments. */
  for (i = 0; i < argc; i++)
    switch (argv[i].type)
      {
      case SSH_AUDIT_SOURCE_INTERFACE:
      case SSH_AUDIT_DESTINATION_INTERFACE:
      case SSH_AUDIT_PACKET_ATTACK:
      case SSH_AUDIT_PACKET_CORRUPTION:
      case SSH_AUDIT_SOURCE_ADDRESS_STR:
      case SSH_AUDIT_DESTINATION_ADDRESS_STR:
      case SSH_AUDIT_TXT:
      case SSH_AUDIT_USER:
      case SSH_AUDIT_REMOTE_USER:
      case SSH_AUDIT_HTTP_METHOD:
      case SSH_AUDIT_REQUEST_URI:
      case SSH_AUDIT_HTTP_VERSION:
      case SSH_AUDIT_RULE_NAME:
      case SSH_AUDIT_RULE_ACTION:
      case SSH_AUDIT_EVENT_SOURCE:
      case SSH_AUDIT_SOURCE_HOST:
      case SSH_AUDIT_DESTINATION_HOST:
      case SSH_AUDIT_CIFS_DOMAIN:
      case SSH_AUDIT_CIFS_ACCOUNT:
      case SSH_AUDIT_CIFS_SUBCOMMAND:
      case SSH_AUDIT_CIFS_COMMAND:
      case SSH_AUDIT_CIFS_DIALECT:
      case SSH_AUDIT_NBT_SOURCE_HOST:
      case SSH_AUDIT_NBT_DESTINATION_HOST:
      case SSH_AUDIT_USERNAME:
      case SSH_AUDIT_TOTUNNEL_ID:
      case SSH_AUDIT_FROMTUNNEL_ID:
        if (argv[i].data_len == 0)
          argv[i].data_len = strlen((char *) argv[i].data);
        else
          SSH_ASSERT(strlen((char *) argv[i].data) == argv[i].data_len);
        break;

      case SSH_AUDIT_SOURCE_ADDRESS:
      case SSH_AUDIT_DESTINATION_ADDRESS:
      case SSH_AUDIT_SOCKS_SERVER_IP:
      case SSH_AUDIT_TARGET_IP:
        SSH_ASSERT(argv[i].data_len == 0 || argv[i].data_len == 4
                   || argv[i].data_len == 16);
        break;

      case SSH_AUDIT_SPI:
      case SSH_AUDIT_IPV6_FLOW_ID:
      case SSH_AUDIT_SEQUENCE_NUMBER:
      case SSH_AUDIT_IPV4_OPTION:
      case SSH_AUDIT_IPPROTO:
      case SSH_AUDIT_SOURCE_PORT:
      case SSH_AUDIT_DESTINATION_PORT:
      case SSH_AUDIT_ICMP_TYPECODE:
      case SSH_AUDIT_SESSION_ID:
      case SSH_AUDIT_SUB_ID:
      case SSH_AUDIT_ERROR_CODE:
      case SSH_AUDIT_FILE_NAME:
      case SSH_AUDIT_COMMAND:
      case SSH_AUDIT_TOTAL_LENGTH:
      case SSH_AUDIT_DATA_WRITTEN:
      case SSH_AUDIT_DATA_READ:
      case SSH_AUDIT_IPV6ICMP_TYPECODE:
      case SSH_AUDIT_TCP_FLAGS:
      case SSH_AUDIT_KEY_LENGTH:
      case SSH_AUDIT_TARGET_PORT:
      case SSH_AUDIT_SOCKS_SERVER_PORT:
      case SSH_AUDIT_SOCKS_VERSION:
      case SSH_AUDIT_FTP_COMMAND:
      case SSH_AUDIT_TRANSMIT_BYTES:
      case SSH_AUDIT_TRANSMIT_DIGEST:
        /* No sanity checks for these. */
        break;

      default:
        ssh_fatal("Invalid audit argument type %d", argv[i].type);
        break;
      }

  /* Pass the event to the user. */
  (*context->audit_callback)(event, argc, argv, context->callback_context);
}


void
ssh_audit_event_enable(SshAuditContext context, SshAuditEvent event)
{
  SshUInt32 bit;

  SSH_ASSERT(1 <= event && event < SSH_AUDIT_MAX_VALUE);

  if (context == NULL)
    return;

  bit = (SshUInt32) 1 << (event % 32);

  context->event_disabled[event / 32] &= ~bit;
}


void
ssh_audit_event_disable(SshAuditContext context, SshAuditEvent event)
{
  SshUInt32 bit;

  SSH_ASSERT(1 <= event && event < SSH_AUDIT_MAX_VALUE);

  if (context == NULL)
    return;

  bit = (SshUInt32) 1 << (event % 32);

  context->event_disabled[event / 32] |= bit;
}


Boolean
ssh_audit_event_query(SshAuditContext context, SshAuditEvent event)
{
  SSH_ASSERT(1 <= event && event < SSH_AUDIT_MAX_VALUE);

  if (context == NULL)
    return TRUE;

  if (context->event_disabled[event / 32] & ((SshUInt32) 1 << (event % 32)))
    return FALSE;

  return TRUE;
}
