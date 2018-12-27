/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Debugging utilities.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshmiscstring.h"

/*
 * Prototypes.
 */

/* Return true if the debug level (after potential update) of the IKE
   SA `sa' is equal to or greater than `level'. */
static Boolean
ike_debug_ike_sa_enabled(SshIkeSA sa, SshUInt32 level);

/* Output a debug line for an IKE exchange event. The string `text' is
   added to the end of the line. Output IKE SA identification
   attributes if necessary. Output exchange attribues. */
static void
ike_debug_exchange(SshIkeNegotiation negotiation, const char *text);

/* Output a debug line for an IKE SA event. The string `text' is added
   to the end of the line. Output IKE SA identification attributes if
   necessary. Output other IKE SA attributes. */
static void
ike_debug_ike_sa(SshIkeSA sa, const char *text);

/* Output a debug line for an IKE packet event. The string `pfx' is
   printed before listing packet payload types. Output IKE SA
   identification attributes if necessary. Output packet
   attributes. */
static void
ike_debug_packet(SshIkeSA sa, SshIkePacket packet, const char *pfx);

/* Check if identifying data such as addresses have been output for
   IKE SA `sa' and if not then output the data as one or more
   lines. */
static void
ike_debug_identify_ike_sa(SshIkeSA sa);

/* Give pointer to the name of payload type `type', or "unknown". */
static const char *
ike_debug_payload_name(SshIkePayloadType type);

/* Output a line a la ssh_ike_debug_buffer(). */
static void
ike_debug_buffer(const char *str, const unsigned char *buf, size_t len);

/*
 * Data.
 */

static const char *ike_debug_payload_names[] = {
  "NONE",   /* 0 */
  "SA",     /* 1 */
  "P",      /* 2 */
  "T",      /* 3 */
  "KE",     /* 4 */
  "ID",     /* 5 */
  "CERT",   /* 6 */
  "CR",     /* 7 */
  "HASH",   /* 8 */
  "SIG",    /* 9 */
  "NONCE", /* 10 */
  "N",     /* 11 */
  "D",     /* 12 */
  "VID",   /* 13 */
#ifdef SSHDIST_ISAKMP_CFG_MODE
  "ATTR"   /* 14 */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
};

extern const SshKeywordStruct isakmp_auth[];

/*
 * Public functions.
 */

void
ssh_ike_debug_error_local(SshIkeNegotiation negotiation, const char *text)
{
  SshIkeSA sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 1))
    return;

  ike_debug_ike_sa(sa, "local error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}

void
ssh_ike_debug_error_remote(SshIkeNegotiation negotiation, const char *text)
{
  SshIkeSA sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 1))
    return;

  ike_debug_ike_sa(sa, "remote error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}

/*
 * IKE library internal functions.
 */

void
ike_debug_exchange_fail_local(
  SshIkeNegotiation negotiation, SshIkeNotifyMessageType error)
{
  if (!ike_debug_ike_sa_enabled(negotiation->sa, 1))
    return;

  ike_debug_exchange(negotiation, "local failure");

  ssh_pdbg_output_information(
    "IKE-Error:\"%s\"", ssh_ike_error_code_to_string(error));
}

void
ike_debug_exchange_fail_remote(
  SshIkeNegotiation negotiation, SshIkeNotifyMessageType error)
{
  if (!ike_debug_ike_sa_enabled(negotiation->sa, 1))
    return;

  ike_debug_exchange(negotiation, "remote failure");

  ssh_pdbg_output_information(
    "IKE-Error:\"%s\"", ssh_ike_error_code_to_string(error));
}

void
ike_debug_negotiation_error(SshIkeNegotiation negotiation, const char *text)
{
  SshIkeSA sa = negotiation->sa;

  if (sa == NULL || !ike_debug_ike_sa_enabled(negotiation->sa, 1))
    return;

  ike_debug_ike_sa(sa, "error");

  ssh_pdbg_output_information("IKE-Error:\"%s\"", text);
}

void
ike_debug_exchange_begin(SshIkeNegotiation negotiation)
{
  if (!ike_debug_ike_sa_enabled(negotiation->sa, 3))
    return;

  ike_debug_exchange(negotiation, "started");
}

void
ike_debug_exchange_end(SshIkeNegotiation negotiation)
{
  if (!ike_debug_ike_sa_enabled(negotiation->sa, 3))
    return;

  ike_debug_exchange(negotiation, "completed");
}

void
ike_debug_ike_sa_open(SshIkeNegotiation negotiation)
{
  SshIkeSA sa = negotiation->sa;
  SshIkePMPhaseI pi = negotiation->ike_pm_info;
  const char *auth_meth;

  if (!ike_debug_ike_sa_enabled(sa, 2))
    return;

  ike_debug_ike_sa(sa, "opened");

  ssh_pdbg_output_information(
    "Local-Id:%s Remote-Id:%s", pi->local_id_txt, pi->remote_id_txt);

  auth_meth = ssh_find_keyword_name(isakmp_auth, pi->auth_method);
  if (auth_meth == NULL)
    auth_meth = "-";
  ssh_pdbg_output_information("Authentication-Method:%s", auth_meth);

  ssh_pdbg_output_information(
    "Algorithms:%s,%s,%s DH-Group:%d",
    sa->encryption_algorithm_name,
    sa->hash_algorithm_name,
    sa->prf_algorithm_name,
    (int)negotiation->ike_ed->group->descriptor);
}

void
ike_debug_ike_sa_close(SshIkeNegotiation negotiation)
{
  SshIkeSA sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 2))
    return;

  ike_debug_ike_sa(sa, "closed");
}

void
ike_debug_packet_in(SshIkeNegotiation negotiation, SshIkePacket packet)
{
  SshIkeSA sa;

  if (negotiation == NULL)
    return;

  sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 3))
    return;

  ike_debug_packet(sa, packet, "RX");
}

void
ike_debug_packet_out(SshIkeNegotiation negotiation, SshIkePacket packet)
{
  SshIkeSA sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 3))
    return;

  ike_debug_packet(sa, packet, "TX");
}

void
ike_debug_encode_start(SshIkeNegotiation negotiation)
{
  SshIkeSA sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 4))
    return;

  ssh_pdbg_output_event("IKEv1-SA", &sa->debug_object, "encoding packet");

  ike_debug_identify_ike_sa(sa);
}

void
ike_debug_encode_printf(SshIkeNegotiation negotiation, const char *fmt, ...)
{
  va_list ap;

  if (!ike_debug_ike_sa_enabled(negotiation->sa, 4))
    return;

  va_start(ap, fmt);
  ssh_pdbg_output_vinformation(fmt, ap);
  va_end(ap);
}

void
ike_debug_encode_buffer(
  SshIkeNegotiation negotiation,
  const unsigned char *buf, size_t len, const char *str)
{
  if (!ike_debug_ike_sa_enabled(negotiation->sa, 4))
    return;

  ike_debug_buffer(str, buf, len);
}

void
ike_debug_encode_printf_buffer(
  SshIkeNegotiation negotiation,
  const unsigned char *buf, size_t len, const char *fmt, ...)
{
  va_list ap;
  char tmp[64];

  if (!ike_debug_ike_sa_enabled(negotiation->sa, 4))
    return;

  va_start(ap, fmt);
  ssh_vsnprintf(tmp, sizeof tmp, fmt, ap);
  tmp[sizeof tmp - 1] = '\0';
  va_end(ap);

  ike_debug_buffer(tmp, buf, len);
}

void
ike_debug_decode_start(SshIkeNegotiation negotiation)
{
  SshIkeSA sa;

  if (negotiation == NULL)
    return;

  sa = negotiation->sa;

  if (!ike_debug_ike_sa_enabled(sa, 4))
    return;

  ssh_pdbg_output_event("IKEv1-SA", &sa->debug_object, "decoding packet");

  ike_debug_identify_ike_sa(sa);
}

void
ike_debug_decode(SshIkeNegotiation negotiation, const char *fmt, ...)
{
  va_list ap;

  if (negotiation == NULL)
    return;

  if (!ike_debug_ike_sa_enabled(negotiation->sa, 4))
    return;

  va_start(ap, fmt);
  ssh_pdbg_output_vinformation(fmt, ap);
  va_end(ap);
}

void
ike_debug_decode_buffer(
  SshIkeNegotiation negotiation,
  const unsigned char *buf, size_t len, const char *str)
{
  if (negotiation == NULL)
    return;

  if (!ike_debug_ike_sa_enabled(negotiation->sa, 4))
    return;

  ike_debug_buffer(str, buf, len);
}

void
ike_debug_decode_printf_buffer(
  SshIkeNegotiation negotiation,
  const unsigned char *buf, size_t len, const char *fmt, ...)
{
  va_list ap;
  char tmp[64];

  if (negotiation == NULL)
    return;

  if (!ike_debug_ike_sa_enabled(negotiation->sa, 4))
    return;

  va_start(ap, fmt);
  ssh_vsnprintf(tmp, sizeof tmp, fmt, ap);
  tmp[sizeof tmp - 1] = '\0';
  va_end(ap);

  ike_debug_buffer(tmp, buf, len);
}

/*
 * Static functions.
 */

static Boolean
ike_debug_ike_sa_enabled(SshIkeSA sa, SshUInt32 level)
{
  SshIkeNegotiation negotiation = NULL;
  SshIkeServerContext server = NULL;
  SshIkeContext context = NULL;
  SshPdbgConfig c = NULL;
  SshPdbgObject o = NULL;

  if (sa == NULL)
    return FALSE;

  negotiation = sa->isakmp_negotiation;
  server = sa->server_context;
  context = server->isakmp_context;
  c = context->debug_config;
  o = &sa->debug_object;

  if (c == NULL)
    return FALSE;

  if (!SSH_IP_DEFINED(sa->debug_remote_addr))
    {
      ssh_ipaddr_parse(
        sa->debug_remote_addr, negotiation->ike_pm_info->remote_ip);
      sa->debug_remote_port =
        strtoul((char *)negotiation->ike_pm_info->remote_port, NULL, 0);
    }

  if (o->generation != c->generation)
    ssh_pdbg_object_update(
      c, o, server->ip_address, sa->debug_remote_addr);

  return o->level >= level;
}

static void
ike_debug_exchange(SshIkeNegotiation negotiation, const char *text)
{
  SshIkeSA sa = negotiation->sa;
  char *role, *exch;
  Boolean this_end_is_initiator;

  switch(negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_IP:
      this_end_is_initiator = negotiation->ike_pm_info->this_end_is_initiator;
      exch = "Main Mode";
      break;
    case SSH_IKE_XCHG_TYPE_AGGR:
      this_end_is_initiator = negotiation->ike_pm_info->this_end_is_initiator;
      exch = "Aggressive Mode";
      break;
    case SSH_IKE_XCHG_TYPE_INFO:
      this_end_is_initiator = negotiation->info_pm_info->this_end_is_initiator;
      exch = "Informational Exchange";
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
      this_end_is_initiator = negotiation->cfg_pm_info->this_end_is_initiator;
      exch = "Config Mode";
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    case SSH_IKE_XCHG_TYPE_QM:
      this_end_is_initiator = negotiation->qm_pm_info->this_end_is_initiator;
      exch = "Quick Mode";
      break;
    case SSH_IKE_XCHG_TYPE_NGM:
      this_end_is_initiator = negotiation->ngm_pm_info->this_end_is_initiator;
      exch = "New Group Mode";
      break;
    default:
      this_end_is_initiator = negotiation->ike_pm_info->this_end_is_initiator;
      exch = "-";
      break;
    }

  if (this_end_is_initiator)
    role = "initiator";
  else
    role = "responder";

  ssh_pdbg_output_event(
    "IKEv1-SA", &sa->debug_object, "%s %s %s", role, exch, text);

  ike_debug_identify_ike_sa(sa);
}

static void
ike_debug_ike_sa(SshIkeSA sa, const char *text)
{
  SshIkeNegotiation negotiation = sa->isakmp_negotiation;
  unsigned char *l, *r;

  ssh_pdbg_output_event("IKEv1-SA", &sa->debug_object, "IKE SA %s", text);

  ike_debug_identify_ike_sa(sa);

  if (negotiation->ike_pm_info->this_end_is_initiator)
    {
      l = sa->cookies.initiator_cookie;
      r = sa->cookies.responder_cookie;
    }
  else
    {
      l = sa->cookies.responder_cookie;
      r = sa->cookies.initiator_cookie;
    }

  ssh_pdbg_output_information(
    "Local-SPI: %.*@ Remote-SPI: %.*@",
    8, ssh_hex_render, l, 8, ssh_hex_render, r);
}

static void
ike_debug_packet(SshIkeSA sa, SshIkePacket packet, const char *pfx)
{
  SshPdbgBufferStruct pb;
  SshIkePayload pl;
  int i;

  ssh_pdbg_bclear(&pb);
  ssh_pdbg_bprintf(&pb, "MSG-%x HDR", (unsigned)packet->message_id);
  for (i = 0; i < packet->number_of_payload_packets; i++)
    {
      pl = packet->payloads[i];
      ssh_pdbg_bprintf(&pb, ",%s", ike_debug_payload_name(pl->type));
    }

  ssh_pdbg_output_event(
    "IKEv1-SA", &sa->debug_object, "%s %s", pfx, ssh_pdbg_bstring(&pb));

  ike_debug_identify_ike_sa(sa);
}

static void
ike_debug_identify_ike_sa(SshIkeSA sa)
{
  SshPdbgObject o = &sa->debug_object;
  SshIkeServerContext server = sa->server_context;
  unsigned int local_port;

  /* Do this only once. */
  if (o->flags != 0)
    return;
  o->flags = 1;

  if (sa->use_natt)
    local_port = server->nat_t_local_port;
  else
    local_port = server->normal_local_port;

  ssh_pdbg_output_connection(
    server->ip_address, local_port,
    sa->debug_remote_addr, sa->debug_remote_port);
}

static const char *
ike_debug_payload_name(SshIkePayloadType type)
{
  const int n =
    sizeof ike_debug_payload_names / sizeof ike_debug_payload_names[0];

  if ((int)type < 0)
    return "unknown";
  else if (type < n)
    return ike_debug_payload_names[(int)type];
  else if (type < 128)
    return "RESERVED";
  else if (type < 256 || type == SSH_IKE_PAYLOAD_TYPE_PRV)
    return "PRIVATE";
  else
    return "unknown";
}

static void
ike_debug_buffer(const char *str, const unsigned char *buf, size_t len)
{
  if (len > 0)
    ssh_pdbg_output_information(
      "%s[%d] = 0x%.*@", str, len, len, ssh_hex_render, buf);
  else
    ssh_pdbg_output_information("%s[%d]", str, len);
}
