/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Debugging utilities.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-payloads.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"
#include "sshmiscstring.h"
#include "isakmp_util.h"
#include "x509.h"
#include "dn.h"

/*
 * Types.
 */

/* Packet reading buffer. */
typedef struct SshIkev2DebugGetBufferRec {
  const unsigned char *buf;
  int len;
  int pos;
} SshIkev2DebugGetBufferStruct, *SshIkev2DebugGetBuffer;

/*
 * Data.
 */

static const char *ikev2_debug_payload_names[] = {
  "SA",        /* 33 */
  "KE",        /* 34 */
  "IDi",       /* 35 */
  "IDr",       /* 36 */
  "CERT",      /* 37 */
  "CERTREQ",   /* 38 */
  "AUTH",      /* 39 */
  "NONCE",     /* 40 */
  "N",         /* 41 */
  "D",         /* 42 */
  "V",         /* 43 */
  "TSi",       /* 44 */
  "TSr",       /* 45 */
  "SK",        /* 46 */
  "CP",        /* 47 */
  "EAP"        /* 48 */
};


/*
 * Prototypes.
 */

/* Return true if the debug level (after potential update) of the IKE
   SA `ike_sa' is equal to or greater than `level'. */
static Boolean
ikev2_debug_ike_sa_enabled(SshIkev2Sa ike_sa, SshUInt32 level);

/* Output a debug line for an IKE exchange event. The string`text' is
   added to the end of the line. Output IKE SA identification
   attributes if necessary. Output exchange attributes. */
static void
ikev2_debug_exchange(SshIkev2Packet packet, const char *text);

/* Output a debug line for an IKE SA event. The string `text' is added
   to the end of the line. Output IKE SA identification attributes if
   necessary. Output other IKE SA attributes. */
static void
ikev2_debug_ike_sa(SshIkev2Sa ike_sa, const char *text);

/* Output a debug line for an IKE packet event. The string `pfx' is
   printed before listing packet payload types. Output IKE SA
   identification attributes if necessary. Output packet
   attributes. */
static void
ikev2_debug_packet(
  SshIkev2Sa ike_sa, SshIkev2Packet packet, const char *pfx);

/* Check if identifying data such as addresses have been output for
   IKE SA `ike_sa' and if not then output the data as one or more
   lines. */
static void
ikev2_debug_identify_ike_sa(SshIkev2Sa ike_sa);

/* Append a string representation of IKE identity `id' to buffer
   `b'. */
static void
ikev2_debug_bprint_identity(SshPdbgBuffer b, SshIkev2PayloadID id);

/* If MOBIKE is enabled output local and remote addresses and ports of
   the pakcet. */
static void
ikev2_debug_mobike_endpoints(SshIkev2Packet packet);

/* Append the abbreviations of the payload types in the encoded IKE
   packet at `buf' with length `len' to buffer `b'. If `use_natt' is
   TRUE assume NAT-T encoding. If `iv_length' if nonzero it is used to
   determine the length of the header of an encrypted payload. */
static void
ikev2_debug_bprint_payloads(
  SshPdbgBuffer b, unsigned char *buf, int len,
  Boolean use_natt, SshUInt32 iv_length);

/* Print IKE payloads in the reading buffer `gb' to the buffer
   `b'. The type of the first payload in `gb' is `first_payload'. The
   length if the initialization vector in an encrypted payload is
   `iv_length'. */
static void
ikev2_debug_bprint_payloads_sub(
  SshPdbgBuffer b, SshIkev2DebugGetBuffer gb,
  SshUInt32 first_payload, SshUInt32 iv_length);

/* Get an 8-bit value. */
static Boolean
ikev2_debug_get_8bit(SshIkev2DebugGetBuffer gb, SshUInt32 *p);

/* Get a 16-bit value. */
static Boolean
ikev2_debug_get_16bit(SshIkev2DebugGetBuffer gb, SshUInt32 *p);

/* Get a 32-bit value. */
static Boolean
ikev2_debug_get_32bit(SshIkev2DebugGetBuffer gb, SshUInt32 *p);

/* Get an 8-byte IKE SPI value. */
static Boolean
ikev2_debug_get_spi(SshIkev2DebugGetBuffer gb, unsigned char *p);

/* Skip desired amount of bytes. */
static Boolean
ikev2_debug_skip_bytes(SshIkev2DebugGetBuffer gb, int len);

/* Give pointer to the name of payload type `type', or "unknown". */
static const char *
ikev2_debug_payload_name(SshIkev2PayloadType type);

/** Print a string representation of the IPv4/IPv6 address `a'. An
    IPv6 address is surrounded by square brackets. */
static void
ikev2_debug_bprint_addr(SshPdbgBuffer b, SshIpAddr a);

/*
 * Public functions.
 */

void
ssh_ikev2_debug_error_local(SshIkev2Sa ike_sa, const char *text)
{
#ifdef SSHDIST_IKEV1
  if (ike_sa != NULL && ike_sa->v1_sa != NULL)
    {
      ssh_ike_debug_error_local(ike_sa->v1_sa, text);
      return;
    }
#endif /* SSHDIST_IKEV1 */

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 1))
    return;

  ikev2_debug_ike_sa(ike_sa, "local error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}

void
ssh_ikev2_debug_error_remote(SshIkev2Sa ike_sa, const char *text)
{
#ifdef SSHDIST_IKEV1
  if (ike_sa != NULL && ike_sa->v1_sa != NULL)
    {
      ssh_ike_debug_error_remote(ike_sa->v1_sa, text);
      return;
    }
#endif /* SSHDIST_IKEV1 */

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 1))
    return;

  ikev2_debug_ike_sa(ike_sa, "remote error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}

/*
 * IKE library internal functions.
 */

void
ikev2_debug_exchange_fail_local(SshIkev2Packet packet, SshIkev2Error error)
{
  if (!ikev2_debug_ike_sa_enabled(packet->ike_sa, 1))
    return;

  ikev2_debug_exchange(packet, "local failure");

  ssh_pdbg_output_information(
    "IKE-Error:\"%s\"", ssh_ikev2_error_to_string(error));
}

void
ikev2_debug_exchange_fail_remote(SshIkev2Packet packet, SshIkev2Error error)
{
  if (!ikev2_debug_ike_sa_enabled(packet->ike_sa, 1))
    return;

  ikev2_debug_exchange(packet, "remote failure");

  ssh_pdbg_output_information(
    "IKE-Error:\"%s\"", ssh_ikev2_error_to_string(error));
}

void
ikev2_debug_error(SshIkev2Sa ike_sa, const char *text)
{
  if (!ikev2_debug_ike_sa_enabled(ike_sa, 1))
    return;

  ikev2_debug_ike_sa(ike_sa, "error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}

void
ikev2_debug_exchange_begin(SshIkev2Packet packet)
{
  if (!ikev2_debug_ike_sa_enabled(packet->ike_sa, 3))
    return;

  ikev2_debug_exchange(packet, "started");
}

void
ikev2_debug_exchange_end(SshIkev2Packet packet)
{
  if (!ikev2_debug_ike_sa_enabled(packet->ike_sa, 3))
    return;

  ikev2_debug_exchange(packet, "completed");
}

void
ikev2_debug_ike_sa_open(SshIkev2Sa ike_sa)
{
  SshIkev2PayloadID local, remote;
  SshIkev2SaExchangeData ike_ed;
  SshPdbgBufferStruct b;
  SshIkev2AuthMethod local_auth_method;
  const char *local_auth_name, *remote_auth_name;
#ifdef SSHDIST_IKE_CERT_AUTH
  const char *type;
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 2))
    return;

  ikev2_debug_ike_sa(ike_sa, "opened");

  ike_ed = ike_sa->initial_ed->ike_ed;

  if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      local = ike_ed->id_i;
      remote = ike_ed->id_r;
    }
  else
    {
      local = ike_ed->id_r;
      remote = ike_ed->id_i;
    }

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "Local-Id:");
  ikev2_debug_bprint_identity(&b, local);
  ssh_pdbg_bprintf(&b, " Remote-Id:");
  ikev2_debug_bprint_identity(&b, remote);
  ssh_pdbg_output_information("%s", ssh_pdbg_bstring(&b));

#ifdef SSHDIST_IKE_EAP_AUTH
  if (SSH_IKEV2_EAP_ENABLED(ike_ed) &&
      (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      local_auth_name = "EAP";
    }
  else
#endif /* SSHDIST_IKE_EAP_AUTH */
    {
#ifndef SSHDIST_IKE_CERT_AUTH
      local_auth_method = SSH_IKEV2_AUTH_METHOD_SHARED_KEY;
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
      if (!ike_ed->private_key)
        local_auth_method = SSH_IKEV2_AUTH_METHOD_SHARED_KEY;
      else if (ssh_private_key_get_info(
                 ike_ed->private_key, SSH_PKF_KEY_TYPE, &type, SSH_PKF_END) !=
               SSH_CRYPTO_OK)
        local_auth_method = 0;
      else if (strcmp(type, "if-modn") == 0)
        local_auth_method = SSH_IKEV2_AUTH_METHOD_RSA_SIG;
      else if (strcmp(type, "dl-modp") == 0)
        local_auth_method = SSH_IKEV2_AUTH_METHOD_DSS_SIG;
#ifdef SSHDIST_CRYPT_ECP
      else if (strcmp(type, "ec-modp") == 0)
        switch (ssh_private_key_max_signature_output_len(ike_ed->private_key))
          {
          case 64:
            local_auth_method = SSH_IKEV2_AUTH_METHOD_ECP_DSA_256;
            break;
          case 96:
            local_auth_method = SSH_IKEV2_AUTH_METHOD_ECP_DSA_384;
            break;
          case 132:
            local_auth_method = SSH_IKEV2_AUTH_METHOD_ECP_DSA_521;
            break;
          default:
            local_auth_method = 0;
            break;
          }
#endif /* SSHDIST_CRYPT_ECP  */
      else
        local_auth_method = 0;
#endif /* SSHDIST_IKE_CERT_AUTH */

      local_auth_name = ssh_ikev2_auth_method_to_string(local_auth_method);
    }

#ifdef SSHDIST_IKE_EAP_AUTH
  if (SSH_IKEV2_EAP_ENABLED(ike_ed) &&
      !(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    remote_auth_name = "EAP";
  else
#endif /* SSHDIST_IKE_EAP_AUTH */
    remote_auth_name =
      ssh_ikev2_auth_method_to_string(ike_ed->auth_remote->auth_method);

  ssh_pdbg_output_information(
    "Local-Auth:%s Remote-Auth:%s", local_auth_name, remote_auth_name);

  ssh_pdbg_output_information(
    "Algorithms:%s,%s,%s DH-Group:%d",
    ike_sa->encrypt_algorithm,
    ike_sa->prf_algorithm,
    ike_sa->mac_algorithm,
    (int)ike_ed->group_number);
}

void ikev2_debug_ike_sa_rekey(SshIkev2Sa new_sa, SshIkev2Sa old_sa)
{
  unsigned char *l, *r;

  if (!ikev2_debug_ike_sa_enabled(new_sa, 2))
    return;

  ikev2_debug_ike_sa(new_sa, "rekeyed");

  if ((old_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      l = old_sa->ike_spi_i;
      r = old_sa->ike_spi_r;
    }
  else
    {
      l = old_sa->ike_spi_r;
      r = old_sa->ike_spi_i;
    }

  ssh_pdbg_output_information(
    "Rekeyed-Local-SPI: %.*@ Rekeyed-Remote-SPI: %.*@",
    8, ssh_hex_render, l, 8, ssh_hex_render, r);
}

void
ikev2_debug_ike_sa_close(SshIkev2Sa ike_sa)
{
  if (!ikev2_debug_ike_sa_enabled(ike_sa, 2))
    return;

  ikev2_debug_ike_sa(ike_sa, "closed");
}

void
ikev2_debug_packet_in(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 3))
    return;

  ikev2_debug_packet(ike_sa, packet, "RX");
}

void
ikev2_debug_packet_out(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 3))
    return;

  ikev2_debug_packet(ike_sa, packet, "TX");
}

void
ikev2_debug_packet_out_retransmit(SshIkev2Sa ike_sa, SshIkev2Packet packet)
{
  if (!ikev2_debug_ike_sa_enabled(ike_sa, 3))
    return;

  ikev2_debug_packet(ike_sa, packet, "TX");
}

void
ikev2_debug_encode_payload(SshIkev2Packet packet, const char *fmt, ...)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  va_list ap;
  char tmp[1024];

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 4))
    return;

  if (packet->ed == NULL || packet->ed->buffer == NULL ||
      ssh_buffer_len(packet->ed->buffer) == 0)
    {
      ssh_pdbg_output_event(
        "IKEv2-SA", &ike_sa->debug_object, "encoding packet");

      ikev2_debug_identify_ike_sa(ike_sa);
      ikev2_debug_mobike_endpoints(packet);
    }

  va_start(ap, fmt);
  ssh_vsnprintf(tmp, sizeof tmp, fmt, ap);
  tmp[sizeof tmp - 1] = '\0';
  va_end(ap);

  ssh_pdbg_output_information("%s", tmp);
}

void ikev2_debug_decode_start(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (!ikev2_debug_ike_sa_enabled(ike_sa, 4))
    return;

  ssh_pdbg_output_event("IKEv2-SA", &ike_sa->debug_object, "decoding packet");

  ikev2_debug_identify_ike_sa(ike_sa);
  ikev2_debug_mobike_endpoints(packet);
}

void
ikev2_debug_decode_payload(SshIkev2Packet packet, const char *fmt, ...)
{
  va_list ap;
  char tmp[1024];

  if (!ikev2_debug_ike_sa_enabled(packet->ike_sa, 4))
    return;

  va_start(ap, fmt);
  ssh_vsnprintf(tmp, sizeof tmp, fmt, ap);
  tmp[sizeof tmp - 1] = '\0';
  va_end(ap);

  ssh_pdbg_output_information("%s", tmp);
}

void
ikev2_debug_decode_payload_hex(
  SshIkev2Packet packet, const unsigned char *payload, size_t payload_len,
  const char *fmt, ...)
{
  va_list ap;
  char tmp[64];

  if (!ikev2_debug_ike_sa_enabled(packet->ike_sa, 4))
    return;

  va_start(ap, fmt);
  ssh_vsnprintf(tmp, sizeof tmp, fmt, ap);
  tmp[sizeof tmp - 1] = '\0';
  va_end(ap);

  ssh_pdbg_output_information(
    "%s%.*@", tmp, payload_len, ssh_hex_render, payload);
}

/*
 * Static functions.
 */

static Boolean
ikev2_debug_ike_sa_enabled(SshIkev2Sa ike_sa, SshUInt32 level)
{
  SshIkev2 ikev2 = NULL;
  SshPdbgConfig c = NULL;
  SshPdbgObject o = NULL;
  SshIpAddr l, r;

  if (ike_sa == NULL)
    return FALSE;

  ikev2 = ike_sa->server->context;
  c = ikev2->params.debug_config;
  o = &ike_sa->debug_object;

  if (c == NULL)
    return FALSE;

  if (o->generation != c->generation)
    {
      if (o->level == 0)
        {
          l = ike_sa->server->ip_address;
          r = ike_sa->remote_ip;
          ssh_pdbg_object_update(c, o, l, r);
          if (o->level > 0)
            {
              *ike_sa->debug_local = *l;
              *ike_sa->debug_remote = *r;
            }
        }
      else
        {
          l = ike_sa->debug_local;
          r = ike_sa->debug_remote;
          ssh_pdbg_object_update(c, o, l, r);
        }
    }

  return o->level >= level;
}

static void
ikev2_debug_exchange(SshIkev2Packet packet, const char *text)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2ExchangeData ed = packet->ed;
  char *role = NULL, *exch;

  switch (packet->exchange_type)
    {
    case SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT:
    case SSH_IKEV2_EXCH_TYPE_IKE_AUTH:
      exch = "INIT-AUTH";
      if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
        role = "initiator";
      else
        role = "responder";
      break;
    case SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA:
      exch = "CHILD";
      if (ed != NULL)
        {
          if ((ed->ipsec_ed->flags &
               SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_INITIATOR))
            role = "initiator";
          else
            role = "responder";
        }
      break;
    case SSH_IKEV2_EXCH_TYPE_INFORMATIONAL:
      exch = "INFO";
      if (ed != NULL)
        {
          if ((ed->info_ed->flags & SSH_IKEV2_INFO_CREATE_FLAGS_INITIATOR))
            role = "initiator";
          else
            role = "responder";
        }
      break;
    default:
      exch = "-";
      role = "-";
      break;
    }

  ssh_pdbg_output_event(
    "IKEv2-SA", &ike_sa->debug_object, "%s %s %s", role, exch, text);

  ikev2_debug_identify_ike_sa(ike_sa);
}

static void
ikev2_debug_ike_sa(SshIkev2Sa ike_sa, const char *text)
{
  unsigned char *l, *r;

  ssh_pdbg_output_event("IKEv2-SA", &ike_sa->debug_object, "IKE SA %s", text);

  ikev2_debug_identify_ike_sa(ike_sa);

  if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      l = ike_sa->ike_spi_i;
      r = ike_sa->ike_spi_r;
    }
  else
    {
      l = ike_sa->ike_spi_r;
      r = ike_sa->ike_spi_i;
    }

  ssh_pdbg_output_information(
    "Local-SPI: %.*@ Remote-SPI: %.*@",
    8, ssh_hex_render, l, 8, ssh_hex_render, r);
}

static void
ikev2_debug_packet(
  SshIkev2Sa ike_sa, SshIkev2Packet packet, const char *pfx)
{
  SshPdbgBufferStruct pb;
  SshUInt32 iv_length;

  if (packet->retransmit_counter == 0 &&
      packet->ike_sa && ike_sa->encrypt_algorithm)
    iv_length = ssh_cipher_get_iv_length(ssh_csstr(ike_sa->encrypt_algorithm));
  else
    iv_length = 0;

  ssh_pdbg_bclear(&pb);
  ikev2_debug_bprint_payloads(
    &pb, packet->encoded_packet, packet->encoded_packet_len,
    packet->use_natt, iv_length);

  ssh_pdbg_output_event(
    "IKEv2-SA", &ike_sa->debug_object, "%s %s", pfx, ssh_pdbg_bstring(&pb));

  ikev2_debug_identify_ike_sa(ike_sa);
}

static void
ikev2_debug_identify_ike_sa(SshIkev2Sa ike_sa)
{
  SshPdbgObject o = &ike_sa->debug_object;
  unsigned int local_port;

  /* Do this only once. */
  if (o->flags != 0)
    return;
  o->flags = 1;

  if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
    local_port = ike_sa->server->nat_t_local_port;
  else
    local_port = ike_sa->server->normal_local_port;

  ssh_pdbg_output_connection(
    ike_sa->server->ip_address, local_port,
    ike_sa->remote_ip,ike_sa->remote_port);
}

static void
ikev2_debug_mobike_endpoints(SshIkev2Packet packet)
{
  SshPdbgBufferStruct b;
  unsigned int local_port;

#ifdef SSHDIST_IKE_MOBIKE
  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED))
#endif /* SSHDIST_IKE_MOBIKE */
    return;

  if (packet->use_natt)
    local_port = packet->server->nat_t_local_port;
  else
    local_port = packet->server->normal_local_port;

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "MOBIKE-Local:");
  ikev2_debug_bprint_addr(&b, packet->server->ip_address);
  ssh_pdbg_bprintf(&b, ":%u", local_port);

  ssh_debug("  %s", ssh_pdbg_bstring(&b));

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "MOBIKE-Remote:");
  ikev2_debug_bprint_addr(&b, packet->remote_ip);
  ssh_pdbg_bprintf(&b, ":%u", packet->remote_port);

  ssh_debug("  %s", ssh_pdbg_bstring(&b));
}

static void
ikev2_debug_bprint_identity(SshPdbgBuffer b, SshIkev2PayloadID id)
{
  SshUInt32 u;
  void *ptr = id->id_data;
  int len = id->id_data_size;
#ifdef SSHDIST_IKE_CERT_AUTH
  SshDNStruct dn;
  char *ldap;
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_pdbg_bprintf(b, "%s:", ssh_ikev2_id_to_string(id->id_type));

  switch (id->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      if (len == 4)
        {
          u = SSH_GET_32BIT(ptr);
          ssh_pdbg_bprintf(
            b, "%@", ssh_ipaddr4_uint32_render, (void *)(size_t)u);
        }
      else
        ssh_pdbg_bprintf(b, "-");
      break;

    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
        ssh_pdbg_bprintf(b, "%.*@", len, ssh_safe_text_render, ptr);
        break;

    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      if (len == 16)
        ssh_pdbg_bprintf(b, "%@", ssh_ipaddr6_byte16_render, ptr);
      else
        ssh_pdbg_bprintf(b, "-");
      break;

#ifdef SSHDIST_IKE_CERT_AUTH
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
      ssh_dn_init(&dn);
      if (ssh_dn_decode_der(ptr, len, &dn, NULL) == 0)
        ssh_pdbg_bprintf(b, "-");
      else
        {
          if (ssh_dn_encode_ldap(&dn, &ldap) == 0)
            ssh_pdbg_bprintf(b, "-");
          else
            {
              ssh_pdbg_bprintf(b, "\"%s\"", ldap);
              ssh_free(ldap);
            }
        }
      ssh_dn_clear(&dn);
      break;
#endif /* SSHDIST_IKE_CERT_AUTH */

    case SSH_IKEV2_ID_TYPE_KEY_ID:
      ssh_pdbg_bprintf(b, "%.*@", len, ssh_hex_render, ptr);
      break;

    default:
      ssh_pdbg_bprintf(b, "%.*@", len, ssh_hex_render, ptr);
      break;
    }

}

static void
ikev2_debug_bprint_payloads(
  SshPdbgBuffer b, unsigned char *buf, int len,
  Boolean use_natt, SshUInt32 iv_length)
{
  SshIkev2DebugGetBufferStruct gb = {buf, len};
  unsigned char ispi[8], rspi[8];
  SshUInt32 zero, next_payload, length, versions, exchange, flags, message;
  SshUInt32 total_len;
  const char *type;

  if ((use_natt && !ikev2_debug_get_32bit(&gb, &zero)) ||
      !ikev2_debug_get_spi(&gb, ispi) ||
      !ikev2_debug_get_spi(&gb, rspi) ||
      !ikev2_debug_get_8bit(&gb, &next_payload) ||
      !ikev2_debug_get_8bit(&gb, &versions) ||
      !ikev2_debug_get_8bit(&gb, &exchange) ||
      !ikev2_debug_get_8bit(&gb, &flags) ||
      !ikev2_debug_get_32bit(&gb, &message) ||
      !ikev2_debug_get_32bit(&gb, &length))
    goto invalid;

  if (use_natt)
    total_len = 4 + length;
  else
    total_len = length;

  if (total_len < gb.pos)
    goto invalid;

  /* not an error; MAC & padding removed by ikev2_decode_encr()
  if (total_len > gb.len)
    goto invalid;
  */

  if (gb.len > total_len)
    gb.len = total_len;

  if (next_payload == 0)
    goto invalid;

  if ((flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))
    type = "RSP";
  else
    type = "REQ";

  ssh_pdbg_bprintf(b, "%s-%x HDR,", type, (unsigned)message);
  ikev2_debug_bprint_payloads_sub(b, &gb, next_payload, iv_length);
  return;

 invalid:
  ssh_pdbg_bprintf(b, "-");
  return;
}

static void
ikev2_debug_bprint_payloads_sub(
  SshPdbgBuffer b, SshIkev2DebugGetBuffer gb,
  SshUInt32 first_payload, SshUInt32 iv_length)
{
  SshUInt32 curr_payload = first_payload;
  SshUInt32 next_payload, critical, payload_length;
  const char *s, *sep = "";

  while (curr_payload != 0 && gb->pos < gb->len)
    {
      if (!ikev2_debug_get_8bit(gb, &next_payload) ||
          !ikev2_debug_get_8bit(gb, &critical) ||
          !ikev2_debug_get_16bit(gb, &payload_length))
        goto invalid;

      if (curr_payload == SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED)
        {
          ssh_pdbg_bprintf(b, "%sSK{", sep);
          if (iv_length != 0)
            {
              if (!ikev2_debug_skip_bytes(gb, iv_length))
                goto invalid;
              ikev2_debug_bprint_payloads_sub(b, gb, next_payload, iv_length);
            }
          else
            {
              ssh_pdbg_bputc('-', b);
            }
          ssh_pdbg_bprintf(b, "}");
          next_payload = 0;
        }
      else
        {
          if (!ikev2_debug_skip_bytes(gb, payload_length - 4))
            goto invalid;

          s = ikev2_debug_payload_name(curr_payload);
          ssh_pdbg_bprintf(b, "%s%s", sep, s);
        }

      curr_payload = next_payload;
      sep = ",";
    }

  return;

 invalid:
  ssh_pdbg_bprintf(b, "%s-", sep);
  return;
}

static Boolean
ikev2_debug_get_8bit(SshIkev2DebugGetBuffer gb, SshUInt32 *p)
{
  if (gb->pos + 1 > gb->len)
    return FALSE;

  *p = gb->buf[gb->pos++];
  return TRUE;
}

static Boolean
ikev2_debug_get_16bit(SshIkev2DebugGetBuffer gb, SshUInt32 *p)
{
  if (gb->pos + 2 > gb->len)
    return FALSE;

  *p = SSH_GET_16BIT(gb->buf + gb->pos);
  gb->pos += 2;
  return TRUE;
}

static Boolean
ikev2_debug_get_32bit(SshIkev2DebugGetBuffer gb, SshUInt32 *p)
{
  if (gb->pos + 4 > gb->len)
    return FALSE;

  *p = SSH_GET_32BIT(gb->buf + gb->pos);
  gb->pos += 4;
  return TRUE;
}

static Boolean
ikev2_debug_get_spi(SshIkev2DebugGetBuffer gb, unsigned char *p)
{
  if (gb->pos + 8 > gb->len)
    return FALSE;

  memcpy(p, gb->buf + gb->pos, 8);
  gb->pos += 8;
  return TRUE;
}

static Boolean
ikev2_debug_skip_bytes(SshIkev2DebugGetBuffer gb, int len)
{
  if (gb->pos + len > gb->len)
    return FALSE;

  gb->pos += len;
  return TRUE;
}

static const char *
ikev2_debug_payload_name(SshIkev2PayloadType type)
{
  const int n =
    sizeof ikev2_debug_payload_names / sizeof ikev2_debug_payload_names[0];

  if ((int)type < 0)
    return "unknown";
  else if (type == 0)
    return "NONE";
  else if (type < 33)
    return "unknown";
  else if (type < 33 + n)
    return ikev2_debug_payload_names[(int)type - 33];
  else
    return "unknown";
}

static void
ikev2_debug_bprint_addr(SshPdbgBuffer b, SshIpAddr a)
{
  SshUInt32 u;

  switch (a->type)
    {
    case SSH_IP_TYPE_IPV4:
      u = SSH_GET_32BIT(a->addr_data);
      ssh_pdbg_bprintf(b, "%@", ssh_ipaddr4_uint32_render, (void *)(size_t)u);
      break;

    case SSH_IP_TYPE_IPV6:
      ssh_pdbg_bprintf(b, "[%@]", ssh_ipaddr6_byte16_render, a->addr_data);
      break;

    default:
      ssh_pdbg_bputc('-', b);
      break;
    }
}
