/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppConfig"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshtime.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshbuffer.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"

/* Declarations of option type implementations */

static Boolean
ssh_ppp_config_option_init(SshPppConfigOption,
                           SshPppConfigOptionImpl,
                           SshUInt8 max_iters);

static Boolean
ssh_ppp_config_option_basic_cmp(SshPppConfigOption opt,
                                SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_basic_equals(struct SshPppConfigOptionRec* opt,
                                   SshPppConfigOption opt2);

static Boolean
ssh_ppp_config_option_basic_ispref(struct SshPppConfigOptionRec* opt,
                                   SshPppPktBuffer pkt);

static unsigned long
ssh_ppp_config_option_basic_marshal(SshPppConfigOption opt,
                                    SshPppPktBuffer pkt);

static void
ssh_ppp_config_option_basic_unmarshal(SshPppConfigOption opt,
                                      SshPppPktBuffer pkt);

/* Authentication option type */

static Boolean
ssh_ppp_config_option_auth_cmp(SshPppConfigOption opt,
                               SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_auth_ispref(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_auth_equals(struct SshPppConfigOptionRec* opt,
                                  SshPppConfigOption opt2);


static unsigned long
ssh_ppp_config_option_auth_marshal(SshPppConfigOption opt,
                                   SshPppPktBuffer pkt);

static void
ssh_ppp_config_option_auth_unmarshal(SshPppConfigOption opt,
                                     SshPppPktBuffer pkt);

static SshPppConfigResponse
ssh_ppp_config_option_auth_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt);

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_auth_impl =
  {

    SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL,

    ssh_ppp_config_option_auth_cmp,
    ssh_ppp_config_option_auth_ispref,
    ssh_ppp_config_option_auth_equals,
    ssh_ppp_config_option_auth_isok,
    ssh_ppp_config_option_auth_unmarshal,
    ssh_ppp_config_option_auth_marshal,
    NULL_FNPTR,
  };

/* MRU option type */

SshPppConfigResponse
ssh_ppp_config_option_mru_isok(SshPppConfigOption opt,
                               SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_mru_ispref(SshPppConfigOption opt,
                                 SshPppPktBuffer pkt);

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_mru_impl =
  {
    SSH_LCP_CONFIG_TYPE_MRU,

    ssh_ppp_config_option_basic_cmp,
    ssh_ppp_config_option_mru_ispref,
    ssh_ppp_config_option_basic_equals,
    ssh_ppp_config_option_mru_isok,
    ssh_ppp_config_option_basic_unmarshal,
    ssh_ppp_config_option_basic_marshal,
    NULL_FNPTR
  };

/* ACCM option type */

SshPppConfigResponse
ssh_ppp_config_option_accm_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt);

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_accm_impl =
  {
    SSH_LCP_CONFIG_TYPE_ACCM,

    ssh_ppp_config_option_basic_cmp,
    ssh_ppp_config_option_basic_ispref,
    ssh_ppp_config_option_basic_equals,
    ssh_ppp_config_option_accm_isok,
    ssh_ppp_config_option_basic_unmarshal,
    ssh_ppp_config_option_basic_marshal,
    NULL_FNPTR
  };

/* IPv4 option type */

static unsigned long
ssh_ppp_config_option_ipv4_marshal(SshPppConfigOption opt,
                                   SshPppPktBuffer pkt);


static void
ssh_ppp_config_option_ipv4_unmarshal(SshPppConfigOption opt,
                                     SshPppPktBuffer pkt);


static Boolean
ssh_ppp_config_option_ipv4_cmp(SshPppConfigOption opt,
                               SshPppPktBuffer pkt);


static Boolean
ssh_ppp_config_option_ipv4_ispref(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt);

SshPppConfigResponse
ssh_ppp_config_option_ipv4_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_ipv4_equals(struct SshPppConfigOptionRec* opt,
                                  SshPppConfigOption opt2);

static void
ssh_ppp_config_option_ipv4_uninit(SshPppConfigOption val);

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_ipv4_impl =
  {
    SSH_IPCP_CONFIG_TYPE_IP_ADDRESS,

    ssh_ppp_config_option_ipv4_cmp,
    ssh_ppp_config_option_ipv4_ispref,
    ssh_ppp_config_option_ipv4_equals,
    ssh_ppp_config_option_ipv4_isok,
    ssh_ppp_config_option_ipv4_unmarshal,
    ssh_ppp_config_option_ipv4_marshal,
    ssh_ppp_config_option_ipv4_uninit
  };

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_dns_primary_impl =
  {
    SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY,

    ssh_ppp_config_option_ipv4_cmp,
    ssh_ppp_config_option_ipv4_ispref,
    ssh_ppp_config_option_ipv4_equals,
    ssh_ppp_config_option_ipv4_isok,
    ssh_ppp_config_option_ipv4_unmarshal,
    ssh_ppp_config_option_ipv4_marshal,
    ssh_ppp_config_option_ipv4_uninit
  };

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_dns_secondary_impl =
  {
    SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY,

    ssh_ppp_config_option_ipv4_cmp,
    ssh_ppp_config_option_ipv4_ispref,
    ssh_ppp_config_option_ipv4_equals,
    ssh_ppp_config_option_ipv4_isok,
    ssh_ppp_config_option_ipv4_unmarshal,
    ssh_ppp_config_option_ipv4_marshal,
    ssh_ppp_config_option_ipv4_uninit
  };

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_nbns_primary_impl =
  {
    SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY,

    ssh_ppp_config_option_ipv4_cmp,
    ssh_ppp_config_option_ipv4_ispref,
    ssh_ppp_config_option_ipv4_equals,
    ssh_ppp_config_option_ipv4_isok,
    ssh_ppp_config_option_ipv4_unmarshal,
    ssh_ppp_config_option_ipv4_marshal,
    ssh_ppp_config_option_ipv4_uninit
  };

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_nbns_secondary_impl =
  {
    SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY,

    ssh_ppp_config_option_ipv4_cmp,
    ssh_ppp_config_option_ipv4_ispref,
    ssh_ppp_config_option_ipv4_equals,
    ssh_ppp_config_option_ipv4_isok,
    ssh_ppp_config_option_ipv4_unmarshal,
    ssh_ppp_config_option_ipv4_marshal,
    ssh_ppp_config_option_ipv4_uninit
  };


/* Quality option type */

static SshPppConfigResponse
ssh_ppp_config_option_quality_isok(SshPppConfigOption opt,
                                   SshPppPktBuffer pkt);


static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_quality_impl =
  {
    SSH_LCP_CONFIG_TYPE_QUALITY_PROTOCOL,

    ssh_ppp_config_option_basic_cmp,
    ssh_ppp_config_option_basic_ispref,
    ssh_ppp_config_option_basic_equals,
    ssh_ppp_config_option_quality_isok,
    ssh_ppp_config_option_basic_unmarshal,
    ssh_ppp_config_option_basic_marshal,
    NULL_FNPTR
  };

/* Magic option type */

static SshPppConfigResponse
ssh_ppp_config_option_magic_isok(SshPppConfigOption opt,
                                 SshPppPktBuffer pkt);

static unsigned long
ssh_ppp_config_option_magic_marshal(SshPppConfigOption opt,
                                    SshPppPktBuffer pkt);


static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_magic_impl =
  {
    SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER,

    ssh_ppp_config_option_basic_cmp,
    ssh_ppp_config_option_basic_ispref,
    ssh_ppp_config_option_basic_equals,
    ssh_ppp_config_option_magic_isok,
    ssh_ppp_config_option_basic_unmarshal,
    ssh_ppp_config_option_magic_marshal,
    NULL_FNPTR
  };

/* PFC option type */

static unsigned long
ssh_ppp_config_option_boolean_marshal(SshPppConfigOption opt,
                                      SshPppPktBuffer pkt);

static void
ssh_ppp_config_option_boolean_unmarshal(SshPppConfigOption opt,
                                        SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_boolean_cmp(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_boolean_ispref(SshPppConfigOption opt,
                                     SshPppPktBuffer pkt);

static Boolean
ssh_ppp_config_option_boolean_equals(SshPppConfigOption opt,
                                     SshPppConfigOption opt2);

static SshPppConfigResponse
ssh_ppp_config_option_pfc_isok(SshPppConfigOption opt,
                               SshPppPktBuffer pkt);

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_pfc_impl =
  {
    SSH_LCP_CONFIG_TYPE_PROTOCOL_FIELD_COMPRESSION,

    ssh_ppp_config_option_boolean_cmp,
    ssh_ppp_config_option_boolean_ispref,
    ssh_ppp_config_option_boolean_equals,
    ssh_ppp_config_option_pfc_isok,
    ssh_ppp_config_option_boolean_unmarshal,
    ssh_ppp_config_option_boolean_marshal,
    NULL_FNPTR
  };

/* ACFC option type */

static SshPppConfigResponse
ssh_ppp_config_option_acfc_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt);

static
SSH_RODATA
SshPppConfigOptionImplStruct ssh_ppp_config_acfc_impl =
{
  SSH_LCP_CONFIG_TYPE_ADDRESS_AND_CONTROL_FIELD_COMPRESSION,

  ssh_ppp_config_option_boolean_cmp,
  ssh_ppp_config_option_boolean_ispref,
  ssh_ppp_config_option_boolean_equals,
  ssh_ppp_config_option_acfc_isok,
  ssh_ppp_config_option_boolean_unmarshal,
  ssh_ppp_config_option_boolean_marshal,
  NULL_FNPTR
};

/* The actual code */

void
ssh_ppp_config_option_set_conter(SshPppConfigOption opt, SshPppCounter i)
{
  SSH_ASSERT(opt != NULL);
  opt->counter = i;
}

void
ssh_ppp_config_option_inc_counter(SshPppConfigOption opt)
{
  opt->counter++;
}

SshPppCounter
ssh_ppp_config_option_get_counter(SshPppConfigOption opt)
{
  return opt->counter;
}

void
ssh_ppp_config_preference_set(SshPppConfigOption opt,
                              SshPppConfigPreference pref)
{
  SSH_DEBUG(SSH_D_MY,("setting preference of option %d to %d",
                      opt->impl->type,pref));
  opt->preference = pref;
}

SshPppConfigPreference
ssh_ppp_config_preference_get(SshPppConfigOption opt)
{
  return opt->preference;
}

/* Simple hooks for handling options supported only on
   either downlink/uplink */

SshPppConfigResponse
ssh_ppp_config_nak(SshPppPktBuffer pkt)
{
  return SSH_LCP_NAK;
}

SshPppConfigResponse
ssh_ppp_config_ack(SshPppPktBuffer pkt)
{
  return SSH_LCP_ACK;
}

SshPppConfigResponse
ssh_ppp_config_rej(SshPppPktBuffer pkt)
{
  return SSH_LCP_REJ;
}

SshPppConfigResponse
ssh_ppp_config_option_mru_isok(SshPppConfigOption opt,
                               SshPppPktBuffer pkt)
{
  SshUInt32 val;
  SshUInt8 len;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len != 4)
    {
      return SSH_LCP_REJ;
    }

  val = ssh_ppp_config_option_basic_read(pkt);

  /* Make sure we can build our basic LCP stuff always */

  if (val < 64)
    {
      return SSH_LCP_NAK;
    }

  /* Assume we will later be encapsulated in
     IP packets. Leave sufficient room to accomodate
     even quite complex layerings */

  if (val > 60000)
    {
      return SSH_LCP_NAK;
    }

  /* See if we are within sane boundaries */

  if ((val < opt->ctx.bound.min && opt->ctx.bound.min != 0)
      || (val > opt->ctx.bound.max  && opt->ctx.bound.max != 0))
    {
      return SSH_LCP_NAK;
    }

  /* Is ok? */

  return SSH_LCP_ACK;
}

void
ssh_ppp_config_option_mru_set_constraint(struct SshPppConfigOptionRec* opt,
                                         SshUInt16 min,
                                         SshUInt16 max)
{
  SSH_PRECOND(opt != NULL && opt->impl != NULL);
  SSH_PRECOND(opt->impl->type == SSH_LCP_CONFIG_TYPE_MRU);

  opt->ctx.bound.min = min;
  opt->ctx.bound.max = max;
}

static Boolean
ssh_ppp_config_option_mru_ispref(SshPppConfigOption opt,
                                 SshPppPktBuffer pkt)
{
  SshUInt32 wire_val;
  SshUInt16 own_val;

  SSH_PRECOND(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);

  wire_val = ssh_ppp_config_option_basic_read(pkt);
  own_val = ssh_ppp_config_option_int32_get_value(opt);

  if (wire_val > own_val)
    {
      return TRUE;
    }

  return FALSE;
}



SshPppConfigResponse
ssh_ppp_config_option_accm_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt)
{
  SshUInt8 len;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len != 6)
    {
      return SSH_LCP_REJ;
    }

  return SSH_LCP_ACK;
}

/* Functions for handling options using integers with upto 32 bits in
   the option payload */

static Boolean
ssh_ppp_config_option_basic_cmp(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt32 val;
  SshUInt32 val2;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);
  SSH_ASSERT(opt != NULL);

  val = ssh_ppp_config_option_basic_read(pkt);
  val2 = ssh_ppp_config_option_int32_get_value(opt);

  return (val == val2 ? TRUE : FALSE);
}

static Boolean
ssh_ppp_config_option_basic_ispref(SshPppConfigOption opt,
                                   SshPppPktBuffer pkt)
{
  return FALSE;
}

static Boolean
ssh_ppp_config_option_basic_equals(struct SshPppConfigOptionRec* opt,
                                   SshPppConfigOption opt2)
{
  SshUInt32 val;
  SshUInt32 val2;

  SSH_ASSERT(opt != NULL);

  if (opt->impl->type != opt2->impl->type)
    {
      return FALSE;
    }

  val =  ssh_ppp_config_option_int32_get_value(opt);
  val2 = ssh_ppp_config_option_int32_get_value(opt2);

  return (val == val2 ? TRUE : FALSE);
}

static unsigned long
ssh_ppp_config_option_basic_marshal(SshPppConfigOption opt,
                                    SshPppPktBuffer pkt)
{
  SshUInt32 optval;

  ssh_ppp_pkt_buffer_append_uint8(pkt,opt->impl->type);
  optval = ssh_ppp_config_option_int32_get_value(opt);

  switch (opt->impl->type)
    {
    case SSH_LCP_CONFIG_TYPE_MRU:
      ssh_ppp_pkt_buffer_append_uint8(pkt,4);
      ssh_ppp_pkt_buffer_append_uint16(pkt,(SshUInt16)optval);
      return 4;
    case SSH_LCP_CONFIG_TYPE_ACCM:
      ssh_ppp_pkt_buffer_append_uint8(pkt,6);
      ssh_ppp_pkt_buffer_append_uint32(pkt,(SshUInt32)optval);
      return 6;

    }
  SSH_ASSERT(0);
  return 0;
}

SshPppConfigResponse
ssh_ppp_config_option_ipv4_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt)
{
  SshUInt8 len;
  SshUInt32 val;
  SshIPCPConfigOptionValueIPv4ConstraintStruct *optcon;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len != 6)
    {
      return SSH_LCP_REJ;
    }

  val = ssh_ppp_config_option_basic_read(pkt);

  if (val == 0xFFFFFFFF || val == 0)
    {
      return SSH_LCP_NAK;
    }

  optcon = (SshIPCPConfigOptionValueIPv4ConstraintStruct*)opt->ctx.ptr;

  if (optcon->constraint_initialized == 1)
    {
      if ((optcon->mask & val) != optcon->net_address)
        {
          return SSH_LCP_NAK;
        }
    }

  return SSH_LCP_ACK;
}

static unsigned long
ssh_ppp_config_option_ipv4_marshal(SshPppConfigOption opt,
                                   SshPppPktBuffer pkt)
{
  SshIPCPConfigOptionValueIPv4Struct* optval;

  optval = ssh_ppp_config_option_get_optionvalue_ipv4(opt);

  ssh_ppp_pkt_buffer_append_uint8(pkt,opt->impl->type);
  ssh_ppp_pkt_buffer_append_uint8(pkt,6);

  ssh_ppp_pkt_buffer_append_uint32(pkt,optval->host_address);
  return 6;
}

static void
ssh_ppp_config_option_ipv4_unmarshal(SshPppConfigOption opt,
                                     SshPppPktBuffer pkt)
{
  SshUInt32 val;

  val = ssh_ppp_config_option_basic_read(pkt);
  ssh_ppp_config_option_ipv4_set_ip(opt,val);
}

static Boolean
ssh_ppp_config_option_ipv4_cmp(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt32 val;
  SshIPCPConfigOptionValueIPv4Struct* optval;

  optval = ssh_ppp_config_option_get_optionvalue_ipv4(opt);
  val = ssh_ppp_config_option_basic_read(pkt);

  return (optval->host_address == val ? TRUE : FALSE);
}

static Boolean
ssh_ppp_config_option_ipv4_ispref(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt)
{
  return FALSE;
}

static Boolean
ssh_ppp_config_option_ipv4_equals(struct SshPppConfigOptionRec* opt,
                                  SshPppConfigOption opt2)
{
  SshIPCPConfigOptionValueIPv4Struct *optval,*optval2;

  if (opt->impl->type != opt2->impl->type)
    {
      return FALSE;
    }

  /* Currently only compare on the basis of the actual
     configuration item value. Ignore any possible
     constraints set via mask and net_address */

  optval = ssh_ppp_config_option_get_optionvalue_ipv4(opt);
  optval2 = ssh_ppp_config_option_get_optionvalue_ipv4(opt2);

  return (optval->host_address == optval2->host_address ? TRUE : FALSE);
}

static unsigned long
ssh_ppp_config_option_magic_marshal(SshPppConfigOption opt,
                                    SshPppPktBuffer pkt)
{
  SshUInt32 optval;

  SSH_ASSERT(opt->impl->type == SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER);

  optval = ssh_ppp_config_option_int32_get_value(opt);

  ssh_ppp_pkt_buffer_append_uint8(pkt,opt->impl->type);
  ssh_ppp_pkt_buffer_append_uint8(pkt,6);
  ssh_ppp_pkt_buffer_append_uint32(pkt,optval);

  return 6;
}

static unsigned long
ssh_ppp_config_option_boolean_marshal(SshPppConfigOption opt,
                                      SshPppPktBuffer pkt)
{
  ssh_ppp_pkt_buffer_append_uint8(pkt,opt->impl->type);
  ssh_ppp_pkt_buffer_append_uint8(pkt,2);

  return 2;
}

static void
ssh_ppp_config_option_boolean_unmarshal(SshPppConfigOption opt,
                                        SshPppPktBuffer pkt)
{
  return;
}

static Boolean
ssh_ppp_config_option_boolean_cmp(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt)
{
  return TRUE;
}

static Boolean
ssh_ppp_config_option_boolean_ispref(SshPppConfigOption opt,
                                     SshPppPktBuffer pkt)
{
  return TRUE;
}

static Boolean
ssh_ppp_config_option_boolean_equals(SshPppConfigOption opt,
                                     SshPppConfigOption opt2)
{
  return TRUE;
}

SshUInt32
ssh_ppp_config_option_basic_read(SshPppPktBuffer pkt)
{
  SshUInt8 len;
  SshUInt32 val;
  unsigned long i;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);

  len = ssh_ppp_protocol_option_get_length(pkt);

  len -= 2;
  val = 0;

  for (i = 0; i < len; i++)
    {
      val = (val << 8) | ssh_ppp_pkt_buffer_get_uint8(pkt,i+2);
    }
  return val;
}

static void
ssh_ppp_config_option_basic_unmarshal(SshPppConfigOption opt,
                                      SshPppPktBuffer pkt)
{
  SshUInt32 val;

  val = ssh_ppp_config_option_basic_read(pkt);
  ssh_ppp_config_option_int32_set(opt,val);
}

/* Unmarshal a suggestion */


static SshPppConfigResponse
ssh_ppp_config_option_auth_isok(SshPppConfigOption opt,
                                SshPppPktBuffer pkt)
{
  SshUInt8 len;
  SshUInt16 val;

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len < 4
      || len > ssh_ppp_pkt_buffer_get_contentlen(pkt))
    {
      SSH_DEBUG(SSH_D_NETGARB,("auth option value field corrupted"));
      return SSH_LCP_REJ;
    }

  val = ssh_ppp_pkt_buffer_get_uint16(pkt,2);

  if ((len - 4) > SSH_PPP_AUTH_DATA_MAX)
    {
      SSH_DEBUG(SSH_D_NETGARB,("auth option value field too long"));
      return SSH_LCP_NAK;
    }

  if (val == SSH_PPP_PID_CHAP && len == 5)
    {

      val = ssh_ppp_pkt_buffer_get_uint8(pkt,4);

      SSH_DEBUG(SSH_D_MIDOK,
                ("peer requests authentication protocol CHAP with "
                 "algorithm %d ",val));

      if (val == SSH_PPP_CHAP_ALGORITHM_MD5
          && (opt->ctx.flags & SSH_PPP_AUTH_F_CHAP_OK) != 0)
        return SSH_LCP_ACK;

      if (val == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1
          && (opt->ctx.flags & SSH_PPP_AUTH_F_MSCHAPv1_OK) != 0)
        return SSH_LCP_ACK;

      if (val == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2
          && (opt->ctx.flags & SSH_PPP_AUTH_F_MSCHAPv2_OK) != 0)
        return SSH_LCP_ACK;
    }

  if (val == SSH_PPP_PID_EAP)
    {
      SSH_DEBUG(SSH_D_MIDOK,("peer requests authentication protocol EAP"));

      if (len != 4)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("auth option value field corrupted (length %d)",len));
          return SSH_LCP_NAK;
        }

      if ((opt->ctx.flags & SSH_PPP_AUTH_F_EAP_OK) == 0)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("requested EAP authentication not configured"));
          return SSH_LCP_NAK;
        }
      return SSH_LCP_ACK;

    }

  if (val == SSH_PPP_PID_PAP)
    {
      SSH_DEBUG(SSH_D_MIDOK,("peer requests authentication protocol PAP"));
      if (len != 4)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("auth option value field corrupted (length %d)",len));
          return SSH_LCP_NAK;
        }

    if ((opt->ctx.flags & SSH_PPP_AUTH_F_PAP_OK) == 0)
      {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("requested PAP authentication not configured"));
        return SSH_LCP_NAK;
      }
    return SSH_LCP_ACK;
    }

  return SSH_LCP_NAK;
}

static unsigned long
ssh_ppp_config_option_auth_marshal(SshPppConfigOption opt,
                                   SshPppPktBuffer pkt)
{
  SshLCPConfigOptionValueAuth* o;
  SshUInt16 pid;

  SSH_ASSERT(opt != NULL);

  o = ssh_ppp_config_option_get_optionvalue_auth(opt);
  SSH_ASSERT(o != NULL);

  pid = ssh_ppp_config_option_auth_get_protocol(opt);

  ssh_ppp_pkt_buffer_append_uint8(pkt,opt->impl->type);
  ssh_ppp_pkt_buffer_append_uint8(pkt,(SshUInt8)(o->datalen + 4));
  ssh_ppp_pkt_buffer_append_uint16(pkt,pid);

  ssh_ppp_pkt_buffer_append_buf(pkt,o->data,o->datalen);

  SSH_ASSERT(ssh_ppp_config_option_auth_get_protocol(opt) != SSH_PPP_PID_EAP
             || o->datalen == 0);

  SSH_ASSERT(ssh_ppp_config_option_auth_get_protocol(opt) != SSH_PPP_PID_PAP
             || o->datalen == 0);

  return o->datalen+4;
}

static void
ssh_ppp_config_option_auth_unmarshal(SshPppConfigOption opt,
                                     SshPppPktBuffer pkt)
{
  SshUInt16 protocol;

  /* Currently support only CHAP, EAP and PAP */

  SSH_ASSERT(ssh_ppp_protocol_option_get_length(pkt) >= 4);

  protocol = ssh_ppp_pkt_buffer_get_uint16(pkt,2);

  SSH_ASSERT(protocol == SSH_PPP_PID_EAP
             || protocol == SSH_PPP_PID_CHAP
             || protocol == SSH_PPP_PID_PAP);

  if (protocol == SSH_PPP_PID_EAP)
    {
      ssh_ppp_config_option_auth_set(opt,protocol,NULL,0);
    }
  else if (protocol == SSH_PPP_PID_PAP)
    {
      ssh_ppp_config_option_auth_set(opt, protocol, NULL,0);
    }
  else if (protocol == SSH_PPP_PID_CHAP)
    {
      SSH_ASSERT(ssh_ppp_protocol_option_get_length(pkt) == 5);
      ssh_ppp_config_option_auth_set(opt,protocol,
                                     ssh_ppp_pkt_buffer_get_ptr(pkt,4,1),1);
    }
  else
    {
      SSH_NOTREACHED;
    }
}

static Boolean
ssh_ppp_config_option_auth_equals(struct SshPppConfigOptionRec* opt,
                                  SshPppConfigOption opt2)
{
  SshUInt16 proto1,proto2;
  SshUInt8 alg1, alg2;

  proto1 = ssh_ppp_config_option_auth_get_protocol(opt);
  proto2 = ssh_ppp_config_option_auth_get_protocol(opt2);

  if (proto1 != proto2)
    {
      return FALSE;
    }

  if (proto1 == SSH_PPP_PID_EAP || proto1 == SSH_PPP_PID_PAP)
    {
      return TRUE;
    }

  SSH_ASSERT(proto1 == SSH_PPP_PID_CHAP);

  alg1 = ssh_ppp_config_option_auth_chap_get_algorithm(opt);
  alg2 = ssh_ppp_config_option_auth_chap_get_algorithm(opt2);

  if (alg1 != alg2)
    {
      return FALSE;
    }

  return TRUE;
}

static Boolean
ssh_ppp_config_option_auth_ispref(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt)
{
  SshUInt16 opt_val, wire_val;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);
  SSH_ASSERT(opt != NULL);

  opt_val = ssh_ppp_config_option_auth_get_protocol(opt);
  wire_val = ssh_ppp_pkt_buffer_get_uint16(pkt,2);

  /* Basic logic:
     - Prefer EAP over all other protocols
     - Prefer all other protocols over PAP
  */

  if (wire_val == SSH_PPP_PID_EAP)
    {
      return TRUE;
    }

  if (opt_val == SSH_PPP_PID_PAP
      && wire_val != SSH_PPP_PID_PAP)
    {
      return TRUE;
    }
  return FALSE;
}

static Boolean
ssh_ppp_config_option_auth_cmp(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt16 val;
  SshUInt16 val2;
  SshLCPConfigOptionValueAuth* o;
  unsigned long datalen;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) == SSH_PPP_OK);
  SSH_ASSERT(opt != NULL);

  o = (SshLCPConfigOptionValueAuth*)opt->option;
  SSH_ASSERT(o != NULL);

  datalen = ssh_ppp_protocol_option_get_length(pkt) - 4;

  if (datalen != o[opt->current_idx].datalen)
    {
      return FALSE;
    }

  val = ssh_ppp_config_option_auth_get_protocol(opt);
  val2 = ssh_ppp_pkt_buffer_get_uint16(pkt,2);

  if (val != val2)
    {
      return FALSE;
    }

  if (datalen != 0)
    {
      return (memcmp(o[opt->current_idx].data,
                     ssh_ppp_pkt_buffer_get_ptr(pkt, 4, datalen),
                     datalen) == 0 ? TRUE : FALSE);
    }

  return TRUE;
}


void
ssh_ppp_config_option_auth_set(SshPppConfigOption opt,
                               SshUInt16 protocol,
                               SshUInt8* buf,
                               unsigned long len)
{
  SshLCPConfigOptionValueAuth* o;

  o = (SshLCPConfigOptionValueAuth*)opt->option;

  SSH_ASSERT(o != NULL);

  o[opt->current_idx].protocol = protocol;

  SSH_ASSERT(len <= SSH_PPP_AUTH_DATA_MAX);

  if (buf != NULL)
    {
      memcpy(o[opt->current_idx].data, buf, len);
      o[opt->current_idx].datalen = (SshUInt8)len;
    }
  else
    {
      SSH_ASSERT(len == 0);
      o[opt->current_idx].datalen = 0;
    }

  ssh_ppp_config_option_set_value_status(opt,SSH_PPP_CONFIG_VAL_SET);
}

SshUInt16
ssh_ppp_config_option_auth_get_protocol(SshPppConfigOption opt)
{
  SshLCPConfigOptionValueAuth* o;
  SshUInt16 val;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  o = (SshLCPConfigOptionValueAuth*)opt->option;

  SSH_ASSERT(o != NULL);

  val = o[opt->current_idx].protocol;

  return val;
}

SshUInt8
ssh_ppp_config_option_auth_chap_get_algorithm(SshPppConfigOption opt)
{
  SshLCPConfigOptionValueAuth* o;
  SshUInt8 val;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  o = (SshLCPConfigOptionValueAuth*)opt->option;

  SSH_ASSERT(o != NULL);

  SSH_ASSERT(o[opt->current_idx].datalen == 1);

  val = o[opt->current_idx].data[0];
  return val;
}


static SshPppConfigResponse
ssh_ppp_config_option_quality_isok(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt8 len;

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len < 4)
    {
      return SSH_LCP_REJ;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("peer requests link quality monitoring protocol 0x%x",
             ssh_ppp_pkt_buffer_get_uint16(pkt,2)));

  return SSH_LCP_NAK;
}

static SshPppConfigResponse
ssh_ppp_config_option_magic_isok(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt8 len;
  SshUInt32 val;

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len != 6)
    {
      return SSH_LCP_REJ;
    }

  val = ssh_ppp_config_option_basic_read(pkt);

  /* RFC 1661 6.4: "A Magic-numer of zero is illegal..."
     Assume that the peer's magic number handling is broken and
     reject the option. */

  if (val == 0)
    {
      return SSH_LCP_REJ;
    }

  return SSH_LCP_ACK;
}

static SshPppConfigResponse
ssh_ppp_config_option_pfc_isok(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt8 len;

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len != 2)
    {
      return SSH_LCP_REJ;
    }

  return SSH_LCP_ACK;
}

static SshPppConfigResponse
ssh_ppp_config_option_acfc_isok(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshUInt8 len;

  len = ssh_ppp_protocol_option_get_length(pkt);

  if (len != 2)
    {
      return SSH_LCP_REJ;
    }

  return SSH_LCP_ACK;
}

/*
  Functions for handling the configuration state associated with a
  LCP connection.
*/

static Boolean
ssh_ppp_config_option_init(SshPppConfigOption val,
                           SshPppConfigOptionImpl impl,
                           SshUInt8 max_iters)
{
  SshUInt8* status;

  SSH_ASSERT(max_iters > 0);

  val->status = NULL;
  val->impl = NULL;
  val->max_idx = 0;
  val->current_idx = 0;
  val->option = NULL;
  val->ctx.ptr = NULL;
  val->ctx.flags = 0;
  val->ctx.bound.min = 0;
  val->ctx.bound.max = 0;


  status = (SshUInt8*)ssh_malloc(sizeof(SshUInt8)*max_iters);

  if (status == NULL)
    return FALSE;

  val->status = status;
  val->impl = impl;
  val->max_idx = max_iters;

  ssh_ppp_config_option_reset(val);

  return TRUE;
}

void
ssh_ppp_config_option_uninit(SshPppConfigOption rec)
{
  if (rec->impl->uninit != NULL_FNPTR)
    rec->impl->uninit(rec);

  if (rec->status != NULL)
    ssh_free(rec->status);

  if (rec->option != NULL)
    ssh_free(rec->option);
}

Boolean
ssh_ppp_config_option_init_mru(SshPppConfigOption val,
                               SshUInt8 max_iters)
{
  unsigned long len;

  len = sizeof(SshLCPConfigOptionValueInt32Struct)*max_iters;

  if (ssh_ppp_config_option_init(val,&ssh_ppp_config_mru_impl,max_iters)
      == FALSE)
    return FALSE;

  val->option = ssh_malloc(len);

  if (val->option == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;
    }
  return TRUE;
}

Boolean
ssh_ppp_config_option_init_accm(SshPppConfigOption val,
                                         SshUInt8 max_iters)
{
  unsigned long len;

  len = sizeof(SshLCPConfigOptionValueInt32Struct)*max_iters;

  if (ssh_ppp_config_option_init(val,&ssh_ppp_config_accm_impl,max_iters)
      == FALSE)
    return FALSE;

  val->option = ssh_malloc(len);

  if (val->option == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;
    }

  return TRUE;
}

Boolean
ssh_ppp_config_option_init_auth(SshPppConfigOption val,
                                         SshUInt8 max_iters)
{
  unsigned long len;

  len = sizeof(SshLCPConfigOptionValueAuth)*max_iters;

  if (ssh_ppp_config_option_init(val,&ssh_ppp_config_auth_impl,max_iters)
      == FALSE)
    return FALSE;

  val->option = ssh_malloc(len);

  if (val->option == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;
    }
  return TRUE;
}

Boolean
ssh_ppp_config_option_init_quality(SshPppConfigOption val,
                                                 SshUInt8 max_iters)
{
  unsigned long len;

  len = sizeof(SshLCPConfigOptionValueInt32Struct)*max_iters;

  if (ssh_ppp_config_option_init(val,&ssh_ppp_config_quality_impl,
                                 max_iters) == FALSE)
    return FALSE;

  val->option = ssh_malloc(len);

  if (val->option == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;
    }
  return TRUE;
}

Boolean
ssh_ppp_config_option_init_magic(SshPppConfigOption val,
                                 SshUInt8 max_iters)
{
  SshUInt32 magic;
  unsigned long len;

  if (ssh_ppp_config_option_init(val,&ssh_ppp_config_magic_impl,
                                 max_iters) == FALSE)
    return FALSE;

  len = sizeof(SshLCPConfigOptionValueInt32Struct)*max_iters;

  val->option = ssh_malloc(len);

  if (val->option == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;
    }

  magic = (ssh_random_get_byte() << 24) | (ssh_random_get_byte() << 16)
    | (ssh_random_get_byte() << 8) | ssh_random_get_byte();

  ssh_ppp_config_option_int32_set(val, magic);
  return TRUE;
}

Boolean
ssh_ppp_config_option_init_pfc(SshPppConfigOption val,
                                             SshUInt8 max_iters)
{
  Boolean b;
  b = ssh_ppp_config_option_init(val,&ssh_ppp_config_pfc_impl,max_iters);
  val->option = NULL;
  return b;
}

Boolean
ssh_ppp_config_option_init_acfc(SshPppConfigOption val,
                                SshUInt8 max_iters)
{
  Boolean b;
  b = ssh_ppp_config_option_init(val,&ssh_ppp_config_acfc_impl,max_iters);
  val->option = NULL;
  return b;
}

Boolean
ssh_ppp_config_option_init_ipv4(SshPppConfigOption val,
                                SshUInt8 type,
                                SshUInt8 max_iters)
{
  SshPppConfigOptionImplStruct *impl = NULL;
  unsigned long len;

  SshIPCPConfigOptionValueIPv4ConstraintStruct* optcon;

  switch (type)
    {
    case SSH_IPCP_CONFIG_TYPE_IP_ADDRESS:
      impl = &ssh_ppp_config_ipv4_impl;
      break;
    case SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY:
      impl = &ssh_ppp_config_dns_primary_impl;
      break;
    case SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY:
      impl = &ssh_ppp_config_dns_secondary_impl;
      break;
    case SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY:
      impl = &ssh_ppp_config_nbns_primary_impl;
      break;
    case SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY:
      impl = &ssh_ppp_config_nbns_secondary_impl;
      break;
    default:
      SSH_NOTREACHED;
    }

  if (ssh_ppp_config_option_init(val,impl,max_iters) == FALSE)
    return FALSE;

  len = sizeof(SshIPCPConfigOptionValueIPv4Struct)*max_iters;
  val->option = ssh_malloc(len);

  val->ctx.ptr = NULL;

  if (val->option == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;
    }

  optcon = ssh_malloc(sizeof(SshIPCPConfigOptionValueIPv4ConstraintStruct));

  if (optcon == NULL)
    {
      ssh_ppp_config_option_uninit(val);
      return FALSE;

    }
  optcon->constraint_initialized = 0;
  val->ctx.ptr = optcon;

  return TRUE;
}

static void
ssh_ppp_config_option_ipv4_uninit(SshPppConfigOption val)
{
  if (val->ctx.ptr != NULL)
    {
      ssh_free(val->ctx.ptr);
      val->ctx.ptr = NULL;
    }
}


void
ssh_ppp_config_option_int32_set(SshPppConfigOption opt,SshUInt32 value)
{
  SshLCPConfigOptionValueInt32Struct* o;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);

  o = (SshLCPConfigOptionValueInt32Struct*)opt->option;

  SSH_ASSERT(o != NULL);

  o[opt->current_idx].value = value;
  ssh_ppp_config_option_set_value_status(opt,SSH_PPP_CONFIG_VAL_SET);
}

void
ssh_ppp_config_option_ipv4_set_ip(SshPppConfigOption opt, SshUInt32 value)
{
  SshIPCPConfigOptionValueIPv4Struct* optval;

  optval = ssh_ppp_config_option_get_optionvalue_ipv4(opt);

  optval->host_address = value;

  ssh_ppp_config_option_set_value_status(opt,SSH_PPP_CONFIG_VAL_SET);
}

void
ssh_ppp_config_option_ipv4_unset_constraint(SshPppConfigOption opt)
{
  SshIPCPConfigOptionValueIPv4ConstraintStruct* optcon;

  optcon = (SshIPCPConfigOptionValueIPv4ConstraintStruct*)opt->ctx.ptr;

  optcon->constraint_initialized = 0;
}

void
ssh_ppp_config_option_ipv4_set_constraint(SshPppConfigOption opt,
                                          SshUInt32 addr,
                                          SshUInt32 mask)
{
  SshIPCPConfigOptionValueIPv4ConstraintStruct* optcon;

  optcon = (SshIPCPConfigOptionValueIPv4ConstraintStruct*)opt->ctx.ptr;

  optcon->constraint_initialized = 1;
  optcon->net_address = addr;
  optcon->mask = mask;
}

void
ssh_ppp_config_option_auth_accept(SshPppConfigOption opt,
                                  SshPppAuthType auth_type)
{
  SSH_PRECOND(opt->impl->type==SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL);

  switch (auth_type)
    {
    case SSH_PPP_AUTH_CHAP:
      opt->ctx.flags |= SSH_PPP_AUTH_F_CHAP_OK;
      break;
#ifdef SSHDIST_EAP
    case SSH_PPP_AUTH_EAP:
      opt->ctx.flags |= SSH_PPP_AUTH_F_EAP_OK;
      break;
#endif /* SSHDIST_EAP */
    case SSH_PPP_AUTH_PAP:
      opt->ctx.flags |= SSH_PPP_AUTH_F_PAP_OK;
      break;
    case SSH_PPP_AUTH_MSCHAPv1:
      opt->ctx.flags |= SSH_PPP_AUTH_F_MSCHAPv1_OK;
      break;
    case SSH_PPP_AUTH_MSCHAPv2:
      opt->ctx.flags |= SSH_PPP_AUTH_F_MSCHAPv2_OK;
      break;
    default:
      SSH_NOTREACHED;
      break;
    }
}

SshUInt32
ssh_ppp_config_option_int32_get_value(SshPppConfigOption opt)
{
  SshLCPConfigOptionValueInt32Struct* o;
  SshUInt32 val;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  o = (SshLCPConfigOptionValueInt32Struct*)opt->option;

  SSH_ASSERT(o != NULL);

  val = o[opt->current_idx].value;

  return val;
}

SshIPCPConfigOptionValueIPv4Struct*
ssh_ppp_config_option_get_optionvalue_ipv4(SshPppConfigOption opt)
{
  SshIPCPConfigOptionValueIPv4Struct* o;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  o = (SshIPCPConfigOptionValueIPv4Struct*)opt->option;

  SSH_ASSERT(o != NULL);

  return &o[opt->current_idx];
}

SshLCPConfigOptionValueAuth*
ssh_ppp_config_option_get_optionvalue_auth(SshPppConfigOption opt)
{
  SshLCPConfigOptionValueAuth* o;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  o = (SshLCPConfigOptionValueAuth*)opt->option;

  SSH_ASSERT(o != NULL);

  return &o[opt->current_idx];
}


SshLCPConfigOptionValueInt32Struct*
ssh_ppp_config_option_get_optionvalue_int32(SshPppConfigOption opt)
{
  SshLCPConfigOptionValueInt32Struct* o;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  o = (SshLCPConfigOptionValueInt32Struct*)opt->option;

  SSH_ASSERT(o != NULL);

  return &o[opt->current_idx];
}


SshPppConfigStatus
ssh_ppp_config_option_get_status(SshPppConfigOption opt)
{
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  return SSH_PPP_CONFIG_NEGOTIATION_STATUS(opt->status[opt->current_idx]);
}

void
ssh_ppp_config_option_set_status(SshPppConfigOption opt,
                                 SshPppConfigStatus status)
{
  SshPppConfigValueStatus val_status;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  val_status = SSH_PPP_CONFIG_VALUE_STATUS(opt->status[opt->current_idx]);

  opt->status[opt->current_idx] = SSH_PPP_CONFIG_STATUS(status, val_status);
}

SshPppConfigValueStatus
ssh_ppp_config_option_get_value_status(SshPppConfigOption opt)
{
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  return SSH_PPP_CONFIG_VALUE_STATUS(opt->status[opt->current_idx]);
}

void
ssh_ppp_config_option_set_value_status(SshPppConfigOption opt,
                                       SshPppConfigValueStatus status)
{
  SshPppConfigStatus neg_status;

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->max_idx > 0);
  SSH_ASSERT(opt->current_idx < opt->max_idx);

  neg_status=SSH_PPP_CONFIG_NEGOTIATION_STATUS(opt->status[opt->current_idx]);

  opt->status[opt->current_idx] = SSH_PPP_CONFIG_STATUS(neg_status, status);
}

void
ssh_ppp_config_option_push(SshPppConfigOption opt)
{
  opt->current_idx = (opt->current_idx + 1) % opt->max_idx;
  if (opt->current_idx == 0)
    {
      SSH_DEBUG(SSH_D_MY,
                ("NOTICE: current_idx wrapped around for option %d!",
                 opt->impl->type));
    }

  ssh_ppp_config_option_set_value_status(opt,SSH_PPP_CONFIG_VAL_UNSET);
  ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_UNINIT);
}

void
ssh_ppp_config_option_pop(SshPppConfigOption opt)
{
  opt->current_idx = (opt->max_idx + opt->current_idx - 1) % opt->max_idx;
}

int
ssh_ppp_config_option_isack(SshPppConfigOption opt)
{
  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {
      return 1;
    }
  return 0;
}

int
ssh_ppp_config_option_isquery(SshPppConfigOption opt)
{
  SshPppConfigStatus status;

  status = ssh_ppp_config_option_get_status(opt);

  if (status == SSH_PPP_CONFIG_STATUS_QUERY)
    {
      return 1;
    }
  return 0;
}

Boolean
ssh_ppp_config_option_cmp(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SSH_ASSERT(opt != NULL);

  if (ssh_ppp_protocol_option_get_type(pkt) != opt->impl->type)
    {
      return FALSE;
    }

  return opt->impl->iseq(opt,pkt);
}

int
ssh_ppp_config_option_equals(struct SshPppConfigOptionRec* opt,
                             SshPppConfigOption opt2)
{
  SSH_ASSERT(opt != NULL);
  if (opt->impl->type != opt2->impl->type)
    {
      return 0;
    }
  return opt->impl->equals(opt,opt2);
}

unsigned long
ssh_ppp_config_option_marshal(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SSH_ASSERT(opt != NULL);
  return opt->impl->marshal(opt,pkt);
}

void
ssh_ppp_config_option_unmarshal(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SSH_ASSERT(opt != NULL);
  opt->impl->unmarshal(opt,pkt);
}

SshPppConfigResponse
ssh_ppp_config_option_isok(SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  SshPppConfigResponse res;

  /* Sanity check */

  SSH_ASSERT(ssh_ppp_protocol_option_get_type(pkt) == opt->impl->type);

  if (opt->preference == SSH_PPP_CONFIG_PREF_REJECT)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("rejecting option %d due to configured preference",
                 ssh_ppp_protocol_option_get_type(pkt)));
      return SSH_LCP_REJ;
    }

  SSH_ASSERT(opt != NULL);
  SSH_ASSERT(opt->impl->isok != NULL_FNPTR);

  res = opt->impl->isok(opt,pkt);

  /* Transform NAK's into REJ's if there do not
     exist any better alternatives to be offered */

  if (res == SSH_LCP_NAK)
    {
      if (ssh_ppp_config_option_isnakable(opt) == 0)
        {
          res = SSH_LCP_REJ;
        }
    }

  return res;
}

Boolean
ssh_ppp_config_option_ispref(SshPppConfigOption opt,
                             SshPppPktBuffer pkt)
{
  SSH_PRECOND(ssh_ppp_config_option_isok(opt,pkt) == SSH_LCP_ACK);
  SSH_PRECOND(opt != NULL);
  SSH_PRECOND(opt->impl != NULL);
  SSH_PRECOND(opt->impl->ispref != NULL_FNPTR);

  /* If value is unset, then always prefer */

  if (ssh_ppp_config_option_get_value_status(opt)
      != SSH_PPP_CONFIG_VAL_SET)
    {
      return TRUE;
    }

  return opt->impl->ispref(opt, pkt);
}

int
ssh_ppp_config_option_isnakable(SshPppConfigOption opt)
{
  SshPppConfigValueStatus val_status;
  SshPppConfigStatus neg_status;
  unsigned long i;

  for (i = 0; i < opt->max_idx; i++)
    {

      val_status = SSH_PPP_CONFIG_VALUE_STATUS(opt->status[i]);
      neg_status = SSH_PPP_CONFIG_NEGOTIATION_STATUS(opt->status[i]);

      /* It is illegal for a NAK proposal to contain values which
         have been NAK'd before. */

      if (val_status == SSH_PPP_CONFIG_VAL_SET
          && (neg_status != SSH_PPP_CONFIG_STATUS_NAK
              || neg_status != SSH_PPP_CONFIG_STATUS_REJECTED))
        {
          return 1;
        }
    }
  return 0;
}

unsigned long
ssh_ppp_config_option_marshal_all(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt)
{
  SshUInt8 i, bak, len;
  SshPppConfigValueStatus val_status;
  SshPppConfigStatus neg_status;

  bak = opt->current_idx;
  len = 0;

  for (i = 0; i < opt->max_idx; i++)
    {
      opt->current_idx = i;

      val_status = SSH_PPP_CONFIG_VALUE_STATUS(opt->status[i]);
      neg_status = SSH_PPP_CONFIG_NEGOTIATION_STATUS(opt->status[i]);

      if (val_status == SSH_PPP_CONFIG_VAL_SET
          && (neg_status != SSH_PPP_CONFIG_STATUS_NAK
              || neg_status != SSH_PPP_CONFIG_STATUS_REJECTED))
        {
          len += (SshUInt8)ssh_ppp_config_option_marshal(opt, pkt);
        }
    }

  opt->current_idx = bak;
  return len;
}

SshUInt8
ssh_ppp_config_option_get_type(SshPppConfigOption opt)
{
  SSH_PRECOND(opt != NULL);
  SSH_PRECOND(opt->impl != NULL);

  return opt->impl->type;
}

void
ssh_ppp_config_option_reset(SshPppConfigOption opt)
{
  int i;

  for (i = 0; i < opt->max_idx; i++)
    {
      opt->status[i] = SSH_PPP_CONFIG_STATUS(SSH_PPP_CONFIG_STATUS_UNINIT,
                                             SSH_PPP_CONFIG_VAL_UNSET);
    }

  opt->current_idx = 0;
  opt->counter = 0;
  opt->preference = SSH_PPP_CONFIG_PREF_DEFAULT;
}
