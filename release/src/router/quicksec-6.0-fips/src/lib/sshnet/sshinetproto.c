/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP protocol related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetProto"


/* Mapping between protocol name and doi protocol number */
const SshKeywordStruct ssh_ip_protocol_id_keywords[] =
{
  { "hopopt", SSH_IPPROTO_HOPOPT },
  { "icmp", SSH_IPPROTO_ICMP },
  { "igmp", SSH_IPPROTO_IGMP },
  { "ggp", SSH_IPPROTO_GGP },
  { "ipip", SSH_IPPROTO_IPIP },
  { "st", SSH_IPPROTO_ST },
  { "tcp", SSH_IPPROTO_TCP },
  { "cbt", SSH_IPPROTO_CBT },
  { "egp", SSH_IPPROTO_EGP },
  { "igp", SSH_IPPROTO_IGP },
  { "bbn", SSH_IPPROTO_BBN },
  { "nvp", SSH_IPPROTO_NVP },
  { "pup", SSH_IPPROTO_PUP },
  { "argus", SSH_IPPROTO_ARGUS },
  { "emcon", SSH_IPPROTO_EMCON },
  { "xnet", SSH_IPPROTO_XNET },
  { "chaos", SSH_IPPROTO_CHAOS },
  { "udp", SSH_IPPROTO_UDP },
  { "mux", SSH_IPPROTO_MUX },
  { "dcn", SSH_IPPROTO_DCN },
  { "hmp", SSH_IPPROTO_HMP },
  { "prm", SSH_IPPROTO_PRM },
  { "xns", SSH_IPPROTO_XNS },
  { "trunk1", SSH_IPPROTO_TRUNK1 },
  { "trunk2", SSH_IPPROTO_TRUNK2 },
  { "leaf1", SSH_IPPROTO_LEAF1 },
  { "leaf2", SSH_IPPROTO_LEAF2 },
  { "rdp", SSH_IPPROTO_RDP },
  { "irtp", SSH_IPPROTO_IRTP },
  { "isotp4", SSH_IPPROTO_ISOTP4 },
  { "netblt", SSH_IPPROTO_NETBLT },
  { "mfe", SSH_IPPROTO_MFE },
  { "merit", SSH_IPPROTO_MERIT },
  { "sep", SSH_IPPROTO_SEP },
  { "3pc", SSH_IPPROTO_3PC },
  { "idpr", SSH_IPPROTO_IDPR },
  { "xtp", SSH_IPPROTO_XTP },
  { "ddp", SSH_IPPROTO_DDP },
  { "idprc", SSH_IPPROTO_IDPRC },
  { "tp", SSH_IPPROTO_TP },
  { "il", SSH_IPPROTO_IL },
  { "ipv6", SSH_IPPROTO_IPV6 },
  { "sdrp", SSH_IPPROTO_SDRP },
  { "ipv6route", SSH_IPPROTO_IPV6ROUTE },
  { "ipv6frag", SSH_IPPROTO_IPV6FRAG },
  { "idrp", SSH_IPPROTO_IDRP },
  { "rsvp", SSH_IPPROTO_RSVP },
  { "gre", SSH_IPPROTO_GRE },
  { "mhrp", SSH_IPPROTO_MHRP },
  { "bna", SSH_IPPROTO_BNA },
  { "esp", SSH_IPPROTO_ESP },
  { "ah", SSH_IPPROTO_AH },
  { "inlsp", SSH_IPPROTO_INLSP },
  { "swipe", SSH_IPPROTO_SWIPE },
  { "narp", SSH_IPPROTO_NARP },
  { "mobile", SSH_IPPROTO_MOBILE },
  { "tlsp", SSH_IPPROTO_TLSP },
  { "skip", SSH_IPPROTO_SKIP },
  { "ipv6icmp", SSH_IPPROTO_IPV6ICMP },
  { "ipv6nonxt", SSH_IPPROTO_IPV6NONXT },
  { "ipv6opts", SSH_IPPROTO_IPV6OPTS },
  { "cftp", SSH_IPPROTO_CFTP },
  { "local", SSH_IPPROTO_LOCAL },
  { "sat", SSH_IPPROTO_SAT },
  { "kryptolan", SSH_IPPROTO_KRYPTOLAN },
  { "rvd", SSH_IPPROTO_RVD },
  { "ippc", SSH_IPPROTO_IPPC },
  { "distfs", SSH_IPPROTO_DISTFS },
  { "satmon", SSH_IPPROTO_SATMON },
  { "visa", SSH_IPPROTO_VISA },
  { "ipcv", SSH_IPPROTO_IPCV },
  { "cpnx", SSH_IPPROTO_CPNX },
  { "cphb", SSH_IPPROTO_CPHB },
  { "wsn", SSH_IPPROTO_WSN },
  { "pvp", SSH_IPPROTO_PVP },
  { "brsatmon", SSH_IPPROTO_BRSATMON },
  { "sunnd", SSH_IPPROTO_SUNND },
  { "wbmon", SSH_IPPROTO_WBMON },
  { "wbexpak", SSH_IPPROTO_WBEXPAK },
  { "isoip", SSH_IPPROTO_ISOIP },
  { "vmtp", SSH_IPPROTO_VMTP },
  { "securevmtp", SSH_IPPROTO_SECUREVMTP },
  { "vines", SSH_IPPROTO_VINES },
  { "ttp", SSH_IPPROTO_TTP },
  { "nsfnet", SSH_IPPROTO_NSFNET },
  { "dgp", SSH_IPPROTO_DGP },
  { "tcf", SSH_IPPROTO_TCF },
  { "eigrp", SSH_IPPROTO_EIGRP },
  { "ospfigp", SSH_IPPROTO_OSPFIGP },
  { "sprite", SSH_IPPROTO_SPRITE },
  { "larp", SSH_IPPROTO_LARP },
  { "mtp", SSH_IPPROTO_MTP },
  { "ax25", SSH_IPPROTO_AX25 },
  { "ipwip", SSH_IPPROTO_IPWIP },
  { "micp", SSH_IPPROTO_MICP },
  { "scc", SSH_IPPROTO_SCC },
  { "etherip", SSH_IPPROTO_ETHERIP },
  { "encap", SSH_IPPROTO_ENCAP },
  { "encrypt", SSH_IPPROTO_ENCRYPT },
  { "gmtp", SSH_IPPROTO_GMTP },
  { "ifmp", SSH_IPPROTO_IFMP },
  { "pnni", SSH_IPPROTO_PNNI },
  { "pim", SSH_IPPROTO_PIM },
  { "aris", SSH_IPPROTO_ARIS },
  { "scps", SSH_IPPROTO_SCPS },
  { "qnx", SSH_IPPROTO_QNX },
  { "an", SSH_IPPROTO_AN },
  { "ippcp", SSH_IPPROTO_IPPCP },
  { "snp", SSH_IPPROTO_SNP },
  { "compaq", SSH_IPPROTO_COMPAQ },
  { "ipxip", SSH_IPPROTO_IPXIP },
  { "vrrp", SSH_IPPROTO_VRRP },
  { "pgm", SSH_IPPROTO_PGM },
  { "0hop", SSH_IPPROTO_0HOP },
  { "l2tp", SSH_IPPROTO_L2TP },
  { "ddx", SSH_IPPROTO_DDX },
  { "iatp", SSH_IPPROTO_IATP },
  { "stp", SSH_IPPROTO_STP },
  { "srp", SSH_IPPROTO_SRP },
  { "uti", SSH_IPPROTO_UTI },
  { "smp", SSH_IPPROTO_SMP },
  { "sm", SSH_IPPROTO_SM },
  { "ptp", SSH_IPPROTO_PTP},
  { "isis over ipv4", SSH_IPPROTO_ISISIPV4 },
  { "fire", SSH_IPPROTO_FIRE },
  { "crtp", SSH_IPPROTO_CRTP },
  { "crudp", SSH_IPPROTO_CRUDP },
  { "sscopmce", SSH_IPPROTO_SSCOPMCE },
  { "iplt", SSH_IPPROTO_IPLT },
  { "sps", SSH_IPPROTO_SPS },
  { "pipe", SSH_IPPROTO_PIPE },
  { "sctp", SSH_IPPROTO_SCTP },
  { "fc", SSH_IPPROTO_FC },
  { "rsvp-e2e-ignore", SSH_IPPROTO_RSVP_E2E_IGNORE },
  { "mobility header", SSH_IPPROTO_MOBILE },
  { "udp-lite", SSH_IPPROTO_UDPLITE },
  { "any", SSH_IPPROTO_ANY },
  { NULL, 0 }
};

/* Renders an IP protocol name */
int ssh_ipproto_render(unsigned char *buf, int buf_size, int precision,
                       void *datum)
{
  SshInetIPProtocolID proto = (SshInetIPProtocolID) datum;
  const char *name;
  int len;

  name = ssh_find_keyword_name(ssh_ip_protocol_id_keywords, proto);

  if (name == NULL)
    len = ssh_snprintf(buf, buf_size + 1, "(unknown %u)", proto);
  else
    len = ssh_snprintf(buf, buf_size + 1, "%s", name);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}
