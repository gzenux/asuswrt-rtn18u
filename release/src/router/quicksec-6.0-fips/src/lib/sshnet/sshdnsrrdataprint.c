/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Render rrdata
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshfsm.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshDnsRRData"

/* Print the resource data of type `type' to the given buffer. */
int ssh_dns_rrdata_print(unsigned char *buf, int buf_size,
                         SshDNSRRType type, unsigned char *rdata,
                         size_t rdlength, int indent)
{
  size_t len;

  if (indent < 0)
    {
      indent = 0;
    }

  len = 0;

  len += ssh_snprintf(buf + len, buf_size - len + 1, "%.*s",
                      indent, ssh_dns_packet_indent);

  if (len >= buf_size)
    return buf_size + 1;

  switch (type)
    {
    case SSH_DNS_RESOURCE_A:        /* Host address, rfc1035 */
    case SSH_DNS_RESOURCE_AAAA:     /* IP6, Address */
      {
        SshIpAddrStruct address[1];
        if (rdlength != 4 && rdlength != 16)
          goto error;
        SSH_IP_DECODE(address, rdata, rdlength);
        len += ssh_snprintf(buf + len, buf_size - len + 1, "%@",
                            ssh_ipaddr_render, address);
        break;
      }
    case SSH_DNS_RESOURCE_NS:       /* Authoritative server, rfc1035 */
    case SSH_DNS_RESOURCE_MD:       /* Mail destination, obs rfc1035 */
    case SSH_DNS_RESOURCE_MF:       /* Mail forwarder, obs rfc1035 */
    case SSH_DNS_RESOURCE_CNAME:    /* Canonical name, rfc1035 */
    case SSH_DNS_RESOURCE_MB:       /* Mailbox domain name, exp rfc1035 */
    case SSH_DNS_RESOURCE_MG:       /* Mail group member, exp rfc1035 */
    case SSH_DNS_RESOURCE_MR:       /* Mail rename name, exp rfc1035 */
    case SSH_DNS_RESOURCE_PTR:      /* Domain name pointer, rfc1035 */
    case SSH_DNS_RESOURCE_NSAP_PTR: /* Reverse NSAP lookup (deprecated) */
      {
        if (ssh_ustrnlen(rdata, rdlength) + 1 != rdlength)
          goto error;
        len += ssh_snprintf(buf + len, buf_size - len + 1, "%@",
                            ssh_dns_name_render, rdata);
        break;
      }
    case SSH_DNS_RESOURCE_SOA:      /* Start of authority zone, rfc1035 */
      {
        int len2, len3;

        len2 = ssh_ustrnlen(rdata, rdlength) + 1;
        if (len2 >= rdlength)
          goto error;
        len3 = ssh_ustrnlen(rdata + len2, rdlength - len2) + 1;
        if (len2 + len3 >= rdlength)
          goto error;
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "mname = %@%s%.*srname = %@%s%.*s",
                            ssh_dns_name_render, rdata,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_dns_name_render, rdata + len2,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent);
        if (len >= buf_size)
          return buf_size + 1;
        if (len2 + len3 + 20 != rdlength)
          goto error;
        len2 += len3;
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "serial = %ld%s%.*srefresh = %@%s%.*s"
                            "retry = %@%s%.*sexpire = %@%s%.*sminimum = %@",
                            SSH_GET_32BIT(rdata + len2),
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_format_time32buf_render, rdata + len2 + 4,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_format_time32buf_render, rdata + len2 + 8,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_format_time32buf_render, rdata + len2 + 12,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_format_time32buf_render, rdata + len2 + 16);
        break;
      }
    case SSH_DNS_RESOURCE_NULL:     /* Null resource record, exp rfc1035*/
    case SSH_DNS_RESOURCE_TXT:      /* Text strings, rfc1035 */
    case SSH_DNS_RESOURCE_X25:      /* X_25, calling address, rfc1183 */
    case SSH_DNS_RESOURCE_ISDN:     /* ISDN calling address, rfc1183 */
    case SSH_DNS_RESOURCE_NSAP:     /* NSAP address, rfc1706 */
      {
        len += ssh_snprintf(buf + len, buf_size - len + 1, "%.*@",
                            (int) rdlength, ssh_safe_text_render, rdata);
        break;
      }
    case SSH_DNS_RESOURCE_WKS:      /* Well known service, rfc1035 */
      {
        SshIpAddrStruct address[1];
        int i;

        if (rdlength < 5)
          goto error;
        SSH_IP_DECODE(address, rdata, 4);
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "%@%s%.*sproto = %@:",
                            ssh_ipaddr_render, address,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_ipproto_render, rdata[4]);

        for(i = 0; i < (rdlength - 5) * 8; i++)
          {
            if (len >= buf_size)
              return buf_size + 1;
            if (rdata[(i / 8) + 5] & (0x80 >> (i % 8)))
              len += ssh_snprintf(buf + len, buf_size - len + 1, " %d", i);
          }
        break;
      }
    case SSH_DNS_RESOURCE_HINFO:    /* Host information, rfc1035 */
      {
        int len2, len3;

        len2 = rdata[0] + 1;
        if (len2 >= rdlength)
          goto error;
        len3 = rdata[len2] + 1;
        if (len2 + len3 != rdlength)
          goto error;
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "cpu = %.*@%s%.*sos = %.*@",
                            len2 - 1, ssh_safe_text_render, rdata + 1,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            len3 - 1, ssh_safe_text_render, rdata + len2 + 1);
        break;
      }
    case SSH_DNS_RESOURCE_MINFO:    /* Mailbox information, rfc1035 */
    case SSH_DNS_RESOURCE_RP:       /* Responsible person, rfc1183 */
      {
        int len2, len3;

        len2 = ssh_ustrnlen(rdata, rdlength) + 1;
        if (len2 >= rdlength)
          goto error;
        len3 = ssh_ustrnlen(rdata + len2, rdlength - len2) + 1;
        if (len2 + len3 != rdlength)
          goto error;

        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "%@%s%.*s%@",
                            ssh_dns_name_render, rdata,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_dns_name_render, rdata + len2);
        break;
      }
    case SSH_DNS_RESOURCE_MX:       /* Mail routing information, rfc1035 */
    case SSH_DNS_RESOURCE_RT:       /* Router through, rfc1183 */
      {
        if (rdlength < 2 ||
            ssh_ustrnlen(rdata + 2, rdlength - 2) + 3 != rdlength)
          goto error;
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "preference = %d%s%.*s%@",
                            SSH_GET_16BIT(rdata),
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_dns_name_render, rdata + 2);
        break;
      }
    case SSH_DNS_RESOURCE_AFSDB:    /* AFS cell database, rfc1183 */
      {
        if (rdlength < 2 ||
            ssh_ustrnlen(rdata + 2, rdlength - 2) + 3 != rdlength)
          goto error;
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "subtype = %d%s%.*s%@",
                            SSH_GET_16BIT(rdata),
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_dns_name_render, rdata + 2);
        break;
      }
    case SSH_DNS_RESOURCE_SIG:      /* Security signature, rfc2931 */
      {
        int len2;

        if (rdlength < 18)
          goto error;
        len2 = ssh_ustrnlen(rdata + 18, rdlength - 18) + 1;
        if (18 + len >= rdlength)
          goto error;
        len +=
          ssh_snprintf(buf + len, buf_size - len + 1,
                       "type covered = %s%s%.*salg = %d%s%.*s"
                       "labels = %d%s%.*sorig ttl = %@%s%.*s"
                       "expire = %@%s%.*sinception = %@%s%.*s"
                       "key tag = %d%s%.*sname = %@%s%.*ssignature = %.*@",
                       ssh_dns_rrtype_string(SSH_GET_16BIT(rdata)),
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       rdata[2],
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       rdata[3],
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       ssh_format_time32buf_render, rdata + 4,
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       ssh_time32buf_render, rdata + 8,
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       ssh_time32buf_render, rdata + 12,
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       SSH_GET_16BIT(rdata + 16),
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       ssh_dns_name_render, rdata + 18,
                       indent == 0 ? ", " : "\n",
                       indent, ssh_dns_packet_indent,
                       rdlength - 18 - len2,
                       ssh_hex_render, rdata + 18 + len2);
        break;
      }
    case SSH_DNS_RESOURCE_KEY:      /* Security key, rfc2535 */
      {
        if (rdlength < 4)
          goto error;

        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "flags = 0x%04x%s%.*sproto = %@%s%.*s"
                            "alg = %d%s%.*spublic key = %.*@",
                            SSH_GET_16BIT(rdata),
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_ipproto_render, rdata[2],
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            rdata[3],
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            rdlength - 4, ssh_hex_render, rdata + 4);
        break;
      }
    case SSH_DNS_RESOURCE_PX:       /* X.400, mail mapping, rfc2163 */
      {
        int len2, len3;

        if (rdlength < 2)
          goto error;

        len2 = ssh_ustrnlen(rdata + 2, rdlength - 2) + 1;
        if (2 + len2 >= rdlength)
          goto error;
        len3 = ssh_ustrnlen(rdata + 2 + len2, rdlength - 2 - len2) + 1;
        if (2 + len2 + len3 != rdlength)
          goto error;

        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "preference = %d%s%.*s%@%s%.*s%@",
                            SSH_GET_16BIT(rdata),
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_dns_name_render, rdata + 2,
                            indent == 0 ? ", " : "\n",
                            indent, ssh_dns_packet_indent,
                            ssh_dns_name_render, rdata + 2 + len2);
        break;
      }
    case SSH_DNS_RESOURCE_NXT:      /* Next Valid Name in Zone, rfc2535 */
      {
        int len2;
        int i;

        len2 = ssh_ustrnlen(rdata, rdlength) + 1;
        if (len2 + 4 >= rdlength)
          goto error;
        len += ssh_snprintf(buf + len, buf_size - len + 1, "%@",
                            ssh_dns_name_render, rdata);

        for(i = 0; i < rdlength - 5; i++)
          {
            if (len >= buf_size)
              return buf_size + 1;
            if (rdata[(i / 8) + len2] & (0x80 >> (i % 8)))
              len += ssh_snprintf(buf + len, buf_size - len + 1, " %s",
                                  ssh_dns_rrtype_string(i));
          }
        break;
      }
    case SSH_DNS_RESOURCE_GPOS:     /* Geographical position,
                                       withdrawn rfc1712 */
    case SSH_DNS_RESOURCE_LOC:      /* Location Information */
    case SSH_DNS_RESOURCE_EID:      /* Endpoint identifier */
    case SSH_DNS_RESOURCE_NIMLOC:   /* Nimrod locator */
    case SSH_DNS_RESOURCE_SRV:      /* Server selection, rfc2782 */
    case SSH_DNS_RESOURCE_ATMA:     /* ATM Address */
    case SSH_DNS_RESOURCE_NAPTR:    /* Naming Authority PoinTeR,
                                       rfc2168, rfc2915 */
    case SSH_DNS_RESOURCE_KX:           /* Key Exchanger, rfc2230 */
    case SSH_DNS_RESOURCE_CERT:         /* Certificate, rfc2538 */
    case SSH_DNS_RESOURCE_A6:           /* A6, rfc2874 */
    case SSH_DNS_RESOURCE_DNAME:        /* DNAME, rfc2672 */
    case SSH_DNS_RESOURCE_SINK:         /* SINK */
    case SSH_DNS_RESOURCE_OPT:          /* OPT, rfc2671 */
    case SSH_DNS_RESOURCE_APL:          /* APL, rfc3123 */
    case SSH_DNS_RESOURCE_DS:           /* Delegation Signer, rfc3658 */
    case SSH_DNS_RESOURCE_SSHFP:        /* SSH Key Fingerprint */
    case SSH_DNS_RESOURCE_RRSIG:        /* RRSIG */
    case SSH_DNS_RESOURCE_NSEC:         /* NSEC */
    case SSH_DNS_RESOURCE_DNSKEY:       /* DNSKEY */
    case SSH_DNS_RESOURCE_UINFO:    /* User (finger) information */
    case SSH_DNS_RESOURCE_UID:      /* User ID */
    case SSH_DNS_RESOURCE_GID:      /* Group ID */
    case SSH_DNS_RESOURCE_UNSPEC:   /* Unspecified format (binary data) */
    default:
      {
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "(pretty print unimplemented) %.*@",
                            (int) rdlength, ssh_safe_text_render, rdata);
        break;
      error:
        len += ssh_snprintf(buf + len, buf_size - len + 1,
                            "(error) %.*@",
                            (int) rdlength, ssh_safe_text_render, rdata);
      }
    }
  if (len >= buf_size)
    return buf_size + 1;
  len += ssh_snprintf(buf + len, buf_size - len + 1, "%s",
                      indent == 0 ? ", " : "\n");

  return len;
}
