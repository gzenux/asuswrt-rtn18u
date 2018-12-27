/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Render rrset.
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

#define SSH_DEBUG_MODULE "SshDnsRRsetRender"

/* Render function to render rrset for %@ format string for ssh_e*printf */
int ssh_dns_rrset_render(unsigned char *buf, int buf_size, int precision,
                         void *datum)
{
  SshDNSRRset rrset = datum;
  int i, ind, new_precision;
  size_t len;

  if (precision > 0)
    {
      ind = precision;
      new_precision = precision + 1;
    }
  else
    {
      ind = 0;
      new_precision = 0;
    }

  if (rrset == NULL)
    {
      len = ssh_snprintf(buf, buf_size, "%.*sNULL", ind,
                         ssh_dns_packet_indent);
      return len;
    }

  len = ssh_snprintf(buf, buf_size,
                     "%.*sState = %s (%d)%s%.*sname = %@%s%.*s"
                     "type = %s (%d)%s%.*sttl = %@%s%.*s"
                     "rrs = %d%s%.*sref_cnt/valid = %d/%d%s",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_rrsetstate_string(rrset->state), rrset->state,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_name_render, rrset->name,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_rrtype_string(rrset->type), rrset->type,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     ssh_format_time32_render, &rrset->ttl,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     (int) rrset->number_of_rrs,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     (int) rrset->reference_count, (int) rrset->valid,
                     precision <= 0 ? ", " : "\n");
  for(i = 0; i < rrset->number_of_rrs; i++)
    {
      if (len >= buf_size)
        return len;
      len += ssh_snprintf(buf + len, buf_size - len, "%.*s[%d]%s",
                          ind, ssh_dns_packet_indent,
                          i, precision <= 0 ? "; " : "\n");
      if (len >= buf_size)
        return len;
      len += ssh_dns_rrdata_print(buf + len, buf_size - len,
                                  rrset->type,
                                  rrset->array_of_rdata[i],
                                  rrset->array_of_rdlengths[i],
                                  new_precision);
    }
  return len;
}

