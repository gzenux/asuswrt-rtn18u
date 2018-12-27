/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Render dns packet.
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

#define SSH_DEBUG_MODULE "SshDnsPacketRender"

const char ssh_dns_packet_indent[] =
"\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/* Render function to render question for %@ format string for ssh_e*printf */
int ssh_dns_packet_question_render(unsigned char *buf, int buf_size,
                                   int precision, void *datum)
{
  SshDNSQuestion question = datum;
  size_t len;
  int ind;

  if (precision > 0)
    ind = precision;
  else
    ind = 0;

  len = ssh_snprintf(buf, buf_size + 1,
                     "%.*sname = %@%s%.*stype = %s (%d)%s%.*sclass = %d%s",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_name_render, question->qname,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_rrtype_string(question->qtype), question->qtype,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     question->qclass,
                     precision <= 0 ? ", " : "\n");
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

/* Render function to render record for %@ format string for ssh_e*printf */
int ssh_dns_packet_record_render(unsigned char *buf, int buf_size,
                                 int precision, void *datum)
{
  SshDNSRecord record = datum;
  int ind, new_precision;
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

  len = ssh_snprintf(buf, buf_size + 1,
                     "%.*sname = %@%s%.*stype = %s (%d)%s%.*sclass = %d%s%.*s"
                     "ttl = %@%s%.*srdlength = %zd%s%.*srdata = %s",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_name_render, record->name,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     ssh_dns_rrtype_string(record->type), record->type,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     record->dns_class,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     ssh_format_time32_render, &record->ttl,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     record->rdlength,
                     precision <= 0 ? ", " : "\n",
                     ind, ssh_dns_packet_indent,
                     precision <= 0 ? "" : "\n");
  len += ssh_dns_rrdata_print(buf + len, buf_size - len,
                              record->type, record->rdata,
                              record->rdlength,
                              new_precision);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


/* Render function to render dnspacket for %@ format string for ssh_e*printf */
int ssh_dns_packet_render(unsigned char *buf, int buf_size, int precision,
                          void *datum)
{
  SshDNSPacket packet = datum;
  int i, ind, new_precision;
  size_t len;

  ind = 0;
  new_precision = 0;

  if (precision > 0)
    {
      ind = precision;
      new_precision = precision + 1;
    }

  len = ssh_snprintf(buf, buf_size + 1,
                     "%.*sId = 0x%04x, flags = 0x%04x, op_code = %d, "
                     "response_code = %s (%d)%s",
                     ind, ssh_dns_packet_indent,
                     packet->id, packet->flags, packet->op_code,
                     ssh_dns_response_code_string(packet->response_code),
                     packet->response_code,
                     precision <= 0 ? ", " : "\n");
  if (len >= buf_size)
    return buf_size + 1;
  len += ssh_snprintf(buf + len, buf_size - len + 1,
                      "%.*squestions = %d%s",
                      ind, ssh_dns_packet_indent,
                      packet->question_count,
                      precision <= 0 ? "; " : "\n");

  for(i = 0; i < packet->question_count; i++)
    {
      if (len >= buf_size)
        return buf_size + 1;
      len += ssh_snprintf(buf + len, buf_size - len + 1,
                          "%.*@",
                          new_precision,
                          ssh_dns_packet_question_render,
                          &(packet->question_array[i]));
    }

  if (len >= buf_size)
    return buf_size + 1;
  len += ssh_snprintf(buf + len, buf_size - len + 1,
                      "%.*sanswers = %d%s",
                      ind, ssh_dns_packet_indent,
                      packet->answer_count,
                      precision <= 0 ? "; " : "\n");

  for(i = 0; i < packet->answer_count; i++)
    {
      if (len >= buf_size)
        return buf_size + 1;
      len += ssh_snprintf(buf + len, buf_size - len + 1,
                          "%.*@",
                          new_precision,
                          ssh_dns_packet_record_render,
                          &(packet->answer_array[i]));
    }

  if (len >= buf_size)
    return buf_size + 1;
  len += ssh_snprintf(buf + len, buf_size - len + 1,
                      "%.*sauthoritys = %d%s",
                      ind, ssh_dns_packet_indent,
                      packet->authority_count,
                      precision <= 0 ? "; " : "\n");

  for(i = 0; i < packet->authority_count; i++)
    {
      if (len >= buf_size)
        return buf_size + 1;
      len += ssh_snprintf(buf + len, buf_size - len + 1,
                          "%.*@",
                          new_precision,
                          ssh_dns_packet_record_render,
                          &(packet->authority_array[i]));
    }

  if (len >= buf_size)
    return buf_size + 1;
  len += ssh_snprintf(buf + len, buf_size - len + 1,
                      "%.*sadditionals = %d%s",
                      ind, ssh_dns_packet_indent,
                      packet->additional_count,
                      precision <= 0 ? "; " : "\n");

  for(i = 0; i < packet->additional_count; i++)
    {
      if (len >= buf_size)
        return buf_size + 1;
      len += ssh_snprintf(buf + len, buf_size - len + 1,
                          "%.*@",
                          new_precision,
                          ssh_dns_packet_record_render,
                          &(packet->additional_array[i]));
    }
  if (len >= buf_size)
    return buf_size + 1;
  len += ssh_snprintf(buf + len, buf_size - len + 1,
                      "%.*s<end>",
                      ind, ssh_dns_packet_indent);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

