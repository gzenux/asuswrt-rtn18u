/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS packet encode and decode routines.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshencode.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshDnsPacket"

/* Allocate new packet. This will also automatically allocate space for the
   given number of question, answer, authority, and additional records. Those
   records are initialized to zeros. Returns NULL if out of memory. */
SshDNSPacket ssh_dns_packet_allocate(SshUInt16 question_count,
                                     SshUInt16 answer_count,
                                     SshUInt16 authority_count,
                                     SshUInt16 additional_count)
{
  SshObStackConfStruct obstack_conf[1];
  SshDNSPacket packet;

  packet = ssh_calloc(1, sizeof(*packet));
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating packet"));
      return NULL;
    }

  /* Make sure we have enough space for the full sized dns packet. */
  obstack_conf->prealloc_size = 512;

  /* Do not set max size. */
  obstack_conf->max_size = 0;

  /* Allocate obstack. */
  packet->obstack = ssh_obstack_create(obstack_conf);

  if (packet->obstack == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating packet"));
      ssh_free(packet);
      return NULL;
    }

  packet->question_count = question_count;
  packet->answer_count = answer_count;
  packet->authority_count = authority_count;
  packet->additional_count = additional_count;

  if (packet->question_count != 0)
    packet->question_array =
      ssh_obstack_calloc(packet->obstack, question_count *
                         sizeof(SshDNSQuestionStruct));
  if (packet->answer_count != 0)
    packet->answer_array =
      ssh_obstack_calloc(packet->obstack, answer_count *
                         sizeof(SshDNSRecordStruct));
  if (packet->authority_count != 0)
    packet->authority_array =
      ssh_obstack_calloc(packet->obstack, authority_count *
                         sizeof(SshDNSRecordStruct));
  if (packet->additional_count != 0)
    packet->additional_array =
      ssh_obstack_calloc(packet->obstack, additional_count *
                         sizeof(SshDNSRecordStruct));

  if ((packet->question_count != 0 && packet->question_array == NULL) ||
      (packet->answer_count != 0 && packet->answer_array == NULL) ||
      (packet->authority_count != 0 && packet->authority_array == NULL) ||
      (packet->additional_count != 0 && packet->additional_array == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating packet"));
      ssh_dns_packet_free(packet);
      return NULL;
    }
  return packet;
}

/* Free dns packet. */
void ssh_dns_packet_free(SshDNSPacket packet)
{
  ssh_obstack_destroy(packet->obstack);
  ssh_free(packet);
}

/* Return name length or 0 if error. The offset_ptr is modified to
   include the max offset used in packet_buffer. */
size_t ssh_dns_packet_decode_name_len(const unsigned char *packet_buffer,
                                      size_t packet_length,
                                      size_t *offset_ptr)
{
  size_t len, offset, new_offset;
  Boolean jumped;
  int i;

  len = 1;
  offset = *offset_ptr;
  jumped = FALSE;
  if (offset >= packet_length)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated name"));
      return 0;
    }
  *offset_ptr = offset + 1;
  while (packet_buffer[offset] != 0)
    {
      if ((packet_buffer[offset] & 0xc0) == 0xc0)
        {
          /* Compressed data pointer. */
          if (offset + 2 > packet_length)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Compression offset does not fit to buffer"));
              return 0;
            }
          if (!jumped)
            *offset_ptr = offset + 2;
          new_offset = SSH_GET_16BIT(packet_buffer + offset) & 0x3fff;
          if (new_offset >= offset)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Compression offset point to outside parsed buffer"));
              return 0;
            }
          offset = new_offset;
          jumped = TRUE;
        }
      else
        {
          /* Label, check the length. */
          if (offset + packet_buffer[offset] > packet_length)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Label does not fit to buffer"));
              return 0;
            }
          /* Label cannot contain nuls. */
          for(i = packet_buffer[offset]; i > 1; i--)
            if (!packet_buffer[offset + i])
              {
                SSH_DEBUG(SSH_D_NETGARB, ("Nul in label"));
                return 0;
              }
          len += packet_buffer[offset] + 1;
          offset += packet_buffer[offset] + 1;
          if (!jumped)
            *offset_ptr = offset + 1;
        }
      if (len > SSH_DNS_MAX_NAME_LEN)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Length exceeds dns max name len"));
          return 0;
        }
      if (offset >= packet_length)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Truncated name"));
          return 0;
        }
    }
  return len;
}

/* Copy name to given buffer. The buffer size must be correct. */
void ssh_dns_packet_decode_name_copy(const unsigned char *packet_buffer,
                                     size_t packet_length,
                                     size_t offset,
                                     unsigned char *data)
{
  while (packet_buffer[offset] != 0)
    {
      if ((packet_buffer[offset] & 0xc0) == 0xc0)
        {
          /* Compressed data pointer. */
          offset = SSH_GET_16BIT(packet_buffer + offset) & 0x3fff;
        }
      else
        {
          /* Copy the label. */
          memcpy(data, packet_buffer + offset, packet_buffer[offset] + 1);
          data += packet_buffer[offset] + 1;
          offset += packet_buffer[offset] + 1;
        }
    }
  /* Add the last item (root). */
  data[0] = 0;
  return;
}

/* Decode name, and decompress it. Returns true if successfull and FALSE if
   there is error. */
Boolean ssh_dns_packet_decode_name(SshDNSPacket packet,
                                   const unsigned char *packet_buffer,
                                   size_t packet_length,
                                   size_t *offset_ptr,
                                   unsigned char **data_ptr)
{
  unsigned char *data;
  size_t offset, len;

  offset = *offset_ptr;
  len = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                       offset_ptr);
  if (len == 0)
    return FALSE;

  data = ssh_obstack_alloc_unaligned(packet->obstack, len);
  if (data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate space for name length = %d",
                             len));
      return FALSE;
    }

  *data_ptr = data;
  ssh_dns_packet_decode_name_copy(packet_buffer, packet_length, offset, data);
  return TRUE;
}

/* Decode question. */
Boolean ssh_dns_packet_decode_question(SshDNSPacket packet,
                                       const unsigned char *packet_buffer,
                                       size_t packet_length,
                                       size_t *offset_ptr,
                                       SshDNSQuestion question)
{
  SshUInt16 qtype, qclass;
  size_t len;

  if (!ssh_dns_packet_decode_name(packet, packet_buffer, packet_length,
                                  offset_ptr, &question->qname))
    return FALSE;

  len = ssh_decode_array(packet_buffer + *offset_ptr,
                         packet_length - *offset_ptr,
                         SSH_DECODE_UINT16(&qtype),
                         SSH_DECODE_UINT16(&qclass),
                         SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Error decoding question"));
      return FALSE;
    }

  *offset_ptr += len;
  question->qtype = qtype;
  question->qclass = qclass;
  return TRUE;
}

/* Decode record. */
Boolean ssh_dns_packet_decode_record(SshDNSPacket packet,
                                     const unsigned char *packet_buffer,
                                     size_t packet_length,
                                     size_t *offset_ptr,
                                     SshDNSRecord record)
{
  SshUInt16 type, dns_class, rdlength;
  size_t len, len2, new_rdlength, offset, offset2;

  if (!ssh_dns_packet_decode_name(packet, packet_buffer, packet_length,
                                  offset_ptr, &record->name))
    return FALSE;

  len = ssh_decode_array(packet_buffer + *offset_ptr,
                         packet_length - *offset_ptr,
                         SSH_DECODE_UINT16(&type),
                         SSH_DECODE_UINT16(&dns_class),
                         SSH_DECODE_UINT32(&record->ttl),
                         SSH_DECODE_UINT16(&rdlength),
                         SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Error decoding record"));
      return FALSE;
    }

  if (*offset_ptr + len + rdlength > packet_length)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Data length in record exceeds packet size"));
      return FALSE;
    }

  record->type = type;
  record->dns_class = dns_class;
  *offset_ptr += len;

  switch (record->type)
    {
      /* One compressed name. Copy rest. */
    case SSH_DNS_RESOURCE_NS:
    case SSH_DNS_RESOURCE_MD:
    case SSH_DNS_RESOURCE_MF:
    case SSH_DNS_RESOURCE_CNAME:
    case SSH_DNS_RESOURCE_MB:
    case SSH_DNS_RESOURCE_MG:
    case SSH_DNS_RESOURCE_MR:
    case SSH_DNS_RESOURCE_PTR:
    case SSH_DNS_RESOURCE_NSAP_PTR:
    case SSH_DNS_RESOURCE_NXT:
    case SSH_DNS_RESOURCE_DNAME: /* Do not compress, but do decompress. */
    case SSH_DNS_RESOURCE_NSEC: /* Do not compress, but do decompress. */
      offset = *offset_ptr;
      len = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                           offset_ptr);
      if (len == 0)
        return FALSE;
      new_rdlength = len + rdlength - (*offset_ptr - offset);
      record->rdata = ssh_obstack_alloc(packet->obstack, new_rdlength);
      ssh_dns_packet_decode_name_copy(packet_buffer, packet_length,
                                      offset, record->rdata);
      memcpy(record->rdata + len, packet_buffer + *offset_ptr,
             new_rdlength - len);
      *offset_ptr += new_rdlength - len;
      break;

      /* Two domain name addresses, copy rest. */
    case SSH_DNS_RESOURCE_SOA:
    case SSH_DNS_RESOURCE_MINFO:
    case SSH_DNS_RESOURCE_RP:
      offset = *offset_ptr;
      len = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                           offset_ptr);
      if (len == 0)
        return FALSE;
      offset2 = *offset_ptr;
      len2 = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                            offset_ptr);
      if (len2 == 0)
        return FALSE;

      new_rdlength = len + len2 + rdlength - (*offset_ptr - offset);
      record->rdata = ssh_obstack_alloc(packet->obstack, new_rdlength);
      ssh_dns_packet_decode_name_copy(packet_buffer, packet_length,
                                      offset, record->rdata);
      ssh_dns_packet_decode_name_copy(packet_buffer, packet_length,
                                      offset2, record->rdata + len);
      memcpy(record->rdata + len + len2, packet_buffer + *offset_ptr,
             new_rdlength - len - len2);
      *offset_ptr += new_rdlength - len - len2;
      break;

      /* 16-bit number and dns name. */
    case SSH_DNS_RESOURCE_MX:
    case SSH_DNS_RESOURCE_AFSDB:
    case SSH_DNS_RESOURCE_RT:
    case SSH_DNS_RESOURCE_KX: /* Do not compress, but do decompress. */
      len2 = 2;
    copy_name_copy:
      offset = *offset_ptr;
      *offset_ptr += len2;
      len = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                           offset_ptr);
      if (len == 0)
        return FALSE;
      new_rdlength = len2 + len + rdlength - (*offset_ptr - offset);
      record->rdata = ssh_obstack_alloc(packet->obstack, new_rdlength);
      memcpy(record->rdata, packet_buffer + offset, len2);
      ssh_dns_packet_decode_name_copy(packet_buffer, packet_length,
                                      offset + len2, record->rdata + len2);
      memcpy(record->rdata + len2 + len, packet_buffer + *offset_ptr,
             new_rdlength - len2 - len);
      *offset_ptr += new_rdlength - len2 - len;
      break;

      /* Copy 9 bytes, then decompress signers name, and then copy rest. */
    case SSH_DNS_RESOURCE_SIG:
    case SSH_DNS_RESOURCE_RRSIG: /* Docompress, must not compress */
      len2 = 9;
      goto copy_name_copy;

      /* 16-bit number and 2 dns names. */
    case SSH_DNS_RESOURCE_PX:
      offset = *offset_ptr;
      *offset_ptr += 2;
      len = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                           offset_ptr);
      if (len == 0)
        return FALSE;
      offset2 = *offset_ptr;
      len2 = ssh_dns_packet_decode_name_len(packet_buffer, packet_length,
                                            offset_ptr);
      if (len2 == 0)
        return FALSE;

      new_rdlength = len + len2 + rdlength - (*offset_ptr - offset);
      record->rdata = ssh_obstack_alloc(packet->obstack, new_rdlength);
      memcpy(record->rdata, packet_buffer + offset, 2);
      ssh_dns_packet_decode_name_copy(packet_buffer, packet_length,
                                      offset + 2, record->rdata + 2);
      ssh_dns_packet_decode_name_copy(packet_buffer, packet_length,
                                      offset2, record->rdata + len + 2);
      memcpy(record->rdata + 2 + len + len2, packet_buffer + *offset_ptr,
             new_rdlength - 2 - len - len2);
      *offset_ptr += new_rdlength - 2 - len - len2;
      break;

      /* 3 16-bit numbers and dns name. */
    case SSH_DNS_RESOURCE_SRV:  /* Do not compress, but do decompress */
      len2 = 6;
      goto copy_name_copy;

      /* Special handling. */
    case SSH_DNS_RESOURCE_OPT:
      /* The special OPT handling is to parse the data and then copy it.
         i.e. we will fall through to the next case. */
      packet->response_code |= ((record->ttl & 0xff000000) >> 24) << 4;
      /* We leave rest of the special stuff (i.e. senders UDP payload size
         version, extra flags, etc in the class, ttl etc fields, and there
         might be some attribute value pairs also). */

      /* Just copy data. */
    case SSH_DNS_RESOURCE_A:
    case SSH_DNS_RESOURCE_NULL:
    case SSH_DNS_RESOURCE_WKS:
    case SSH_DNS_RESOURCE_HINFO:
    case SSH_DNS_RESOURCE_TXT:
    case SSH_DNS_RESOURCE_X25:
    case SSH_DNS_RESOURCE_ISDN:
    case SSH_DNS_RESOURCE_NSAP:
    case SSH_DNS_RESOURCE_KEY:
    case SSH_DNS_RESOURCE_GPOS:
    case SSH_DNS_RESOURCE_AAAA:
    case SSH_DNS_RESOURCE_LOC:
    case SSH_DNS_RESOURCE_NAPTR: /* Contains name, and rfc2168 says it is
                                    compressed, but rfc2915 says that will not
                                    be compressed. */
    case SSH_DNS_RESOURCE_CERT:
    case SSH_DNS_RESOURCE_A6:   /* Contains name, but MUST NOT be compr. */
    case SSH_DNS_RESOURCE_APL:
    case SSH_DNS_RESOURCE_DS:
    case SSH_DNS_RESOURCE_SSHFP:
    case SSH_DNS_RESOURCE_DNSKEY:
    case SSH_DNS_QUERY_TKEY:
    case SSH_DNS_QUERY_TSIG:
      /* Unknown, just copy. */
    case SSH_DNS_RESOURCE_EID:
    case SSH_DNS_RESOURCE_NIMLOC:
    case SSH_DNS_RESOURCE_ATMA:
    case SSH_DNS_RESOURCE_SINK:
    case SSH_DNS_RESOURCE_UINFO:
    case SSH_DNS_RESOURCE_UID:
    case SSH_DNS_RESOURCE_GID:
    case SSH_DNS_RESOURCE_UNSPEC:
      /* Query typedef values which do not appear in resource records, copy */
    case SSH_DNS_QUERY_IXFR:
    case SSH_DNS_QUERY_AXFR:
    case SSH_DNS_QUERY_MAILB:
    case SSH_DNS_QUERY_MAILA:
    case SSH_DNS_QUERY_ANY:
    default:
      record->rdata = ssh_obstack_memdup(packet->obstack,
                                         packet_buffer + *offset_ptr,
                                         rdlength);
      *offset_ptr += rdlength;
      new_rdlength = rdlength;
      break;
    }
  record->rdlength = new_rdlength;

  return TRUE;

}

/* Decode packet. This returns NULL if there is memory error or parse error,
   otherwise it will return the decoded packet. */
SshDNSPacket ssh_dns_packet_decode(const unsigned char *packet_buffer,
                                   size_t packet_length)
{
  SshUInt16 question_count, answer_count, authority_count, additional_count;
  SshUInt16 id, flags;
  SshDNSPacket packet;
  size_t len;
  int i;

  len = ssh_decode_array(packet_buffer, packet_length,
                         SSH_DECODE_UINT16(&id),
                         SSH_DECODE_UINT16(&flags),
                         SSH_DECODE_UINT16(&question_count),
                         SSH_DECODE_UINT16(&answer_count),
                         SSH_DECODE_UINT16(&authority_count),
                         SSH_DECODE_UINT16(&additional_count),
                         SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Error decoding dns packet"));
      return NULL;
    }

  packet = ssh_dns_packet_allocate(question_count, answer_count,
                                   authority_count, additional_count);
  if (packet == NULL)
    return NULL;

  packet->id = id;
  packet->flags = flags & SSH_DNS_FLAG_MASK;
  packet->op_code = (flags >> 11) & 0xf;
  packet->response_code = flags & 0xf;

  for (i = 0; i < question_count; i++)
    {
      if (!ssh_dns_packet_decode_question(packet, packet_buffer,
                                          packet_length, &len,
                                          &(packet->question_array[i])))
        goto error;
    }
  for (i = 0; i < answer_count; i++)
    {
      if (!ssh_dns_packet_decode_record(packet, packet_buffer,
                                        packet_length, &len,
                                        &(packet->answer_array[i])))
        goto error;
    }
  for (i = 0; i < authority_count; i++)
    {
      if (!ssh_dns_packet_decode_record(packet, packet_buffer,
                                        packet_length, &len,
                                        &(packet->authority_array[i])))
        goto error;
    }
  for (i = 0; i < additional_count; i++)
    {
      if (!ssh_dns_packet_decode_record(packet, packet_buffer,
                                        packet_length, &len,
                                        &(packet->additional_array[i])))
        goto error;
    }
  if (packet_length > len)
    {



      SSH_DEBUG(SSH_D_NETGARB, ("Dns packet contains %d bytes of extra data",
                                packet_length - len));
    }
  return packet;
 error:
  ssh_dns_packet_free(packet);
  return NULL;
}

/* Compress map entry. */
typedef struct SshDNSCompressMapEntryRec {
  struct SshDNSCompressMapEntryRec *next;
  /* Pointer to the compressed string. */
  unsigned char *ptr;
  /* Offset to the beginning of the string. */
  size_t offset;
  /* Length of the entry. */
  size_t length;
} *SshDNSCompressMapEntry, SshDNSCompressMapEntryStruct;

typedef struct SshDNSCompressMapRec {
  SshDNSCompressMapEntry first;
  SshDNSCompressMapEntry last;
} *SshDNSCompressMap, SshDNSCompressMapStruct;

/* Allocate compress map. */
SshDNSCompressMap ssh_dns_compress_map_allocate(void)
{
  SshDNSCompressMap map;

  map = ssh_calloc(1, sizeof(*map));
  return map;
}

/* Free compress map. */
void ssh_dns_compress_map_free(SshDNSCompressMap map)
{
  SshDNSCompressMapEntry current, next;

  current = map->first;
  while (current != NULL)
    {
      next = current->next;
      ssh_free(current);
      current = next;
    }
  ssh_free(map);
}

/* Add entry to the map. */
void ssh_dns_compress_map_add(SshDNSCompressMap map,
                              unsigned char *ptr,
                              size_t offset)
{
  SshDNSCompressMapEntry entry;

  entry = ssh_calloc(1, sizeof(*entry));
  if (entry == NULL)
    return;
  entry->ptr = ptr;
  entry->offset = offset;
  entry->length = ssh_ustrlen(ptr);
  if (map->last == NULL)
    {
      map->first = map->last = entry;
    }
  else
    {
      map->last->next = entry;
      map->last = entry;
    }
}

/* Find entry from the map, returns the offset or 0 if not found. */
SshUInt16 ssh_dns_compress_map_find(SshDNSCompressMap map,
                                    unsigned char *ptr)
{
  SshDNSCompressMapEntry entry;
  size_t len;

  len = ssh_ustrlen(ptr);
  for(entry = map->first; entry != NULL; entry = entry->next)
    {
      /* See if they can match. If the entry in the map is shorter,
         they cannot match. */
      if (entry->length < len)
        continue;

      /* Match the entries. */
      if (ssh_ustrcmp(entry->ptr + entry->length - len, ptr) != 0)
        continue;

      /* Yes, they matched, return offset. */
      return entry->offset + entry->length - len;
    }
  return 0;
}

/* Encode name. Return the number of bytes written to buffer. */
size_t ssh_dns_packet_encode_name(unsigned char *buffer,
                                  size_t buffer_length,
                                  size_t offset,
                                  unsigned char *name,
                                  SshDNSCompressMap map)
{
  size_t len, len2;
  SshUInt16 compression_ptr;
  Boolean added;

  len = 0;
  added = FALSE;
  while (*name != 0)
    {
      compression_ptr = ssh_dns_compress_map_find(map, name);
      if (compression_ptr != 0 && compression_ptr != offset)
        {
          /* We can compress rest away, we need 2 bytes for it. */
          if (buffer_length < offset + 2)
            return 0;
          SSH_PUT_16BIT(buffer + offset, compression_ptr | 0xc000);
          return len + 2;
        }

      /* Add entry to the compression map, if we haven't yet added it there. */
      if (!added)
        {
          ssh_dns_compress_map_add(map, name, offset);
          added = TRUE;
        }

      /* Ok, check the length and copy the label. */
      len2 = (*name) + 1;
      if (buffer_length < offset + len2)
        return 0;

      /* Copy data. */
      memcpy(buffer + offset, name, len2);

      /* Move to the next label. */
      name += len2;
      offset += len2;
      len += len2;
    }
  /* Mark the end. */
  buffer[offset] = '\0';
  return len + 1;
}

/* Encode question. */
size_t ssh_dns_packet_encode_question(unsigned char *buffer,
                                      size_t buffer_length,
                                      size_t offset,
                                      SshDNSQuestion question,
                                      SshDNSCompressMap map)
{
  size_t len, len2;

  len = ssh_dns_packet_encode_name(buffer, buffer_length, offset,
                                   question->qname, map);
  if (len == 0)
    return 0;

  len2 = ssh_encode_array(buffer + offset + len,
                          buffer_length - offset - len,
                          SSH_ENCODE_UINT16(question->qtype),
                          SSH_ENCODE_UINT16(question->qclass),
                          SSH_FORMAT_END);
  if (len2 == 0)
    return 0;
  return len + len2;
}

/* Encode record. */
size_t ssh_dns_packet_encode_record(unsigned char *buffer,
                                    size_t buffer_length,
                                    size_t offset,
                                    SshDNSRecord record,
                                    SshDNSCompressMap map)
{
  size_t len, len2, len3, rdlength;

  len = ssh_dns_packet_encode_name(buffer, buffer_length, offset,
                                   record->name, map);
  if (len == 0)
    return 0;

  len2 = ssh_encode_array(buffer + offset + len,
                          buffer_length - offset - len,
                          SSH_ENCODE_UINT16(record->type),
                          SSH_ENCODE_UINT16(record->dns_class),
                          SSH_ENCODE_UINT32(record->ttl),
                          SSH_ENCODE_UINT16(0),
                          SSH_FORMAT_END);
  if (len2 == 0)
    return 0;

  /* Offset points to the beginning of rdata. */
  offset += len + len2;
  len += len2;

  switch (record->type)
    {
      /* One compressed name. Copy rest. */
    case SSH_DNS_RESOURCE_NS:
    case SSH_DNS_RESOURCE_MD:
    case SSH_DNS_RESOURCE_MF:
    case SSH_DNS_RESOURCE_CNAME:
    case SSH_DNS_RESOURCE_MB:
    case SSH_DNS_RESOURCE_MG:
    case SSH_DNS_RESOURCE_MR:
    case SSH_DNS_RESOURCE_PTR:
      rdlength = ssh_dns_packet_encode_name(buffer, buffer_length,
                                            offset, record->rdata, map);
      if (rdlength == 0)
        return 0;
      len2 = ssh_ustrnlen(record->rdata, record->rdlength) + 1;
      goto copy_rest;
      break;

      /* Two domain name addresses, copy rest. */
    case SSH_DNS_RESOURCE_SOA:
    case SSH_DNS_RESOURCE_MINFO:
      rdlength = ssh_dns_packet_encode_name(buffer, buffer_length,
                                            offset, record->rdata, map);
      if (rdlength == 0)
        return 0;
      len3 = ssh_ustrnlen(record->rdata, record->rdlength) + 1;
      if (len3 >= record->rdlength)
        return 0;
      len2 = ssh_dns_packet_encode_name(buffer, buffer_length,
                                        offset + rdlength,
                                        record->rdata + len3, map);
      if (len2 == 0)
        return 0;
      rdlength += len2;
      len2 = len3 + ssh_ustrnlen(record->rdata + len3,
                                record->rdlength - len3) + 1;
      goto copy_rest;
      break;

      /* 16-bit number and dns name. */
    case SSH_DNS_RESOURCE_MX:
      len2 = 2;
      if (buffer_length < offset + len2)
        return 0;
      memcpy(buffer + offset, record->rdata, len2);

      rdlength = ssh_dns_packet_encode_name(buffer, buffer_length,
                                            offset + len2,
                                            record->rdata + len2,
                                            map);
      if (rdlength == 0)
        return 0;
      rdlength += len2;
      len2 += ssh_ustrnlen(record->rdata + len2, record->rdlength - len2) + 1;
      goto copy_rest;
      break;

      /* Just copy data. */
    case SSH_DNS_RESOURCE_A:
    case SSH_DNS_RESOURCE_NULL:
    case SSH_DNS_RESOURCE_WKS:
    case SSH_DNS_RESOURCE_HINFO:
    case SSH_DNS_RESOURCE_TXT:
    case SSH_DNS_RESOURCE_X25:
    case SSH_DNS_RESOURCE_ISDN:
    case SSH_DNS_RESOURCE_NSAP:
    case SSH_DNS_RESOURCE_KEY:
    case SSH_DNS_RESOURCE_GPOS:
    case SSH_DNS_RESOURCE_AAAA:
    case SSH_DNS_RESOURCE_LOC:
    case SSH_DNS_RESOURCE_NAPTR: /* Contains name, and rfc2168 says it is
                                    compressed, but rfc2915 says that will not
                                    be compressed. */
    case SSH_DNS_RESOURCE_CERT:
    case SSH_DNS_RESOURCE_A6:   /* Contains name, but MUST NOT be compr. */
    case SSH_DNS_RESOURCE_APL:
    case SSH_DNS_RESOURCE_DS:
    case SSH_DNS_RESOURCE_SSHFP:
    case SSH_DNS_RESOURCE_DNSKEY:
    case SSH_DNS_QUERY_TKEY:
    case SSH_DNS_QUERY_TSIG:
      /* Contains names, but do not compress. See RFC 3597 for details */
    case SSH_DNS_RESOURCE_DNAME: /* Do not compress, but do decompress. */
    case SSH_DNS_RESOURCE_NSEC: /* Do not compress, but do decompress. */
    case SSH_DNS_RESOURCE_KX: /* Do not compress, but do decompress. */
    case SSH_DNS_RESOURCE_RRSIG: /* Docompress, must not compress */
    case SSH_DNS_RESOURCE_SRV:  /* Do not compress, but do decompress */
    case SSH_DNS_RESOURCE_NSAP_PTR: /* Do not compress */
    case SSH_DNS_RESOURCE_NXT:  /* Do not compress */
    case SSH_DNS_RESOURCE_RP:   /* Do not compress */
    case SSH_DNS_RESOURCE_AFSDB: /* Do not compress */
    case SSH_DNS_RESOURCE_RT:   /* Do not compress */
    case SSH_DNS_RESOURCE_SIG:  /* Do not compress */
    case SSH_DNS_RESOURCE_PX:   /* Do not compress */
      /* Special handling, we just copy it, we assume that if the sender wants
         to use the extended flags etc, he will add OPT record himself, i.e. we
         do not try to parse the response codes etc to see if there is
         something which would need OPT record. . */
    case SSH_DNS_RESOURCE_OPT:
      /* Unknown, just copy. */
    case SSH_DNS_RESOURCE_EID:
    case SSH_DNS_RESOURCE_NIMLOC:
    case SSH_DNS_RESOURCE_ATMA:
    case SSH_DNS_RESOURCE_SINK:
    case SSH_DNS_RESOURCE_UINFO:
    case SSH_DNS_RESOURCE_UID:
    case SSH_DNS_RESOURCE_GID:
    case SSH_DNS_RESOURCE_UNSPEC:
      /* Query typedef values which do not appear in resource records, copy */
    case SSH_DNS_QUERY_IXFR:
    case SSH_DNS_QUERY_AXFR:
    case SSH_DNS_QUERY_MAILB:
    case SSH_DNS_QUERY_MAILA:
    case SSH_DNS_QUERY_ANY:
    default:
      rdlength = 0;
      len2 = 0;
    copy_rest:
      /* Len2 is the number of bytes consumed from the record->rdata. */
      if (buffer_length < offset + rdlength + record->rdlength - len2)
        return 0;
      memcpy(buffer + offset + rdlength, record->rdata + len2,
             record->rdlength - len2);
      rdlength += record->rdlength - len2;
    }

  /* Fix the length. It is stored just before the rdata. */
  SSH_PUT_16BIT(buffer + offset - 2, rdlength);
  return len + rdlength;
}

/* Encode packet. This will store the packet to the given buffer of size
   packet_length. This will return the number of bytes consumed from the
   packet, and if the packet cannot fit to the buffer given then the truncated
   flag is set on the packet, and return value is number of bytes actually used
   from the buffer, but it is given out as negative number. If there is error
   (out of memory, etc then this will return 0). */
int ssh_dns_packet_encode(SshDNSPacket packet, unsigned char *buffer,
                          size_t buffer_length)
{
  SshUInt16 question_count, answer_count, authority_count, additional_count;
  SshDNSCompressMap map;
  SshUInt16 flags;
  size_t len2;
  int len;
  int i;

  flags = packet->flags | (packet->op_code << 11) | packet->response_code;
  /* The fixed header is put in place last, allocate space for it. */
  len = 12;
  if (buffer_length < len)
    return 0;

  /* Initially set all counts to 0. */
  question_count = 0;
  answer_count = 0;
  authority_count = 0;
  additional_count = 0;

  /* Initialize compress map. */
  map = ssh_dns_compress_map_allocate();
  if (!map)
    return 0;

  /* Encode question. */
  for(i = 0; i < packet->question_count; i++)
    {
      len2 = ssh_dns_packet_encode_question(buffer, buffer_length, len,
                                            &(packet->question_array[i]),
                                            map);
      if (len2 == 0)
        {
          question_count = i;
          flags |= SSH_DNS_FLAG_TRUNCATED;
          len = -len;
          goto truncated;
        }
      len += len2;
    }
  question_count = packet->question_count;

  /* Encode answer. */
  for(i = 0; i < packet->answer_count; i++)
    {
      len2 = ssh_dns_packet_encode_record(buffer, buffer_length, len,
                                          &(packet->answer_array[i]),
                                          map);
      if (len2 == 0)
        {
          answer_count = i;
          flags |= SSH_DNS_FLAG_TRUNCATED;
          len = -len;
          goto truncated;
        }
      len += len2;
    }
  answer_count = packet->answer_count;

  /* Encode authority section. */
  for(i = 0; i < packet->authority_count; i++)
    {
      len2 = ssh_dns_packet_encode_record(buffer, buffer_length, len,
                                          &(packet->authority_array[i]),
                                          map);
      if (len2 == 0)
        {
          authority_count = i;
          flags |= SSH_DNS_FLAG_TRUNCATED;
          len = -len;
          goto truncated;
        }
      len += len2;
    }
  authority_count = packet->authority_count;

  /* Encode additional section. */
  for(i = 0; i < packet->additional_count; i++)
    {
      len2 = ssh_dns_packet_encode_record(buffer, buffer_length, len,
                                          &(packet->additional_array[i]),
                                          map);
      if (len2 == 0)
        {
          additional_count = i;
          flags |= SSH_DNS_FLAG_TRUNCATED;
          len = -len;
          goto truncated;
        }
      len += len2;
    }
  additional_count = packet->additional_count;
 truncated:
  len2 = ssh_encode_array(buffer, buffer_length,
                          SSH_ENCODE_UINT16(packet->id),
                          SSH_ENCODE_UINT16(flags),
                          SSH_ENCODE_UINT16(question_count),
                          SSH_ENCODE_UINT16(answer_count),
                          SSH_ENCODE_UINT16(authority_count),
                          SSH_ENCODE_UINT16(additional_count),
                          SSH_FORMAT_END);
  SSH_ASSERT(len2 == 12);

  ssh_dns_compress_map_free(map);
  return len;
}
