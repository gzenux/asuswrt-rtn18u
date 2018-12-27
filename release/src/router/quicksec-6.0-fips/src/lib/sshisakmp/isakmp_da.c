/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp data attribute module.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkeDa"

/*                                                              shade{0.9}
 * Decode data attribute length. Returns number of bytes
 * used by this attribute. Assumes the buffer have at
 * least 4 bytes.                                               shade{1.0}
 */
size_t ssh_ike_decode_data_attribute_size(const unsigned char *buffer,
                                          SshUInt32 flags)
{
  SshUInt16 type;
  size_t padding, len;

  type = SSH_IKE_GET16(buffer);
  len = SSH_IKE_GET16(buffer + 2);
  padding = 0;
  if ((type & 0x8000) != 0)
    {
      SSH_DEBUG(10, ("decode_size B: "
                     "type = %d (0x%04x), value = %d (0x%04x), size = 4",
                     type & 0x7fff, type & 0x7fff, len, len));
      return 4;
    }
  else
    {
      SSH_DEBUG(10, ("decode_size V: "
                     "type = %d (0x%04x), len = %d (0x%04x), padding = %d, "
                     "size = %d",
                     type, type, len, len, padding, len + padding + 4));
      return len + padding + 4;
    }
}

/*                                                              shade{0.9}
 * Decode data attribute, and fill attribute_filled
 * structure with pointer to buffer given to it. Note
 * this doesn't allocate buffer for data, nor
 * it copies data anywhere, it will just return pointer
 * to buffer given to it. The attribute value is valid
 * as long as the buffer given to this function is
 * valid. Return false if error occured (not enough
 * data in buffer etc). If used_bytes is non null the
 * number of used bytes is stored there.                        shade{1.0}
 */
Boolean ssh_ike_decode_data_attribute(unsigned char *buffer,
                                      size_t buffer_len,
                                      size_t *used_bytes,
                                      SshIkeDataAttribute attribute_filled,
                                      SshUInt32 flags)
{
  SshUInt16 type;
  size_t padding, len;

  padding = 0;
  if (buffer_len < 4)
    return FALSE;
  type = SSH_IKE_GET16(buffer);
  len = SSH_IKE_GET16(buffer + 2);
  if ((type & 0x8000) != 0)
    {
      attribute_filled->attribute_type = type & 0x7fff;
      attribute_filled->attribute_length = 2;
      attribute_filled->attribute = buffer + 2;
      if (used_bytes != NULL)
        *used_bytes = 4;
      SSH_DEBUG(10, ("decode B: "
                     "type = %d (0x%04x), value = %d (0x%04x), len = 2, "
                     "used_bytes = 4",
                    type & 0x7fff, type & 0x7fff, len, len));
    }
  else
    {
      if (buffer_len < len + padding + 4)
        return FALSE;
      attribute_filled->attribute_type = type;
      attribute_filled->attribute_length = len;
      attribute_filled->attribute = buffer + 4 + padding;
      if (used_bytes != NULL)
        *used_bytes = len + padding + 4;
      SSH_DEBUG(10, ("decode V: "
                     "type = %d (0x%04x), len = %d (0x%04x), padding = %d, "
                     "used_bytes = %d, value = %08lx %08lx ...",
                     type, type, len, len,
                     padding, len + padding + 4,
                     (unsigned long)
                     SSH_IKE_GET32(attribute_filled->attribute),
                     (unsigned long)
                     SSH_IKE_GET32(attribute_filled->attribute + 4)));
    }
  return TRUE;
}

/*                                                              shade{0.9}
 * Decode data attribute, sets the value_return to
 * data value and returns true. If the value cannot
 * be represented in 32 bit integer, return false.              shade{1.0}
 */
Boolean ssh_ike_decode_data_attribute_int(const unsigned char *buffer,
                                          size_t buffer_len,
                                          SshUInt16 *type_return,
                                          SshUInt32 *value_return,
                                          SshUInt32 flags)
{
  SshUInt16 type;
  size_t len;

  if (buffer_len < 4)
    return FALSE;
  type = SSH_IKE_GET16(buffer);
  len = SSH_IKE_GET16(buffer + 2);
  if ((type & 0x8000) != 0)
    {
      *type_return = type & 0x7fff;
      *value_return = len;
      SSH_DEBUG(10, ("decode_int B: "
                     "type = %d (0x%04x), value = %d (0x%04x), len = 2, "
                     "used_bytes = 4",
                    type & 0x7fff, type & 0x7fff, len, len));
    }
  else
    {
      if (buffer_len < 4 + len || len > 4)
        return FALSE;
      *type_return = type;
      switch (len)
        {
        case 0: *value_return = 0; break;
        case 1: *value_return = SSH_IKE_GET8(buffer + 4); break;
        case 2: *value_return = SSH_IKE_GET16(buffer + 4); break;
        case 3: *value_return = SSH_IKE_GET24(buffer + 4); break;
        case 4: *value_return = SSH_IKE_GET32(buffer + 4); break;
        }
      SSH_DEBUG(10, ("decode_int V: "
                     "type = %d (0x%04x), value = %d (0x%08x), "
                     "len = %zd (0x%04zx)",
                     type, type, (int) *value_return, (int) *value_return,
                     len, len));
    }
  return TRUE;
}


/*                                                              shade{0.9}
 * Read 32 bit integer from data attribute. If the
 * value cannot be represented in 32 bit integer,
 * return false.                                                shade{1.0}
 */
Boolean ssh_ike_get_data_attribute_int(SshIkeDataAttribute da,
                                       SshUInt32 *value_return,
                                       SshUInt32 flags)
{
  if (da->attribute_length > 4)
    return FALSE;
  if (da->attribute_length == 4)
    *value_return = SSH_IKE_GET32(da->attribute);
  else if (da->attribute_length == 3)
    *value_return = SSH_IKE_GET24(da->attribute);
  else if (da->attribute_length == 2)
    *value_return = SSH_IKE_GET16(da->attribute);
  else if (da->attribute_length == 1)
    *value_return = SSH_IKE_GET8(da->attribute);
  else if (da->attribute_length == 0)
    *value_return = 0;
  SSH_DEBUG(10, ("get_int: "
                 "type = %d (0x%04x), value = %d (0x%08x), "
                 "len = %zd (0x%04zx)",
                 da->attribute_type, da->attribute_type,
                 (int) *value_return, (int) *value_return,
                 da->attribute_length, da->attribute_length));
  return TRUE;
}

/*                                                              shade{0.9}
 * Encode data attribute and append it to buffer. Returns
 * number of bytes appended to buffer.                          shade{1.0}
 */
size_t ssh_ike_encode_data_attribute(SshBuffer buffer,
                                     SshIkeDataAttribute attribute,
                                     SshUInt32 flags)
{
  size_t length, padding;
  unsigned char *p;
  SshUInt16 type;

  padding = 0;
  type = attribute->attribute_type;
  if (attribute->attribute_length == 0)
    {
      SSH_DEBUG(10, ("encode B: type = %d (0x%04x), len = %d, no value",
                     type, type, attribute->attribute_length));
      type &= ~0x8000;
      length = 4;
      if (ssh_buffer_append_space(buffer, &p, length) != SSH_BUFFER_OK)
        return -1;
      SSH_IKE_PUT16(p, type);
      p += 2;
      SSH_IKE_PUT16(p, attribute->attribute_length);
      return length;
    }
  else if (attribute->attribute_length == 2)
    {
      SSH_DEBUG(10, ("encode B: type = %d (0x%04x), len = %d, value = %04x",
                    type, type, attribute->attribute_length,
                    SSH_IKE_GET16(attribute->attribute)));
      type |= 0x8000;
      length = 4;
      padding = 2 - attribute->attribute_length;
    }
  else
    {
      length = 4 + attribute->attribute_length + padding;
      SSH_DEBUG(10, ("encode V: "
                     "type = %d (0x%04x), len = %zd (0x%04zx), "
                     "value = %08lx ...",
                     type, type, attribute->attribute_length,
                     attribute->attribute_length,
                     (unsigned long)
                     SSH_IKE_GET32(attribute->attribute)));
      type &= ~0x8000;
    }
  if (ssh_buffer_append_space(buffer, &p, length) != SSH_BUFFER_OK)
    return -1;
  SSH_IKE_PUT16(p, type);
  p += 2;
  if (attribute->attribute_length &&
      attribute->attribute_length != 2)
    {
      SSH_IKE_PUT16(p, attribute->attribute_length);
      p += 2;
    }
  if (padding != 0)
    memset(p, 0, padding);
  memcpy(p + padding, attribute->attribute, attribute->attribute_length);
  return length;
}

/*                                                              shade{0.9}
 * Encode integer as data attribute and append
 * it to buffer. Returns number of bytes appended
 * to buffer. If use_16_bits is true then value
 * is encoded as 16 bit number, otherwise it is
 * encoded as 32 bit number. Returns -1 in case of
 * error (value to big to be represented as 16 bit value).      shade{1.0}
 */
size_t ssh_ike_encode_data_attribute_int(SshBuffer buffer,
                                         SshUInt16 type,
                                         Boolean use_16_bits,
                                         SshUInt32 attribute,
                                         SshUInt32 flags)
{
  unsigned char buf[4];
  struct SshIkeDataAttributeRec data;

  data.attribute_type = type & 0x7fff;
  if (use_16_bits)
    {
      if (attribute > 0xffff)
        {
          return -1;
        }
      SSH_IKE_PUT16(buf, attribute);
      data.attribute = buf;
      data.attribute_length = 2;
    }
  else
    {
      SSH_IKE_PUT32(buf, attribute);
      data.attribute = buf;
      data.attribute_length = 4;
    }
  return ssh_ike_encode_data_attribute(buffer, &data, flags);
}
