/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP header checksum computation.
*/

#define SSH_DEBUG_MODULE "SshIpCksum"

#include "sshincludes.h"
#include "ip_cksum.h"

/* Computes the complement of IP checksum over the buffer.  The
   checksum is returned in host byte order. */

SshUInt16 ssh_ip_cksum(const unsigned char *buf, size_t bytes)
{
  register SshUInt32 sum; /* possibly swapped */
  SshUInt32 leftover_sum; /* in network byte order */
  register const SshUInt16 *uptr;
  const void *end;

  /* Align buf. */
  if (((unsigned long)(size_t)buf & 0x01) != 0 && bytes != 0)
    {
      /* In network byte order, the first byte is always MSB. */
      leftover_sum = buf[0] << 8;
      uptr = (const SshUInt16 *)(buf + 1);
    }
  else
    {
      leftover_sum = 0;
      uptr = (const SshUInt16 *)buf;
    }

  /* Loop over the main part of the packet. */
  end = (const void *)(buf + bytes);
  sum = 0;
  while ((const void *)(uptr + 10) <= end)
    {
      sum += uptr[0];
      sum += uptr[1];
      sum += uptr[2];
      sum += uptr[3];
      sum += uptr[4];
      sum += uptr[5];
      sum += uptr[6];
      sum += uptr[7];
      sum += uptr[8];
      sum += uptr[9];
      uptr += 10;
    }
  while ((const void *)(uptr + 1) <= end)
    sum += *uptr++;

  /* Add left-over byte, if any. */
  if ((const unsigned char *)uptr < buf + bytes)
    leftover_sum += (bytes & 0x01) ? (buf[bytes - 1] << 8) : buf[bytes - 1];

  /*  Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

#ifdef WORDS_BIGENDIAN
  /* The sum is already in host byte order, but check if it needs to be
     swapped because of bad alignment. */
  if (((unsigned long)buf & 0x01) != 0)
    sum = (((sum & 0xff) << 8) | (sum >> 8));
#else /* WORDS_BIGENDIAN */
  /* Convert the checksum into host byte order, unless we also had bad
     alignment. */
  if (((unsigned long)(size_t)buf & 0x01) == 0)
    sum = (((sum & 0xff) << 8) | (sum >> 8));
#endif /* WORDS_BIGENDIAN */

  /* Add any leftover bytes, and fold again. */
  sum += leftover_sum;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}

/* Update the complement of IP checksum by having a byte change at a
   specified offset.  The input checksum and the returned checksum are
   in host byte order. */

SshUInt16 ssh_ip_cksum_update_byte(SshUInt16 cks, size_t ofs,
                                   SshUInt8 old_value, SshUInt8 new_value)
{
  SshUInt32 sum;

  sum = (~cks) & 0xffff;

  /* Update the sum. */
  if (ofs & 0x01)
    {
      sum -= old_value;
      sum = (sum & 0xffff) + (sum >> 16);
      sum &= 0xffff;
      sum += new_value;
    }
  else
    {
      sum -= ((SshUInt32)old_value << 8) & 0xff00;
      sum = (sum & 0xffff) + (sum >> 16);
      sum &= 0xffff;
      sum += ((SshUInt32)new_value << 8);
    }

  /*  Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}

/* Update the complement of IP checksum by having a short (16-bit
   value) change at a specified offset.  The input checksum and the
   returned checksum are in host byte order. */

SshUInt16 ssh_ip_cksum_update_short(SshUInt16 cks, size_t ofs,
                                    SshUInt16 old_value, SshUInt16 new_value)
{
  SshUInt32 sum;

  /* Byte-swap values if odd offset. */
  if (ofs & 0x01)
    {
      old_value = (((old_value & 0xff) << 8) | (old_value >> 8));
      new_value = (((new_value & 0xff) << 8) | (new_value >> 8));
    }

  /* Update the sum. */
  sum = (~cks) & 0xffff;
  sum -= old_value;
  sum = (sum & 0xffff) + (sum >> 16);
  sum &= 0xffff;
  sum += new_value;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}

/* Update the complement of IP checksum by having a long (32-bit
   value) change at a specified offset.  The input checksum and the
   returned checksum are in host byte order. */

SshUInt16 ssh_ip_cksum_update_long(SshUInt16 cks, size_t ofs,
                                   SshUInt32 old_value, SshUInt32 new_value)
{
  SshUInt32 sum;
  SshUInt16 old1, old2, new1, new2;

  /* Split the old and new values into 16 bit quantities. */
  old1 = old_value & 0xffff;
  old2 = old_value >> 16;
  new1 = new_value & 0xffff;
  new2 = new_value >> 16;

  /* Byte-swap the values if odd offset. */
  if (ofs & 0x01)
    {
      old1 = (((old1 & 0xff) << 8) | (old1 >> 8));
      old2 = (((old2 & 0xff) << 8) | (old2 >> 8));
      new1 = (((new1 & 0xff) << 8) | (new1 >> 8));
      new2 = (((new2 & 0xff) << 8) | (new2 >> 8));
    }

  cks = ~cks;
  old1 = ~old1;
  sum = cks + old1 + new1;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  old2 = ~old2;
  sum = sum + old2 + new2;
  sum = (sum >> 16) + (sum & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  return (~sum) & 0xFFFF;
}
