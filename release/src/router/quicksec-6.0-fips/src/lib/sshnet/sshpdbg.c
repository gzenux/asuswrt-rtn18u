/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Protocol debugging utilities.
*/

#include "sshpdbg.h"

/*
 * Types.
 */

/* IPv6 address `part', i.e. zero or more 16-bit pieces as an integer
   array. */
typedef struct SshPdbgV6PartRec {
  unsigned int *tab;
  int num;
} SshPdbgV6PartStruct, *SshPdbgV6Part;

/*
 * Prototypes.
 */

/** Print a string representation of the IPv4/IPv6 address `a'. An
    IPv6 address is surrounded by square brackets. */
static void
pdbg_bprint_addr(SshPdbgBuffer b, SshIpAddr a);

/*
 * Public functions.
 */

Boolean
ssh_pdbg_config_insert(SshPdbgConfig config, SshPdbgConstConfigEntry entry)
{
  SshPdbgConfigEntry e;
  int i, n = sizeof config->entries / sizeof config->entries[0];

  /* Find an unused entry, i.e. one with level 0. */
  for (i = 0; i < n; i++)
    {
      e = &config->entries[i];
      if (e->level == 0)
        break;
    }
  if (i >= n)
    return FALSE;

  /* Copy parameters. */
  memcpy(e, entry, sizeof *e);

  /* Mark debug configuration changed. */
  config->generation++;

  return TRUE;
}

Boolean
ssh_pdbg_config_remove(SshPdbgConfig config, SshPdbgConstConfigEntry entry)
{
  SshPdbgConfigEntry e;
  int i, n = sizeof config->entries / sizeof config->entries[0];

  /* Find a matching entry. */
  for (i = 0; i < n; i++)
    {
      e = &config->entries[i];

      if (e->level != entry->level)
        continue;

      /* No match unless both undefined or both defined and prefix
         bits equal. */
      if (!(!SSH_IP_DEFINED(&e->local) &&
            !SSH_IP_DEFINED(&entry->local)) &&
          !(SSH_IP_DEFINED(&e->local) &&
            SSH_IP_DEFINED(&entry->local) &&
            e->local.mask_len == entry->local.mask_len &&
            ssh_ipaddr_mask_equal(&e->local, (SshIpAddr)&entry->local)))
        continue;

      /* No match unless both undefined or both defined and prefix
         bits equal. */
      if (!(!SSH_IP_DEFINED(&e->remote) &&
            !SSH_IP_DEFINED(&entry->remote)) &&
          !(SSH_IP_DEFINED(&e->remote) &&
            SSH_IP_DEFINED(&entry->remote) &&
            e->remote.mask_len == entry->remote.mask_len &&
            ssh_ipaddr_mask_equal(&e->remote, (SshIpAddr)&entry->remote)))
        continue;

        break;
    }
  if (i >= n)
    return FALSE;

  /* Mark entry unused. */
  e->level = 0;

  /* Mark debug configuration changed. */
  config->generation++;

  return TRUE;
}

SshPdbgConstConfigEntry
ssh_pdbg_config_get(SshPdbgConfig config, SshPdbgConstConfigEntry previous)
{
  SshPdbgConstConfigEntry e;
  int n = sizeof config->entries / sizeof config->entries[0];

  /* If previous is NULL start with the first entry. If previous is
     too small return NULL. Otherwise start with the next entry (and
     cover previous-too-large case later). */
  if (previous == NULL)
    e = &config->entries[0];
  else if (previous < &config->entries[0])
    return NULL;
  else
    e = previous + 1;

  /* Scan entries while within the array and return the first one with
     non-zero levels. */
  while (e < &config->entries[n])
    {
      if (e->level > 0)
        return e;
      e++;
    }

  /* No entry found. */
  return NULL;
}

void
ssh_pdbg_object_update(
  SshPdbgConfig config, SshPdbgObject object,
  SshIpAddr local, SshIpAddr remote)
{
  SshPdbgConfigEntry e;
  SshUInt32 level;
  int i, n = sizeof config->entries / sizeof config->entries[0];

  /* Do nothing if object generation matches config generation. */
  if (object->generation == config->generation)
    return;

  /* Find a matching configuration entry with the highest debug
     level. Use level 0 if no entry found. */
  level = 0;
  for (i = 0; i < n; i++)
    {
      e = &config->entries[i];

      if (e->level <= level)
        continue;

      if (SSH_IP_DEFINED(&e->local) &&
          !ssh_ipaddr_mask_equal(local, &e->local))
        continue;

      if (SSH_IP_DEFINED(&e->remote) &&
          !ssh_ipaddr_mask_equal(remote, &e->remote))
        continue;

        level = e->level;
    }

  /* Update debug level and configuration generation. */
  object->level = level;
  object->generation = config->generation;

  /* Give a debug identifier if not already done. */
  if (object->ident == 0)
    object->ident = ++config->ident;
}

void
ssh_pdbg_output_event(
  const char *type, SshPdbgObject object, const char *fmt, ...)
{
  va_list ap;
  SshPdbgBufferStruct b;
  SshCalendarTimeStruct cal;

  ssh_pdbg_bclear(&b);

  ssh_calendar_time(ssh_time(), &cal, TRUE);

  ssh_pdbg_bprintf(
    &b, "%02u:%02u:%02u %s-%08x ",
    cal.hour, cal.minute, cal.second, type, (unsigned)object->ident);

  va_start(ap, fmt);
  ssh_pdbg_vbprintf(&b, fmt, ap);
  va_end(ap);

  ssh_debug("%s", ssh_pdbg_bstring(&b));
}

void
ssh_pdbg_output_connection(
  SshIpAddr local_addr, SshUInt16 local_port,
  SshIpAddr remote_addr, SshUInt16 remote_port)
{
  SshPdbgBufferStruct b;

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "Local-Endpoint:");
  pdbg_bprint_addr(&b, local_addr);
  ssh_pdbg_bprintf(&b, ":%u", local_port);

  ssh_debug("  %s", ssh_pdbg_bstring(&b));

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "Remote-Endpoint:");
  pdbg_bprint_addr(&b, remote_addr);
  ssh_pdbg_bprintf(&b, ":%u", remote_port);

  ssh_debug("  %s", ssh_pdbg_bstring(&b));
}

void
ssh_pdbg_output_information(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  ssh_pdbg_output_vinformation(fmt, ap);
  va_end(ap);
}

void
ssh_pdbg_output_vinformation(const char *fmt, va_list ap)
{
  SshPdbgBufferStruct b;

  ssh_pdbg_bclear(&b);
  ssh_pdbg_vbprintf(&b, fmt, ap);

  ssh_debug("  %s", ssh_pdbg_bstring(&b));
}

void
ssh_pdbg_bclear(SshPdbgBuffer b)
{
  b->pos = 0;
  b->buf[0] = '\0';
}

void
ssh_pdbg_bprintf(SshPdbgBuffer b, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  ssh_pdbg_vbprintf(b, fmt, ap);
  va_end(ap);
}

void
ssh_pdbg_vbprintf(SshPdbgBuffer b, const char *fmt, va_list ap)
{
  int n;

  if (b->pos >= sizeof b->buf - 1)
    return;

  n = ssh_vsnprintf(
    ssh_ustr(b->buf + b->pos), sizeof b->buf - b->pos, fmt, ap);

  if (n >= 0 && b->pos + n < sizeof b->buf)
    b->pos += n;
  else
    b->pos = sizeof b->buf - 1;

  b->buf[b->pos] = '\0';
}

void
ssh_pdbg_bputc(int c, SshPdbgBuffer b)
{
  if (b->pos >= sizeof b->buf - 1)
    return;

  b->buf[b->pos] = (char)c;

  b->pos++;
  b->buf[b->pos] = '\0';
}

const char *
ssh_pdbg_bstring(SshPdbgBuffer b)
{
  return b->buf;
}

/*
 * Static functions.
 */

static void
pdbg_bprint_addr(SshPdbgBuffer b, SshIpAddr a)
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
