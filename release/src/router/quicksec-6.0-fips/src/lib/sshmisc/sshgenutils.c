/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General small utilities which are yet too long to be written again every
   time.
*/

#include "sshincludes.h"
#include "sshgenutils.h"
#include "sshtimemeasure.h"
#include "sshcrc32.h"


char *ssh_str_extract(const char *source,
                      char **target,
                      char delimiter, int occurence)
{
  int c, len, i = 0;

  if (!source) return NULL;
  if (!target) return NULL;

  while (occurence > 0 && source[i] != '\0')
    if (source[i++] == delimiter) occurence--;

  /* Did we find a substring. If not return an empty string*/
  if (occurence != 0)
    {
      *target = ssh_xmalloc(1);
      (*target)[0] = '\0';
      return *target;
    }

  /* preserve our location in string */
  c = i;

  /* Count the length of asked substring */
  while (source[i] != delimiter && source[i++] != '\0');
  len = i-c+1;

  *target = ssh_xmalloc(len);

  memcpy(*target, &source[c], len-1);
  (*target)[len-1] = '\0';

  return *target;
}


void ssh_busy_wait_usec(const SshUInt64 time_us)
{
  SshTimeMeasure timer;

  timer = ssh_time_measure_allocate();
  ssh_time_measure_start(timer);
  while (ssh_time_measure_stamp(timer,
                                SSH_TIME_GRANULARITY_MICROSECOND) <
         time_us)
    /*NOTHING*/;
  ssh_time_measure_stop(timer);
  ssh_time_measure_free(timer);
}

char *ssh_generate_name_from_buffer(const char *name,
                                    const unsigned char *blob,
                                    size_t bloblen)
{
  unsigned char *ret;
  size_t namelen;
  SshUInt32 crc;

  if (!name)
    name = "???";
  namelen = strlen(name);
  crc = crc32_buffer(blob, bloblen);
  ret = ssh_xmalloc(namelen + 10);
  ssh_ustrncpy(ret, ssh_custr(name), namelen);
  ret[namelen] = ' ';
  ssh_snprintf(ret + namelen + 1, 9, "%08lx", (unsigned long)crc);
  return (char *) ret;
}
