/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Protocol debugging utilities.
*/

#ifndef SSH_PDBG_H
#define SSH_PDBG_H

#include "sshincludes.h"
#include "sshinet.h"

/*
 * Macros.
 */

/** Maximum number of debug configuration entries. This number should
    be kept small to avoid potentially large number of address matches
    at a debug point. */
#define SSH_PDBG_DEBUG_CONFIG_ENTRIES 4

/** Size of a buffer used for formatting `small' amounts of text (at
    most one long line), in bytes. */
#define SSH_PDBG_BUFFER_SIZE 1024

/*
 * Types.
 */

/** Debug configuration entry. */
typedef struct SshPdbgConfigEntryRec {

  /** Address prefix for matching the local IP address. An undefined
      address matches any IPv4/IPv6 address. */
  SshIpAddrStruct local;

  /** Address prefix for matching the remote IP address. An undefined
      address matches any IPv4/IPv6 address. */
  SshIpAddrStruct remote;

  /** Debug level. Zero marks an unused entry. A nonzero level x
      enables output of debug messages at levels less than or equal to x. */
  SshUInt32 level;
} SshPdbgConfigEntryStruct, *SshPdbgConfigEntry;

typedef const struct SshPdbgConfigEntryRec
SshPdbgConstConfigEntryStruct, *SshPdbgConstConfigEntry;

/** Debug configuration. */
typedef struct SshPdbgConfigRec {

  /** Debug configuration entries. */
  SshPdbgConfigEntryStruct entries[SSH_PDBG_DEBUG_CONFIG_ENTRIES];

  /** Debug configuration generation number. */
  SshUInt32 generation;

  /** Identity to increment and give to each new object. */
  SshUInt32 ident;

} SshPdbgConfigStruct, *SshPdbgConfig;

/** Debuggable object. */
typedef struct SshPdbgObjectRec {

  /** Debug identity, e.g. an increasing number given to each
      new object. */
  SshUInt32 ident;

  /** Debug level. Zero means debug is disabled for this object. A
      nonzero level x enables output of debug messages at levels less
      than or equal to x. */
  SshUInt32 level;

  /** Debug configuration generation when this object was last matched
      against debug configuration. */
  SshUInt32 generation;

  /** Flags for application use. */
  SshUInt32 flags;

} SshPdbgObjectStruct, *SshPdbgObject;

/** Buffer type for formatting small amounts of text. */
typedef struct SshPdbgBufferRec {

  /** Buffer containing a null-terminated string. */
  char buf[SSH_PDBG_BUFFER_SIZE];

  /** Length of string excluding null. */
  int pos;

} SshPdbgBufferStruct, *SshPdbgBuffer;

/*
 * Debug configuration management.
 */

/** Add a new debug configuration entry to the debug configuration
    `config'. The addresses and level are copied from the object
    pointed to by `entry'. Return TRUE on success, FALSE if no more
    entries are allowed. Entries with duplicate or overlapping
    adresses are allowed. */
Boolean
ssh_pdbg_config_insert(SshPdbgConfig config, SshPdbgConstConfigEntry entry);

/** Remove a debug configuration entry from the debug configuration
    `config'. The addresses and level must exactly match those in the
    object pointed to by `entry'. Return TRUE if a matching entry was
    removed, FALSE if there was no matching entry. If more than one
    entry matches only one is removed. */
Boolean
ssh_pdbg_config_remove(SshPdbgConfig config, SshPdbgConstConfigEntry entry);

/** Get one debug configuration entry in the debug configuration
    `config'. If the `previous' parameter is a null pointer the
    function returns a pointer to one of the entries. The returned
    pointer directly points to data in the configuration and should be
    used for reading only. Also, the returned pointer should be used
    as the `previous' parameter in the next call to the function in
    order to retrieve the next entry. If there are no entries left
    then a null pointer is returned. The order in which entries are
    returned is unspecified. Using a pointer returned by this function
    as an argument to ssh_pdbg_config_insert() or
    ssh_pdgb_config_remove() is discouraged. */
SshPdbgConstConfigEntry
ssh_pdbg_config_get(SshPdbgConfig config, SshPdbgConstConfigEntry previous);

/*
 * Debuggable object management.
 */

/** Update the debuggable object `object' based on the debug
    configuration `config' if their configuration generation numbers
    differ. Updating involves address matching using `local' and
    `remote' after which the debug level, debug identity and
    configuration generation number of the `object' are updated. */
void
ssh_pdbg_object_update(
  SshPdbgConfig config, SshPdbgObject object,
  SshIpAddr local, SshIpAddr remote);

/*
 * Message output.
 */

/** Output a timestamp and an identifier consisting of the string
    `type', a dash and the identifier number of debuggable object
    `object' in hex, followed by a message formatted according to the
    printf-style format string `fmt' and variable arguments. */
void
ssh_pdbg_output_event(
  const char *type, SshPdbgObject object, const char *fmt, ...);

/** Output indented lines containing the `connection' parameters
    associated with the last event that was output using
    ssh_pdbg_output_event(), i.e. local and remote endpoints. */
void
ssh_pdbg_output_connection(
  SshIpAddr local_addr, SshUInt16 local_port,
  SshIpAddr remote_addr, SshUInt16 remote_port);

/** Output an indented line containing additional attributes
    associated with the last event that was output using
    ssh_pdbg_output_event(), formatted according to the printf-style
    format string `fmt' and variable arguments. */
void
ssh_pdbg_output_information(const char *fmt, ...);

/** Output an indented line containing additional attributes
    associated with the last event that was output using
    ssh_pdbg_output_event(), formatted according to the printf-style
    format string `fmt' and variable argument list `ap'. */
void
ssh_pdbg_output_vinformation(const char *fmt, va_list ap);

/*
 * Formatted printing into fixed-size buffer.
 */

/** Initialize buffer `b' to contain an empty null-terminated
    string. */
void
ssh_pdbg_bclear(SshPdbgBuffer b);

/** Format the variable arguments according to the printf-style format
    string `fmt', append the result to buffer and
    null-terminate. Truncate if there is insufficient space. */
void
ssh_pdbg_bprintf(SshPdbgBuffer b, const char *fmt, ...);

/** Format the arguments in `ap' according to the printf-style format
    string `fmt', append the result to buffer and
    null-terminate. Truncate if there is insufficient space. */
void
ssh_pdbg_vbprintf(SshPdbgBuffer b, const char *fmt, va_list ap);

/** Append a character to buffer `b' and null-terminate unless there
    is insufficient space. */
void
ssh_pdbg_bputc(int c, SshPdbgBuffer b);

/** Return pointer to the null-terminated string in buffer `b'. */
const char *
ssh_pdbg_bstring(SshPdbgBuffer b);

#endif /* SSH_PDBG_H */
