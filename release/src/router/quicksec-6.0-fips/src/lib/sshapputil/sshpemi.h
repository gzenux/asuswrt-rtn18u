/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHPEMI_H
#define SSHPEMI_H

#include "sshadt.h"
#include "sshbuffer.h"

/* Following types are currently available for the viewer of the
   PEM blobs.

   Remark. This interface will change.
   */

typedef struct SshPemKeywordRec SshPemKeyword;
typedef struct SshPemBlobRec    SshPemBlob;
typedef struct SshPemParserRec  SshPemParser;
typedef struct SshPemWriterRec  SshPemWriter;
typedef struct SshPemBinDataRec SshPemBinData;
typedef struct SshPemArgRec     SshPemArg;

struct SshPemBinDataRec
{
  unsigned char *data;
  size_t         data_len;
};

typedef enum
{
  SSH_PEM_ARG_END,
  SSH_PEM_ARG_IASTRING, /* An IA string */
  SSH_PEM_ARG_BINARY,
  SSH_PEM_ARG_NUMBER,
  SSH_PEM_ARG_KEYWORD,
  SSH_PEM_ARG_SSH2STRING /* A string as in ssh2 key comment. */
} SshPemArgType;

#define SSH_PEM_MAXNUMBER 0xffffffff

struct SshPemArgRec
{
  SshPemArgType type;

  /* Following objects are available. */
  union {
    char         *str;
    SshPemBinData    bin;
    unsigned int  num;
    const SshPemKeyword   *keyword;
  } ob;
};

/* Definitions of all keywords. */
struct SshPemKeywordRec
{
  /* The name token. */
  char *name;
  /* Number of arguments. */
  int   min_num_args, max_num_args;
#define SSH_PEM_MAX_ARGS 10
  SshPemArgType arg_types[SSH_PEM_MAX_ARGS];
  int (*parser)(SshPemParser *p,
                SshPemArg    *args,
                unsigned int  num_args);
  int (*handler)(SshPemBlob  *blob,
                 SshPemArg   *args,
                 unsigned int num_args);
};

struct SshPemBlobRec
{
  /* Header information, this is not rigorously checked by the
     library. */
  char *begin_header, *end_header;
  size_t begin_num_lines;

  /* The list of read arguments. */
  SshADTContainer args;

  /* The actual text contents. */
  unsigned char *text;
  size_t         text_len;

  /* The block position in the data. This information is used
     only during parsing. */
  const unsigned char *block;
  size_t         block_len;
};

/* The parser context.

   The parser is a simple linear one-pass parser.
 */
struct SshPemParserRec
{
  /* The input data, length and current position. */
  const unsigned char *data;
  size_t         data_len, data_pos;
  size_t         data_num_lines;

  /* The read PEM blobs are stored here. The last is the one that
     we are currently building. */
  SshADTContainer list;

  /* All the generated messages. */
  SshADTContainer msg;
};

/* The writer context. */
struct SshPemWriterRec
{
  /* The output buffer. */
  SshBufferStruct output;

  /* TODO */
};

typedef enum
{
  SSH_PEM_OK,

  /* Warnings. */

  SSH_PEM_WARNING_LINE_FEED,

  /* Errors. */
  SSH_PEM_ERROR_MISSING_ARGUMENT,
  SSH_PEM_ERROR_UNKNOWN_ALGORITHM,

  /* Dummy enum stopper. */
  SSH_PEM_ERROR
} SshPemMsgId;

SshPemParser *ssh_pem_parser_alloc(const unsigned char *data, size_t data_len);

void ssh_pem_parser_free(SshPemParser *p);


#endif /* SSHPEMI_H */
