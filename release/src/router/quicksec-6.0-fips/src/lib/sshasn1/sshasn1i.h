/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for the ASN.1 parser.
*/

#ifndef SSHASN1I_H
#define SSHASN1I_H

#include "sshfastalloc.h"

typedef enum
{
  SSH_ASN1_DEFEXT_NONE,
  SSH_ASN1_DEFEXT_NODE,
  SSH_ASN1_DEFEXT_CHOICE,
  SSH_ASN1_DEFEXT_OPTIONAL
} SshAsn1DefExt;

/* Format of Asn.1 tree node. Notice that we have currently restricted
   ourselves to small tag numbers. There does not seem to be any
   reason to use larger than 32-bit tags. */
struct SshAsn1NodeRec
{
  /* Class and tag number within the class specify the tag node. */
  SshAsn1Class classp;
  SshAsn1Tag tag_number;

  /* The encoding rules to use. */
  SshAsn1Encoding encoding;

  /* BER/DER encoded tag (according to class, tag_number and encoding) */
  size_t tag_length;
  unsigned char *tag;

  /* BER/DER encoded data and the data length in bytes. The length
     encoding specifies if the length is definitive or not. */
  SshAsn1LengthEncoding length_encoding;
  size_t length;
  unsigned char *data;

  /* The tree is represented as a doubly-linked list of nodes that
     might have children which could also have doubly-linked list of
     nodes and children and so forth... */
  struct SshAsn1NodeRec *next, *prev, *child, *parent;
};

struct SshAsn1ContextRec
{
  /* To free everything allocated */
  SshObStackContext obstack;
  /* For the parser parser */
#define ASN1_MAX_TOKEN_LEN 128
  SshFastMemoryAllocator valuebag;
  SshFastMemoryAllocator cellbag;

  size_t max_input_nesting;
  size_t max_input_length;
};

/* Asn.1 moving context. */
struct SshAsn1TreeRec
{
  SshAsn1Node root;
  SshAsn1Node current;
  unsigned char *data;
  size_t length;
};

typedef enum {
  SSH_ASN1_DEF_NONE,
  SSH_ASN1_DEF_BOOLEAN,
  SSH_ASN1_DEF_SHORT,
  SSH_ASN1_DEF_INT,
  SSH_ASN1_DEF_STRING,
  SSH_ASN1_DEF_BIT_STRING,
  SSH_ASN1_DEF_OID,
  SSH_ASN1_DEF_TIME,
  SSH_ASN1_DEF_NULL
} SshAsn1DefType;

typedef struct
{
  /* Name of the ASN.1 function. */
  char *name;

  /* Type of the name, used for optimizations. */
  SshAsn1DefType type;

  /* Tag number if any. */
  SshUInt32 tag_number;
  /* Extended type. */
  SshAsn1DefExt extended;

  /* BER (or any other) encoding function. */
  SshBerStatus (*encode)(SshObStackContext context,
                         SshAsn1Class a_class,
                         SshAsn1Encoding encoding,
                         SshAsn1Tag tag_number,
                         SshAsn1LengthEncoding length_encoding,
                         unsigned char **data,
                         size_t *length,
                         unsigned char **tag,
                         size_t *tag_length,
                         void *value,
                         void *len);
  /* BER (or any other) decoding function. */
  SshBerStatus (*decode)(unsigned char *data, size_t length,
                         SshBerFreeList list,
                         void *value, void *len);
} SshAsn1Defs;


/* Token types. */
typedef enum
{
  tSYMBOL = 5, tINTEGER, tLPAREN, tRPAREN, tEOF, tPAIR
} SshAsn1FormatTokenType;

/* SshAsn1FormatToken structure.*/
typedef struct SshAsn1FormatTokenRec
{
  SshAsn1FormatTokenType type;
  unsigned char *data;
  int intval;
} *SshAsn1FormatToken;

typedef struct SshAsn1FormatRec
{
  size_t offset;
  const char *data;
  SshFastMemoryAllocator valuebag;
  SshFastMemoryAllocator cellbag;
} *SshAsn1Format;

typedef struct SshAsn1FormatNodeRec
{
  SshAsn1FormatTokenType type;
  struct SshAsn1FormatNodeRec *next_sibling;
  struct SshAsn1FormatNodeRec *next_child;
  struct SshAsn1FormatNodeRec *parent;

  /* These are used for cell value and name */
  union {
    char *strval;
    int intval;
  } u;

  SshUInt32 flags;
  SshUInt32 tagnum;
  const SshAsn1Defs *def;
  SshAsn1Node node;

  /* These are used to store destination pointers when reading. See
     asn1read for details. */
  union
  {
    SshInt32 *chosen;
    SshAsn1Node *any;
    SshBerTime timeval;
    SshWord *shortval;
    SshMPInteger  intval;
    Boolean *boolval;
    char **strval;
    struct
    {
      unsigned char **strval;
      size_t *lenval;
    } s;
  } r;

#define plenval   r.s.lenval
#define pstrval   r.s.strval
#define poidval   r.strval
#define ptimeval  r.timeval
#define pshortval r.shortval
#define pintval   r.intval
#define pboolval  r.boolval
#define pchosen   r.chosen
#define panyval   r.any

} *SshAsn1FormatNode;




#define ENCODEARGS(ctx, node) \
  (ctx)->obstack, \
  (node)->classp, (node)->encoding, (node)->tag_number, \
  (node)->length_encoding, \
 &(node)->data, &(node)->length, &(node)->tag, &(node)->tag_length

#define ssh_asn1_encode_ber(ctx, defs, node, ap, status)                \
  do {                                                                  \
    switch ((defs)->type)                                               \
      {                                                                 \
      case SSH_ASN1_DEF_BOOLEAN: {                                      \
        Boolean _bool; _bool = va_arg((ap), Boolean);                   \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       &_bool, NULL);                   \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_SHORT: {                                        \
        SshWord _word; _word = va_arg((ap), SshWord);                   \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       &_word, NULL);                   \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_INT: {                                          \
        SshMPInteger _int; _int = va_arg((ap), SshMPInteger);           \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       &_int, NULL);                    \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_OID: {                                          \
        char *_oid; _oid = va_arg((ap), char *);                        \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       &_oid, NULL);                    \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_TIME: {                                         \
        SshBerTime _time; _time = va_arg((ap), SshBerTime );            \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       &_time, NULL);                   \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_BIT_STRING:                                     \
      case SSH_ASN1_DEF_STRING: {                                       \
        unsigned char *_str;                                            \
        size_t _len;                                                    \
        _str = va_arg((ap), unsigned char *);                           \
        _len = va_arg((ap), size_t);                                    \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       &_str, &_len);                   \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_NULL: {                                         \
        if ((defs)->encode == NULL_FNPTR)                               \
          (status) = SSH_ASN1_STATUS_ERROR;                             \
        else                                                            \
          (status) = (*(defs)->encode)(ENCODEARGS((ctx), (node)),       \
                                       NULL, NULL);                     \
      }                                                                 \
        break;                                                          \
      case SSH_ASN1_DEF_NONE: (status) = SSH_ASN1_STATUS_OK; break;     \
      }                                                                 \
  } while (0)


#define GETCH(port)          (port)->data[port->offset++,((port)->offset-1)]
#define UNGETCH(format, ch)  ((void)(port)->offset--)

#define READ_ERROR 0
#define READ_OK    1
#define READ_EOF   2

#define WHITESPACE(ch) ((ch) == ' ' || (ch) == '\n' || (ch) == '\t')
#define DELIMITER(ch) (WHITESPACE(ch) || (ch) == '(' || (ch) == ')')

#define LETTER(ch) \
  (('a' <= (ch) && (ch) <= 'z') || ('A' <= (ch) && (ch) <= 'Z'))
#define DIGIT(ch) ('0' <= (ch) && (ch) <= '9')
#define SPECIAL(ch) (((ch) == '-') || ((ch) == '+') || ((ch) == '*'))
#define INITIAL(ch) (LETTER(ch) || SPECIAL(ch))
#define SUBSEQUENT(ch) (INITIAL(ch) || DIGIT(ch) || SPECIAL(ch))


/* These macros are used for traversing the tree without recursion.
   They are supposed to appear in the following construction:

     SshAsn1FormatNode cell = rootnode, prevcell;
     int level = 0;

     while (1) {
       while (1) {
         ... code to manipulate current cell.
         FOLLOW_CHILD(cell, prevcell, level);
       }
       BACKUP(cell, prevcell, level);
     }
   traversed:
     ... code to do exit routines.

   The calls modify integer variable level to keep track of depth
   of traversal from rootnode (which depth is the initial value
   of level).

   Do not alter the cell next_child or next_sibling (right and left
   pointers) on the code that accesses the cell.

   Because of travelsal mechanism this can not be conveniently used to
   free the tree. */

/* This macro follows the next_child tree until there is no next
   child, in which case it breaks out from the surrounding loop. */

#define FOLLOW_CHILD(cell, prev, level)         \
  if (TRUE)                                     \
    {                                           \
      if ((cell)->next_child)                   \
        {                                       \
          (cell)->flags |= SSH_ASN1_FOLLOW_SIBLING;     \
          (prev) = (cell);                      \
          (cell) = (cell)->next_child;          \
          (cell)->parent = (prev);              \
          (level)++;                            \
        }                                       \
      else                                      \
        {                                       \
          break;                                \
        }                                       \
    }                                           \
  else {}

/* This macro goes up from current node. Should be called after
   FOLLOW_CHILD has breaked out from the loop it is in. We expect the
   function to define label `traversed'. This jumps to that label when
   whole tree has been traversed. */

#define BACKUP(cell, prev, level)               \
  if (TRUE)                                     \
    {                                           \
      while (1)                                 \
        {                                       \
          if ((prev) == NULL)                   \
            {                                   \
              goto traversed;                   \
            }                                   \
          (level)--;                            \
          if ((prev)->flags & SSH_ASN1_FOLLOW_SIBLING)          \
            {                                                   \
              (prev)->flags &= (~SSH_ASN1_FOLLOW_SIBLING);      \
              if ((prev)->next_sibling)         \
                {                               \
                  (cell) = (prev)->next_sibling;\
                  break;                        \
                }                               \
              else                              \
                {                               \
                  (cell) = (cell)->parent;      \
                  (prev) = (cell)->parent;      \
                }                               \
            }                                   \
          else                                  \
            {                                   \
              (cell) = (cell)->parent;          \
              (prev) = (cell)->parent;          \
            }                                   \
        }                                       \
     }                                          \
  else {}



/* This macro definition adds newnode to ASN.1 hierarchy at level
   level when the previous level was plevel. In this context the level
   means the depth of the tree from the root. */

#define ADDNODE(parent, prevnode, newnode, level, plevel) \
 do {                                                   \
   if ((level) > (plevel))                              \
     {                                                  \
       (prevnode) = (newnode);                          \
       if ((parent))                                    \
         (parent)->child = (newnode);                   \
     }                                                  \
   else if ((level) == (plevel))                        \
     {                                                  \
       SSH_ASSERT((prevnode) != NULL);                  \
       (prevnode)->next = (newnode);                    \
       (newnode)->prev = (prevnode);                    \
       (prevnode) = (newnode);                          \
     }                                                  \
   else                                                 \
     {                                                  \
       SshAsn1Node p;                                   \
       SSH_ASSERT((parent) != NULL);                    \
       p = (parent)->child;                             \
       while (p)                                        \
         {                                              \
           (prevnode) = p;                              \
           p = p->next;                                 \
         }                                              \
       SSH_ASSERT((prevnode) != NULL);                  \
       (prevnode)->next = (newnode);                    \
       (newnode)->prev = (prevnode);                    \
       (prevnode) = (newnode);                          \
     }                                                  \
 } while (0)


#define SSH_ASN1_OPTIONAL        (1 << 0)
#define SSH_ASN1_OPTIONAL_FAILED (1 << 1)

typedef enum
{
  SSH_ASN1_RULE_SCAN_ALL = 1, /* Search tagged throughout. */
  SSH_ASN1_RULE_NO_SCAN  = 2, /* Don't scan just match */
  SSH_ASN1_RULE_SCAN_FWD = 3, /* Scan only forwards (from the current). */
  SSH_ASN1_RULE_NO_MATCH = 4 /* No scan and no match. */
} SshAsn1Rule;



#define SSH_ASN1_MATCH_DEFS     (1 << 15)
#define SSH_ASN1_FOLLOW_SIBLING (1 << 30) /* special for traversing */

#define SSH_ASN1_LENGTH_ENCODING (SSH_ASN1_LENGTH_DEFINITE|\
                                  SSH_ASN1_LENGTH_INDEFINITE|\
                                  SSH_ASN1_LENGTH_STAR)
#define SSH_ASN1_TAGGING_MODE \
  (SSH_ASN1_TAGGING_IMPLICIT|SSH_ASN1_TAGGING_EXPLICIT)


extern SshAsn1Node
ssh_asn1_search_node(SshAsn1Node first, SshAsn1Node *current,
                     SshAsn1Rule rule_tagged,
                     SshAsn1Rule rule_untagged,
                     const SshAsn1Defs *defs,
                     Boolean is_tagged,
                     SshAsn1Class tag_class,
                     SshAsn1LengthEncoding length_encoding,
                     SshAsn1Tag tag_number,
                     SshAsn1TaggingMode tagging_mode);

#endif /* SSHASN1I_H */
