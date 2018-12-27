/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements the interface for matching regular expressions
   in sshregex.h.

   The matching algorithm is worst-case linear in both the length of
   regular expression and the length of matched text, i.e.

     O(|e| |t|)

   if `e' is the regex and `t' is the text.

   The O(|t|) factor is there always.  The factor O(|e|) is typically
   much smaller.

   Alert: this file is very badly documented.  Do not modify the
   algorithms unless you know what you are doing.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshregex.h"
#include "sshdlex.h"
#include "sshfastalloc.h"

#undef SSH_REX_DEBUG

#define SSH_REX_MAX_REPEATS 1000 /* The syntactically imposed max values in
                                    {n, m}. */

#define SSH_DEBUG_MODULE "SshRegex"

typedef enum {
  SSH_REX_BEGINNING             = 0,
  SSH_REX_END                   = 1,
  SSH_REX_LITERAL               = 2,
  SSH_REX_ANY                   = 3,
  SSH_REX_CHAR_SET              = 4,
  SSH_REX_START_SUBEXPR         = 5,
  SSH_REX_END_SUBEXPR           = 6,
  SSH_REX_ACCEPT                = 7,
  SSH_REX_DISJUNCT              = 8,
  SSH_REX_LOOKAHEAD             = 9,
  SSH_REX_LOOKBACK              = 10,

  /* These are used in the intermediary constructions. */
  SSH_REX_CONCATENATION,
  SSH_REX_PLUS,
  SSH_REX_STAR,
  SSH_REX_OPTIONAL,
  SSH_REX_RANGE,
  SSH_REX_LAZY_PLUS,
  SSH_REX_LAZY_STAR,
  SSH_REX_LAZY_OPTIONAL,
  SSH_REX_LAZY_RANGE,
  SSH_REX_SUBEXPR,
  SSH_REX_ANON_SUBEXPR,
  SSH_REX_FORWARD,
  SSH_REX_START_ANON_SUBEXPR,
  SSH_REX_END_ANON_SUBEXPR,
  SSH_REX_SUB_NFA
} SshRexMatchType;

/* Matcher proc flag definitions. */
#define SSH_REX_ACCEPT_PREFIX           0x0001

/* Flag definitions. */

/* This flag is used only when dumping NFAs to stderr, which is not
   normally done. */
#define SSH_REX_DUMPED                  0x0001

/* Used to denote those nodes that have been already examined during
   the removal of forwarding nodes. */
#define SSH_REX_STREAMLINED             0x0002

/* This flag is set for those states that can be part of accepting
   sequences even if there are no more characters available in the
   string to match against, i.e. if we are at the end.  Never set for
   consuming nodes. */
#define SSH_REX_CAN_BE_LAST             0x0008

/* Set for those nodes during compilation that really are not anchored
   due to ^. */
#define SSH_REX_NOT_ANCHORED            0x0010


/* Subexpressions are denoted by integers. */
typedef int SshRexSubexpr;

/***************************************************************** Syntaxes. */

typedef enum {
  SSH_REX_P_START_SUBEXPR,      /* Start numbered subexpression */
  SSH_REX_P_END_SUBEXPR,        /* End numbered subexpression */
  SSH_REX_P_START_ANON_SUBEXPR, /* Start anonymous subexpression */
  SSH_REX_P_END_ANON_SUBEXPR,   /* End anonymous subexpression */
  SSH_REX_P_STAR,               /* Kleene star */
  SSH_REX_P_STAR_LAZY,          /* Lazy version */
  SSH_REX_P_PLUS,               /* Once, then kleene star */
  SSH_REX_P_PLUS_LAZY,          /* Lazy version */
  SSH_REX_P_OPTIONAL,           /* Optional subexpression */
  SSH_REX_P_OPTIONAL_LAZY,      /* Lazy version */
  SSH_REX_P_START_RANGE,        /* Start construction {n,m}. */
  SSH_REX_P_END_RANGE,          /* End construction {n,m}. */
  SSH_REX_P_START_END_RANGE,    /* Both start and end range construction. */
  SSH_REX_P_END_RANGE_LAZY,     /* Lazy version */
  SSH_REX_P_DISJUNCT,           /* Disjunction */
  SSH_REX_P_LITERAL,            /* Parse as literal */
  SSH_REX_P_ANY,                /* Any char */
  SSH_REX_P_BEGINNING,          /* Anchor at beginning */
  SSH_REX_P_END,                /* Anchor at end */
  SSH_REX_P_CHARSET_START,      /* Start charset */
  SSH_REX_P_CHARSET_END,        /* End charset */
  SSH_REX_P_CHARSET_COMPLEMENT_IF_FIRST, /* If first in charset spec,
                                            complement the charset */
  SSH_REX_P_CHARSET_RANGE,      /* Range character */
  SSH_REX_P_CHARSET_POSITIVE,   /* Positive range switch */
  SSH_REX_P_CHARSET_NEGATIVE,   /* Negative range switch */
  SSH_REX_P_ESCAPE,             /* Escape character */
  SSH_REX_P_NUMERIC_LITERAL,    /* Start numeric literal */
  SSH_REX_P_HEX_LITERAL,        /* Start hexdecimal literal */
  SSH_REX_P_LOOKAHEAD,          /* Look at the next character but
                                   do not consume. The continuing regex
                                   must yield a literal or a charset. */
  SSH_REX_P_LOOKBACK,           /* Look at the previous character but
                                   do not consume. The continuing regex
                                   must yield a literal or a charset. */
  SSH_REX_P_ANY_BUT_NEWLINE,    /* Any character except for newlines.
                                   Parses as a charset. */
  SSH_REX_P_ERROR,              /* Unacceptable character */

  /* Some typically escaped literals. */
  SSH_REX_P_LITERAL_TAB,
  SSH_REX_P_LITERAL_NEWLINE,
  SSH_REX_P_LITERAL_RETURN,
  SSH_REX_P_LITERAL_LINE_FEED,
  SSH_REX_P_LITERAL_ALARM,
  SSH_REX_P_LITERAL_ESCAPE,

  /* Some predefined charsets. */
  SSH_REX_P_PDC_WORD,
  SSH_REX_P_PDC_NWORD,
  SSH_REX_P_PDC_WHITESPACE,
  SSH_REX_P_PDC_NWHITESPACE,
  SSH_REX_P_PDC_DIGIT,
  SSH_REX_P_PDC_NDIGIT,
  SSH_REX_P_PDC_NOT_NEWLINE,

  /* Some precompiled NFA fragments. */
  SSH_REX_P_PCNFA_WORD_BOUNDARY,
  SSH_REX_P_PCNFA_NWORD_BOUNDARY,
  SSH_REX_P_PCNFA_WORD_START,
  SSH_REX_P_PCNFA_WORD_END,
  SSH_REX_P_PCNFA_LINE_START,
  SSH_REX_P_PCNFA_LINE_END,

  /* These are used in fileglobbing. */
  SSH_REX_P_PCNFA_ZSH_STAR,
  SSH_REX_P_PCNFA_ZSH_STAR_STAR,
  SSH_REX_P_PCNFA_ZSH_QUESTION_MARK,

  /* Full charset. Used only in token parsing, not an assignable
     syntax class. */
  SSH_REX_P_CHARSET,

  /* Range specification. */
  SSH_REX_P_RANGE,
  SSH_REX_P_RANGE_LAZY,

  /* A pre-existing NFA fragment. Used only in parsing. */
  SSH_REX_P_NFA,

  /* End of string. */
  SSH_REX_P_EOI
} SshRexParseEntity;

typedef struct {
  char *string;
  SshRexParseEntity entity;
} SshRexCompoundEntity;

#define SSH_REX_MAX_COMPOUND_ENTITIES 10

#define SSH_REX_PARSE_FLAG_POSIX_CHARSETS 1
#define SSH_REX_PARSE_FLAG_ALWAYS_ANCHOR  2

typedef struct {
  /* Mapping of characters when not inside charset or escaped. */
  SshRexParseEntity std_map[256];

  /* Mapping of characters after escape. */
  SshRexParseEntity escape_map[256];

  /* Mapping of characters inside charsets. */
  SshRexParseEntity charset_map[256];

  SshRexCompoundEntity compounds[SSH_REX_MAX_COMPOUND_ENTITIES];

  unsigned int flags;
} SshRexParseMap;

#include "sshregexsyn_ssh.c"
#include "sshregexsyn_egrep.c"
#include "sshregexsyn_zsh.c"

/*********************************************************** Character sets. */

#define SSH_REX_CHARSET_ARRAY_SIZE (256/(sizeof(SshUInt64) * 8))

#ifdef SSHUINT64_IS_64BITS
typedef SshUInt64 SshRexWord;
#define SSH_REX_CSET_SHIFT 6    /* Divide by 64 */
#define SSH_REX_CSET_MASK 63    /* Modulo 64 */
#define SSH_REX_WORD_BITS 64
#else
typedef SshUInt32 SshRexWord;
#define SSH_REX_CSET_SHIFT 5    /* Divide by 32 */
#define SSH_REX_CSET_MASK 31    /* Modulo 32 */
#define SSH_REX_WORD_BITS 32
#endif

#define SSH_REX_WORD_BYTES (SSH_REX_WORD_BITS / 8)

typedef SshRexWord SshRexCharset[SSH_REX_CHARSET_ARRAY_SIZE];

#define SSH_REX_CSET_ISSET(set, idx)    \
(set[(idx) >> SSH_REX_CSET_SHIFT] &     \
 (((SshRexWord)1) << ((idx) & SSH_REX_CSET_MASK)))

#define SSH_REX_CSET_SET(set, idx)                      \
do                                                      \
{                                                       \
  set[(idx) >> SSH_REX_CSET_SHIFT] |=                   \
   (((SshRexWord)1) << ((idx) & SSH_REX_CSET_MASK));    \
}                                                       \
while (0)

#define SSH_REX_CSET_CLEAR(set, idx)                    \
do                                                      \
{                                                       \
  set[(idx) >> SSH_REX_CSET_SHIFT] &=                   \
    ~(((SshRexWord)1) << ((idx) & SSH_REX_CSET_MASK));  \
}                                                       \
while (0)

#define SSH_REX_CSET_ZERO(set)                                                \
do                                                                            \
{                                                                             \
  int __i;                                                                    \
  for (__i = 0; __i < SSH_REX_CHARSET_ARRAY_SIZE; __i++)                      \
    {                                                                         \
      set[__i] = (SshRexWord)0;                                               \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_CSET_COMPLEMENT(set)                                          \
do                                                                            \
{                                                                             \
  int __i;                                                                    \
  for (__i = 0; __i < SSH_REX_CHARSET_ARRAY_SIZE; __i++)                      \
    {                                                                         \
      set[__i] ^= (SshRexWord)(-1L);                                          \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_CSET_FILL(set)                                                \
do                                                                            \
{                                                                             \
  int __i;                                                                    \
  for (__i = 0; __i < SSH_REX_CHARSET_ARRAY_SIZE; __i++)                      \
    {                                                                         \
      set[__i] = (SshRexWord)(-1L);                                           \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_CSET_COPY(dst, src)                                           \
do                                                                            \
{                                                                             \
  int __i;                                                                    \
  for (__i = 0; __i < SSH_REX_CHARSET_ARRAY_SIZE; __i++)                      \
    {                                                                         \
      dst[__i] = src[__i];                                                    \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_CSET_OR(dst, src)                                             \
do                                                                            \
{                                                                             \
  int __i;                                                                    \
  for (__i = 0; __i < SSH_REX_CHARSET_ARRAY_SIZE; __i++)                      \
    {                                                                         \
      dst[__i] |= src[__i];                                                   \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_CSET_AND(dst, src)                                            \
do                                                                            \
{                                                                             \
  int __i;                                                                    \
  for (__i = 0; __i < SSH_REX_CHARSET_ARRAY_SIZE; __i++)                      \
    {                                                                         \
      dst[__i] &= src[__i];                                                   \
    }                                                                         \
}                                                                             \
while (0)

/******************************************************* NFA nodes and NFAs. */

/* Structure containing data for nodes of the type
   SSH_REX_LITERAL. */

typedef struct {
  unsigned char *data;
  size_t data_len;
} SshRexLiteral;

/* Structure containing data for nodes of the type
   SSH_REX_DISJUNCT. */

typedef struct {
  struct ssh_rex_nfa_node *second;
  SshRexCharset second_transition_charset;
} SshRexDisjunct;

typedef struct {
  int range_min, range_max;
} SshRexRange;

/* Union of all possible node data items. */

typedef struct ssh_rex_nfa *SshRexNFA;

typedef union {
  SshRexCharset charset;        /* SSH_REX_CHAR_SET,
                                   SSH_REX_LOOKAHEAD,
                                   SSH_REX_LOOKBACK. */
  SshRexLiteral literal;        /* SSH_REX_LITERAL */
  SshRexDisjunct disjunct;      /* SSH_REX_DISJUNCT */
  SshRexSubexpr subexpr;        /* SSH_REX_START_SUBEXPR,
                                   SSH_REX_END_SUBEXPR */
  SshRexNFA sub_nfa;            /* Used while parsing. */
  SshRexRange range;            /* Used while parsing. */
} SshRexNodeData;

/* Data structure representing a node in a nondeterministic
   finite-state machine. */

typedef struct ssh_rex_thread *SshRexThread;

typedef struct ssh_rex_nfa_node {
  /* Type of the node */
  SshRexMatchType type;

  /* Next node in the state chain for the type SSH_REX_ANY,
     SSH_REX_LITERAL, SSH_REX_CHAR_SET, SSH_REX_START_SUBEXPR,
     SSH_REX_END_SUBEXPR, and SSH_REX_BEGINNING,
     SSH_REX_LOOKAHEAD, SSH_REX_LOOKBACK.  The first of the two arcs
     for SSH_REX_DISJUNCT. */
  struct ssh_rex_nfa_node *next;

  /* The `transition_charset' contains the set of characters that can
     be accepted next if the current transition is taken. This
     one-character lookahead is basically used for eliminating void
     thread forks.  The performance aspect of this optimization needs
     to be measured. */
  SshRexCharset transition_charset;

  /* Type-specific data. */
  SshRexNodeData u;

  /* Some helpful flags. */
  SshUInt32 flags;

  /* The number of incoming edges. Basically a reference count that is
     used to delete nodes that are removed due to optimization. */
  int incoming_edges;

  /* Number of the node. Used to index the array of all NFA nodes. */
  int number;

  /* Tag. */
  int tag;
} *SshRexNFANode, SshRexNFANodeRec;

struct ssh_rex_nfa {
  /* The entry node. */
  SshRexNFANode first;

  /* The accepting node. */
  SshRexNFANode accept;

  /* An array of all the nodes in the NFA. */
  SshRexNFANode *nodes_array;

  /* Number of nodes in the array. */
  int num_nodes;

  /* The allocation size of the array. Can be larger than num_nodes. */
  int array_size;
};

typedef struct ssh_rex_nfa SshRexNFARec;

/************************************************************** Parse trees. */

/* Binary tree node. Used for representing the parsed regular expression
   before the NFA is built. */
typedef struct ssh_rex_btree_node {
  SshRexMatchType type;
  SshRexNodeData u;
  struct ssh_rex_btree_node *left, *right;
} *SshRexBTreeNode, SshRexBTreeNodeRec;

/**************************************************************** Matchers.  */

/* A data structure representing a submatch. */
typedef struct {
  const unsigned char *from;          /* Start of the submatch. */
  const unsigned char *limit;         /* First character not in
                                         the submatch. */
  unsigned char *dupped;              /* If not NULL, a NUL-terminated copy
                                         of the submatch string. */
} SshRexSavedMatch;

/* A regular expression matcher, representing a compiled regular
   expression. */
struct ssh_rex_matcher {
  /* The global context backpointer. */
  SshRegexContext g;

  SshFastMemoryAllocator submatch_bitmask_allocator;

  SshRexNFA nfa; /* The NFA. */

  SshRexSavedMatch *matches;    /* An array of submatch structures */
  int num_matches;              /* The number of subexpressions + 1 */
  const unsigned char *text;    /* Text of the last match */

  /* The list of threads in priority order, highest priority first. */
  SshRexThread threads;

  SshRexThread accepted;

  unsigned int flags;

  SshRegexError e;
};

/************************************************* Non-backtracking matcher. */

/* Data structures used by the non-backtracking matcher. */

/* Trees built from SshRexMatchTreeNodes are used to represent the
   submatch starts and ends for distinct `threads'.  Using reference
   counted trees makes it possible to share already fixed
   positions. */

typedef struct ssh_rex_match_tree_node {
  /* A bit mask of those subexpressions whose starting and ending positions
     have already been fixed. */
  SshRexWord *fixed_submatches;

  /* Reference count for this node. */
  SshUInt32 refcount;

  /* The submatch whose start or end position is set here. */
  SshRexSubexpr subexpr;

  /* TRUE if start, otherwise end. */
  Boolean is_start;

  /* Position where the submatch either starts or ends. */
  const unsigned char *pos;

  /* The parent node, representing the rest of the tree. */
  struct ssh_rex_match_tree_node *parent;
} *SshRexMatchTreeNode, SshRexMatchTreeNodeRec;

struct ssh_rex_thread {
  /* The current state in the NFA where the thread resides. */
  SshRexNFANode state;

  /* The submatch tree representing the already decided submatches. */
  SshRexMatchTreeNode submatches;

  /* The next thread in some list of threads. */
  SshRexThread next;

  /* If delay > 0, then the thread is `out of play' for the next
     `delay' c-transitions (and the corresponding e-transitions).
     After that, the thread is moved to `state' and the thread
     continues normally. This is used to make it possible to have
     coalesced literals. */
  int delay;

  /* Set the true when the thread has been scheduled for deleted but
     cannot be deleted yet because the deleted thread can be part of
     some actively handled list. */
  Boolean deleted;
};

typedef struct ssh_rex_thread SshRexThreadRec;

/**************************************************** Global regex context. */

typedef struct {
  SshRexBTreeNode *stack;       /* The binary tree stack during
                                   rex compilation. */
  int in_stack;                 /* Depth of the active stack */
  int stack_allocated;          /* Number of allocated cells in the stack. */
} SshRexParsingContext;

struct ssh_rex_global_context {
  SshFastMemoryAllocator nfa_node_allocator,
    thread_allocator,
    tree_allocator,
    subexpr_tree_allocator;

  /* Some predefined charsets. */
  SshRexCharset word_chars, digit_chars, whitespace_chars;
  SshRexCharset nword_chars, ndigit_chars, nwhitespace_chars;
  SshRexCharset not_newline_chars;

  SshRexCharset posix_alnum, posix_alpha, posix_cntrl, posix_digit,
    posix_graph, posix_lower, posix_print, posix_punct, posix_space,
    posix_upper, posix_xdigit;

  /* Some precompiled NFA fragments, to be copied and included
     into a full NFA when appropriate. */
  SshRexNFA word_boundary, word_nonboundary;
  SshRexNFA word_start, word_end;
  SshRexNFA line_start, line_end;
  SshRexNFA zsh_star, zsh_star_star, zsh_qmark;

  SshRexParsingContext pc;

  SshRegexError e;
};

/**************************************************************** Bit masks. */

#define SSH_REX_BITMASK_WORDS(nbits) \
(((nbits) + (SSH_REX_WORD_BITS - 1)) / (SSH_REX_WORD_BITS))

#define SSH_REX_BITMASK_BYTES(nbits) \
(SSH_REX_BITMASK_WORDS(nbits) * SSH_REX_WORD_BYTES)

#define SSH_REX_BITMASK_CLEAR(bmask, nbits)                                   \
do                                                                            \
{                                                                             \
  int __temp;                                                                 \
  int __nwords = SSH_REX_BITMASK_WORDS(nbits);                                \
  for (__temp = 0; __temp < __nwords; __temp++)                               \
    {                                                                         \
      ((SshRexWord *)bmask)[__temp] = (SshRexWord)(0L);                       \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_BITMASK_COPY(dst, src, nbits)                                 \
do                                                                            \
{                                                                             \
  int __temp;                                                                 \
  int __nwords = SSH_REX_BITMASK_WORDS(nbits);                                \
  SshRexWord *__dst = (dst); SshRexWord *__src = (src);                       \
  for (__temp = 0; __temp < __nwords; __temp++)                               \
    {                                                                         \
      __dst[__temp] = __src[__temp];                                          \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_REX_BITMASK_SET(bmask, bit)                                       \
do                                                                            \
{                                                                             \
  int __word = (bit) / SSH_REX_WORD_BITS;                                     \
  int __shift = (bit) % SSH_REX_WORD_BITS;                                    \
  (bmask)[__word] |= ((SshRexWord)1L) << __shift;                             \
}                                                                             \
while (0)

/* This macro evaluates `bit' twice. */
#define SSH_REX_BITMASK_ISSET(bmask, bit)                                     \
(((bmask)[(bit) / SSH_REX_WORD_BITS]) &                                       \
 ((SshRexWord)1L) << (bit) % SSH_REX_WORD_BITS)

/******************************************* Auxiliary macros and functions. */

#define ALLOCATE_X(c, var, allocator)                                         \
ssh_fastalloc_alloc_m((c)->allocator, var)

#define FREE_X(c, blob, allocator)                                            \
ssh_fastalloc_free_m((c)->allocator, blob)

#define ALLOCATE_THREAD(c, var)                                               \
ALLOCATE_X(c, var, thread_allocator)

#define ALLOCATE_NFA_NODE(c, var)                                             \
ALLOCATE_X(c, var, nfa_node_allocator)

#define ALLOCATE_TREE_NODE(c, var)                                            \
ALLOCATE_X(c, var, tree_allocator)

#define ALLOCATE_SUBEXPR_NODE(c, var)                                         \
ALLOCATE_X(c, var, subexpr_tree_allocator)

#define FREE_THREAD(c, blob)                                                  \
FREE_X(c, blob, thread_allocator)

#define FREE_NFA_NODE(c, blob)                                                \
FREE_X(c, blob, nfa_node_allocator)

#define FREE_TREE_NODE(c, blob)                                               \
FREE_X(c, blob, tree_allocator)

#define FREE_SUBEXPR_NODE(c, blob)                                            \
FREE_X(c, blob, subexpr_tree_allocator)

/* Set the character set `c' to match exactly those characters in the string
   `string'. */
static void set_cset_from_string(SshRexCharset c, const unsigned char *string)
{
  SSH_REX_CSET_ZERO(c);
  while (*string != 0)
    {
      SSH_REX_CSET_SET(c, *string);
      string++;
    }
}

/********************************************* The non-backtracking matcher. */

/* Clear all the submatch records. Called before a new matching proces
   starts. */

static void clear_matches(SshRegexMatcher m)
{
  int i;
  for (i = 0; i < m->num_matches; i++)
    {
      m->matches[i].from = NULL;
      ssh_free(m->matches[i].dupped);
      m->matches[i].dupped = NULL;
    }
}

/* Initialize the submatch records when they have been allocated.
   Called only when a matcher is created. */

static void init_matches(SshRegexMatcher m)
{
  int i;
  for (i = 0; i < m->num_matches; i++)
    {
      m->matches[i].from = NULL;
      m->matches[i].dupped = NULL;
    }
}

/* Match trees. */

/* Add a new leaf to the match tree `n'. The leafs reference count is
   set to 1 and the parent's reference count is left intact.

   Can return NULL if memory runs out. */
SshRexMatchTreeNode grow_match_tree(SshRegexMatcher m,
                                    SshRexMatchTreeNode n,
                                    SshRexSubexpr subexpr,
                                    Boolean is_start,
                                    const unsigned char *pos)
{
  SshRexMatchTreeNode node;
  ALLOCATE_SUBEXPR_NODE(m->g, node);
  if (node == NULL) return NULL;

  node->parent = n;
  node->pos = pos;
  node->is_start = is_start;
  node->subexpr = subexpr;
  node->refcount = 1;

  ssh_fastalloc_alloc_m(m->submatch_bitmask_allocator, node->fixed_submatches);

  if (node->fixed_submatches == NULL)
    {
      FREE_SUBEXPR_NODE(m->g, node);
      return NULL;
    }

  SSH_ASSERT(subexpr < m->num_matches);

  if (n == NULL)
    SSH_REX_BITMASK_CLEAR(node->fixed_submatches, m->num_matches);
  else
    SSH_REX_BITMASK_COPY(node->fixed_submatches, n->fixed_submatches,
                         m->num_matches);

  if (!is_start)
    SSH_REX_BITMASK_SET(node->fixed_submatches, subexpr);

  return node;
}

void kill_match_tree(SshRegexMatcher m, SshRexMatchTreeNode n)
{
  if (n == NULL) return;
  SSH_ASSERT(n->refcount > 0);
  n->refcount--;
  if (n->refcount == 0)
    {
      kill_match_tree(m, n->parent);
      ssh_fastalloc_free_m(m->submatch_bitmask_allocator,
                           n->fixed_submatches);
      FREE_SUBEXPR_NODE(m->g, n);
    }
}


/* Create a thread that is a copy of `parent' but resides in the state
   `state'. `parent' can be set to NULL. Then this is the initial thread.

   This function does not modify the NFA nodes. */
SshRexThread fork_thread(SshRegexMatcher m, SshRexThread parent,
                         SshRexNFANode state)
{
  SshRexThread t;
  ALLOCATE_THREAD(m->g, t);

  if (t == NULL) /* OUT OF MEMORY */
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, cannot create thread."));
      return NULL;
    }

  t->state = state;
  t->deleted = FALSE;
  if (parent == NULL)
    {
      t->submatches = NULL;
    }
  else
    {
      t->submatches = parent->submatches;
      if (t->submatches != NULL)
        t->submatches->refcount++;
    }
  /* t->next is undefined. */
  t->delay = 0;
  return t;
}

/* Kill a thread. This function does not modify the NFA nodes. */
static void kill_thread(SshRegexMatcher m, SshRexThread thread)
{
  SSH_DEBUG(8, ("Killing thread %p.", thread));
  kill_match_tree(m, thread->submatches);
  FREE_THREAD(m->g, thread);
}

static void get_thread_submatch(SshRegexMatcher m,
                                SshRexThread t,
                                SshRexSubexpr s,
                                const unsigned char **start,
                                const unsigned char **end)
{
  SshRexMatchTreeNode n = t->submatches;
  *start = NULL; *end = NULL;
  while (n != NULL)
    {
      if (n->subexpr == s)
        {
          if (n->is_start)
            *start = n->pos;
          else
            *end = n->pos;
        }
      n = n->parent;
    }

  /* In prefix matching it is possible that a submatch is only
     partial.  In that case the end marker is not found, so if start
     != NULL but end == NULL, ignore the partial match and set the
     start to NULL also. */
  if (*start != NULL && *end == NULL)
    *start = NULL;
}

#ifdef SSH_REX_DEBUG
static void dump_match_tree(SshRexMatchTreeNode n)
{
  while (n != NULL)
    {
      fprintf(stderr, "* %s %d at %p\n",
              (n->is_start ? "start" : "end"),
              n->subexpr,
              n->pos);
      n = n->parent;
    }
}
#endif

#define TC_CHECK_E(charset)                                                   \
((this_state->flags & SSH_REX_CAN_BE_LAST) ||                                 \
 (pos < data_len && (SSH_REX_CSET_ISSET(charset, data[pos]))) ||              \
 (pos == data_len && (m->flags & SSH_REX_ACCEPT_PREFIX)))


#define TC_CHECK(charset)                                                     \
((next_state->flags & SSH_REX_CAN_BE_LAST) ||                                 \
 (pos < (data_len - 1) && (SSH_REX_CSET_ISSET(charset, data[pos + 1]))) ||    \
 (pos >= data_len - 1 && (m->flags && SSH_REX_ACCEPT_PREFIX)))

#define KILL_THREAD()                                                         \
do                                                                            \
{                                                                             \
  *ptr = t->next;                                                             \
  kill_thread(m, t);                                                          \
  goto after_kill;                                                            \
}                                                                             \
while (0)

#define CAN_STEP_TO(state) ((state)->tag != tag)

#define FAST_ESTEP_THREAD_TO(nstate)                                          \
do                                                                            \
{                                                                             \
  t->state = (nstate);                                                        \
  goto redo_thread;                                                           \
}                                                                             \
while (0)

#define ESTEP_THREAD_TO(state)                                                \
do                                                                            \
{                                                                             \
  if (CAN_STEP_TO(state)) FAST_ESTEP_THREAD_TO(state);                        \
  else KILL_THREAD();                                                         \
}                                                                             \
while (0)

#define ESTEP_THREAD()                                                        \
do                                                                            \
{                                                                             \
  if (CAN_STEP_TO(next_state) && TC_CHECK_E(this_state->transition_charset))  \
    FAST_ESTEP_THREAD_TO(next_state);                                         \
  else KILL_THREAD();                                                         \
}                                                                             \
while (0)

#define CAN_STEP() CAN_STEP_TO(next_state)

#define FAST_ESTEP_THREAD()     FAST_ESTEP_THREAD_TO(next_state)

#define STAY_AND_NEXT()                                                       \
do                                                                            \
{                                                                             \
  this_state->tag = tag;                                                      \
  NEXT_THREAD();                                                              \
}                                                                             \
while (0)

#define NEXT_THREAD() goto next_thread

#define STEP_THREAD()                                                         \
do                                                                            \
{                                                                             \
  if (CAN_STEP() && TC_CHECK(this_state->transition_charset))                 \
    {                                                                         \
      t->state = next_state;                                                  \
      next_state->tag = tag;                                                  \
      NEXT_THREAD();                                                          \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      KILL_THREAD();                                                          \
    }                                                                         \
}                                                                             \
while (0)

#define DELAY_THREAD()                                                        \
do                                                                            \
{                                                                             \
  t->state = next_state;                                                      \
  NEXT_THREAD();                                                              \
}                                                                             \
while (0)

#define POM_ACCEPT_IF_LAST()                                                  \
do                                                                            \
{                                                                             \
  if ((m->flags & SSH_REX_ACCEPT_PREFIX) &&                                   \
      (pos == data_len))                                                      \
    goto accept_this_thread;                                                  \
}                                                                             \
while (0)

static Boolean do_step(SshRegexMatcher m, const unsigned char *data,
                       size_t data_len, int pos, int tag)
{
  SshRexThread *ptr = &(m->threads);
  SshRexMatchType type;
  SshRexNFANode next_state, this_state;
  SshRexSubexpr s;
  SshRexThread t;
  SshRexNFANode first, second;
  Boolean step1, step2;
  SshRexThread forked;
  SshRexMatchTreeNode new_tree;
  int rest = data_len - pos;

  SSH_DEBUG(8, ("Stepping pos=%d data starts `%.5s'.", pos,
                data + pos));

  if (*ptr == NULL) return FALSE; /* No threads. */

  while ((t = *ptr) != NULL)
    {
      SSH_DEBUG(8, ("Thread=%p delay=%d", t, t->delay));

      if (t->delay > 0)
        {
          t->delay--;
          if (t->delay == 0)
            {
              if (t->state->tag == tag)
                {
                  KILL_THREAD();
                }
              else
                {
                  t->state->tag = tag;
                  NEXT_THREAD();
                }
            }
          else
            {
              NEXT_THREAD();
            }
        }

    redo_thread:
      this_state = t->state;

      SSH_DEBUG(8, ("State=%d (%p).", this_state->number, this_state));

      if (this_state->tag == tag)
        {
          SSH_DEBUG(8, ("Same tag found."));
          KILL_THREAD();
        }

      if (!(this_state->flags & SSH_REX_NOT_ANCHORED) &&
          pos > 0)
        {
          KILL_THREAD();
        }

      next_state = this_state->next;
      type = this_state->type;

      switch (type)
        {
        case SSH_REX_BEGINNING:
          if (pos != 0) KILL_THREAD();
          else ESTEP_THREAD();
          break;

        case SSH_REX_END:
          if (pos != data_len) KILL_THREAD();
          else ESTEP_THREAD();
          break;

        case SSH_REX_LOOKAHEAD:
          if (pos < data_len &&
              SSH_REX_CSET_ISSET(this_state->u.charset, data[pos]))
            {
              ESTEP_THREAD();
              break;
            }
          POM_ACCEPT_IF_LAST();
          KILL_THREAD();

        case SSH_REX_LOOKBACK:
          if (pos > 0 &&
              SSH_REX_CSET_ISSET(this_state->u.charset, data[pos - 1]))
            ESTEP_THREAD();
          else
            KILL_THREAD();
          break;

        case SSH_REX_START_SUBEXPR:
          if (CAN_STEP())
            {
              s = this_state->u.subexpr;
              if (t->submatches == NULL
                  ||
                  !SSH_REX_BITMASK_ISSET(t->submatches->fixed_submatches, s))
                {
                  new_tree = grow_match_tree(m, t->submatches, s,
                                             TRUE, data + pos);
                  if (new_tree == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Cannot allocate new match tree item."));
                      m->e = SSH_REGEX_OUT_OF_MEMORY;
                      return FALSE;
                    }
                  t->submatches = new_tree;
                }
              FAST_ESTEP_THREAD();
            }
          else
            {
              KILL_THREAD();
            }
          break;

        case SSH_REX_END_SUBEXPR:
          if (CAN_STEP())
            {
              s = this_state->u.subexpr;
              if (!SSH_REX_BITMASK_ISSET(t->submatches->fixed_submatches, s))
                {
                  new_tree = grow_match_tree(m, t->submatches, s,
                                             FALSE, data + pos);
                  if (new_tree == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Cannot allocate new match tree item."));
                      m->e = SSH_REGEX_OUT_OF_MEMORY;
                      return FALSE;
                    }
                  t->submatches = new_tree;
                }
              FAST_ESTEP_THREAD();
            }
          else
            {
              KILL_THREAD();
            }
          break;

        case SSH_REX_DISJUNCT:
          first = this_state->next;
          second = this_state->u.disjunct.second;
          step1 = CAN_STEP_TO(first) &&
            TC_CHECK_E(this_state->transition_charset);
          step2 = CAN_STEP_TO(second) &&
            TC_CHECK_E(this_state->u.disjunct.second_transition_charset);
          if (!step1 && !step2)
            KILL_THREAD();
          else if (!step1)
            ESTEP_THREAD_TO(second);
          else if (!step2)
            ESTEP_THREAD_TO(first);
          else
            {
              forked = fork_thread(m, t, second);
              if (forked == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Out of memory when forking new thread."));
                  m->e = SSH_REGEX_OUT_OF_MEMORY;
                  m->accepted = NULL;
                  return FALSE;
                }
              forked->next = t->next;
              t->next = forked;
              FAST_ESTEP_THREAD();
            }
          break;

        case SSH_REX_ACCEPT:
        accept_this_thread:
          m->accepted = t;
          /* If this is the highest priority thread, the match cannot
             be overriden --- exit immediately. */
          if (m->threads == t) return FALSE;
          STAY_AND_NEXT();
          break;

        case SSH_REX_LITERAL:
          if (rest < this_state->u.literal.data_len)
            {
              if (m->flags & SSH_REX_ACCEPT_PREFIX)
                {
                  if (rest == 0
                      || !memcmp(&data[pos], this_state->u.literal.data, rest))
                    goto accept_this_thread;
                }
              KILL_THREAD();
            }
          else if (memcmp(&data[pos], this_state->u.literal.data,
                          this_state->u.literal.data_len))
            {
              KILL_THREAD();
            }
          else if (this_state->u.literal.data_len == 1)
            {
              STEP_THREAD();
            }
          else
            {
              t->delay = this_state->u.literal.data_len - 1;
              DELAY_THREAD();
            }
          break;

        case SSH_REX_ANY:
          POM_ACCEPT_IF_LAST();
          if (pos == data_len) KILL_THREAD();
          else STEP_THREAD();
          break;

        case SSH_REX_CHAR_SET:
          POM_ACCEPT_IF_LAST();
          if (pos == data_len) KILL_THREAD();
          else if (!SSH_REX_CSET_ISSET(this_state->u.charset, data[pos]))
            KILL_THREAD();
          else STEP_THREAD();
          break;

        default:
          ssh_fatal("Invalid type %d", type);
        }
    next_thread:
      ptr = &(t->next);
    after_kill:
      continue;
    }

  if (pos == data_len)
    return FALSE;
  else
    return TRUE;
}

static void init_nb_match(SshRegexMatcher m)
{
  int i;

  m->threads = NULL;
  m->accepted = NULL;
  m->text = NULL;

  /* Clear the thread slots. */
  for (i = 0; i < m->nfa->num_nodes; i++)
    {
      m->nfa->nodes_array[i]->tag = 0;
    }
}

static void purge_list(SshRegexMatcher m,
                       SshRexThread *l)
{
  SshRexThread t = *l;
  SshRexThread s;
  while (t != NULL)
    {
      s = t;
      t = t->next;
      kill_thread(m, s);
    }
  *l = NULL;
}

static Boolean nb_match_run(SshRegexMatcher m, const unsigned char *data,
                            size_t data_len)
{
  SshRexThread t;
  int pos = 0;
  int s;
  int tag = 0;

  SSH_DEBUG(7, ("Running the NB match."));

  m->e = SSH_REGEX_NO_MATCH;

  t = fork_thread(m, NULL, m->nfa->first);

  if (t == NULL) /* OUT OF MEMORY */
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not start the initial thread."));
      m->e = SSH_REGEX_OUT_OF_MEMORY;
      return FALSE;
    }

  m->threads = t;
  t->next = NULL;

  while (1)
    {
      tag++;
      if (!do_step(m, data, data_len, pos, tag))
        break;

      pos++;
    }

  if (m->accepted == NULL)
    {
      purge_list(m, &(m->threads));
      return FALSE;
    }
  else
    {
      m->e = SSH_REGEX_OK;
#ifdef SSH_REX_DEBUG
      dump_match_tree(m->accepted->submatches);
#endif
      for (s = 0; s < m->num_matches; s++)
        {
          get_thread_submatch(m, m->accepted, s,
                              &(m->matches[s].from),
                              &(m->matches[s].limit));
        }
      purge_list(m, &(m->threads));
      return TRUE;
    }
}

static Boolean nb_match(SshRegexMatcher m, const unsigned char *data,
                        size_t data_len, unsigned int flags)
{
  m->flags = flags;
  init_nb_match(m);
  clear_matches(m);
  m->text = data;
  return nb_match_run(m, data, data_len);
}

/**** NFA CONSTRUCTION: Construct a nondeterministic finite
      automaton from a parse tree. ****/

static void free_nfa_node(SshRegexContext c, SshRexNFANode n)
{
  if (n->type == SSH_REX_LITERAL)
    ssh_free(n->u.literal.data);
  FREE_NFA_NODE(c, n);
}

static SshRexNFANode new_nfa_node(SshRegexContext c,
                                  SshRexNFA nfa)
{
  SshRexNFANode n;
  SshRexNFANode *new_array;
  int new_size;

  ALLOCATE_NFA_NODE(c, n);

  if (n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory when allocation an NFA node."));
      return NULL;
    }

  n->next = NULL;
  n->flags = 0;
  n->number = nfa->num_nodes;
  n->incoming_edges = 0;
  /* Just set the type to an arbitrary value so that `free_nfa_node' works
     correctly if the node gets freed prematurely. */
  n->type = SSH_REX_BEGINNING;

  if (nfa->num_nodes >= nfa->array_size || nfa->nodes_array == NULL)
    {
      new_size = (nfa->array_size * 2) + 10;

      /* We cannot use realloc here because realloc could return NULL and then
         the pointers to the already allocated nodes would be lost and they
         couldn't be freed. */
      new_array = ssh_malloc(new_size * sizeof(nfa->nodes_array[0]));

      if (new_array == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Out of memory when reallocating NFA nodes array."));

          FREE_NFA_NODE(c, n);
          return NULL;
        }

      if (nfa->nodes_array != NULL)
        {
          memcpy(new_array, nfa->nodes_array,
                 sizeof(nfa->nodes_array[0]) * nfa->num_nodes);
          ssh_free(nfa->nodes_array);
        }
      nfa->nodes_array = new_array;
      nfa->array_size = new_size;
    }

  nfa->nodes_array[nfa->num_nodes] = n;
  nfa->num_nodes++;

  return n;
}

static void free_registered_node(SshRegexContext c,
                                 SshRexNFA nfa,
                                 SshRexNFANode n)
{
  nfa->nodes_array[n->number] = NULL;
  free_nfa_node(c, n);
}

static void destroy_nfa(SshRegexContext c, SshRexNFA nfa)
{
  int i;
  for (i = 0; i < nfa->num_nodes; i++)
    {
      if (nfa->nodes_array[i] != NULL)
        free_nfa_node(c, nfa->nodes_array[i]);
    }
  ssh_free(nfa->nodes_array);
  ssh_free(nfa);
}

#ifdef SSH_REX_DEBUG

static void dump_charset(SshRexCharset cset)
{
  int i;
  Boolean dash = FALSE;

  for (i = 0; i < 256; i++)
    {
      if (SSH_REX_CSET_ISSET(cset, i))
        {
          if (i > 0 && i < 255 &&
              SSH_REX_CSET_ISSET(cset, i - 1) &&
              SSH_REX_CSET_ISSET(cset, i + 1))
            {
              if (!dash)
                {
                  fprintf(stderr, "-");
                  dash = TRUE;
                }
            }
          else
            {
              dash = FALSE;
              if (i > 32 && i < 127)
                fprintf(stderr, "%c", i);
              else
                fprintf(stderr, "~%d", i);
            }
        }
    }
}

static void dump_nfa_node(SshRexNFANode n)
{
  fprintf(stderr, "%04d: ", n->number);
  switch (n->type)
    {
    case SSH_REX_BEGINNING:
      fprintf(stderr, "TextBegin ==> %04d", n->next->number);
      break;
    case SSH_REX_END:
      fprintf(stderr, "TextEnd   ==> %04d", n->next->number);
      break;
    case SSH_REX_ANY:
      fprintf(stderr, "AnyChar   ==> %04d", n->next->number);
      break;
    case SSH_REX_CHAR_SET:
      fprintf(stderr, "CharSet   ==> %04d", n->next->number);
      break;
    case SSH_REX_LITERAL:
      fprintf(stderr, "Literal   ==> %04d", n->next->number);
      break;
    case SSH_REX_ACCEPT:
      fprintf(stderr, "Accept.           ");
      break;
    case SSH_REX_LOOKAHEAD:
      fprintf(stderr, "Lookahead ==> %04d", n->next->number);
      break;
    case SSH_REX_LOOKBACK:
      fprintf(stderr, "Lookback ==> %04d", n->next->number);
      break;
    case SSH_REX_DISJUNCT:
      fprintf(stderr, "Disjunct  ==> %04d, %04d",
              n->next->number, n->u.disjunct.second->number);
      break;
    case SSH_REX_FORWARD:
      fprintf(stderr, "Forward   ==> %04d",
              n->next->number);
      break;
    case SSH_REX_START_SUBEXPR:
      fprintf(stderr, "Sub %02d    ==> %04d",
              n->u.subexpr, n->next->number);
      break;
    case SSH_REX_END_SUBEXPR:
      fprintf(stderr, "ESub %02d   ==> %04d",
              n->u.subexpr, n->next->number);
      break;

    default:
      SSH_NOTREACHED;
    }

  if (n->type == SSH_REX_CHAR_SET || n->type == SSH_REX_LOOKAHEAD
      || n->type == SSH_REX_LOOKBACK)
    {
      fprintf(stderr, " CS [");
      dump_charset(n->u.charset);
      fprintf(stderr, "]");
    }

  if (n->type == SSH_REX_LITERAL)
    {
      fprintf(stderr, " `");
      fwrite(n->u.literal.data, n->u.literal.data_len, 1, stderr);
      fprintf(stderr, "'");
    }

  if (n->flags & SSH_REX_CAN_BE_LAST)
    fprintf(stderr, " [last?]");
  if (n->flags & SSH_REX_NOT_ANCHORED)
    fprintf(stderr, " [n.anch.]");

  if (n->type != SSH_REX_DISJUNCT && n->type != SSH_REX_ACCEPT)
    {
      fprintf(stderr, " TC [");
      dump_charset(n->transition_charset);
      fprintf(stderr, "]");
    }

  if (n->type == SSH_REX_DISJUNCT)
    {
      fprintf(stderr, " TC1 [");
      dump_charset(n->transition_charset);
      fprintf(stderr, "] TC2 [");
      dump_charset(n->u.disjunct.second_transition_charset);
      fprintf(stderr, "]");
    }

  fprintf(stderr, "\n");
}

static void dump_nfa(SshRexNFA nfa)
{
  int i;
  fprintf(stderr, "The entry node is %d.\n", nfa->first->number);
  for (i = 0; i < nfa->num_nodes; i++)
    {
      dump_nfa_node(nfa->nodes_array[i]);
    }
}

#endif

/* Streamlining code, which removes all forwarding nodes from an NFA. */

static void streamline_nfa(SshRegexContext c, SshRexNFA nfa, SshRexNFANode n);

static void streamline(SshRegexContext c, SshRexNFA nfa, SshRexNFANode *ptr)
{
 redo:
  SSH_ASSERT((*ptr) != NULL);
  if ((*ptr)->type == SSH_REX_FORWARD)
    {
      SshRexNFANode f = (*ptr);
      SSH_DEBUG(8, ("Seeing forwarding node %d.", f->number));
      SSH_ASSERT(f->incoming_edges > 0);

      (*ptr) = f->next;

      f->incoming_edges--;
      if (f->incoming_edges == 0)
        {
          free_registered_node(c, nfa, f);
        }
      else
        {
          f->next->incoming_edges++;
        }
      goto redo;
    }
  streamline_nfa(c, nfa, (*ptr));
}

static void streamline_nfa(SshRegexContext c,
                           SshRexNFA nfa,
                           SshRexNFANode n)
{
  if (n->flags & SSH_REX_STREAMLINED) return;
  n->flags |= SSH_REX_STREAMLINED;

  SSH_DEBUG(8, ("Streamlining node %d.", n->number));

  switch (n->type)
    {
    case SSH_REX_ACCEPT:
      return;
    case SSH_REX_DISJUNCT:
      streamline(c, nfa, &(n->u.disjunct.second));
      /* Fall through. */
    default:
      streamline(c, nfa, &(n->next));
      return;
    }
}

/* Returns FALSE on memory allocation error, although that actually never
   happens. */
static Boolean shrink_nodes_array(SshRegexContext c, SshRexNFA nfa)
{
  int i;
  int offset = 0;
  SshRexNFANode *new_array;

  for (i = 0; i < nfa->num_nodes; i++)
    {
      if (nfa->nodes_array[i] == NULL)
        {
          offset++;
          continue;
        }
      if (offset > 0)
        {
          nfa->nodes_array[i - offset] = nfa->nodes_array[i];
          nfa->nodes_array[i]->number -= offset;
        }
    }
  nfa->num_nodes -= offset;

  /* Cannot use realloc because realloc could fail and then the live pointers
     would be lost. */
  new_array = ssh_malloc(nfa->num_nodes * sizeof(nfa->nodes_array[0]));

  if (new_array == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate new array in `shrink_nodes_array'"
                 " but can continue."));
      return TRUE;
    }

  memcpy(new_array, nfa->nodes_array, sizeof(new_array[0]) * nfa->num_nodes);
  nfa->array_size = nfa->num_nodes;
  ssh_free(nfa->nodes_array);
  nfa->nodes_array = new_array;

  return TRUE;
}

/* Returns FALSE on memory allocation error. */
static Boolean copy_nfa_nodes(SshRegexContext c, SshRexNFA orig,
                              SshRexNFA nfa,
                              SshRexNFANode *enter, SshRexNFANode *accept)
{
  int i, saved;
  SshRexNFANode n, dst, src;
  SshRexNFANode *a;

  a = ssh_malloc(sizeof(a[0]) * orig->num_nodes);

  if (a == NULL) /* OUT OF MEMORY */
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory when copying NFA nodes array."));
      return FALSE;
    }

  for (i = 0; i < orig->num_nodes; i++)
    {
      n = new_nfa_node(c, nfa);
      if (n == NULL) /* OUT OF MEMORY */
        {
          SSH_DEBUG(SSH_D_FAIL, ("Out of memory when copying NFA nodes."));
          for (i = i - 1; i >= 0; i--)
            {
              free_registered_node(c, nfa, a[i]);
            }
          ssh_free(a);
          return FALSE;
        }
      a[i] = n;
    }

  for (i = 0; i < orig->num_nodes; i++)
    {
      dst = a[i];
      src = orig->nodes_array[i];
      saved = dst->number;
      memcpy(dst, src, sizeof(*dst));
      dst->flags = 0;
      dst->number = saved;

      if (dst->type != SSH_REX_ACCEPT)
        {
          dst->next = a[src->next->number];
        }
      if (dst->type == SSH_REX_DISJUNCT)
        {
          dst->u.disjunct.second = a[src->u.disjunct.second->number];
        }
      if (dst->type == SSH_REX_LITERAL)
        {
          dst->u.literal.data = ssh_malloc(dst->u.literal.data_len);

          if (dst->u.literal.data == NULL) /* OUT OF MEMORY */
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Out of memory when copying NFA nodes'"
                         " literal data."));
              for (i = 0; i < orig->num_nodes; i++)
                {
                  free_registered_node(c, nfa, a[i]);
                }
              ssh_free(a);
              return FALSE;
            }

          memcpy(dst->u.literal.data, src->u.literal.data,
                 dst->u.literal.data_len);
        }
    }

  *enter  = a[orig->first->number];
  *accept = a[orig->accept->number];

  ssh_free(a);

  return TRUE;
}

/* The actual recursive procedure for constructing the NFA. */

#define MAKE_NODE() new_nfa_node(c, nfa)

#define NEWNFANODE(x)                                                         \
do                                                                            \
{                                                                             \
  x = MAKE_NODE();                                                            \
  if (x == NULL) return FALSE;                                                \
}                                                                             \
while (0)

#define RECURSE(tree, enterp, acceptp) \
if (!construct_nfa(c, nfa, tree, enterp, acceptp)) return FALSE

/* Returns FALSE on memory allocation error. */
static Boolean construct_nfa(SshRegexContext c,
                             SshRexNFA nfa,
                             SshRexBTreeNode tree,
                             SshRexNFANode *enter,
                             SshRexNFANode *accept)
{
  SshRexNFANode nfa1_e, nfa1_a, nfa2_e, nfa2_a;
  SshRexNFANode n1, n2;

  /* Some invalid regexps cause this to be entered with tree==NULL
     (e.g., "~|?").  This avoids the crash. */
  if (!tree)
    return FALSE;

  switch (tree->type)
    {
    case SSH_REX_BEGINNING:
    case SSH_REX_END:
    case SSH_REX_ANY:
    case SSH_REX_CHAR_SET:
    case SSH_REX_LITERAL:
    case SSH_REX_LOOKAHEAD:
    case SSH_REX_LOOKBACK:

      NEWNFANODE(n2);
      NEWNFANODE(n1);

      n2->type = SSH_REX_ACCEPT;
      n2->incoming_edges = 1;

      n1->type = tree->type;
      memcpy(&(n1->u), &(tree->u), sizeof(n1->u));
      n1->next = n2;

      *enter = n1; *accept = n2;

      /* If the node was a literal node, copy the literal data. */
      if (tree->type == SSH_REX_LITERAL)
        {
          n1->u.literal.data = ssh_malloc(n1->u.literal.data_len);

          if (n1->u.literal.data == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Out of memory when allocating literal data."));
              return FALSE;
            }

          memcpy(n1->u.literal.data, tree->u.literal.data,
                 tree->u.literal.data_len);
        }

      return TRUE;

    case SSH_REX_SUB_NFA:
      if (!copy_nfa_nodes(c, tree->u.sub_nfa, nfa, enter, accept))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Copying NFA failed."));
          return FALSE;
        }
      return TRUE;

    case SSH_REX_DISJUNCT:
      RECURSE(tree->left,  &nfa1_e, &nfa1_a);
      RECURSE(tree->right, &nfa2_e, &nfa2_a);

      NEWNFANODE(n1);
      n1->type = SSH_REX_DISJUNCT;
      n1->next = nfa1_e;
      n1->u.disjunct.second = nfa2_e;

      nfa1_e->incoming_edges++;
      nfa2_e->incoming_edges++;

      nfa1_a->type = SSH_REX_FORWARD;
      nfa1_a->next = nfa2_a;
      nfa2_a->incoming_edges++;

      *enter = n1; *accept = nfa2_a; return TRUE;

    case SSH_REX_CONCATENATION:
      RECURSE(tree->left, &nfa1_e, &nfa1_a);
      RECURSE(tree->right, &nfa2_e, &nfa2_a);

      nfa1_a->type = SSH_REX_FORWARD;
      nfa1_a->next = nfa2_e;
      nfa2_e->incoming_edges++;

      *enter = nfa1_e; *accept = nfa2_a; return TRUE;

    case SSH_REX_STAR:
    case SSH_REX_LAZY_STAR:
      NEWNFANODE(n1);
      n1->type = SSH_REX_ACCEPT;

      RECURSE(tree->left, &nfa1_e, &nfa1_a);

      nfa1_a->type = SSH_REX_DISJUNCT;

      if (tree->type == SSH_REX_STAR)
        {
          nfa1_a->next = nfa1_e;
          nfa1_a->u.disjunct.second = n1;
        }
      else
        {
          nfa1_a->next = n1;
          nfa1_a->u.disjunct.second = nfa1_e;
        }

      nfa1_e->incoming_edges++;
      n1->incoming_edges++;

      *enter = nfa1_a; *accept = n1; return TRUE;

    case SSH_REX_PLUS:
    case SSH_REX_LAZY_PLUS:
      NEWNFANODE(n1);
      n1->type = SSH_REX_ACCEPT;

      RECURSE(tree->left, &nfa1_e, &nfa1_a);

      nfa1_a->type = SSH_REX_DISJUNCT;

      if (tree->type == SSH_REX_PLUS)
        {
          nfa1_a->next = nfa1_e;
          nfa1_a->u.disjunct.second = n1;
        }
      else
        {
          nfa1_a->next = n1;
          nfa1_a->u.disjunct.second = nfa1_e;
        }

      nfa1_e->incoming_edges++;
      n1->incoming_edges++;

      *enter = nfa1_e; *accept = n1; return TRUE;

    case SSH_REX_OPTIONAL:
    case SSH_REX_LAZY_OPTIONAL:
      NEWNFANODE(n1);

      RECURSE(tree->left, &nfa1_e, &nfa1_a);

      n1->type = SSH_REX_DISJUNCT;

      if (tree->type == SSH_REX_OPTIONAL)
        {
          n1->next = nfa1_e;
          n1->u.disjunct.second = nfa1_a;
        }
      else
        {
          n1->next = nfa1_a;
          n1->u.disjunct.second = nfa1_e;
        }

      nfa1_e->incoming_edges++;
      nfa1_a->incoming_edges++;

      *enter = n1; *accept = nfa1_a; return TRUE;

    case SSH_REX_RANGE:
    case SSH_REX_LAZY_RANGE:
      {
        SshRexBTreeNodeRec saved;

        memcpy(&saved, tree, sizeof(saved));

        /* If in E{n,m}, n > 0, then create a concatenation

           E E{n-1,m-1}

           except that if m = -1, do not change m. */

        if (tree->u.range.range_min > 0)
          {
            RECURSE(tree->left, &nfa1_e, &nfa1_a);

            tree->u.range.range_min--;
            if (tree->u.range.range_max != -1)
              tree->u.range.range_max--;

            RECURSE(tree, &nfa2_e, &nfa2_a);

            nfa1_a->type = SSH_REX_FORWARD;
            nfa1_a->next = nfa2_e;
            nfa2_e->incoming_edges++;
            *enter = nfa1_e;
            *accept = nfa2_a;
          }

        /* Otherwise, in E{0,m}, if m is unlimited change {0,m} to * and
           construct E*.  Otherwise E{0,m} = (E E{0,m-1})? and E{0,1} = E? */

        else
          {
            Boolean is_lazy;

            /* We need to memoize this result because the actual type of
               the tree node gets changed to STAR or OPTIONAL during
               recursion. */

            is_lazy = (tree->type == SSH_REX_LAZY_RANGE);

            if (tree->u.range.range_max == 0)
              {
                NEWNFANODE(n1);
                n1->type = SSH_REX_ACCEPT;
                *enter = n1; *accept = n1;
              }
            else if (tree->u.range.range_max == -1)
              {
                if (tree->type == SSH_REX_RANGE)
                  tree->type = SSH_REX_STAR;
                else
                  tree->type = SSH_REX_LAZY_STAR;
                RECURSE(tree, enter, accept);
                return TRUE;
              }
            else if (tree->u.range.range_max == 1)
              {
                if (tree->type == SSH_REX_RANGE)
                  tree->type = SSH_REX_OPTIONAL;
                else
                  tree->type = SSH_REX_LAZY_OPTIONAL;
                RECURSE(tree, enter, accept);
                return TRUE;
              }
            else
              {
                SSH_ASSERT(tree->u.range.range_max > 1);

                RECURSE(tree->left, &nfa1_e, &nfa1_a);
                tree->u.range.range_max--;
                RECURSE(tree, &nfa2_e, &nfa2_a);

                nfa1_a->type = SSH_REX_FORWARD;
                nfa1_a->next = nfa2_e;
                nfa2_e->incoming_edges++;

                NEWNFANODE(n1);

                n1->type = SSH_REX_DISJUNCT;

                if (!is_lazy)
                  {
                    n1->next = nfa1_e;
                    n1->u.disjunct.second = nfa2_e;
                  }
                else
                  {
                    n1->next = nfa2_e;
                    n1->u.disjunct.second = nfa1_e;
                  }
                nfa1_e->incoming_edges++;
                nfa2_e->incoming_edges++;

                *enter = n1; *accept = nfa2_a;
              }
          }

        memcpy(tree, &saved, sizeof(*tree));

        return TRUE;
      }

    case SSH_REX_SUBEXPR:
      NEWNFANODE(n1);
      NEWNFANODE(n2);

      RECURSE(tree->left, &nfa1_e, &nfa1_a);

      n1->type = SSH_REX_START_SUBEXPR;
      n2->type = SSH_REX_ACCEPT;
      nfa1_a->type = SSH_REX_END_SUBEXPR;
      n1->u.subexpr = tree->u.subexpr;
      n1->next = nfa1_e;
      nfa1_e->incoming_edges++;
      nfa1_a->u.subexpr = tree->u.subexpr;
      nfa1_a->next = n2;
      n2->incoming_edges++;

      *enter = n1; *accept = n2; return TRUE;

    case SSH_REX_ANON_SUBEXPR:
      RECURSE(tree->left, enter, accept);
      return TRUE;

    default:
      SSH_NOTREACHED;
    }
  /* Not reached. */
  return FALSE;
}

#undef RECURSE

/******************************************************* Transition charsets */

static void literal_charset(SshRexNFANode n, SshRexCharset r)
{
  switch (n->type)
    {
    case SSH_REX_ANY:
      SSH_REX_CSET_FILL(r);
      return;

    case SSH_REX_LITERAL:
      SSH_REX_CSET_ZERO(r);
      SSH_REX_CSET_SET(r, n->u.literal.data[0]);
      return;

    case SSH_REX_CHAR_SET:
      SSH_REX_CSET_COPY(r, n->u.charset);
      return;

    default:
      SSH_NOTREACHED;
    }
}

typedef struct ssh_rex_efill_stack {
  SshRexNFANode node;
  struct ssh_rex_efill_stack *next;
} SshRexEFillStack;

static Boolean e_fill(SshRegexContext c, SshRexNFA nfa, SshRexNFANode n,
                      SshRexCharset r, SshRexEFillStack *stack)
{
  SshRexEFillStack s, *sptr;

  switch (n->type)
    {
      /* For different types of consuming literal nodes, figure out
         the set of accepted characters and return the set in r. Do
         not modify the local non-e node at all. */
    case SSH_REX_ANY:
    case SSH_REX_LITERAL:
    case SSH_REX_CHAR_SET:
      literal_charset(n, r);
      return TRUE;
    default:
      break;
    }

  for (sptr = stack; sptr != NULL; sptr = sptr->next)
    {
      if (sptr->node == n) return FALSE; /* Loop. */
    }

  s.node = n;
  s.next = stack;

  switch (n->type)
    {
      /* The accept node can match at the end of the string so raise
         the flag for the node. */
    case SSH_REX_ACCEPT:
      n->flags |= SSH_REX_CAN_BE_LAST;
      SSH_REX_CSET_FILL(r);
      return TRUE;

      /* Disjuncts: fill the both options and return in `r' the union
         of the two possible character sets. At the same time, set the
         CAN_BE_LAST flag in `n' if at least one of the options can
         match at the end of the string. */
    case SSH_REX_DISJUNCT:
      if (!(e_fill(c, nfa, n->next, n->transition_charset, &s) &&
            e_fill(c, nfa, n->u.disjunct.second,
                   n->u.disjunct.second_transition_charset, &s)))
        return FALSE;
      SSH_REX_CSET_COPY(r, n->transition_charset);
      SSH_REX_CSET_OR(r, n->u.disjunct.second_transition_charset);
      if ((n->next->flags & SSH_REX_CAN_BE_LAST) ||
          (n->u.disjunct.second->flags & SSH_REX_CAN_BE_LAST))
        n->flags |= SSH_REX_CAN_BE_LAST;
      return TRUE;

      /* Lookaheads: first traverse forward and get the returned
         character set. Then `filter' if with the lookahead set and
         return the filtered set. */
    case SSH_REX_LOOKAHEAD:
      if (!(e_fill(c, nfa, n->next, n->transition_charset, &s)))
        return FALSE;
      SSH_REX_CSET_AND(n->transition_charset, n->u.charset);
      SSH_REX_CSET_COPY(r, n->transition_charset);
      return TRUE;

      /* The remaining e-nodes just pass the character sets upwards. */
    case SSH_REX_START_SUBEXPR:
    case SSH_REX_END_SUBEXPR:
    case SSH_REX_LOOKBACK:
    case SSH_REX_BEGINNING:
    case SSH_REX_END:
      if (!(e_fill(c, nfa, n->next, n->transition_charset, &s)))
        return FALSE;
      SSH_REX_CSET_COPY(r, n->transition_charset);
      if (n->next->flags & SSH_REX_CAN_BE_LAST)
        n->flags |= SSH_REX_CAN_BE_LAST;
      return TRUE;

    default:
      fprintf(stderr, "%d\n", n->type);
      SSH_NOTREACHED;
      break;
    }
  return FALSE;                 /* Never actually reached. */
}

static Boolean calculate_transition_charsets(SshRegexContext c,
                                             SshRexNFA nfa)
{
  int i;
  SshRexNFANode n, n2;
  SshRexCharset r;

  if (!e_fill(c, nfa, nfa->first, r, NULL))
    return FALSE;

  for (i = 0; i < nfa->num_nodes; i++)
    {
      n = nfa->nodes_array[i];
      switch (n->type)
        {
          case SSH_REX_ANY:
          case SSH_REX_LITERAL:
          case SSH_REX_CHAR_SET:

            n2 = n->next;

            switch (n2->type)
              {
              case SSH_REX_ANY:
              case SSH_REX_LITERAL:
              case SSH_REX_CHAR_SET:
                literal_charset(n2, n->transition_charset);
                break;

              case SSH_REX_ACCEPT:
                SSH_REX_CSET_FILL(n->transition_charset);
                break;

              default:
                if (!(e_fill(c, nfa, n2, r, NULL)))
                  return FALSE;

                SSH_REX_CSET_COPY(n->transition_charset, r);
                break;
              }
        default:
          break;
        }
    }
  return TRUE;
}

static void anchor_search(SshRegexContext c, SshRexNFANode n, int tag)
{
  if (n->type == SSH_REX_ACCEPT)
    {
      n->flags |= SSH_REX_NOT_ANCHORED;
      return;
    }

  if (n->tag == tag)
    {
      return;
    }

  n->tag = tag;

  switch (n->type)
    {
    case SSH_REX_BEGINNING:
      anchor_search(c, n->next, tag);
      return;

    case SSH_REX_DISJUNCT:
      anchor_search(c, n->next, tag);
      anchor_search(c, n->u.disjunct.second, tag);
      if ((n->next->flags & SSH_REX_NOT_ANCHORED) ||
          (n->u.disjunct.second->flags & SSH_REX_NOT_ANCHORED))
        n->flags |= SSH_REX_NOT_ANCHORED;
      break;

    default:
      anchor_search(c, n->next, tag);
      if (n->next->flags & SSH_REX_NOT_ANCHORED)
        n->flags |= SSH_REX_NOT_ANCHORED;
    }
}

static void calculate_anchor_hints(SshRegexContext c, SshRexNFA nfa)
{
  int i, tag = 0;

  for (i = 0; i < nfa->num_nodes; i++)
    {
      nfa->nodes_array[i]->tag = 0;
    }

  for (i = 0; i < nfa->num_nodes; i++)
    {
      tag++;
      anchor_search(c, nfa->nodes_array[i], tag);
    }
}

/********************************** REGEX PARSER: Parse strings into trees. */

/********************************************************** Stack operations */

#define STACKREF(n) stack_ref(c, n)

/* This macro frees the tree `n' manually because it doesn't appear in the
   stack when we go to `cleanup_and_barf', which frees every tree that has a
   root in the stack. */
#define PUSH(n)                                                               \
do                                                                            \
{                                                                             \
  if (!stack_push(c, n))                                                      \
    {                                                                         \
      delete_btree(c, n);                                                     \
      c->e = SSH_REGEX_OUT_OF_MEMORY;                                         \
      goto cleanup_and_barf;                                                  \
    }                                                                         \
}                                                                             \
while (0)

#define POP()       stack_pop(c)
#define DISCARD()   stack_discard(c)

static SshRexBTreeNode stack_ref(SshRegexContext c, int offset)
{
  SSH_ASSERT(c->pc.in_stack >= (offset + 1));
  return c->pc.stack[c->pc.in_stack - (1 + offset)];
}

/* Returns FALSE if running out of memory. Cannot use realloc here because the
   contents of the stack must be preserved so that we can free the tree nodes
   on the it. */
static Boolean stack_push(SshRegexContext c, SshRexBTreeNode n)
{
  SshRexBTreeNode *new_stack;
  if (c->pc.in_stack == c->pc.stack_allocated)
    {
      c->pc.stack_allocated *= 2;
      c->pc.stack_allocated += 10;

      new_stack = ssh_malloc(sizeof(c->pc.stack[0]) * c->pc.stack_allocated);

      if (new_stack == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Out of memory when growing the parse stack."));
          return FALSE;
        }

      memcpy(new_stack, c->pc.stack, sizeof(c->pc.stack[0]) * c->pc.in_stack);
      ssh_free(c->pc.stack);
      c->pc.stack = new_stack;
    }
  c->pc.stack[c->pc.in_stack++] = n;
  return TRUE;
}

static SshRexBTreeNode stack_pop(SshRegexContext c)
{
  SSH_ASSERT(c->pc.in_stack > 0);
  return c->pc.stack[--(c->pc.in_stack)];
}

static void stack_discard(SshRegexContext c)
{
  SSH_ASSERT(c->pc.in_stack > 0);
  c->pc.in_stack--;
}

/************************************** Creating and destroying parse trees. */

static SshRexBTreeNode new_btree_node(SshRegexContext c)
{
  SshRexBTreeNode n;
  ALLOCATE_TREE_NODE(c, n);
  if (n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory when allocating a"
                             " new tree node."));
      return NULL;
    }
  n->left = n->right = NULL;
  return n;
}

static void delete_btree_node(SshRegexContext c, SshRexBTreeNode node)
{
  SSH_DEBUG(8, ("Releasing a binary tree node."));

  if (node->type == SSH_REX_LITERAL)
    {
      ssh_free(node->u.literal.data);
    }

  FREE_TREE_NODE(c, node);
}

static void delete_btree(SshRegexContext c, SshRexBTreeNode node)
{
  if (node == NULL) return;
  delete_btree(c, node->left);
  delete_btree(c, node->right);
  delete_btree_node(c, node);
}

/********************************************************** Debugging dumps. */

#ifdef SSH_REX_DEBUG

static void dump_btree(SshRexBTreeNode node)
{
  if (node == NULL)
    {
      fprintf(stderr, "[null]");
      return;
    }
  switch (node->type)
    {
    case SSH_REX_ANON_SUBEXPR:
      fprintf(stderr, "expr(");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_SUB_NFA:
      fprintf(stderr, "NFA(%p)",
              node->u.sub_nfa);
      break;

    case SSH_REX_BEGINNING:
      fprintf(stderr, "begin");
      break;

    case SSH_REX_END:
      fprintf(stderr, "end");
      break;

    case SSH_REX_START_SUBEXPR:
      fprintf(stderr, "start-subexpr[%d]", node->u.subexpr);
      break;

    case SSH_REX_START_ANON_SUBEXPR:
      fprintf(stderr, "start-anon-subexpr");
      break;

    case SSH_REX_STAR:
      fprintf(stderr, "*(");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_PLUS:
      fprintf(stderr, "+(");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_OPTIONAL:
      fprintf(stderr, "?(");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_LAZY_STAR:
      fprintf(stderr, "*[lazy](");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_LAZY_PLUS:
      fprintf(stderr, "+[lazy](");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_LAZY_OPTIONAL:
      fprintf(stderr, "?[lazy](");
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_RANGE:
      fprintf(stderr, "range{%d,%d}(", node->u.range.range_min,
              node->u.range.range_max);
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_LAZY_RANGE:
      fprintf(stderr, "range[lazy]{%d,%d}(", node->u.range.range_min,
              node->u.range.range_max);
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_ANY:
      fprintf(stderr, ".");
      break;

    case SSH_REX_CONCATENATION:
      fprintf(stderr, "conc(");
      dump_btree(node->left);
      fprintf(stderr, ", ");
      dump_btree(node->right);
      fprintf(stderr, ")");
      break;

    case SSH_REX_DISJUNCT:
      fprintf(stderr, "or(");
      dump_btree(node->left);
      fprintf(stderr, ", ");
      dump_btree(node->right);
      fprintf(stderr, ")");
      break;

    case SSH_REX_SUBEXPR:
      fprintf(stderr, "subexpr[%d](", node->u.subexpr);
      dump_btree(node->left);
      fprintf(stderr, ")");
      break;

    case SSH_REX_CHAR_SET:
    case SSH_REX_LOOKBACK:
    case SSH_REX_LOOKAHEAD:
      fprintf(stderr, "%s(",
              node->type == SSH_REX_CHAR_SET ? "charset" :
              node->type == SSH_REX_LOOKAHEAD ? "lookahead" :
              "lookback");
      dump_charset(node->u.charset);
      fprintf(stderr, ")");
      break;

    case SSH_REX_LITERAL:
      fprintf(stderr, "literal(");
      {
        int i;
        for (i = 0; i < node->u.literal.data_len; i++)
          {
            fprintf(stderr, "%c", node->u.literal.data[i]);
          }
      }
      fprintf(stderr, ")");
      break;

    default:
      /* looks strange, but without splitting the string contains
         a trigraph -- shoot whoever invented those.. */
      fprintf(stderr, "<?" "?" "?>");
    }
}

#endif

#ifdef SSH_REX_DEBUG

static void dump_stack(SshRegexContext c)
{
  int i;
  for (i = 0; i < c->pc.in_stack; i++)
    {
      fprintf(stderr, "[%d] ", i);
      dump_btree(c->pc.stack[i]);
      fprintf(stderr, "\n");
    }
}

#endif

/****************************************************** Auxiliary functions. */

/* Returns FALSE if running out of memory. */
static Boolean add_to_literal(SshRexLiteral *l, const unsigned char *data,
                              size_t len)
{
  l->data = ssh_realloc(l->data, l->data_len, l->data_len + len);
  if (l->data == NULL) return FALSE;
  memcpy(l->data + l->data_len, data, len);
  l->data_len += len;
  return TRUE;
}

/*********************************************************** Stack collapse. */

/* Collapse all concatenations until (1) bottom is reached, (2) a
   subexpression start is detected, or (3) a disjunct is detected, in
   which case the concatenated upper half is set to the disjuncts
   `right' branch and collapsing ends. */
static Boolean collapse_stack(SshRegexContext c)
{
  while (1)
    {
      SshRexBTreeNode n;

      SSH_DEBUG(8, ("Collapsing..."));

#ifdef SSH_REX_DEBUG
      dump_stack(c);
#endif

      if (c->pc.in_stack == 0) return TRUE;

      /* Empty subexpressions are not allowed. */
      if (STACKREF(0)->type == SSH_REX_START_SUBEXPR ||
          STACKREF(0)->type == SSH_REX_START_ANON_SUBEXPR)
        {
          c->e = SSH_REGEX_PARSE_ERROR;
          return FALSE;
        }

      /* If `|' appears on the top, signal error. */
      if (STACKREF(0)->type == SSH_REX_DISJUNCT)
        {
          c->e = SSH_REGEX_PARSE_ERROR;
          return FALSE;
        }

      if (c->pc.in_stack == 1) return TRUE;

      if (STACKREF(1)->type == SSH_REX_START_SUBEXPR ||
          STACKREF(1)->type == SSH_REX_START_ANON_SUBEXPR)
        {
          return TRUE;
        }

      if (STACKREF(1)->type == SSH_REX_DISJUNCT)
        {
          SSH_ASSERT(STACKREF(1)->right == NULL);
          STACKREF(1)->right = STACKREF(0);
          DISCARD();
          return TRUE;
        }

      n = new_btree_node(c);

      if (n == NULL)
        {
          c->e = SSH_REGEX_OUT_OF_MEMORY;
          return FALSE;
        }

      n->type = SSH_REX_CONCATENATION;
      n->right = POP();
      n->left = POP();
      PUSH(n);
    }
  /* the loop above does not break */

  /* Label must exist because `PUSH' could jump there.  But actually it
     doesn't, because we POP two times and PUSH only once, and the memory
     allocated for the stack never decreases. */
 cleanup_and_barf:
  SSH_NOTREACHED;
  return FALSE;
}

/*********************************************************** Actual parsing. */

typedef struct {
  SshRexParseEntity t;
  const unsigned char *literal_data;
  size_t data_len;
  SshRexCharset charset;
  SshRexNFA nfa;
  int range_min, range_max; /* for {n, m}. n or m is set to -1 if not given */
} SshRexToken;

typedef enum {
  SSH_REX_PARSE_MAIN, SSH_REX_PARSE_ESCAPE, SSH_REX_PARSE_CHARSET,
  SSH_REX_PARSE_ALL_LITERAL
} SshRexParseMode;

static const unsigned char all_chars[256] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,

  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,

  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,

  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,

  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,

  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,

  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,

  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,

  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,

  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,

  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,

  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,

  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,

  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,

  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static Boolean get_compound_entity(SshRegexContext c,
                                   const unsigned char **ptr,
                                   SshRexToken *token,
                                   const SshRexParseMap *map)
{
  const SshRexCompoundEntity *compounds;
  SshRexParseEntity e;
  int l;

  compounds = map->compounds;

  while (compounds->string != NULL)
    {
      l = strlen(compounds->string);
      if (!strncmp(compounds->string, (char *)(*ptr), l))
        {
          /* Accept a sequence of characters as a compound character
             entity. Works only in the main mode. */
          e = compounds->entity;
          token->literal_data = (*ptr);
          token->data_len = l;
          (*ptr) += l;
          token->t = e;
          return TRUE;
        }
      compounds++;
    }
  return FALSE;
}

static void get_numeric_literal_token(SshRegexContext c,
                                      const unsigned char **ptr,
                                      SshRexToken *token,
                                      int base)
{
  long l;
  const unsigned char *orig = *ptr;
  l = strtol((char *)*ptr, (char **)ptr, base);
  if (*ptr == orig || l < 0 || l > 255)
    {
      token->t = SSH_REX_P_ERROR;
      return;
    }
  token->t = SSH_REX_P_LITERAL;
  token->literal_data = &(all_chars[l]);
  token->data_len = 1;
}

/* Forward declaration because get_charset_token and
   get_next_token are mutually recursive, at least in theory. */
static void get_next_token(SshRegexContext c,
                           const unsigned char **ptr,
                           SshRexToken *token,
                           const SshRexParseMap *map,
                           SshRexParseMode mode);

static void get_range_token(SshRegexContext c,
                            const unsigned char **ptr,
                            SshRexToken *token,
                            const SshRexParseMap *map)
{
  long lmin, lmax;
  SshRexToken mytoken;

  lmin = strtol((char *)*ptr, (char **)ptr, 0);

  if (lmin < 0 || lmin > SSH_REX_MAX_REPEATS) goto barf;
  if (lmin == 0) lmin = -1;
  if ((**ptr) != ',') { lmax = lmin; goto perhaps_one_item; }
  (*ptr)++;

  lmax = strtol((char *)*ptr, (char **)ptr, 0);
  if ((lmax != 0 && lmax < lmin) || lmax > SSH_REX_MAX_REPEATS) goto barf;
  if (lmax == 0) lmax = -1;

 perhaps_one_item:

  if (!get_compound_entity(c, ptr, &mytoken, map))
    {
      mytoken.t = map->std_map[(*ptr)[0]];
      (*ptr)++;
    }
  if (mytoken.t == SSH_REX_P_END_RANGE_LAZY)
    token->t = SSH_REX_P_RANGE_LAZY;
  else if (mytoken.t == SSH_REX_P_END_RANGE ||
           mytoken.t == SSH_REX_P_START_END_RANGE)
    token->t = SSH_REX_P_RANGE;
  else goto barf;

  token->range_min = lmin;
  token->range_max = lmax;

  return;

 barf:
  token->t = SSH_REX_P_ERROR;
}

#define POSIX_CSET(name, length, field)                                       \
if ((!strncmp((char *)p + 1, name, length))                                   \
    &&                                                                        \
    p[length + 1] == ':'                                                      \
    &&                                                                        \
    p[length + 2] == ']')                                                     \
{                                                                             \
  *ptr = p + length + 3;                                                      \
  SSH_REX_CSET_COPY(cset, c->field);                                          \
  return TRUE;                                                                \
}

static Boolean get_posix_charset(SshRegexContext c,
                                 const unsigned char **ptr,
                                 SshRexCharset cset)
{
  const unsigned char *p = *ptr;
  if (p[0] != ':') return FALSE;

  POSIX_CSET("alnum",  5, posix_alnum);
  POSIX_CSET("alpha",  5, posix_alpha);
  POSIX_CSET("cntrl",  5, posix_cntrl);
  POSIX_CSET("digit",  5, posix_digit);
  POSIX_CSET("graph",  5, posix_graph);
  POSIX_CSET("lower",  5, posix_lower);
  POSIX_CSET("print",  5, posix_print);
  POSIX_CSET("punct",  5, posix_punct);
  POSIX_CSET("space",  5, posix_space);
  POSIX_CSET("upper",  5, posix_upper);
  POSIX_CSET("xdigit", 6, posix_xdigit);

  return FALSE;
}

static void get_charset_token(SshRegexContext c,
                              const unsigned char **ptr,
                              SshRexToken *token,
                              const SshRexParseMap *map)
{
  SshRexToken mytoken;
  Boolean adding = TRUE;
  Boolean at_start = TRUE;
  Boolean prev_at_start = TRUE;
  Boolean complement_finally = FALSE;
  unsigned char last_literal = 0;
  Boolean last_literal_valid = FALSE;
  Boolean ranging = FALSE;
  unsigned int ch;
  SshRexCharset cset;

  SSH_REX_CSET_ZERO(token->charset);
  while (1)
    {
      get_next_token(c, ptr, &mytoken, map, SSH_REX_PARSE_CHARSET);

      switch (mytoken.t)
        {
        case SSH_REX_P_LITERAL:
        literal:
          if (mytoken.data_len != 1)
            goto error;

          if ((map->flags & SSH_REX_PARSE_FLAG_POSIX_CHARSETS) &&
              mytoken.literal_data[0] == '[')
            {
              if (get_posix_charset(c, ptr, cset))
                {
                  if (ranging) goto error;
                  last_literal_valid = FALSE;
                  if (adding)
                    {
                      SSH_REX_CSET_OR(token->charset, cset);
                    }
                  else
                    {
                      SSH_REX_CSET_COMPLEMENT(cset);
                      SSH_REX_CSET_AND(token->charset, cset);
                    }
                  break;
                }
            }

          if (ranging)
            {
              for (ch = last_literal; ch <= mytoken.literal_data[0]; ch++)
                {
                  if (adding)
                    SSH_REX_CSET_SET(token->charset, ch);
                  else
                    SSH_REX_CSET_CLEAR(token->charset, ch);
                }
              ranging = FALSE;
              last_literal_valid = FALSE;
              break;
            }

          last_literal_valid = TRUE;
          last_literal = mytoken.literal_data[0];
          if (adding)
            SSH_REX_CSET_SET(token->charset, last_literal);
          else
            SSH_REX_CSET_CLEAR(token->charset, last_literal);
          break;

        case SSH_REX_P_CHARSET:
          if (ranging) goto error;
          last_literal_valid = FALSE;
          if (adding)
            {
              SSH_REX_CSET_OR(token->charset, mytoken.charset);
            }
          else
            {
              SSH_REX_CSET_COMPLEMENT(mytoken.charset);
              SSH_REX_CSET_AND(token->charset, mytoken.charset);
            }
          break;

        case SSH_REX_P_CHARSET_POSITIVE:
          if (ranging) goto error;
          last_literal_valid = FALSE;
          adding = TRUE;
          break;

        case SSH_REX_P_CHARSET_NEGATIVE:
          if (ranging) goto error;
          last_literal_valid = FALSE;
          adding = FALSE;
          if (at_start)
            SSH_REX_CSET_FILL(token->charset);
          break;

        case SSH_REX_P_CHARSET_COMPLEMENT_IF_FIRST:
          if (at_start) complement_finally = TRUE;
          else goto literal;
          break;

        case SSH_REX_P_CHARSET_RANGE:
          if (at_start) goto literal;
          if (prev_at_start && complement_finally) goto literal;
          if ((!last_literal_valid) || ranging) goto error;
          ranging = TRUE;
          break;

        case SSH_REX_P_CHARSET_END:
          if (at_start)
            goto literal;
          goto done;

        default:
          goto error;
        }
      prev_at_start = at_start;
      at_start = FALSE;
    }

 done:
  if (complement_finally)
    SSH_REX_CSET_COMPLEMENT(token->charset);
  token->t = SSH_REX_P_CHARSET;
  return;

 error:
  token->t = SSH_REX_P_ERROR;
  return;
}

#define LITERAL(x)                                                            \
token->t = SSH_REX_P_LITERAL;                                                 \
token->literal_data = (unsigned char *)x;                                     \
token->data_len = strlen(x)

#define PDC(x)                                                                \
token->t = SSH_REX_P_CHARSET;                                                 \
memcpy(token->charset, c->x ## _chars, sizeof(token->charset))

#define NFA(x)                                                                \
token->t = SSH_REX_P_NFA;                                                     \
token->nfa = c->x

static void get_next_token(SshRegexContext c,
                           const unsigned char **ptr,
                           SshRexToken *token,
                           const SshRexParseMap *map,
                           SshRexParseMode mode)
{
  const unsigned char *d = *ptr;
  SshRexParseEntity e;
  const SshRexParseEntity *table = NULL;

  SSH_DEBUG(8, ("Reading next token, mode=%d str=`%.5s'.",
                mode, d));

  switch (mode)
    {
      case SSH_REX_PARSE_MAIN: table = map->std_map; break;
      case SSH_REX_PARSE_ESCAPE: table = map->escape_map; break;
      case SSH_REX_PARSE_CHARSET: table = map->charset_map; break;

    default:
      SSH_ASSERT(mode == SSH_REX_PARSE_ALL_LITERAL);
      break;
    }

  if (mode == SSH_REX_PARSE_ALL_LITERAL)
    {
      e = SSH_REX_P_LITERAL;
    }
  else
    {
      if (mode == SSH_REX_PARSE_MAIN)
        {
          if (get_compound_entity(c, ptr, token, map))
            goto got_entity;
        }
      e = table[*d];
    }

  /* Accepted a single character as a parse entity. */

  (*ptr)++;

  token->literal_data = d;
  token->data_len = 1;
  token->t = e;

 got_entity:

  e = token->t;
  SSH_DEBUG(8, ("Syntax class=%d.", e));

  switch (e)
    {
    case SSH_REX_P_START_RANGE:
    case SSH_REX_P_START_END_RANGE:
      get_range_token(c, ptr, token, map);
      break;

    case SSH_REX_P_ESCAPE:
      get_next_token(c, ptr, token, map, SSH_REX_PARSE_ESCAPE);
      break;

    case SSH_REX_P_CHARSET_START:
      get_charset_token(c, ptr, token, map);
      break;

    case SSH_REX_P_NUMERIC_LITERAL:
      /* We need to read the starting digit again. */
      (*ptr)--;
      get_numeric_literal_token(c, ptr, token, 0);
      break;

    case SSH_REX_P_HEX_LITERAL:
      get_numeric_literal_token(c, ptr, token, 16);
      break;

    case SSH_REX_P_LOOKAHEAD:
    case SSH_REX_P_LOOKBACK:
      {
        SshRexToken newtoken;
        get_next_token(c, ptr, &newtoken, map, mode);
        if (newtoken.t != SSH_REX_P_CHARSET)
          {
            SSH_DEBUG(7, ("Not a charset after lookahead/back."));
            token->t = SSH_REX_P_ERROR;
            return;
          }
        memcpy(token->charset, newtoken.charset, sizeof(token->charset));
        break;
      }

    case SSH_REX_P_LITERAL_TAB:       LITERAL("\t"); break;
    case SSH_REX_P_LITERAL_NEWLINE:   LITERAL("\n"); break;
    case SSH_REX_P_LITERAL_RETURN:    LITERAL("\r"); break;
    case SSH_REX_P_LITERAL_LINE_FEED: LITERAL("\f"); break;
    case SSH_REX_P_LITERAL_ALARM:     LITERAL("\a"); break;
    case SSH_REX_P_LITERAL_ESCAPE:    LITERAL("\033"); break;

    case SSH_REX_P_PDC_WORD:          PDC(word); break;
    case SSH_REX_P_PDC_NWORD:         PDC(nword); break;
    case SSH_REX_P_PDC_WHITESPACE:    PDC(whitespace); break;
    case SSH_REX_P_PDC_NWHITESPACE:   PDC(nwhitespace); break;
    case SSH_REX_P_PDC_DIGIT:         PDC(digit); break;
    case SSH_REX_P_PDC_NDIGIT:        PDC(ndigit); break;
    case SSH_REX_P_PDC_NOT_NEWLINE:   PDC(not_newline); break;

    case SSH_REX_P_PCNFA_WORD_BOUNDARY:  NFA(word_boundary); break;
    case SSH_REX_P_PCNFA_NWORD_BOUNDARY: NFA(word_nonboundary); break;
    case SSH_REX_P_PCNFA_WORD_START:     NFA(word_start); break;
    case SSH_REX_P_PCNFA_WORD_END:       NFA(word_end); break;
    case SSH_REX_P_PCNFA_LINE_START:     NFA(line_start); break;
    case SSH_REX_P_PCNFA_LINE_END:       NFA(line_end); break;
    case SSH_REX_P_PCNFA_ZSH_STAR_STAR:   NFA(zsh_star_star); break;
    case SSH_REX_P_PCNFA_ZSH_STAR:       NFA(zsh_star); break;
    case SSH_REX_P_PCNFA_ZSH_QUESTION_MARK: NFA(zsh_qmark); break;

    default:
      break;
    }
  return;
}

#undef LITERAL
#undef PDC
#undef NFA

#define PARSE_ERROR                                                           \
do { c->e = SSH_REGEX_PARSE_ERROR; goto cleanup_and_barf; } while (0)

#define FAIL_COMPILE                                                          \
do { SSH_ASSERT(c->e != SSH_REGEX_OK); goto cleanup_and_barf; } while (0)

#define COMPILE_NO_MEMORY                                                     \
do { c->e = SSH_REGEX_OUT_OF_MEMORY; goto cleanup_and_barf; } while (0)

#define NEWNODE(n)                                                            \
do                                                                            \
{                                                                             \
  n = new_btree_node(c);                                                      \
  if (n == NULL) COMPILE_NO_MEMORY;                                           \
}                                                                             \
while (0)

#define NEWNODE3(n, m, o)                                                     \
do                                                                            \
{                                                                             \
  n = new_btree_node(c);                                                      \
  m = new_btree_node(c);                                                      \
  o = new_btree_node(c);                                                      \
  if (n == NULL || m == NULL || o == NULL)                                    \
    {                                                                         \
      if (n != NULL) FREE_TREE_NODE(c, n);                                    \
      if (m != NULL) FREE_TREE_NODE(c, m);                                    \
      if (o != NULL) FREE_TREE_NODE(c, o);                                    \
      COMPILE_NO_MEMORY;                                                      \
    }                                                                         \
}                                                                             \
while (0)

#define UNARYOP(nodetype)                                                     \
do                                                                            \
{                                                                             \
  type = nodetype;                                                            \
  goto generic_unary_op;                                                      \
}                                                                             \
while (0)

static SshRexNFA compile_nfa(SshRegexContext c,
                             const unsigned char *regex,
                             const SshRexParseMap *map,
                             int *num_subexprs_return,
                             Boolean is_final)
{
  SshRexBTreeNode n, n2, n3;
  int subexpr_number = 0;
  SshRexToken token;
  SshRexNFA nfa;
  SshRexMatchType type;
  unsigned char *literal_data = NULL;

  SSH_DEBUG(7, ("Starting to preparse the regex `%s'.", regex));

  while (1)
    {
      SSH_DEBUG(8, (": %s", regex));
#ifdef SSH_REX_DEBUG
      dump_stack(c);
#endif
      get_next_token(c, &regex, &token, map, SSH_REX_PARSE_MAIN);
      if (token.t == SSH_REX_P_ERROR) PARSE_ERROR;

      switch (token.t)
        {
        case SSH_REX_P_STAR:
          type = SSH_REX_STAR;

        generic_unary_op:
          if (c->pc.in_stack == 0) PARSE_ERROR;

          /* If the previous object is a literal whose length is greater than
             one, must split it into two parts because the unary operators *, +
             etc. have higher precedence than catenation. */
          if (STACKREF(0)->type == SSH_REX_LITERAL &&
              STACKREF(0)->u.literal.data_len > 1)
            {
              literal_data = ssh_malloc(1);

              if (literal_data == NULL) COMPILE_NO_MEMORY;

              NEWNODE3(n, n2, n3);

              n->type = SSH_REX_LITERAL;
              n->u.literal.data = literal_data;
              literal_data = NULL;
              n->u.literal.data[0] =
                STACKREF(0)->u.literal.data[STACKREF(0)->u.literal.data_len
                                           - 1];

              n->u.literal.data_len = 1;

              STACKREF(0)->u.literal.data_len--;

              n3->type = type;
              n3->left = n;

              n2->type = SSH_REX_CONCATENATION;
              n2->left = STACKREF(0);
              n2->right = n3;
              DISCARD();
              PUSH(n2);
            }
          else
            {
              NEWNODE(n3);
              n3->type = type;
              n3->left = POP(); PUSH(n3);
            }
          break;

        case SSH_REX_P_PLUS:
          UNARYOP(SSH_REX_PLUS); break;

        case SSH_REX_P_OPTIONAL:
          UNARYOP(SSH_REX_OPTIONAL); break;

        case SSH_REX_P_STAR_LAZY:
          UNARYOP(SSH_REX_LAZY_STAR); break;

        case SSH_REX_P_PLUS_LAZY:
          UNARYOP(SSH_REX_LAZY_PLUS); break;

        case SSH_REX_P_OPTIONAL_LAZY:
          UNARYOP(SSH_REX_LAZY_OPTIONAL); break;

        case SSH_REX_P_ANY:
          NEWNODE(n);
          n->type = SSH_REX_ANY; PUSH(n);
          break;

        case SSH_REX_P_RANGE:
        case SSH_REX_P_RANGE_LAZY:
          if (token.t == SSH_REX_P_RANGE)
            type = SSH_REX_RANGE;
          else
            type = SSH_REX_LAZY_RANGE;

          /* If the previous object is a literal whose length is greater than
             one, must split it into two parts because the unary operators *, +
             etc. have higher precedence than catenation. */
          if (STACKREF(0)->type == SSH_REX_LITERAL &&
              STACKREF(0)->u.literal.data_len > 1)
            {
              literal_data = ssh_malloc(1);

              if (literal_data == NULL) COMPILE_NO_MEMORY;

              NEWNODE3(n, n2, n3);

              n->type = SSH_REX_LITERAL;
              n->u.literal.data = literal_data;
              literal_data = NULL;
              n->u.literal.data[0] =
                STACKREF(0)->u.literal.data[STACKREF(0)->u.literal.data_len
                                           - 1];

              n->u.literal.data_len = 1;

              STACKREF(0)->u.literal.data_len--;

              n3->type = type;
              n3->left = n;

              n2->type = SSH_REX_CONCATENATION;
              n2->left = STACKREF(0);
              n2->right = n3;

              DISCARD();
              PUSH(n2);
            }
          else
            {
              NEWNODE(n3);
              n3->type = type;
              n3->left = POP(); PUSH(n3);
            }

          /* Set the ranges. */
          n3->u.range.range_min = token.range_min;
          n3->u.range.range_max = token.range_max;
          SSH_DEBUG(8, ("Ranges %d %d.", token.range_min, token.range_max));
          break;

        case SSH_REX_P_DISJUNCT:
          if (c->pc.in_stack == 0) PARSE_ERROR;
          if (!collapse_stack(c)) FAIL_COMPILE;
          NEWNODE(n);
          n->type = SSH_REX_DISJUNCT;
          n->left = POP();
          PUSH(n);
          break;

        case SSH_REX_P_START_SUBEXPR:
          subexpr_number++;
          NEWNODE(n);
          n->type = SSH_REX_START_SUBEXPR;
          n->u.subexpr = subexpr_number;
          PUSH(n); break;

        case SSH_REX_P_END_SUBEXPR:
          if (!collapse_stack(c)) FAIL_COMPILE;
          if (c->pc.in_stack < 2) PARSE_ERROR;
          if (STACKREF(1)->type != SSH_REX_START_SUBEXPR) PARSE_ERROR;
          NEWNODE(n);
          n->type = SSH_REX_SUBEXPR;
          n->u.subexpr = STACKREF(1)->u.subexpr;
          n->left = STACKREF(0);
          DISCARD();
          delete_btree_node(c, STACKREF(0));
          DISCARD();
          PUSH(n);
          break;

        case SSH_REX_P_START_ANON_SUBEXPR:
          NEWNODE(n);
          n->type = SSH_REX_START_ANON_SUBEXPR;
          PUSH(n);
          break;

        case SSH_REX_P_END_ANON_SUBEXPR:
          if (!collapse_stack(c)) FAIL_COMPILE;
          if (c->pc.in_stack < 2) PARSE_ERROR;
          if (STACKREF(1)->type != SSH_REX_START_ANON_SUBEXPR) PARSE_ERROR;
          n = STACKREF(0);
          DISCARD();
          delete_btree_node(c, STACKREF(0));
          DISCARD();
          NEWNODE(n2);
          n2->type = SSH_REX_ANON_SUBEXPR;
          n2->left = n;
          PUSH(n2);
          break;

        case SSH_REX_P_CHARSET:
          NEWNODE(n);
          n->type = SSH_REX_CHAR_SET;
          PUSH(n);
          memcpy(n->u.charset, token.charset, sizeof(n->u.charset));
          break;

        case SSH_REX_P_LOOKAHEAD:
          NEWNODE(n);
          n->type = SSH_REX_LOOKAHEAD;
          PUSH(n);
          memcpy(n->u.charset, token.charset, sizeof(n->u.charset));
          break;

        case SSH_REX_P_LOOKBACK:
          NEWNODE(n);
          n->type = SSH_REX_LOOKBACK;
          PUSH(n);
          memcpy(n->u.charset, token.charset, sizeof(n->u.charset));
          break;

        case SSH_REX_P_BEGINNING:
          NEWNODE(n);
          n->type = SSH_REX_BEGINNING;
          PUSH(n);
          break;

        case SSH_REX_P_END:
          NEWNODE(n);
          n->type = SSH_REX_END;
          PUSH(n);
          break;

        case SSH_REX_P_LITERAL:
          if (c->pc.in_stack > 0)
            {
              if (STACKREF(0)->type == SSH_REX_LITERAL)
                {
                  if (!add_to_literal(&(STACKREF(0)->u.literal),
                                      token.literal_data,
                                      token.data_len))
                    COMPILE_NO_MEMORY;
                  break;
                }
            }

          literal_data = ssh_malloc(token.data_len);
          if (literal_data == NULL) COMPILE_NO_MEMORY;

          NEWNODE(n);
          n->type = SSH_REX_LITERAL;
          n->u.literal.data_len = token.data_len;
          n->u.literal.data = literal_data;
          literal_data = NULL;
          memcpy(n->u.literal.data, token.literal_data, token.data_len);
          PUSH(n);
          break;

        case SSH_REX_P_NFA:
          NEWNODE(n);
          n->type = SSH_REX_SUB_NFA;
          n->u.sub_nfa = token.nfa;
          PUSH(n);
          break;

        case SSH_REX_P_EOI:
          goto end_of_input;

        default:
          FAIL_COMPILE;
        }
    }

 end_of_input:

  if (!collapse_stack(c)) FAIL_COMPILE;
  if (c->pc.in_stack != 1) PARSE_ERROR;

#ifdef SSH_REX_DEBUG
  dump_btree(STACKREF(0));
  fprintf(stderr, "\n");
#endif

  nfa = ssh_malloc(sizeof(*nfa));

  if (nfa == NULL)
    {
      COMPILE_NO_MEMORY;
    }

  nfa->nodes_array = NULL;
  nfa->num_nodes = 0;
  nfa->array_size = 0;
  nfa->first = NULL;
  nfa->accept = NULL;

  /* If this is not the top-level regex then there should not be any referable
     subexpressions because they will confuse the subexpression numbering of
     the user-supplied regex.  However, because the compile_partial_nfa is
     nowadays also used for creating the dynamic lexers, the following
     assertion must be commented out: */

  /* SSH_ASSERT(is_final || subexpr_number == 0); */

  if (!construct_nfa(c, nfa, STACKREF(0),
                     &(nfa->first),
                     &(nfa->accept)))
    {
      destroy_nfa(c, nfa);
      COMPILE_NO_MEMORY;
    }

  if (is_final)
    {
      SshRexNFANode old_accept;
      SshRexNFANode disjunct, anychar, subexpr_start, new_accept;
      SshRexNFANode end_anchor, start_anchor;

      *num_subexprs_return = subexpr_number + 1;

      old_accept = nfa->accept;

      if (map->flags & SSH_REX_PARSE_FLAG_ALWAYS_ANCHOR)
        {
          /* Wrap R ==> ^(R)$ */
          end_anchor    = new_nfa_node(c, nfa);
          subexpr_start = new_nfa_node(c, nfa);
          new_accept    = new_nfa_node(c, nfa);
          start_anchor  = new_nfa_node(c, nfa);

          if (end_anchor == NULL
              || subexpr_start == NULL
              || new_accept == NULL
              || start_anchor == NULL)
            {
              destroy_nfa(c, nfa);
              c->e = SSH_REGEX_OUT_OF_MEMORY;
              FAIL_COMPILE;
            }


          end_anchor->type = SSH_REX_END;
          start_anchor->type = SSH_REX_BEGINNING;
          subexpr_start->type = SSH_REX_START_SUBEXPR;
          subexpr_start->u.subexpr = 0;
          new_accept->type = SSH_REX_ACCEPT;

          old_accept->type = SSH_REX_END_SUBEXPR;
          old_accept->u.subexpr = 0;

          start_anchor->next = subexpr_start;
          subexpr_start->next = nfa->first;
          old_accept->next = end_anchor;
          end_anchor->next = new_accept;

          nfa->first = start_anchor;
          nfa->accept = new_accept;
        }
      else
        {
          /* Wrap R ==> .*(R) where the subexpr is subexpr 0 */

          disjunct = new_nfa_node(c, nfa);
          anychar = new_nfa_node(c, nfa);
          subexpr_start = new_nfa_node(c, nfa);
          new_accept = new_nfa_node(c, nfa);

          if (disjunct == NULL
              || anychar == NULL
              || subexpr_start == NULL
              || new_accept == NULL)
            {
              destroy_nfa(c, nfa);
              c->e = SSH_REGEX_OUT_OF_MEMORY;
              FAIL_COMPILE;
            }

          disjunct->type = SSH_REX_DISJUNCT;
          disjunct->next = subexpr_start;
          disjunct->u.disjunct.second = anychar;

          anychar->type = SSH_REX_ANY;
          anychar->next = disjunct;

          subexpr_start->type = SSH_REX_START_SUBEXPR;
          subexpr_start->u.subexpr = 0;
          subexpr_start->next = nfa->first;

          nfa->first = disjunct;

          old_accept->type = SSH_REX_END_SUBEXPR;
          old_accept->u.subexpr = 0;
          old_accept->next = new_accept;

          new_accept->type = SSH_REX_ACCEPT;
          new_accept->next = NULL;

          nfa->accept = new_accept;
        }

#ifdef SSH_REX_DEBUG
      dump_nfa(nfa);
#endif

      streamline_nfa(c, nfa, nfa->first);

      if (!shrink_nodes_array(c, nfa))
        {
          destroy_nfa(c, nfa);
          goto cleanup_and_barf;
        }

      if (!calculate_transition_charsets(c, nfa))
        {
          SSH_DEBUG(5, ("Semantically invalid regular expression."));
#ifdef SSH_REX_DEBUG
          dump_nfa(nfa);
#endif
          c->e = SSH_REGEX_SEMANTIC_ERROR;
          destroy_nfa(c, nfa);
          FAIL_COMPILE;
        }
      calculate_anchor_hints(c, nfa);
    }
  else
    {
      /* Do this in any case. */
      streamline_nfa(c, nfa, nfa->first);

      if (!shrink_nodes_array(c, nfa))
        {
          destroy_nfa(c, nfa);
          goto cleanup_and_barf;
        }
    }

#ifdef SSH_REX_DEBUG
  dump_nfa(nfa);
#endif

  delete_btree(c, STACKREF(0));

  c->pc.in_stack = 0;

#ifdef SSH_REX_DEBUG
  fprintf(stderr, "Returning %p\n", nfa);
#endif

  return nfa;

 cleanup_and_barf:
  SSH_DEBUG(7, ("Failed to compile."));

  {
    int i;
    for (i = 0; i < c->pc.in_stack; i++)
      {
        delete_btree(c, STACKREF(i));
      }
    c->pc.in_stack = 0;

#ifdef SSH_REX_DEBUG
    fprintf(stderr, "Returning NULL.\n");
#endif

    if (literal_data != NULL)
      ssh_free(literal_data);

    return NULL;
  }
}

static SshRexNFA compile_full_nfa(SshRegexContext c,
                                  const char *regex,
                                  const SshRexParseMap *map,
                                  int *num_subexprs_ret)
{
  return compile_nfa(c, (unsigned char *)regex, map, num_subexprs_ret, TRUE);
}

static SshRexNFA compile_partial_nfa(SshRegexContext c,
                                     const char *regex,
                                     const SshRexParseMap *map)
{
  return compile_nfa(c, (unsigned char *)regex, map, NULL, FALSE);
}

/************************ Main interface for compiling regexs and matching. */

/* Create a compiled regular expression. Return a matcher or NULL if
   compilation fails due to (1) unknown syntax, (2) syntactically
   invalid regex or (3) semantically invalid regex. */

const SshRexParseMap *ssh_regex_map_by_syntax(SshRegexSyntax syntax)
{
  switch (syntax)
    {
    case SSH_REGEX_SYNTAX_SSH:
      return &syntax_ssh;

    case SSH_REGEX_SYNTAX_EGREP:
      return &syntax_egrep;

    case SSH_REGEX_SYNTAX_ZSH_FILEGLOB:
      return &syntax_zsh;

    default:
      ssh_fatal("Unknown regular expression syntax %d.",
                  syntax);
      return NULL;
    }
}

/* If this procedure runs out of memory, `nfa' is freed when the
   procedure returns. */
SshRegexMatcher ssh_regex_wrap_nfa(SshRegexContext c,
                                   SshRexNFA nfa,
                                   int num_subexprs)
{
  SshRegexMatcher m;

  m = ssh_malloc(sizeof(*m));

  if (m == NULL)
    {
      destroy_nfa(c, nfa);
      c->e = SSH_REGEX_OUT_OF_MEMORY;
      return NULL;
    }

  m->e = SSH_REGEX_OK;
  m->g = c;
  m->nfa = nfa;
  m->num_matches = num_subexprs;
  m->matches = ssh_malloc(sizeof(m->matches[0]) * num_subexprs);

  if (m->matches == NULL)
    {
      ssh_free(m);
      destroy_nfa(c, nfa);
      c->e = SSH_REGEX_OUT_OF_MEMORY;
      return NULL;
    }

  init_matches(m);

  m->submatch_bitmask_allocator =
    ssh_fastalloc_initialize(SSH_REX_BITMASK_BYTES(num_subexprs), 20);

  if (m->submatch_bitmask_allocator == NULL)
    {
      ssh_free(m->matches);
      ssh_free(m);
      destroy_nfa(c, nfa);
      c->e = SSH_REGEX_OUT_OF_MEMORY;
      return NULL;
    }

  return m;
}

SshRegexMatcher ssh_regex_create(SshRegexContext c,
                                 const char *regex,
                                 SshRegexSyntax syntax)
{
  const SshRexParseMap *map;
  SshRexNFA nfa;
  int num_subexprs;

  c->e = SSH_REGEX_OK;
  map = ssh_regex_map_by_syntax(syntax);
  nfa = compile_full_nfa(c, regex, map, &num_subexprs);

  if (nfa == NULL)
    {
      SSH_DEBUG(5, ("Compiling regex `%s' failed.", regex));
      SSH_ASSERT(c->e != SSH_REGEX_OK);
      return NULL;
    }

  /* `ssh_regex_wrap_nfa' can return NULL if memory runs out.  In that case
     `nfa' is freed automatically. */
  return ssh_regex_wrap_nfa(c, nfa, num_subexprs);
}

void ssh_regex_free(SshRegexMatcher m)
{
  int i;
  destroy_nfa(m->g, m->nfa);
  for (i = 0; i < m->num_matches; i++)
    {
      ssh_free(m->matches[i].dupped);
    }
  ssh_free(m->matches);
  ssh_fastalloc_uninitialize(m->submatch_bitmask_allocator);
  ssh_free(m);
}

/*********************************************** Actual matching interfaces. */

#define MATCH_PROC nb_match

Boolean ssh_regex_match_cstr(SshRegexMatcher matcher, const char *data)
{
  size_t len = strlen(data);

  return MATCH_PROC(matcher, (unsigned char *)data, len, 0);
}

Boolean ssh_regex_match_cstr_prefix(SshRegexMatcher matcher,
                                    const char *data)
{
  size_t len = strlen(data);

  return MATCH_PROC(matcher, (unsigned char *)data, len,
                    SSH_REX_ACCEPT_PREFIX);
}

Boolean ssh_regex_match(SshRegexMatcher matcher,
                        const unsigned char *data,
                        size_t data_len)
{
  return MATCH_PROC(matcher, data, data_len, 0);
}

Boolean ssh_regex_match_buffer(SshRegexMatcher matcher, SshBuffer buffer)
{
  return MATCH_PROC(matcher, ssh_buffer_ptr(buffer),
                    ssh_buffer_len(buffer), 0);
}

/****************************************************** Accessing submatches */

int ssh_regex_n_subexpressions(SshRegexMatcher m)
{
  return m->num_matches;
}

Boolean ssh_regex_access_submatch(SshRegexMatcher m,
                                  int subexpr_num,
                                  int *index,
                                  size_t *match_len)
{
  if (subexpr_num < 0 || subexpr_num >= m->num_matches ||
      m->matches[subexpr_num].from == NULL)
    {
      return FALSE;
    }
  *index = (int) (m->matches[subexpr_num].from - m->text);
  *match_len = m->matches[subexpr_num].limit -
    m->matches[subexpr_num].from;
  return TRUE;
}

unsigned char *ssh_regex_get_submatch(SshRegexMatcher m,
                                      int subexpr_num)
{
  size_t len;
  if (subexpr_num < 0 || subexpr_num >= m->num_matches ||
      m->matches[subexpr_num].from == NULL)
    return NULL;

  if (m->matches[subexpr_num].dupped != NULL)
    return m->matches[subexpr_num].dupped;

  len = m->matches[subexpr_num].limit - m->matches[subexpr_num].from;

  m->matches[subexpr_num].dupped =
    ssh_malloc(len + 1);

  if (m->matches[subexpr_num].dupped == NULL) return NULL; /* OUT OF MEMORY */

  memcpy(m->matches[subexpr_num].dupped, m->matches[subexpr_num].from, len);

  m->matches[subexpr_num].dupped[len] = '\0';
  return m->matches[subexpr_num].dupped;
}

Boolean ssh_regex_submatch_exists(SshRegexMatcher m,
                                  int subexpr_num)
{
  if (subexpr_num < 0 || subexpr_num >= m->num_matches ||
      m->matches[subexpr_num].from == NULL)
    return FALSE;

  return TRUE;
}

/************************************************************ Global context */

/* Create a global regular expression matching context. This
   initializes the fast allocators and creates some predefined
   charsets and NFA fragments. */

#define SSH_REX_CTYPE_CSET(cset, macro)                                       \
do                                                                            \
{                                                                             \
  int __c;                                                                    \
  SSH_REX_CSET_ZERO(cset);                                                    \
  for (__c = 0; __c < 256; __c++)                                             \
    {                                                                         \
      if (macro(__c)) SSH_REX_CSET_SET(cset, __c);                            \
    }                                                                         \
}                                                                             \
while (0)

SshRegexContext ssh_regex_create_context(void)
{
  SshRegexContext c;
  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL) return NULL;

  /* Initialize the parsing context. */
  c->e = SSH_REGEX_OK;
  c->pc.stack = NULL;
  c->pc.in_stack = 0;
  c->pc.stack_allocated = 0;

  c->nfa_node_allocator =
    ssh_fastalloc_initialize(sizeof(SshRexNFANodeRec), 100);

  c->thread_allocator =
    ssh_fastalloc_initialize(sizeof(SshRexThreadRec), 100);

  c->tree_allocator =
    ssh_fastalloc_initialize(sizeof(SshRexBTreeNodeRec), 100);

  c->subexpr_tree_allocator =
    ssh_fastalloc_initialize(sizeof(SshRexMatchTreeNodeRec), 100);

  if (c->nfa_node_allocator == NULL
      || c->thread_allocator == NULL
      || c->tree_allocator == NULL
      || c->subexpr_tree_allocator == NULL)
    {
      ssh_regex_free_context(c);
      return NULL;
    }

  /* Initialize character sets. This does not allocate any more memory. */
  set_cset_from_string(c->word_chars,
                       (unsigned char *)
                       "abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "0123456789"
                       "_");

  set_cset_from_string(c->digit_chars, (unsigned char *)"0123456789");
  set_cset_from_string(c->whitespace_chars, (unsigned char *)" \f\n\r\t\v");

  SSH_REX_CSET_COPY(c->nword_chars, c->word_chars);
  SSH_REX_CSET_COMPLEMENT(c->nword_chars);

  SSH_REX_CSET_COPY(c->ndigit_chars, c->digit_chars);
  SSH_REX_CSET_COMPLEMENT(c->ndigit_chars);

  SSH_REX_CSET_COPY(c->nwhitespace_chars, c->whitespace_chars);
  SSH_REX_CSET_COMPLEMENT(c->nwhitespace_chars);

  SSH_REX_CTYPE_CSET(c->posix_alnum, isalnum);
  SSH_REX_CTYPE_CSET(c->posix_alpha, isalpha);
  SSH_REX_CTYPE_CSET(c->posix_cntrl, iscntrl);
  SSH_REX_CTYPE_CSET(c->posix_digit, isdigit);
  SSH_REX_CTYPE_CSET(c->posix_graph, isgraph);
  SSH_REX_CTYPE_CSET(c->posix_lower, islower);
  SSH_REX_CTYPE_CSET(c->posix_print, isprint);
  SSH_REX_CTYPE_CSET(c->posix_punct, ispunct);
  SSH_REX_CTYPE_CSET(c->posix_space, isspace);
  SSH_REX_CTYPE_CSET(c->posix_upper, isupper);
  SSH_REX_CTYPE_CSET(c->posix_xdigit, isxdigit);

  set_cset_from_string(c->not_newline_chars, (unsigned char *)"\f\n\r");
  SSH_REX_CSET_COMPLEMENT(c->not_newline_chars);

  /* Do not accept the NUL byte either. */
  SSH_REX_CSET_CLEAR(c->not_newline_chars, 0);

  /* Precompile certain NFAs. PRECOMPILE_NFA can fail if memory runs out.  In
     that case just free the context that we are creating and return NULL. */

#define PRECOMPILE_NFA(variable, str)                                         \
do                                                                            \
  {                                                                           \
    c->variable = compile_partial_nfa(c, str, &syntax_ssh);                   \
    if (c->variable == NULL)                                                  \
      {                                                                       \
        ssh_regex_free_context(c);                                            \
        return NULL;                                                          \
      }                                                                       \
  }                                                                           \
while (0)

  /* Word boundary is matched when
     (1) at beginning, and next char is a word character,
     (2) at end, and the previous character is a word character,
     (3) the previous character is a non-word character and the next
         is a word character, or
     (4) vice versa.

     Empty string is not a word boundary, matching word boundary
     implies a non-zero length string. Therefore, no ^$ here. */
  PRECOMPILE_NFA(word_boundary,
                 "{^>~w}|{<~w$}|{<~W>~w}|{<~w>~W}");

  /* A word non-boundary is matched when
     (1) at beginning, and next char is not a word character,
     (2) at end, and the previous character is not a word character,
     (3) both the surrounding chars are non-word characters, or
     (4) both the surrounding chars are word characters. */
  PRECOMPILE_NFA(word_nonboundary,
                 "{<~w>~w}|{<~W>~W}|{^>~W}|{<~W$}");

  /* Word start: a word character preceded by a non-word character or
     string start. */
  PRECOMPILE_NFA(word_start, "{^|<~W}>~w");

  /* Word end: a word character followed by a non-word character or
     string end. */
  PRECOMPILE_NFA(word_end, "<~w{$|>~W}");

  /* Line start and end. */
  PRECOMPILE_NFA(line_start, "{^|<[~f~n~r]}");
  PRECOMPILE_NFA(line_end, "{$|>[~f~n~r]}");

  /* word_boundary and word_nonboundary are mutually exclusive, but
     the empty string "" matches neither of those. */

  /* Then `*' and `**' from ZSH, for the cases where the regexp
     utility is actually used for file globbing.

     Star matches either the empty string, or [^/]+ when the previous
     character is not / and we are not at the start of the string,
     or [^/.][^/]+ when the previous character is / or we are at the
     start of the string.

     Star star is as above, but accept slashes inside matched portion,
     however requiring that the last character matched after ** is slash.
     Can match also the empty string. */
  PRECOMPILE_NFA(zsh_star, "{{{{^|<[/]}[-./]}|{<[-/][-/]}}[-/]*}?");

  PRECOMPILE_NFA(zsh_star_star, "{{{{^|<[/]}[-.]}|{<[-/].}}*~/}?");

  /* The fileglob `?' matches anything except slash and not dot if the
     previous character is / or we are at the beginning of the string. */

  PRECOMPILE_NFA(zsh_qmark, "{{{^|<[/]}[-/.]}|{<[-/][-/]}}");

#undef PRECOMPILE_NFA

  return c;
}

/* Free a regular expression global context. This uninitializes the
   fast allocators and destroys the NFA fragments. */

void ssh_regex_free_context(SshRegexContext c)
{
  /* ssh_regex_free_context can be called from inside
     `ssh_regex_create_context' if memory runs out while compiling the
     precompiled NFAs. Therefore must take into account the possibility that
     some of the NFAs can be NULLs. */
  if (c->word_boundary != NULL) destroy_nfa(c, c->word_boundary);
  if (c->word_nonboundary != NULL) destroy_nfa(c, c->word_nonboundary);
  if (c->word_start != NULL) destroy_nfa(c, c->word_start);
  if (c->word_end != NULL) destroy_nfa(c, c->word_end);
  if (c->line_start != NULL) destroy_nfa(c, c->line_start);
  if (c->line_end != NULL) destroy_nfa(c, c->line_end);
  if (c->zsh_star != NULL) destroy_nfa(c, c->zsh_star);
  if (c->zsh_star_star != NULL) destroy_nfa(c, c->zsh_star_star);
  if (c->zsh_qmark != NULL) destroy_nfa(c, c->zsh_qmark);

  /* Similar considerations apply here. */
  if (c->nfa_node_allocator != NULL)
    ssh_fastalloc_uninitialize(c->nfa_node_allocator);

  if (c->thread_allocator != NULL)
    ssh_fastalloc_uninitialize(c->thread_allocator);

  if (c->tree_allocator != NULL)
    ssh_fastalloc_uninitialize(c->tree_allocator);

  if (c->subexpr_tree_allocator != NULL)
    ssh_fastalloc_uninitialize(c->subexpr_tree_allocator);

  ssh_free(c->pc.stack);
  ssh_free(c);
}

SshRegexError ssh_regex_get_compile_error(SshRegexContext c)
{
  return c->e;
}

SshRegexError ssh_regex_get_match_error(SshRegexMatcher m)
{
  return m->e;
}

/* Substitution. */
unsigned char *ssh_regex_compose(SshRegexMatcher matcher,
                                 SshRegexSubstitutionItem items,
                                 int num_items,
                                 size_t *length_return)
{
  int i;

  size_t total_len = 0;
  size_t match_len = 0;
  size_t str_len;

  const unsigned char *start;
  int start_index = 0;
  unsigned char *ptr;
  unsigned char *dst;

  SSH_PRECOND(matcher != NULL);
  SSH_PRECOND(items != NULL);
  SSH_PRECOND(num_items >= 0);
  SSH_PRECOND(length_return != NULL);

  /* First calculate the total length of the string that we must allocate. */
  for (i = 0; i < num_items; i++)
    {
      if (items[i].literal != NULL)
        {
          if (items[i].literal_len == 0)
            total_len += strlen((char *)items[i].literal);
          else
            total_len += items[i].literal_len;
        }
      else
        {
          ssh_regex_access_submatch(matcher, items[i].subexpr, &start_index,
                                    &match_len);
          start = matcher->text + start_index;
          if (start != NULL)
            {
              total_len += match_len;
            }
        }
    }

  dst = ssh_malloc(total_len + 1);

  if (dst == NULL) return NULL; /* OUT OF MEMORY */

  ptr = dst;

  for (i = 0; i < num_items; i++)
    {
      if (items[i].literal != NULL)
        {
          if (items[i].literal_len == 0)
            {
              str_len = strlen((char *)items[i].literal);
            }
          else
            {
              str_len = items[i].literal_len;
            }
          memcpy(dst, ptr, str_len);
          ptr += str_len;
        }
      else
        {
          ssh_regex_access_submatch(matcher, items[i].subexpr, &start_index,
                                     &match_len);
          start = matcher->text + start_index;
          if (start != NULL)
            {
              memcpy(ptr, start, match_len);
              ptr += match_len;
            }
        }
    }

  *ptr = 0;

  SSH_POSTCOND(ptr == dst + total_len);

  *length_return = total_len;

  return dst;
}

/***************************************** The dynamic lexer implementation. */

SshDLexer ssh_dlex_create(SshRegexContext c,
                          const char **regexs,
                          int n_regexs,
                          SshRegexSyntax syntax,
                          unsigned int flags)
{
  SshRexNFA *nfas;
  int i, j;
  const SshRexParseMap *map;
  SshRexNFA nfa;
  SshRexNFANode node;

  SSH_PRECOND(n_regexs > 0);

  SSH_ASSERT(flags & SSH_DLEX_FIRST_MATCH);

  map = ssh_regex_map_by_syntax(syntax);
  nfas = ssh_calloc(n_regexs, sizeof(*nfas));

  if (nfas == NULL) /* OUT OF MEMORY */
    return NULL;

  /* First compile all the regular expressions separately. */
  for (i = 0; i < n_regexs; i++)
    {
      nfas[i] = compile_partial_nfa(c, regexs[i], map);
      if (nfas[i] == NULL)
        {
          for (i--; i >= 0; i--)
            {
              destroy_nfa(c, nfas[i]);
            }
          ssh_free(nfas);
          return NULL;
        }
    }

  /* Then transform all named subexpressions into non-named ones. */
  for (i = 0; i < n_regexs; i++)
    {
      nfa = nfas[i];
      for (j = 0; j < nfa->num_nodes; j++)
        {
          node = nfa->nodes_array[j];
          if (node->type == SSH_REX_START_SUBEXPR ||
              node->type == SSH_REX_END_SUBEXPR)
            node->type = SSH_REX_FORWARD;
        }
    }

  /* Then create a big disjunct, where all NFAs correspond to numbered
     subexpressions. */

  /* This is the final NFA. */
  nfa = ssh_malloc(sizeof(*nfa));

  if (nfa == NULL) /* OUT OF MEMORY */
    {
      for (i = 0; i < n_regexs; i++)
        {
          destroy_nfa(c, nfas[i]);
        }
      ssh_free(nfas);
      return NULL;
    }

  nfa->nodes_array = NULL;
  nfa->num_nodes = 0;
  nfa->array_size = 0;
  nfa->first = NULL;
  nfa->accept = NULL;

  {
    SshRexNFANode n1, n2;
    SshRexNFANode e, a;

    if (!copy_nfa_nodes(c, nfas[n_regexs - 1],
                        nfa, &e, &a)) /* OUT OF MEMORY */
      {
      out_of_memory_1:
        for (i = 0; i < n_regexs; i++)
          destroy_nfa(c, nfas[i]);
        ssh_free(nfas);
        destroy_nfa(c, nfa);
        return NULL;
      }

    n1 = MAKE_NODE();
    n2 = MAKE_NODE();

    if (n1 == NULL || n2 == NULL) /* OUT OF MEMORY */
      goto out_of_memory_1;

    a->type = SSH_REX_END_SUBEXPR;
    a->u.subexpr = n_regexs - 1;

    n1->type = SSH_REX_START_SUBEXPR;
    n1->u.subexpr = n_regexs - 1;

    n2->type = SSH_REX_ACCEPT;

    a->next = n2;
    n2->incoming_edges++;
    n1->next = e;
    e->incoming_edges++;

    nfa->first = n1; nfa->accept = n2;

    destroy_nfa(c, nfas[n_regexs - 1]);
  }

  for (j = n_regexs - 2; j >= 0; j--)
    {
      SshRexNFANode n1, n2;
      SshRexNFANode e, a;

      if (!copy_nfa_nodes(c, nfas[j], nfa, &e, &a))
        {
        out_of_memory_2:
          for (i = 0; i <= j; i++)
            destroy_nfa(c, nfas[i]);
          ssh_free(nfas);
          destroy_nfa(c, nfa);
          return NULL;
        }

      n1 = MAKE_NODE();
      n2 = MAKE_NODE();

      if (n1 == NULL || n2 == NULL) /* OUT OF MEMORY */
        goto out_of_memory_2;

      n1->type = SSH_REX_START_SUBEXPR;
      n1->u.subexpr = j;
      n1->next = e;
      e->incoming_edges++;

      a->type = SSH_REX_END_SUBEXPR;
      a->u.subexpr = j;
      a->next = nfa->accept;
      nfa->accept->incoming_edges++;

      n2->type = SSH_REX_DISJUNCT;
      n2->next = n1;
      n1->incoming_edges++;
      n2->u.disjunct.second = nfa->first;

      nfa->first = n2;

      destroy_nfa(c, nfas[j]);
    }

  ssh_free(nfas);

  /* Finally add the `anchor to beginning' node. */
  node = MAKE_NODE();

  if (node == NULL) /* OUT OF MEMORY */
    {
      destroy_nfa(c, nfa);
      return NULL;
    }

  node->type = SSH_REX_BEGINNING;
  node->next = nfa->first;
  nfa->first = node;

  /* Now the NFA is finished, so optimize it and wrap inside a regular
     expression structure. */

  /* `streamline_nfa' does not allocate more memory. */
  streamline_nfa(c, nfa, nfa->first);

  if (!shrink_nodes_array(c, nfa))
    {
      destroy_nfa(c, nfa);
      return NULL;
    }

  /* These are memory-safe. */
  if (!calculate_transition_charsets(c, nfa))
    {
      ssh_fatal("internal error in ssh_dlex_create");
    }
  calculate_anchor_hints(c, nfa);

#ifdef SSH_REX_DEBUG
  dump_nfa(nfa);
#endif

  /* Can return NULL if memory runs out. In that case `nfa' is automatically
     freed. */
  return ssh_regex_wrap_nfa(c, nfa, n_regexs);
}

void ssh_dlex_destroy(SshDLexer d)
{
  ssh_regex_free((SshRegexMatcher)d);
}

Boolean ssh_dlex_next(SshDLexer dlex, const unsigned char *data, int data_len,
                      int *match_len, int *token)
{
  Boolean result;
  size_t match = 0;
  int idx = 0;
  int x;

  result = MATCH_PROC((SshRegexMatcher)dlex, data, data_len, 0);

  if (!result) return FALSE;

  for (x = 0; x < dlex->num_matches; x++)
    {
      if (dlex->matches[x].from != NULL)
        {
          result = ssh_regex_access_submatch(dlex, x, &idx, &match);

          *match_len = (int) match;
          SSH_ASSERT(result);
          SSH_ASSERT(idx == 0);

          *token = x;

          return TRUE;
        }
    }

  SSH_NOTREACHED;

  return FALSE;
}

SshRegexError ssh_dlex_get_scan_error(SshDLexer dlex)
{
  return ssh_regex_get_match_error((SshRegexMatcher)dlex);
}
