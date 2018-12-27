/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Deterministic finite automata construction for verifying element
   content specifications.  This uses the Algorithm 3.5 from the
   "Compilers: Principles, Techniques, and Tools" by Aho, Sethi, and
   Ullman.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshXmlVerifierDfa"

/* A place-holder value for an invalid state transition. */
#define SSH_XML_DFA_INVALID_STATE       0xffff

/* Set error code `new_error' to the verifier `verifier' unless it is
   already set. */
#define SSH_XML_DFA_ERROR(verifier, new_error)  \
do                                              \
  {                                             \
    if (!(verifier)->dfa.error)                 \
      (verifier)->dfa.error = (new_error);      \
  }                                             \
while (0)

/* A node set. */
struct SshXmlDfaNodeSetRec
{
  /* Size of the set. */
  SshUInt16 set_size;

  /* Number of nodes in the set. */
  SshUInt16 num_items;

  /* Pointers to the nodes. */
  struct SshXmlDfaNodeRec **set;
};

typedef struct SshXmlDfaNodeSetRec SshXmlDfaNodeSetStruct;
typedef struct SshXmlDfaNodeSetRec *SshXmlDfaNodeSet;

/* Node type. */
typedef enum
{
  SSH_XML_DFA_NODE_NAME,
  SSH_XML_DFA_NODE_PCDATA,
  SSH_XML_DFA_NODE_SEQ,
  SSH_XML_DFA_NODE_OR,
  SSH_XML_DFA_NODE_REPEAT,
  SSH_XML_DFA_NODE_TERMINAL
} SshXmlDfaNodeType;

/* A syntax tree node. */
struct SshXmlDfaNodeRec
{
  SshXmlDfaNodeType type;

  /* Flags. */
  unsigned int nullable : 1;    /* Is nullable. */
  unsigned int label : 16;      /* Node's label. */

  /* Sets. */
  SshXmlDfaNodeSet firstpos;
  SshXmlDfaNodeSet lastpos;
  SshXmlDfaNodeSet followpos;

  /* Node's value. */
  union
  {
    /* Pointer to the interned name. */
    unsigned char *name;

    /* A pair, used in sequence and or-nodes. */
    struct
    {
      struct SshXmlDfaNodeRec *left;
      struct SshXmlDfaNodeRec *right;
    } pair;

    /* Repetition. */
    struct
    {
      int type;                 /* '?', '+', '*' */
      struct SshXmlDfaNodeRec *item;
    } repeat;
  } u;
};

typedef struct SshXmlDfaNodeRec SshXmlDfaNodeStruct;
typedef struct SshXmlDfaNodeRec *SshXmlDfaNode;

/* A DFA state. */
struct SshXmlDfaStateRec
{
  /* Flags. */
  unsigned int accepting : 1;   /* Is this an accepting state. */
  unsigned int marked : 1;      /* Is this state marked. */
  unsigned int number : 24;     /* State number. */

  /* The set of positions implementing this state.  This is used only
     when the DFA is being constructed.  It is not set for a
     constructed DFA. */
  struct SshXmlDfaNodeSetRec *set;

  /* Transitions from the input symbol (index to this array) to the
     state number (index of the array of SshXmlDfaState
     structures). */
  SshUInt16 *transitions;
};

typedef struct SshXmlDfaStateRec SshXmlDfaStateStruct;
typedef struct SshXmlDfaStateRec *SshXmlDfaState;

/* A DFA implementing the regexp style content specifications. */
struct SshXmlDfaRec
{
  SshXmlVerifier verifier;

  /* The number of input symbols. */
  SshUInt32 num_symbols;
  SshUInt32 num_symbols_allocated;

  /* The input symbols.  The first two symbols are special.  The index
     0 is the end-of-element and the index 1 is #PCDATA.  All other
     symbols are pointers to interned input names. */
  unsigned char **input_symbols;

  /* The states of the DFA. */
  SshUInt32 num_states;
  SshUInt32 num_states_allocated;
  SshXmlDfaState states;
};

typedef struct SshXmlDfaRec SshXmlDfStruct;


/********************************** Lexer ***********************************/

/* Special tokens.  Character values < 128 are used as-is as
   tokens. */
#define SSH_XML_DFA_TOKEN_EOF           255
#define SSH_XML_DFA_TOKEN_NAME          254
#define SSH_XML_DFA_TOKEN_PCDATA        253
#define SSH_XML_DFA_TOKEN_TERMINAL      252

/* Get a character from the current input buffer of the verifier
   `verifier'.  The function returns TRUE if a character was get and
   FALSE if the end-of-file was reached.  The character is returned in
   `ch_return'. */
static Boolean
ssh_xml_dfa_getch(SshXmlVerifier verifier, SshXmlChar *ch_return)
{
  size_t len;
  SshUInt32 ch;

  /* Is the ungetch valid? */
  if (verifier->dfa_ungetch_valid)
    {
      *ch_return = verifier->dfa.ungetch;
      verifier->dfa_ungetch_valid = 0;
      return TRUE;
    }

  /* Save the character start position. */
  verifier->dfa.char_start = verifier->dfa.input_pos;

  /* Convert one character from the UTF-8 input buffer into a native
     unicode character. */
  len = ssh_charset_convert(verifier->dfa.input_conv,
                            verifier->dfa.input + verifier->dfa.input_pos,
                            (verifier->dfa.input_len
                             - verifier->dfa.input_pos),
                            &ch, sizeof(ch));
  if (len < sizeof(ch))
    /* EOF. */
    return FALSE;

  /* Got one character. */

  verifier->dfa.input_pos
    += ssh_charset_input_consumed(verifier->dfa.input_conv);

  *ch_return = ch;

  return TRUE;
}

/* Unget the character `ch' into the verifier `verifier'. */
void
ssh_xml_dfa_ungetch(SshXmlVerifier verifier, SshXmlChar ch)
{
  verifier->dfa.ungetch = ch;
  verifier->dfa_ungetch_valid = 1;
}

/* Get a token from the current input buffer of the verifier
   `verifier'.  The function returns TRUE if a token was extracted and
   FALSE if the there were any errors.  If the operation files, the
   function sets an error code to the `verifier'.  The type of the
   token is returned in `token_return'.  If the token is a NAME token,
   the argument `name_return' is set to point to the interned name. */
Boolean
ssh_xml_dfa_get_token(SshXmlVerifier verifier, SshXmlChar *token_return,
                      unsigned char **name_return)
{
  SshXmlChar ch;

  /* Is the unget token valid? */
  if (verifier->dfa_ungettoken_valid)
    {
      /* Yes it is.  Let's reuse it now. */
      *token_return = verifier->dfa.last_token;
      *name_return = verifier->dfa.last_name;
      verifier->dfa_ungettoken_valid = 0;

      return TRUE;
    }

  /* As a default, we do not have name. */
  *name_return = NULL;

  while (1)
    {
      /* Get a character. */
      if (!ssh_xml_dfa_getch(verifier, &ch))
        {
          /* EOF. */
          *token_return = SSH_XML_DFA_TOKEN_EOF;
          break;
        }

      /* Skip whitespace. */
      if (SSH_XML_IS_SPACE(ch))
        continue;

      /* Name tokens. */
      if (SSH_XML_IS_NAME_CHAR(ch))
        {
          size_t name_start = verifier->dfa.char_start;
          size_t name_end;

          while (1)
            {
              if (!ssh_xml_dfa_getch(verifier, &ch))
                {
                  /* EOF. */
                  name_end = verifier->dfa.input_pos;
                  break;
                }
              if (!SSH_XML_IS_NAME_CHAR(ch))
                {
                  name_end = verifier->dfa.char_start;
                  ssh_xml_dfa_ungetch(verifier, ch);
                  break;
                }
              /* Collect more. */
            }

          /* Intern the name. */
          *name_return = ssh_xml_intern(verifier->parser,
                                        verifier->dfa.input + name_start,
                                        name_end - name_start);
          if (*name_return == NULL)
            {
              SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
              return FALSE;
            }

          *token_return = SSH_XML_DFA_TOKEN_NAME;
          break;
        }
      else if (ch == '#')
        {
          size_t name_start = verifier->dfa.char_start;
          size_t name_end;

          /* Handle special tokens starting with the `#' character. */
          while (1)
            {
              if (!ssh_xml_dfa_getch(verifier, &ch))
                {
                  /* EOF. */
                  name_end = verifier->dfa.input_pos;
                  break;
                }
              if (!SSH_XML_IS_NAME_CHAR(ch))
                {
                  /* End of the special token. */
                  name_end = verifier->dfa.char_start;
                  ssh_xml_dfa_ungetch(verifier, ch);
                  break;
                }
              /* Collect more. */
            }

          /* Check what we got. */
          if (name_end - name_start == 1)
            {
              /* Only the `#' at the end of the input.  This is our
                 special end marked that was added after the original
                 expression. */
              *token_return = SSH_XML_DFA_TOKEN_TERMINAL;
              break;
            }
          else if (name_end - name_start == 7
                   && memcmp(verifier->dfa.input + name_start,
                             "#PCDATA", 7) == 0)
            {
              /* Parsed character data. */
              *token_return = SSH_XML_DFA_TOKEN_PCDATA;
              break;
            }
          else
            {
              /* An unknown special token. */
              SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_NOT_WELL_FORMED);
              return FALSE;
            }
        }

      /* Return the character as-is as token. */
      *token_return = ch;
      break;
    }

  /* Got a token. */
  verifier->dfa.last_token = *token_return;
  verifier->dfa.last_name = *name_return;

  return TRUE;
}

/* Unget the last token. */
void
ssh_xml_dfa_unget_token(SshXmlVerifier verifier)
{
  verifier->dfa_ungettoken_valid = 1;
}


/**************************** Handling node sets ****************************/

/* Create a new node set object. */
static SshXmlDfaNodeSet
ssh_xml_dfa_node_set_create(SshXmlVerifier verifier)
{
  SshXmlDfaNodeSet set;

  set = ssh_obstack_calloc(verifier->obstack, sizeof(*set));
  if (set == NULL)
    return NULL;

  set->set_size = verifier->dfa.num_nodes;
  set->set = ssh_obstack_calloc(verifier->obstack,
                                set->set_size * sizeof(SshXmlDfaNode));
  if (set->set == NULL)
    {
      return NULL;
    }

  return set;
}

/* Destroy the node set object `set'. */
static void
ssh_xml_dfa_node_set_destroy(SshXmlDfaNodeSet set)
{
  return;
}

/* Add node `n' into the node set `set'. */
static void
ssh_xml_dfa_node_set_add(SshXmlDfaNodeSet set, SshXmlDfaNode n)
{
  SshUInt32 i;

  /* Is the item already there. */
  for (i = 0; i < set->num_items; i++)
    if (set->set[i] == n)
      /* Already there. */
      return;
    else if (n < set->set[i])
      /* The list is kept sorted and we passed the value.  It is not
         there. */
      break;

  /* There must be space for the new item. */
  SSH_ASSERT(set->num_items < set->set_size);

  /* Move tail one slot forward. */
  memmove(&set->set[i + 1], &set->set[i],
          (set->num_items - i) * sizeof(*set->set));

  /* Insert the new item. */
  set->set[i] = n;
  set->num_items++;
}

/* Copy all items of the node set `src' into the destination node set
   `dst'. */
static void
ssh_xml_dfa_node_set_copy(SshXmlDfaNodeSet dst, SshXmlDfaNodeSet src)
{
  SshUInt32 i;

  /* Add all items from the source to the destination. */
  for (i = 0; i < src->num_items; i++)
    ssh_xml_dfa_node_set_add(dst, src->set[i]);
}

/* Compute an union of the sets `a' and `b' and save the result into
   the set `result'. */
static void
ssh_xml_dfa_node_set_union(SshXmlDfaNodeSet result,
                           SshXmlDfaNodeSet a, SshXmlDfaNodeSet b)
{
  /* Add items from both arguments sets into the result set. */
  ssh_xml_dfa_node_set_copy(result, a);
  ssh_xml_dfa_node_set_copy(result, b);
}

/* Check whether the sets `a' and `b' are equal. */
static Boolean
ssh_xml_dfa_node_set_equal(SshXmlDfaNodeSet a, SshXmlDfaNodeSet b)
{
  if (a->num_items != b->num_items)
    return FALSE;

  /* The sets are kept sorted so simple memcmp() will do the
     comparison. */
  if (memcmp(a->set, b->set, a->num_items * sizeof(*a->set)) != 0)
    /* They differ. */
    return FALSE;

  /* The sets are equal. */
  return TRUE;
}


/****************************** Handling nodes ******************************/

/* Allocate a new node of type `type'. */
static SshXmlDfaNode
ssh_xml_dfa_node_alloc(SshXmlVerifier verifier, SshXmlDfaNodeType type)
{
  SshXmlDfaNode n;

  if (verifier->dfa.num_nodes == SSH_XML_DFA_INVALID_STATE)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Too big DFA: num_nodes=%u",
                              SSH_XML_DFA_INVALID_STATE));
      return NULL;
    }

  n = ssh_obstack_calloc(verifier->obstack, sizeof(*n));
  if (n)
    {
      n->type = type;
      n->label = verifier->dfa.num_nodes++;
    }

  return n;
}

/* Free the node `n'. */
static void
ssh_xml_dfa_node_free(SshXmlDfaNode n)
{
  if (n == NULL)
    return;

  /* Free node sets. */
  ssh_xml_dfa_node_set_destroy(n->firstpos);
  ssh_xml_dfa_node_set_destroy(n->lastpos);
  ssh_xml_dfa_node_set_destroy(n->followpos);

  /* Free node's data. */
  switch (n->type)
    {
    case SSH_XML_DFA_NODE_NAME:
    case SSH_XML_DFA_NODE_PCDATA:
    case SSH_XML_DFA_NODE_TERMINAL:
      /* Nothing here. */
      break;

    case SSH_XML_DFA_NODE_SEQ:
    case SSH_XML_DFA_NODE_OR:
      ssh_xml_dfa_node_free(n->u.pair.left);
      ssh_xml_dfa_node_free(n->u.pair.right);
      break;

    case SSH_XML_DFA_NODE_REPEAT:
      ssh_xml_dfa_node_free(n->u.repeat.item);
      break;
    }
}


/**************************** Expression parsing ****************************/

/* Forward declarations of the parser functions. */
static SshXmlDfaNode ssh_xml_dfa_parse_expr(SshXmlVerifier verifier);
static SshXmlDfaNode ssh_xml_dfa_parse_sequence(SshXmlVerifier verifier);
static SshXmlDfaNode ssh_xml_dfa_parse_or(SshXmlVerifier verifier);
static SshXmlDfaNode ssh_xml_dfa_parse_unary(SshXmlVerifier verifier);
static SshXmlDfaNode ssh_xml_dfa_parse_atom(SshXmlVerifier verifier);

/* Parse an expression. */
static SshXmlDfaNode
ssh_xml_dfa_parse_expr(SshXmlVerifier verifier)
{
  SshXmlDfaNode n;

  n = ssh_xml_dfa_parse_sequence(verifier);
  return n;
}

/* Parse a comma separated sequence. */
static SshXmlDfaNode
ssh_xml_dfa_parse_sequence(SshXmlVerifier verifier)
{
  SshXmlDfaNode s, n, n2;
  SshXmlChar token;
  unsigned char *name;

  s = ssh_xml_dfa_parse_or(verifier);
  if (s == NULL)
    return NULL;

  while (1)
    {
      if (!ssh_xml_dfa_get_token(verifier, &token, &name))
        {
          ssh_xml_dfa_node_free(s);
          return NULL;
        }

      if (token == SSH_XML_DFA_TOKEN_EOF)
        break;

      if (token != ',')
        {
          ssh_xml_dfa_unget_token(verifier);
          break;
        }

      n = ssh_xml_dfa_parse_or(verifier);
      if (n == NULL)
        {
          /* Syntax error. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_NOT_WELL_FORMED);
          ssh_xml_dfa_node_free(s);
          return NULL;
        }

      n2 = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_SEQ);
      if (n2 == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          ssh_xml_dfa_node_free(s);
          ssh_xml_dfa_node_free(n);
          return NULL;
        }

      n2->u.pair.left = s;
      n2->u.pair.right = n;

      s = n2;
    }

  return s;
}

/* Parse a `|' separated or-expression. */
static SshXmlDfaNode
ssh_xml_dfa_parse_or(SshXmlVerifier verifier)
{
  SshXmlDfaNode o, n, n2;
  SshXmlChar token;
  unsigned char *name;

  o = ssh_xml_dfa_parse_unary(verifier);
  if (o == NULL)
    return NULL;

  while (1)
    {
      if (!ssh_xml_dfa_get_token(verifier, &token, &name))
        {
          ssh_xml_dfa_node_free(o);
          return NULL;
        }

      if (token == SSH_XML_DFA_TOKEN_EOF)
        break;

      if (token != '|')
        {
          ssh_xml_dfa_unget_token(verifier);
          break;
        }

      n = ssh_xml_dfa_parse_unary(verifier);
      if (n == NULL)
        {
          /* Syntax error. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_NOT_WELL_FORMED);
          ssh_xml_dfa_node_free(o);
          return NULL;
        }

      n2 = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_OR);
      if (n2 == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          ssh_xml_dfa_node_free(o);
          ssh_xml_dfa_node_free(n);
          return NULL;
        }

      n2->u.pair.left = o;
      n2->u.pair.right = n;

      o = n2;
    }

  return o;
}

/* Parse an unary expression. */
static SshXmlDfaNode
ssh_xml_dfa_parse_unary(SshXmlVerifier verifier)
{
  SshXmlDfaNode n, u;
  SshXmlChar token;
  unsigned char *name;

  n = ssh_xml_dfa_parse_atom(verifier);
  if (n == NULL)
    return NULL;

  if (!ssh_xml_dfa_get_token(verifier, &token, &name))
    {
      ssh_xml_dfa_node_free(n);
      return NULL;
    }

  if (token == SSH_XML_DFA_TOKEN_EOF)
    return n;

  if (token == '?' || token == '+' || token == '*')
    {
      u = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_REPEAT);
      if (u == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          ssh_xml_dfa_node_free(n);
          return NULL;
        }

      u->u.repeat.type = token;
      u->u.repeat.item = n;

      return u;
    }

  ssh_xml_dfa_unget_token(verifier);
  return n;
}

/* Parse an atomic expression. */
static SshXmlDfaNode
ssh_xml_dfa_parse_atom(SshXmlVerifier verifier)
{
  SshXmlDfaNode n, n2;
  SshXmlChar token;
  unsigned char *name;

  if (!ssh_xml_dfa_get_token(verifier, &token, &name))
    return NULL;

  if (token == SSH_XML_DFA_TOKEN_EOF)
    return NULL;

  if (token == '(')
    {
      n = ssh_xml_dfa_parse_expr(verifier);
      if (n == NULL)
        return NULL;

      if (!ssh_xml_dfa_get_token(verifier, &token, &name))
        {
          ssh_xml_dfa_node_free(n);
          return NULL;
        }
      if (token != ')')
        {
          /* Syntax error. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_NOT_WELL_FORMED);
          ssh_xml_dfa_node_free(n);
          return NULL;
        }
      return n;
    }
  else if (token == SSH_XML_DFA_TOKEN_NAME)
    {
      n = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_NAME);
      if (n == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          return NULL;
        }

      n->u.name = name;
      return n;
    }
  else if (token == SSH_XML_DFA_TOKEN_TERMINAL)
    {
      n = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_TERMINAL);
      if (n == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          return NULL;
        }

      return n;
    }
  else if (token == SSH_XML_DFA_TOKEN_PCDATA)
    {
      n = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_PCDATA);
      if (n == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          return NULL;
        }

      /* PCDATA has an implicit `*' repeat around it. */
      n2 = ssh_xml_dfa_node_alloc(verifier, SSH_XML_DFA_NODE_REPEAT);
      if (n2 == NULL)
        {
          /* Out of memory. */
          SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
          ssh_xml_dfa_node_free(n);
          return NULL;
        }

      n2->u.repeat.type = '*';
      n2->u.repeat.item = n;

      return n2;
    }

  /* Syntax error. */
  SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_NOT_WELL_FORMED);

  return NULL;
}


/****************** DFA construction from the syntax tree *******************/

/* Compute nullable, firstpos, lastpos, and followpos sets for the
   syntax tree `tree'. */
static Boolean
ssh_xml_create_sets(SshXmlVerifier verifier, SshXmlDfaNode tree)
{
  SshUInt32 i, j;
  SshXmlDfaNodeSet s1, s2;

  /* Allocate firstpos and lastpos. */

  tree->firstpos = ssh_xml_dfa_node_set_create(verifier);
  tree->lastpos = ssh_xml_dfa_node_set_create(verifier);
  tree->followpos = ssh_xml_dfa_node_set_create(verifier);

  if (tree->firstpos == NULL
      || tree->lastpos == NULL
      || tree->followpos == NULL)
    return FALSE;

  /* Process syntax tree. */
  switch (tree->type)
    {
    case SSH_XML_DFA_NODE_NAME:
      /* Nullable. */
      tree->nullable = 0;

      /* Firstpos. */
      ssh_xml_dfa_node_set_add(tree->firstpos, tree);

      /* Lastpos. */
      ssh_xml_dfa_node_set_add(tree->lastpos, tree);
      break;

    case SSH_XML_DFA_NODE_PCDATA:
      /* Nullable. */
      tree->nullable = 0;

      /* Firstpos. */
      ssh_xml_dfa_node_set_add(tree->firstpos, tree);

      /* Lastpos. */
      ssh_xml_dfa_node_set_add(tree->lastpos, tree);
      break;

    case SSH_XML_DFA_NODE_SEQ:
      /* Depth first traversal. */
      if (!ssh_xml_create_sets(verifier, tree->u.pair.left)
          || !ssh_xml_create_sets(verifier, tree->u.pair.right))
        return FALSE;

      /* Nullable. */
      tree->nullable = (tree->u.pair.left->nullable
                        && tree->u.pair.right->nullable);

      /* Firstpos. */
      if (tree->u.pair.left->nullable)
        ssh_xml_dfa_node_set_union(tree->firstpos,
                                   tree->u.pair.left->firstpos,
                                   tree->u.pair.right->firstpos);
      else
        ssh_xml_dfa_node_set_copy(tree->firstpos,
                                  tree->u.pair.left->firstpos);

      /* Lastpos. */
      if (tree->u.pair.right->nullable)
        ssh_xml_dfa_node_set_union(tree->lastpos,
                                   tree->u.pair.left->lastpos,
                                   tree->u.pair.right->lastpos);
      else
        ssh_xml_dfa_node_set_copy(tree->lastpos,
                                  tree->u.pair.right->lastpos);

      /* Followpos. */

      s1 = tree->u.pair.left->lastpos;
      s2 = tree->u.pair.right->firstpos;

      for (i = 0; i < s1->num_items; i++)
        for (j = 0; j < s2->num_items; j++)
          ssh_xml_dfa_node_set_add(s1->set[i]->followpos, s2->set[j]);

      break;

    case SSH_XML_DFA_NODE_OR:
      /* Depth first traversal. */
      if (!ssh_xml_create_sets(verifier, tree->u.pair.left)
          || !ssh_xml_create_sets(verifier, tree->u.pair.right))
        return FALSE;

      /* Nullable. */
      tree->nullable = (tree->u.pair.left->nullable
                        || tree->u.pair.right->nullable);

      /* Firstpos. */
      ssh_xml_dfa_node_set_union(tree->firstpos,
                                 tree->u.pair.left->firstpos,
                                 tree->u.pair.right->firstpos);

      /* Lastpos. */
      ssh_xml_dfa_node_set_union(tree->lastpos,
                                 tree->u.pair.left->lastpos,
                                 tree->u.pair.right->lastpos);
      break;

    case SSH_XML_DFA_NODE_REPEAT:
      /* Depth first traversal. */
      if (!ssh_xml_create_sets(verifier, tree->u.repeat.item))
        return FALSE;

      switch (tree->u.repeat.type)
        {
        case '*':
          /* Nullable. */
          tree->nullable = 1;

          /* Firstpos. */
          ssh_xml_dfa_node_set_copy(tree->firstpos,
                                    tree->u.repeat.item->firstpos);
          /* Lastpos. */
          ssh_xml_dfa_node_set_copy(tree->lastpos,
                                    tree->u.repeat.item->lastpos);

          /* Followpos. */

          s1 = tree->u.repeat.item->lastpos;
          s2 = tree->u.repeat.item->firstpos;

          for (i = 0; i < s1->num_items; i++)
            for (j = 0; j < s2->num_items; j++)
              ssh_xml_dfa_node_set_add(s1->set[i]->followpos, s2->set[j]);

          break;

        case '+':
          /* Nullable. */
          tree->nullable = tree->u.repeat.item->nullable;

          /* Firstpos. */
          ssh_xml_dfa_node_set_copy(tree->firstpos,
                                    tree->u.repeat.item->firstpos);
          /* Lastpos. */
          ssh_xml_dfa_node_set_copy(tree->lastpos,
                                    tree->u.repeat.item->lastpos);

          /* Followpos. */

          s1 = tree->u.repeat.item->lastpos;
          s2 = tree->u.repeat.item->firstpos;

          for (i = 0; i < s1->num_items; i++)
            for (j = 0; j < s2->num_items; j++)
              ssh_xml_dfa_node_set_add(s1->set[i]->followpos, s2->set[j]);

          break;

        case '?':
          /* Nullable. */
          tree->nullable = 1;

          /* Firstpos. */
          ssh_xml_dfa_node_set_copy(tree->firstpos,
                                    tree->u.repeat.item->firstpos);
          /* Lastpos. */
          ssh_xml_dfa_node_set_copy(tree->lastpos,
                                    tree->u.repeat.item->lastpos);
          break;

        default:
          SSH_NOTREACHED;
          break;
        }
      break;

    case SSH_XML_DFA_NODE_TERMINAL:
      /* Nullable. */
      tree->nullable = 0;

      /* Firstpos. */
      ssh_xml_dfa_node_set_add(tree->firstpos, tree);

      /* Lastpos. */
      ssh_xml_dfa_node_set_add(tree->lastpos, tree);
      break;
    }

  return TRUE;
}

/* Add input symbol `symbol' into the list of know input symbols in
   the DFA `dfa'. */
static Boolean
ssh_xml_dfa_add_symbol(SshXmlDfa dfa, unsigned char *symbol)
{
  SshUInt32 i;
  unsigned char **ndata;

  /* Is `symbol' already in the input symbols? */
  for (i = 0; i < dfa->num_symbols; i++)
    if (dfa->input_symbols[i] == symbol)
      /* Found it. */
      return TRUE;

  if (dfa->num_symbols >= dfa->num_symbols_allocated)
    {
      /* Allocate space for the new symbol. */
      ndata = ssh_obstack_calloc(dfa->verifier->obstack,
                                 (dfa->num_symbols_allocated + 5) *
                                 sizeof(*dfa->input_symbols));
      if (ndata == NULL)
        return FALSE;

      dfa->num_symbols_allocated += 5;

      memcpy(ndata, dfa->input_symbols,
             dfa->num_symbols * sizeof(*dfa->input_symbols));

      dfa->input_symbols = ndata;
    }

  /* And add it to our list of known input symbols. */
  dfa->input_symbols[dfa->num_symbols++] = symbol;

  return TRUE;
}

/* Collect all input symbols of the syntax tree `n' into the DFA
   `dfa'. */
static Boolean
ssh_xml_dfa_collect_symbols(SshXmlDfa dfa, SshXmlDfaNode n)
{
  switch (n->type)
    {
    case SSH_XML_DFA_NODE_NAME:
      /* Add the name. */
      if (!ssh_xml_dfa_add_symbol(dfa, n->u.name))
        return FALSE;
      break;

    case SSH_XML_DFA_NODE_PCDATA:
      /* Add #PCDATA. */
      if (!ssh_xml_dfa_add_symbol(dfa, SSH_XML_DFA_INPUT_PCDATA))
        return FALSE;
      break;

    case SSH_XML_DFA_NODE_SEQ:
    case SSH_XML_DFA_NODE_OR:
      if (!ssh_xml_dfa_collect_symbols(dfa, n->u.pair.left)
          || !ssh_xml_dfa_collect_symbols(dfa, n->u.pair.right))
        return FALSE;
      break;

    case SSH_XML_DFA_NODE_REPEAT:
      if (!ssh_xml_dfa_collect_symbols(dfa, n->u.repeat.item))
        return FALSE;
      return TRUE;

    case SSH_XML_DFA_NODE_TERMINAL:
      /* Nothing here. */
      break;
    }

  return TRUE;
}

#ifdef DEBUG_LIGHT
/* Dump the DFA `dfa' with ssh_debug().  The function returns the
   number of states in the DFA. */
static SshUInt32
ssh_xml_dump_dfa(SshXmlDfa dfa)
{
  SshBufferStruct buf;
  SshUInt32 i, j;
  unsigned char tmp[64];

  ssh_buffer_init(&buf);

  for (j = 0; j < dfa->num_symbols; j++)
    {
      if (dfa->input_symbols[j] == SSH_XML_DFA_INPUT_PCDATA)
        ssh_snprintf(tmp, sizeof(tmp), "\t#PCDATA");
      else
        ssh_snprintf(tmp, sizeof(tmp), "\t%.7s", dfa->input_symbols[j]);

      if (ssh_buffer_append_cstrs(&buf, tmp, NULL))
        goto out;
    }

  if (ssh_buffer_append_cstrs(&buf,
                              "\n-------------------------------------"
                              "-----------------------", NULL))
    goto out;

  ssh_debug("%.*s", ssh_buffer_len(&buf), ssh_buffer_ptr(&buf));


  for (i = 0; i < dfa->num_states; i++)
    {
      ssh_buffer_clear(&buf);

      ssh_snprintf(tmp, sizeof(tmp),
                   "%s%d%s",
                   i == 0 ? ">" : " ",
                   (int) i,
                   dfa->states[i].accepting ? "*" : "");

      if (ssh_buffer_append_cstrs(&buf, tmp, NULL))
        goto out;

      for (j = 0; j < dfa->num_symbols; j++)
        {
          if (dfa->states[i].transitions[j] == SSH_XML_DFA_INVALID_STATE)
            {
              if (ssh_buffer_append_cstrs(&buf, "\t-", NULL))
                goto out;
            }
          else
            {
              ssh_snprintf(tmp, sizeof(tmp),
                           "\t%d", (int) dfa->states[i].transitions[j]);
              if (ssh_buffer_append_cstrs(&buf, tmp, NULL))
                goto out;
            }
        }
      ssh_debug("%.*s", ssh_buffer_len(&buf), ssh_buffer_ptr(&buf));
    }

 out:
  ssh_buffer_uninit(&buf);

  return dfa->num_states;
}
#endif /* DEBUG_LIGHT */

/* Push a new state into the DFA `dfa'.  The state contains the nodes
   of the node set `set'. */
static Boolean
ssh_xml_dfa_push_state(SshXmlDfa dfa, SshXmlDfaNodeSet set)
{
  SshXmlDfaState nstate;
  SshXmlDfaState s;
  SshUInt32 i;

  if (dfa->num_states >= dfa->num_states_allocated)
    {
      /* Allocate space for the new state. */
      nstate = ssh_obstack_calloc(dfa->verifier->obstack,
                                  (dfa->num_states_allocated + 5) *
                                  sizeof(*dfa->states));
      if (nstate == NULL)
        return FALSE;

      dfa->num_states_allocated += 5;

      memcpy(nstate, dfa->states, dfa->num_states * sizeof(*dfa->states));

      dfa->states = nstate;
    }

  s = &dfa->states[dfa->num_states];

  /* Init the new state. */

  memset(s, 0, sizeof(*s));
  s->number = dfa->num_states++;

  s->transitions = ssh_obstack_calloc(dfa->verifier->obstack,
                                      dfa->num_symbols *
                                      sizeof(*s->transitions));
  if (s->transitions == NULL)
    return FALSE;

  /* Now we can not fail anymore so we can store a reference to our
     argument set. */
  s->set = set;

  /* Initialize all transitions to invalid. */
  for (i = 0; i < dfa->num_symbols; i++)
    s->transitions[i] = SSH_XML_DFA_INVALID_STATE;

  /* Is this an accepting state? */
  for (i = 0; i < set->num_items; i++)
    if (set->set[i]->type == SSH_XML_DFA_NODE_TERMINAL)
      {
        /* Yes, its set contains the terminal state so this is an
           accepting state. */
        s->accepting = 1;
        break;
      }

  return TRUE;
}

/* Check whether the state `set' already exists in the DFA `dfa'.  The
   function returns TRUE if the sets exists and FALSE otherwise.  If
   the state exists, its index is returned in `index_return'. */
static Boolean
ssh_xml_dfa_state_exists(SshXmlDfa dfa, SshXmlDfaNodeSet set,
                         SshUInt16 *index_return)
{
  SshUInt16 i;

  for (i = 0; i < dfa->num_states; i++)
    if (ssh_xml_dfa_node_set_equal(dfa->states[i].set, set))
      {
        /* Found it. */
        *index_return = i;
        return TRUE;
      }

  return FALSE;
}

/* Create DFA from the syntax tree `tree'.  The syntax tree has
   already the necessary sets (nullable, firstpos, lastpos, followpos)
   computed. */
static SshXmlDfa
ssh_xml_create_dfa(SshXmlVerifier verifier, SshXmlDfaNode tree)
{
  SshXmlDfa dfa;
  SshXmlDfaNodeSet set;

  /* Allocate a fresh dfa. */
  dfa = ssh_obstack_calloc(verifier->obstack, sizeof(*dfa));
  if (dfa == NULL)
    goto error;

  dfa->verifier = verifier;

  /* Count and collect input symbols. */
  if (!ssh_xml_dfa_collect_symbols(dfa, tree))
    goto error;

  /* Push the initial state which is the firstpos(root). */

  set = ssh_xml_dfa_node_set_create(verifier);
  if (set == NULL)
    goto error;

  ssh_xml_dfa_node_set_copy(set, tree->firstpos);

  if (!ssh_xml_dfa_push_state(dfa, set))
    {
      ssh_xml_dfa_node_set_destroy(set);
      goto error;
    }

  /* Constructing the DFA. */
  while (1)
    {
      SshUInt32 statei, i;

      /* Lookup an unmarked state. */
      for (statei = 0; statei < dfa->num_states; statei++)
        if (!dfa->states[statei].marked)
          break;

      if (statei >= dfa->num_states)
        /* All states processed. */
        break;

      /* Mark state. */
      dfa->states[statei].marked = 1;

      /* For each input symbol. */
      for (i = 0; i < dfa->num_symbols; i++)
        {
          unsigned char *symbol = dfa->input_symbols[i];
          SshXmlDfaNodeSet u, t;
          SshUInt32 j;

          u = ssh_xml_dfa_node_set_create(verifier);
          if (u == NULL)
            goto error;

          /* Process all positions of the state. */
          t = dfa->states[statei].set;
          for (j = 0; j < t->num_items; j++)
            {
              SshXmlDfaNode node = t->set[j];

              /* If the position's symbol matches our current input
                 symbol. */
              switch (node->type)
                {
                case SSH_XML_DFA_NODE_NAME:
                  if (symbol == node->u.name)
                    /* Add all symbols of the followpos(node). */
                    ssh_xml_dfa_node_set_copy(u, node->followpos);
                  break;

                case SSH_XML_DFA_NODE_PCDATA:
                  if (symbol == SSH_XML_DFA_INPUT_PCDATA)
                    /* Add all symbols of the followpos(node). */
                    ssh_xml_dfa_node_set_copy(u, node->followpos);
                  break;

                case SSH_XML_DFA_NODE_SEQ:
                case SSH_XML_DFA_NODE_OR:
                case SSH_XML_DFA_NODE_REPEAT:
                  /* Non-leaf nodes. */
                  break;

                case SSH_XML_DFA_NODE_TERMINAL:
                  /* Nothing here. */
                  break;
                }
            }

          if (u->num_items)
            {
              SshUInt16 uindex;

              /* Add the state unless it already exists */
              if (!ssh_xml_dfa_state_exists(dfa, u, &uindex))
                {
                  if (!ssh_xml_dfa_push_state(dfa, u))
                    {
                      ssh_xml_dfa_node_set_destroy(u);
                      goto error;
                    }
                  uindex = (SshUInt16) (dfa->num_states - 1);
                }
              else
                {
                  ssh_xml_dfa_node_set_destroy(u);
                }

              /* Make a transition. */
              dfa->states[statei].transitions[i] = uindex;
            }
          else
            {
              ssh_xml_dfa_node_set_destroy(u);
            }
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("DFA created:"));
  SSH_DEBUG(SSH_D_LOWOK, ("%u states, %u input symbols",
                          (int) ssh_xml_dump_dfa(dfa),
                          (int) dfa->num_symbols));

  /* All done. */
  return dfa;


  /* Error handling. */

 error:
  ssh_xml_verifier_destroy_dfa(dfa);

  return NULL;
}


/*************************** Interface functions ****************************/

SshXmlDfa
ssh_xml_verifier_create_dfa(SshXmlVerifier verifier,
                            const unsigned char *expr, size_t expr_len)
{
  SshXmlDfaNode tree = NULL;
  SshXmlDfa dfa;

  /* Create an augmented expression `expr,#'.  The input expressions
     are already parenthesized so we don't have to add extra
     parenthesis here. */
  verifier->dfa.input = ssh_obstack_alloc(verifier->obstack, expr_len + 2);
  if (verifier->dfa.input == NULL)
    return NULL;

  memcpy(verifier->dfa.input, expr, expr_len);
  verifier->dfa.input[expr_len + 0] = ',';
  verifier->dfa.input[expr_len + 1] = '#';
  verifier->dfa.input_len = expr_len + 2;

  verifier->dfa.input_pos = 0;
  verifier->dfa.num_nodes = 0;
  verifier->dfa.error = SSH_XML_OK;

  /* Construct syntax tree. */
  tree = ssh_xml_dfa_parse_expr(verifier);
  if (tree == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Content expression parsing failed"));
      /* The error is already set in the parser. */
      goto error;
    }

  /* Create nullable, firstpos, lastpos, and followpos. */
  if (!ssh_xml_create_sets(verifier, tree))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create sets"));
      SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
      goto error;
    }

  /* Create the DFA. */
  dfa = ssh_xml_create_dfa(verifier, tree);
  if (dfa == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create DFA"));
      SSH_XML_DFA_ERROR(verifier, SSH_XML_ERROR_MEMORY);
      goto error;
    }

  /* Free the syntax tree. */
  ssh_xml_dfa_node_free(tree);

  /* All done. */
  return dfa;


  /* Error handling. */

 error:

  if (tree)
    ssh_xml_dfa_node_free(tree);

  return NULL;
}



void
ssh_xml_verifier_destroy_dfa(SshXmlDfa dfa)
{
  SshUInt32 i;

  if (dfa == NULL)
    return;

  for (i = 0; i < dfa->num_states; i++)
    ssh_xml_dfa_node_set_destroy(dfa->states[i].set);
}




Boolean
ssh_xml_verifier_execute_dfa(SshXmlDfa dfa, const unsigned char *input,
                             SshUInt16 *statep)
{
  SshXmlDfaState state;
  SshUInt32 i;

  /* Fetch the state. */
  SSH_ASSERT(*statep < dfa->num_states);
  state = &dfa->states[*statep];

  /* Check EOF as a special case. */
  if (input == SSH_XML_DFA_INPUT_EOF)
    {
      if (state->accepting)
        return TRUE;
      else
        return FALSE;
    }

  /* Is the input symbol known. */
  for (i = 0; i < dfa->num_symbols; i++)
    if (dfa->input_symbols[i] == input)
      {
        /* Found it.  Check if the transition is known. */
        if (state->transitions[i] == SSH_XML_DFA_INVALID_STATE)
          /* Not allowed. */
          return FALSE;

        /* It is ok.  Let's make a state transition. */
        *statep = state->transitions[i];
        return TRUE;
      }

  /* An unknown input symbol. */
  return FALSE;
}
