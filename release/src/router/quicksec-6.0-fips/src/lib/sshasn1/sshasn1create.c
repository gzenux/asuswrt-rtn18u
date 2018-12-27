/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encode/Decode ASN.1 using s-expr like descriptions and
   varargs.
*/

#include "sshincludes.h"
#include "sshber.h"
#include "sshasn1.h"
#include "sshasn1i.h"

#ifdef SSHDIST_ASN1
#define SSH_DEBUG_MODULE "SshAsn1Create"

/* Free the tree parsed from the command. */
static void asn1freeformat(SshAsn1Format port, SshAsn1FormatNode cell)
{
  if (cell)
    {
      if (cell->next_child)
        asn1freeformat(port, cell->next_child);
      if (cell->next_sibling)
        asn1freeformat(port, cell->next_sibling);

      if (cell->type == tSYMBOL)
        ssh_fastalloc_free(port->valuebag, cell->u.strval);

      ssh_fastalloc_free(port->cellbag, cell);
    }
}

/* Read in number on base 10 from input at port */
static SshAsn1Status
asn1parsenumber(SshAsn1Format port, SshAsn1FormatToken token)
{
  int ch, pos = 0;
  char buf[ASN1_MAX_TOKEN_LEN];
  Boolean done = FALSE;

  /* Read up to the decimal point. */
  while (!done)
    {
      ch = GETCH(port);
      if (isdigit((unsigned char) ch))
        buf[pos++] = ch;
      else
        {
          done = TRUE;
          UNGETCH(port, ch);
        }
    }
  buf[pos] = '\000';
  token->intval = strtol(buf, NULL, 10);
  token->type = tINTEGER;
  return SSH_ASN1_STATUS_OK;
}

/* Read one token from the port <port>. */
static SshAsn1Status
asn1parsetoken(SshAsn1Format port, SshAsn1FormatToken token)
{
  int ch;
  unsigned int i = 0;

  token->data = NULL;
 loop:
  ch = GETCH(port);

  /* EOF? */
  if (ch == '\0')
    {
      token->type = tEOF;
      return SSH_ASN1_STATUS_OK;
    }

  /* Whitespace? */
  if (WHITESPACE(ch))
    goto loop;

  /* Symbol? */
  if (INITIAL(ch))
    {
      if ((token->data = ssh_fastalloc_alloc(port->valuebag)) == NULL)
        return SSH_ASN1_STATUS_ERROR;

      /* Yes it is a symbol. */
      token->data[i++] = ch;
      while (1)
        {
          if (i + 1 >= ASN1_MAX_TOKEN_LEN)
            {
              ssh_fastalloc_free(port->valuebag, token->data);
              return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
            }

          ch = GETCH(port);
          if (ch == tEOF)
            break;

          if (!SUBSEQUENT(ch))
            {
              UNGETCH(port, ch);
              break;
            }
          token->data[i++] = ch;
        }
      token->data[i] = '\0';
      token->type = tSYMBOL;
      return SSH_ASN1_STATUS_OK;
    }
  /* Number? */
  if (DIGIT(ch))
    {
      UNGETCH(port, ch);
      return asn1parsenumber(port, token);
    }

  /* Parenthesis. */
  if (ch == '(')
    {
      token->type = tLPAREN;
      return SSH_ASN1_STATUS_OK;
    }
  if (ch == ')')
    {
      token->type = tRPAREN;
      return SSH_ASN1_STATUS_OK;
    }
  return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
}

/* Read in ASN.1 tree from format given as port. */
static SshAsn1Status
asn1parse(SshAsn1Format port, SshAsn1FormatNode value)
{
  SshAsn1FormatNode head = NULL, tail = NULL, phead = NULL;
  struct SshAsn1FormatNodeRec cell, *tmp = NULL;
  struct SshAsn1FormatTokenRec token;
  SshAsn1Status retval, got;

  if ((retval = asn1parsetoken(port, &token)) != SSH_ASN1_STATUS_OK)
    goto out;

  switch (token.type)
    {
    case tSYMBOL:
      value->next_child = value->next_sibling = NULL;
      value->u.strval = (char *)token.data;
      value->type = tSYMBOL;
      break;

    case tINTEGER:
      value->next_child = value->next_sibling = NULL;
      value->u.intval = token.intval;
      value->type = tINTEGER;
      break;

    case tLPAREN:
      head = NULL;
      memset(&cell, 0, sizeof(cell));
      while (1)
        {
          got = asn1parse(port, &cell);
          if (got != SSH_ASN1_STATUS_OK)
            {
              retval = got;
              goto out;
            }
          if (cell.type == tRPAREN)
            {
              if (head == NULL)
                {
                  phead = &cell;
                  phead->type = tPAIR;
                  if ((tmp = ssh_fastalloc_alloc(port->cellbag)) == NULL)
                    {
                      retval = SSH_ASN1_STATUS_ERROR;
                      goto out;
                    }
                  memmove(tmp, &cell, sizeof(cell));
                  phead->next_child = tmp;
                }
              break;
            }

          if (cell.type == tINTEGER)
            {
              if (head == NULL)
                {
                  phead = &cell;
                  if ((tmp = ssh_fastalloc_alloc(port->cellbag)) == NULL)
                    {
                      retval = SSH_ASN1_STATUS_ERROR;
                      goto out;
                    }
                  memmove(tmp, &cell, sizeof(cell));
                  phead->next_child = tmp;
                }
            }

          if (head == NULL)
            {
              if ((phead = head = ssh_fastalloc_alloc(port->cellbag)) == NULL)
                {
                  if (tmp) ssh_fastalloc_free(port->cellbag, tmp);
                  retval = SSH_ASN1_STATUS_ERROR;
                  goto out;
                }
              memmove(phead, &cell, sizeof(cell));
              tail = head;
            }
          else
            {
              if (tail->next_child)
                {
                  if ((tail->next_sibling =
                       ssh_fastalloc_alloc(port->cellbag)) == NULL)
                    {
                      if (tmp) ssh_fastalloc_free(port->cellbag, tmp);
                      retval = SSH_ASN1_STATUS_ERROR;
                      goto out;
                    }

                  memmove(tail->next_sibling, &cell, sizeof(cell));
                  tail = tail->next_sibling;
                }
              else
                {
                  if ((tail->next_child =
                       ssh_fastalloc_alloc(port->cellbag)) == NULL)
                    {
                      if (tmp) ssh_fastalloc_free(port->cellbag, tmp);
                      retval = SSH_ASN1_STATUS_ERROR;
                      goto out;
                    }
                  memmove(tail->next_child, &cell, sizeof(cell));
                  tail = tail->next_child;
                }
            }
        }

      if (!value)
        {
          if (token.data)
            ssh_fastalloc_free(port->valuebag, token.data);
          retval = SSH_ASN1_STATUS_ERROR;
          goto out;
        }

      memmove(value, phead, sizeof(*phead));
      if (head)
        ssh_fastalloc_free(port->cellbag, head);
      break;

    case tEOF: retval = SSH_ASN1_STATUS_FORMAT_STRING_END; break;
    case tRPAREN: value->type = tRPAREN; break;
    default: break;
    }

 out:
  return retval;
}


/*****************************************************************************/


/* If tags are present (e.g. the options is not an empty list), then
   we'll assume the class to be context, and the node to be tagged
   implicitly (unless explicit flag given). The length encoding is
   definitive unless othervice stated. */

static
Boolean asn1processoptions(SshAsn1Format port,
                           SshAsn1FormatNode parent, SshAsn1FormatNode child)
{
  int i = 0, o;

  if (child == NULL)
    {
      child = parent->next_child;
      if (child == NULL)
        return FALSE;
    }

  parent->flags |= SSH_ASN1_LENGTH_DEFINITE;
  if ((parent->flags & SSH_ASN1_TAGGED) == 0)
    parent->flags |= SSH_ASN1_CLASS_CONTEXT;

  if (child->type == tSYMBOL)
    {
      if (!(parent->flags & SSH_ASN1_TAGGING_EXPLICIT))
        parent->flags |= (SSH_ASN1_TAGGED|SSH_ASN1_TAGGING_IMPLICIT);
      while ((o = child->u.strval[i]))
        {
          switch (o)
            {
            case 'u':
              parent->flags &= ~0xff;
              parent->flags |= (SSH_ASN1_CLASS_UNIVERSAL|SSH_ASN1_TAGGED);
              break;
            case 'p':
              parent->flags &= ~0xff;
              parent->flags |= (SSH_ASN1_CLASS_PRIVATE|SSH_ASN1_TAGGED);
              break;
            case 'c':
              parent->flags &= ~0xff;
              parent->flags |= (SSH_ASN1_CLASS_CONTEXT|SSH_ASN1_TAGGED);
              break;
            case 'a':
              parent->flags &= ~0xff;
              parent->flags |= (SSH_ASN1_CLASS_APPLICATION|SSH_ASN1_TAGGED);
              break;
            case 'e':
              parent->flags &= ~SSH_ASN1_TAGGING_IMPLICIT;
              parent->flags |= (SSH_ASN1_TAGGING_EXPLICIT|SSH_ASN1_TAGGED);
              break;
            case 'i':
              parent->flags |= SSH_ASN1_LENGTH_INDEFINITE;
              parent->flags &= ~SSH_ASN1_LENGTH_DEFINITE;
              break;
            case 'l':
              parent->flags &= ~(SSH_ASN1_TAGGING_IMPLICIT|SSH_ASN1_TAGGED);
              parent->flags |= SSH_ASN1_LENGTH_STAR;
              break;
            case '*':
              if (parent->flags & SSH_ASN1_LENGTH_STAR)
                break;
              parent->flags |= SSH_ASN1_MATCH_DEFS;
              break;
            default:
              return FALSE;
            }
          i++;
        }
      if (child->next_child)
        {
          if (child->next_child->type == tINTEGER)
            return asn1processoptions(port, parent, child->next_child);
          else
            {
              SshAsn1FormatNode n = ssh_fastalloc_alloc(port->cellbag);

              if (n)
                {
                  memset(n, 0, sizeof(*n));
                  child->next_sibling = child->next_child;
                  child->next_child = n;
                  n->type = tPAIR;
                  return TRUE;
                }
              else
                return FALSE;
            }
        }
    }
  else if (child->type == tINTEGER)
    {
      parent->tagnum = child->u.intval;
      if (!(parent->flags & SSH_ASN1_TAGGING_EXPLICIT))
        parent->flags |= (SSH_ASN1_TAGGED|SSH_ASN1_TAGGING_IMPLICIT);
    }
  else if (child->type == tPAIR)
    {
      parent->tagnum = parent->def->tag_number;
      parent->flags &= ~0xff;
      parent->flags |= SSH_ASN1_CLASS_UNIVERSAL;
    }

  return TRUE;
}

static const SshAsn1Defs ssh_asn1_definitions[37] =
{
  { "boolean", SSH_ASN1_DEF_BOOLEAN,
    SSH_ASN1_TAG_BOOLEAN, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_boolean, ssh_ber_decode_boolean },

  { "general-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_GENERAL_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "bit-string",  SSH_ASN1_DEF_BIT_STRING,
    SSH_ASN1_TAG_BIT_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_bit_string, ssh_ber_decode_bit_string },

  { "object-identifier", SSH_ASN1_DEF_OID,
    SSH_ASN1_TAG_OID_TYPE, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_oid_type, ssh_ber_decode_oid_type },

  { "null", SSH_ASN1_DEF_NULL,
    SSH_ASN1_TAG_NULL, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_null, ssh_ber_decode_null},

  { "printable-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_PRINTABLE_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  { "unrestricted-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_UNRESTRICTED_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  { "graphic-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_GRAPHIC_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "ia5-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_IA5_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "generalized-time", SSH_ASN1_DEF_TIME,
    SSH_ASN1_TAG_GENERALIZED_TIME, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_generalized_time, ssh_ber_decode_generalized_time },

  { "visible-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_VISIBLE_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  { "sequence", SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_SEQUENCE, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "optional", SSH_ASN1_DEF_NONE,
    0, SSH_ASN1_DEFEXT_OPTIONAL,
    NULL_FNPTR, NULL_FNPTR },

  { "utc-time", SSH_ASN1_DEF_TIME,
    SSH_ASN1_TAG_UNIVERSAL_TIME, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_universal_time, ssh_ber_decode_universal_time },

  { "enum", SSH_ASN1_DEF_INT,
    SSH_ASN1_TAG_ENUM, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_integer, ssh_ber_decode_integer },

  { "enum-short",  SSH_ASN1_DEF_SHORT,
    SSH_ASN1_TAG_ENUM, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_integer_short, ssh_ber_decode_integer_short },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "bmp-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_BMP_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  { "universal-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_UNIVERSAL_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  { "teletex-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_TELETEX_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  { "choice", SSH_ASN1_DEF_NONE,
    0, SSH_ASN1_DEFEXT_CHOICE,
    NULL_FNPTR, NULL_FNPTR },

  { "integer",  SSH_ASN1_DEF_INT,
    SSH_ASN1_TAG_INTEGER, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_integer, ssh_ber_decode_integer },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "integer-short",  SSH_ASN1_DEF_SHORT,
    SSH_ASN1_TAG_INTEGER, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_integer_short, ssh_ber_decode_integer_short },

  { "utf8-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_UTF8_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "any", SSH_ASN1_DEF_NONE,
    0, SSH_ASN1_DEFEXT_NODE,
    NULL_FNPTR, NULL_FNPTR },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "set", SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_SET, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "octet-string", SSH_ASN1_DEF_STRING,
    SSH_ASN1_TAG_OCTET_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string, ssh_ber_decode_octet_string },

  /* unsupported */
  { NULL, SSH_ASN1_DEF_NONE,
    SSH_ASN1_TAG_RESERVED_0, SSH_ASN1_DEFEXT_NONE,
    NULL_FNPTR, NULL_FNPTR },

  { "empty", SSH_ASN1_DEF_NULL,
    0, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_empty }
};

static const
SshAsn1Defs *asn1getcommand(const char *str)
{
  unsigned int x;
  int i, len;

  len = strlen(str);
  /* Compute the hash. */
  for (x = 0x5ef0bdf5, i = 0; i < len; i++)
    {
      x ^= str[i];
      if (x & 0x1)
        x = (x >> 1) ^ 0x1221d22f;
      else
        x >>= 1;
      x &= 0xffffffff;
    }
  x %= 37;

  /* This discards many possibilities. */
  if (ssh_asn1_definitions[x].name == NULL ||
      strcmp(ssh_asn1_definitions[x].name, str) != 0)
    return NULL;
  else
    return &ssh_asn1_definitions[x];
}

/* Traverse a tree and check all the command keywords and format
   specifiers are OK. */
static
SshAsn1Status asn1checksyntax(SshAsn1Format port,
                              SshAsn1FormatNode parent,
                              SshAsn1FormatNode cell,
                              Boolean verbose,
                              int level)
{
  const SshAsn1Defs *def;
  SshAsn1Status status = SSH_ASN1_STATUS_OK;

  if (cell)
    {
      cell->parent = parent;
      if (cell->type == tSYMBOL)
        {
          if ((def = asn1getcommand((const char *)cell->u.strval)) != NULL)
            {
              cell->def = def;
              if (def->extended == SSH_ASN1_DEFEXT_CHOICE ||
                  def->extended == SSH_ASN1_DEFEXT_OPTIONAL)
                goto notags;

              /* The next child is option */
              if (!asn1processoptions(port, cell, cell->next_child))
                return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
            }
        }
    notags:
      if (level > -1) level++;
      status = asn1checksyntax(port, cell, cell->next_child, verbose, level);
      if (status != SSH_ASN1_STATUS_OK)
        return status;
      if (level > -1) level--;
      status = asn1checksyntax(port,
                               cell->parent,
                               cell->next_sibling, verbose, level);
      if (status != SSH_ASN1_STATUS_OK)
        return status;
    }
  return SSH_ASN1_STATUS_OK;
}

/*****************************************************************************/

static
SshAsn1Node asn1newnode(SshAsn1Context context, SshAsn1Node parent)
{
  SshAsn1Node node;

  if ((node = ssh_obstack_alloc(context->obstack, sizeof(*node))) != NULL)
    {
      memset(node, 0, sizeof(*node));
      node->parent = parent;
    }
  return node;
}

static
SshAsn1Tree asn1newtree(SshAsn1Context context)
{
  SshAsn1Tree tree;

  if ((tree = ssh_obstack_alloc(context->obstack, sizeof(*tree))) != NULL)
    memset(tree, 0, sizeof(*tree));
  return tree;
}

/* Create ASN.1 tree from parsed description at cell into pnode. */
static
SshAsn1Status asn1create(SshAsn1Context context,
                         SshAsn1Node *pnode,
                         SshAsn1FormatNode cell, va_list ap)
{
  SshAsn1FormatNode prev = NULL;
  const SshAsn1Defs *def;
  SshAsn1Node rootnode = NULL;
  SshAsn1Node node, tagnode, anynode;
  SshAsn1Node prevnode = NULL, parentnode = NULL;
  int status = SSH_ASN1_STATUS_ERROR, level = 0, prevlevel = -1;
  Boolean skiplevel = FALSE;

  while (1)
    {
      while (1)
        {
          if (cell->def)
            {
              /* It is a command. */
              def = cell->def;
              switch (def->extended)
                {
                case SSH_ASN1_DEFEXT_CHOICE:
                case SSH_ASN1_DEFEXT_OPTIONAL:
                  /* Choice and Optional are for decoder. */
                  return SSH_ASN1_STATUS_UNKNOWN_COMMAND;

                case SSH_ASN1_DEFEXT_NODE:
                  /* Add pre-made node as any data to the tree. */
                  if (cell->parent)
                    {
                      if (cell->parent->flags & SSH_ASN1_TAGGING_EXPLICIT)
                        parentnode = cell->parent->node->child;
                      else
                        parentnode = cell->parent->node;
                    }

                  node = va_arg(ap, SshAsn1Node);
                  if (node == NULL)
                    {
                      skiplevel = TRUE; level--; prevlevel--;
                      break;
                    }

                  if ((cell->flags & SSH_ASN1_TAGGED) &&
                      (cell->flags & SSH_ASN1_TAGGING_EXPLICIT))
                    {
                      if ((tagnode = asn1newnode(context, parentnode)) == NULL)
                        return SSH_ASN1_STATUS_ERROR;

                      tagnode->tag_number = cell->tagnum;
                      tagnode->classp = cell->flags & 0xff;
                      tagnode->encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
                      tagnode->length_encoding = SSH_ASN1_LENGTH_DEFINITE;

                      /* Fix parent pointers at the new node */
                      anynode = node;
                      while (anynode)
                        {
                          anynode->parent = tagnode;
                          anynode = anynode->next;
                        }
                      anynode = tagnode;
                      ADDNODE(parentnode, prevnode, tagnode, level, prevlevel);
                      tagnode->child = node;
                      node->parent = tagnode;
                      prevnode = tagnode;
                    }
                  else
                    {
                      /* node->class = cell->flags & 0xff; */
                      anynode = node;
                      while (anynode)
                        {
                          anynode->parent = parentnode;
                          anynode = anynode->next;
                        }
                      anynode = node;
                      ADDNODE(parentnode, prevnode, anynode, level, prevlevel);
                    }

                  /* Fix for implicit tagging modes. */
                  if (cell->flags & SSH_ASN1_TAGGED &&
                      cell->flags & SSH_ASN1_TAGGING_IMPLICIT)
                    {
                      /* Check that this node isn't encoded and it cannot
                         be retagged in that case. */
                      SSH_ASSERT(node->tag == NULL);

                      node->classp = cell->flags & 0xff;
                      node->tag_number = cell->tagnum;
                    }

                  cell->node = anynode;
                  if (!rootnode)
                    rootnode = anynode;
                  break;

                case SSH_ASN1_DEFEXT_NONE:
                  /* Allocate and add new ASN.1 node to the tree. */
                  if (cell->parent)
                    {
                      if (cell->parent->flags & SSH_ASN1_TAGGING_EXPLICIT)
                        parentnode = cell->parent->node->child;
                      else
                        parentnode = cell->parent->node;
                    }

                  if ((node = asn1newnode(context, parentnode)) == NULL)
                    return SSH_ASN1_STATUS_ERROR;

                  cell->node = node;

                  ADDNODE(parentnode, prevnode, node, level, prevlevel);
                  if (!rootnode)
                    rootnode = node;

                  if ((cell->flags & SSH_ASN1_TAGGED) &&
                      (cell->flags & SSH_ASN1_TAGGING_EXPLICIT))
                    {
                      tagnode = node;
                      tagnode->tag_number = cell->tagnum;
                      tagnode->classp = cell->flags & 0xff;
                      tagnode->encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
                      tagnode->length_encoding = SSH_ASN1_LENGTH_DEFINITE;
                      if ((node = asn1newnode(context, tagnode)) == NULL)
                        return SSH_ASN1_STATUS_ERROR;

                      tagnode->child = node;
                      prevnode = tagnode;
                    }

                  if ((cell->flags & SSH_ASN1_TAGGED) &&
                      (cell->flags & SSH_ASN1_TAGGING_IMPLICIT))
                    {
                      node->classp = cell->flags & 0xff;
                      node->tag_number = cell->tagnum;
                    }
                  else
                    {
                      node->classp = SSH_ASN1_CLASS_UNIVERSAL;
                      node->tag_number = def->tag_number;
                    }
                  if (def->encode)
                    node->encoding = SSH_ASN1_ENCODING_PRIMITIVE;
                  else
                    node->encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
                  node->length_encoding =
                    (cell->flags & SSH_ASN1_LENGTH_ENCODING);

                  /* Build structure of the tree into the ASN.1
                     coding as well. */
                  ssh_asn1_encode_ber(context, def, node, ap, status);

                  if (status != SSH_ASN1_STATUS_OK)
                    return status;

                  break;
                }
              /* Take a copy of current level of structure */
              if (!skiplevel)
                prevlevel = level;
              else
                skiplevel = FALSE;

            }
          FOLLOW_CHILD(cell, prev, level);
        }

      SSH_ASSERT(cell->parent != NULL);

      BACKUP(cell, prev, level);
    }

 traversed:
  *pnode = rootnode;
  return SSH_ASN1_STATUS_OK;
}


static void
asn1_parse_function(SshAsn1Format port,
                    SshAsn1FormatNode cell,
                    SshAsn1Status *status)
{
  size_t len;
  SshAsn1FormatNode prev = NULL;

  *status = SSH_ASN1_STATUS_OK;

  len = strlen(port->data);
  while (port->offset < len && *status == SSH_ASN1_STATUS_OK)
    {
      if (((*status =
            asn1parse(port, cell)) == SSH_ASN1_STATUS_OK) &&
          ((*status =
            asn1checksyntax(port, NULL, cell, TRUE, -1))
           == SSH_ASN1_STATUS_OK))
        {
          prev = cell;
          cell->next_sibling = ssh_fastalloc_alloc(port->cellbag);
          if (cell->next_sibling == NULL)
            *status = SSH_ASN1_STATUS_ERROR;
          else
            {
              memset(cell->next_sibling, 0, sizeof(*cell));
              cell = cell->next_sibling;
            }
        }
      else
        break;
    }
  if (prev)
    {
      if (prev->next_sibling)
        ssh_fastalloc_free(port->cellbag, prev->next_sibling);
      prev->next_sibling = NULL;
    }
}

#define PARSE(port, cell, status) \
  asn1_parse_function(&(port), (cell), &(status))

SshAsn1Status ssh_asn1_create_node(SshAsn1Context context,
                                   SshAsn1Node *node,
                                   const char *format, ...)
{
  struct SshAsn1FormatRec port;
  SshAsn1FormatNode head, cell;
  SshAsn1Status status = 0;
  va_list ap;

  SSH_DEBUG(SSH_D_LOWSTART, ("ASN.1 create node with format \"%s\"", format));

  port.offset = 0;
  port.data = format;
  port.cellbag = context->cellbag;
  port.valuebag = context->valuebag;

  if ((head = cell = ssh_fastalloc_alloc(port.cellbag)) == NULL)
    return SSH_ASN1_STATUS_ERROR;
  else
    memset(cell, 0, sizeof(*cell));
  PARSE(port, cell, status);
  if (status == SSH_ASN1_STATUS_OK)
    {
      va_start(ap, format);
      status = asn1create(context, node, head, ap);
      va_end(ap);
    }
  asn1freeformat(&port, head);
  return status;
}

SshAsn1Status ssh_asn1_create_tree(SshAsn1Context context,
                                   SshAsn1Tree *tree,
                                   const char *format, ...)
{
  struct SshAsn1FormatRec port;
  SshAsn1FormatNode head, cell;
  SshAsn1Status status = 0;
  va_list ap;

  SSH_DEBUG(SSH_D_MIDSTART, ("ASN.1 create tree with format \"%s\"", format));
  if ((*tree = asn1newtree(context)) == NULL)
    return SSH_ASN1_STATUS_ERROR;

  port.offset = 0;
  port.data = format;
  port.cellbag = context->cellbag;
  port.valuebag = context->valuebag;

  if ((head = cell = ssh_fastalloc_alloc(port.cellbag)) == NULL)
    return SSH_ASN1_STATUS_ERROR;
  else
    memset(cell, 0, sizeof(*cell));
  PARSE(port, cell, status);
  if (status == SSH_ASN1_STATUS_OK)
    {
      va_start(ap, format);
      /* Create tree and set current position. */
      status = asn1create(context, &(*tree)->root, head, ap);
      (*tree)->current = (*tree)->root;
      va_end(ap);
    }
  asn1freeformat(&port, head);
  return status;
}

/*****************************************************************************/

#define DECODE(cell, list, node, val, len) \
  (*(cell)->def->decode)((node)->data, (node)->length, (list), (val), (len))


static SshBerStatus asn1_decode_string_generic(SshAsn1FormatNode cell,
                                               SshAsn1Node node,
                                               SshBerFreeList list,
                                               Boolean bit_string)
{
  unsigned char *tmp, *value;
  SshAsn1Node tmpnode;
  size_t len, byte_len, offset = 0;
  SshBerStatus status = SSH_BER_STATUS_OK;

  if ((status = DECODE(cell, list, node, cell->pstrval, cell->plenval))
      != SSH_BER_STATUS_OK)
    {
      return status;
    }

  if ((node->length_encoding == SSH_ASN1_LENGTH_INDEFINITE) ||
      (node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED))
    {
      tmp = *cell->pstrval;
      tmpnode = ssh_asn1_node_child(node);
      if (tmpnode == NULL)
        {
          /* empty string */
          *cell->plenval = 0;
          return SSH_BER_STATUS_OK;
        }

      do {
        if ((status = DECODE(cell, list, tmpnode, &value, &len))
            == SSH_BER_STATUS_OK)
          {
            /* If this encodes a bit string, convert to byte length. */
            if (bit_string)
              byte_len = (len + 7) / 8;
            else
              byte_len = len;

            if (offset + byte_len <=
                bit_string ? (*cell->plenval + 7) / 8 : *cell->plenval)
              {
                memmove(tmp + offset, value, byte_len);
                ssh_free(value);
              }
            else
              status = SSH_BER_STATUS_BUFFER_TOO_SMALL;

            offset += byte_len;
          }
      } while ((status == SSH_BER_STATUS_OK) &&
               ((tmpnode = ssh_asn1_node_next(tmpnode)) != NULL));
      *cell->plenval = offset;
    }

 return status;
}


static SshBerStatus asn1_decode_string(SshAsn1FormatNode cell,
                                       SshAsn1Node node,
                                       SshBerFreeList list)
{
  return asn1_decode_string_generic(cell, node, list, FALSE);
}

static SshBerStatus asn1_decode_bit_string(SshAsn1FormatNode cell,
                                           SshAsn1Node node,
                                           SshBerFreeList list)
{
  return asn1_decode_string_generic(cell, node, list, TRUE);
}

static SshBerStatus asn1_decode_ber(SshAsn1FormatNode cell,
                                    SshAsn1Node node,
                                    SshBerFreeList list)
{
  SshBerStatus status = SSH_BER_STATUS_ERROR;

  switch (cell->def->type)
    {
    case SSH_ASN1_DEF_BOOLEAN:
      status = DECODE(cell, list, node, cell->pboolval, NULL);
      break;
    case SSH_ASN1_DEF_SHORT:
      status = DECODE(cell, list, node, cell->pshortval, NULL);
      break;
    case SSH_ASN1_DEF_INT:
      status = DECODE(cell, list, node, cell->pintval, NULL);
      break;
    case SSH_ASN1_DEF_OID:
      status = DECODE(cell, list, node, cell->poidval, NULL);
      break;
    case SSH_ASN1_DEF_TIME:
      status = DECODE(cell, list, node, cell->ptimeval, NULL);
      break;
    case SSH_ASN1_DEF_STRING:
      status = asn1_decode_string(cell, node, list);
      break;
    case SSH_ASN1_DEF_BIT_STRING:
      status = asn1_decode_bit_string(cell, node, list);
      break;
    case SSH_ASN1_DEF_NULL:
      status = DECODE(cell, list, node, NULL, NULL);
      break;
    case SSH_ASN1_DEF_NONE:
      status = SSH_BER_STATUS_OK;
      break;
    }
  return status;
}

/* This is the recursive core of matching. */
static SshAsn1Status asn1assign(SshAsn1Context context,
                                SshAsn1Node first,
                                SshAsn1FormatNode cell,
                                SshUInt8 tagged, SshUInt8 untagged,
                                SshUInt32 choice,
                                SshUInt32 optional,
                                SshBerFreeList freelist)
{
  const SshAsn1Defs *def;
  int tagnum, nth = 0;
  SshBerStatus ber_status;
  SshAsn1Status status = SSH_ASN1_STATUS_OK;
  SshUInt32 children_optional;
  SshAsn1Node current, node, children;
  SshAsn1FormatNode child;

  current = first;

  /* Loop this level (e.g. cell and all its siblings) matching the
     description against the current ASN.1 subtree. If match is found,
     it is consumed from the current. If mandatory match is not found
     or some other error occurs, this returns directly. */

  while (cell)
    {
      def = cell->def;

      if (def)
        {
          switch (def->extended)
            {
            case SSH_ASN1_DEFEXT_NODE:
              if (optional & SSH_ASN1_OPTIONAL_FAILED)
                break;

              if (current == NULL && !optional)
                {
                  *cell->panyval = NULL;
                  break;
                }

              node =
                ssh_asn1_search_node(first, &current,
                                     tagged, SSH_ASN1_RULE_NO_MATCH,
                                     def,
                                     cell->flags & SSH_ASN1_TAGGED,
                                     cell->flags & 0xff,
                                     cell->flags & SSH_ASN1_LENGTH_ENCODING,
                                     cell->tagnum,
                                     cell->flags & SSH_ASN1_TAGGING_MODE);

              if (node)
                {
                  *cell->panyval = node;
                }
              else
                {
                  if (!(optional & SSH_ASN1_OPTIONAL))
                    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
                  else
                    {
                      status = SSH_ASN1_STATUS_MATCH_NOT_FOUND;
                      optional |= SSH_ASN1_OPTIONAL_FAILED;
                    }
                }
              break;

            case SSH_ASN1_DEFEXT_NONE:
              if (current == NULL && !(optional & SSH_ASN1_OPTIONAL))
                return SSH_ASN1_STATUS_NODE_NULL;

              if (cell->flags & SSH_ASN1_MATCH_DEFS)
                node = current;
              else
                node =
                  ssh_asn1_search_node(first, &current,
                                       tagged, untagged,
                                       def,
                                       cell->flags & SSH_ASN1_TAGGED,
                                       cell->flags & 0xff,
                                       cell->flags & SSH_ASN1_LENGTH_ENCODING,
                                       cell->tagnum,
                                       cell->flags & SSH_ASN1_TAGGING_MODE);

              if (!node)
                return SSH_ASN1_STATUS_MATCH_NOT_FOUND;

              if (def->decode)
                {
                  ber_status = asn1_decode_ber(cell, node, freelist);
                  if (ber_status != SSH_BER_STATUS_OK)
                    return SSH_ASN1_STATUS_BER_DECODE_FAILED;
                }
              else
                {
                  /* The cell requires constructed type. March into the
                     subtree. */
                  if (node->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
                    return SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED;

                  children = node->child;
                  children_optional = optional;
                  tagnum = cell->tagnum;
                  if (tagnum != SSH_ASN1_TAG_SET)
                    tagnum = SSH_ASN1_TAG_SEQUENCE;

                  if (tagnum == SSH_ASN1_TAG_SET)
                    status =
                      asn1assign(context,
                                 children, cell->next_child->next_sibling,
                                 SSH_ASN1_RULE_SCAN_ALL,
                                 SSH_ASN1_RULE_SCAN_ALL,
                                 FALSE, children_optional, freelist);
                  else
                    status =
                      asn1assign(context,
                                 children, cell->next_child->next_sibling,
                                 SSH_ASN1_RULE_SCAN_ALL,
                                 SSH_ASN1_RULE_SCAN_FWD,
                                 FALSE, children_optional, freelist);

                  if ((optional & SSH_ASN1_OPTIONAL) &&
                      status == SSH_ASN1_STATUS_MATCH_NOT_FOUND)
                    {
                      optional |= SSH_ASN1_OPTIONAL_FAILED;
                      break;
                    }
                  if (status != SSH_ASN1_STATUS_OK)
                    return status;
                }
              break;

            case SSH_ASN1_DEFEXT_CHOICE:
              *cell->pchosen = -1;
              child = cell->next_child;
              nth = 0;
              while (child)
                {
                  status =
                    asn1assign(context, current, child,
                               SSH_ASN1_RULE_NO_SCAN, SSH_ASN1_RULE_NO_SCAN,
                               TRUE,
                               optional & ~SSH_ASN1_OPTIONAL,
                               freelist);

                  if (status == SSH_ASN1_STATUS_OK)
                    {
                      if (*cell->pchosen != -1)
                        return SSH_ASN1_STATUS_CHOICE_TOO_MANY_MATCHES;
                      else
                        *cell->pchosen = nth;
                    }

                  child = child->next_sibling;
                  nth += 1;
                }

              if (*cell->pchosen == -1)
                {
                  if (!(optional & SSH_ASN1_OPTIONAL))
                    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
                  else
                    {
                      optional |= SSH_ASN1_OPTIONAL_FAILED;
                      break;
                    }
                }
              else
                {
                  /* Something was found. */
                  status = SSH_ASN1_STATUS_OK;
                }
              break;

            case SSH_ASN1_DEFEXT_OPTIONAL:
              if (optional & SSH_ASN1_OPTIONAL_FAILED)
                {
                  *cell->pboolval = FALSE;
                  break;
                }
              if (current)
                status =
                  asn1assign(context, current, cell->next_child,
                             tagged, untagged,
                             choice,
                             SSH_ASN1_OPTIONAL|(optional &
                                                SSH_ASN1_OPTIONAL_FAILED),
                             freelist);
              else
                status = SSH_ASN1_STATUS_MATCH_NOT_FOUND;

              if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND)
                {
                  optional |= SSH_ASN1_OPTIONAL_FAILED;
                  *cell->pboolval = FALSE;
                  break;
                }
              if (status != SSH_ASN1_STATUS_OK)
                {
                  *cell->pboolval = FALSE;
                  return status;
                }

              *cell->pboolval = TRUE;
              break;

            default:
              break;
            }
        }

      if (choice)
        return SSH_ASN1_STATUS_OK;

      /* Go to next sibling node */
      cell = cell->next_sibling;
      if (current && !(optional & SSH_ASN1_OPTIONAL_FAILED))
        current = current->next;
      optional &= ~SSH_ASN1_OPTIONAL_FAILED;
    }

  if (optional && status)
    return status;
  return SSH_ASN1_STATUS_OK;
}

/* The reader has a bit different approach than the create routine.
   We do things in two phases. First we assign the addresses from the
   va_list into nodes of the parse-tree at `cell'. The we take a
   second pass (that now can be recursive) to assing the actual values
   the these addresses. */
static SshAsn1Status asn1readnode(SshAsn1Context context,
                                  SshAsn1Node node,
                                  SshAsn1FormatNode cell, va_list ap)
{
  SshAsn1FormatNode prev = NULL, rootcell = cell;
  const SshAsn1Defs *def;
  int level = 0;

  while (1)
    {
      while (1)
        {
          if (cell->def)
            {
              def = cell->def;

              switch (def->extended)
                {
                case SSH_ASN1_DEFEXT_CHOICE:
                  cell->pchosen = va_arg(ap, SshInt32 *);
                  break;
                case SSH_ASN1_DEFEXT_OPTIONAL:
                  cell->pboolval = va_arg(ap, Boolean *);
                  break;
                case SSH_ASN1_DEFEXT_NODE:
                  cell->panyval = va_arg(ap, SshAsn1Node *);
                  break;
                case SSH_ASN1_DEFEXT_NONE:
                  switch (def->type)
                    {
                    case SSH_ASN1_DEF_BOOLEAN:
                      cell->pboolval = va_arg(ap, Boolean *);
                      break;
                    case SSH_ASN1_DEF_SHORT:
                      cell->pshortval = va_arg(ap, SshWord *);
                      break;
                    case SSH_ASN1_DEF_INT:
                      cell->pintval = va_arg(ap, SshMPInteger);
                      break;
                    case SSH_ASN1_DEF_OID:
                      cell->poidval = va_arg(ap, char **);
                      break;
                    case SSH_ASN1_DEF_TIME:
                      cell->ptimeval = va_arg(ap, SshBerTime );
                      break;
                    case SSH_ASN1_DEF_STRING:
                    case SSH_ASN1_DEF_BIT_STRING:
                      cell->pstrval = va_arg(ap, unsigned char **);
                      cell->plenval = va_arg(ap, size_t *);
                      break;
                    case SSH_ASN1_DEF_NONE:
                    case SSH_ASN1_DEF_NULL:
                      break;
                    }
                }
            }
          FOLLOW_CHILD(cell, prev, level);
        }
      BACKUP(cell, prev, level);
    }
 traversed:
  {
    SshBerFreeListStruct *list = NULL;
    SshAsn1Status status = SSH_ASN1_STATUS_ERROR;

    status = asn1assign(context,
                        node, rootcell,
                        SSH_ASN1_RULE_SCAN_ALL, SSH_ASN1_RULE_SCAN_FWD,
                        FALSE, 0, &list);
    ssh_ber_freelist_free(&list,
                          (status == SSH_ASN1_STATUS_OK) ? FALSE: TRUE);
    return status;
  }
}


SshAsn1Status ssh_asn1_read_tree(SshAsn1Context context,
                                 SshAsn1Tree tree,
                                 const char *format, ...)
{
  struct SshAsn1FormatRec port;
  SshAsn1FormatNode head, cell;
  SshAsn1Status status = SSH_ASN1_STATUS_OK;
  va_list ap;

  SSH_DEBUG(SSH_D_MIDSTART, ("ASN.1 read tree with format \"%s\"", format));

  port.offset = 0;
  port.data = format;
  port.cellbag = context->cellbag;
  port.valuebag = context->valuebag;

  if ((head = cell = ssh_fastalloc_alloc(port.cellbag)) == NULL)
    return SSH_ASN1_STATUS_ERROR;
  else
    memset(cell, 0, sizeof(*cell));
  PARSE(port, cell, status);
  if (status == SSH_ASN1_STATUS_OK)
    {
      va_start(ap, format);
      status = asn1readnode(context, tree->current, head, ap);
      va_end(ap);
    }
  asn1freeformat(&port, head);
  return status;
}

SshAsn1Status ssh_asn1_read_node(SshAsn1Context context,
                                 SshAsn1Node node,
                                 const char *format, ...)
{
  struct SshAsn1FormatRec port;
  SshAsn1FormatNode head, cell;
  SshAsn1Status status = 0;
  va_list ap;

  SSH_DEBUG(SSH_D_MIDSTART, ("ASN.1 read node with format \"%s\"", format));

  port.offset = 0;
  port.data = format;
  port.cellbag = context->cellbag;
  port.valuebag = context->valuebag;

  if ((head = cell = ssh_fastalloc_alloc(port.cellbag)) == NULL)
    return SSH_ASN1_STATUS_ERROR;
  else
    memset(cell, 0, sizeof(*cell));
  PARSE(port, cell, status);
  if (status == SSH_ASN1_STATUS_OK)
    {
      va_start(ap, format);
      status = asn1readnode(context, node, head, ap);
      va_end(ap);
    }
  asn1freeformat(&port, head);
  return status;
}

#ifdef DEBUG_LIGHT
void ssh_asn1_print_force_linkage_of_functions(void);

void ssh_asn1_print_force_linkage_of_functions(void)
{
  ssh_asn1_print_tree(NULL);
  ssh_asn1_print_node(NULL);
}
#endif
#endif /* SSHDIST_ASN1 */
