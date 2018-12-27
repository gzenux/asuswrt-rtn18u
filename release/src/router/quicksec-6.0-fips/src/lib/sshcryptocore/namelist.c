/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Computation of the intersection of two lists of names.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshadt.h"
#include "sshadt_list.h"
#include "namelist.h"

#define SSH_DEBUG_MODULE "SshNameList"

/* Tree based approach to parse and compare namelists. */

/* Internal status. */
typedef enum
{
  NTREE_ERROR,
  NTREE_OK,
  NTREE_REMOVE
} NTreeStatus;

/* Internal representation name tree nodes. */
struct SshNameNodeRec
{
  const char *identifier;
  size_t identifier_len;
  int identifier_set;
  struct SshNameNodeRec *next, *prev, *child, *parent;
};

/* Name tree. */
struct SshNameTreeRec
{
  SshNameNode root;
};

/* Allocation and setting up one node. */
SshNameNode ssh_nnode_allocate(void)
{
  SshNameNode node = ssh_malloc(sizeof(*node));

  if (node)
    {
      node->identifier = NULL;
      node->identifier_len = 0;
      node->identifier_set = 1;
      node->next = node->prev = node->child = node->parent = NULL;
    }
  return node;
}

/* Free one node from a tree, so that the tree will still be valid. */
void ssh_nnode_free(SshNameTree tree, SshNameNode thisp)
{
  SshNameNode temp, node = thisp->child;

  while (node && node != thisp)
    {
      if (node->child)
        {
          node = node->child;
          continue;
        }
      if (node->next)
        {
          node->next->prev = NULL;
          temp = node->next;
          ssh_free(node);
          node = temp;
        }
      else
        {
          if (node->parent)
            node->parent->child = NULL;
          temp = node->parent;
          ssh_free(node);
          node = temp;
        }
    }

  if (thisp->parent)
    {
      if (thisp->parent->child == thisp)
        {
          if (thisp->next)
            thisp->parent->child = thisp->next;
          if (thisp->prev)
            thisp->parent->child = thisp->prev;
          if (!thisp->prev && !thisp->next)
            thisp->parent->child = NULL;
        }
    }
  else
    {
      if (tree->root == thisp)
        {
          if (thisp->next)
            tree->root = thisp->next;
          if (thisp->prev)
            tree->root = thisp->prev;
          if (!thisp->next && !thisp->prev)
            tree->root = NULL;
        }
    }
  if (thisp->next)
    thisp->next->prev = thisp->prev;
  if (thisp->prev)
    thisp->prev->next = thisp->next;

  if (!thisp->prev && !thisp->next)
    if (thisp->parent)
      thisp->parent->child = NULL;

  ssh_free(thisp);
}

/* Allocate and initialize an empty tree. */
void ssh_ntree_allocate(SshNameTree *tree)
{
  SshNameTree created = ssh_malloc(sizeof(*created));

  if (created)
    created->root = NULL;
  *tree = created;
}

static void ntree_free_nodes(SshNameTree tree)
{
  SshNameNode node, temp;

  node = tree->root;
  while (node)
    {
      temp = node->next;
      ssh_nnode_free(tree, node);
      node = temp;
    }
}

/* Free a tree. */
void ssh_ntree_free(SshNameTree tree)
{
  if (tree)
    {
      ntree_free_nodes(tree);
      ssh_free(tree);
    }
}

/* Print tree, routine which can be used while testing. Uses given routine
   to print the tree, which should be a-ok. */
void ssh_ntree_print(SshNameTree tree,
                     void (*print_char)(const char byte))
{
  SshNameNode node = tree->root;
  size_t i;
  unsigned int flag = 0;

  while (node)
    {
      if (flag)
        {
          (*print_char)(',');
          flag = 0;
        }
      for (i = 0; i < node->identifier_len; i++)
        (*print_char)(node->identifier[i]);
      if (node->child)
        {
          (*print_char)('{');
          node = node->child;
          continue;
        }
      if (node->next)
        {
          flag = 1;
          node = node->next;
          continue;
        }

      while (node->parent)
        {
          node = node->parent;
          (*print_char)('}');
          flag = 1;
          if (node->next)
            break;
        }
      if (node->next)
        {
          node = node->next;
          continue;
        }
      break;
    }
}

SshNameNode ssh_nnode_find_identifier(SshNameNode node,
                                      const char *identifier)
{
  size_t len = strlen(identifier);
  while (node)
    {
      if (node->identifier_len == len)
        {
          if (memcmp(node->identifier, identifier, len) == 0)
            {
              return node;
            }
        }
      node = node->next;
    }
  return NULL;
}

/* Get identifier out of specific node. */
char *ssh_nnode_get_identifier(SshNameNode node)
{
  return node ? ssh_memdup(node->identifier, node->identifier_len) : NULL;
}

const char *ssh_nnode_get_identifier_pointer(SshNameNode node, size_t *len)
{
  *len = node->identifier_len;
  return node->identifier;
}

/* Add a child node. */
SshNameNode
ssh_ntree_add_child(SshNameTree tree,
                    SshNameNode node, const char *identifier)
{
  SshNameNode temp = ssh_nnode_allocate();

  if (temp)
    {
      if (tree->root == NULL)
        {
          tree->root = temp;
        }
      else
        {
          temp->parent = node;
          node->child = temp;
        }

      temp->identifier = identifier;
      temp->identifier_len = strlen(identifier);
    }
  return temp;
}

/* Add a node to a list. */
SshNameNode ssh_ntree_add_next(SshNameTree tree, SshNameNode node,
                               const char *identifier)
{
  SshNameNode temp = ssh_nnode_allocate();

  if (tree->root == NULL)
    {
      tree->root = temp;
    }
  else
    {
      if (node->next)
        node->next->prev = temp;
      temp->next = node->next;
      temp->parent = node->parent;
      temp->prev = node;
      node->next = temp;
    }
  temp->identifier = identifier;
  temp->identifier_len = strlen(identifier);

  return temp;
}

SshNameNode ssh_nnode_get_parent(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->parent;
}

SshNameNode ssh_nnode_get_child(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->child;
}

SshNameNode ssh_nnode_get_next(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->next;
}

SshNameNode ssh_nnode_get_prev(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->prev;
}

SshNameNode ssh_ntree_get_root(SshNameTree tree)
{
  if (tree == NULL)
    return NULL;
  return tree->root;
}

/* Parse given namelist and get a tree out of it. Uses the tree to avoid
   code recursion. Returns SSH_NTREE_ERROR if namelist can't be parsed, or
   does not follow specifications. */
SshNameTreeStatus ssh_ntree_parse(const char *namelist, SshNameTree tree)
{
  size_t i, len, start_of_identifier;
  SshNameNode node, prev, parent;
  unsigned int flag;
#define FLAG_ID         1
#define FLAG_COMMA      2
#define FLAG_OPEN       4
#define FLAG_CLOSE      8
  int level = 0;

  if (namelist == NULL || tree == NULL)
    return SSH_NTREE_ERROR;

  len = strlen(namelist);

  if (len == 0)
    return SSH_NTREE_OK;

  /* Initialize state variables. */
  flag = FLAG_ID;
  parent = NULL;
  prev = NULL;
  if ((node = ssh_nnode_allocate()) == NULL)
    return SSH_NTREE_ERROR;

  tree->root = node;
  start_of_identifier = 0;

  /* Run through namelist one character at a time. */
  for (i = 0; i < len; i++)
    {
      switch (namelist[i])
        {
          /* Handle identifier after comma. As always check that this is
             valid operation, and set the previous identifier length
             correctly.

             For the next node set prev field, and for the prev node set
             the next field. Set parent. Set flag for what to expect next.
             This is correct, because one gets here only if node before
             exists.
             */

        case ',':
          if ((flag & FLAG_COMMA) != FLAG_COMMA)
            return SSH_NTREE_ERROR;
          if (node->identifier_set == 0)
            {
              node->identifier_len = i - start_of_identifier;
              node->identifier_set = 1;
            }
          prev = node;
          if ((node = ssh_nnode_allocate()) == NULL)
            {
              ntree_free_nodes(tree);
              return SSH_NTREE_ERROR;
            }
          node->prev = prev;
          prev->next = node;
          node->parent = parent;
          flag = FLAG_ID;
          break;
          /* Handle opening parenthesis. Check that not too many levels
             are being build; which would be error. Start also a new
             list for the child node. Assume that only identifier can
             follow this mark. */
        case '{':
          if ((flag & FLAG_OPEN) != FLAG_OPEN)
            return SSH_NTREE_ERROR;

          if (++level > SSH_NTREE_MAX_LEVEL)
            return SSH_NTREE_ERROR;

          if (node->identifier_set == 0)
            {
              node->identifier_len = i - start_of_identifier;
              node->identifier_set = 1;
            }
          parent = node;
          if ((node = ssh_nnode_allocate()) == NULL)
            {
              ntree_free_nodes(tree);
              return SSH_NTREE_ERROR;
            }

          node->parent = parent;
          parent->child = node;
          flag = FLAG_ID;
          break;
          /* Handle closing parenthesis. */
        case '}':
          if ((flag & FLAG_CLOSE) != FLAG_CLOSE)
            return SSH_NTREE_ERROR;
          if (!node->parent)
            return SSH_NTREE_ERROR;

          if (--level < 0)
            return SSH_NTREE_ERROR;

          if (node->identifier_set == 0)
            {
              node->identifier_len = i - start_of_identifier;
              node->identifier_set = 1;
            }
          node = node->parent;
          parent = node->parent;
          flag = FLAG_COMMA | FLAG_CLOSE;
          break;
          /* Handle as a default case letters of the identifier. */
        default:
          if ((flag & FLAG_ID) != FLAG_ID)
            return SSH_NTREE_ERROR;
          if (node->identifier == NULL)
            {
              node->identifier = &namelist[i];
              start_of_identifier = i;
              node->identifier_set = 0;
            }
          flag = FLAG_ID | FLAG_OPEN | FLAG_CLOSE | FLAG_COMMA;
          break;
        }
    }
  /* Unclosed parenthesis. */
  if (level)
    return SSH_NTREE_ERROR;

  if (node->identifier_set == 0)
    node->identifier_len = i - start_of_identifier;

#undef FLAG_ID
#undef FLAG_OPEN
#undef FLAG_CLOSE
#undef FLAG_COMMA

  return SSH_NTREE_OK;
}

/* Copy src tree to dest tree. Assumes dest to be empty. */
void ssh_ntree_copy(SshNameTree dest, SshNameTree src)
{
  SshNameNode src_node, dest_node, prev, parent;

  src_node = src->root;
  dest_node = NULL;
  parent = NULL;
  prev = NULL;
  while (src_node)
    {
      dest_node = ssh_nnode_allocate();
      dest_node->identifier = src_node->identifier;
      dest_node->identifier_len = src_node->identifier_len;
      dest_node->identifier_set = src_node->identifier_set;
      dest_node->parent = parent;
      dest_node->prev = prev;

      if (!dest->root)
        {
          dest->root = dest_node;
        }
      else
      if (prev)
        {
          prev->next = dest_node;
        }
      else
      if (parent && !parent->child)
        {
            parent->child = dest_node;
        }
      else
        SSH_NOTREACHED;

      if (src_node->child)
        {
          parent = dest_node;
          src_node = src_node->child;
          prev = NULL;
          continue;
        }
      if (src_node->next)
        {
          src_node = src_node->next;
          prev = dest_node;
          continue;
        }
      dest_node = dest_node->parent;
      prev = dest_node;
      src_node = src_node->parent;
      if (src_node)
        src_node = src_node->next;
      if (dest_node)
        parent = dest_node->parent;
      else
        parent = NULL;
    }
}

/* Compute intersection between two trees. The recursive routine. */
NTreeStatus ssh_ntree_intersection_recurse(SshNameNode a,
                                           SshNameNode b,
                                           SshNameTree a_tree)
{
  SshNameNode temp, match;
  NTreeStatus status;

  while (a)
    {
      status = NTREE_OK;
      match = NULL;
      temp = b;
      while (temp)
        {
          if (a->identifier_len == temp->identifier_len)
            {
              if (memcmp(a->identifier, temp->identifier,
                         a->identifier_len) == 0)
                {
                  /* We are currently allowing the same element multiple
                     times in a list. */
                  if (match == NULL)
                    match = temp;
                }
            }
          temp = temp->next;
        }

      if (match)
        {
          if (a->child && !match->child)
            status = NTREE_REMOVE;
          if (!a->child && match->child)
            status = NTREE_REMOVE;
          if (a->child && match->child)
            status = ssh_ntree_intersection_recurse(a->child, match->child,
                                                    a_tree);
        }

      /* Matched? */
      if (!match)
        status = NTREE_REMOVE;

      switch (status)
        {
        case NTREE_ERROR:
          return NTREE_ERROR;
          break;
        case NTREE_REMOVE:
          temp = a->next;
          if (a->prev || a->next)
            ssh_nnode_free(a_tree, a);
          else
            return NTREE_REMOVE;
          break;
        default:
          temp = a->next;
          break;
        }
      a = temp;
    }
  return NTREE_OK;
}

/* Compute intersection between a and b. Returns intersection in ret,
   a and b unchanged. */
SshNameTreeStatus ssh_ntree_intersection(SshNameTree ret,
                                         SshNameTree a, SshNameTree b)
{
  ssh_ntree_copy(ret, a);

  switch (ssh_ntree_intersection_recurse(ret->root, b->root, ret))
    {
    case NTREE_OK:
      break;
    case NTREE_ERROR:
      return SSH_NTREE_ERROR;
      break;
    case NTREE_REMOVE:
      ssh_nnode_free(ret, ret->root);
      break;
    default:
      break;
    }
  return SSH_NTREE_OK;
}


/* Function expands the given tree of form:

   a{b{c{d...},d{e...}}},...

   into

   a-b-c-d,a-b-d-e,...

   */

/* This is the hard case. Using a function parse_name() which parses
   one name into a list which can then be added to the tree. However
   it is quite a lot of work in itself. */
char *ssh_ntree_transform_list_to_tree(char *namelist,
                                       SshNameNode parse_name(const char *str,
                                                              size_t len))
{
  SshNameTree tree, list;
  SshNameNode node, temp, level, tmp;
  SshADTContainer stack;
  SshADTHandle h;
  char *ret = NULL;

  stack = ssh_adt_create_generic(SSH_ADT_LIST,
                                 /*SSH_ADT_SIZE, sizeof(SshNameNode),*/
                                 SSH_ADT_ARGS_END);

  if (!stack)
    return NULL;

  /* We assume that the given parameter is actually a list, but then you
     never know. */
  ssh_ntree_allocate(&list);
  if (ssh_ntree_parse(namelist, list) != SSH_NTREE_OK)
    {
      ssh_adt_destroy(stack);
      ssh_ntree_free(list);
      return NULL;
    }

  node = list->root;
  level = NULL;
  ssh_ntree_allocate(&tree);

  while (node)
    {
      temp = parse_name(node->identifier, node->identifier_len);

      if (temp == NULL)
        goto failure;

      /* Add to the tree. */
      if (level)
        {
          tmp = level;
          while (tmp)
            {
              if (tmp->identifier_len == temp->identifier_len)
                {
                  if (memcmp(tmp->identifier, temp->identifier,
                             tmp->identifier_len) == 0)
                    {
                      /* Match found. */

                      if (tmp->child == NULL)
                        {
                          tmp->child = temp;
                          temp->parent = tmp;
                          break;
                        }

                      tmp = tmp->child;
                      temp = temp->child;
                      continue;
                    }
                }

              if (tmp->next == NULL)
                {
                  tmp->next = temp;
                  temp->prev = tmp;
                  temp->parent = tmp->parent;
                  break;
                }
              tmp = tmp->next;
            }
          /* We have now interleaved the generated name "list" into our
             tree. */
        }
      else
        {
          if (tree->root == NULL)
            tree->root = temp;
          else
            {
              h = ssh_adt_get_handle_to_location(stack, SSH_ADT_END);
              SSH_ASSERT(h != SSH_ADT_INVALID);
              temp->parent = (SshNameNode) ssh_adt_get(stack, h);
            }
          level = temp;
        }

      if (node->child)
        {
          node = node->child;
          h = ssh_adt_insert_to(stack, SSH_ADT_END, level);

          if (h == SSH_ADT_INVALID)
            goto failure;

          level = NULL;
          continue;
        }

      if (node->next)
        {
          node = node->next;
          continue;
        }

      while (node)
        {
          if (node->next)
            {
              node = node->next;
              break;
            }

          node = node->parent;

          h = ssh_adt_get_handle_to_location(stack, SSH_ADT_END);
          SSH_ASSERT(h != SSH_ADT_INVALID);
          level = ssh_adt_get(stack, h);
          ssh_adt_detach(stack, h);
        }
    }

  /* Make a string out of the input, this should now be correctly
     transformed. */
  ssh_ntree_generate_string(tree, &ret);

 failure:

  ssh_adt_destroy(stack);
  ssh_ntree_free(tree);
  ssh_ntree_free(list);

  return ret;
}

/* This one of the transform functions is the easier, nothing is
   needed to know of the format. */

char *ssh_ntree_transform_tree_to_list(char *nametree)
{
  SshBufferStruct buffer;
  SshNameTree tree;
  SshNameNode node, temp;
  SshADTContainer stack;
  SshADTHandle h;
  unsigned int count;
  char *ret = NULL;

  stack = ssh_adt_create_generic(SSH_ADT_LIST,
                                 /*SSH_ADT_SIZE, sizeof(SshNameNode),*/
                                 SSH_ADT_ARGS_END);

  if (stack == NULL)
    return NULL;

  ssh_ntree_allocate(&tree);

  if (tree == NULL)
    {
      ssh_adt_destroy(stack);
      return NULL;
    }

  if (ssh_ntree_parse(nametree, tree) != SSH_NTREE_OK)
    {
      ssh_adt_destroy(stack);
      ssh_ntree_free(tree);
      return NULL;
    }

  ssh_buffer_init(&buffer);

  node = tree->root;
  while (node)
    {
      if (node->child)
        {
          node = node->child;
          continue;
        }

      /* Append one full string into buffer. */

      /* First find out how long this thing actually is. */
      temp = node;
      while (temp)
        {
          h = ssh_adt_insert_to(stack, SSH_ADT_END, temp);

          if (h == SSH_ADT_INVALID)
            goto failure;

          temp = temp->parent;
        }

      /* Then loop back using the stack. */
      count = 0;
      /*      while (ssh_dstack_exists(&stack))*/
      while (ssh_adt_num_objects(stack) > 0)
        {
          if (count > 0)
            {
              if (ssh_buffer_append(&buffer, (unsigned char *) "-", 1)
                  != SSH_BUFFER_OK)
                goto failure;
            }
          count++;
          h = ssh_adt_get_handle_to_location(stack, SSH_ADT_END);
          SSH_ASSERT(h != SSH_ADT_INVALID);
          temp = ssh_adt_get(stack, h);
          ssh_adt_detach(stack, h);

          if (ssh_buffer_append(&buffer,
                                (unsigned char *) temp->identifier,
                                temp->identifier_len) != SSH_BUFFER_OK)
            goto failure;
        }

      /* Move to next first. */
      if (node->next)
        {
          node = node->next;
          continue;
        }

      /* If can't move to next then try one back and to there next. */
      while (node)
        {
          if (node->next)
            {
              node = node->next;
              break;
            }
          node = node->parent;
        }

      /* Here you either have it (that is non-null node) or don't. */
    }

  /* Final touches. */
  if (ssh_buffer_append(&buffer, (unsigned char *) "\0", 1) == SSH_BUFFER_OK)
    ret = ssh_strdup(ssh_buffer_ptr(&buffer));

 failure:
  /*while (ssh_dstack_exists(&stack)) ssh_dstack_pop(&stack);*/

  ssh_adt_destroy(stack);
  ssh_ntree_free(tree);
  ssh_buffer_uninit(&buffer);

  return ret;
}

/* Get a namelist string from given tree. */
void ssh_ntree_generate_string(SshNameTree tree, char **namelist)
{
  SshBufferStruct buffer;
  SshNameNode node;
  unsigned int flag = 0;

  *namelist = NULL;

  ssh_buffer_init(&buffer);

  node = tree->root;
  while (node)
    {
      if (flag)
        {
          if (ssh_buffer_append(&buffer, (unsigned char *) ",", 1)
              != SSH_BUFFER_OK)
            goto failure;
          flag = 0;
        }

      if (ssh_buffer_append(&buffer, (unsigned char *) node->identifier,
                            node->identifier_len) != SSH_BUFFER_OK)
        goto failure;

      if (node->child)
        {
          node = node->child;

          if (ssh_buffer_append(&buffer, (unsigned char *) "{", 1)
              != SSH_BUFFER_OK)
            goto failure;

          continue;
        }
      if (node->next)
        {
          node = node->next;
          flag = 1;
          continue;
        }
      while (node->parent)
        {
          node = node->parent;
          if (ssh_buffer_append(&buffer, (unsigned char *) "}", 1)
              != SSH_BUFFER_OK)
            goto failure;

          flag = 1;
          if (node->next)
            break;
        }
      if (node->next)
        {
          node = node->next;
          continue;
        }
      break;
    }

  if (ssh_buffer_append(&buffer, (unsigned char *) "\0", 1) == SSH_BUFFER_OK)
    *namelist = ssh_strdup(ssh_buffer_ptr(&buffer));

 failure:
  ssh_buffer_uninit(&buffer);
}

/* Compute intersection using tree approach, which is more general, but
   takes lots of memory and time. */

char *ssh_name_list_intersection(const char *src1, const char *src2)
{
  SshNameTree a, b, c;
  char *tmp = NULL;

  /* Initialize tree's. */
  ssh_ntree_allocate(&a);
  ssh_ntree_allocate(&b);
  ssh_ntree_allocate(&c);

  if (a && b && c)
    {
      /* Parse, parse, compute intersection and output suitable
         string. */
      if (ssh_ntree_parse(src1, a) != SSH_NTREE_OK)
        goto failure;
      if (ssh_ntree_parse(src2, b) != SSH_NTREE_OK)
        goto failure;
      if (ssh_ntree_intersection(c, a, b) != SSH_NTREE_OK)
        goto failure;

      ssh_ntree_generate_string(c, &tmp);
    }

 failure:
  ssh_ntree_free(a);
  ssh_ntree_free(b);
  ssh_ntree_free(c);
  return tmp;
}

/* Implemented for backward compatibility. */
char *ssh_name_list_get_name(const char *namelist)
{
  SshNameTree tree;
  SshNameNode node, temp;
  char *tmp;

  ssh_ntree_allocate(&tree);
  if (tree == NULL ||
      ssh_ntree_parse(namelist, tree) != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return NULL;
    }

  node = ssh_ntree_get_root(tree);
  node = ssh_nnode_get_next(node);
  while (node)
    {
      temp = ssh_nnode_get_next(node);
      ssh_nnode_free(tree, node);
      node = temp;
    }
  ssh_ntree_generate_string(tree, &tmp);
  ssh_ntree_free(tree);

  return tmp;
}

const char *ssh_name_list_step_forward(const char *namelist)
{
  SshNameTree tree;
  SshNameNode node;
  const char *tmp;
  size_t len;

  ssh_ntree_allocate(&tree);
  if (tree == NULL)
    return NULL;

  if (ssh_ntree_parse(namelist, tree) != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return NULL;
    }

  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return NULL;
    }
  node = ssh_nnode_get_next(node);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return NULL;
    }
  tmp = ssh_nnode_get_identifier_pointer(node, &len);
  ssh_ntree_free(tree);

  return tmp;
}
