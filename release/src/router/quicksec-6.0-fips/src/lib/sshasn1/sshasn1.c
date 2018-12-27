/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of an ASN.1 BER/DER parser/encoder. This is
   block, not stream oriented.
*/

#include "sshincludes.h"
#include "sshobstack.h"
#include "sshber.h"
#include "sshasn1.h"
#include "sshasn1i.h"

#ifdef SSHDIST_ASN1

/*************** Internal memory management *************/

#define SSH_DEBUG_MODULE "SshAsn1"

/* Allocate and initialize Asn.1 context. */

SshAsn1Context ssh_asn1_init(void)
{
  SshAsn1Context created = ssh_calloc(1, sizeof(*created));

  if (created)
    {
      created->obstack = ssh_obstack_create(NULL);
      if (created->obstack == NULL)
        goto failed;

      created->valuebag = ssh_fastalloc_initialize(ASN1_MAX_TOKEN_LEN, 50);
      if (created->valuebag == NULL)
        goto failed;

      created->cellbag =
        ssh_fastalloc_initialize(sizeof(struct SshAsn1FormatNodeRec), 100);
      if (created->cellbag == NULL)
        {
        failed:
          ssh_asn1_free(created);
          return NULL;
        }
      ssh_asn1_set_limits(created,
                          SSH_BER_DECODE_MAX_INPUT_SIZE,
                          SSH_BER_DECODE_STACK_DEPTH);
    }
  return created;
}

void ssh_asn1_set_limits(SshAsn1Context context,
                         size_t max_input_length,
                         size_t max_input_nesting)
{
  if (max_input_length)
    context->max_input_length = max_input_length;
  if (max_input_nesting)
    context->max_input_nesting = max_input_nesting;
}
/* Free Asn.1 context and all data that might have been allocated
   under it. */

void ssh_asn1_free(SshAsn1Context context)
{
  if (context)
    {
      if (context->cellbag)
        ssh_fastalloc_uninitialize(context->cellbag);
      if (context->valuebag)
        ssh_fastalloc_uninitialize(context->valuebag);
      if (context->obstack)
        ssh_obstack_destroy(context->obstack);
    }
  ssh_free(context);
}

/* Allocate memory from context structure. */

static unsigned char *
ssh_asn1_malloc_b(SshAsn1Context context, size_t size)
{
  return ssh_obstack_alloc_unaligned(context->obstack, size);
}

static void *
ssh_asn1_malloc_s(SshAsn1Context context, size_t size)
{
  return ssh_obstack_alloc(context->obstack, size);
}

/************** Tree decoding and encoding from/to BER **************/

/* Decode given BER/DER buffer recursively to a Asn.1 tree. */

static SshAsn1Status
ssh_asn1_decode_recurse(SshAsn1Context context,
                        unsigned char *buf, size_t len,
                        SshAsn1Node *first, SshAsn1Node parent,
                        size_t *next_step,
                        size_t level)
{
  SshAsn1Node node, prev;
  SshAsn1Status status;
  SshBerStatus ber_status;
  size_t error_len;
  SshAsn1Class classp;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  size_t length, tag_length, step;
  unsigned char *data, *tag;

  /* Get some defaults and error detection. */
  prev       = NULL;
  error_len  = len;
  step       = 0;

  if (level > context->max_input_nesting)
    return SSH_ASN1_STATUS_BER_DECODE_FAILED;

  while (len && len <= error_len)
    {
      /* Open the BER element to a opened form. Note that this means
         just placing the pointer to the buffer correctly. This also
         verifies, that encoded length value is within buffer
         boundaries. */
      ber_status = ssh_ber_open_element(buf, len,
                                        &classp, &encoding,
                                        &tag_number, &length_encoding,
                                        &tag_length,
                                        &tag,
                                        &length,
                                        &data);

      SSH_DEBUG(SSH_D_MIDRESULT,
                ("BER: %s class %d encoding %d data (%d)",
                 ber_status == 0 ? "OK" : "FAILURE",
                 classp, encoding, length));

      if (ber_status != SSH_BER_STATUS_OK)
        {
          if (parent == NULL && *first)
            return SSH_ASN1_STATUS_OK_GARBAGE_AT_END;

          return SSH_ASN1_STATUS_BER_OPEN_FAILED;
        }

      SSH_DEBUG_HEXDUMP(12, ("data"), data, length);

      buf  += tag_length;
      len  -= tag_length;
      step += tag_length;

      /* Handle the end-of-contents octets. */
      if (classp == SSH_ASN1_CLASS_UNIVERSAL &&
          encoding == SSH_ASN1_ENCODING_PRIMITIVE &&
          tag_number == 0)
        {
          if (len - length > error_len)
            {
              if (parent == NULL && *first)
                return SSH_ASN1_STATUS_OK_GARBAGE_AT_END;
              return SSH_ASN1_STATUS_BUFFER_OVERFLOW;
            }

          if (next_step == NULL)
            {
              /* This is an error, but some applications may want to
                 still look up the remains. */
              return SSH_ASN1_STATUS_BAD_GARBAGE_AT_END;
            }

          *next_step = step;
          return SSH_ASN1_STATUS_OK;
        }

      /* Allocate new node to place the data to be read. */
      node = ssh_asn1_malloc_s(context, sizeof(*node));
      if (node == NULL)
        {
          return SSH_ASN1_STATUS_OPERATION_FAILED;
        }

      node->next = node->prev = node->child = NULL;

      /* Set up the node. */
      node->classp = classp;
      node->encoding = encoding;
      node->tag_number = tag_number;
      node->length_encoding = length_encoding;
      node->tag_length = tag_length;
      node->tag = tag;
      node->length = length;
      node->data = data;
      node->parent = parent;

      /* Check if child actually do exist. */
      if (node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED)
        {
          /* Recursively decode childs. */
          if (node->length_encoding == SSH_ASN1_LENGTH_DEFINITE)
            {
              status = ssh_asn1_decode_recurse(context,
                                               node->data,
                                               node->length,
                                               &node->child,
                                               node,
                                               NULL,
                                               level + 1);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  /* If we have actually found out something, but
                     failed in some deep valley we still might want to
                     read about these things. */
                  if (parent == NULL && *first)
                    return SSH_ASN1_STATUS_BAD_GARBAGE_AT_END;
                  return status;
                }
            }
          else
            {
              size_t node_step;

              /* Now run through the contents. Here we want to keep
                 track of the size, as we currently haven't got the
                 any idea. */
              status = ssh_asn1_decode_recurse(context,
                                               node->data,
                                               len,
                                               &node->child,
                                               node,
                                               &node_step,
                                               level + 1);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  /* If we have actually found out something, but
                     failed in some deep valley we still might want to
                     read about these things. */
                  if (parent == NULL && *first)
                    return SSH_ASN1_STATUS_BAD_GARBAGE_AT_END;
                  return status;
                }

              /* Fix the sizes. This helps the error detection routine. */
              node->length = node_step;
              length       = node_step;
            }
        }

      /* If previous node is available then link accordingly. */
      if (prev)
        {
          node->prev = prev;
          prev->next = node;
        }
      else
        {
          /* Set as parent if no other has yet been set. */
          if (*first == NULL)
            *first = node;
        }
      prev = node;

      /* Step over element. */
      buf  += length;
      len  -= length;
      step += length;

      /* Simple check for errors. */
      if (len > error_len)
        return SSH_ASN1_STATUS_BUFFER_OVERFLOW;
    }

  if (next_step)
    return SSH_ASN1_STATUS_BUFFER_OVERFLOW;

  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status ssh_asn1_decode(SshAsn1Context context,
                              const unsigned char *buf, size_t len,
                              SshAsn1Tree *tree)
{
  SshAsn1Status status;

  if (len == 0)
    return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
  if (len > context->max_input_length)
    return SSH_ASN1_STATUS_BUFFER_OVERFLOW;

  /* Allocate for a new tree. */
  *tree = ssh_asn1_init_tree(context, NULL, NULL);
  if (*tree == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  (*tree)->data = ssh_asn1_malloc_b(context, len);
  if ((*tree)->data == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  (*tree)->length = len;
  memcpy((*tree)->data, buf, (*tree)->length);

  status = ssh_asn1_decode_recurse(context,
                                   (*tree)->data, (*tree)->length,
                                   &(*tree)->root, NULL,
                                   NULL,
                                   0);

  /* Set current also to point at the tree. */
  (*tree)->current = (*tree)->root;

  return status;
}

SshAsn1Status ssh_asn1_decode_node(SshAsn1Context context,
                                   const unsigned char *buf, size_t len,
                                   SshAsn1Node *node)
{
  unsigned char *data;
  SshAsn1Status status;

  if (len == 0)
    return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
  if (len > context->max_input_length)
    return SSH_ASN1_STATUS_BUFFER_OVERFLOW;

  /* Initialize the node. */
  *node = NULL;

  /* Allocate buffer for the data. */
  data = ssh_asn1_malloc_b(context, len);
  if (data == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  memcpy(data, buf, len);

  /* Decode recursively. */
  status = ssh_asn1_decode_recurse(context, data, len, node, NULL, NULL, 0);
  return status;
}

/* Count length of actual BER encoded tree or subtree. */

size_t ssh_asn1_count_length(SshAsn1Node node)
{
  size_t len = 0;

  while (node)
    {
      /* If constructed then count the childs too. */
      if (node->data == NULL &&
          node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED)
        {
          node->length = ssh_asn1_count_length(node->child);

          /* Add space for end-of-contents octets. */
          if (node->length_encoding == SSH_ASN1_LENGTH_INDEFINITE)
            node->length += 2;

          /* Compute now the tag length. */
          node->tag_length = ssh_ber_compute_tag_length(node->classp,
                                                        node->encoding,
                                                        node->tag_number,
                                                        node->length_encoding,
                                                        node->length);

        }

      /* Increase the total length. */
      len += node->tag_length + node->length;
      node = node->next;
    }

  return len;
}

/* Recursively compose the buffer with BER encoded data from the Asn.1
   tree. */

static SshAsn1Status
ssh_asn1_encode_recurse(SshAsn1Context context,
                        SshAsn1Node first,
                        unsigned char *buf, size_t len)
{
  SshAsn1Status status;
  SshBerStatus ber_status;
  SshAsn1Node node;

  node = first;

  while (node)
    {
      if (node->data != NULL || node->encoding == SSH_ASN1_ENCODING_PRIMITIVE)
        {
          /* This element contains unchanged childs (or is primitive)
             and thus can be simply copied to the buffer (i.e. closed). */

          if (node->data != NULL && node->tag_length + node->length <= len)
            {
              memcpy(buf, node->tag, node->tag_length);
              memcpy(buf + node->tag_length, node->data, node->length);

              node->tag = buf;
              node->data = buf + node->tag_length;
            }
          else
            {
              return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
        }
      else
        {
          /* Compute tag length. */

          if (node->tag_length > len)
            {
              return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
            }

          /* Recursively compose child lists. */
          status = ssh_asn1_encode_recurse(context, node->child,
                                           buf + node->tag_length,
                                           len - node->tag_length);

          if (status != SSH_ASN1_STATUS_OK)
            return status;

          if (node->length_encoding == SSH_ASN1_LENGTH_INDEFINITE)
            {
              if (len < 2)
                {
                  return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
                }

              /* Add end-of-contents octets to the buffer. */
              buf[node->tag_length + node->length - 2] = 0x0;
              buf[node->tag_length + node->length - 1] = 0x0;
            }

          /* This node contains no encoded tag's because it contains no
             contents :) Thus we are forced to build some. */

          node->tag = buf;
          node->data = buf + node->tag_length;
          ber_status = ssh_ber_set_tag(node->tag, node->tag_length,
                                       node->classp, node->encoding,
                                       node->tag_number, node->length_encoding,
                                       node->length);

          if (ber_status != SSH_BER_STATUS_OK)
            return SSH_ASN1_STATUS_BER_CLOSE_FAILED;
        }

      /* Jump over the just encoded element. */
      buf += node->tag_length + node->length;
      len -= node->tag_length + node->length;

      node = node->next;
    }

  return SSH_ASN1_STATUS_OK;
}

int ssh_asn1_node_compare(SshAsn1Node n1, SshAsn1Node n2)
{
  size_t temp1_len, temp2_len, temp_len;
  int rv;

  /* Compute lengths. */
  temp1_len = n1->tag_length + n1->length;
  temp2_len = n2->tag_length + n2->length;

  /* Check if either is larger. */

  if (temp1_len >= temp2_len)
    temp_len = temp2_len;
  else
    temp_len = temp1_len;

  /* Compare. */
  rv = memcmp(n1->tag, n2->tag, temp_len);

  /* Check for padding. */
  if (rv == 0)
    {
      if (temp1_len > temp2_len)
        rv = 1;
      if (temp2_len > temp1_len)
        rv = -1;
    }

  return rv;
}

/* Sort with delayed move. Methods such are qsort or radix sort are quicker,
   but take more coding and this should be fine. */

SshAsn1Node ssh_asn1_sort_list(SshAsn1Context context,
                               SshAsn1Node first)
{
  SshAsn1Node node, min, step;
  size_t size;
  unsigned char *buf;

  /* Sort the trivial case. */
  if (first == NULL)
    return NULL;

  /* Encode all data before sorting. */
  size = ssh_asn1_count_length(first);

  buf = ssh_asn1_malloc_b(context, size);
  if (buf == NULL)
    return NULL;

  if (ssh_asn1_encode_recurse(context,
                              first, buf, size) != SSH_ASN1_STATUS_OK)
    return NULL;

  /* Defaults. */
  step = first;

  /* Sort nodes. */
  while (step)
    {
      /* Search the least... */
      node = step;
      min = step;
      while (node->next)
        {
          if (ssh_asn1_node_compare(min, node->next) > 0)
            min = node->next;
          node = node->next;
        }

      if (min != step)
        {
          /* Detach min. */
          if (min->prev)
            min->prev->next = min->next;
          if (min->next)
            min->next->prev = min->prev;

          /* Append min. */
          min->prev = step->prev;
          min->next = step;

          if (step->prev)
            step->prev->next = min;
          else
            {
              /* Now the step must be the first in row and thus
                 the parent must point to it. We however want that
                 the parent points to the first in row so set min there. */
              if (step->parent)
                step->parent->child = min;
              first = min;
            }
          step->prev = min;
        }
      else
        step = step->next;
    }

  /* Nodes are now in order. */
#ifdef DEBUG_LIGHT
  {
    SshAsn1Node t = first;
    SSH_DEBUG(10, ("Verifying the sort"));
    while (t && t->next)
      {
        SSH_ASSERT(ssh_asn1_node_compare(t, t->next) < 0);
        t = t->next;
      }
  }
#endif /* DEBUG_LIGHT */

  return first;
}

/* Generic encoding of the Asn.1 tree to the BER byte code. */

SshAsn1Status ssh_asn1_encode(SshAsn1Context context,
                              SshAsn1Tree tree)
{
  SshAsn1Node root = tree->root;
  SshAsn1Status status;

  if (root == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;

  /* Compute the tree length when composed as BER byte code. */
  tree->length = ssh_asn1_count_length(root);

  if ((tree->data = ssh_asn1_malloc_b(context, tree->length)) == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  memset(tree->data, 0, tree->length);

  /* Compose the actual BER byte code. */
  status = ssh_asn1_encode_recurse(context, root, tree->data, tree->length);
  return status;
}

/* Encode starting from some specific node. */

SshAsn1Status ssh_asn1_encode_node(SshAsn1Context context,
                                   SshAsn1Node parent)
{
  SshBerStatus ber_status;
  SshAsn1Status status;

  if (parent == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;

  if (parent->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
    {
      /* This is a primitive. The data is set to the node ok. */
      return SSH_ASN1_STATUS_OK;
    }

  /* Compute the tree length when composed as BER byte code. */
  ssh_asn1_count_length(parent);

  /* Allocate new buffer for everything. */
  if ((parent->tag =
       ssh_asn1_malloc_b(context, parent->tag_length + parent->length))
      == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  parent->data = parent->tag + parent->tag_length;

  /* Compose child's byte code. */
  status = ssh_asn1_encode_recurse(context, parent->child,
                                   parent->data, parent->length);

  if (status != SSH_ASN1_STATUS_OK)
    return status;

  /* Do the actual tag encoding. */
  ber_status = ssh_ber_set_tag(parent->tag, parent->tag_length,
                               parent->classp, parent->encoding,
                               parent->tag_number,
                               parent->length_encoding,
                               parent->length);
  if (ber_status != SSH_BER_STATUS_OK)
    return SSH_ASN1_STATUS_BER_CLOSE_FAILED;

  return SSH_ASN1_STATUS_OK;
}

typedef enum
{
  SSH_ASN1_FIT = 1,
  SSH_ASN1_CHILD_FIT = 2,
  SSH_ASN1_NO_FIT = 0
} SshAsn1Fit;

SshAsn1Fit ssh_asn1_compare_fit(SshAsn1Node temp,
                                Boolean is_tagged,
                                const SshAsn1Defs *defs,
                                SshAsn1Class tag_class,
                                SshAsn1LengthEncoding length_encoding,
                                SshAsn1Tag tag_number,
                                SshAsn1TaggingMode tagging_mode)
{
  if (temp == NULL)
    return SSH_ASN1_NO_FIT;

  if (is_tagged)
    {
      if ((temp->classp ==tag_class)
          && temp->tag_number == tag_number
          && (length_encoding & SSH_ASN1_LENGTH_STAR
              || (temp->length_encoding
                  == (length_encoding & ~SSH_ASN1_LENGTH_STAR))))
        {
          if (tagging_mode & SSH_ASN1_TAGGING_EXPLICIT)
            {
              if (defs->tag_number == 0)
                return SSH_ASN1_CHILD_FIT;

              if (temp->child != NULL
                  && temp->child->classp ==SSH_ASN1_CLASS_UNIVERSAL
                  && temp->child->tag_number == defs->tag_number
                  && (length_encoding & SSH_ASN1_LENGTH_STAR
                      || (temp->child->length_encoding
                          == (length_encoding & ~SSH_ASN1_LENGTH_STAR))))
                return SSH_ASN1_CHILD_FIT;
            }
          else
            return SSH_ASN1_FIT;
        }
    }
  else
    {
      if (temp->classp ==SSH_ASN1_CLASS_UNIVERSAL
          && temp->tag_number == defs->tag_number
          && (length_encoding & SSH_ASN1_LENGTH_STAR
              || (temp->length_encoding
                  == (length_encoding & ~SSH_ASN1_LENGTH_STAR))))
        return SSH_ASN1_FIT;
    }
  return SSH_ASN1_NO_FIT;
}

SshAsn1Node ssh_asn1_search_node(SshAsn1Node first, SshAsn1Node *current,
                                 SshAsn1Rule rule_tagged,
                                 SshAsn1Rule rule_untagged,
                                 const SshAsn1Defs *defs,
                                 Boolean is_tagged,
                                 SshAsn1Class tag_classp,
                                 SshAsn1LengthEncoding length_encoding,
                                 SshAsn1Tag tag_number,
                                 SshAsn1TaggingMode tagging_mode)
{
  SshAsn1Node temp, node;
  SshAsn1Fit fitness;
  SshAsn1Rule rule;

  if (is_tagged)
    rule = rule_tagged;
  else
    rule = rule_untagged;

  fitness = SSH_ASN1_NO_FIT;
  node    = NULL;

  switch (rule)
    {
    case SSH_ASN1_RULE_SCAN_ALL:
      /* Search for the tag. */
      temp = first;
      while (temp)
        {
          fitness = ssh_asn1_compare_fit(temp, is_tagged, defs, tag_classp,
                                         length_encoding,
                                         tag_number, tagging_mode);
          if (fitness != SSH_ASN1_NO_FIT)
            break;
          temp = temp->next;
        }
      break;
    case SSH_ASN1_RULE_NO_MATCH:
      temp = *current;
      fitness = SSH_ASN1_FIT;
      break;
    case SSH_ASN1_RULE_NO_SCAN:
      temp = *current;
      fitness = ssh_asn1_compare_fit(temp, is_tagged, defs, tag_classp,
                                     length_encoding,
                                     tag_number, tagging_mode);
      break;
    case SSH_ASN1_RULE_SCAN_FWD:
      temp = *current;
      while (temp)
        {
          fitness = ssh_asn1_compare_fit(temp, is_tagged, defs, tag_classp,
                                         length_encoding,
                                         tag_number, tagging_mode);
          if (fitness != SSH_ASN1_NO_FIT)
            break;
          temp = temp->next;
        }
      break;
    default:
      return NULL;
      break;
    }

  switch (fitness)
    {
    case SSH_ASN1_FIT:
      node = temp;
      break;
    case SSH_ASN1_CHILD_FIT:
      node = temp->child;
      break;
    case SSH_ASN1_NO_FIT:
      node = NULL;
      break;
    }

  if (is_tagged == FALSE)
    *current = temp;

  return node;
}

/******************* Tree handling and moving 'round ********************/

SshAsn1Tree ssh_asn1_init_tree(SshAsn1Context context,
                               SshAsn1Node root, SshAsn1Node current)
{
  SshAsn1Tree tree = ssh_asn1_malloc_s(context, sizeof(*tree));

  if (tree)
    {
      tree->root = root;
      tree->current = current;
    }
  return tree;
}

void ssh_asn1_copy_tree(SshAsn1Tree dest, SshAsn1Tree src)
{
  dest->root = src->root;
  dest->current = src->current;
}

void ssh_asn1_reset_tree(SshAsn1Tree tree)
{
  tree->current = tree->root;
}

unsigned int ssh_asn1_move_forward(SshAsn1Tree tree, unsigned int n)
{
  SshAsn1Node current = tree->current;
  unsigned int moved = 0;

  while (current->next && moved < n)
    {
      current = current->next;
      moved++;
    }

  tree->current = current;

  return moved;
}

unsigned int ssh_asn1_move_backward(SshAsn1Tree tree, unsigned int n)
{
  SshAsn1Node current = tree->current;
  unsigned int moved = 0;

  while (current->prev && moved < n)
    {
      current = current->prev;
      moved++;
    }

  tree->current = current;

  return moved;
}

SshAsn1Status ssh_asn1_move_down(SshAsn1Tree tree)
{
  if (tree->current->child)
    {
      tree->current = tree->current->child;
      return SSH_ASN1_STATUS_OK;
    }

  return SSH_ASN1_STATUS_NO_CHILD;
}

SshAsn1Status ssh_asn1_move_up(SshAsn1Tree tree)
{
  if (tree->current->parent)
    {
      tree->current = tree->current->parent;
      return SSH_ASN1_STATUS_OK;
    }

  return SSH_ASN1_STATUS_NO_PARENT;
}

SshAsn1Node ssh_asn1_get_current(SshAsn1Tree tree)
{
  return tree->current;
}

SshAsn1Node ssh_asn1_get_root(SshAsn1Tree tree)
{
  return tree->root;
}

/* Routine for getting data out from a tree. This data must be
   first encoded. */

void ssh_asn1_get_data(SshAsn1Tree tree, unsigned char **data, size_t *length)
{
  *data = ssh_malloc(tree->length);
  if (*data != NULL)
    {
      *length = tree->length;
      memcpy(*data, tree->data, tree->length);
    }
  else
    *length = 0;
}

/* Direct node moving routines. */

SshAsn1Node ssh_asn1_node_next(SshAsn1Node node)
{
  if (node)
    return node->next;
  return NULL;
}

SshAsn1Node ssh_asn1_node_prev(SshAsn1Node node)
{
  if (node)
    return node->prev;
  return NULL;
}

SshAsn1Node ssh_asn1_node_parent(SshAsn1Node node)
{
  if (node)
    return node->parent;
  return NULL;
}

SshAsn1Node ssh_asn1_node_child(SshAsn1Node node)
{
  if (node)
    return node->child;
  return NULL;
}

/*********************** Insertion and deletion *********************/

void ssh_asn1_flag_changes(SshAsn1Node node)
{
  /* Flag changes to parents. */

  while (node)
    {
      node->data = NULL;
      node->length = 0;
      node->tag = NULL;
      node->tag_length = 0;

      node = node->parent;
    }
}

SshAsn1Node ssh_asn1_add_list(SshAsn1Node list, SshAsn1Node node)
{
  SshAsn1Node temp;

  if (list == NULL)
    return node;

  if (node == NULL)
    return list;

  /* Find last. */
  temp = list;
  while (temp->next)
    temp = temp->next;

  temp->next = node;
  node->prev = temp;

  temp = node;
  while (temp)
    {
      temp->parent = list->parent;
      temp = temp->next;
    }
  ssh_asn1_flag_changes(node->parent);
  return list;
}

SshAsn1Status ssh_asn1_insert_list(SshAsn1Node before,
                                   SshAsn1Node after, SshAsn1Node node)
{
  SshAsn1Node temp;
  SshAsn1Node last;

  if (node == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;

  /* Find the last in the list. */
  last = node;
  while (last->next)
    last = last->next;

  if (before)
    {
      node->prev = before;
      last->next = before->next;

      if (before->next)
        before->next->prev = last;
      before->next = node;

      /* Set the parent pointers. */
      temp = node;
      while (temp)
        {
          temp->parent = before->parent;
          temp = temp->next;
        }

      /* Flag changes... */
      ssh_asn1_flag_changes(node->parent);
      return SSH_ASN1_STATUS_OK;
    }

  if (after)
    {
      node->prev = after->prev;
      node->next = after;

      if (after->prev)
        after->prev->next = node;
      after->prev = last;

      /* Set the parent pointers. */
      temp = node;
      while (temp)
        {
          temp->parent = after->parent;
          temp = temp->next;
        }

      /* Flag changes. */
      ssh_asn1_flag_changes(node->parent);
      return SSH_ASN1_STATUS_OK;
    }
  return SSH_ASN1_STATUS_NODE_NULL;
}

SshAsn1Status ssh_asn1_remove_node(SshAsn1Node node)
{
  if (node == NULL)
    return SSH_ASN1_STATUS_OK;

  /* Detach node. */
  if (node->next)
    node->next->prev = node->prev;
  if (node->prev)
    node->prev->next = node->next;

  /* Flag changes... */
  ssh_asn1_flag_changes(node);

  node->parent = NULL;

  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status ssh_asn1_insert_subnode(SshAsn1Node base, SshAsn1Node node)
{
  SshAsn1Node temp;

  if (base->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
    return SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED;

  if (base->child)
    {
      temp = base->child;

      /* Seek the last node in the list. */
      while (temp->next)
        temp = temp->next;

      /* Insert new nodes. */
      node->prev = temp;
      temp->next = node;

      while (node)
        {
          node->parent = base;
          node = node->next;
        }
    }
  else
    {
      base->child = node;
      node->prev = NULL;

      while (node)
        {
          node->parent = base;
          node = node->next;
        }
    }

  /* Flag changes. */
  ssh_asn1_flag_changes(base);

  return SSH_ASN1_STATUS_OK;
}

/************* Get directly the internals of one particular node ***********/

size_t ssh_asn1_bytes_used(SshAsn1Tree tree)
{
  return ssh_asn1_count_length(tree->root);
}

SshAsn1Status
ssh_asn1_node_get_data(SshAsn1Node node,
                       unsigned char **data, size_t *data_len)
{
  if (node == NULL)
    {
      *data = NULL;
      *data_len = 0;
      return SSH_ASN1_STATUS_NODE_NULL;
    }

  *data = ssh_malloc(node->length + node->tag_length);
  if (*data != NULL)
    {
      memcpy(*data, node->tag, node->length + node->tag_length );
      *data_len = node->length + node->tag_length;
      return SSH_ASN1_STATUS_OK;
    }
  else
    {
      *data_len = 0;
      return SSH_ASN1_STATUS_OPERATION_FAILED;
    }
}

SshAsn1Node ssh_asn1_node_init(SshAsn1Context context)
{
  SshAsn1Node node;

  node = ssh_asn1_malloc_s(context, sizeof(*node));
  if (node != NULL)
    {
      node->classp = SSH_ASN1_CLASS_UNIVERSAL;
      node->encoding = SSH_ASN1_ENCODING_PRIMITIVE;
      node->tag_number = SSH_ASN1_TAG_RESERVED_0;
      node->length_encoding = SSH_ASN1_LENGTH_DEFINITE;
      node->prev = node->next = node->child = node->parent = NULL;
      node->length = node->tag_length = 0;
      node->data = node->tag = NULL;
    }

  return node;
}

SshAsn1Status ssh_asn1_node_get(SshAsn1Node node,
                                SshAsn1Class *classp,
                                SshAsn1Encoding *encoding,
                                SshAsn1Tag *tag_number,
                                SshAsn1LengthEncoding *length_encoding,
                                size_t *length,
                                unsigned char **data)
{
  if (node == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;

  if (classp)
    *classp = node->classp;

  if (encoding)
    *encoding = node->encoding;

  if (tag_number)
    *tag_number = node->tag_number;

  if (length_encoding)
    *length_encoding = node->length_encoding;

  if (length)
    {
      *length = node->length;
      if (data)
        {
          /* Copy the data. */
          *data = ssh_memdup(node->data, *length);
          if (*data == NULL)
            *length = 0;
        }
    }

  return SSH_ASN1_STATUS_OK;
}

int ssh_asn1_node_size(SshAsn1Node node)
{
  if (node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED)
    return node->tag_length;
  return node->tag_length + node->length;
}

SshAsn1Status ssh_asn1_node_put(SshAsn1Context context,
                                SshAsn1Node node,
                                SshAsn1Class classp,
                                SshAsn1Encoding encoding,
                                SshAsn1Tag tag_number,
                                SshAsn1LengthEncoding length_encoding,
                                size_t length,
                                unsigned char *data)
{
  SshBerStatus ber_status;

  if (node == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;

  node->classp = classp;
  node->encoding = encoding;
  node->tag_number = tag_number;
  node->length_encoding = length_encoding;
  node->length = length;

  node->tag_length = ssh_ber_compute_tag_length(node->classp,
                                                node->encoding,
                                                node->tag_number,
                                                node->length_encoding,
                                                node->length);

  node->tag = ssh_asn1_malloc_b(context, node->length + node->tag_length);
  if (node->tag == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  node->data = node->tag + node->tag_length;
  memcpy(node->data, data, node->length);

  /* Set tag. */
  ber_status = ssh_ber_set_tag(node->tag, node->tag_length,
                               node->classp, node->encoding,
                               node->tag_number, node->length_encoding,
                               node->length);

  if (ber_status != SSH_BER_STATUS_OK)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  /* Flag changes... */
  ssh_asn1_flag_changes(node);

  return SSH_ASN1_STATUS_OK;
}


SshAsn1Status ssh_asn1_copy_node(SshAsn1Context context,
                                 SshAsn1Node *node_to,
                                 SshAsn1Node node_from)
{
  if (!node_from)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  /* Allocate new node_to to place the data to be copied. */
  *node_to = ssh_asn1_malloc_s(context, sizeof(**node_to));
  if (*node_to == NULL)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  (*node_to)->next = NULL;
  (*node_to)->prev = NULL;
  (*node_to)->child = node_from->child;

  /* Copy the values from node_from to node_to.  */
  (*node_to)->classp = node_from->classp;
  (*node_to)->encoding = node_from->encoding;
  (*node_to)->tag_number = node_from->tag_number;
  (*node_to)->length_encoding = node_from->length_encoding;
  (*node_to)->tag_length = node_from->tag_length;
  (*node_to)->tag = node_from->tag;
  (*node_to)->length = node_from->length;
  (*node_to)->data = node_from->data;
  (*node_to)->parent = NULL;

  return SSH_ASN1_STATUS_OK;
}

/* sshasn1.c */
#endif /* SSHDIST_ASN1 */
