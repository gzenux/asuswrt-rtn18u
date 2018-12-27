/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "tls_multihash.h"

#define HASH_TABLE_SIZE 1009    /* This is a prime number. */

#define SSH_DEBUG_MODULE "SshTlsMultihash"

typedef struct hash_table_node {
  void **values;
  int num_values;
  int array_size;
  unsigned char *key;
  int key_len;
  struct hash_table_node *next;
} HashTableNode;

struct ssh_tls_mhtab {
  HashTableNode *nodes[HASH_TABLE_SIZE];
};

SshTlsMultiHashTable ssh_tls_mh_allocate(void)
{
  SshTlsMultiHashTable t;
  int i;

  SSH_DEBUG(6, ("Allocating a new hash table."));

  if ((t = ssh_calloc(1, sizeof(*t))) != NULL)
    {
      for (i = 0; i < HASH_TABLE_SIZE; i++)
        {
          t->nodes[i] = NULL;
        }
    }
  return t;
}

static void free_node(HashTableNode *node)
{
  ssh_free(node->values);
  ssh_free(node->key);
  ssh_free(node);
}

void ssh_tls_mh_clear(SshTlsMultiHashTable table)
{
  int i;
  HashTableNode *temp;

  SSH_DEBUG(6, ("Clearing a hash table."));

  for (i = 0; i < HASH_TABLE_SIZE; i++)
    {
      while (table->nodes[i] != NULL)
        {
          temp = table->nodes[i];
          table->nodes[i] = table->nodes[i]->next;
          free_node(temp);
        }
    }
}

void ssh_tls_mh_free(SshTlsMultiHashTable table)
{
  SSH_DEBUG(6, ("Freeing a hash table."));

  ssh_tls_mh_clear(table);
  ssh_free(table);
}

static int hash_value(const unsigned char *key, int key_len)
{
  int i = 0;
  unsigned int acc = 0;

  SSH_ASSERT(key != NULL);
  SSH_ASSERT(key_len >= 0);

  while (i < key_len)
    {
      acc = ((acc << 5) + key[i]) + (acc >> 7);
      i++;
    }
  return (acc % HASH_TABLE_SIZE);
}

static HashTableNode **hash_find(SshTlsMultiHashTable table,
                                 const unsigned char *key, int key_len)
{
  int i = hash_value(key, key_len);
  HashTableNode **n = &(table->nodes[i]);

  while (*n != NULL &&
         (((*n)->key_len != key_len) || memcmp(key, (*n)->key, key_len)))
    {
      n = &((*n)->next);
    }

  SSH_ASSERT(n != NULL);
  return n;
}

int ssh_tls_mh_find(SshTlsMultiHashTable table,
                    const unsigned char *key, int key_len, void ***ptr)
{
  HashTableNode **n;

  n = hash_find(table, key, key_len);
  if (*n == NULL) return 0;
  *ptr = (*n)->values;
  return (*n)->num_values;
}

void ssh_tls_mh_delete_all(SshTlsMultiHashTable table,
                           const unsigned char *key, int key_len)
{
  HashTableNode **n;
  HashTableNode *temp;

  n = hash_find(table, key, key_len);
  if ((*n) == NULL) return;
  temp = *n;
  (*n) = temp->next;
  free_node(temp);
}

static void shift_deleted(HashTableNode *node)
{
  int i, j = 0;
  for (i = 0; i < node->num_values; i++)
    {
      if (node->values[i] != SSH_TLS_MH_DELETED)
        {
          if (j != i)
            node->values[j] = node->values[i];
          j++;
        }
    }
  node->num_values = j;
}

static void remove_duplicates(HashTableNode *node)
{
  int i, j;

  /* This cool quadratic algorithm... */
  for (i = 0; i < node->num_values; i++)
    {
      for (j = i+1; j < node->num_values; j++)
        {
          if (node->values[i] == node->values[j])
            node->values[j] = SSH_TLS_MH_DELETED;
        }
    }
  shift_deleted(node);
}

/* Add values given at array `ptr', whose size is `array_size'
   elements to multihash `table'. If memory allocation for values
   fails, this is a silent nop. Sorry. */
static void add_values(SshTlsMultiHashTable table,
                       const unsigned char *key, int key_len,
                       void **ptr, int array_size, int no_dupl)
{
  HashTableNode *node;
  HashTableNode **p;
  void **tmp;

  p = hash_find(table, key, key_len);

  if (*p == NULL)
    {
      if ((node = ssh_calloc(1, sizeof(HashTableNode))) != NULL)
        {
          node->next = NULL;
          if ((node->key = ssh_memdup(key, key_len)) == NULL)
            {
              ssh_free(node);
              return;
            }
          node->key_len = key_len;

          if ((node->values =
               ssh_calloc(1, sizeof(void *) * array_size)) == NULL)
            {
              ssh_free(node->key);
              ssh_free(node);
              return;
            }

          node->array_size = array_size;
          node->num_values = 0;

          *p = node;
        }
      else
        {
          return;
        }
    }
  else
    {
      node = *p;
      if (node->array_size < (node->num_values + array_size))
        {
          if ((tmp =
               ssh_realloc(node->values,
                           (node->array_size) * sizeof(void *),
                           (node->array_size + array_size)* sizeof(void *)))
              != NULL)
            {
              node->array_size = node->num_values + array_size;
              node->values = tmp;
            }
          else
            {
              return;
            }
        }
    }

  memcpy(&(node->values[node->num_values]),
         ptr,
         sizeof(void *) * array_size);

  node->num_values += array_size;
  if (no_dupl)
    remove_duplicates(node);
}

/* Add a single new value under the given key. This adds the value
   even it if already exists in the set of values associated with the
   key. */
void ssh_tls_mh_add_nonuniq(SshTlsMultiHashTable table,
                            const unsigned char *key, int key_len,
                            void *ptr)
{
  add_values(table, key, key_len, &ptr, 1, 0);
}

/* Similar, but add only if the value doesn't already exist. */
void ssh_tls_mh_add_uniq(SshTlsMultiHashTable table,
                         const unsigned char *key, int key_len,
                         void *ptr)
{
  add_values(table, key, key_len, &ptr, 1, 1);
}

/* Similar to the two functions above, but add multiple values at a single
   shot. */
void ssh_tls_mh_add_multiple_nonuniq(SshTlsMultiHashTable table,
                                     const unsigned char *key, int key_len,
                                     void **ptr, int array_size)
{
  add_values(table, key, key_len, ptr, array_size, 0);
}

/* This function also detects those multiply occurring values that
   occur many times in the array `*ptr' and handles them correctly. */
void ssh_tls_mh_add_multiple_uniq(SshTlsMultiHashTable table,
                                  const unsigned char *key, int key_len,
                                  void **ptr, int array_size)
{
  add_values(table, key, key_len, ptr, array_size, 1);
}

void ssh_tls_mh_set(SshTlsMultiHashTable table,
                    const unsigned char *key, int key_len,
                    void **ptr, int array_size)
{
  HashTableNode **n;
  HashTableNode *node;
  void **tmp;

  n = hash_find(table, key, key_len);
  node = *n;
  SSH_ASSERT(node != NULL);
  SSH_ASSERT(node->values != NULL);

  if (node->values != ptr)
    {
      /* Check that there is no partial overlap; that might
         cause very strange bugs especially because of the
         ssh_xrealloc() call below. */
      SSH_ASSERT((ptr + array_size < node->values) ||
                 (node->values + node->array_size) < ptr);

      if (node->array_size < array_size)
        {
          if ((tmp =
               ssh_realloc(node->values,
                           sizeof(void *) * node->array_size,
                           sizeof(void *) * array_size))
              != NULL)
            {
              node->values = tmp;
              node->array_size = array_size;
              memcpy(node->values, ptr, sizeof(void *) * array_size);
              node->num_values = array_size;
            }
          else
            {
              return;
            }
        }
    }
  else
    {
      SSH_ASSERT(array_size == node->num_values);
    }
  remove_duplicates(node);
}

#ifdef DEBUG_LIGHT
void dump_table(SshTlsMultiHashTable table)
{
  int i;
  int k;
  HashTableNode *n;
  int count = 0;

  for (i = 0; i < HASH_TABLE_SIZE; i++)
    {
      if (table->nodes[i] != NULL)
        {
          k = 0;
          n = table->nodes[i];
          while (n != NULL)
            {
              k += n->num_values; n = n->next;
            }
          fprintf(stderr, "Index %d: %d values\n", i, k);
          count += k;
        }
    }
  fprintf(stderr, "%d values in total.\n", count);
}
#endif /* DEBUG_LIGHT */

#if 0

void ssh_tls_mh_tests(void)
{
  SshTlsMultiHashTable table;
  int i;
  unsigned char buf[20];
  unsigned char **str;
  void **ptr;
  int m, k;
  unsigned char *s;
  int count = 0;

  if ((str = ssh_calloc(1, sizeof(unsigned char *) * 500000)) == NULL)
    return;

  table = ssh_tls_mh_allocate();

  SSH_DEBUG(4, ("First test."));
  SSH_DEBUG(4, ("Adding 500000 elements."));

  for (i = 0; i < 500000; i++)
    {
      buf[0] = (i % 26) + 'A';
      buf[1] = ((i * 17) % 25) + 'A';
      buf[2] = ((i * 5) % 24) + 'A';
      buf[3] = ((i * 11) % 23) + 'A';
      buf[4] = '\0';
      str[i] = (unsigned char *)strdup(buf);
      ssh_tls_mh_add_nonuniq(table, buf, 4, str[i]);
    }

  SSH_DEBUG(4, ("Now check that we can get them correctly back."));

  for (i = 0; i < 500000; i++)
    {
      buf[0] = (i % 26) + 'A';
      buf[1] = ((i * 17) % 25) + 'A';
      buf[2] = ((i * 5) % 24) + 'A';
      buf[3] = ((i * 11) % 23) + 'A';
      buf[4] = '\0';
      m = ssh_tls_mh_find(table, buf, 4, &ptr);
      for (k = 0; k < m; k++)
        {
          s = ptr[k];
          if (s[4] != '\0') go_fatal("Not a string.");
          if (strcmp(s, buf)) go_fatal("Invalid string.");
          count++;
        }
    }
  for (i = 0; i < 500000; i++)
    {
      ssh_free(str[i]);
    }

  SSH_DEBUG(4, ("Counted %d data elements in total (> 500000 is just normal).",
               count));

  ssh_tls_mh_clear(table);

  SSH_DEBUG(4, ("Then test adding just NULL elements and not "
               "removing duplicates."));
  SSH_DEBUG(4, ("Adding 500000 elements."));

  for (i = 0; i < 500000; i++)
    {
      buf[0] = (i % 26) + 'A';
      buf[1] = ((i * 17) % 25) + 'A';
      buf[2] = ((i * 5) % 24) + 'A';
      buf[3] = ((i * 11) % 23) + 'A';
      buf[4] = '\0';
      ssh_tls_mh_add_nonuniq(table, buf, 4, NULL);
    }

  SSH_DEBUG(4, ("Now count the elements.."));
  count = 0;
  for (i = 0; i < 500000; i++)
    {
      buf[0] = (i % 26) + 'A';
      buf[1] = ((i * 17) % 25) + 'A';
      buf[2] = ((i * 5) % 24) + 'A';
      buf[3] = ((i * 11) % 23) + 'A';
      buf[4] = '\0';
      m = ssh_tls_mh_find(table, buf, 4, &ptr);
      count += m;
    }
  SSH_DEBUG(4, ("Counted %d data elements in total.", count));
  ssh_tls_mh_clear(table);

  SSH_DEBUG(4, ("Then the same but remove duplicates."));
  SSH_DEBUG(4, ("Adding 500000 elements."));

  for (i = 0; i < 500000; i++)
    {
      buf[0] = (i % 26) + 'A';
      buf[1] = ((i * 17) % 25) + 'A';
      buf[2] = ((i * 5) % 24) + 'A';
      buf[3] = ((i * 11) % 23) + 'A';
      buf[4] = '\0';
      ssh_tls_mh_add_uniq(table, buf, 4, NULL);
    }

  SSH_DEBUG(4, ("Now count the elements.."));
  count = 0;
  for (i = 0; i < 500000; i++)
    {
      buf[0] = (i % 26) + 'A';
      buf[1] = ((i * 17) % 25) + 'A';
      buf[2] = ((i * 5) % 24) + 'A';
      buf[3] = ((i * 11) % 23) + 'A';
      buf[4] = '\0';
      m = ssh_tls_mh_find(table, buf, 4, &ptr);
      count += m;
    }
  SSH_DEBUG(4, ("Counted %d data elements in total.", count));
  ssh_tls_mh_clear(table);

  ssh_tls_mh_free(table);
  ssh_free(str);
  SSH_DEBUG(4, ("End of test."));
}

#endif
