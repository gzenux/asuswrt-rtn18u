/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Support for global variables.
*/

#include "sshincludes.h"
#include "sshglobals.h"
#ifdef VXWORKS
#include "taskLib.h"
#include "taskVarLib.h"

/* Use standard malloc on vxworks, to prevent loop from globals to
   sshmallocdebug and back. */

#include "memLib.h"
#undef ssh_malloc
#undef ssh_calloc
#undef ssh_free
#define ssh_malloc malloc
#define ssh_calloc calloc
#define ssh_free free
#undef malloc
#undef calloc
#undef free

static int net_task_id;

#endif /* VXWORKS */

#define SSH_DEBUG_MODULE "SshGlobals"

/* This is the hash table entry. The name is the constant string of the
   variable name (it is the first string given to the ssh_global_get).
   Immediately after the name pointer starts the actual value of the data. */
typedef struct SshGlobalsHashItemRec {
  struct SshGlobalsHashItemRec *next;
  SshUInt32 hash;
  const char *name;
} *SshGlobalsHashItem, SshGlobalsHashItemStruct;


typedef struct SshGlobalsRec {
  /* Entry point of the hash table. */
  SshGlobalsHashItem *hash_table;
  /* How many items does the hash table contain, and how many entries
     are in it now.  We rehash to double size whenever the number of
     items exceeds the number of hash table slots.  The number of
     entries must be a power of two.  Collisions are handled with
     separate chaining. */
  SshUInt32 number_of_items;
  SshUInt32 size_of_table;
} *SshGlobals, SshGlobalsStruct;


/* In some environments this should be the only global variable in the
   program. Depending on environment variable needs to be static or
   non static. Some extra attributes may also be needed. */
#ifndef VXWORKS
static
#endif /* !VXWORKS */
SshGlobals ssh_globals = NULL;

static SshUInt32 ssh_global_hash_fun(const char *s)
{
  SshUInt32 h = 0xDEADBEEF;

  /* The `one-at-a-time' hash function from Robert J. Jenkins' web
     articles.  One of the better string hash functions I know of. */
  while (*s) {
    h += *s++;
    h += h << 10;
    h ^= h >> 6;
  }
  h += h << 3;
  h ^= h >> 11;
  h += (h << 15) & 0xffffffff;

  return h;
}


/* Find item from the hash table. */
static SshGlobalsHashItem ssh_global_hash_item_find(const char *str)
{
  SshGlobalsHashItem p;
  SshUInt32 h;

  if (ssh_globals == NULL || ssh_globals->hash_table == NULL)
    return NULL;

  h = ssh_global_hash_fun(str);
  /* Assert that the size of the table is a power of two. */
  SSH_ASSERT((ssh_globals->size_of_table & (ssh_globals->size_of_table - 1))
             == 0);

  for (p = ssh_globals->hash_table[h & (ssh_globals->size_of_table - 1)];
       p != NULL;
       p = p->next)
    {
      if (h == p->hash && strcmp(str, p->name) == 0)
        return p;
    }
  return NULL;
}


/* Add new entry to hash table */
static void ssh_global_hash_item_add(SshGlobalsHashItem item)
{
  if (ssh_globals == NULL)
    ssh_global_init();

  if (ssh_globals->hash_table == NULL)
    {
      ssh_globals->size_of_table = 64;
      if ((ssh_globals->hash_table =
           ssh_calloc(ssh_globals->size_of_table, sizeof(SshGlobalsHashItem)))
          == NULL)
        ssh_fatal("Can't initialize global variable hash table. "
                  "Program execution can not continue.");
    }
  else if (ssh_globals->number_of_items > ssh_globals->size_of_table)
    {
      /* Rehash the old table. */
      SshGlobalsHashItem *old_globals = ssh_globals->hash_table;
      SshUInt32 old_size = ssh_globals->size_of_table;
      SshUInt32 i;

      /* Double the size. */
      ssh_globals->size_of_table *= 2;
      if ((ssh_globals->hash_table =
           ssh_calloc(ssh_globals->size_of_table, sizeof(SshGlobalsHashItem)))
          == NULL)
        ssh_fatal("Can't expand global variable hash table. "
                  "Program execution can not continue.");

      for (i = 0; i < old_size; i++)
        /* Traverse all slots in the old table. */
        {
          SshGlobalsHashItem p, p_next;

          for (p = old_globals[i]; p != NULL; p = p_next)
            /* All items in the chain. */
            {
              SshUInt32 new_i = p->hash & (ssh_globals->size_of_table - 1);

              SSH_ASSERT((p->hash & (old_size - 1)) == i);

              /* Push the item first in the new slot.  As a side
                 effect the chain is reversed, but this shouldn't
                 matter. */
              p_next = p->next;
              p->next = ssh_globals->hash_table[new_i];
              ssh_globals->hash_table[new_i] = p;
            }
        }
      ssh_free(old_globals);
    }

  {
    SshUInt32 i;

    item->hash = ssh_global_hash_fun(item->name);
    i = item->hash & (ssh_globals->size_of_table - 1);
    item->next = ssh_globals->hash_table[i];
    ssh_globals->hash_table[i] = item;
    ssh_globals->number_of_items++;
  }
}

/* It's sole purpose is to make globals and debugging interoperate
   and allow for code that allows init to be called twice. */
Boolean ssh_global_check(const char *str, int flags)
{
  return ssh_global_hash_item_find(str) != NULL;
}

/* Function that returns pointer to the global variable based on the name of
   the global variable. If the variable is used before it is initialized (i.e
   the ssh_global_init_variable is not called before the first use of the
   ssh_global_get), then ssh_global_get might print out warning, and the value
   of the variable will be all zeros. */
void *ssh_global_get(const char *str, size_t variable_size, int flags)
{
  SshGlobalsHashItem item;

  item = ssh_global_hash_item_find(str);

  if (item == NULL)
    {
#ifdef VXWORKS
      if (taskVarGet(taskIdSelf(), (int *)(void *)&ssh_globals) == -1 ||
          ((flags & SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK) == 0 &&
           net_task_id == taskIdSelf()))
        {
          ssh_fatal("Cannot use ssh_global: %s on this task\n", str);
        }

#endif /* VXWORKS */

      ssh_fatal("Use of uninitialized global variable %s", str);

      if ((item =
           ssh_calloc(1, sizeof(SshGlobalsHashItemStruct) + variable_size))
          == NULL)
        ssh_fatal("Can't initialize global variable. "
                  "Program execution can not continue.");
      item->name = str;
      ssh_global_hash_item_add(item);
    }
  return (void *) (((char *) item) + sizeof(SshGlobalsHashItemStruct));
}


/* Function that returns pointer to the global variable based on the name of
   the global variable. If the variable is used before it is initialized (i.e
   the ssh_global_init_variable is not called before the first use of the
   ssh_global_get), then variable is initialized automatically. */
void *ssh_global_get_init(const char *str, size_t variable_size,
                          int flags, const void *init)
{
  SshGlobalsHashItem item;

  item = ssh_global_hash_item_find(str);

  if (item == NULL)
    {
#ifdef VXWORKS
      if (taskVarGet(taskIdSelf(), (int *)(void *)&ssh_globals) == -1 ||
          ((flags & SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK) == 0 &&
           net_task_id == taskIdSelf()))
        {
          ssh_fatal("Cannot use ssh_global: %s on this task\n", str);
        }
#endif /* VXWORKS */

      if ((item =
           ssh_calloc(1, sizeof(SshGlobalsHashItemStruct) + variable_size))
          == NULL)
        ssh_fatal("Can't initialize global variable. "
                  "Program execution can not continue.");
      item->name = str;
      ssh_global_hash_item_add(item);

      memcpy((void *) (((char *) item) +
                       sizeof(SshGlobalsHashItemStruct)),
             init, variable_size);
    }
  return (void *) (((char *) item) + sizeof(SshGlobalsHashItemStruct));
}

/* Initialize variable to have value of all zeros. This makes the variable to
   be known to the system, and ssh_global_get will assume not print out
   warnings about use of uninitialized variables. Call this function twice
   will print out warning. This returns always returns 0. */
int ssh_global_init_variable(const char *str, size_t variable_size, int flags)
{
  SshGlobalsHashItem item;

  item = ssh_global_hash_item_find(str);

#ifdef VXWORKS
  if (taskVarGet(taskIdSelf(), (int *)(void *)&ssh_globals) == -1 ||
      ((flags & SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK) == 0 &&
       net_task_id == taskIdSelf()))
    {
      ssh_fatal("Cannot use ssh_global: %s on this task\n", str);
    }
#endif /* VXWORKS */

  if (item != NULL)
    {
      ssh_warning("Duplicate initialization of the variable %s", str);
      return 0;
    }
  if ((item = ssh_calloc(1, sizeof(SshGlobalsHashItemStruct) + variable_size))
      == NULL)
    ssh_fatal("Can't initialize global variable. "
              "Program execution can not continue.");

  item->name = str;
  ssh_global_hash_item_add(item);
  return 0;
}


/* Initialize global variables system. Calling this will reset all global
   variables to uninitialized state. */
void ssh_global_init(void)
{
  if ((ssh_globals = ssh_calloc(1, sizeof(SshGlobalsStruct))) == NULL)
    ssh_fatal("Can't initialize global variable storage. "
              "Program execution can not continue.");
#ifdef VXWORKS
  if ((net_task_id = taskNameToId("tNetTask")) == ERROR)
    ssh_fatal("Can't get task id of tNetTask. "
              "Program execution can not continue.");

#endif /* VXWORKS */
}

/* Uninitialize global variables system. Calling this will reset all global
   variables to uninitialized state, and free all state allocated for the
   global variables. */
void ssh_global_uninit(void)
{
  SshGlobalsHashItem p, p_next;
  SshUInt32 i;

  if (ssh_globals == NULL)
    return;

  if (ssh_globals->hash_table != NULL)
    {
      for (i = 0; i < ssh_globals->size_of_table; i++)
        for (p = ssh_globals->hash_table[i]; p != NULL; p = p_next)
          {
            p_next = p->next;
            ssh_free(p);
          }
      ssh_free(ssh_globals->hash_table);
    }

  ssh_free(ssh_globals);
  ssh_globals = NULL;
}

#ifdef DEBUG_LIGHT

/* Dump contents of globals.
   Notice: this function does not contain locking so problems may come
   if table is modified during the call. */
void ssh_globals_dump(
#ifdef VXWORKS
void *taskptr,
#endif /* VXWORKS */
const char *name)
{
  int first = 1;
  int i;
#ifdef VXWORKS
  SshGlobals globals;

  globals = (void *)taskVarGet((int)taskptr, (int *)(void *)&ssh_globals);

  if (globals == 0 || ((int)globals) == -1)
    {
      printf("ssh_globals_dump: Please specify task with ssh_globals.\n");
      return;
    }
#else /* VXWORKS */
  SshGlobals globals = ssh_globals;
#endif /* VXWORKS */

  printf("Ssh globals (%lu variables, %lu storage allocated):\n",
         globals? (unsigned long)globals->number_of_items: 0,
         globals? (unsigned long)globals->size_of_table: 0);

  if (globals && globals->hash_table)
    {
      for(i=0; i < globals->size_of_table; i++)
        {
          SshGlobalsHashItem p;
          void **ptr;

          p = globals->hash_table[i];
          if (!p) continue;
          if (name && strcmp(p->name,name)) continue;
          if (!first) printf(", ");
          first = 0;
          ptr = (void **) (p+1);
          printf("%s(%p:%p)", p->name, ptr, *ptr);
        }
    }
  if (globals && globals->number_of_items) printf("\n");
}

#endif /* DEBUG_LIGHT */
