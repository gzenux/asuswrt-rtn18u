/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Map operation to completion of other operations.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "sshadt.h"
#include "sshadt_map.h"
#include "sshadt_priority_heap.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertMap"


typedef struct SshCMMapNameRec   *SshCMMapName, SshCMMapNameStruct;
typedef struct SshCMMapNameObRec *SshCMMapNameOb, SshCMMapNameObStruct;
typedef struct SshCMMapObRec     *SshCMMapOb, SshCMMapObStruct;

struct SshCMMapNameObRec
{
  SshADTHeaderStruct prq_header;

  /* The two linked lists. */
  SshCMMapNameOb n_next, n_prev, o_next, o_prev;

  /* The object. */
  SshCMMapOb ob;
  /* The name. */
  SshCMMapName name;

  /* The delay. */
  SshUInt32 delay_msecs;

  SshUInt64 priority;

  /* Refcount. */
  unsigned int refcount;
  Boolean free_in_process;

  /* The name specific private context. */
  void       *context;
};

struct SshCMMapNameRec
{
  /* Concreate header, concrete object model */
  SshADTHeaderStruct adt_header;

  /* The list of objects to which this name is linked to. */
  SshCMMapNameOb list;

  /* The name. (index) */
  const unsigned char *name;
  size_t name_length;
};

struct SshCMMapObRec
{
  /* Concreate header, concrete object model */
  SshADTHeaderStruct adt_header;

  /* The list of names this object is linked to. */
  SshCMMapNameOb list;

  /* The locator (index to map) */
  SshCMMapLocator locator;

  /* The callbacks for the context. */
  const SshCMMapOp *op;
  /* The stored context. */
  void     *ob_context;
};

struct SshCMMapRec
{
  /* Hash tables for objects[bylocator] and names[byname] */
  SshADTContainer objects;
  SshADTContainer names;

  /* The priority queue for control routine. */
  SshADTContainer prq;

  /* The monotonically increasing identifier. */
  SshUInt64 id_no;

  /* Time measure structure for easy use. */
  struct SshTimeMeasureRec timer;
};

int
cm_map_priority_compare(const void *object1, const void *object2,
                        void *context)
{
  SshCMMapNameOb c1 = (SshCMMapNameOb)object1;
  SshCMMapNameOb c2 = (SshCMMapNameOb)object2;

  if (c1->priority == c2->priority)
    return 0;
  else if (c1->priority < c2->priority)
    return -1;
  else
    return 1;
}

SshUInt32
cm_map_name_hash(const void *object, void *context)
{
  SshUInt32 h = 0, i;
  SshCMMapName c = (SshCMMapName) object;

  for (i = 0; i < c->name_length; i++)
    h = c->name[i] ^ ((h << 7) | (h >> 26));
  return h;
}

int
cm_map_name_compare(const void *object1, const void *object2,
                    void *context)
{
  SshCMMapName c1 = (SshCMMapName) object1;
  SshCMMapName c2 = (SshCMMapName) object2;

  if (c1->name_length == c2->name_length)
    return memcmp(c1->name, c2->name, c1->name_length);
  else if (c1->name_length < c2->name_length)
    return -1;
  else
    return 1;
}


SshUInt32
cm_map_object_hash(const void *object, void *context)
{
  SshCMMapOb c = (SshCMMapOb) object;
  return c->locator;
}

int
cm_map_object_compare(const void *object1, const void *object2,
                      void *context)
{
  SshCMMapOb c1 = (SshCMMapOb) object1;
  SshCMMapOb c2 = (SshCMMapOb) object2;

  if (c1->locator == c2->locator)
    return 0;
  else if (c1->locator < c2->locator)
    return -1;
  else
    return 1;
}

static SshCMMapNameOb map_name_ob_allocate(void)
{
  SshCMMapNameOb name_ob;

  name_ob = ssh_calloc(1, sizeof(*name_ob));

  return name_ob;
}

static void map_name_ob_unlink_internal(SshCMMap map,
                                        SshCMMapNameOb name_ob)
{
  /* Unlink from names. */
  if (name_ob->n_next)
    name_ob->n_next->n_prev = name_ob->n_prev;
  if (name_ob->n_prev)
    name_ob->n_prev->n_next = name_ob->n_next;
  else
    if (name_ob->name)
      name_ob->name->list = name_ob->n_next;

  /* Unlink from obs. */
  if (name_ob->o_next)
    name_ob->o_next->o_prev = name_ob->o_prev;
  if (name_ob->o_prev)
    name_ob->o_prev->o_next = name_ob->o_next;
  else
    if (name_ob->ob)
      name_ob->ob->list = name_ob->o_next;

  /* Clear the pointers. */
  name_ob->n_next = name_ob->n_prev = name_ob->o_next = name_ob->o_prev = NULL;
}

static void map_name_ob_free(SshCMMap map, SshCMMapNameOb name_ob)
{
  void     *context = name_ob->context;
  SshCMMapOb     ob = name_ob->ob;

  /* This name is already in the process of being freed. */
  if (name_ob->free_in_process == TRUE)
    return;

  name_ob->free_in_process = TRUE;

  /* Free the private context (if available). */
  if (context && ob &&
      ob->op && ob->op->free_name_ctx)
    {
      (*ob->op->free_name_ctx)(map,
                               context,
                               ob->ob_context);
    }

  /* Unlink. */
  map_name_ob_unlink_internal(map, name_ob);

  /* Clean the name_ob. */
  name_ob->ob = NULL;
  name_ob->name = NULL;
  name_ob->context = NULL;

  name_ob->free_in_process = FALSE;

  /* Handle as a special case the situation when the name_ob is in
     the priority queue (or otherwise referenced). */
  if (name_ob->refcount)
    return;
  /* Free the memory. */
  ssh_free(name_ob);
}

static void map_name_ob_link(SshCMMap map,
                             SshCMMapNameOb name_ob,
                             SshCMMapName   name,
                             SshCMMapOb     ob)
{
  /* Link to parents. */
  name_ob->name = name;
  name_ob->ob   = ob;

  /* Connect the lists. */
  name_ob->n_next = name->list;
  name_ob->n_prev = NULL;
  name_ob->o_next = ob->list;
  name_ob->o_prev = NULL;

  if (name->list)
    name->list->n_prev = name_ob;
  if (ob->list)
    ob->list->o_prev = name_ob;

  name->list = name_ob;
  ob->list = name_ob;
}

static SshCMMapName
map_name_allocate(SshCMMap map,
                  unsigned char *name, size_t name_length)
{
  SshCMMapNameStruct *mapname = NULL, probe;
  SshADTHandle handle;

  if (name && name_length > 0)
    {
      probe.name = name;
      probe.name_length = name_length;

      if ((handle = ssh_adt_get_handle_to_equal(map->names, &probe))
          == SSH_ADT_INVALID)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                            ("MAP: allocate; NEW"), name, name_length);
          if ((mapname = ssh_calloc(1, sizeof(*mapname))) != NULL)
            {
              mapname->name = name;
              mapname->name_length = name_length;
              mapname->list = NULL; /* empty list. */

              ssh_adt_insert(map->names, mapname);
            }
          else
            ssh_free(name);
        }
      else
        {
          SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                            ("MAP: allocate; OLD"), name, name_length);
          mapname = ssh_adt_get(map->names, handle);
          ssh_free(name);
        }
    }

  return mapname;
}

static void
map_name_free(SshCMMap map, SshCMMapName name)
{
  SshCMMapNameOb name_ob, name_ob_next;
  SshADTHandle handle;

  for (name_ob = name->list; name_ob; name_ob = name_ob_next)
    {
      name_ob_next = name_ob->n_next;
      map_name_ob_free(map, name_ob);
    }

  /* Abort the operation. */
  if ((handle = ssh_adt_get_handle_to_equal(map->names, name))
      != SSH_ADT_INVALID)
    {
      ssh_adt_detach(map->names, handle);
    }

  ssh_free((void *)name->name);
  ssh_free(name);
}

static void map_name_ob_unlink(SshCMMap map,
                               SshCMMapNameOb name_ob)
{
  SshCMMapName name = name_ob->name;

  map_name_ob_free(map, name_ob);
  if (name && name->list == NULL)
    map_name_free(map, name);
}

/* TRUE; call me again, Sam */
Boolean ssh_cm_map_control(SshCMMap map)
{
  SshUInt64 stamp;
  SshCMMapNameOb name_ob = NULL;
  SshADTHandle handle;
  SshCMMapName name;

  stamp = ssh_time_measure_stamp(&map->timer,
                                 SSH_TIME_GRANULARITY_MILLISECOND);

  SSH_DEBUG(SSH_D_MIDOK, ("MAP: control: stamp=%qd", stamp));

  while ((handle = ssh_adt_get_handle_to_location(map->prq,
                                                  SSH_ADT_DEFAULT))
         != SSH_ADT_INVALID)
    {
      name_ob = ssh_adt_get(map->prq, handle);
      if (name_ob->ob == NULL)
        {
          name_ob = ssh_adt_detach(map->prq, handle);
          name = name_ob->name;
          name_ob->refcount--;
          map_name_ob_free(map, name_ob);
          if (name && name->list == NULL)
            map_name_free(map, name);
          continue;
        }

      if (name_ob->priority >= stamp)
        break;

      /* It is old enough to be processed. */
      name_ob = ssh_adt_detach(map->prq, handle);
      name_ob->refcount--;

      if (name_ob->ob && name_ob->ob->op && name_ob->ob->op->state)
        {
          name_ob->refcount++;
          switch ((*name_ob->ob->op->state)(map,
                                            name_ob->context,
                                            name_ob->ob->ob_context))
            {
            case SSH_CM_MAP_STATE_FREE:
              /* Free the object. */
              name = name_ob->name;
              name_ob->refcount--;
              map_name_ob_free(map, name_ob);
              if (name && name->list == NULL)
                map_name_free(map, name);
              break;

            case SSH_CM_MAP_STATE_KEEP:
              /* Keep the object. */
              name_ob->priority = name_ob->delay_msecs + stamp;
              ssh_adt_insert(map->prq, name_ob);
              break;

            default:
              ssh_fatal("map_timeout_control: unknown state.");
              break;
            }
        }
      else
        {
          ssh_fatal("map_timeout_control: corrupted object detected.");
        }
    }

  return name_ob != NULL;
}

static Boolean
ssh_cm_map_remove_ob_internal(SshCMMap map, SshCMMapOb ob)
{
  SshCMMapNameOb name_ob, name_ob_next;

  for (name_ob = ob->list; name_ob; name_ob = name_ob_next)
    {
      name_ob_next = name_ob->o_next;

      /* Unlink the name (possibly destroying others too). */
      map_name_ob_unlink(map, name_ob);
    }

  /* Call the free routine for the context. */
  if (ob->ob_context &&
      ob->op &&
      ob->op->free_ob)
    {
      (*ob->op->free_ob)(map, ob->ob_context);
    }

  /* Mark removed. */
  ob->list    = NULL;
  ob->op      = NULL;
  ob->locator = 0;
  ob->ob_context = NULL;

  /* Free the object. */
  ssh_free(ob);

  return TRUE;
}

Boolean ssh_cm_map_remove_ob(SshCMMap map,
                             SshCMMapLocator locator)
{
  SshCMMapObStruct *ob, probe;
  SshADTHandle handle;

  probe.locator = locator;
  if ((handle = ssh_adt_get_handle_to_equal(map->objects, &probe))
      != SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("MAP: removing object: key=%ld",
                              (unsigned long) locator));

      ob = ssh_adt_get(map->objects, handle);
      ssh_adt_detach(map->objects, handle);
      ssh_cm_map_remove_ob_internal(map, ob);
      return TRUE;
    }
  return FALSE;
}

void ssh_cm_map_free(SshCMMap map)
{
  SshCMMapOb ob;
  SshCMMapNameOb name_ob;
  SshCMMapName name;
  SshADTHandle handle, next;

  if (map)
    {
      if (map->objects)
        {
          /* Clear objects */
          for (handle = ssh_adt_enumerate_start(map->objects);
               handle != SSH_ADT_INVALID;
               handle = next)
            {
              next = ssh_adt_enumerate_next(map->objects, handle);
              ob = ssh_adt_get(map->objects, handle);
              ssh_adt_detach(map->objects, handle);
              ssh_cm_map_remove_ob_internal(map, ob);
            }
          ssh_adt_destroy(map->objects);
        }

      if (map->prq)
        {
          while ((handle =
                  ssh_adt_get_handle_to_location(map->prq, SSH_ADT_DEFAULT))
                 != SSH_ADT_INVALID)
            {
              name_ob = ssh_adt_get(map->prq, handle);
              ssh_adt_detach(map->prq, handle);
              name_ob->refcount -= 1;
              map_name_ob_free(map, name_ob);
            }
          ssh_adt_destroy(map->prq);
        }

      if (map->names)
        {
          /* Clear map names. */
          for (handle = ssh_adt_enumerate_start(map->names);
               handle != SSH_ADT_INVALID;
               handle = next)
            {
              next = ssh_adt_enumerate_next(map->names, handle);
              name = ssh_adt_get(map->names, handle);
              map_name_free(map, name);
            }
          ssh_adt_destroy(map->names);
        }

      ssh_time_measure_reset(&map->timer);

      /* Clean the context. */
      memset(map, 0, sizeof(*map));
      /* Finally free the context. */
      ssh_free(map);
    }
}


SshCMMap ssh_cm_map_allocate(void)
{
  SshCMMap created;

  if ((created = ssh_calloc(1, sizeof(*created))) == NULL)
    return NULL;

  if ((created->objects =
       ssh_adt_create_generic(SSH_ADT_MAP,
                              SSH_ADT_HASH,    cm_map_object_hash,
                              SSH_ADT_COMPARE, cm_map_object_compare,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshCMMapObStruct, adt_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_free(created);
      return NULL;
    }

  if ((created->names =
       ssh_adt_create_generic(SSH_ADT_MAP,
                              SSH_ADT_HASH,    cm_map_name_hash,
                              SSH_ADT_COMPARE, cm_map_name_compare,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshCMMapNameStruct,
                                                adt_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_adt_destroy(created->objects);
      ssh_free(created);
      return NULL;
    }

  if ((created->prq =
       ssh_adt_create_generic(SSH_ADT_PRIORITY_HEAP,
                              SSH_ADT_COMPARE, cm_map_priority_compare,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshCMMapNameObStruct,
                                                prq_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_adt_destroy(created->objects);
      ssh_adt_destroy(created->names);
      ssh_free(created);
      return NULL;
    }

  /* Start from 1, leaving zero for other purposes. */
  created->id_no   = 1;

  /* Start up the time measure routines. */
  ssh_time_measure_init(&created->timer);
  ssh_time_measure_start(&created->timer);

  return created;
}

Boolean ssh_cm_map_link_op(SshCMMap map,
                           unsigned char *name,
                           size_t name_length,
                           SshUInt32 delay_msecs,
                           SshCMMapLocator locator,
                           void *context)
{
  SshCMMapObStruct *ob, probe;
  SshCMMapName name_ctx;
  SshCMMapNameOb name_ob;
  SshUInt64 stamp;
  SshADTHandle handle;

  if (locator == 0)
    return FALSE;

  /* Locate object, return FALSE is target object not present */
  probe.locator = locator;
  if ((handle = ssh_adt_get_handle_to_equal(map->objects, &probe))
      == SSH_ADT_INVALID)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                        ("MAP linking; NOT FOUND"), name, name_length);
      ssh_free(name);
      return FALSE;
    }
  else
    {
      ob = ssh_adt_get(map->objects, handle);
    }

  /* Attempt to find/create the name. */
  name_ctx = map_name_allocate(map, name, name_length);
  if (name_ctx == NULL)
    return FALSE;

  /* Now create a new name object. */
  if ((name_ob = map_name_ob_allocate()) == NULL)
    {
      map_name_free(map, name_ctx);
      return FALSE;
    }
  name_ob->ob      = ob;
  name_ob->context = context;
  name_ob->name    = name_ctx;
  name_ob->delay_msecs = delay_msecs;
  name_ob->free_in_process = FALSE;

  /* Link the name_ob. */
  map_name_ob_link(map, name_ob, name_ctx, ob);

  if (name_ob->delay_msecs)
    {
      /* Throw the 'name ob' to the delay list. */
      stamp = ssh_time_measure_stamp(&map->timer,
                                     SSH_TIME_GRANULARITY_MILLISECOND);
      /* Add the delay. */
      name_ob->priority = stamp + delay_msecs;
      name_ob->refcount++;
      ssh_adt_insert(map->prq, name_ob);
    }
  else
    {
      name_ob->refcount = 0;
    }
  return TRUE;
}


SshCMMapLocator ssh_cm_map_add_ob(SshCMMap map,
                                  const SshCMMapOp *op,
                                  void *ob_context)
{
  SshCMMapOb ob;
  unsigned long key = 0;

  if ((ob = ssh_calloc(1, sizeof(*ob))) != NULL)
    {
      /* Give out a new locator value. */
      key = (unsigned long)++map->id_no;

      ob->list       = NULL;
      ob->op         = op;
      ob->ob_context = ob_context;
      ob->locator    = key;

      SSH_DEBUG(SSH_D_MIDOK, ("MAP: adding object: key=%ld", key));
      ssh_adt_insert(map->objects, ob);
    }
  return key;
}

void ssh_cm_map_invoke(SshCMMap map,
                       const unsigned char *name,
                       size_t name_length,
                       void *msg)
{
  SshCMMapNameStruct *mapname, probe;
  SshCMMapNameOb name_ob, name_ob_next;
  SshADTHandle handle;

  if (name == NULL || name_length == 0)
    return;

  probe.name = name;
  probe.name_length = name_length;
  if ((handle = ssh_adt_get_handle_to_equal(map->names, &probe))
      == SSH_ADT_INVALID)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                        ("MAP: invoking; NOT FOUND"), name, name_length);
      return;
    }
  else
    {
      mapname = ssh_adt_get(map->names, handle);
    }

  /* Now run through all the name_obs. */
  for (name_ob = mapname->list; name_ob; name_ob = name_ob_next)
    {
      name_ob_next = name_ob->n_next;

      if (name_ob->ob && name_ob->ob->op && name_ob->ob->op->invoke)
        {
          name_ob->refcount++;

          SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                            ("MAP: invoking: (op=%ld)",
                             (unsigned long) name_ob->ob->locator),
                            name, name_length);

          switch ((*name_ob->ob->op->invoke)
                  (map, msg, name_ob->context, name_ob->ob->ob_context))
            {
            case SSH_CM_MAP_STATE_FREE:
              name_ob->refcount--;
              map_name_ob_free(map, name_ob);
              break;
            case SSH_CM_MAP_STATE_KEEP:
              name_ob->refcount--;
              break;
            default:
              ssh_fatal("ssh_cm_map_invoke: invalid status flag.");
              break;
            }
        }
    }

  if (mapname->list == NULL)
    map_name_free(map, mapname);
}

Boolean ssh_cm_map_check(SshCMMap map,
                         const unsigned char *name,
                         size_t name_length)
{
  SshCMMapNameStruct *mapname, probe;
  SshCMMapNameOb name_ob;
  SshADTHandle handle;

  if (name == NULL || name_length == 0)
    return FALSE;

  probe.name = name;
  probe.name_length = name_length;
  if ((handle = ssh_adt_get_handle_to_equal(map->names, &probe))
      == SSH_ADT_INVALID)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                        ("MAP: checking; NOT FOUND"), name, name_length);
      return FALSE;
    }
  else
    {
      mapname = ssh_adt_get(map->names, handle);
    }

  /* Look for a valid search context. */
  for (name_ob = mapname->list; name_ob; name_ob = name_ob->n_next)
    {
      if (name_ob->context || name_ob->ob || name_ob->name)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                            ("MAP: checking; FOUND"), name, name_length);
          return TRUE;
        }
    }
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                    ("MAP: checking; INVALID CONTEXT"), name, name_length);
  return FALSE;
}

/* cmi-map.c */
#endif /* SSHDIST_CERT */
