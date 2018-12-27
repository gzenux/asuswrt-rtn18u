/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_CMI_MAP_H
#define SSH_CMI_MAP_H

#include "cmi.h"
#include "sshtimemeasure.h"

/* The locator object. A zero (0) implies that the locator is invalid. */
#define SshCMMapLocator unsigned long

typedef struct SshCMMapRec *SshCMMap;

typedef enum
{
  SSH_CM_MAP_STATE_FREE,
  SSH_CM_MAP_STATE_KEEP
} SshCMMapState;

typedef struct SshCMMapOprec
{
  /* The function which is called periodically. Its purpose is to
     tell when the delay time is up. */
  SshCMMapState (*state)(SshCMMap        map,
                         void           *context,
                         void           *ob_context);

  /* A special msg is sent to all the contexts by the same name. */
  SshCMMapState (*invoke)(SshCMMap        map,
                          void           *msg,
                          void           *context,
                          void           *ob_context);

  /* The free routine. This is called when the context requests to be
     removed, or when the map gets freed itself. */
  void (*free_ob)(SshCMMap map,
                  void    *ob_context);
  void (*free_name_ctx)(SshCMMap map,
                        void *context,
                        void *ob_context);
} SshCMMapOp;

/* Allocate a new map object. */
SshCMMap ssh_cm_map_allocate(void);

/* Free the map object and everything inside it. */
void ssh_cm_map_free(SshCMMap map);

/* Add a new object to the MAP, this produces a unique identifier for the
   object. Observe that same object can be added multiple times. */
SshCMMapLocator ssh_cm_map_add_ob(SshCMMap       map,
                                  const SshCMMapOp    *op,
                                  void                *ob_context);

/* Remove the object pointed by "locator" from the map. Please note
   that this also invalidates the locators at any "name" list. */
Boolean ssh_cm_map_remove_ob(SshCMMap       map,
                             SshCMMapLocator      locator);

/* Relate the "locator" to the "name". That is build a hash table
   entry by the key "name" with value "locator".

   Name must be allocated by the caller, and is freed by this routine. */
Boolean ssh_cm_map_link_op(SshCMMap             map,
                           unsigned char       *name,
                           size_t               name_length,
                           SshUInt32            delay_msecs,
                           SshCMMapLocator      locator,
                           void                *context);

/* Look for a name, and if such a name exists within the map this
   returns TRUE, otherwise returns FALSE. */
Boolean ssh_cm_map_check(SshCMMap             map,
                         const unsigned char *name,
                         size_t               name_length);

/* Send a message.
   This message is sent to all the objects linked to the name. */
void ssh_cm_map_invoke(SshCMMap             map,
                       const unsigned char *name,
                       size_t               name_length,
                       void                *msg);

/* Clean up map. Should be called periodically.  Return TRUE if map
   still has items. If no items at the map, one should not register
   timeouts to call this. */
Boolean ssh_cm_map_control(SshCMMap map);

#endif /* SSH_CMI_MAP_H */
