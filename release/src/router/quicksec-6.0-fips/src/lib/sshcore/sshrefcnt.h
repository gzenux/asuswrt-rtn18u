/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Reference counting code.

   <keywords reference counting, counting/reference,
   utility functions/reference counting>

   @internal

   @description
   Generic macros for making reference counted objects. This is very useful
   when using fsm threads and you want to change the configuration on the fly.
   The old configuration data (i.e all data that is referenced by the running
   fsm threads), must be kept intact untill the fsm thread exits, but when the
   final reference to the object disappeares then the object should be
   immediately freed (or closed).

   The usage is quite simple. First you add SSH_REF_CNT_DEFINE(object_type)
   defines in the beginning of some header file that is used to define the
   object_type itself. This will define new structure that contains the
   original object and a reference counter. Then you replace all the
   object_type type names with the SSH_REF_CNT_TYPE(object_type), so all the
   places where you used to use object_type you now use the new reference
   counted object type.

   The next step is to allocate new object. This must be done using the
   SSH_REF_CNT_ALLOC(name, object) macro. The name is the variable of type
   SSH_REF_CNT_TYPE(object_type), and the allocated object is stored there. The
   object is the object itself to be stored in the reference counted object.
   This can be function call to allocate the object. When the object is
   allocated it already has one reference to it, namely the `name' variable
   contains reference to it.

   When you want to get the actual object from the referenced object (of type
   SSH_REF_CNT_TYPE(object_type)) you must use SSH_REF_CNT_REF(name) macro.

   When you want to take extra reference to the object you use
   SSH_REF_CNT_INC(name) macro. That will return NEW object pointer that you
   must store for later SSH_REF_CNT_DEC macro call. This new object pointer is
   actually copy of the current value of the name, but because you quite often
   use some global data to actually get the name, you cannot use that later
   when you want to derefence the object. The global data might already be
   freed at that point. So you want to store the object returned from the
   SSH_REF_CNT_INC to thread or callback local data structure, and you don't
   want to reference the global data again (the value of that might already
   have changed).

   When you don't need the reference anymore you might free it by using the
   SSH_REF_CNT_DEC(name, free_func) macro. The first object is the variable of
   type SSH_REF_CNT_TYPE(object_type) that was returned by the SSH_REF_CNT_INC
   macro. The second argument is operation that might be used to free the
   object in case this was last reference to it. Note, that you normally give
   the actual object to the free function, so you must use free function like
   ssh_xfree(SSH_REF_CNT_REF(name)).

   Here is a short example:

   @example
   ...
   #include "sshrefcnt.h"                                  Include sshrefcnt.h

   SSH_REF_CNT_DEFINE(FooObject);                          Define new
                                                           referenced
                                                           type for FooObject

   typedef struct GlobalDataRec {
     SSH_REF_CNT_TYPE(FooObject) foo_obj;                  This field is the
   } *GlobalData;                                          referenced FooObject

   typedef struct ThreadDataRec {
     SSH_REF_CNT_TYPE(FooObject) foo_obj;                  This is the thread
   } *ThreadData;                                          local reference to
   ...                                                     global FooObject

   void init(void)
   {
     ...                                                   Initialize threads
     SSH_REF_CNT_ALLOC(gdata->foo_obj,                     and allocate global
                       foo_obj_alloc(foo_param1,           FooObject. This is
                                     foo_param2));         the object that is
     ...                                                   used to take
                                                           references.
   }

   void start_using_it(void)
   {
     ...                                                   New thread wants to
     tdata->foo_obj = SSH_REF_CNT_INC(gdata->foo_obj);     use the FooObject,
     ...                                                   so it takes a
                                                           reference and
   }                                                       stores the current
                                                           value of FooObject
                                                           to thread local
                                                           data.
   void use_it(void)
   {
     ...                                                   When the threads use
     foo_obj_do(SSH_REF_CNT_REF(tdata->foo_obj);           object they use the
     ...                                                   local reference. The
   }                                                       global object might
                                                           already be different
                                                           now.
   void end_using_it(void)
   {
     ...                                                   When the thread does
     SSH_REF_CNT_DEC(tdata->foo_obj,                       does not need the
             foo_obj_free(SSH_REF_CNT_REF(tdata->          obj anymore it will
                                          foo_obj)));      free the reference.
     ...                                                   If this object still
                                                           has some
   }                                                       references it only
                                                           decrements the
                                                           reference counter.
                                                           If this was last
                                                           reference then it
                                                           frees
                                                           the object using the
                                                           free function.
   void reconfigure(void)
   {                                                       When server is
     ...                                                   reconfigured the
     SSH_REF_CNT_DEC(gdata->foo_obj,                       global reference to
             foo_obj_free(SSH_REF_CNT_REF(tdata->          the object is
                                          foo_obj)));      removed. If there
                                                           was no other
                                                           references to obj
                                                           it is freed at this
                                                           point. If there is
                                                           other references
                                                           then this will just
                                                           decrement the
                                                           reference
                                                           counter and then the
                                                           when the final
                                                           reference is freed
                                                           the object is freed.

     SSH_REF_CNT_ALLOC(gdata->foo_obj,                     After that the
                       foo_obj_alloc(new_param1,           serverallocates new
                                     new_param2));         object with new
     ...                                                   parameters and
   }                                                       and stores that to
                                                           the global
                                                           structure. New
                                                           transactions take
                                                           copy of this instead
                                                           of using the old
                                                           object.
*/

#ifndef SSHREFCNT_H
#define SSHREFCNT_H


/** Define new reference counted type for object of type `object_type'. */
#define SSH_REF_CNT_DEFINE(object_type) \
typedef struct SshRefCnt##object_type##Rec { \
  object_type o; \
  int r; \
} *SshRefCnt##object_type

/** Return reference counted type when the object type is given. */
#define SSH_REF_CNT_TYPE(object_type) SshRefCnt##object_type

/** Allocate referenced variable `lvalue', and store `object' there.
    This will automatically take one reference. Note the `lvalue' is
    executed multiple times, but the `object' only once. */
#define SSH_REF_CNT_ALLOC(lvalue,object) \
  do { \
    (lvalue) = ssh_xmalloc(sizeof(*(lvalue))); \
    (lvalue)->r = 1; \
    (lvalue)->o = (object); \
  } while (0)

/** Return actual object from the reference counted variable. */
#define SSH_REF_CNT_REF(lvalue) ((lvalue)->o)

/** Take reference to `lvalue' and increment reference counter.
    You must store the returned pointer somewhere. */
#define SSH_REF_CNT_INC(lvalue) ((lvalue)->r++, lvalue)

/** Decrement reference in the `lvalue'. The `lvalue' must be something
    that is either allocated using the SSH_REF_CNT_ALLOC (original
    reference), or something that was returned by the SSH_REF_CNT_INC.
    Note: you cannot call this twice for the same object. This will also
    automatically set the `lvalue' to NULL. The `code_to_free_object'
    is executed in case the object needs to be freed. */
#define SSH_REF_CNT_DEC(lvalue,code_to_free_object) \
  do { \
    if (--(lvalue)->r <= 0) \
      { \
        { code_to_free_object; } \
        ssh_xfree(lvalue); \
      } \
      (lvalue) = NULL; \
  } while (0)

#endif /* SSHREFCNT_H */
