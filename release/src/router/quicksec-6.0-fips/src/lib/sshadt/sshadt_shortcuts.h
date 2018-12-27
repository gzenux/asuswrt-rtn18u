/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Abstract Data Type (ADT) utility functions.
*/

#ifndef SSHADT_INSIDE_SSHADT_H
#error sshadt_shorcuts.h cannot be included outside sshadt.h
#endif

#define ssh_adt_insert(c, o)                                                  \
  ssh_adt_insert_to((c), SSH_ADT_DEFAULT, (o))

#define ssh_adt_alloc(c)                                                      \
  ssh_adt_alloc_to((c), SSH_ADT_DEFAULT)

#define ssh_adt_alloc_n(c, s)                                                 \
  ssh_adt_alloc_n_to((c), SSH_ADT_DEFAULT, (s))

#define ssh_adt_alloc_at(c, l, h)                                             \
  ssh_adt_alloc_n_at((c),(l),(h),SSH_ADT_DEFAULT_SIZE(c))

#define ssh_adt_alloc_to(c, l)                                                \
  ssh_adt_alloc_n_to((c),(l),SSH_ADT_DEFAULT_SIZE(c))

#define ssh_adt_put_at(c, l, h, o)                                            \
  ssh_adt_put_n_at((c), (l), (h), SSH_ADT_DEFAULT_SIZE(c), (o))

#define ssh_adt_put_to(c, l, o)                                               \
  ssh_adt_put_n_to((c), (l), SSH_ADT_DEFAULT_SIZE(c), (o))

#define ssh_adt_put(c, o)                                                     \
  ssh_adt_put_to((c), SSH_ADT_DEFAULT, (o))

#define ssh_adt_put_n(c, s1, o)                                               \
  ssh_adt_put_n_to((c), SSH_ADT_DEFAULT, (s1), (o))

#define ssh_adt_detach_object(c, o)                                           \
  ssh_adt_detach(c, ssh_adt_get_handle_to(c, o))

#define ssh_adt_delete_object(c, o)                                           \
  ssh_adt_delete(c, ssh_adt_get_handle_to(c, o))

#define ssh_adt_detach_from(c, l)                                             \
  ssh_adt_detach(c, ssh_adt_get_handle_to_location(c, l))

#define ssh_adt_delete_from(c, l)                                             \
  ssh_adt_delete(c, ssh_adt_get_handle_to_location(c, l))

#define ssh_adt_duplicate_at(c, l, h, o)                                      \
  ssh_adt_insert_at(c, l, h, ssh_adt_duplicate_object(c, o))

#define ssh_adt_duplicate_to(c, l, o)                                         \
  ssh_adt_insert_to(c, l, ssh_adt_duplicate_object(c, o))

#define ssh_adt_duplicate(c, o)                                               \
  ssh_adt_insert(c, ssh_adt_duplicate_object(c, o))

#define ssh_adt_default_size(c)                                               \
  SSH_ADT_DEFAULT_SIZE(c)

#define ssh_adt_get_object_from_equal(c, o)                                   \
  ssh_adt_get(c, ssh_adt_get_handle_to_equal(c, o))

#define ssh_adt_get_object_from_location(c, l)                                \
  ssh_adt_get(c, ssh_adt_get_handle_to_location(c, l))
