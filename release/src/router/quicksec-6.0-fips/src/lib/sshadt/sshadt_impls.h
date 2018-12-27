/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Abstract Data Type (ADT) utility functions.
*/

#ifdef SSH_ADT_WITH_MACRO_INTERFACE
#define ssh_adt_clear(a1) \
  (*((a1)->static_data->methods.clear))(a1)
#define ssh_adt_insert_at(a1, a2, a3, a4) \
  (*((a1)->static_data->methods.insert_at))(a1, a2, a3, a4)
#define ssh_adt_insert_to(a1, a2, a3) \
  (*((a1)->static_data->methods.insert_to))(a1, a2, a3)
#define ssh_adt_alloc_n_at(a1, a2, a3, a4) \
  (*((a1)->static_data->methods.alloc_n_at))(a1, a2, a3, a4)
#define ssh_adt_alloc_n_to(a1, a2, a3) \
  (*((a1)->static_data->methods.alloc_n_to))(a1, a2, a3)
#define ssh_adt_put_n_at(a1, a2, a3, a4, a5) \
  (*((a1)->static_data->methods.put_n_at))(a1, a2, a3, a4, a5)
#define ssh_adt_put_n_to(a1, a2, a3, a4) \
  (*((a1)->static_data->methods.put_n_to))(a1, a2, a3, a4)
#define ssh_adt_get(a1, a2) \
  (*((a1)->static_data->methods.get))(a1, a2)
#define ssh_adt_num_objects(a1) \
  (*((a1)->static_data->methods.num_objects))(a1)
#define ssh_adt_get_handle_to(a1, a2) \
  (*((a1)->static_data->methods.get_handle_to))(a1, a2)
#define ssh_adt_get_handle_to_location(a1, a2) \
  (*((a1)->static_data->methods.get_handle_to_location))(a1, a2)
#define ssh_adt_next(a1, a2) \
  (*((a1)->static_data->methods.next))(a1, a2)
#define ssh_adt_previous(a1, a2) \
  (*((a1)->static_data->methods.previous))(a1, a2)
#define ssh_adt_enumerate_start(a1) \
  (*((a1)->static_data->methods.enumerate_start))(a1)
#define ssh_adt_enumerate_next(a1, a2) \
  (*((a1)->static_data->methods.enumerate_next))(a1, a2)
#define ssh_adt_get_handle_to_equal(a1, a2) \
  (*((a1)->static_data->methods.get_handle_to_equal))(a1, a2)
#define ssh_adt_realloc(a1, a2, a3) \
  (*((a1)->static_data->methods.reallocate))(a1, a2, a3)
#define ssh_adt_detach(a1, a2) \
  (*((a1)->static_data->methods.detach))(a1, a2)
#define ssh_adt_delete(a1, a2) \
  (*((a1)->static_data->methods.delet))(a1, a2)
#define ssh_adt_map_lookup(a1, a2) \
  (*((a1)->static_data->methods.map_lookup))(a1, a2)
#define ssh_adt_map_attach(a1, a2, a3) \
  (*((a1)->static_data->methods.map_attach))(a1, a2, a3)
#endif /* SSH_ADT_WITH_MACRO_INTERFACE */
#ifdef SSH_ADT_INTERNAL_MACROS
#define ssh_adt_clear__(a1) \
  (*((a1)->static_data->methods.clear))(a1)
#define ssh_adt_insert_at__(a1, a2, a3, a4) \
  (*((a1)->static_data->methods.insert_at))(a1, a2, a3, a4)
#define ssh_adt_insert_to__(a1, a2, a3) \
  (*((a1)->static_data->methods.insert_to))(a1, a2, a3)
#define ssh_adt_alloc_n_at__(a1, a2, a3, a4) \
  (*((a1)->static_data->methods.alloc_n_at))(a1, a2, a3, a4)
#define ssh_adt_alloc_n_to__(a1, a2, a3) \
  (*((a1)->static_data->methods.alloc_n_to))(a1, a2, a3)
#define ssh_adt_put_n_at__(a1, a2, a3, a4, a5) \
  (*((a1)->static_data->methods.put_n_at))(a1, a2, a3, a4, a5)
#define ssh_adt_put_n_to__(a1, a2, a3, a4) \
  (*((a1)->static_data->methods.put_n_to))(a1, a2, a3, a4)
#define ssh_adt_get__(a1, a2) \
  (*((a1)->static_data->methods.get))(a1, a2)
#define ssh_adt_num_objects__(a1) \
  (*((a1)->static_data->methods.num_objects))(a1)
#define ssh_adt_get_handle_to__(a1, a2) \
  (*((a1)->static_data->methods.get_handle_to))(a1, a2)
#define ssh_adt_get_handle_to_location__(a1, a2) \
  (*((a1)->static_data->methods.get_handle_to_location))(a1, a2)
#define ssh_adt_next__(a1, a2) \
  (*((a1)->static_data->methods.next))(a1, a2)
#define ssh_adt_previous__(a1, a2) \
  (*((a1)->static_data->methods.previous))(a1, a2)
#define ssh_adt_enumerate_start__(a1) \
  (*((a1)->static_data->methods.enumerate_start))(a1)
#define ssh_adt_enumerate_next__(a1, a2) \
  (*((a1)->static_data->methods.enumerate_next))(a1, a2)
#define ssh_adt_get_handle_to_equal__(a1, a2) \
  (*((a1)->static_data->methods.get_handle_to_equal))(a1, a2)
#define ssh_adt_realloc__(a1, a2, a3) \
  (*((a1)->static_data->methods.reallocate))(a1, a2, a3)
#define ssh_adt_detach__(a1, a2) \
  (*((a1)->static_data->methods.detach))(a1, a2)
#define ssh_adt_delete__(a1, a2) \
  (*((a1)->static_data->methods.delet))(a1, a2)
#define ssh_adt_map_lookup__(a1, a2) \
  (*((a1)->static_data->methods.map_lookup))(a1, a2)
#define ssh_adt_map_attach__(a1, a2, a3) \
  (*((a1)->static_data->methods.map_attach))(a1, a2, a3)
#endif /* SSH_ADT_INTERNAL_MACROS */
