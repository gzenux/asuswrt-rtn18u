/*
 * @File: list.h
 *
 * @Abstract: Double linked-list implementation.
 *
 * @Notes:
 *
 * Copyright (c) 2011 Atheros Communications Inc.
 * All rights reserved.
 *
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef list__h
#define list__h

#include <sys/types.h>
#include <stddef.h>

/*
 * Double linked list type
 */
typedef struct list_head_t
{
	struct list_head_t *next;
	struct list_head_t *prev;

} list_head_t;

/*
 * Setup the list head
 * head:	list head.
 *
 */
static inline void list_set_head( list_head_t *head )
{
	head->next = head;
	head->prev = head;
}

/*
 * Remove an entry from the list
 * entry:	list element to remove.
 */
static inline void list_remove_entry( list_head_t *entry )
{
	/* Disconnect entry from prev and next entries */
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;

	/* Clear the entry's prev and next pointers */
	entry->prev = NULL; entry->next = NULL;
}

/*
 * Check if a list is empty
 * head:	list head.
 */
static inline u_int32_t list_is_empty( const list_head_t *head )
{
	return ( head->next == head );
}

/*
 * Insert an entry before a list head
 * entry:	list element to insert.
 * head:	list head.
 */
static inline void list_insert_entry( list_head_t *entry, list_head_t *head )
{
	/* Connect the new entry to the head and its previous */
	entry->next = head;
	entry->prev = head->prev;

	/* Connect the head's previous to the new entry as next */
	head->prev->next = entry;

	/* Connect the head to the new entry as prev */
	head->prev = entry;
}

/*
 * Get the struct for this entry
 * _head:	the list head pointer.
 * _type:	data type of structure.
 * _member:	member name.
 */
#define list_entry( _head, _type, _member ) \
	container_of( _head, _type, _member )

/*
 * Get the first entry from a list
 * _head:	the list head to take the element from.
 * _type:	data type of structure.
 * _member:	member name.
 */
#define list_first_entry( _head, _type, _member ) \
		container_of( (_head)->next, _type, _member )

/*
 * For loop iteration on a list
 * _entry:	a list_head_t element to use as a loop cursor.
 * _head:	list head.
 */
#define list_for_each( _entry, _head ) \
	for ( _entry = (_head)->next; (_entry) != (_head); _entry = (_entry)->next )

/*
 * container_of - cast a member of a structure out to the containing structure
 * _ptr:    the pointer to the member.
 * _type:   the type of the container struct this is embedded in.
 * _member: the name of the member within the struct.
 *
 */
#define container_of( _ptr, _type, _member) ({ \
            const typeof( ((_type *)0)->_member ) *__mptr = (_ptr);    \
            (_type *)( (u_int8_t *)__mptr - offsetof(_type,_member) ); \
    })

#endif
