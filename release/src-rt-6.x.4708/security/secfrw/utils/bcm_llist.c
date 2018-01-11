/*
 * Linked list manipulation routines
 * See discussion below for more info
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcm_llist.c,v 1.5 2010-12-21 23:05:53 $
 */

#include <stdio.h>
#include <typedefs.h>
#include <bcm_llist.h>
#include <debug.h>


/* Discussion
 * The functions herein provide a means of adding and deleting a list member
 * from a given singly linked list.
 * You must create your list with the next pointer as the first element in the
 * list element structure.
 */

#ifdef TARGETOS_symbian
extern int SymbianOslPrintf(const char *format, ...);
#define printf SymbianOslPrintf
#endif


typedef struct list {
	struct list * next;
}list_t;


/* Adds member pnew to list *head if possible */
int bcm_llist_add_member(void *pplhd, void *plmember)
{
	list_t **head = (list_t **)pplhd;
	list_t *pnew = (list_t *)plmember;
	char *funstr = "bcm_llist_add_member";

	if (pnew == NULL) {
		PRINT(("%s: can't add NULL member\n", funstr));
		return -1;
	}
	pnew->next = *head;
	*head = pnew;
	return 0;
}


/* Removes member pdel from list *head if possible */
int bcm_llist_del_member(void *pplhd, void *plmember)
{
	list_t **head = (list_t **)pplhd;
	list_t *pdel = (list_t *)plmember;
	list_t *pprev, *plist;
	char *funstr = "bcm_llist_del_member";

	PRINT_TRACE(("%s: Requested to delete member %p from list %p\n",
		funstr, pdel, *head));

	if (*head == NULL) {
		PRINT_TRACE(("%s: list empty\n", funstr));
		return -1;
	}
	if (pdel == NULL) {
		PRINT(("%s: can't delete NULL member\n", funstr));
		return -1;
	}

	for (plist = *head, pprev = NULL; plist; ) {
		if (plist == pdel) {
			/* first entry? */
			if (pprev == NULL)
				*head = plist->next;
			else
				pprev->next = plist->next;

			return 0;

		}
		/* advancd */
		pprev = plist;
		plist = plist->next;
	}

	/* not found */
	PRINT_TRACE(("%s: member %p not found in list %p\n",
		funstr, pdel, *head));
	return -1;
}

/* Removes member containing "arg" from list *head if possible,
 * If successful returns pointer to that member, otherwise NULL
 */
void * bcm_llist_del_membercmp(void *pplhd, void *arg, bool (*pcmp)(void *, void *))
{
	list_t **head = (list_t **)pplhd;
	list_t *pprev, *plist;
	char *funstr = "bcm_llist_del_member";

	PRINT_TRACE(("%s: Requested to delete member with %p from list %p\n",
		funstr, arg, *head));

	if (*head == NULL) {
		PRINT_TRACE(("%s: list empty\n", funstr));
		return NULL;
	}
	if (pcmp == NULL) {
		PRINT(("%s: comparison fun NULL, bailing \n", funstr));
		return NULL;
	}

	for (plist = *head, pprev = NULL; plist; ) {
		if ((*pcmp)(plist, arg)) {
			/* first entry? */
			if (pprev == NULL)
				*head = plist->next;
			else
				pprev->next = plist->next;

			return plist;

		}
		/* advancd */
		pprev = plist;
		plist = plist->next;
	}

	/* not found */
	PRINT_TRACE(("%s: member %p not found in list %p\n",
		funstr, arg, *head));
	return NULL;
}
