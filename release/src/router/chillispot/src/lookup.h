/* 
 * Hash lookup function.
 * Copyright (C) 2003, 2004 Mondru AB.
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

/**
 * lookup()
 * Generates a 32 bit hash.
 * Based on public domain code by Bob Jenkins
 * It should be one of the best hash functions around in terms of both
 * statistical properties and speed. It is NOT recommended for cryptographic
 * purposes.
 **/

#ifndef _LOOKUP_H
#define _LOOKUP_H
unsigned long int lookup( unsigned char *k, unsigned long int length, unsigned long int level);

#include <sys/shm.h>
#include <sys/sem.h>
//#include <sys/types.h>

#define UNAUTH_CONN_MAX 25
//typedef unsigned long uint32;

struct conn_queue_t
{
    int num;
};

extern struct conn_queue_t conn_queue;

struct http_filter_t
{
    uint32_t saddr;
    uint32_t daddr;
    struct http_filter_t *next;
};

struct http_filter_ctl_t
{
   struct http_filter_t *head;
   struct http_filter_t *tail;
};

//extern struct http_filter_t *http_filter_head;
extern struct http_filter_ctl_t http_filter_ctl;

union semun
{
    int val;
    struct semid_ds *buf;
    unsigned short *arry;
};

int create_shm(int id,int size,int type);
int del_shm(int id);
int add_to_queue();
int del_from_queue();

int create_sem(int id);
int set_semvalue(int sem_id);
void del_semvalue(int sem_id);
static int semaphore_p(int sem_id);
static int semaphore_v(int sem_id);

int add_to_filter_queue(uint32_t saddr,uint32_t daddr);
int del_from_filter_queue(uint32_t saddr,char *buf);

int add_filter_item(uint32_t saddr,uint32_t daddr,struct http_filter_ctl_t *ctl);
int del_filter_item(uint32_t saddr,uint32_t daddr,struct http_filter_ctl_t *ctl);
int get_filter_item(uint32_t saddr,uint32_t daddr,struct http_filter_ctl_t *ctl);
void free_filter_item(struct http_filter_ctl_t *ctl);
void print_all_filter_item(struct http_filter_ctl_t *ctl);

#endif	/* !_LOOKUP_H */
