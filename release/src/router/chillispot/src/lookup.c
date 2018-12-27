/* 
 * Hash lookup function.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>

#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include <time.h>
#include <sys/time.h>

#include <signal.h>
#include <netdb.h>
#include "lookup.h"

extern int sem_id;
extern int sem_filter_id;

/**
 * lookup()
 * Generates a 32 bit hash.
 * Based on public domain code by Bob Jenkins
 * It should be one of the best hash functions around in terms of both
 * statistical properties and speed. It is NOT recommended for cryptographic
 * purposes.
 **/
unsigned long int lookup( k, length, level)
register unsigned char *k;         /* the key */
register unsigned long int length; /* the length of the key */
register unsigned long int level; /* the previous hash, or an arbitrary value*/
{

#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

  typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
  typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */
  register unsigned long int a,b,c,len;
  
  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
  c = level;           /* the previous hash value */
  
  /*---------------------------------------- handle most of the key */
  while (len >= 12)
    {
      a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
      b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
      c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
    }
  
  /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch(len)              /* all the case statements fall through */
    {
    case 11: c+=((ub4)k[10]<<24);
    case 10: c+=((ub4)k[9]<<16);
    case 9 : c+=((ub4)k[8]<<8);
      /* the first byte of c is reserved for the length */
    case 8 : b+=((ub4)k[7]<<24);
    case 7 : b+=((ub4)k[6]<<16);
    case 6 : b+=((ub4)k[5]<<8);
    case 5 : b+=k[4];
    case 4 : a+=((ub4)k[3]<<24);
    case 3 : a+=((ub4)k[2]<<16);
    case 2 : a+=((ub4)k[1]<<8);
    case 1 : a+=k[0];
      /* case 0: nothing left to add */
    }
  mix(a,b,c);
  /*-------------------------------------------- report the result */
  return c;
}

int create_shm(int id,int size,int type)
{
    int shmid;
    shmid = shmget((key_t)id, size, 0666|IPC_CREAT); //create share memory for progress
    if(shmid == -1)
    {
        fprintf(stderr, "shmget failed\n");
        exit(1);
    }

    if(type == 1)
    {
        struct conn_queue_t *q;
        if(attach_shm(&q) == -1)
            return;
        q->num = 0;
    }
    else if(type == 2)
    {
        struct http_filter_ctl_t *q;
        if(attach_filter_shm(&q) == -1)
            return;
        q->head = q->tail = NULL;
    }



    return shmid;
}

int del_shm(int id)
{
    //删除共享内存
    struct shmid_ds ds;
    if(shmctl(id,IPC_RMID,&ds) == -1)
        fprintf(stderr, "Failed to delete semaphore\n");
}

int attach_shm(struct conn_queue_t **q)
{
    void *shm = NULL;//分配的共享内存的原始首地址
    int shmid;//共享内存标识符

    shmid = shmget((key_t)1234, sizeof(struct conn_queue_t), 0666|IPC_CREAT);
    if(shmid == -1)
    {
        fprintf(stderr, "shmget failed\n");
        return -1;
    }
    //将共享内存连接到当前进程的地址空间
    shm = shmat(shmid, 0, 0);
    if(shm == (void*)-1)
    {
        fprintf(stderr, "shmat failed\n");
        return -1;
    }
    //printf("\nMemory attached at %X\n", (int)shm);
    *q = (struct conn_queue_t*)shm;

    return 0;
}

int attach_filter_shm(struct http_filter_ctl_t **q)
{
    void *shm = NULL;//分配的共享内存的原始首地址
    int shmid;//共享内存标识符

    shmid = shmget((key_t)1235, sizeof(struct conn_queue_t), 0666|IPC_CREAT);
    if(shmid == -1)
    {
        fprintf(stderr, "shmget failed\n");
        return -1;
    }
    //将共享内存连接到当前进程的地址空间
    shm = shmat(shmid, 0, 0);
    if(shm == (void*)-1)
    {
        fprintf(stderr, "shmat failed\n");
        return -1;
    }
    //printf("\nMemory attached at %X\n", (int)shm);
    *q = (struct http_filter_ctl_t *)shm;

    return 0;
}

int add_to_queue()
{
    struct conn_queue_t *q;

    if(attach_shm(&q) == -1)
        return;

    semaphore_p(sem_id);
    if(q->num >= UNAUTH_CONN_MAX)
    {
        semaphore_v(sem_id);
        //printf("unauth connections queue is full,num=%d\n",q->num);
        return -1;
    }
    q->num++;
    //printf("after add queue num=%d\n",q->num);
    semaphore_v(sem_id);
}

int del_from_queue()
{
    //sleep(2);

    struct conn_queue_t *q;

    if(attach_shm(&q) == -1)
        return;

    semaphore_p(sem_id);
    if(q->num <= 0)
    {
        semaphore_v(sem_id);
        //printf("unauth connections queue is empty,num=%d\n",q->num);
        return -1;
    }
    q->num--;
    //printf("after del queue num=%d\n",q->num);
    semaphore_v(sem_id);
}

int create_sem(int id)
{
    int sem_id;

    sem_id = semget((key_t)id, 1, 0666 | IPC_CREAT);  // create signal var for progress
    if(!set_semvalue(sem_id))
    {
        fprintf(stderr, "Failed to initialize semaphore\n");
        exit(1);
    }

    return sem_id;
}

//sem
int set_semvalue(int sem_id)
{
    //用于初始化信号量，在使用信号量前必须这样做
    union semun sem_union;

    sem_union.val = 1;
    if(semctl(sem_id, 0, SETVAL, sem_union) == -1)
        return 0;
    return 1;
}

void del_semvalue(int sem_id)
{
    //删除信号量
    union semun sem_union;

    if(semctl(sem_id, 0, IPC_RMID, sem_union) == -1)
        fprintf(stderr, "Failed to delete semaphore\n");
}

int semaphore_p(int sem_id)
{
    //对信号量做减1操作，即等待P（sv）
    struct sembuf sem_b;
    sem_b.sem_num = 0;
    sem_b.sem_op = -1;//P()
    sem_b.sem_flg = SEM_UNDO;
    if(semop(sem_id, &sem_b, 1) == -1)
    {
        fprintf(stderr, "semaphore_p failed\n");
        return 0;
    }
    return 1;
}

int semaphore_v(int sem_id)
{
    //这是一个释放操作，它使信号量变为可用，即发送信号V（sv）
    struct sembuf sem_b;
    sem_b.sem_num = 0;
    sem_b.sem_op = 1;//V()
    sem_b.sem_flg = SEM_UNDO;
    if(semop(sem_id, &sem_b, 1) == -1)
    {
        fprintf(stderr, "semaphore_v failed\n");
        return 0;
    }
    return 1;
}

int add_to_filter_queue(uint32_t saddr,uint32_t daddr)
{
    //printf("enter add_to_filter_queue function\n");
    struct http_filter_ctl_t *q;

    //printf("11\n");
    if(attach_filter_shm(&q) == -1)
        return;

    //printf("22\n");

    semaphore_p(sem_filter_id);
    //printf("33\n");
    add_filter_item(saddr,daddr,q);
    //printf("44\n");
    semaphore_v(sem_filter_id);
    //print_all_filter_item(q);
}

int get_host(char *buf,char *host)
{
    //printf("enter get_host() function\n");
    char *p,*p1 = NULL;
    p = strstr(buf,"Host: ");
    if(p)
    {
        p += 6;
        //printf("p=%s\n",p);
        p1 = strstr(p,"\r\n");
        if(p1)
        {
            //printf("p1=%s\n",p1);
            strncpy(host,p,strlen(p)-strlen(p1));
            return 0;
        }
    }
    //printf("get host fail\n");
    return -1;
}

int del_from_filter_queue(uint32_t saddr,char *buf)
{
    //sleep(20);
    //printf("enter del_from_filter_queue\n");
    char host[128] = {0};
    struct in_addr my_addr;
    uint32_t daddr = 0;
    struct sockaddr_in sa;
    struct http_filter_ctl_t *q;

    if(attach_filter_shm(&q) == -1)
        return -1;

    if(q->head == NULL)
        return 0;

    if(get_host(buf,host) == -1)
        return -1;

    //printf("host=%s\n",host);

    struct hostent *h;
    if((h = (struct hostent *)gethostbyname(host)) == NULL) {
        herror(host);
        return 0;
    }

    //printf("gethostbyname end\n");

    int j = 0;
    while (h->h_addr_list[j] != NULL)
    {
      memcpy(&sa.sin_addr, h->h_addr_list[j],h->h_length);
      semaphore_p(sem_filter_id);
      del_filter_item(saddr,sa.sin_addr.s_addr,q);
      semaphore_v(sem_filter_id);
      j++;
    }

    //print_all_filter_item(q);
}

int get_filter_item(uint32_t saddr,uint32_t daddr,struct http_filter_ctl_t *ctl)
{
    struct http_filter_t *p;
    //printf("xx\n");
    if(ctl->head == NULL)
        return -1;
    //printf("xxx\n");
    p = ctl->head;
    while(p != NULL)
    {
        if(p->saddr == saddr && p->daddr == daddr)
            return 0;
        p = p->next;
    }
    //printf("xxxx\n");

    return -1;
}

//filter queue
int add_filter_item(uint32_t saddr,uint32_t daddr,struct http_filter_ctl_t *ctl)
{
    //struct http_filter_t *p = NULL;
    //p = *head;
    //printf("aa\n");
    if(ctl->head != NULL)
    {
        if(get_filter_item(saddr,daddr,ctl) == 0) //find item;
        {
            //printf("##########this request handling,drop request##########\n");
            return -1;
        }
    }
    //printf("bb\n");
    struct http_filter_t *q= (struct http_filter_t *)malloc(sizeof(struct http_filter_t));
    q->saddr = saddr;
    q->daddr = daddr;
    q->next = NULL;
    //printf("cc\n");
    if(ctl->tail)
        ctl->tail->next = q;
    else
        ctl->head = ctl->tail = q;
    //printf("dd\n");
    return 0;
}

int del_filter_item(uint32_t saddr,uint32_t daddr,struct http_filter_ctl_t *ctl)
{
    struct http_filter_t *p,*p1;
    //printf("in_saddr=%x,in_daddr=%x\n",saddr,daddr);

    if(ctl->head == NULL)
        return -1;

    p = ctl->head;
    while(p != NULL)
    {
        //printf("saddr=%x,daddr=%x\n",p->saddr,p->daddr);
        if(p->saddr == saddr && p->daddr == daddr)
        {
            //printf("find item\n");
            if(p == ctl->head)
            {
                if(p->next == NULL)
                    ctl->head = ctl->tail = NULL;
                else
                    ctl->head = p->next;
            }
            else if(p == ctl->tail)
            {
                p1->next = NULL;
                ctl->tail = p1;
            }
            else
            {
                p1->next = p->next;
            }

             free(p);

            return 0;
        }
        p1 = p;
        p = p->next;
    }

    //printf("can not find item\n");

    return -1;
}

void clear_filter_item()
{
    struct http_filter_ctl_t *q;
    if(attach_filter_shm(&q) == -1)
        return;

    semaphore_p(sem_filter_id);
    free_filter_item(q);
    semaphore_v(sem_filter_id);
}

void free_filter_item(struct http_filter_ctl_t *ctl)
{
    struct http_filter_t *p,*p1;

    if(ctl->head == NULL)
        return;

    p = ctl->head;
    while(p != NULL)
    {
        p1 = p;
        p = p->next;
        free(p1);
    }

    ctl->head = ctl->tail == NULL;

    return;
}

void print_all_filter_item(struct http_filter_ctl_t *ctl)
{
    struct http_filter_t *p;
    struct in_addr saddr,daddr;

    if(ctl->head == NULL)
    {
        printf("filter is null\n");
        return;
    }

    p = ctl->head;
    while(p != NULL)
    {
        saddr.s_addr = p->saddr;
        daddr.s_addr = p->daddr;
        printf("saddr=%s\n",inet_ntoa(saddr));
        printf("daddr=%s\n",inet_ntoa(daddr));
        p = p->next;
    }

    return;
}

