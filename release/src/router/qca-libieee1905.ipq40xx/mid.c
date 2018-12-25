/*
 * Copyright (c) 2012, Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <unistd.h>
#include <pthread.h>
#include <sys/shm.h>
#include "mid.h"

typedef struct messageIdMem_t
{
    key_t key;
    int32_t id;
    void *addr;

} messageIdMem_t;

typedef struct messageId_t
{
    pthread_mutex_t lock;
    u_int16_t mid;

} messageId_t;

static messageIdMem_t messageIdMem;
static messageId_t *messageId = NULL;

int32_t messageId_init( void )
{
    int32_t newMessageId = 0;

    /* Check if this is the first time we call init */
    if( !messageId )
    {
        /* Generate an IPC key */
        if( ( messageIdMem.key = ftok( "/proc/version", 63 ) ) == -1 )
        {
            return -1;
        }

        /* Try to get an existing shared memory segment from different contexts */
        if( ( messageIdMem.id = shmget( messageIdMem.key, 0, 0666 ) ) < 0 )
        {
            newMessageId = 1;

            /* If it doesn't exist, create it - We are the first context */
            if( ( messageIdMem.id = shmget( messageIdMem.key, sizeof(u_int16_t), IPC_CREAT | 0666 ) ) < 0 )
            {
                return -1;
            }
        }

        /* Get the shared memory segment address */
        if( ( messageIdMem.addr = shmat( messageIdMem.id, NULL, 0 ) ) == NULL )
        {
            return -1;
        }

        /* messageId actually holds the mid data */
        messageId = (messageId_t *)messageIdMem.addr;

        if( newMessageId )
        {
            pthread_mutexattr_t mutex_attr;

            /* Make the lock shared across all processes */
            pthread_mutexattr_init( &mutex_attr );
            pthread_mutexattr_setpshared( &mutex_attr, PTHREAD_PROCESS_SHARED );
            pthread_mutex_init( &messageId->lock, &mutex_attr );

            /* Set mid to 0 */
            messageId->mid = 0;
        }
    }
    return 0;
}

u_int16_t messageId_getNext( void )
{
    u_int16_t mid;

    if( !messageId )
    {
        messageId_init();

        if( !messageId )
            return -1;
    }

    /* Lock access */
    pthread_mutex_lock( &messageId->lock );

    /* Atomically get and increment mid */
    mid = messageId->mid++;

    /* Unlock access */
    pthread_mutex_unlock( &messageId->lock );

    return mid;
}

void messageId_reset( void )
{
    if( !messageId )
    {
        return;
    }

    /* Lock access */
    pthread_mutex_lock( &messageId->lock );

    /* Atomically reset mid */
    messageId->mid = 0;

    /* Unlock access */
    pthread_mutex_unlock( &messageId->lock );
}
