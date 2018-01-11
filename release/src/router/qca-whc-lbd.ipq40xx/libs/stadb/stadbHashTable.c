// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbHashTable.c
 *
 * @Abstract: Implementation of a hash table of stadbEntry objects
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include <stdlib.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif /* LBD_DBG_MENU */

#include "list.h"
#include "lb_common.h"

#include "stadbHashTable.h"
#include "stadbEntryPrivate.h"

// Forward decls
static stadbEntry_handle_t stadbHashTableFindWithinBucket(
        stadbHashTableHandle_t table, u_int8_t bucketIndex,
        const struct ether_addr *addr);
static void stadbHashTableDestroyBucket(stadbHashTableHandle_t table,
                                        u_int8_t bucketIndex);
static void stadbHashTableIterateBucket(stadbHashTableHandle_t table,
                                        u_int8_t bucketIndex,
                                        stadbHashTableIterFunc_t callbac,
                                        void *cookie);

// The (very simple) hash function for MAC addresses in internal.h that is
// being used just XORs all of the bytes together. This will lead to a value
// from 0-255. Thus, there is no need for the hash table size to be a prime.
// Of course this hash function may not be well designed, so this may need to
// be revisited.
#define HASH_TABLE_SIZE 256

typedef struct stadbHashTablePriv_t {
    size_t      curSize;
    list_head_t buckets[HASH_TABLE_SIZE];
} stadbHashTablePriv_t;

stadbHashTableHandle_t stadbHashTableCreate(void) {
    stadbHashTableHandle_t table = calloc(1, sizeof(stadbHashTablePriv_t));

    // Initialize all of the buckets to be empty.
    size_t i;
    for (i = 0; i < HASH_TABLE_SIZE; ++i) {
        list_set_head(&table->buckets[i]);
    }

    return table;
}

stadbEntry_handle_t stadbHashTableFind(stadbHashTableHandle_t table,
                                      const struct ether_addr *addr) {
    if (!table || !addr) {
        return NULL;
    }

    u_int8_t hashcode = stadbEntryComputeHashCode(addr);
    if (!list_is_empty(&table->buckets[hashcode])) {
        return stadbHashTableFindWithinBucket(table, hashcode, addr);
    }

    return NULL;
}

LBD_STATUS stadbHashTableInsert(stadbHashTableHandle_t table,
                                stadbEntry_handle_t entry) {
    if (!table || !entry) {
        return LBD_NOK;
    }

    // @todo bbuesker handle collisions
    u_int8_t hashcode = stadbEntryComputeHashCode(&entry->addr);
    if (!stadbHashTableFindWithinBucket(table, hashcode, &entry->addr)) {
        // No match; insert at the head.
        list_insert_entry(&entry->hashChain, &table->buckets[hashcode]);
        table->curSize++;
        return LBD_OK;
    }

    // Only reach here if it was a duplicate.
    return LBD_NOK;
}

LBD_STATUS stadbHashTableIterate(const stadbHashTableHandle_t table,
                                 stadbHashTableIterFunc_t callback,
                                 void *cookie) {
    if (!table || !callback) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < HASH_TABLE_SIZE; ++i) {
        stadbHashTableIterateBucket(table, i, callback, cookie);
    }

    return LBD_OK;
}

size_t stadbHashTableGetSize(const stadbHashTableHandle_t table) {
    if (!table) {
        return 0;
    }

    return table->curSize;
}

LBD_STATUS stadbHashTableDelete(stadbHashTableHandle_t table,
                                stadbEntry_handle_t entry) {
    if (!table || !entry) {
        return LBD_NOK;
    }

    // Can just directly unlink it from the table if the pointers are valid.
    if (entry->hashChain.prev && entry->hashChain.next) {
        list_remove_entry(&entry->hashChain);
        table->curSize--;
        return LBD_OK;
    }

    return LBD_NOK;
}

void stadbHashTableDestroy(stadbHashTableHandle_t table) {
    if (!table) {
        return;
    }

    size_t i;
    for (i = 0; i < HASH_TABLE_SIZE; ++i) {
        stadbHashTableDestroyBucket(table, i);
    }

    free(table);
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Locate the matching STA entry within a bucket using the MAC address
 *        provided.
 *
 * @param [in] table  the overall hash table
 * @param [in] bucketIndex  the index of the bucket within the hash table in
 *                          which to search
 * @param [in] addr  the address for which to search
 *
 * @return the matching handle, or NULL if no match was found
 */
static stadbEntry_handle_t stadbHashTableFindWithinBucket(
        stadbHashTableHandle_t table, u_int8_t bucketIndex,
        const struct ether_addr *addr) {
    list_head_t *iter;
    list_for_each(iter, &table->buckets[bucketIndex]) {
        stadbEntry_handle_t curEntry =
            list_entry(iter, stadbEntryPriv_t, hashChain);
        if (lbAreEqualMACAddrs(curEntry->addr.ether_addr_octet,
                               addr->ether_addr_octet)) {
            return curEntry;
        }
    }

    return NULL;
}

/**
 * @brief Dispatch the callback on each valid entry in the indicated bucket.
 *
 * The dispatch is done in such a way to allow for the entry to be deleted
 * from the table from within the callback. Additionally the callback may
 * indicate that the entry should be deleted and destroyed, in which case
 * this function will handle the deletion.
 *
 * @param [in] table  the overall hash table
 * @param [in] bucketIndex  the index of the bucket within the hash table over
 *                          which to iterate
 * @param [in] callback  the callback function to invoke for each entry
 * @param [in] cookie  the parameter to pass to the callback function
 */
static void stadbHashTableIterateBucket(stadbHashTableHandle_t table,
                                        u_int8_t bucketIndex,
                                        stadbHashTableIterFunc_t callback,
                                        void *cookie) {
    list_head_t *iter = table->buckets[bucketIndex].next;
    while (iter != &table->buckets[bucketIndex]) {
        stadbEntry_handle_t entry =
            list_entry(iter, stadbEntryPriv_t, hashChain);

        iter = iter->next;

        if (callback(table, entry, cookie)) {
            // Delete and destroy requested.
            stadbHashTableDelete(table, entry); // should not fail
            stadbEntryDestroy(entry);
        }
    }
}

/**
 * @brief Destroy all STA entries within the bucket.
 *
 * @param [in] table  the overall hash table
 * @param [in] bucketIndex  the index of the bucket within the hash table for
 *                          which to destroy entries
 */
static void stadbHashTableDestroyBucket(stadbHashTableHandle_t table,
                                        u_int8_t bucketIndex) {
    list_head_t *iter = table->buckets[bucketIndex].next;
    while (iter != &table->buckets[bucketIndex]) {
        stadbEntry_handle_t entry =
            list_entry(iter, stadbEntryPriv_t, hashChain);

        iter = iter->next;
        stadbEntryDestroy(entry);
    }
}

#ifdef LBD_DBG_MENU

/**
 * @brief Iterator callback for dumping the database of out-of-network
 *        nodes to an output stream.
 *
 * @param [in] handle  the hash table being dumped
 * @param [in] entry  the current entry
 * @param [in] cookie  the cmdContext object to use for output
 */
static LBD_BOOL stadbHashTablePrintOutOfNetworkCB(
        stadbHashTableHandle_t handle,
        stadbEntry_handle_t entry, void *cookie) {
    struct cmdContext *context = (struct cmdContext *) cookie;
    if (!stadbEntry_isInNetwork(entry)) {
        stadbEntryPrintSummary(entry, context, LBD_FALSE /* inNetwork */);
    }
    return LBD_FALSE;  // no delete
}

/**
 * @brief Iterator callback for dumping the database of in-network nodes to
 *        an output stream.
 *
 * @param [in] handle  the hash table being dumped
 * @param [in] entry  the current entry
 * @param [in] cookie  the cmdContext object to use for output
 */
static LBD_BOOL stadbHashTablePrintInNetworkCB(stadbHashTableHandle_t handle,
                                               stadbEntry_handle_t entry,
                                               void *cookie) {
    struct cmdContext *context = (struct cmdContext *) cookie;
    if (stadbEntry_isInNetwork(entry)) {
        stadbEntryPrintSummary(entry, context, LBD_TRUE /* inNetwork */);
    }
    return LBD_FALSE;  // no delete
}

void stadbHashTablePrintSummary(stadbHashTableHandle_t table,
                                struct cmdContext *context,
                                LBD_BOOL inNetworkOnly) {
    cmdf(context, "Num entries = %u\n\n", stadbHashTableGetSize(table));
    stadbEntryPrintSummaryHeader(context, inNetworkOnly);

    if (inNetworkOnly) {
        stadbHashTableIterate(table, stadbHashTablePrintInNetworkCB, context);
    } else {
        stadbHashTableIterate(table, stadbHashTablePrintOutOfNetworkCB, context);
    }
}

/**
 * @brief Parameters used when printing detailed info of in-network nodes
 */
typedef struct stadbHashTablePrintDetailCBParams_t {
    /// The context to print details
    struct cmdContext *context;
    /// The type of detailed info requested
    stadbEntryDBGInfoType_e infoType;
} stadbHashTablePrintDetailCBParams_t;

/**
 * @brief Iterator callback for dumping detailed information of an
 *        in-network node to an output stream.
 *
 * @param [in] handle  the hash table being dumped
 * @param [in] entry  the current entry
 * @param [in] cookie  the cmdContext object to use for output
 */
static LBD_BOOL stadbHashTablePrintDetailCB(stadbHashTableHandle_t handle,
                                            stadbEntry_handle_t entry,
                                            void *cookie) {
    if (stadbEntry_isInNetwork(entry)) {
        stadbHashTablePrintDetailCBParams_t *params =
            (stadbHashTablePrintDetailCBParams_t *) cookie;
        stadbEntryPrintDetail(params->context, entry,
                              params->infoType, LBD_TRUE /* listAddr */);
    }
    return LBD_FALSE;  // no delete
}

void stadbHashTablePrintDetail(stadbHashTableHandle_t table,
                               struct cmdContext *context,
                               stadbEntryDBGInfoType_e infoType) {
    stadbEntryPrintDetailHeader(context, infoType, LBD_TRUE /* listAddr */);
    stadbHashTablePrintDetailCBParams_t params = {
        context, infoType
    };
    stadbHashTableIterate(table, stadbHashTablePrintDetailCB, &params);
}

#endif /* LBD_DBG_MENU */
