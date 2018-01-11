// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbHashTable.h
 *
 * @Abstract: Hash table data structure for efficient lookup of stations
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
 */

#ifndef stadbHashTable__h
#define stadbHashTable__h

#include "lbd_types.h"  // for LBD_STATUS

#if defined(__cplusplus)
extern "C" {
#endif

#include "stadbEntry.h"
#include "stadbEntryPrivate.h" // for stadbEntryDBGInfoType_e

struct stadbHashTablePriv_t;  // opaque forward declaration
typedef struct stadbHashTablePriv_t *stadbHashTableHandle_t;

/**
 * @brief Callback function type for table iteration.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 * @param [in] entry  a station entry in the table
 * @param [in] cookie  the argument provided to stadbHashTableIterate
 *
 * @return LBD_TRUE if the entry should be removed from the hash table
 *         and destroyed; otherwise LBD_FALSE
 */
typedef LBD_BOOL (*stadbHashTableIterFunc_t)(stadbHashTableHandle_t handle,
                                             stadbEntry_handle_t entry,
                                             void *cookie);

/**
 * @brief Create an empty station database hash table.
 *
 * @return a handle to the hash table, or NULL if it could not be created
 */
stadbHashTableHandle_t stadbHashTableCreate(void);

/**
 * @brief Find the entry in the database with the matching address.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 *
 * @return  the handle to the STA entry, or NULL if it was not found
 */
stadbEntry_handle_t stadbHashTableFind(stadbHashTableHandle_t handle,
                                       const struct ether_addr *addr);

/**
 * @brief Add the entry to the database.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 * @param [in] entry  the entry to add to the database
 *
 * @return LBD_OK if the entry was added; LBD_NOK if it could not be added
 *         (due to it already being present or due to one of the parameters
 *          being invalid)
 */
LBD_STATUS stadbHashTableInsert(stadbHashTableHandle_t handle,
                                stadbEntry_handle_t entry);

/**
 * @brief Remove the entry from the database.
 *
 * It is the caller's responsibility to call stadbEntryDelete after this is
 * done. It will not deallocate the memory itself.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 * @param [in] entry  the entry to remove from the database
 *
 * @return LBD_OK if the entry was removed; LBD_NOK if it could not be removed
 *         (due to it not being present or due to one of the parameters being
 *          invalid)
 */
LBD_STATUS stadbHashTableDelete(stadbHashTableHandle_t handle,
                                stadbEntry_handle_t entry);

/**
 * @brief Iterate over the hash table, invoking a callback with each entry
 *        along with the cookie provided.
 *
 * The callback is permitted to delete the entry in the callback itself but
 * may not delete any other entries.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 * @param [in] func  the callback function
 * @param [in] cookie  the parameter to provide to the callback function
 *                     (in addition to the table and the entry)
 *
 * @return LBD_OK if the iteration was successful; otherwise LBD_NOK
 */
LBD_STATUS stadbHashTableIterate(const stadbHashTableHandle_t handle,
                                 stadbHashTableIterFunc_t func,
                                 void *cookie);

/**
 * @brief Get the current number of entries in the hash table.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 *
 * @return the number of entries in the table, or 0 if the handle is invalid
 */
size_t stadbHashTableGetSize(const stadbHashTableHandle_t handle);

/**
 * @brief Destroy a station database hash table, including the station
 *        entries that are stored in it.
 *
 * @param [in] handle  the handle returned from stadbHashTableCreate
 */
void stadbHashTableDestroy(stadbHashTableHandle_t handle);

#ifdef LBD_DBG_MENU
struct cmdContext;

/**
 * @brief Print the summary of each node in the hash table to the debug stream.
 *
 * @param [in] handle  the hash table to dump
 * @param [in] context  the output context
 * @param [in] inNetworkOnly  whether to only dump in-network nodes
 */
void stadbHashTablePrintSummary(stadbHashTableHandle_t handle,
                                struct cmdContext *context,
                                LBD_BOOL inNetworkOnly);

/**
 * @brief Print the details of each in-network node in the hash table
 *        to the debug stream
 *
 * @param [in] handle  the hash table to dump
 * @param [in] context  the output context
 * @param [in] infoType  the type of detailed info to print
 */
void stadbHashTablePrintDetail(stadbHashTableHandle_t handle,
                               struct cmdContext *context,
                               stadbEntryDBGInfoType_e infoType);

#endif /* LBD_DBG_MENU */

#if defined(__cplusplus)
}
#endif

#endif
