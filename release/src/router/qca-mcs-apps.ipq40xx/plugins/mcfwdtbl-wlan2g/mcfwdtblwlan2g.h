/*
 * @File: mcfwdtblwlan2g.h
 *
 * @Abstract: WLAN2G Multicast forwarding database plugin
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef MCFWDTBLWLAN2G_H_
#define MCFWDTBLWLAN2G_H_

#include "mcif.h"

int WLAN2G_InitForwardTablePlugin(interface_t *iface);
int WLAN2G_UpdateForwardTable(interface_t *iface, void *table, u_int32_t size);
int WLAN2G_FlushForwardTable(interface_t *iface);

#endif /* MCFWDTBLWLAN2G_H_ */
