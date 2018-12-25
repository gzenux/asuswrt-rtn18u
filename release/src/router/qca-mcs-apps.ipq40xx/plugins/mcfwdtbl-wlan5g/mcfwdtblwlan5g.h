/*
 * @File: mcfwdtblwlan5g.h
 *
 * @Abstract: WLAN5G Multicast forwarding database plugin
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef MCFWDTBLWLAN5G_H_
#define MCFWDTBLWLAN5G_H_

#include "mcif.h"

int WLAN5G_InitForwardTablePlugin(interface_t *iface);
int WLAN5G_UpdateForwardTable(interface_t *iface, void *table, u_int32_t size);
int WLAN5G_FlushForwardTable(interface_t *iface);

#endif /* MCFWDTBLWLAN5G_H_ */
