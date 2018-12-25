/*
 * @File: mcfwdtbleswitch.h
 *
 * @Abstract: ESWITCH Multicast forwarding database plugin
 *
 * @Notes:
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef MCFWDTBLESWITCH_H_
#define MCFWDTBLESWITCH_H_

#include "mcif.h"

int ESWITCH_InitForwardTablePlugin(interface_t *iface);
int ESWITCH_UpdateForwardTable(interface_t *iface, void *table, u_int32_t size);
int ESWITCH_FlushForwardTable(interface_t *iface);

#endif /* MCFWDTBLESWITCH_H_ */
