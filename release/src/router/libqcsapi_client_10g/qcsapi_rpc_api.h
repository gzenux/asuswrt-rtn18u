/*
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 Quantenna Communications Inc                   **
**                                                                           **
**  File        : qcsapi_rpc_api.h                                           **
**  Description : APIs to call QCSAPIs remotely (over PCIe or using sockrpc) **
**                                                                           **
*******************************************************************************
*/

#ifndef _QCSAPI_RPC_API_H
#define _QCSAPI_RPC_API_H

#include <rpc/rpc.h>	/* CLIENT */
#include <rpc/types.h>	/* u_long */

extern CLIENT *clnt_pci_create(const char *hostname, u_long prog, u_long vers, const char *proto);

/* sess_id */
#define QRPC_QCSAPI_RPCD_SID		0
#define QRPC_CALL_QCSAPI_RPCD_SID	1

extern CLIENT *qrpc_clnt_raw_create(u_long prog, u_long vers, const char *const srcif_name,
	const uint8_t *dmac_addr, uint8_t sess_id);

#endif /* _QCSAPI_RPC_API_H */


