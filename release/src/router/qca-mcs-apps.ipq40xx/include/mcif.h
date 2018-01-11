/*
 * @File: mcif.h
 *
 * @Abstract: mulitcast interface management module header
 *
 * @Notes:
 *
 * Copyright (c) 2012, 2015 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef mcif__h
#define mcif__h

#include <sys/types.h>
#include <net/if.h>
#include "internal.h"

/*
 * Maximum amount of interfaces
 */
#define INTERFACE_MAX_INTERFACES      ( 52 )

#define INTERFACE_LIST \
    INTERFACE_ENTRY( WLAN2G, '2' ) \
    INTERFACE_ENTRY( WLAN5G, '5' ) \
    INTERFACE_ENTRY( PLC, 'P' ) \
    INTERFACE_ENTRY( ETHER, 'E' ) \
    INTERFACE_ENTRY( MOCA, 'M' ) \
    \
    INTERFACE_ENTRY( BRIDGE, '\0' ) \
    INTERFACE_ENTRY( WLAN, '\0' ) \
    INTERFACE_ENTRY( ESWITCH, '\0' )

/* Interface type enumeration */
#define INTERFACE_ENTRY( _x, _y ) interfaceType_##_x,
typedef enum interfaceType_e {
	INTERFACE_LIST interfaceType_Reserved
} interfaceType_e;

#undef INTERFACE_ENTRY

typedef enum interfaceGroup_e {
	interfaceGroup_Relaying,
	interfaceGroup_NonRelaying,

	interfaceGroup_Reserved
} interfaceGroup_e;

/* Interface flags */
#define INTERFACE_FLAGS_NON_QCA		(1 << 0)
#define INTERFACE_FLAGS_ESWITCH		(1 << 1)

typedef struct interface_t {
	u_int32_t index;	/* Internal indexing */
	char name[IFNAMSIZ];	/* Interface name */
	interfaceType_e type;	/* Interface media type */
	u_int32_t systemIndex;	/* Interface system index */
	interfaceGroup_e group;	/* Interface group */
	u_int32_t flags;	/* Flags */

	void *pcData;		/* Path characterization data */

} interface_t;

typedef struct interfaceStats_t {
	u_int64_t rxBytes;	/* RX Statistics */
	u_int64_t rxPackets;
	u_int32_t rxErrors;
	u_int32_t rxDropped;
	u_int32_t rxMulticast;
	u_int64_t rxUnicast;

	u_int64_t txBytes;	/* TX Statistics */
	u_int64_t txPackets;
	u_int32_t txErrors;
	u_int32_t txDropped;
	u_int32_t txMulticast;
	u_int64_t txUnicast;

} interfaceStats_t;

/*
 * API
 */
u_int32_t interface_getNumInterfaces(void);
interface_t *interface_getBridge(void);
interface_t *interface_getFirst(void);
interface_t *interface_getNext(interface_t *prev);
interface_t *interface_getInterfaceFromName(const char *name);
interface_t *interface_getInterfaceFromSystemIndex(u_int32_t systemIndex);
const char *interface_getTypeString(interfaceType_e type);
interface_t *interface_getInterfaceFromType(interfaceType_e type);
MCS_STATUS interface_getInterfaceStats(interface_t *iface, interfaceStats_t *stats);
u_int8_t interface_getIeee1905WlanMediaTypeGet(interface_t *iface);
void interface_init(void);

#endif /* mcif__h */
