/*
 * @File: ieee1905.c
 *
 * @Abstract: construct and dispatch IEEE 1905.1 control protocol packets.
 *
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <errno.h>
#include <sys/time.h>

#include "dbg.h"
#include "bufrd.h"
#include "bufwr.h"
#include "interface.h"
#include "ieee1905.h"
#include "mid.h"

/*-------------------------------------------------*/

#define ieee1905AreEqualMACAddrs( _addr1, _addr2 ) !memcmp( _addr1, _addr2, 6 )

/*
 * ieee1905MACAddFmt - Format a MAC address (use with (s)printf)
 */
#define ieee1905MACAddFmt(_sep) "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X"

/*
 * ieee1905MACAddData - MAC Address data octets
 */
#define ieee1905MACAddData(_arg) __Midx(_arg, 0), __Midx(_arg, 1), __Midx(_arg, 2), __Midx(_arg, 3), __Midx(_arg, 4), __Midx(_arg, 5)

#define __Midx(_arg, _i) (((u_int8_t *)_arg)[_i])

/*
 * ieee1905CopyMACAddr - Copy MAC address variable
 */
#define ieee1905CopyMACAddr(src, dst) memcpy( dst, src, ETH_ALEN )


typedef struct ieee1905Interface_t
{
    char name[ IF_NAMESIZE ];
    u_int32_t sysIndex;
    u_int32_t index;
    struct ether_addr addr;

    struct bufwr WriteBuf; /* for writing to */
    char desc[ 16 ];

} ieee1905Interface_t;

/*--- ieee1905State -- global data for hybrid control protocol
 */
static struct ieee1905State_t
{
    u_int32_t IsInit;
    struct bufrd ReadBuf; /* for reading from */
    ieee1905Interface_t Interface[ IEEE1905_MAX_INTERFACES + 1 ];
    struct dbgModule *DebugModule;
    ieee1905ReceiveCallback_f ieee1905ReceiveCallback;
    ieee1905RelayCallback_f ieee1905MessageRelayCallback;

} ieee1905S;

#define IEEE1905_FRAGMENTED_MESSAGE_TIMEOUT     ( 500 ) /* ms */
#define IEEE1905_MAX_PACKETS_PER_CLEANUP        ( 64 )  /* Packets */
#define IEEE1905_MAX_FRAGMENTED_SESSIONS        ( 64 )

#define HYBRID_BRIDGE_INDEX     IEEE1905_MAX_INTERFACES
#define IEEE1905_MAX_TX_RETRIES                 ( 3 )


typedef struct ieee1905FragmentedMessage_t
{
    ieee1905MessageType_e type;     /* Fragmented message type */
    u_int8_t *buffer;               /* Fragmented message accumulated buffer */
    u_int32_t bufferLen;            /* Buffer length */
    u_int32_t dataLen;              /* Actual data length in buffer */
    u_int16_t mid;                  /* Fragmented message identifier */
    u_int8_t fid;                   /* Fragmented message fragment id */
    struct timeval timeStamp;       /* Time stamp for this entry */

} ieee1905FragmentedMessage_t;

/*
 * Message status, used by the message assembly function
 */
typedef enum ieee1905MessageStatus_e
{
    IEEE1905_MESSAGE_VALID,
    IEEE1905_MESSAGE_INVALID,
    IEEE1905_MESSAGE_DUPLICATED

} ieee1905MessageStatus_e;

/*
 * Static variables
 */
static ieee1905FragmentedMessage_t fragmentedMessage[ IEEE1905_MAX_FRAGMENTED_SESSIONS ];
static u_int8_t ieee1905XmitBuf[ ETH_FRAME_LEN ];

/*--- ieee1905Debug -- print debug messages (see dbgf documentation)
 */
#define ieee1905Debug(...) dbgf(ieee1905S.DebugModule, __VA_ARGS__)

static void ieee1905ReadCB( void *Cookie );
/*========================================================================*/
/*============ Internal handling =========================================*/
/*========================================================================*/

static int32_t __ieee1905SockCreate( const char *ifName, u_int16_t etherType )
{
    int32_t sock;
    struct ifreq ifreq;
    struct sockaddr_ll sockaddr_ll =
    {
        PF_PACKET,              /* sll_family */
        htons( etherType ),     /* sll_protocol */
        0,                      /* sll_ifindex */
        ARPHRD_ETHER,           /* sll_hatype */
        PACKET_OTHERHOST,       /* sll_pkttype */
        ETH_ALEN,               /* sll_halen */
        { 0 }                   /* sll_addr */
    };

    /* Sanity checks */
    if( !ifName || !ifName[0] )
    {
        ieee1905Debug(DBGERR, "%s: Empty interface name", __func__);
        return -1;
    }

    /* Create a new socket */
    if( ( sock = socket( PF_PACKET, SOCK_RAW, etherType ) ) < 0 )
    {
        ieee1905Debug(DBGERR, "%s: socket():%s", __func__, strerror(errno));
        return -1;
    }

    /* Init interface name, and retrieve its index */
    memset( ifreq.ifr_name, 0, sizeof ( ifreq.ifr_name ) );
    strncpy( ifreq.ifr_name, ifName, sizeof ( ifreq.ifr_name ) - 1 );

    if( ioctl( sock, SIOCGIFINDEX, &ifreq ) < 0 )
    {
        ieee1905Debug(DBGERR, "%s: ioctl index: %s", __func__, strerror(errno));
        goto err;
    }

    sockaddr_ll.sll_ifindex = ifreq.ifr_ifindex;

    /* Retrieve interface's MAC address */
    if( ioctl( sock, SIOCGIFHWADDR, &ifreq ) < 0 )
    {
        ieee1905Debug(DBGERR, "%s: ioctl hwaddr: %s", __func__, strerror(errno));
        goto err;
    }

    /* Bind the socket */
    memcpy( sockaddr_ll.sll_addr, ifreq.ifr_ifru.ifru_hwaddr.sa_data, sizeof ( sockaddr_ll.sll_addr ) );
    if( bind( sock, (struct sockaddr *) ( &sockaddr_ll ), sizeof ( sockaddr_ll ) ) < 0 )
    {
        ieee1905Debug(DBGERR, "%s: bind:%s", __func__, strerror(errno));
        goto err;
    }

    /* Read interface flags */
    if( ioctl( sock, SIOCGIFFLAGS, &ifreq ) < 0 )
    {
        ieee1905Debug(DBGERR, "%s: ioctl get flags:%s", __func__, strerror(errno));
        goto err;
    }

    /* Configure the interface, enable broadcast and multicast */
    ifreq.ifr_flags |= ( IFF_BROADCAST | IFF_MULTICAST );

    if( ioctl( sock, SIOCSIFFLAGS, &ifreq ) < 0 )
    {
        ieee1905Debug(DBGERR, "%s: ioctl set flags:%s", __func__, strerror(errno));
        goto err;
    }

    return sock;

    err:
    close( sock );
    return -1;
}

static IEEE1905_STATUS ieee1905WriteBufCreate( ieee1905Interface_t *iface )
{
    int32_t sock = __ieee1905SockCreate( iface->name, IEEE1905_ETHER_TYPE );

    if( sock >= 0 )
    {
        snprintf( iface->desc, sizeof( iface->desc ), "ieee1905-wr%d",
                iface->index );

        bufwrCreate( &iface->WriteBuf, iface->desc,
            sock, 0, NULL/*no callback*/, NULL );

        return IEEE1905_OK;
    }

    return IEEE1905_NOK;
}

static void ieee1905WriteBufDestroy( ieee1905Interface_t *iface )
{
    bufwrDestroyNow( &iface->WriteBuf );
}

static IEEE1905_STATUS ieee1905ReadBufCreate( void )
{
    int32_t sock = __ieee1905SockCreate( ieee1905S.Interface[HYBRID_BRIDGE_INDEX].name, IEEE1905_ETHER_TYPE );

    if( sock >= 0 )
    {
        bufrdCreate( &ieee1905S.ReadBuf, "ieee1905-rd", sock, ETH_FRAME_LEN,
            ieee1905ReadCB, NULL );

        return IEEE1905_OK;
    }

    return IEEE1905_NOK;
}

static void ieee1905ReadBufDestroy( void )
{
    bufrdDestroy( &ieee1905S.ReadBuf );
}

static IEEE1905_STATUS ieee1905PollingInit( void )
{
    /* Create read and write buffers */
    if( ieee1905ReadBufCreate() != IEEE1905_OK )
        return IEEE1905_NOK;

    if( ieee1905WriteBufCreate( &ieee1905S.Interface[HYBRID_BRIDGE_INDEX] ) != IEEE1905_OK )
    {
        ieee1905ReadBufDestroy();
        return IEEE1905_NOK;
    }

    return IEEE1905_OK;
}

static void ieee1905PollingExit( void )
{
    ieee1905ReadBufDestroy();
    ieee1905WriteBufDestroy( &ieee1905S.Interface[HYBRID_BRIDGE_INDEX] );
}


/*
 * ieee1905EventDispatch - Dispatch all events to listeners
 *
 * NOTE, dispatch format: the whole message
 */
static void ieee1905EventDispatch( u_int8_t *frame, u_int32_t len, u_int32_t type )
{
    ieee1905Message_t *message = (ieee1905Message_t *)frame;
    ieee1905TLV_t *TLV;

    if( !ieee1905S.ieee1905ReceiveCallback )
        return;

    TLV = ieee1905TLVTypeFind( (ieee1905TLV_t *)message->content, IEEE1905_TLV_TYPE_AL_ID );

    if( TLV )
    {
        struct ether_addr *alId;

        alId = (struct ether_addr *)ieee1905TLVValGet(TLV);

        if( ieee1905AreEqualMACAddrs( alId->ether_addr_octet, ieee1905S.Interface[ HYBRID_BRIDGE_INDEX ].addr.ether_addr_octet ) )
        {
            /* Do not process locally generated packets.
             * We could have received it as a relayed message. */
            return;
        }
    }

    switch( type )
    {
        case IEEE1905_MSG_TYPE_TOPOLOGY_DISCOVERY:
        case IEEE1905_MSG_TYPE_TOPOLOGY_NOTIFICATION:
        case IEEE1905_MSG_TYPE_TOPOLOGY_QUERY:
        case IEEE1905_MSG_TYPE_TOPOLOGY_RESPONSE:
            ieee1905S.ieee1905ReceiveCallback( IEEE1905_EVENT_TOPOLOGY, frame, len );
            break;

        case IEEE1905_MSG_TYPE_VENDOR_SPECIFIC:
            ieee1905S.ieee1905ReceiveCallback( IEEE1905_EVENT_VENDOR_SPECIFIC, frame, len );
            break;

        case IEEE1905_MSG_TYPE_LINK_METRIC_QUERY:
        case IEEE1905_MSG_TYPE_LINK_METRIC_RESPONSE:
            ieee1905S.ieee1905ReceiveCallback( IEEE1905_EVENT_LINK_METRIC, frame, len );
            break;

        case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_SEARCH:
        case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RESPONSE:
        case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS:
        case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RENEW:
            ieee1905S.ieee1905ReceiveCallback( IEEE1905_EVENT_AP_AUTOCONFIGURATION, frame, len );
            break;

        default:
            break;
    }
}

IEEE1905_BOOL ieee1905IsAgedOutGeneric( struct timeval *t_old, struct timeval *t_now, u_int32_t timeout )
{
    u_int32_t old, now;

    old = t_old->tv_sec * 1000 + t_old->tv_usec / 1000;
    now = t_now->tv_sec * 1000 + t_now->tv_usec / 1000;

    if( /* now >= old && */ now - old >= timeout )
    {
        return IEEE1905_TRUE;
    }

    return IEEE1905_FALSE;
}

int32_t ieee1905GetContentSize( ieee1905Message_t *message, u_int32_t contentLenOnWire )
{
    u_int32_t contentLen = 0;
    ieee1905TLV_t *TLV = (ieee1905TLV_t *)message->content;
    ieee1905TlvType_e tlvType;
    u_int32_t hasEOM = 0;

    if( contentLen < contentLenOnWire )
    {
        tlvType = ieee1905TLVTypeGet(TLV);
    }
    else
    {
        return -1;
    }

    while( contentLen < contentLenOnWire )
    {
        if (tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE)
        {
            hasEOM = 1;
            break;
        }

        contentLen += ieee1905TLVLenGet(TLV) + IEEE1905_TLV_MIN_LEN;

        if( contentLen > contentLenOnWire )
        {
            return -1;
        }

        TLV = ieee1905TLVGetNext(TLV);
        tlvType = ieee1905TLVTypeGet(TLV);
    }

    /*The non-fragmented packets must be ended with End-of-Message.
      And for the fragmented with End-of-Message, we accept it for compatibility
      with old QCA devices*/
    if (!ieee1905IsMessageFragmented(message->ieee1905Header.flags)
        && ! hasEOM)
    {
        return -1;
    }

    return contentLen;
}

static IEEE1905_BOOL ieee1905FragmentedMessageStored( u_int32_t index )
{
    return ( fragmentedMessage[ index ].buffer != NULL );
}

ieee1905MessageStatus_e ieee1905FragmentedMessageCheck( u_int32_t index, ieee1905Message_t *message )
{
    /* Compare message ID and type */
    if( ( htons( message->ieee1905Header.mid ) == fragmentedMessage[ index ].mid ) &&
        ( htons( message->ieee1905Header.type ) == fragmentedMessage[ index ].type ) )
    {
        /* Check if we have received the maximum allowed fragments and fragment flag is still on */
        if( ( message->ieee1905Header.fid == ~0 && ieee1905IsMessageFragmented( message->ieee1905Header.flags ) ) )
        {
            return IEEE1905_MESSAGE_INVALID;
        }

        /* Check that the new fragment ID is the following one (what we expect).
         * If the fragment ID is lower than what we have, it could be a relayed message
         * which we received on a different interface */
        if( message->ieee1905Header.fid == fragmentedMessage[ index ].fid + 1 )
        {
            fragmentedMessage[ index ].fid++;
            return IEEE1905_MESSAGE_VALID;
        }
        else if( message->ieee1905Header.fid <= fragmentedMessage[ index ].fid )
        {
            return IEEE1905_MESSAGE_DUPLICATED;
        }

        /* There is a gap, probably lost packets. Drop this message */
    }

    /* Not the same message ID or type */
    return IEEE1905_MESSAGE_INVALID;
}

static IEEE1905_STATUS ieee1905FragmentedMessageClear( u_int32_t index )
{
    if( fragmentedMessage[ index ].buffer )
    {
        /* Free the buffer */
        free( fragmentedMessage[ index ].buffer );
    }

    /* Clear the structure */
    memset( &fragmentedMessage[ index ], 0, sizeof( ieee1905FragmentedMessage_t ) );

    return IEEE1905_OK;
}

static IEEE1905_STATUS ieee1905FragmentedMessageSetupFirst( u_int32_t index, ieee1905Message_t *message, u_int32_t contentLen )
{
    if( fragmentedMessage[ index ].buffer )
    {
        /* Should not happen */
        free( fragmentedMessage[ index ].buffer );
        fragmentedMessage[ index ].buffer = NULL;
    }

    /* Allocate a buffer, double the size of 1518 Ethernet packet */
    fragmentedMessage[ index ].buffer = malloc( ETH_FRAME_LEN * 2 );

    if( !fragmentedMessage[ index ].buffer )
    {
        ieee1905Debug(DBGERR, "Failed to allocate memory for fragmented message. Index = %d, mid = 0x%05X, fid = %d",
            index, htons( message->ieee1905Header.mid ), message->ieee1905Header.fid );

        return IEEE1905_NOK;
    }

    fragmentedMessage[ index ].bufferLen = ETH_FRAME_LEN * 2;
    fragmentedMessage[ index ].dataLen = contentLen;
    fragmentedMessage[ index ].mid = htons( message->ieee1905Header.mid );
    fragmentedMessage[ index ].fid = message->ieee1905Header.fid;
    fragmentedMessage[ index ].type = htons( message->ieee1905Header.type );

    /* First packet in buffer contains the packet headers, but without the last TLV */
    memcpy( fragmentedMessage[ index ].buffer, message, contentLen + IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN );
    gettimeofday( &fragmentedMessage[ index ].timeStamp, NULL );

    return IEEE1905_OK;
}

static IEEE1905_STATUS ieee1905FragmentedMessageAppend( u_int32_t index, ieee1905Message_t *message, u_int32_t contentLen )
{
    ieee1905Message_t *fragMessage;

    if( !fragmentedMessage[ index ].buffer )
    {
        ieee1905Debug(DBGERR, "Buffer not initialized. Index = %d, mid = 0x%05X, fid = %d",
            index, htons( message->ieee1905Header.mid ), message->ieee1905Header.fid );

        return IEEE1905_NOK;
    }

    if( !ieee1905IsMessageFragmented( message->ieee1905Header.flags ) )
    {
        /* This is the last fragment. Append the END-OF-MESSAGE TLV. */
        contentLen += IEEE1905_TLV_MIN_LEN;
    }

    /* Check if buffer is big enough */
    if( fragmentedMessage[ index ].dataLen + contentLen > fragmentedMessage[ index ].bufferLen )
    {
        fragmentedMessage[ index ].buffer =
            realloc( fragmentedMessage[ index ].buffer, fragmentedMessage[ index ].bufferLen + ETH_FRAME_LEN );

        if( !fragmentedMessage[ index ].buffer )
        {
            ieee1905FragmentedMessageClear( index );

            ieee1905Debug(DBGERR, "Failed to reallocate memory for fragmented message. Index = %d, mid = 0x%05X, fid = %d",
                index, htons( message->ieee1905Header.mid ), message->ieee1905Header.fid );

            return IEEE1905_NOK;
        }

        fragmentedMessage[ index ].bufferLen += ETH_FRAME_LEN;
    }

    /* Append the data to the end of the current data */
    fragMessage = ( ieee1905Message_t *)fragmentedMessage[ index ].buffer;

    memcpy( fragMessage->content + fragmentedMessage[ index ].dataLen, message->content, contentLen );
    fragmentedMessage[ index ].dataLen += contentLen;
    gettimeofday( &fragmentedMessage[ index ].timeStamp, NULL );

    return IEEE1905_OK;
}

static void ieee1905FragmentedMessageCleanup( void )
{
    u_int32_t i;
    struct timeval t_now;

    gettimeofday( &t_now, NULL );

    /* Cleanup old messages */
    for( i = 0; i < IEEE1905_MAX_FRAGMENTED_SESSIONS; i++ )
    {
        if( fragmentedMessage[ i ].buffer &&
            ieee1905IsAgedOutGeneric( &fragmentedMessage[ i ].timeStamp, &t_now, IEEE1905_FRAGMENTED_MESSAGE_TIMEOUT ) )
        {
            ieee1905FragmentedMessageClear( i );
        }
    }
}

static int32_t ieee1905FragmentedMessageLookup( struct ether_addr *saddr )
{
    u_int32_t i;

    for( i = 0; i < IEEE1905_MAX_FRAGMENTED_SESSIONS; i++ )
    {
        if( fragmentedMessage[ i ].buffer )
        {
            if( ieee1905AreEqualMACAddrs( saddr->ether_addr_octet, fragmentedMessage[ i ].buffer + ETH_ALEN ) )
            {
                return i;
            }
        }
    }

    return -1;
}

static int32_t ieee1905FragmentedMessageGetFreeEntry( void )
{
    u_int32_t i;

    for( i = 0; i < IEEE1905_MAX_FRAGMENTED_SESSIONS; i++ )
    {
        if( !fragmentedMessage[ i ].buffer )
        {
            return i;
        }
    }

    /* This is very unfortunate */
    ieee1905Debug(DBGERR, "No more free entries for fragmented messages" );

    return -1;
}


static IEEE1905_STATUS ieee1905FrameAssembly( u_int8_t *frame, u_int32_t len )
{
    ieee1905Message_t *message = (ieee1905Message_t *)frame;
    u_int32_t contentLenOnWire = len - sizeof( struct ether_header ) - sizeof( struct ieee1905Header_t );
    int32_t contentLen;
    int32_t index = -1;
    static u_int32_t fragmentCleanupCounter = 0;

    /* Check the content size */
    contentLen = ieee1905GetContentSize( message, contentLenOnWire );

    if( contentLen < 0 )
    {
        ieee1905Debug(DBGDEBUG, "%s: Received Malformed IEEE1905.1 packet type %d from address " ieee1905MACAddFmt(":") ", dropping.",
            __func__, htons( message->ieee1905Header.type ), ieee1905MACAddData(message->etherHeader.ether_shost ) );

        /* Garbage packet */
        return IEEE1905_NOK;
    }
    else
    {
        ieee1905Debug(DBGDEBUG, "%s: Received IEEE1905.1 packet type %d from address " ieee1905MACAddFmt(":"),
            __func__, htons( message->ieee1905Header.type ), ieee1905MACAddData(message->etherHeader.ether_shost ) );
    }

    /* Check if message is fragmented */
    if( ieee1905IsMessageFragmented(message->ieee1905Header.flags) )
    {
        ieee1905Debug(DBGDEBUG, "%s: Received fragmented IEEE1905.1 packet type %d from address " ieee1905MACAddFmt(":"),
            __func__, htons( message->ieee1905Header.type ), ieee1905MACAddData(message->etherHeader.ether_shost ) );

        /* Clean up old messages */
        ieee1905FragmentedMessageCleanup();
        fragmentCleanupCounter = 0;

        index = ieee1905FragmentedMessageLookup( (struct ether_addr *)message->etherHeader.ether_shost );

        if( index < 0 )
        {
            /* Check fragment ID. This is a new message, FID must be 0.
             */
            if( message->ieee1905Header.fid == 0 )
            {
                index = ieee1905FragmentedMessageGetFreeEntry();

                if( index < 0 )
                {
                    /* Cannot process any other fragmented messages.
                     * Very unlikely, unless this is a torture bench...
                     */
                    ieee1905Debug( DBGERR, "Dropping fragmented IEEE1905.1 packet, maximum concurrent fragmented packets." );
                    return IEEE1905_OK;
                }

                ieee1905Debug(DBGDEBUG, "%s: Setting up new entry for FID = 0, MID = %d",
                    __func__, htons( message->ieee1905Header.mid ) );

                /* Save this message for later processing */
                ieee1905FragmentedMessageSetupFirst( index, message, contentLen );
                return IEEE1905_OK;
            }
        }

        /* Message is fragmented. Check that it is valid, if either it's a new message,
         * or the next fragment of an existing message.
         */
        if( ieee1905FragmentedMessageStored( index ) )
        {
            ieee1905MessageStatus_e messageStatus = ieee1905FragmentedMessageCheck( index, message );

            switch( messageStatus )
            {
                case IEEE1905_MESSAGE_VALID:
                    /* Valid. Append this fragment to the buffer for later processing.
                     * No need to check for return value, returning anyway. */
                    ieee1905FragmentedMessageAppend( index, message, contentLen );
                    ieee1905Debug(DBGDEBUG, "%s: Appending fragmented message FID = %d, MID = %d",
                        __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );
                    break;

                case IEEE1905_MESSAGE_DUPLICATED:
                    /* Duplicated message, ignore it */
                    ieee1905Debug(DBGDEBUG, "%s: Duplicated message FID = %d, MID = %d",
                        __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );
                    break;

                default:
                    /* Invalid. Clear exiting buffer */
                    ieee1905FragmentedMessageClear( index );

                    if( message->ieee1905Header.fid == 0 )
                    {
                        index = ieee1905FragmentedMessageGetFreeEntry();

                        if( index < 0 )
                        {
                            /* Cannot process any other fragmented messages.
                             * Very unlikely, unless this is a torture bench...
                             */
                            ieee1905Debug( DBGERR, "Dropping fragmented IEEE1905.1 packet, maximum concurrent fragmented packets." );
                            return IEEE1905_OK;
                        }

                        ieee1905Debug(DBGDEBUG, "%s: Setting up new entry for FID = 0, MID = %d",
                            __func__, htons( message->ieee1905Header.mid ) );

                        /* Save this message for later processing */
                        ieee1905FragmentedMessageSetupFirst( index, message, contentLen );
                        return IEEE1905_OK;
                    }
                    else
                    {
                        ieee1905Debug(DBGDEBUG, "%s: Invalid fragmented message FID = %d, MID = %d, dropping the message",
                            __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );
                    }
                    break;
            }

            return IEEE1905_OK;
        }

        return IEEE1905_OK;
    }
    else
    {
        /* Last fragment bit is on. If Fragment ID is not 0, then it must be the last fragment
         * of a message we collected. Check that this message is valid.
         */
        if( message->ieee1905Header.fid != 0 )
        {
            /* Clean up old messages */
            ieee1905FragmentedMessageCleanup();
            fragmentCleanupCounter = 0;

            index = ieee1905FragmentedMessageLookup( ( struct ether_addr *)message->etherHeader.ether_shost );

            if( index < 0 )
            {
                ieee1905Debug(DBGDEBUG, "%s: Invalid fragmented message FID = %d, MID = %d, dropping the message",
                    __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );

                /* No fragments are stored from this source address. Fragment ID is not 0,
                 * so drop this packet.
                 */
                return IEEE1905_OK;
            }

            if( ieee1905FragmentedMessageCheck( index, message ) == IEEE1905_MESSAGE_VALID )
            {
                /* Valid. Append this last fragment to the buffer for final processing */
                if( ieee1905FragmentedMessageAppend( index, message, contentLen ) != IEEE1905_OK )
                {
                    ieee1905Debug(DBGERR, "%s: Failed to append last fragmented message FID = %d, MID = %d",
                        __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );

                    /* Something bad happened, we cannot process this message */
                    ieee1905FragmentedMessageClear( index );
                    return IEEE1905_OK;
                }

                ieee1905Debug(DBGDEBUG, "%s: Appending last fragmented message FID = %d, MID = %d",
                    __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );
            }
            else
            {
                /* Should not reach here. Duplicates are meaningless because the last
                 * packet has already been assembled and processed. The lookup check should
                 * detect the duplicates/invalids */
                ieee1905Debug(DBGDEBUG, "%s: Invalid last fragmented message FID = %d, MID = %d, dropping",
                    __func__, message->ieee1905Header.fid, htons( message->ieee1905Header.mid ) );

                return IEEE1905_OK;
            }
        }
    }

    /* If we are here, then it means we need to process a packet.
     * if index is not negative, then we have a jumbo packet to process.
     */
    if( index >= 0 )
    {
        /* Process the assembled message */
        ieee1905EventDispatch( fragmentedMessage[ index ].buffer, fragmentedMessage[ index ].bufferLen,
            htons( ((ieee1905Message_t *)( fragmentedMessage[ index ].buffer ))->ieee1905Header.type ) );

        /* Clear entry and free memory */
        ieee1905FragmentedMessageClear( index );

        /* Clean up old messages */
        ieee1905FragmentedMessageCleanup();
        fragmentCleanupCounter = 0;
    }
    else
    {
        /* Process the message */
        ieee1905EventDispatch( frame, len, htons( message->ieee1905Header.type ) );

        if( fragmentCleanupCounter++ > IEEE1905_MAX_PACKETS_PER_CLEANUP )
        {
            /* Clean up old messages, but avoid doing it every time. */
            ieee1905FragmentedMessageCleanup();
            fragmentCleanupCounter = 0;
        }
    }

    return IEEE1905_OK;
}

static void ieee1905FrameRcv( u_int8_t *frame, u_int32_t len )
{
    ieee1905Message_t *msg = (ieee1905Message_t *)frame;
    ieee1905Header_t *hdr = &msg->ieee1905Header;
    u_int16_t type;

    /* An IEEE 1905.1 frame has been received.
     * Check message integrity, dispatch events and forward it.
     */
    if( htons( msg->etherHeader.ether_type ) != IEEE1905_ETHER_TYPE )
    {
        ieee1905Debug(DBGINFO, "%s: Not an IEEE1905.1 EtherType (received 0x%04X, expected 0x%04X)",
                __func__, htons( msg->etherHeader.ether_type ), IEEE1905_ETHER_TYPE );
        return;
    }

    if( len < IEEE1905_FRAME_MIN_LEN )
    {
        ieee1905Debug(DBGERR, "%s: Bad length of the frame: %d", __func__, len);
        return;
    }

    if( ieee1905AreEqualMACAddrs( msg->etherHeader.ether_shost, ieee1905S.Interface[ HYBRID_BRIDGE_INDEX ].addr.ether_addr_octet ) )
    {
        /* Do not process locally generated packets */
        return;
    }

    if( hdr->version > IEEE1905_PROTOCOL_VERSION )
    {
        ieee1905Debug(DBGDEBUG, "%s: Unsupported version: %d", __func__, hdr->version );

        if( ieee1905GetContentSize( msg, len - sizeof( struct ether_header ) - sizeof( struct ieee1905Header_t )) > 0 )
        {
            /* If relay bit is on, need to forward the packet */
            if( ( msg->ieee1905Header.flags & IEEE1905_HEADER_FLAG_RELAY ) &&
                    ieee1905S.ieee1905MessageRelayCallback )
            {
                /* Relay the frame if necessary */
                ieee1905S.ieee1905MessageRelayCallback( frame, len );
            }
        }
        return;
    }

    type = ntohs( hdr->type );
    if( type >= IEEE1905_MSG_TYPE_RESERVED )
    {
        ieee1905Debug(DBGERR, "%s: Invalid message type: %d", __func__, type);
        return;
    }

    /* Assemble frames and dispatch events. This function also checks that the packet
     * is valid. */
    if( ieee1905FrameAssembly( frame, len ) == IEEE1905_OK )
    {
        /* If relay bit is on, need to forward the packet */
        if( ( msg->ieee1905Header.flags & IEEE1905_HEADER_FLAG_RELAY ) &&
                ieee1905S.ieee1905MessageRelayCallback )
        {
            /* Relay the frame if necessary */
            ieee1905S.ieee1905MessageRelayCallback( frame, len );
        }
    }
}

/* Read buffer callback.
 */
static void ieee1905ReadCB( void *Cookie )
{
    struct bufrd *buf = &ieee1905S.ReadBuf;
    u_int32_t len = bufrdNBytesGet( buf );
    u_int8_t *frame = bufrdBufGet( buf );

    /* Error check. */
    if( bufrdErrorGet( buf ) )
    {
        ieee1905Debug(DBGERR, "%s: Read error!", __func__);

        ieee1905PollingExit();
        ieee1905PollingInit();
        return;
    }

    if( !len || !frame )
        return;

    /* Make sure we are not overflowing */
    if( len > ETH_FRAME_LEN )
        len = ETH_FRAME_LEN;

    /* Handle packet */
    ieee1905FrameRcv( frame, len );
    bufrdConsume( buf, len );
}

/*========================================================================*/
/*============ Init ======================================================*/
/*========================================================================*/

/*--- ieee1905Init -- first time init.
 */
void ieee1905Init( const char *bridgeName, ieee1905ReceiveCallback_f ieee1905ReceiveCallback, ieee1905RelayCallback_f ieee1905RelayCallback )
{
    u_int32_t i;

    if( ieee1905S.IsInit )
        return;

    messageId_init();

    ieee1905S.IsInit = 1;

    ieee1905S.DebugModule = dbgModuleFind( "ieee1905" );
    ieee1905Debug(DBGDEBUG, "Enter %s", __func__);

    memset( fragmentedMessage, 0, sizeof( fragmentedMessage ) );

    memset( ieee1905S.Interface, 0, sizeof(ieee1905S.Interface) );

    if( bridgeName )
    {
        /* Get bridge MAC address */
        if( interfaceGetMACAddressForInterface( bridgeName, ieee1905S.Interface[ HYBRID_BRIDGE_INDEX ].addr.ether_addr_octet ) ) /* non-zero for error */
        {
            ieee1905Debug(DBGERR, "%s: Cannot get MAC address of %s", __func__, bridgeName );
            exit(1);
        }

        strlcpy( ieee1905S.Interface[ HYBRID_BRIDGE_INDEX ].name, bridgeName, IF_NAMESIZE );

        if( ieee1905ReceiveCallback )
        {
            ieee1905PollingInit();
            ieee1905S.ieee1905ReceiveCallback = ieee1905ReceiveCallback;
        }
    }

    if( ieee1905RelayCallback )
    {
        /* For hyd. We can add additional checks to make sure this is hyd. */
        ieee1905S.ieee1905MessageRelayCallback = ieee1905RelayCallback;
    }

    for( i = 0; i < IEEE1905_MAX_INTERFACES; i++ )
    {
        ieee1905S.Interface[ i ].index = ~0;
    }
}

/*-------------------------------------------------------------------*/
/*----------------------------IEEE1905 API--------------------------------*/
/*-------------------------------------------------------------------*/

ieee1905TLV_t* ieee1905TLVTypeFind( ieee1905TLV_t* TLV, u_int8_t type )
{
    while ( TLV->type != IEEE1905_TLV_TYPE_END_OF_MESSAGE )
    {
        if( TLV->type == type )
        {
            return TLV;
        }
        TLV = ieee1905TLVGetNext(TLV);
    }

    return NULL;
}

/*
 * ieee1905MessageBufferGet - Get a pointer to the message buffer
 */
u_int8_t *ieee1905MessageBufferGet( void )
{
    return ieee1905XmitBuf;
}

/*
 * ieee1905MessageIdUpdate - Update an IEEE 1905.1 message identifier
 * @frame: Address of the frame
 * @mid: Message ID
 */
IEEE1905_STATUS ieee1905MessageIdUpdate( u_int8_t *frame, u_int16_t mid )
{
    ieee1905Message_t *msg = ( ieee1905Message_t *)frame;

    if( !frame )
        return IEEE1905_NOK;

    msg->ieee1905Header.mid = htons( mid );

    return IEEE1905_OK;
}

/*
 * ieee1905MessageSetup - Setup a new IEEE 1905.1 message
 * @frame: Address of the frame
 * @type: Message type
 * @mid: Message ID
 * @fid: Fragment ID
 * @flags: Message flags
 */
IEEE1905_STATUS ieee1905MessageSetup( u_int8_t *frame, ieee1905MessageType_e type, u_int16_t mid, u_int8_t fid, u_int8_t flags )
{
    ieee1905Message_t *msg = ( ieee1905Message_t *)frame;

    /* Sanity checks */
    if( !frame )
    {
        ieee1905Debug(DBGERR, "frame pointer NULL" );
        return IEEE1905_NOK;
    }

    if( type >= IEEE1905_MSG_TYPE_RESERVED )
    {
        ieee1905Debug(DBGERR, "Invalid message type: %d", type );
        return IEEE1905_NOK;
    }

    /* Clear the Ethernet header */
    memset( frame, 0, IEEE1905_ETH_HEAD_LEN );

    /* Setup Ether-type */
    msg->etherHeader.ether_type = htons( IEEE1905_ETHER_TYPE );

    /* Setup IEEE 1905.1 header */
    msg->ieee1905Header.version = IEEE1905_PROTOCOL_VERSION;
    msg->ieee1905Header.type = (u_int16_t)htons( type );
    msg->ieee1905Header.mid = htons( mid );
    msg->ieee1905Header.fid = fid;
    msg->ieee1905Header.flags = flags;
    msg->ieee1905Header.reserved = 0;

    return IEEE1905_OK;
}

static ieee1905Interface_t *ieee1905GetInterface( const char *ifaceName )
{
    u_int32_t i;
    u_int32_t sysIndex = if_nametoindex( ifaceName );

    if(!sysIndex)
    {
        /* Interface not found */
        return NULL;
    }

    for( i = 0; i < IEEE1905_MAX_INTERFACES; i++ )
    {
        if( ieee1905S.Interface[ i ].index == ~0 )
            break;
        else
        {
            if( sysIndex == ieee1905S.Interface[ i ].sysIndex ||
                    !strcmp( ifaceName, ieee1905S.Interface[ i ].name ) )
            {
                sysIndex = ieee1905S.Interface[ i ].sysIndex;
                return &ieee1905S.Interface[ i ];
            }
        }
    }

    /* New interface */
    if( i == IEEE1905_MAX_INTERFACES )
    {
        ieee1905Debug(DBGERR, "%s: Cannot support more than %d interfaces", __func__, IEEE1905_MAX_INTERFACES );
        return NULL;
    }

    ieee1905S.Interface[ i ].index = i;
    strlcpy( ieee1905S.Interface[ i ].name, ifaceName, IF_NAMESIZE );
    if( interfaceGetMACAddressForInterface( ieee1905S.Interface[ i ].name, ieee1905S.Interface[ i ].addr.ether_addr_octet ) ) /* non-zero for error */
    {
        ieee1905Debug(DBGERR, "%s: Cannot get MAC address of %s", __func__, ifaceName );
        ieee1905S.Interface[ i ].index = ~0;
        return NULL;
    }

    if( ieee1905WriteBufCreate( &ieee1905S.Interface[ i ] ) != IEEE1905_OK )
    {
        ieee1905Debug(DBGERR, "%s: Failed to create buffer for interface %s", __func__, ifaceName );
        ieee1905S.Interface[ i ].index = ~0;
        return NULL;
    }

    return &ieee1905S.Interface[ i ];
}

/*
 * ieee1905MessageSetup - Send an ieee1905 message
 * @iface: Specify the tx interface type
 * @frame: Address of the frame
 * @len: Length of this frame should be sent
 * @src: Source address or NULL to send using the selected interface MAC address
 * @dest: Destination address or NULL to send as Multicast message
 */
IEEE1905_STATUS ieee1905MessageSend( const char *ifaceName, u_int8_t *frame, u_int32_t len,
                                     const struct ether_addr *src, const struct ether_addr *dest )
{
    ieee1905Message_t *message = ( ieee1905Message_t *)frame;
    u_int32_t retry = IEEE1905_MAX_TX_RETRIES;
    ieee1905Interface_t *iface;

    if( !frame || len > sizeof ieee1905XmitBuf || len < IEEE1905_FRAME_MIN_LEN)
    {
        ieee1905Debug(DBGERR, "%s: Invalid frame length (%d)", __func__, len );
        return IEEE1905_NOK;
    }

    iface = ieee1905GetInterface( ifaceName );

    if( !iface )
    {
        ieee1905Debug(DBGDEBUG, "%s: Invalid TX interface specified: %s", __func__, ifaceName );
        return IEEE1905_NOK;
    }

    /* Setup source address */
    if( src )
    {
        /* Use the provided address */
        ieee1905CopyMACAddr( src->ether_addr_octet, message->etherHeader.ether_shost );
    }
    else
    {
        /* Use bridge L2 address */
        ieee1905CopyMACAddr( ieee1905S.Interface[ HYBRID_BRIDGE_INDEX ].addr.ether_addr_octet, message->etherHeader.ether_shost );
    }

    /* Setup destination address */
    if( !dest )
    {
        /* Send a multicast message */
        ieee1905CopyMACAddr( IEEE1905_MULTICAST_ADDR, message->etherHeader.ether_dhost );
    }
    else
    {
        /* Send a unicast message */
        ieee1905CopyMACAddr(dest->ether_addr_octet, message->etherHeader.ether_dhost);
    }

    /* Clear the reserved field, we use it locally for RX interface detection */
    message->ieee1905Header.reserved = 0;

    ieee1905Debug(DBGDEBUG, "%s: Sending IEEE1905.1 packet %d, src: " ieee1905MACAddFmt(":") ", dst: " ieee1905MACAddFmt(":") ", frame length: %d",
        __func__, htons( message->ieee1905Header.type ), ieee1905MACAddData(message->etherHeader.ether_shost ), ieee1905MACAddData(message->etherHeader.ether_dhost ), len );

    while( retry > 0 )
    {
        /* Send the frame */
        if( bufwrWrite( &ieee1905S.Interface[ iface->index ].WriteBuf, (char *) frame, len ) )
        {
            ieee1905WriteBufDestroy( iface );

            /* Create a new buffer */
            if( ieee1905WriteBufCreate( iface ) != IEEE1905_OK )
                return IEEE1905_NOK;

            retry--;
        }
        else
        {
            bufwrFlush( &ieee1905S.Interface[ iface->index ].WriteBuf, 1 );

            /* Transmission successful */
            break;
        }
    }

    return retry ? IEEE1905_OK : IEEE1905_NOK;
}
