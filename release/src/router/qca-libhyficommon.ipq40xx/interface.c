/*
 * Copyright (c) 2010 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*-M- interface -- linux network interface utilities
 */

/*===========================================================================*/
/*================= Includes and Configuration ==============================*/
/*===========================================================================*/


/* C and system library includes */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>
#include <netdb.h>

/* Gateway project includes */
#include "split.h"
//#include <gatewayconfig.h>

/* Our Own Include file */
#include "interface.h"


/*-D- Required includes -- 
 */
/*---*/
#include "athrs_ctrl.h"

#if 0   /* auto-extract only */

/*-D- Required includes -- 
 */
#include <ipaddress.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#define ADD_VLAN_CMD 0
#define DEL_VLAN_CMD 1
struct vlan_ioctl_args {
    int cmd; /* Should be one of the vlan_ioctl_cmds enum above. */
    char device1[24];
    
    union {
        char device2[24];
        int VID;
        unsigned int skb_priority;
        unsigned int name_type;
        unsigned int bind_type;
        unsigned int flag; /* Matches vlan_dev_info flags */
    } u;
    
    short vlan_qos;
};


/*-D- NetDeviceStats --
 */
struct NetDeviceStats {
    unsigned long long rx_bytes;    /* total bytes received         */
    unsigned long long rx_packets;  /* total packets received       */
    unsigned int rx_errors;    /* bad packets received         */
    unsigned int rx_dropped;   /* no space in linux buffers    */
    unsigned int rx_fifo_errors;   /* recv'r fifo overrun          */
    unsigned int rx_frame_errors;  /* recv'd frame alignment error */
    unsigned int rx_compressed;
    unsigned int rx_multicast; /* multicast packets received   */
    unsigned long long tx_bytes;    /* total bytes transmitted      */
    unsigned long long tx_packets;  /* total packets transmitted    */
    unsigned int tx_errors;    /* packet transmit problems     */
    unsigned int tx_dropped;   /* no space available in linux  */
    unsigned int tx_fifo_errors;
    unsigned int tx_collisions;
    unsigned int tx_carrier_errors;
    unsigned int tx_compressed; 
    unsigned int tx_mcast;
    unsigned int rx_mcast;
    unsigned int tx_bcast;
    unsigned int rx_bcast;
    unsigned int tx_ucast;
    unsigned int rx_ucast;
    unsigned int tx_rate;
    unsigned int rx_rate;
    unsigned int tx_fail;
};

typedef struct {
    unsigned char addr[6];
} mac_addr_t;

typedef struct {
	mac_addr_t hwaddr;
	int port_map;
	int sa_drop; 
} arl_struct_t;

/*---------------------------------------------------------------------------*/

#endif  /* auto-extract only */
#define GATEWAY_WAN_PORT 0
/* Our Own Definitions */
#define PATH_PROC_NET_DEV  "/proc/net/dev"
#define PATH_PROC_NET_VLAN_CONFIG "/proc/net/vlan/config"
#define SS_FMT "%Lu%Lu%u%u%u%u%u%u%Lu%Lu%u%u%u%u%u%u"

/*private*/ int interfaceEthernetPortMapping(int Port)
{
#if 0
//#ifdef GATEWAY_ETH_PORTMAP
    switch (Port) {
        case 0:
            return 0;
        case 1:
            return GATEWAY_ETH_PORT1;
        case 2:
            return GATEWAY_ETH_PORT2;
        case 3:
            return GATEWAY_ETH_PORT3;
        case 4:
            return GATEWAY_ETH_PORT4;
        case 5:
            return GATEWAY_ETH_PORT5;
#if MAXLANCONFIGURATION == 5
        case 6:
            return GATEWAY_ETH_PORT6;
#endif
        default:
            return -1;
    }
#else
    return Port;
#endif
}

/*-F- interfaceEthernetPortUnMap(int Port) */
int interfaceEthernetPortUnMap(int Port)
{
#if 0
//#ifdef GATEWAY_ETH_PORTMAP
    switch (Port) {
        case GATEWAY_ETH_PORT1:
            return 1;
        case GATEWAY_ETH_PORT2:
            return 2;
        case GATEWAY_ETH_PORT3:
            return 3;
        case GATEWAY_ETH_PORT4:
            return 4;
        case GATEWAY_ETH_PORT5:
            return 5;
#if MAXLANCONFIGURATION == 5
        case GATEWAY_ETH_PORT6:
            return 6;
#endif
        default:
            return -1;
    }
#else
    return Port;
#endif

}

/*private*/ int interfaceVlanConfig(
        struct vlan_ioctl_args * if_request)
{
    if(!if_request) return -1;

    const char conf_file_name[] = PATH_PROC_NET_VLAN_CONFIG;
    int fd;

    if((fd = open(conf_file_name, O_RDONLY)) < 0) {
        //printf("WARNING: Could not open %s.", PATH_PROC_NET_VLAN_CONFIG);
    } else {
        close(fd);
    }

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }
#define SIOCSIFVLAN 0x8983      /* Set 802.1Q VLAN options  */
    if(ioctl(fd, SIOCSIFVLAN, if_request) < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/*-F- interfaceHostToIPString -- 
 */

int interfaceHostToIPString(
    const char *HostString,
    char *IPString,
    const int IPStrLen)
{
    if(!HostString || !IPString) return -1;
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(HostString, NULL, &hints, &res) == 0) {
        if(inet_ntop(AF_INET,
            &((struct sockaddr_in *)res->ai_addr)->sin_addr,
            IPString, IPStrLen)){      
            return 0;
        }
        freeaddrinfo(res);
    }
    return -1;
}

/*-F- interfaceAddVlan -- 
 */
int interfaceAddVlan(const char* Interface, const int VlanID)
{
    if(!Interface) return -1;

    if(VlanID < 0 || VlanID >=4096) return -1;

    struct vlan_ioctl_args if_request;
    memset(&if_request, 0, sizeof(struct vlan_ioctl_args));

    if_request.cmd = ADD_VLAN_CMD;

    strcpy(if_request.device1, Interface);

    if_request.u.VID = VlanID;
                            
    return interfaceVlanConfig(&if_request);
}

/*-F- interfaceDelVlan --
 */
int interfaceDelVlan(const char* Interface)
{
    if(!Interface) return -1;

    struct vlan_ioctl_args if_request;
    memset(&if_request, 0, sizeof(struct vlan_ioctl_args));

    if_request.cmd = DEL_VLAN_CMD;

    strcpy(if_request.device1, Interface);

    return interfaceVlanConfig(&if_request);
}

/*-F- interfaceStartPortVlan --
 */
int interfaceStartPortVlan(
        const char* Interface)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    ethcfg.cmd = ATHR_VLAN_ENABLE;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);
    return 0;
}

/*-f- interfaceStopPortVlan --
 */
int interfaceStopPortVlan(
        const char* Interface)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    ethcfg.cmd = ATHR_VLAN_DISABLE;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);

    return 0;
}

/*-F- interfaceAddPortVlan -- 
 */
int interfaceAddPortVlan(
        const char* Interface,
        int Port,
        int VlanID)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    VlanID &= 0xfff; //vlan-id

    ethcfg.val = (VlanID << 16) | (1<<Port);

    ethcfg.cmd = ATHR_VLAN_ADDPORTS;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);
    return 0;
}

/*-F- interfaceDelPortVlan -- 
 */
int interfaceDelPortVlan(
        const char* Interface,
        int Port,
        int VlanID)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};
    
    if(!Interface) return -1;

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    VlanID &= 0xfff; //vlan-id

    ethcfg.val = (VlanID << 16) | (1<<Port);

    ethcfg.cmd = ATHR_VLAN_DELPORTS;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);
    return 0;
}

/*-F- interfaceSetPortMode --
 */
int interfaceSetPortMode(
        const char* Interface,
        int Port,
        int Mode)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};
    if(!Interface) return -1;

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    Mode &= 0xf; //mode
    Port &= 0x7;  //ports

    ethcfg.val = (Mode << 16) | (Port);

    ethcfg.cmd = ATHR_VLAN_SETTAGMODE;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);

    return 0;
}

/*-F- interfaceSetDefaultVlanID --
 */
int interfaceSetDefaultVlanID(
        const char* Interface,
        int Port,
        int DefaultVlanID)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};
    if(!Interface) return -1;

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    DefaultVlanID &= 0xfff; //default vlan id
    Port &= 0x1ff;  //ports

    ethcfg.val = (DefaultVlanID << 16) | (Port);

    ethcfg.cmd = ATHR_VLAN_SETDEFAULTID;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);

    return 0;
}

/*-F- interfaceSetMTUByName --
 */
int interfaceSetMTUByName(
        const char* Interface,
        const int MTU)
{
    if(!Interface) return -1;

    if(0 == strlen(Interface)) return -1;

    int s = -1;
    struct ifreq ifr = {};

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    ifr.ifr_mtu = MTU;

    if(0 != ioctl(s, SIOCSIFMTU, &ifr)) {
        close(s);
        return -1;
    }

    close(s);

    return 0;
}

/*-F- interfaceControlByName --
 */
int interfaceControlByName(
        const char* Interface,
        const int Up)           /* 1=bring up, 0=take down*/
{
    if(!Interface || 0 == strlen(Interface)) return -1;

    int s = -1;
    struct ifreq ifr = {};

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) {
        close(s);
        return -1;
    }

    if (Up) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);
    return 0;
}
/*-F- interfaceGetIPAddressByName -- 
 */
int interfaceGetIPAddressByName(
        const char* Interface,
        ipaddress_t* IpAddress)
{
    if(!Interface || !IpAddress) return -1;

    if(0 == strlen(Interface)) return -1;

    int s = -1;
    struct ifreq ifr = {};

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    if(0 != ioctl(s, SIOCGIFADDR, &ifr)) {
        close(s);
        return -1;
    }

    memcpy((char*)&(IpAddress->sockaddr_in),
        ((struct sockaddr_in *)&ifr.ifr_addr), sizeof(struct sockaddr_in));

    close(s);
    return 0;
}

/*-F- interfaceSetIPAddressByName --
 */
int interfaceSetIPAddressByName(
        const char* Interface,
        const char* IpAddress,
        const char* SubnetMask)
{
    if(!Interface || !IpAddress) return -1;

    if(0 ==strlen(Interface) || 0 == strlen(IpAddress)) return -1;

    int s = -1;
    struct ifreq ifr = {};
    struct sockaddr_in* addr = NULL;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    addr->sin_family=AF_INET;
    addr->sin_addr.s_addr=inet_addr(IpAddress);

    if( 0 != ioctl(s, SIOCSIFADDR, &ifr)) {
        close(s);
        return -1;
    }

    if(SubnetMask && (strlen(SubnetMask)>0)) {
        addr = (struct sockaddr_in *)&(ifr.ifr_netmask);
        addr->sin_family=AF_INET;
        addr->sin_addr.s_addr=inet_addr(SubnetMask);

        if( 0 != ioctl(s, SIOCSIFNETMASK, &ifr)) {
            close(s);
            return -1;
        }
    }

    close(s);
    return 0;
}


/*-F- interfaceGetMACAddressForInterface -- get six byte mac address
*       Returns nonzero on error.
*/
int interfaceGetMACAddressForInterface(
        const char* Interface,
        unsigned char MACAddress[6])    /* output */
{
    if(!Interface || !MACAddress) return -1;
    if(0 == strlen(Interface)) return -1;

    int s = -1;
    struct ifreq ifr = {};

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    if(0 != ioctl(s, SIOCGIFHWADDR, &ifr)) {
        close(s);
        return -1;
    }
    memcpy(MACAddress, ifr.ifr_hwaddr.sa_data, 6);
    close(s);
    return 0;
}

/*-F- interfaceGetMACAddressByName -- get text represenation of mac address
*       Returns nonzero on error.
*/
int interfaceGetMACAddressByName(
        const char* Interface,
        char* MACAddress,       /* output */
        int MACAddressSize)     /* size of output buffer */
{
    unsigned char BinaryMacAddress[6];
    if(!MACAddress || MACAddressSize <= 0) return -1;
    if (interfaceGetMACAddressForInterface(Interface, BinaryMacAddress)) {
        return -1;
    }
    snprintf(MACAddress, MACAddressSize, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
        BinaryMacAddress[0],
        BinaryMacAddress[1],
        BinaryMacAddress[2],
        BinaryMacAddress[3],
        BinaryMacAddress[4],
        BinaryMacAddress[5]);
    return 0;
}

/*-F- interfaceGetStatusByName --
 */
int interfaceGetStatusByName(
        const char* Interface)
{
    if(!Interface) return -1;
    
    int s = -1;
    struct ifreq ifr = {};
   
    if((s = socket(AF_INET, SOCK_DGRAM, 0)) <= 0) return -1;

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    if(0 != ioctl(s, SIOCGIFFLAGS, &ifr)) {
        close(s);
        return -1;
    }  
   
    close(s);
    return ifr.ifr_flags & IFF_UP;
}

/*-F- interfaceGetPortLinkStatus --
 */
int interfaceGetPortLinkStatus(const char* Interface, int Port)
{
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        close(s);
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    ethcfg.portnum = Port;

    ethcfg.cmd = ATHR_PORT_LINK;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_PHY_CTRL_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);
    return ethcfg.val;
}

/*-F- interfaceGetStatsByName --
 */
int interfaceGetStatsByName(
        const char* Interface,
        struct NetDeviceStats* NDStats)
{
    if(!Interface || ! NDStats) return -1;
    
    char buf[BUFSIZ] = {};
    FILE *f = NULL;

    f = fopen(PATH_PROC_NET_DEV, "r");
    if(!f) return -1;

    fgets(buf, sizeof(buf), f); // eat first line
    fgets(buf, sizeof(buf), f); // eat second line
    
    // TODO: FIXME: hard code here
    while(fgets(buf, sizeof(buf), f)) {
        char col[2*BUFSIZ] = {};
        int n = splitByToken(buf, 2, BUFSIZ, col, ':');
        if(n == 2) {
            char name[BUFSIZ] = {};
            // trim left space
            int i, j=0;
            for(i=0; i<strlen(col); i++) {
                if(col[i] == ' ') continue;
                name[j] = col[i];
                j++;
            }
            name[j] = '\0'; // add end of string
            // check name
            if(0 == strcmp(name, Interface)) {
                // get stats then break
                sscanf(col+BUFSIZ, SS_FMT,
                   &NDStats->rx_bytes, /* missing for 0 */
                   &NDStats->rx_packets,
                   &NDStats->rx_errors,
                   &NDStats->rx_dropped,
                   &NDStats->rx_fifo_errors,
                   &NDStats->rx_frame_errors,
                   &NDStats->rx_compressed, /* missing for <= 1 */
                   &NDStats->rx_multicast, /* missing for <= 1 */
                   &NDStats->tx_bytes, /* missing for 0 */
                   &NDStats->tx_packets,
                   &NDStats->tx_errors,
                   &NDStats->tx_dropped,
                   &NDStats->tx_fifo_errors,
                   &NDStats->tx_collisions,
                   &NDStats->tx_carrier_errors,
                   &NDStats->tx_compressed /* missing for <= 1 */
                   );
                break;
            } else {
                continue;
            }
        } else {
            continue;
        }
    }
    fclose(f);
    return 0;
}

/*-F- interfaceGetLinkOnOffByName --
*/
int interfaceGetLinkOnOffByName(
		const char * Interface)
{
    if(!Interface) return -1;
    
    int sock = -1;
    struct ifreq ifr = {};
   
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) <= 0) return -1;

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));

    if(0 != ioctl(sock, SIOCGIFFLAGS, &ifr)) {
        close(sock);
        return -1;
    }  
	close(sock);
    if (ifr.ifr_flags &IFF_RUNNING)	//up
    	return 1;
    else
    	return 0;
}

/*-F- interfaceGetStatsByName --
 */
int interfaceGetStatsByPort(
        const char* BaseInterface,
        int Port,
        struct NetDeviceStats* NDStats)
{
    int sock;
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

    if(! NDStats) return -1;

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    strlcpy(ifr.ifr_name, BaseInterface, sizeof(ifr.ifr_name));
    ethcfg.portnum = Port;
    ethcfg.cmd = ATHR_PHY_STATS; /* read clear */
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(sock, ATHR_PHY_CTRL_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    NDStats->rx_bytes = ethcfg.rxcntr.rx_goodbl + ethcfg.rxcntr.rx_badbl;
    NDStats->rx_bytes <<= 32;
    NDStats->rx_bytes += ethcfg.rxcntr.rx_goodbh + ethcfg.rxcntr.rx_badbu;
    NDStats->rx_packets = ethcfg.rxcntr.rx_multi
           + ethcfg.rxcntr.rx_broad
           + ethcfg.rxcntr.rx_64b + ethcfg.rxcntr.rx_128b
           + ethcfg.rxcntr.rx_256b + ethcfg.rxcntr.rx_512b
           + ethcfg.rxcntr.rx_1024b + ethcfg.rxcntr.rx_1518b
           + ethcfg.rxcntr.rx_maxb + ethcfg.rxcntr.rx_tool
           + ethcfg.rxcntr.rx_runt + ethcfg.rxcntr.rx_frag;
    NDStats->rx_errors = ethcfg.rxcntr.rx_fcserr + ethcfg.rxcntr.rx_allignerr;
    NDStats->rx_dropped = ethcfg.rxcntr.rx_overflow;
    NDStats->rx_fifo_errors = 0;
    NDStats->rx_frame_errors = ethcfg.rxcntr.rx_allignerr;
    NDStats->rx_compressed = 0;
    NDStats->rx_multicast = ethcfg.rxcntr.rx_multi + ethcfg.rxcntr.rx_broad;

    NDStats->tx_bytes = ethcfg.txcntr.tx_bytel;
    NDStats->tx_bytes <<= 32;
    NDStats->tx_bytes += ethcfg.txcntr.tx_byteh;
    NDStats->tx_packets = ethcfg.txcntr.tx_multi + ethcfg.txcntr.tx_broad
           + ethcfg.txcntr.tx_64b + ethcfg.txcntr.tx_128b
           + ethcfg.txcntr.tx_256b + ethcfg.txcntr.tx_512b
           + ethcfg.txcntr.tx_1024b + ethcfg.txcntr.tx_1518b
           + ethcfg.txcntr.tx_maxb + ethcfg.txcntr.tx_oversiz;
    NDStats->tx_errors = ethcfg.txcntr.tx_oversiz;
    NDStats->tx_dropped = ethcfg.txcntr.tx_underrun + ethcfg.txcntr.tx_abortcol;
    NDStats->tx_fifo_errors = ethcfg.txcntr.tx_underrun;
    NDStats->tx_carrier_errors = 0;
    NDStats->tx_compressed = 0;

    close(sock);
    return 0;
}

/*-F- interfaceSetDuplex --
 */
int interfaceSetDuplex(
        const char* Interface,
        int Mode, /* DUPLEX_HALF, DUPLEX_FULL, 0 for AUTO */
        int Advertise)
{
    int sock;
    struct ethtool_cmd  ethdata;
    struct ifreq        ifr;
    struct ethtool_cmd  *p;

    memset(&ethdata, 0, sizeof(struct ethtool_cmd));

    if((sock = socket(AF_INET,SOCK_DGRAM, 0)) < 0) return -1;
        
    ethdata.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)&ethdata;
    p = (struct ethtool_cmd  *)ifr.ifr_data;
    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
#define SIOCETHTOOL 0x8946      /* Ethtool interface        */
    if(ioctl(sock,SIOCETHTOOL,&ifr) < 0) {
        close(sock);
        return -1;
    }

    ethdata.cmd = ETHTOOL_SSET;
    if(Mode == 0 /*AUTO*/) {
        p->advertising = p->supported & (ADVERTISED_10baseT_Half |
                         ADVERTISED_10baseT_Full |
                         ADVERTISED_100baseT_Half |
                         ADVERTISED_100baseT_Full |
                         ADVERTISED_1000baseT_Half |
                         ADVERTISED_1000baseT_Full |
                         ADVERTISED_10000baseT_Full);
    } else {
        p->duplex = Mode;
        p->advertising = Advertise;
    }

    if(ioctl(sock,SIOCETHTOOL,&ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);    
    return 0;
}


/*-F- interfaceIgmpSnoopingSet --
 */
int interfaceIgmpSnoopingSet(
        unsigned int vlanId,
		int enable)
{
    int sock;
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

	if(enable != 0 && enable != 1)
		return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    
    ethcfg.val = vlanId & 0x1f;
    ethcfg.val |= enable << 7;

	ethcfg.cmd = ATHR_IGMP_ON_OFF;
	ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(sock, ATHR_VLAN_IGMP_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

/*-F- interfaceAddARL --
 */
int interfaceAddARL(
	const char* Interface,
        mac_addr_t macAddr,
	unsigned int Port)
{
    int sock;
    arl_struct_t arl;
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    memcpy(&arl.hwaddr,&macAddr,6);

    // Please note port0 =1 ... portn=1<<n    
    arl.port_map = 1<< Port;
    arl.sa_drop = 0;

    memcpy(&ethcfg.vlanid,&arl,sizeof(arl_struct_t));

    ethcfg.cmd = ATHR_ARL_ADD;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(sock, ATHR_VLAN_IGMP_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}
/*-F- interfaceDelARL --
 */
int interfaceDelARL(
	const char* Interface,
        mac_addr_t mac)
{
    int sock;
    arl_struct_t arl = {};
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

    if(!Interface) return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    memcpy(&arl.hwaddr,&mac,6);

    memcpy(&ethcfg.vlanid,&arl,sizeof(arl_struct_t));

    ethcfg.cmd = ATHR_ARL_DEL;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(sock, ATHR_VLAN_IGMP_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

/*-F- interfaceArlFlush --
 */
int interfaceArlFlush(
        const char* Interface)
{
#if 0
    int s = -1;
    struct ifreq ifr = {};
    struct eth_cfg_params ethcfg = {};

    if(!Interface) return -1;

    if(0 >= (s=socket(AF_INET, SOCK_DGRAM, 0))) {
        return -1;
    }

    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    ethcfg.cmd = ATHR_ARL_FLUSH;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(s, ATHR_VLAN_IGMP_IOC, &ifr) != 0) {
        close(s);
        return -1;
    }

    close(s);
#endif
    return -1;
}

/*-F- interfaceGetPlcPort --
 */
int interfaceGetPlcPort(
	const char* Interface, unsigned char *MAC)
{
#if 0
    int sock;
    arl_struct_t arl;
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

    if(!Interface) return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    
    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    memcpy(&arl.hwaddr, MAC, 6);
    arl.port_map = 0;
   
    memcpy(&ethcfg.vlanid,&arl,sizeof(arl_struct_t));

    ethcfg.cmd = ATHR_VHYFI_PLC_PORT;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(sock, ATHR_VLAN_IGMP_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);

    return ((arl_struct_t *)&ethcfg.vlanid)->port_map;
#endif
    return -1;
}
/*-F- interfaceSetPacketFlag --
 */
int interfaceSetPacketFlag(const char *Interface,
        int Op)
{
    int sock;
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

    if(Op > 1 || Op < 0) return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    strlcpy(ifr.ifr_name, Interface, sizeof(ifr.ifr_name));
    ethcfg.val = Op;
    /* Op = 1: Enable 0: disable */

    ethcfg.cmd = ATHR_PACKET_FLAG;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;
    if (ioctl(sock, ATHR_VLAN_IGMP_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

/*-F- interfaceGetLinkStats --
 * Inforamtion: byte one   -- 1:up/0:down
 *              byte two   -- 1:FULL/0:HALF duplex
 *              byte three -- 0:10M/1:100M/2:1G
 */
int interfaceGetLinkInformation(const char *InterfaceName, int *Information, int Port)
{
    int sock;
    struct ifreq ifr;
    struct eth_cfg_params ethcfg = {};

    if (!Information || !InterfaceName) return -1;

    Port = interfaceEthernetPortMapping(Port);
    if (Port < 0) return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    strlcpy(ifr.ifr_name, InterfaceName, sizeof(ifr.ifr_name));
    ethcfg.val = Port;
    ethcfg.cmd = ATHR_LINK_GETSTAT;
    ifr.ifr_ifru.ifru_data = (void *)&ethcfg;

    if (ioctl(sock, ATHR_VLAN_IGMP_IOC, &ifr) < 0) {
        close(sock);
        return -1;
    }

    *Information = ifr.ifr_ifru.ifru_ivalue;

    close(sock);
    return 0;
}

/*-F- interfaceGetLanLinkSpeed --
 *  return 0: 10M
 *         1: 100M
 *         2: 1000M
 */
int interfaceGetLanLinkSpeed(const char *InterfaceName)
{
    int Information = 0;

    if (interfaceGetLinkInformation(InterfaceName, &Information, 1) < 0)
        return -1;

    return (Information >> 16) & 0x03;
}

/*-F- interfaceGetWanLinkStats --
 */
int interfaceGetWanLinkStats(const char *InterfaceName, int *Stats)
{
    return interfaceGetLinkInformation(InterfaceName, Stats, GATEWAY_WAN_PORT);
}

/*-F- interfaceGetNetmaskByName --
 */
int interfaceGetNetmaskByName(const char *ifName,
    unsigned int *netmask)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *ip = NULL;

    if(ifName == NULL || netmask == NULL) 
        return -1;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strlcpy(ifr.ifr_name, ifName, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        close(sock);
        return -1;
    }
    ip = (struct sockaddr_in *)&ifr.ifr_netmask;
    *netmask = (unsigned int)ip->sin_addr.s_addr;

    close(sock);
    return 0;
}

/*-F- interfaceSetIFFlag --
 */
int interfaceSetIFFlag(const char *ifName, unsigned int IFFlag)
{
    int Sock;
    struct ifreq Ifr;

    if(ifName == NULL) 
        return -1;

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;

    Ifr.ifr_addr.sa_family = AF_INET;
    strlcpy(Ifr.ifr_name, ifName, sizeof(Ifr.ifr_name));

    if (ioctl(Sock, SIOCGIFFLAGS, &Ifr) < 0) {
        close(Sock);
        return -1;
    }

    Ifr.ifr_flags |= IFFlag;

    if (ioctl(Sock, SIOCSIFFLAGS, &Ifr) < 0) {
        close(Sock);
        return -1;
    }

    close(Sock);
    return 0;
}

/*-F- interfaceGetDefaultGateway --
 */
int interfaceGetDefaultGateway(char *DefaultGateway)
{
	FILE *fp = NULL;
	char route[3][20];
	char buf[BUFSIZ] = { };
	fp = popen("ip route", "r");
	if (!fp)
        {
                fp = popen("route", "r");
                if(!fp)
                {
		        return -1;
                }
        }
	while (fgets(buf,sizeof(buf),fp))
	{
		if(strstr(buf,"default")){
			int i,j=0,k = 0;
			for (i = 0; i < strlen(buf); i++) 
			{
				if(buf[i]!=' ')
				{
						route[k][j]=buf[i];
						j++;
				}else{
						route[k][j]='\0';
						k++;
						j=0;
				}
				if (k==3)break;
			}
		}	
	}
	pclose(fp);
	if (0!=strcmp(route[0],"default"))
		route[2][0]='\0';
	strcpy(DefaultGateway,route[2]); 	//get defaultGateway ip
	return 0;
}

/*-F- interfaceGetSignalStrengthByName --
 */
int interfaceGetSignalStrengthByName(const char *Interface)
{
	FILE *fp = NULL;
	char quality[4][20];
	char buf[BUFSIZ] = { };
	int i,tmp=0;
	fp = fopen("/proc/net/wireless", "r");

	if (NULL == fp) {
		perror("/proc/net/wireless");
		return -1;
	}
	fgets(buf, sizeof(buf), fp);	// eat first line
	fgets(buf, sizeof(buf), fp);	// eat second line

	while (fgets(buf, sizeof(buf), fp)) 
	{
		char col[2*BUFSIZ] = { };
		int n = splitByToken(buf, 2, BUFSIZ, col, ':');
		if (n == 2) {
			char name[BUFSIZ] = { };
			// trim left space
			int i, k = 0,j = 0;
			for (i = 0; i < strlen(col); i++) {
				if (col[i] == ' ')
					continue;
				name[j] = col[i];
				j++;
			}
			name[j] = '\0';	// add end of string
			// check name
			if (0 == strcmp(name, Interface)) 
			{
				for(i=0;i<strlen(col+BUFSIZ);i++)
				{
					if (col[BUFSIZ+i] == 0x20){
						j=0; 
						if(col[BUFSIZ+i+1]!= 0x20)
							k++;
					}
					else
					{
						quality[k][j] = col[BUFSIZ+i];
						j++;
					}
					if( k==4)
						break;
				}
			} else {
				continue;
			}
		} 
		else 
		{
			continue;
		}
	}
	pclose(fp);
	for(i=1;i<5;i++)
	{
		if(quality[3][i] == '.') break;
		tmp=tmp*10+ (quality[3][i]-0x30);
	}
	tmp=0-tmp;
	return tmp;
}

/*-F- interfaceGetVapTR181StatsByName --
 */
int interfaceGetVapTR181StatsByName(const char *Interface,
				 struct NetDeviceStats* NDStats)
{
	FILE *fp = NULL;
	char cmd[20]="apstats -v -i ";
	int i,j=0,tmp=0;
	char buf[BUFSIZ] = { };
	char col[2*BUFSIZ] = {};
	int data[14] = { };
	strcat(cmd,Interface);
	fp = popen(cmd, "r");

	if (NULL == fp) {
		perror("apstats error");
		return -1;
	}
	/*
	*the implement depend on apstats,if exist some bug please fix me
	*/
	fgets(buf, sizeof(buf), fp);		// eat first line
	while(fgets(buf, sizeof(buf), fp))
	{
		//printf("%s\n",buf);
		splitByToken(buf, 2, BUFSIZ, col, '=');
		tmp=0;
		for(i=1;i<10;i++)
		{
			if(col[BUFSIZ+1]== '<')
			{
				//printf("No Station\n");
				tmp=0;
				break;
			}
			if(col[BUFSIZ+i] == 0xa) break;
			tmp=(col[BUFSIZ+i]-0x30)+tmp*10;
		}
		//printf("the line data is %d\n",tmp);
		data[j]=tmp;
		if((j++)==13) break;
	}

	NDStats->tx_mcast = data[7];
	NDStats->rx_mcast = data[9];
	NDStats->tx_bcast = data[7];	//wlan can not identify multicast and broadcast
	NDStats->rx_bcast = data[9];
	NDStats->tx_ucast = data[6];
	NDStats->rx_ucast = data[8];
	NDStats->tx_rate =  data[10];
	NDStats->rx_rate =  data[11];
	NDStats->tx_fail =  data[13];
	pclose(fp);
	return 0;
}
