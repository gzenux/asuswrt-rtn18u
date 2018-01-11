#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/wireless.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <time.h>
#include <sys/time.h>
#include <signal.h>

/* wlan driver ioctl id */
#define SIOCGIWRTLGETMIB			0x89f2	// get mib (== RTL8190_IOCTL_GET_MIB)
#define SIOC11KBEACONREQ            0x8BD2
#define SIOC11KBEACONREP            0x8BD3


#define _FRAME_BODY_SUBIE_		    1 
#define _HT_CAP_					45
#define _MOBILITY_DOMAIN_IE_		54
#define _VENDOR_SPEC_IE_            221


#define DEFAULT_RANDOM_INTERVAL  20
#define DEFAULT_MEASURE_DURATION 100
#define DEFAULT_BSSINFO_VALUE    0x000E

#define MACADDRLEN					6
#define MAX_SSID_LEN			    32
#define MAX_BEACON_SUBLEMENT_LEN           226
#define MAX_REQUEST_IE_LEN          16
#define MAX_AP_CHANNEL_REPORT       4
#define MAX_AP_CHANNEL_NUM          8

#define MAX_STA_NUM			128	// max support sta number
#define MAX_NEIGHBOR_NUM    32	// max support neighbor number

#define TIMER_INTERVAL 60
#define BEACON_MEASURE_TIME 13


#define NEIGHBOR_REPORT_PATH "/proc/%s/rm_neighbor_report"
#define STA_INFO_PATH "/proc/%s/sta_info"
#define MIB_11N_PATH "/proc/%s/mib_11n"

char iface_name[20] = {0};
char iface_name2[20] = {0};
char iface_ssid[33] = {0};
unsigned int iface_ft_enable = 0;
char iface_mdid[3] = {0};
unsigned char iface_htcap[26] = {0};

unsigned char request_ie[] = {_HT_CAP_, _MOBILITY_DOMAIN_IE_};
int debug_mode = 0;
unsigned char tempbuf[16384];


#define DOT11K_DEBUG(fmt, args...) do{if(debug_mode) printf(fmt, ## args); }while(0)


/* WLAN sta info structure */
typedef struct wlan_sta_info
{
    unsigned short	aid;
    unsigned char	addr[6];
    unsigned long	tx_packets;
    unsigned long	rx_packets;
    unsigned long	expired_time;	// 10 msec unit
    unsigned short	flag;
    unsigned char	txOperaRates;
    unsigned char	rssi;
    unsigned long	link_time;		// 1 sec unit
    unsigned long	tx_fail;
    unsigned long tx_bytes;
    unsigned long rx_bytes;
    unsigned char network;
    unsigned char ht_info;	// bit0: 0=20M mode, 1=40M mode; bit1: 0=longGI, 1=shortGI
    unsigned char	RxOperaRate;
    unsigned char 	resv[5];
} WLAN_STA_INFO_T, *WLAN_STA_INFO_Tp;



typedef enum
{
    MEASUREMENT_UNKNOWN = 0,
    MEASUREMENT_PROCESSING = 1,
    MEASUREMENT_SUCCEED = 2,
    MEASUREMENT_INCAPABLE = 3,
    MEASUREMENT_REFUSED = 4,
} MEASUREMENT_RESULT;


typedef enum
{
    BEACON_MODE_PASSIVE = 0,
    BEACON_MODE_ACTIVE = 1,
    BEACON_MODE_TABLE = 2,
} BEACON_MODE;


#pragma pack(1)

struct dot11k_ap_channel_report
{
    unsigned char len;
    unsigned char op_class;
    unsigned char channel[MAX_AP_CHANNEL_NUM];
};

struct dot11k_beacon_measurement_req
{
    unsigned char op_class;
    unsigned char channel;
    unsigned short random_interval;
    unsigned short measure_duration;
    unsigned char mode;
    unsigned char bssid[MACADDRLEN];
    char ssid[MAX_SSID_LEN + 1];
    unsigned char report_detail; /* 0: no-fixed len field and element,
                                                               1: all fixed len field and elements in Request ie,
                                                               2: all fixed len field and elements (default)*/
    unsigned char request_ie_len;
    unsigned char request_ie[MAX_REQUEST_IE_LEN];
    struct dot11k_ap_channel_report ap_channel_report[MAX_AP_CHANNEL_REPORT];
};

struct dot11k_beacon_measurement_report_info
{
    unsigned char op_class;
    unsigned char channel;
    unsigned int  measure_time_hi;
    unsigned int  measure_time_lo;
    unsigned short measure_duration;
    unsigned char frame_info;
    unsigned char RCPI;
    unsigned char RSNI;
    unsigned char bssid[MACADDRLEN];
    unsigned char antenna_id;
    unsigned int  parent_tsf;
};


struct dot11k_beacon_measurement_report
{
    struct dot11k_beacon_measurement_report_info info;
    unsigned char subelements_len;
    unsigned char subelements[MAX_BEACON_SUBLEMENT_LEN];
};


union dot11k_neighbor_report_bssinfo
{
    unsigned int value;
    struct
    {
#if  (__BYTE_ORDER == __BIG_ENDIAN)
        unsigned int reserved:20;
        unsigned int high_tp:1;
        unsigned int mde:1;
        unsigned int cap_im_ba:1;
        unsigned int cap_delay_ba:1;
        unsigned int cap_rm:1;
        unsigned int cap_apsd:1;
        unsigned int cap_qos:1;
        unsigned int cap_spectrum:1;
        unsigned int key_scope:1;
        unsigned int security:1;
        unsigned int ap_reachability:2;
#else
        unsigned int ap_reachability:2;
        unsigned int security:1;
        unsigned int key_scope:1;
        unsigned int cap_spectrum:1;
        unsigned int cap_qos:1;
        unsigned int cap_apsd:1;
        unsigned int cap_rm:1;
        unsigned int cap_delay_ba:1;
        unsigned int cap_im_ba:1;
        unsigned int mde:1;
        unsigned int high_tp:1;
        unsigned int reserved:20;
#endif
    } field;
};

struct dot11k_neighbor_report
{
    unsigned char bssid[MACADDRLEN];
    union dot11k_neighbor_report_bssinfo bssinfo;
    unsigned char op_class;
    unsigned char channel;
    unsigned char phytype;
};

#pragma pack(0)


const static unsigned char global_op_class[] = { 115, 118, 121, 124, 125 };


struct dot11k_sta_info
{
    unsigned char valid;

    char iface[20];
    unsigned char hwaddr[MACADDRLEN];
    unsigned char rm_cap[5];
    unsigned char channel;
    unsigned char last_scan_idx;
    MEASUREMENT_RESULT result;
};


struct dot11k_sta_info dot11k_sta[MAX_STA_NUM];
struct dot11k_neighbor_report dot11k_neighbor_list[MAX_NEIGHBOR_NUM];
int dot11k_neighbor_num;

static int pidfile_acquire(char *pidfile)
{
    int pid_fd;

    if(pidfile == NULL)
        return -1;

    pid_fd = open(pidfile, O_CREAT | O_WRONLY, 0644);
    if (pid_fd < 0)
        printf("Unable to open pidfile %s\n", pidfile);
    else
        lockf(pid_fd, F_LOCK, 0);

    return pid_fd;
}

static void pidfile_write_release(int pid_fd)
{
    FILE *out;

    if(pid_fd < 0)
        return;

    if((out = fdopen(pid_fd, "w")) != NULL)
    {
        fprintf(out, "%d\n", getpid());
        fclose(out);
    }
    lockf(pid_fd, F_UNLCK, 0);
    close(pid_fd);
}

static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

static int string_to_hex(char *string, unsigned char *key, int len)
{
    char tmpBuf[4];
    int idx, ii=0;
    for (idx=0; idx<len; idx+=2)
    {
        tmpBuf[0] = string[idx];
        tmpBuf[1] = string[idx+1];
        tmpBuf[2] = 0;
        if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
            return 0;
        key[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
    }
    return 1;
}
static int wlioctl_get_mib(char *interfacename , char* mibname ,void *result,int size )
{

    int skfd;
    struct iwreq wrq;
    unsigned char tmp[30];

    if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) <0)
    {
        printf("[%s %d] socket error \n", __FUNCTION__, __LINE__);
        return -1;
    }

    /* Set device name */
    strcpy(wrq.ifr_name, interfacename);
    strcpy((char *)tmp,mibname);

    wrq.u.data.pointer = tmp;
    wrq.u.data.length = strlen((char *)tmp);

    /* Do the request */
    if(ioctl(skfd, SIOCGIWRTLGETMIB, &wrq) < 0)
    {
        printf("[%s %d] ioctl[SIOCGIWRTLGETMIB]", __FUNCTION__, __LINE__);
        close(skfd);
        return -1;
    }

    close(skfd);
    if(size)
    {
        memcpy(result,tmp, size);
    }
    else
        strcpy(result, (char *)tmp);
    return 0;

}


static int getWlStaInfo( char *ifname)
{
    FILE * fh;
    char  *token,* ptr, *buf = (char *)tempbuf;
    int buf_size = sizeof(tempbuf);
    unsigned char channel;
    unsigned char hwaddr[MACADDRLEN];
    unsigned char rm_cap[5];
    int i, empty = -1;

    wlioctl_get_mib(ifname, "channel", &channel, 1);
    sprintf(buf, STA_INFO_PATH, ifname);
    fh = fopen(buf, "r");
    if (!fh)
    {
        printf("[%s %d] Warning: cannot open %s\n", __FUNCTION__, __LINE__, buf);
        return -1;
    }

    while( fgets(buf, buf_size, fh) != NULL )
    {
        token = "hwaddr:";

        if( (ptr = strstr(buf,token)) != NULL )
        {
            ptr += strlen(token);
            while (*ptr == ' ' ) ptr++;
            string_to_hex(ptr, hwaddr, 12);

            while( fgets(buf, buf_size, fh) != NULL )
            {

                token = "rm_cap:";
                if( (ptr = strstr(buf,token)) != NULL )
                {
                    ptr += strlen(token);
                    while (*ptr == ' ' ) ptr++;
                    string_to_hex(ptr, rm_cap, 10);
                    break;
                }
            }


            for(i = 0; i < MAX_STA_NUM; i++)
            {
                if(dot11k_sta[i].valid)
                {
                    if(memcmp(hwaddr, dot11k_sta[i].hwaddr, MACADDRLEN) == 0)
                    {
                        strcpy(dot11k_sta[i].iface, ifname);
                        memcpy(dot11k_sta[i].rm_cap, rm_cap, 5);
                        dot11k_sta[i].channel = channel;
                        dot11k_sta[i].valid = 2;
                        break;
                    }

                }
                else
                {
                    if(empty == -1)
                        empty = i;
                }
            }

            if(i == MAX_STA_NUM && empty != -1)
            {
                memset(&dot11k_sta[empty], 0, sizeof(struct dot11k_sta_info));
                strcpy(dot11k_sta[empty].iface, ifname);
                memcpy(dot11k_sta[empty].hwaddr, hwaddr, MACADDRLEN);
                memcpy(dot11k_sta[empty].rm_cap, rm_cap, 5);
                dot11k_sta[empty].channel = channel;
                dot11k_sta[empty].valid = 2;
            }
        }
    }

    fclose(fh);

}



static int getWlHtCap( char *ifname, unsigned char* ht_cap)
{
    FILE * fh;
    char  *token, *ptr, *buf = (char *)tempbuf;
    int buf_size = sizeof(tempbuf);

    sprintf(buf, MIB_11N_PATH, ifname);
    fh = fopen(buf, "r");
    if (!fh)
    {
        printf("[%s %d] Warning: cannot open %s\n", __FUNCTION__, __LINE__, buf);
        return -1;
    }

    while( fgets(buf, buf_size, fh) != NULL )
    {
        token = "ht_cap:";
        if( (ptr = strstr(buf, token)) != NULL )
        {
            ptr += strlen(token);
            while (*ptr == ' ' ) ptr++;

            token = "none";
            if(strstr(ptr, token) == 0) { 
                string_to_hex(ptr, ht_cap, 52);
            }
            break;
        }
    }
    fclose(fh);

}

static int issue_beacon_measurement(char *ifname, unsigned char * macaddr,
                                    struct dot11k_beacon_measurement_req* beacon_req)
{
    int sock;
    struct iwreq wrq;
    int err;
    int len = 0;

    /*** Inizializzazione socket ***/
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        err = errno;
        printf("[%s %d]: Can't create socket for ioctl. %s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }
    memcpy(tempbuf, macaddr, MACADDRLEN);
    len += MACADDRLEN;
    memcpy(tempbuf + len, beacon_req, sizeof(struct dot11k_beacon_measurement_req));
    len += sizeof(struct dot11k_beacon_measurement_req);

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)tempbuf;
    wrq.u.data.length = len;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KBEACONREQ, &wrq) < 0)
    {
        err = errno;
        printf("[%s %d]: %s ioctl Error.(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }
    err = 0;

out:
    close(sock);
    return err;
}

static void print_bss_info(struct dot11k_beacon_measurement_report * beacon_report, int index)
{
    int i = 0;
    beacon_report += index;
    printf("\t[%d]BSSID: %02x%02x%02x%02x%02x%02x\n", index + 1,
           beacon_report->info.bssid[0], beacon_report->info.bssid[1], beacon_report->info.bssid[2],
           beacon_report->info.bssid[3], beacon_report->info.bssid[4], beacon_report->info.bssid[5]);
    printf("\t\toperating class: %d\n", beacon_report->info.op_class);
    printf("\t\tchannel: %d\n", beacon_report->info.channel);
    printf("\t\tmeasure_time: 0x%08X%08X\n", beacon_report->info.measure_time_hi, beacon_report->info.measure_time_lo);
    printf("\t\tmeasure_duration: %d\n", beacon_report->info.measure_duration);
    printf("\t\tframe info: 0x%02X\n", beacon_report->info.frame_info);
    printf("\t\tRCPI: 0x%02X\n", beacon_report->info.RCPI);
    printf("\t\tRSNI: 0x%02X\n", beacon_report->info.RSNI);
    printf("\t\tantenna_id: %d\n", beacon_report->info.antenna_id);
    printf("\t\tparent TSF: 0x%08X\n", beacon_report->info.parent_tsf);
    printf("\t\tsubelements len: %d\n", beacon_report->subelements_len);
    printf("\t\tsubelements payload:");
    for(i = 0; i <beacon_report->subelements_len; i++)
    {
        if(i % 16 == 0)
            printf("\n\t\t");
        printf(" %02X", beacon_report->subelements[i]);
    }
    printf("\n");
}


static int colloect_neighbor_report(struct dot11k_beacon_measurement_report * beacon_report)
{
    int len = 0;
    unsigned char subelement_len;
    unsigned char subelement_id;
    unsigned char element_len;
    unsigned char element_id;    
    unsigned char cap_info;
    int i;

    for(i = 0 ; i < dot11k_neighbor_num; i++)
    {
        if(0 == memcmp(dot11k_neighbor_list[i].bssid, beacon_report->info.bssid, MACADDRLEN)) {
            break;
        }
    }

    if(i == dot11k_neighbor_num && dot11k_neighbor_num == MAX_NEIGHBOR_NUM) { /* not found , and full*/
        return 1;
    }

    dot11k_neighbor_num++;

    memcpy(dot11k_neighbor_list[i].bssid, beacon_report->info.bssid, MACADDRLEN);
    dot11k_neighbor_list[i].bssinfo.value = DEFAULT_BSSINFO_VALUE;
    dot11k_neighbor_list[i].channel = beacon_report->info.channel;
    dot11k_neighbor_list[i].op_class = beacon_report->info.op_class;
    dot11k_neighbor_list[i].phytype = 0;

    /* parsing sub element*/
    while(len + 2 <= beacon_report->subelements_len)
    {
        subelement_id = beacon_report->subelements[len];
        subelement_len = beacon_report->subelements[len + 1];
    
        if(len + 2 + subelement_len > beacon_report->subelements_len)
        {
            break;
        }
    
        if(subelement_id == _FRAME_BODY_SUBIE_)
        {
    
            if(len + 14 > beacon_report->subelements_len)
            {
                break;
            }

            /* parsing fixed-length field*/
            /*capability byte 1*/
            cap_info = beacon_report->subelements[len + 13];
            if(cap_info & 0x01) { /*Specture mgmt*/
                dot11k_neighbor_list[i].bssinfo.field.cap_spectrum = 1;
            }
            if(cap_info & 0x02) { /*Qos*/
                dot11k_neighbor_list[i].bssinfo.field.cap_qos = 1;
            }
            if(cap_info & 0x08) { /*APSD*/
                dot11k_neighbor_list[i].bssinfo.field.cap_apsd = 1;
            }
            if(cap_info & 0x10) { /*Radio Measurement*/
                dot11k_neighbor_list[i].bssinfo.field.cap_rm = 1;
            }            
            if(cap_info & 0x40) { /*Delayed Block Ack*/
                dot11k_neighbor_list[i].bssinfo.field.cap_delay_ba = 1;
            }  
            if(cap_info & 0x80) { /*Immediate  Block Ack*/
                dot11k_neighbor_list[i].bssinfo.field.cap_im_ba = 1;
            }  
    
   
            len += 14; // id + len + fixed-length field
    
    
            while(len + 2 <= beacon_report->subelements_len)
            {
                element_id = beacon_report->subelements[len];
                element_len = beacon_report->subelements[len + 1];
    
                if(len + 2 + element_len > beacon_report->subelements_len)
                {
                    break;
                }
                
                /*get MDE ie, check the content is same as our AP*/ 
                if(element_id == _MOBILITY_DOMAIN_IE_ && iface_ft_enable) {                     
                    if(memcmp(iface_mdid, &beacon_report->subelements[len + 2], 3) == 0)
                        dot11k_neighbor_list[i].bssinfo.field.mde = 1;
                }
                else if(element_id == _HT_CAP_) {
                    if(memcmp(iface_htcap, &beacon_report->subelements[len + 2], 26) == 0) /*get HT CAP ie, check the content is same as our AP*/
                        dot11k_neighbor_list[i].bssinfo.field.high_tp = 1;
                }
                len += 2 + element_len;                    
            }
        }
        else if(subelement_id == _VENDOR_SPEC_IE_)
        {
            len += 2 + subelement_len;
        }
        else
        {
            break;
        }
    }

    return 0;

}

static int get_beacon_measurement_report(char *ifname, unsigned char * macaddr,
        MEASUREMENT_RESULT* measure_result, int * bss_num,
        struct dot11k_beacon_measurement_report** beacon_report)
{
    int sock;
    struct iwreq wrq;
    int ret = -1;
    int err;


    /*** Inizializzazione socket ***/
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        err = errno;
        printf("[%s %d]: Can't create socket for ioctl. %s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    memcpy(tempbuf, macaddr, MACADDRLEN);
    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)tempbuf;
    wrq.u.data.length = MACADDRLEN;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KBEACONREP, &wrq) < 0)
    {
        err = errno;
        printf("[%s %d]: ioctl Error.%s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }

    ret = 0;
    *measure_result = *(unsigned char *)wrq.u.data.pointer;
    if(*measure_result == MEASUREMENT_SUCCEED)
    {
        *bss_num = *((unsigned char *)wrq.u.data.pointer + 1);
        if(*bss_num)
        {
            *beacon_report = (struct dot11k_beacon_measurement_report*) malloc(*bss_num * sizeof(struct dot11k_beacon_measurement_report));
            if(*beacon_report)
            {
                memcpy(*beacon_report, (unsigned char *)wrq.u.data.pointer + 2, wrq.u.data.length - 2);
            }
            else
                ret = -1;
        }
    }
out:
    close(sock);
    return ret;

}

void TimerFunc()
{
    struct dot11k_beacon_measurement_req beacon_req;
    int bss_num = 0;
    struct dot11k_beacon_measurement_report *beacon_report = NULL;
    int i,j;
    int finish;
    char cmdbuf[100];

    DOT11K_DEBUG("DOT11K deamon(%d) wakeup\n", getpid());

    alarm(TIMER_INTERVAL);


    getWlStaInfo(iface_name);
    if(strlen(iface_name2))
        getWlStaInfo(iface_name2);

    for(i = 0; i < MAX_STA_NUM; i++)
    {
        if(dot11k_sta[i].valid == 2)
            dot11k_sta[i].valid = 1;
        else
            dot11k_sta[i].valid = 0;
    }


    /* issue beacon req*/
    for(i = 0; i < MAX_STA_NUM; i++)
    {
        if(dot11k_sta[i].valid && (dot11k_sta[i].rm_cap[0] & 0x10))  /*client support passive scan*/
        {
            memset(&beacon_req, 0, sizeof(struct dot11k_beacon_measurement_req));
            if(dot11k_sta[i].channel < 14)
            {
                beacon_req.op_class = 81;
            }
            else
            {
                beacon_req.op_class = global_op_class[dot11k_sta[i].last_scan_idx];
                dot11k_sta[i].last_scan_idx ++;
                dot11k_sta[i].last_scan_idx %= sizeof(global_op_class);
            }


            beacon_req.channel = 0;
            beacon_req.random_interval = DEFAULT_RANDOM_INTERVAL;
            beacon_req.measure_duration = DEFAULT_MEASURE_DURATION;
            beacon_req.mode = BEACON_MODE_ACTIVE;
            strcpy(beacon_req.ssid, iface_ssid);
            beacon_req.report_detail = 1;
            beacon_req.request_ie_len = sizeof(request_ie);
            memcpy(beacon_req.request_ie, request_ie, beacon_req.request_ie_len);


            DOT11K_DEBUG("[issue_beacon_measurement] to %02x%02x%02x%02x%02x%02x (%s) op_class: %d\n",
                         dot11k_sta[i].hwaddr[0], dot11k_sta[i].hwaddr[1],dot11k_sta[i].hwaddr[2],
                         dot11k_sta[i].hwaddr[3],dot11k_sta[i].hwaddr[4], dot11k_sta[i].hwaddr[5],
                         dot11k_sta[i].iface,
                         beacon_req.op_class);
            if(issue_beacon_measurement(dot11k_sta[i].iface, dot11k_sta[i].hwaddr, &beacon_req) == 0)
            {
                dot11k_sta[i].result = MEASUREMENT_PROCESSING;
            }
            else
            {
                dot11k_sta[i].result = MEASUREMENT_UNKNOWN;
            }

        }
    }


    dot11k_neighbor_num = 0;

    /* get beacon report*/
    for(j = 0; j < BEACON_MEASURE_TIME; j++)
    {
        finish = 1;
        for(i = 0; i < MAX_STA_NUM; i++)
        {
            if(dot11k_sta[i].valid && (dot11k_sta[i].rm_cap[0] & 0x10))
            {
                if(dot11k_sta[i].result == MEASUREMENT_PROCESSING)
                {

                    if(0 == get_beacon_measurement_report(dot11k_sta[i].iface, dot11k_sta[i].hwaddr, &dot11k_sta[i].result, &bss_num, &beacon_report))
                    {
                        if(dot11k_sta[i].result == MEASUREMENT_PROCESSING)
                        {
                            finish = 0;
                        }
                        else if(dot11k_sta[i].result == MEASUREMENT_SUCCEED)
                        {
                            DOT11K_DEBUG("[get report] from %02x%02x%02x%02x%02x%02x Collect %d BSS\n", dot11k_sta[i].hwaddr[0], dot11k_sta[i].hwaddr[1],
                                         dot11k_sta[i].hwaddr[2],dot11k_sta[i].hwaddr[3],dot11k_sta[i].hwaddr[4],dot11k_sta[i].hwaddr[5],
                                         bss_num);

                            for(i = 0; i < bss_num; i++)
                            {
                                if(debug_mode)
                                    print_bss_info(beacon_report, i);
                                colloect_neighbor_report(beacon_report + i);  
                            }

                            if(beacon_report)
                                free(beacon_report);

                        }
                        else if(dot11k_sta[i].result == MEASUREMENT_INCAPABLE)
                        {
                            DOT11K_DEBUG("Request Incapable\n");
                        }
                        else if(dot11k_sta[i].result == MEASUREMENT_REFUSED)
                        {
                            DOT11K_DEBUG("Request is refused\n");
                        }
                        else
                        {
                            DOT11K_DEBUG("Request is timeout\n");
                        }
                    }
                }
            }

        }
        if(finish)
            break;
        else
            sleep(1);
    }


    /*write neighbor report to driver*/
    for(i = 0; i < dot11k_neighbor_num; i++)
    {
        sprintf((char *)tempbuf, "echo add %02x%02x%02x%02x%02x%02x 0x%04X %d %d %d %s",
                dot11k_neighbor_list[i].bssid[0], dot11k_neighbor_list[i].bssid[1],
                dot11k_neighbor_list[i].bssid[2], dot11k_neighbor_list[i].bssid[3],
                dot11k_neighbor_list[i].bssid[4], dot11k_neighbor_list[i].bssid[5],
                dot11k_neighbor_list[i].bssinfo.value,
                dot11k_neighbor_list[i].op_class,
                dot11k_neighbor_list[i].channel,
                dot11k_neighbor_list[i].phytype,
                iface_ssid);

        sprintf(cmdbuf, "%s > "NEIGHBOR_REPORT_PATH, (char *)tempbuf, iface_name);
        system(cmdbuf);

        DOT11K_DEBUG("Add neighbor report:::: %s\n", cmdbuf);

        if(strlen(iface_name2))
        {
            sprintf(cmdbuf, "%s > "NEIGHBOR_REPORT_PATH, (char *)tempbuf, iface_name2);
            system(cmdbuf);

            DOT11K_DEBUG("Add neighbor report:::: %s\n", cmdbuf);
        }
    }

}


int main(int argc, char *argv[])
{
    int c;
    int pid_fd;
    FILE *fp;
    char line[20], pid_file_name[100];
    pid_t pid;
    unsigned int mib_value;
    unsigned char mib_char;
    int i;

    while ((c = getopt (argc, argv, "i:t:d")) != -1)
    {
        switch (c)
        {
            case 'i':
                if(strlen(iface_name) == 0)
                {
                    sprintf(iface_name, "%s", optarg);
                }
                else if(strlen(iface_name2) == 0)
                {
                    sprintf(iface_name2, "%s", optarg);
                }
                break;
            case 'd':
                debug_mode = 1;
                DOT11K_DEBUG("enable debug mode\n");
                break;
            default:
                abort();
        }
    }

    if(strlen(iface_name) == 0)
    {
        printf("[%s %d]dot11k error! : no interface", __FUNCTION__, __LINE__);
        return -1;

    }

    wlioctl_get_mib(iface_name, "rm_activated", &mib_char, 1);
    if(mib_char == 0) {
        printf("[%s %d]dot11k error! : %s rm_activated not enabled", __FUNCTION__, __LINE__, iface_name);
        return -1;
    }

    wlioctl_get_mib(iface_name, "rm_neighbor_report", &mib_char, 1);
    if(mib_char == 0) {
        printf("[%s %d]dot11k error! : %s rm_neighbor_reportnot enabled", __FUNCTION__, __LINE__, iface_name);
        return -1;
    }

    wlioctl_get_mib(iface_name, "rm_beacon_passive", &mib_char, 1);
    if(mib_char == 0) {
        printf("[%s %d]dot11k error! : %s rm_beacon_passive enabled", __FUNCTION__, __LINE__, iface_name);
        return -1;
    }    

    wlioctl_get_mib(iface_name, "rm_beacon_active", &mib_char, 1);
    if(mib_char == 0) {
        printf("[%s %d]dot11k error! : %s rm_beacon_active enabled", __FUNCTION__, __LINE__, iface_name);
        return -1;
    }  


    if(strlen(iface_name2))
    {
        wlioctl_get_mib(iface_name2, "rm_activated", &mib_char, 1);
        if(mib_char == 0) {
            printf("[%s %d]dot11k error! : %s rm_activated not enabled", __FUNCTION__, __LINE__, iface_name2);
            return -1;
        }
        
        wlioctl_get_mib(iface_name2, "rm_neighbor_report", &mib_char, 1);
        if(mib_char == 0) {
            printf("[%s %d]dot11k error! : %s rm_neighbor_reportnot enabled", __FUNCTION__, __LINE__, iface_name2);
            return -1;
        }
        
        wlioctl_get_mib(iface_name2, "rm_beacon_passive", &mib_char, 1);
        if(mib_char == 0) {
            printf("[%s %d]dot11k error! : %s rm_beacon_passive enabled", __FUNCTION__, __LINE__, iface_name2);
            return -1;
        }    
        
        wlioctl_get_mib(iface_name2, "rm_beacon_active", &mib_char, 1);
        if(mib_char == 0) {
            printf("[%s %d]dot11k error! : %s rm_beacon_active enabled", __FUNCTION__, __LINE__, iface_name2);
            return -1;
        }  
    }

    memset(dot11k_sta, 0, sizeof(dot11k_sta));
    if(strlen(iface_name2)) {
        sprintf(pid_file_name,"/var/run/dot11k-%s-%s.pid", iface_name, iface_name2);
    }
    else {        
        sprintf(pid_file_name,"/var/run/dot11k-%s.pid", iface_name);       
    }
    
    if ((fp = fopen(pid_file_name, "r")) != NULL)
    {
        fgets(line, sizeof(line), fp);
        if (sscanf(line, "%d", &pid))
        {
            if (pid > 1)
                kill(pid, SIGTERM);
        }
        fclose(fp);
    }
    pid_fd = pidfile_acquire(pid_file_name);
    if (pid_fd < 0)
        return 0;

    if (daemon(0,1) == -1)
    {
        printf("[%s %d]fork dot11k deamon error!\n", __FUNCTION__, __LINE__);
        exit(1);
    }
    pidfile_write_release(pid_fd);
    wlioctl_get_mib(iface_name, "ssid", iface_ssid, 0);

    wlioctl_get_mib(iface_name, "ft_enable", &iface_ft_enable, 4);
    if(iface_ft_enable) {    
        wlioctl_get_mib(iface_name, "ft_mdid", iface_mdid, 2);
        wlioctl_get_mib(iface_name, "ft_over_ds", &mib_value, 4);
        if(mib_value)
            iface_mdid[2] |= 0x01;
        wlioctl_get_mib(iface_name, "ft_res_request", &mib_value, 4);
        if(mib_value)
            iface_mdid[2] |= 0x02;
    }
    getWlHtCap(iface_name, iface_htcap);    

    DOT11K_DEBUG("DOT11K deamon(%d) start: iface_name: %s, iface_name2: %s\n\tssid:%s, mdid: %02X%02X%02X\n",
                 getpid(), iface_name, iface_name2, iface_ssid, iface_mdid[0], iface_mdid[1], iface_mdid[2]);
    DOT11K_DEBUG("\tht_cap: ");
    for(i = 0; i < 26; i++) {
        DOT11K_DEBUG("%02x", iface_htcap[i]);
    }
    DOT11K_DEBUG("\n");

    


    signal(SIGALRM, TimerFunc);
    alarm(1);

    while(1)
    {
        sleep(5);
    }

}




