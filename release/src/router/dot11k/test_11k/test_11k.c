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

#define MACADDRLEN					6
#define MAX_SSID_LEN			    32
#define MAX_BEACON_SUBLEMENT_LEN           226
#define MAX_REQUEST_IE_LEN          16
#define MAX_AP_CHANNEL_REPORT       4
#define MAX_AP_CHANNEL_NUM          8


#define DEFAULT_RANDOM_INTERVAL  20
#define DEFAULT_MEASURE_DURATION 100

#define BEACON_MEASURE_TIME 13

#define SIOC11KLINKREQ 0x8BD0
#define SIOC11KLINKREP 0x8BD1
#define SIOC11KBEACONREQ 0x8BD2
#define SIOC11KBEACONREP 0x8BD3
#define SIOC11KNEIGHBORREQ 0x8BD4
#define SIOC11KNEIGHBORRSP 0x8BD5

#define DEFAULT_AP_REPORT_FILE "/proc/%s/rm_ap_channel_report"


typedef enum {
    MEASUREMENT_UNKNOWN = 0,
    MEASUREMENT_PROCESSING = 1,
    MEASUREMENT_SUCCEED = 2,
    MEASUREMENT_INCAPABLE = 3,
    MEASUREMENT_REFUSED = 4,   
}MEASUREMENT_RESULT;


typedef enum {
    BEACON_MODE_PASSIVE = 0,
    BEACON_MODE_ACTIVE = 1,   
    BEACON_MODE_TABLE = 2,   
}BEACON_MODE;


#pragma pack(1)
struct dot11k_link_measurement
{
    unsigned char tpc_tx_power;
    unsigned char tpc_link_margin;
    unsigned char recv_antenna_id;
    unsigned char xmit_antenna_id;
    unsigned char RCPI;
    unsigned char RSNI;
};

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

union dot11k_neighbor_report_bssinfo {
    unsigned int value;
    struct {
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


/* Commands */

typedef enum
{
    NO_CMD,
    LINK_CMD,
    BEACON_CMD,
    NEIGHBOR_CMD,    
    /*----*/
    CMD_NUM
} cmd_type_t;

typedef struct
{
    cmd_type_t id;
    const char *name;
    const char *description;
    int show_flag;
} cmd_t;


cmd_t CMDs[] =
{
    {NO_CMD, 				""      ,	"", 					0},
    {LINK_CMD,				"link" , 	"link measurement", 1},
    {BEACON_CMD,            "beacon" ,  "beacon measurement: [-o operating_class] [-n channel_number] [-m mode] [-b BSSID] [-s SSID] [-r report_detail]"\
           "\n\tOPTION"\
           "\n\t  -o"\
           "\n\t     set operating class"\
           "\n\t       Operating classes in United States"\
           "\n\t         1: 5g channel 36, 40, 44, 48"\
           "\n\t         2: 5g channel 52, 56, 60, 64"\
           "\n\t         3: 5g channel 149, 153, 157, 161"\
           "\n\t         4: 5g channel 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140"\
           "\n\t         5: 5g channel 149, 153, 157, 161, 165"\
           "\n\t         12: 2g channel 1~11"\
           "\n\t       Operating classes in Europe"\
           "\n\t         1: 5g channel 36, 40, 44, 48"\
           "\n\t         2: 5g channel 52, 56, 60, 64"\
           "\n\t         3: 5g channel 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140"\
           "\n\t         4: 2g channel 1~13,"\
           "\n\t         17: 5g channel 149, 153, 157, 161, 165, 169"\
           "\n\t       Operating classes in Japan"\
           "\n\t         1: 5g channel 36, 40, 44, 48"\
           "\n\t         30: 2g channel 1~13"\
           "\n\t         32: 5g channel 52, 56, 60, 64"\
           "\n\t         33: 5g channel 52, 56, 60, 64"\
           "\n\t         34: 5g channel 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140"\
           "\n\t         35: 5g channel 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140"\
           "\n\t       Global Operating classes"\
           "\n\t         81: 2g channel 1~13"\
           "\n\t         115(default): 5g channel 36, 40, 44, 48"\
           "\n\t         118: 5g channel 52, 56, 60, 64"\
           "\n\t         121: 5g channel 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140"\
           "\n\t         124: 5g channel 149, 153, 157, 161,"\
           "\n\t         125: 5g channel 149, 153, 157, 161, 165, 169" \
           "\n\t  -n"\
           "\n\t     set beacon measurement channel,"\
           "\n\t     0(default): for iterative measuring all supported channel in the operating class"\
           "\n\t      in the operating class"\
           "\n\t     255: for iterative measuring all supported channel liseted in the AP Channel Report"\
           "\n\t     other: the channel number for which the measuremnet request applies"\
           "\n\t  -m"\
           "\n\t     set beacon measurement mode,"\
           "\n\t     0(default): passive mode,"\
           "\n\t     1: active mode"\
           "\n\t     2: table mode"\
           "\n\t  -b"\
           "\n\t     set BSSID for whitch a beacon report is requested, "\
           "\n\t     the default is wildcard BSSID for all BSSs"\
           "\n\t  -s"\
           "\n\t     set SSID for whitch a beacon report is requested, "\
           "\n\t     the default is wildcard SSID that represent all possible SSID"\
           "\n\t  -r"\
           "\n\t     set report detail, "\
           "\n\t     0: no-fixed len field and element,"\
           "\n\t     1: all fixed len field and elements in Request ie,"\
           "\n\t     2(default): all fixed len field and elements", 1},
    {NEIGHBOR_CMD, "neighbor" ,    "get neighbor report [-s SSID]", 1},              
};


unsigned char tempbuf[16384];
unsigned char request_ie[] = {0, 48, 54, 70, 221};

static void print_bss_info(struct dot11k_beacon_measurement_report * beacon_report, int index) {
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
    for(i = 0;i <beacon_report->subelements_len;i++) {
        if(i % 16 == 0)
            printf("\n\t\t");
        printf(" %02X", beacon_report->subelements[i]);
    }
    printf("\n");       
}

static void print_neighbor_info(struct dot11k_neighbor_report * neighbor_report, int index) {
    neighbor_report += index;
    printf("\t[%d]BSSID: %02x%02x%02x%02x%02x%02x\n", index + 1, 
        neighbor_report->bssid[0], neighbor_report->bssid[1], neighbor_report->bssid[2],
        neighbor_report->bssid[3], neighbor_report->bssid[4], neighbor_report->bssid[5]);
    printf("\t\tbss info: 0x%04X\n", neighbor_report->bssinfo.value);
    printf("\t\toperating class: %d\n", neighbor_report->op_class);
    printf("\t\tchannel: %d\n", neighbor_report->channel);
    printf("\t\tphytype: %d\n", neighbor_report->phytype);    
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
        printf("%s(%s): Can't create socket for ioctl.(%d)", __FUNCTION__, ifname, err);
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
        printf("%s(%s): ioctl Error.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    err = 0;

out:
    close(sock);
    return err;
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
        printf("%s(%s): Can't create socket for ioctl.(%d)", __FUNCTION__, ifname, err);
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
        printf("%s(%s): ioctl Error.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    
    ret = 0;
    *measure_result = *(unsigned char *)wrq.u.data.pointer;
    if(*measure_result == MEASUREMENT_SUCCEED) {        
        *bss_num = *((unsigned char *)wrq.u.data.pointer + 1);
        if(*bss_num) {
            *beacon_report = (struct dot11k_beacon_measurement_report*) malloc(*bss_num * sizeof(struct dot11k_beacon_measurement_report));
            if(*beacon_report) {
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

static void do_beacon_measurement(char *ifname, char * macaddr_str, unsigned char op_class,unsigned char channel, unsigned char mode,
                           char * bssid_str, char * ssid_str, unsigned char report_detail)
{
    struct dot11k_beacon_measurement_req beacon_req;
    struct dot11k_beacon_measurement_report *beacon_report = NULL;
    int ret = -1;
    int i = 0, j;
    unsigned char macaddr[MACADDRLEN];
    MEASUREMENT_RESULT measure_result;
    int bss_num = 0;
	FILE *fp;
    char ap_report_filename[50], ap_report_line[100];
    char * strptr;
    
    for(i=0; i<MACADDRLEN; i++)
    {
        tempbuf[0] = macaddr_str[2*i];
        tempbuf[1] = macaddr_str[2*i+1];
        tempbuf[2] = 0;      
        
        macaddr[i] = strtol((char *)tempbuf, NULL, 16);
    }

    
    memset(&beacon_req, 0, sizeof(struct dot11k_beacon_measurement_req));     
    beacon_req.op_class = op_class; 
    beacon_req.channel = channel;
    beacon_req.random_interval = DEFAULT_RANDOM_INTERVAL;    
    beacon_req.measure_duration = DEFAULT_MEASURE_DURATION;       
    beacon_req.mode = mode;

    if(channel == 255) {
        i = 0;
        sprintf(ap_report_filename, DEFAULT_AP_REPORT_FILE, ifname);
    	fp = fopen(ap_report_filename, "r");
    	if (!fp) {
    		printf("Read %s failed!\n", ap_report_filename);
            return;
    	}
        while (fgets(ap_report_line, sizeof(ap_report_line), fp))
        {
            if((strptr = strstr(ap_report_line,"Operating Class")) != 0) {
                strptr += 15;
                while(*strptr == ' ' || *strptr == ':')
                    strptr++;  
                beacon_req.ap_channel_report[i].op_class = strtol(strptr, NULL, 10);
                if(fgets(ap_report_line, sizeof(ap_report_line), fp)) {
                    if((strptr = strstr(ap_report_line,"Channel List")) != 0){
                        strptr += 12;
                        while(*strptr == ' ' || *strptr == ':')
                            strptr++;  
                        j = 0;
                        while(*strptr) {                         
                            beacon_req.ap_channel_report[i].channel[j] = strtol(strptr, NULL, 10);                        
                            j++;
                            if(j >= MAX_AP_CHANNEL_NUM)
                                break;
                            
                            while(*strptr && *strptr != ' ' )
                                strptr++;    
                            while(*strptr && (*strptr == ' ' || *strptr == '\n') )
                                strptr++;                         
                        }
                        beacon_req.ap_channel_report[i].len = j+1;
                        i++;
                        if(i >= MAX_AP_CHANNEL_REPORT)
                            break;
                    
                    }    
                }
            }
          
        }   
        fclose(fp);
    }

    if(bssid_str) {
    	for(i=0; i<MACADDRLEN; i++)
    	{
    		tempbuf[0] = bssid_str[2*i];
    		tempbuf[1] = bssid_str[2*i+1];
    		tempbuf[2] = 0;            
    		beacon_req.bssid[i] = strtol((char *)tempbuf, NULL, 16);
    	}
    }

    if(ssid_str) {    
        strcpy(beacon_req.ssid, ssid_str);
    }

    beacon_req.report_detail = report_detail;
    if(report_detail == 1) {
        beacon_req.request_ie_len = sizeof(request_ie);
        memcpy(beacon_req.request_ie, request_ie, beacon_req.request_ie_len);
    }
    

    i = 0;
    if(0 == issue_beacon_measurement(ifname, macaddr, &beacon_req))
    {
        /*succeed*/
        do
        {
            i++;
            sleep(1);
            ret = get_beacon_measurement_report(ifname, macaddr, &measure_result, &bss_num, &beacon_report);
        }
        while(ret == 0 && i < BEACON_MEASURE_TIME && measure_result == MEASUREMENT_PROCESSING);
    }

    
    if(ret < 0) {
        printf("Request fail!\n");
    }    
    else if(measure_result == MEASUREMENT_SUCCEED) {        
        printf("Colloect %d BSS\n", bss_num);
        printf("-- BSS INFO ---\n");
        for(i = 0; i < bss_num; i++) {
            print_bss_info(beacon_report, i);
        }
    }
    else if(measure_result == MEASUREMENT_INCAPABLE) {
        printf("Request Incapable\n");
    }
    else if(measure_result == MEASUREMENT_REFUSED) {
        printf("Request is refused\n");
    }  
    else {
        printf("Request is timeout\n");
    }
    

    if(beacon_report)
        free(beacon_report);    
}

static int issue_link_measurement(char *ifname, unsigned char * macaddr)
{
    int sock;
    struct iwreq wrq;
    int err;

    /*** Inizializzazione socket ***/
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        err = errno;
        printf("%s(%s): Can't create socket for ioctl.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    memcpy(tempbuf, macaddr, MACADDRLEN);

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)tempbuf;
    wrq.u.data.length = MACADDRLEN;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KLINKREQ, &wrq) < 0)
    {
        err = errno;
        printf("%s(%s): ioctl Error.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    err = 0;

out:
    close(sock);
    return err;
}


static int get_link_measurement_report(char *ifname, unsigned char * macaddr, 
    MEASUREMENT_RESULT* measure_result, struct dot11k_link_measurement * link_report)
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
        printf("%s(%s): Can't create socket for ioctl.(%d)", __FUNCTION__, ifname, err);
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
    if(ioctl(sock, SIOC11KLINKREP, &wrq) < 0)
    {
        err = errno;
        printf("%s(%s): ioctl Error.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }

    ret = 0;
    *measure_result = *(unsigned char *)wrq.u.data.pointer;
    if(*measure_result == MEASUREMENT_SUCCEED) {
        memcpy(link_report, wrq.u.data.pointer + 1, sizeof(struct dot11k_link_measurement));
    }
out:
    close(sock);
    return ret;
}


static void do_link_measurement(char *ifname, char * macaddr_str)
{
    struct dot11k_link_measurement link_report;
    int ret = 0;
    int i;
    unsigned char macaddr[MACADDRLEN];
    MEASUREMENT_RESULT measure_result = MEASUREMENT_UNKNOWN;

    memset(&link_report, 0x00, sizeof(struct dot11k_link_measurement));
    for(i=0; i<MACADDRLEN; i++)
    {
        tempbuf[0] = macaddr_str[2*i];
        tempbuf[1] = macaddr_str[2*i+1];
        tempbuf[2] = 0;
        macaddr[i] = strtol((char *)tempbuf, NULL, 16);
    }


    i = 0;
    if(0 == issue_link_measurement(ifname, macaddr))
    {
        /*succeed*/
        do
        {
            i++;
            sleep(1);
            ret = get_link_measurement_report(ifname, macaddr, &measure_result, &link_report);
        }
        while(ret == 0 && i < 3 && measure_result == MEASUREMENT_PROCESSING);
    }

    if(ret < 0) {
        printf("Request fail!\n");
    } 
    else if(measure_result == MEASUREMENT_SUCCEED)
    {
        printf("tpc_tx_power: %d\n", link_report.tpc_tx_power);
        printf("tpc_link_margin: %d\n", link_report.tpc_link_margin);
        printf("recv_antenna_id: %d\n", link_report.recv_antenna_id);
        printf("xmit_antenna_id: %d\n", link_report.xmit_antenna_id);
        printf("RCPI: 0x%02X\n", link_report.RCPI);
        printf("RSNI: 0x%02X\n", link_report.RSNI);
    }
    else {
        printf("Request timeout!\n");
    }
}


static int issue_neighbor_request(char *ifname,  char * ssid_str)
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
        printf("%s(%s): Can't create socket for ioctl.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    if(ssid_str) {    
        strcpy((char*)tempbuf, ssid_str);
        len = strlen(ssid_str);
    }

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)tempbuf;
    wrq.u.data.length = len;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KNEIGHBORREQ, &wrq) < 0)
    {
        err = errno;
        printf("%s(%s): ioctl Error.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    err = 0;

out:
    close(sock);
    return err;
}

static int get_neighbor_report(char *ifname, MEASUREMENT_RESULT* measure_result, int * bss_num,
    struct dot11k_neighbor_report** neighbor_report)
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
        printf("%s(%s): Can't create socket for ioctl.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }

    /*** Inizializzazione struttura iwreq ***/
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)tempbuf;
    wrq.u.data.length = 0;

    /*** ioctl ***/
    if(ioctl(sock, SIOC11KNEIGHBORRSP, &wrq) < 0)
    {
        err = errno;
        printf("%s(%s): ioctl Error.(%d)", __FUNCTION__, ifname, err);
        goto out;
    }
    
    ret = 0;
    *measure_result = *(unsigned char *)wrq.u.data.pointer;
    if(*measure_result == MEASUREMENT_SUCCEED) {        
        *bss_num = *((unsigned char *)wrq.u.data.pointer + 1);
        if(*bss_num) {
            *neighbor_report = (struct dot11k_neighbor_report*) malloc(*bss_num * sizeof(struct dot11k_neighbor_report));
            if(*neighbor_report) {
                memcpy(*neighbor_report, (unsigned char *)wrq.u.data.pointer + 2, wrq.u.data.length - 2);
            }
            else
                ret = -1;
        }
    }
out:
    close(sock);
    return ret;

}

static void do_neighbor_report(char *ifname, char *ssid_str)
{
    int ret = -1;
    int i;
    MEASUREMENT_RESULT measure_result = MEASUREMENT_UNKNOWN;
    struct dot11k_neighbor_report *neighbor_report = NULL;
    int bss_num = 0;


    i = 0;
    if(0 == issue_neighbor_request(ifname, ssid_str))
    {
        /*succeed*/
        do
        {
            i++;
            sleep(1);
            ret = get_neighbor_report(ifname, &measure_result, &bss_num, &neighbor_report);
        }
        while(ret == 0 && i < 3 && measure_result == MEASUREMENT_PROCESSING);
    }

    if(ret < 0) {
        printf("Request fail!\n");
    } 
    else if(measure_result == MEASUREMENT_SUCCEED)
    {
        printf("NEIGHBOR AP NUM: %d\n", bss_num);
        printf("-- NEIGHBOR AP INFO ---\n");
        for(i = 0; i < bss_num; i++) {
            print_neighbor_info(neighbor_report, i);
        }

    }
    else {
        printf("Request timeout!\n");
    }
    if(neighbor_report)
        free(neighbor_report);       
}


int get_cmd_id(char *cmd)
{
    int i;
    for (i = 1; i < CMD_NUM; i++)
    {
        if (strcmp(CMDs[i].name, cmd) == 0)
            break;
    }
    if(i < CMD_NUM) {
        return CMDs[i].id;
    }
    else 
        return NO_CMD;
}

void usage(char *name)
{
    int i;
    cmd_t *cmd;

    printf("%s [-c command] [-i interface_name] [-a mac_addr]\n", name);
    printf("\nAvailable commands:\n");

    for (i=0; i<CMD_NUM; i++)
    {
        cmd = &CMDs[i];
        if (cmd->show_flag)
            printf("%s\t: %s\n", cmd->name, cmd->description);
    }
}

int main(int argc, char *argv[])
{
    cmd_type_t cmd_id;
    char *command = NULL, *mac_str = NULL;
    char * interface_name = NULL;
    int c;
    unsigned char channel = 0, mode = 0, op_class = 115;
    char *bssid_str = NULL, *ssid_str = NULL;
    unsigned char report_detail = 2;
    
    /* Parse options */
    while ((c = getopt (argc, argv, "hc:a:i:o:n:m:b:s:r:")) != -1)
    {
        switch (c)
        {
            case 'c':
                command = optarg;
                break;
            case 'i':
                interface_name = optarg;
                break;
            case 'a':
                mac_str = optarg;
                break;
            case 'o':
                op_class = atoi(optarg);
                break;
            case 'n':
                channel = atoi(optarg);
                break;
            case 'm':
                mode = atoi(optarg);
                break;
            case 'b':
                bssid_str = optarg;
                break;
            case 's':
                ssid_str = optarg;
                break;
            case 'r':
                report_detail = atoi(optarg);
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                usage(argv[0]);
                abort();

        }
    }
    /* Check arguments */
    if (command == NULL || interface_name == NULL)
    {
        usage(argv[0]);
        exit(0);
    }

    if ((cmd_id = get_cmd_id(command)) == NO_CMD)
    {
        usage(argv[0]);
        exit(0);
    }

    if(cmd_id != NEIGHBOR_CMD) {
        if(mac_str == NULL) {
            usage(argv[0]);
            exit(0);
        }
    }

    /* Execute command */
    switch(cmd_id)
    {
        case LINK_CMD:
            do_link_measurement(interface_name, mac_str);
            break;
        case BEACON_CMD:
            do_beacon_measurement(interface_name, mac_str, op_class, channel, mode, bssid_str, ssid_str, report_detail);
            break;
        case NEIGHBOR_CMD:
            do_neighbor_report(interface_name, ssid_str);            
            break;
        default:
            break;
    }

    exit(0);
}
