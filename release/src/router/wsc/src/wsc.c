/*
 *  Main module for WiFi Simple-Config Daemon
 *
 *	Copyright (C)2006, Realtek Semiconductor Corp. All rights reserved.
 *
 *	$Id: wsc.c,v 1.60 2010/08/11 04:56:26 brian Exp $
 */

/*================================================================*/
/* Include Files */
#ifdef __ECOS
#include <network.h>
#include <pkgconf/devs_eth_rltk_819x_wlan.h>
#include <sys/socket.h>
#include <net/if_dl.h>
//#include "apmib.h"
#include "mini_upnp_global.h"
//#include "hw_settings.h"
//#include "sys_utility.h"
#include "net_api.h"
#endif
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "wsc.h"
#include "built_time"
#ifdef IKD
//for chage priority
#include "../../include/priority.h"
#endif

#ifdef __ECOS
extern int get_mac_address( const char *interface, char *mac_address );
void wsc_alarm_func(cyg_handle_t alarm_hdl, cyg_addrword_t data);
void wsc_upnp_main(cyg_addrword_t data);
#ifndef HAVE_APMIB
void wsc_flash_param_apply(CTX_Tp pCtx, char *ifname, struct wsc_flash_param *param, int flag);
#endif

CTX_T wsc_context;
#ifndef HAVE_APMIB
extern struct wsc_flash_param tmp_flash_param;
#endif
#endif

/*================================================================*/
/* Local Variables */

static const char rnd_seed[] = "Realtek WiFi Simple-Config Daemon program 2006-05-15";
CTX_Tp pGlobalCtx;

#ifdef OUTPUT_LOG
FILE *outlog_fp=NULL;
unsigned char StringbufferOut[80];
#endif

#ifdef __ECOS
char wscd_config[320];
/*
	"port 52881\r\n"
	"max_age 1800\r\n"
	"uuid uuid:63041253-1019-2006-1228-00e04c8196c1\r\n"
	"root_desc_name simplecfg\r\n"
	"known_service_types upnp:rootdevice\r\n"
	"known_service_types urn:schemas-wifialliance-org:device:WFADevice:\r\n"
	"known_service_types urn:schemas-wifialliance-org:service:WFAWLANConfig:\r\n";
*/
int wscd_state = 0;
unsigned char wscd_stack[24*1024];
cyg_handle_t wscd_thread_handle;
cyg_thread wscd_thread_obj;

unsigned char wsc_upnp_stack[12*1024];
cyg_handle_t wsc_upnp_thread_handle;
cyg_thread wsc_upnp_thread_obj;

cyg_flag_t wsc_flag;
cyg_handle_t wsc_alarm_hdl;
cyg_alarm wsc_alarm;

int wps_start_interface0;	// "/var/wps_start_interface0"
int wps_start_interface1;	// "/var/wps_start_interface1"
int wps_done;			// "/var/wps_done"
int wscd_lock_stat;		// "/tmp/wscd_lock_stat"
#endif

/*================================================================*/
/* Global Variables */

unsigned char WSC_VENDOR_ID[3] = {0x00, 0x37, 0x2a};
unsigned char wsc_prime_num[]={
0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2, 0x21,0x68,0xC2,0x34, 0xC4,0xC6,0x62,0x8B, 0x80,0xDC,0x1C,0xD1,
0x29,0x02,0x4E,0x08, 0x8A,0x67,0xCC,0x74, 0x02,0x0B,0xBE,0xA6, 0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79, 0x8E,0x34,0x04,0xDD,
0xEF,0x95,0x19,0xB3, 0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D, 0xF2,0x5F,0x14,0x37, 0x4F,0xE1,0x35,0x6D, 0x6D,0x51,0xC2,0x45,
0xE4,0x85,0xB5,0x76, 0x62,0x5E,0x7E,0xC6, 0xF4,0x4C,0x42,0xE9, 0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6, 0xF4,0x06,0xB7,0xED,
0xEE,0x38,0x6B,0xFB, 0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11, 0x7C,0x4B,0x1F,0xE6, 0x49,0x28,0x66,0x51, 0xEC,0xE4,0x5B,0x3D,
0xC2,0x00,0x7C,0xB8, 0xA1,0x63,0xBF,0x05, 0x98,0xDA,0x48,0x36, 0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8, 0xFD,0x24,0xCF,0x5F,
0x83,0x65,0x5D,0x23, 0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56, 0x20,0x85,0x52,0xBB, 0x9E,0xD5,0x29,0x07, 0x70,0x96,0x96,0x6D,
0x67,0x0C,0x35,0x4E, 0x4A,0xBC,0x98,0x04, 0xF1,0x74,0x6C,0x08, 0xCA,0x23,0x73,0x27, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
};

struct wsc_parms_t wsc_parms_default[12] = {
        {"mode","1"},{"upnp","1"},{"config_method","134"},{"auth_type","1"},
        {"encrypt_type","1"},{"connection_type","1"},{"wsc_manual_config","0"},{"network_key",""},
        {"ssid",""},{"pin_code","89542798"},{"rf_band","1"},{"device_name",""},
};

/*================================================================*/
void process_event(CTX_Tp pCtx, int evt);
static int init_config(CTX_Tp pCtx, int def);

#ifdef __ECOS
int sigHandler_alarm(int signo);
#else
#ifdef WSC_1SEC_TIMER
static int wsc_alarm(void);
static int sigHandler_alarm(int signo);
#else
static void sigHandler_alarm(int signo);
#endif
#endif

int update_ie(CTX_Tp pCtx, unsigned char selected ,int type);
#ifdef FOR_DUAL_BAND
int update_ie2(CTX_Tp pCtx, unsigned char selected , int type);
#endif
static int start_upnp(CTX_Tp pCtx);
/***************************************************************/
//#define PBC_STAT_FILE "/var/pbc_stat"
//#define PBC_STAT_LOCK_FILE "/var/pbc_btn_flock"
#ifdef WPS_FOR_ASUS
char pbc_state_file[128];
char pbc_state_lock_file[128];
char wscd_cancel_file[128];
int file_lock(int fd)
{
	int ret;
	struct flock lock;
	lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_whence = SEEK_SET;
try_again:
	ret = fcntl(fd,F_SETLKW,&lock);
	if(ret == -1) {
		if (errno == EINTR) {
			goto try_again;
		}
	}
	return ret;
}
int file_unlock(int fd)
{
	close(fd);
}

int checkPBCBtnStat(void)
{
	FILE* fp;
	struct stat status;
	int fd;
	int res;
	char buffer[6] = {0};
	int pid = -1;
#ifdef FOR_DUAL_BAND
	CTX_Tp pCtx = pGlobalCtx;
	struct stat cancel_status;
#endif
	if(stat(pbc_state_file, &status) < 0) 
	{
		return -1;
	}
	fd = open(pbc_state_lock_file, O_RDWR|O_CREAT|O_TRUNC);
	if(fd < 0)
	{
		return -1;
	}
	res  = file_lock(fd);
	if(res == -1)
	{
		file_unlock(fd);
		return -1;
	}
	fp = fopen(pbc_state_file,"r+");
	if(fp != NULL)
	{
		fscanf(fp,"%d",&pid);
		//WSC_DEBUG("pid:%d\n",pid);
		if(pid == (int)getpid())
		{
			WSC_DEBUG("PBC pressed!!!!!!\n");
			ftruncate(fileno(fp),0);
			fseek(fp,0L,SEEK_SET);
			fprintf(fp,"0");
#ifdef FOR_DUAL_BAND
			/*2011-11 add for support under dual band mode just trigger single interface*/
			pCtx->inter0only  = 0;
			pCtx->inter1only  = 0;
					
			if (stat(WSCD_IND_ONLY_INTERFACE0, &cancel_status) == 0) {
				WSC_DEBUG("%s\n",WSCD_IND_ONLY_INTERFACE0);
				pCtx->inter0only  = 1;
					unlink(WSCD_IND_ONLY_INTERFACE0);
				}
				if (stat(WSCD_IND_ONLY_INTERFACE1, &cancel_status) == 0) {
					WSC_DEBUG("%s\n",WSCD_IND_ONLY_INTERFACE1);
					pCtx->inter1only  = 1;
					unlink(WSCD_IND_ONLY_INTERFACE1);
				}
					
				WSC_DEBUG("inter0only = %d\n",pCtx->inter0only);
				WSC_DEBUG("inter1only = %d\n",pCtx->inter1only);
					
				/*2011-11 add for support under dual band mode just trigger single interface*/
#endif
			WSC_DEBUG("process PBC press event!!!\n");
			process_event(pGlobalCtx, EV_PB_PRESS);

		}
		fclose(fp);
	}
	file_unlock(fd);
}
#endif
/***************************************************************/

/*================================================================*/
/* Implementation Routines */
#ifdef AUTO_LOCK_DOWN
void InOut_auto_lock_down(CTX_Tp pCtx , int enter)
{
	//struct sysinfo info ;
#ifndef	__ECOS
	char tmpbuf[64];
#endif

	if(enter){	// enter lock state

		printf("\n\n	AUTO_LOCK_DOWN(locked)\n");

#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION
		printf("indefinitely auto-lock-down until user intervenes to unlock!!\n" );
#ifdef	__ECOS
		wscd_lock_stat = 1;
#else
		sprintf(tmpbuf, "echo 1 > %s" ,WSCD_LOCK_STAT);
		system(tmpbuf);			
#endif		
#else
		WSC_DEBUG("locked [%d] seconds\n\n",pCtx->auto_lock_down);
#endif					


		/* update beacon and probe-resp content*/
		if (pCtx->is_ap && pCtx->use_ie
			#ifdef FOR_DUAL_BAND
			&& pCtx->wlan0_wsc_disabled==0
			#endif
		){
			update_ie(pCtx,0, 0);
		}

		#ifdef FOR_DUAL_BAND
		if (pCtx->is_ap && pCtx->use_ie && pCtx->wlan1_wsc_disabled==0){
			update_ie2(pCtx,0, 0);
		}
		#endif



		// led blink into error state
		#ifdef	DET_WPS_SPEC
		if (wlioctl_set_led(TURNKEY_LED_LOCK_DOWN) < 0) {
			DEBUG_ERR("fail\n");
		}
		#else	// if is turnkey
		if (wlioctl_set_led(TURNKEY_LED_WSC_NOP) < 0) {
			DEBUG_ERR("fail\n");
		}
		#endif

	}
	else{	// leave lock state

		printf("\n\n	AUTO_LOCK_DOWN(unlocked)\n\n");
		if (wlioctl_set_led(LED_WSC_END) < 0) {
			DEBUG_ERR("fail\n");
		}

		/* update IE in beacon and probe-resp */
		//init_wlan(pCtx , 1);
		if (pCtx->is_ap && pCtx->use_ie
#ifdef FOR_DUAL_BAND
			&& pCtx->wlan0_wsc_disabled==0
#endif
		){
			update_ie(pCtx,0, 0);
		}

		#ifdef FOR_DUAL_BAND
		if (pCtx->is_ap && pCtx->use_ie && pCtx->wlan1_wsc_disabled==0){
			update_ie2(pCtx,0, 0);
		}
		#endif
		
#ifdef	__ECOS
		wscd_lock_stat = 0;
#else		
		/*remove tmp file*/ 		
		unlink(WSCD_LOCK_STAT);
#endif
	}
}

#endif

static void do_bcopy(unsigned char *dst, unsigned char *src, int len)
{
	int i;
	for (i=0; i<len; dst++, src++, i++)
		*dst = *src;
}

void convert_hex_to_ascii(unsigned long code, char *out)
{
	*out++ = '0' + ((code / 10000000) % 10);
	*out++ = '0' + ((code / 1000000) % 10);
	*out++ = '0' + ((code / 100000) % 10);
	*out++ = '0' + ((code / 10000) % 10);
	*out++ = '0' + ((code / 1000) % 10);
	*out++ = '0' + ((code / 100) % 10);
	*out++ = '0' + ((code / 10) % 10);
	*out++ = '0' + ((code / 1) % 10);
	*out = '\0';
}

int compute_pin_checksum(unsigned long int PIN)
{
	unsigned long int accum = 0;
	int digit;

	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10);
	accum += 1 * ((PIN / 1000000) % 10);
	accum += 3 * ((PIN / 100000) % 10);
	accum += 1 * ((PIN / 10000) % 10);
	accum += 3 * ((PIN / 1000) % 10);
	accum += 1 * ((PIN / 100) % 10);
	accum += 3 * ((PIN / 10) % 10);

	digit = (accum % 10);
	return (10 - digit) % 10;
}

#ifndef __ECOS
static int get_mac_addr(int sk, char *interface, unsigned char *addr)
{
	struct ifreq ifr;

	DBFENTER;

	strcpy(ifr.ifr_name, interface);

#ifdef INBAND_WPS_OVER_HOST
	if ( inband_ioctl(SIOCGIFHWADDR, &ifr) < 0) {
#else
	if ( ioctl(sk, SIOCGIFHWADDR, &ifr) < 0) {
#endif	//INBAND_WPS_OVER_HOST
		printf("ioctl(SIOCGIFHWADDR) failed!\n");
		return -1;
	}

	memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

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

	if((out = fdopen(pid_fd, "w")) != NULL) {
		fprintf(out, "%d\n", getpid());
		fclose(out);
	}
	lockf(pid_fd, F_UNLCK, 0);
	close(pid_fd);
}
#endif


unsigned char convert_atob(char *data, int base)
{
	char tmpbuf[10];
	int bin;

	memcpy(tmpbuf, data, 2);
	tmpbuf[2]='\0';
	if (base == 16)
		sscanf(tmpbuf, "%02x", &bin);
	else
		sscanf(tmpbuf, "%02d", &bin);
	return((unsigned char)bin);
}

#ifndef USE_MINI_UPNP
static char *get_token(char *data, char *token)
{
	char *ptr=data;
	int len=0, idx=0;

	while (*ptr && *ptr != '\n' ) {
		if (*ptr == '=') {
			if (len <= 1)
				return NULL;
			memcpy(token, data, len);

			/* delete ending space */
			for (idx=len-1; idx>=0; idx--) {
				if (token[idx] !=  ' ')
					break;
			}
			token[idx+1] = '\0';

			return ptr+1;
		}
		len++;
		ptr++;
	}
	return NULL;
}

static int get_value(char *data, char *value)
{
	char *ptr=data;
	int len=0, idx, i;

	while (*ptr && *ptr != '\n' && *ptr != '\r') {
		len++;
		ptr++;
	}

	/* delete leading space */
	idx = 0;
	while (len-idx > 0) {
		if (data[idx] != ' ')
			break;
		idx++;
	}
	len -= idx;

	/* delete bracing '"' */
	if (data[idx] == '"') {
		for (i=idx+len-1; i>idx; i--) {
			if (data[i] == '"') {
				idx++;
				len = i - idx;
			}
			break;
		}
	}

	if (len > 0) {
		memcpy(value, &data[idx], len);
		value[len] = '\0';
	}
	return len;
}
#endif

#ifndef __ECOS
static int init_socket(CTX_Tp pCtx)
{
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int ifindex;

	DBFENTER;


#ifdef FOR_DUAL_BAND
    if(!pCtx->wlan0_wsc_disabled)
#endif        
    {

    	pCtx->socket = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
    	if (pCtx->socket < 0) {
    		perror("socket[PF_PACKET,SOCK_RAW]");
    		return -1;
    	}
    	memset(&ifr, 0, sizeof(ifr));
#ifdef INBAND_WPS_OVER_HOST
    	DEBUG_PRINT("%s %d bind socket to MII\n",__FILE__,__LINE__);
    	strncpy(ifr.ifr_name, HOST_MII_INTF, sizeof(ifr.ifr_name));
#else
    	strncpy(ifr.ifr_name, pCtx->wlan_interface_name, sizeof(ifr.ifr_name));
#endif	//INBAND_WPS_OVER_HOST
		WSC_DEBUG("!!!!ifr.ifr_name:%s\n",ifr.ifr_name);
    	while (ioctl(pCtx->socket , SIOCGIFINDEX, &ifr) != 0) {
		WSC_DEBUG("ioctl(SIOCGIFINDEX) failed!\n");
    		sleep(1);
    	}
    	ifindex = ifr.ifr_ifindex;
    	memset(&addr, 0, sizeof(addr));
    	addr.sll_family = AF_PACKET;
    	addr.sll_ifindex = ifindex;
    	if (bind(pCtx->socket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    		WSC_DEBUG("bind[PACKET] fail\n");
    		return -1;
    	}
    }

#ifdef FOR_DUAL_BAND

	if(!pCtx->wlan1_wsc_disabled){
		int countxx=0;
		pCtx->socket2 = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
		if (pCtx->socket2 < 0) {
			perror("socket[PF_PACKET,SOCK_RAW]");
			WSC_DEBUG("bind[PACKET] fail\n");
			return -1;
		}
		memset(&ifr, 0, sizeof(ifr));
#ifdef INBAND_WPS_OVER_HOST
		DEBUG_PRINT("%s %d bind socket2 to MII\n",__FILE__,__LINE__);
		strncpy(ifr.ifr_name, HOST_MII_INTF, sizeof(ifr.ifr_name));
#else
		strncpy(ifr.ifr_name, pCtx->wlan_interface_name2, sizeof(ifr.ifr_name));
#endif
		while (ioctl(pCtx->socket2 , SIOCGIFINDEX, &ifr) != 0) {
			WSC_DEBUG("ioctl(SIOCGIFINDEX) failed!\n");
			countxx++;
			if(countxx>5){
				printf("ioctl(SIOCGIFINDEX) failed!\n");
				break;
			}
			sleep(1);
		}
		ifindex = ifr.ifr_ifindex;
		memset(&addr, 0, sizeof(addr));
		addr.sll_family = AF_PACKET;
		addr.sll_ifindex = ifindex;
		if (bind(pCtx->socket2, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			printf("bind PACKET2 fail\n");
			return -1;
		}
	}
#endif
	return 0;
}
#endif

static STA_CTX_Tp search_sta_entry(CTX_Tp pCtx, unsigned char *addr)
{
	int i, idx=-1;

	for (i=0; i<WSC_MAX_STA_NUM; i++) {
		if (!pCtx->sta[i] || pCtx->sta[i]->used == 0) {
			if (idx < 0)
				idx = i;
			continue;
		}
		if (!memcmp(pCtx->sta[i]->addr, addr, ETHER_ADDRLEN))
			break;
	}

	if ( i != WSC_MAX_STA_NUM)		
		return (pCtx->sta[i]);


	if (idx >= 0) {
		pCtx->sta[idx] = calloc(1, sizeof(STA_CTX));
		return (pCtx->sta[idx]);
	}

	_DEBUG_PRINT("wscd : search_sta_entry : station table full!\n");
	return NULL; // table full
}

static int check_wsc_packet(CTX_Tp pCtx, struct eap_wsc_t *wsc)
{
	if (memcmp(wsc->vendor_id, WSC_VENDOR_ID, 3)) {
		_DEBUG_PRINT("Invalid WSC vendor id!,0x%02x-%02x-%02x\n",
			wsc->vendor_id[0],wsc->vendor_id[1],wsc->vendor_id[2]);
		return -1;
	}

	#ifdef DEBUG		// for debug
	if (wsc->vendor_type != ntohl(WSC_VENDOR_TYPE)) {
		_DEBUG_PRINT("Invalid WSC vendor type!\n");
		//return -1;
	}
	#endif

	if (wsc->op_code < WSC_OP_START || wsc->op_code > WSC_OP_FRAG_ACK) {
		WSC_DEBUG("Invalid WSC OP-Code!\n");
		return -1;
	}
	return 0;
}

static int get_wlan_evt(CTX_Tp pCtx)
{
	int evt;
	unsigned char type;

	type = *(pCtx->rx_buffer + FIFO_HEADER_LEN);
	if (type == (unsigned char)DOT11_EVENT_WSC_ASSOC_REQ_IE_IND)
		evt = EV_ASSOC_IND;
	else if (type == (unsigned char)DOT11_EVENT_WSC_PIN_IND)
		evt = EV_PIN_INPUT;
#ifdef P2P_SUPPORT
	else if (type == (unsigned char)DOT11_EVENT_WSC_SWITCH_MODE)
		evt = EV_P2P_SWITCH_MODE;
	else if (type == (unsigned char)DOT11_EVENT_WSC_STOP){
        WSC_DEBUG("DOT11_EVENT_WSC_STOP -> EV_STOP\n");
		evt = EV_STOP;
    }
	else if (type == (unsigned char)DOT11_EVENT_WSC_SWITCH_WLAN_MODE){ // 20160328
        WSC_DEBUG("Help change WLAN mode\n");
		evt = EV_HELP_CHANGE_WLAN_MODE;
    }
#endif
	else if (type == (unsigned char)DOT11_EVENT_WSC_SET_MY_PIN)
		evt = EV_CHANGE_MY_PIN;
	
	else if (type == (unsigned char)DOT11_EVENT_WSC_CHANGE_MAC_IND)
		evt = EV_MAC_HAS_CHANGED;	
	else if (type == (unsigned char)DOT11_EVENT_WSC_SPEC_SSID)
		evt = EV_SPEC_SSID;
	else if (type == (unsigned char)DOT11_EVENT_WSC_SPEC_MAC_IND)
		evt = EV_SET_SPEC_CONNECT_MAC;
	else if (type == (unsigned char)DOT11_EVENT_WSC_CHANGE_MODE)
		evt = EV_CHANGE_MODE;
#ifdef CONFIG_IWPRIV_INTF
	else if (type == (unsigned char)DOT11_EVENT_WSC_START_IND)
			evt = EV_START;
    else if (type == (unsigned char)DOT11_EVENT_WSC_MODE_IND)
            evt = EV_MODE;
    else if (type == (unsigned char)DOT11_EVENT_WSC_STATUS_IND)
            evt = EV_STATUS;
    else if (type == (unsigned char)DOT11_EVENT_WSC_METHOD_IND)
            evt = EV_METHOD;
    else if (type == (unsigned char)DOT11_EVENT_WSC_STEP_IND)
            evt = EV_STEP;
    else if (type == (unsigned char)DOT11_EVENT_WSC_OOB_IND)
            evt = EV_OOB;
#endif
	else if (type == DOT11_EVENT_EAP_PACKET)
		evt = EV_EAP;
#ifdef SUPPORT_UPNP
	else if (type == (unsigned char)DOT11_EVENT_WSC_PROBE_REQ_IND)
		evt = EV_PROBEREQ_IND;
#endif
	else if (type == (unsigned char)DOT11_EVENT_WSC_RM_PBC_STA){	/* 0528pbc */
		WSC_DEBUG("rx rm pbc event(DOT11_EVENT_WSC_RM_PBC_STA)\n");		
		evt = EV_RM_PBC_STA;
	}else {
		_DEBUG_PRINT("Rx error! event type is not recognized [%d]\n", type);
		return -1;
	}
	return evt;
}

#if !defined(NO_IWCONTROL) || defined(USE_MINI_UPNP)
static void listen_and_process_event(CTX_Tp pCtx)
{
	int selret=0;
	fd_set netFD;
#ifndef __ECOS
	IPCon ipcon=NULL;
	char *ip_addr;
#endif
#ifndef NO_IWCONTROL
	int evt;
	int nRead;
#endif
#ifdef USE_MINI_UPNP
	struct upnphttp * e = 0;
	struct upnphttp * next = 0;
	struct EvtRespElement *EvtResp=NULL;
	struct EvtRespElement *EvtResp_next=NULL;
#endif
	struct timeval timeout;

	DBFENTER;

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	while(1) {
#ifdef __ECOS
		if (pCtx->kill_wsc_upnp) {
			//diag_printf("escape forever loop\n");
			break;
		}
#endif

#ifndef __ECOS
		ipcon = IPCon_New(pCtx->lan_interface_name);
		ip_addr = IPCon_GetIpAddrByStr(ipcon);
		if (ip_addr && memcmp(pCtx->upnp_info.lan_ip_address,ip_addr,IP_ADDRLEN) && pCtx->upnp)
		{
			WSCUpnpStop();
			start_upnp(pCtx);
		}
		if(ipcon)
		{
			free(ipcon);
		}
#endif
		FD_ZERO(&netFD);
#ifndef NO_IWCONTROL

#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan0_wsc_disabled)
#endif
		{
			FD_SET(pCtx->fifo, &netFD);
		}

#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan1_wsc_disabled)
		{
			FD_SET(pCtx->fifo2, &netFD);
		}
#endif
#endif

		if (pCtx->upnp) {
#ifdef USE_MINI_UPNP
#ifdef STAND_ALONE_MINIUPNP
			if (pCtx->upnp_info.sudp >= 0)
				FD_SET(pCtx->upnp_info.sudp, &netFD);
#endif
			if (pCtx->upnp_info.shttpl >= 0)
				FD_SET(pCtx->upnp_info.shttpl, &netFD);

			for(e = pCtx->upnp_info.upnphttphead.lh_first; e != NULL; e = e->entries.le_next)
			{
				if((e->socket >= 0) && (e->state <= 2))
				{
					FD_SET(e->socket, &netFD);
				}
			}

			for(EvtResp = pCtx->upnp_info.subscribe_list.EvtResp_head.lh_first; EvtResp != NULL; EvtResp = EvtResp->entries.le_next)
			{
				if (EvtResp->socket >= 0)
					FD_SET(EvtResp->socket, &netFD);
			}

			//selret = select(FD_SETSIZE, &netFD, NULL, NULL, &timeout);
#endif //USE_MINI_UPNP
		}
		selret = select(FD_SETSIZE, &netFD, NULL, NULL, &timeout);

		if (selret >= 0) {
			if (selret == 0) { // timeout
#ifndef __ECOS //0606
				sigHandler_alarm(0);
#endif
				// reset timer
				timeout.tv_sec = 1;
				timeout.tv_usec = 0;
				continue;
			}
#ifndef NO_IWCONTROL
			/* Polling FIFO event */
			/* get event from wlan0 interface */

#ifdef FOR_DUAL_BAND
		if( pCtx->wlan0_wsc_disabled==0	)
#endif
		{
			if (FD_ISSET(pCtx->fifo, &netFD)) {

				nRead = read(pCtx->fifo, pCtx->rx_buffer, MAX_MSG_SIZE);
					if (nRead > 0){

					evt = get_wlan_evt(pCtx);
					#ifdef FOR_DUAL_BAND
					if(evt == EV_EAP && pCtx->inter1only == 1){
						WSC_DEBUG("drop EAP from %s\n", pCtx->wlan_interface_name);
						continue;
					}
						if( evt == EV_EAP || evt == EV_ASSOC_IND || evt == EV_PROBEREQ_IND){
						pCtx->InterFaceComeIn = COME_FROM_WLAN0 ;
						_DEBUG_PRINT("<<<===from %s\n", pCtx->wlan_interface_name);
					}
					#endif
					if (evt >= 0)
						process_event(pCtx, evt);
				}
			}
		}

#ifdef FOR_DUAL_BAND		/* get event from wlan1 interface */
			//if(pCtx->is_ap && !pCtx->wlan1_wsc_disabled){
			if(pCtx->wlan1_wsc_disabled==0)
			{
				if (FD_ISSET(pCtx->fifo2, &netFD)) {
					nRead = read(pCtx->fifo2, pCtx->rx_buffer, MAX_MSG_SIZE);
					if (nRead > 0 )
					{
						evt = get_wlan_evt(pCtx);
						if(evt == EV_EAP && pCtx->inter0only == 1){
							WSC_DEBUG("drop EAP from %s\n", pCtx->wlan_interface_name2);
							continue;
						}

						if( evt == EV_EAP || evt == EV_ASSOC_IND || evt == EV_PROBEREQ_IND){
							pCtx->InterFaceComeIn = COME_FROM_WLAN1 ;
							_DEBUG_PRINT("<<<===from %s\n", pCtx->wlan_interface_name2);
						}

						if (evt >= 0)
							process_event(pCtx, evt );
					}
				}
			}
#endif
#endif
			if (!pCtx->upnp)
				continue;

#ifdef USE_MINI_UPNP
#ifdef STAND_ALONE_MINIUPNP
			/* process SSDP packets */
			if(pCtx->upnp_info.sudp >= 0 && FD_ISSET(pCtx->upnp_info.sudp, &netFD))
			{
				/*syslog(LOG_INFO, "Received UDP Packet");*/
				//WSC_DEBUG("\n");
				ProcessSSDPRequest(pCtx->upnp_info.sudp, pCtx->upnp_info.lan_ip_address,
					(unsigned short)pCtx->upnp_info.port, &pCtx->upnp_info.SSDP);
			}
#endif

			/* process incoming HTTP connections */
			if(pCtx->upnp_info.shttpl >= 0 && FD_ISSET(pCtx->upnp_info.shttpl, &netFD))
			{
				int shttp;
				socklen_t	clientnamelen;
				struct sockaddr_in clientname;
				struct upnphttp * tmp = 0;
				clientnamelen = sizeof(struct sockaddr_in);
				char *IP=NULL;
				shttp = accept(pCtx->upnp_info.shttpl, (struct sockaddr *)&clientname, &clientnamelen);
				if(shttp<0)
				{
					syslog(LOG_ERR, "accept: %m");
				}
				else
				{
					_DEBUG_PRINT("\n");
					//WSC_DEBUG("HTTP connection from %s:%d\n",inet_ntoa(clientname.sin_addr),ntohs(clientname.sin_port) );
					/*if (fcntl(shttp, F_SETFL, O_NONBLOCK) < 0) {
						syslog(LOG_ERR, "fcntl F_SETFL, O_NONBLOCK");
					}*/
					/* Create a new upnphttp object and add it to
					 * the active upnphttp object list */
					tmp = New_upnphttp(shttp);
					if (tmp) {
						IP = inet_ntoa(clientname.sin_addr);
						memcpy(tmp->IP, IP, strlen(IP));
						tmp->IP[strlen(IP)] = '\0';
						tmp->soapMethods = pCtx->upnp_info.soapMethods;
						tmp->sendDesc = pCtx->upnp_info.sendDesc;
						tmp->subscribe_list = &pCtx->upnp_info.subscribe_list;
						LIST_INSERT_HEAD(&pCtx->upnp_info.upnphttphead, tmp, entries);
					}
					else
						close(shttp);
					
				}
			}
			/* process active HTTP connections */
			/* LIST_FOREACH is not available under linux */
			for(e = pCtx->upnp_info.upnphttphead.lh_first; e != NULL; e = e->entries.le_next)
			{
				if(  (e->socket >= 0) && (e->state <= 2)
			   		&&(FD_ISSET(e->socket, &netFD)) )
					Process_upnphttp(e);
			}
			/* delete finished HTTP connections */
			for(e = pCtx->upnp_info.upnphttphead.lh_first; e != NULL; )
			{
				next = e->entries.le_next;
				if(e->state >= 100)
				{
					LIST_REMOVE(e, entries);
					Delete_upnphttp(e);
				}
				e = next;
			}
			/* process eventing response */
			for(EvtResp = pCtx->upnp_info.subscribe_list.EvtResp_head.lh_first; EvtResp != NULL; )
			{
				EvtResp_next = EvtResp->entries.le_next;
				if(FD_ISSET(EvtResp->socket, &netFD)) {
					ProcessEventingResp(EvtResp);
					LIST_REMOVE(EvtResp, entries);
					if (EvtResp->socket >= 0)
						close(EvtResp->socket);
					free(EvtResp);
				}
				EvtResp = EvtResp_next;
			}
#endif // !USE_MINI_UPNP
		}
	}
}
#endif // !NO_IWCONTROL || USE_MINI_UPNP


//#define SET_SELECT_REG 1
int update_ie(CTX_Tp pCtx,unsigned char selected , int type)
{
        int len;
        unsigned char tmpbuf[1024];
		//WSC_DEBUG("\n");
        len = build_beacon_ie(pCtx, selected, type, pCtx->config_method, tmpbuf);

#ifndef WPS2DOTX
       	//under WSP2.0+ version should not provisioning WEP
        if (pCtx->encrypt_type == WSC_ENCRYPT_WEP) // add provisioning service ie
        {
        	len += build_provisioning_service_ie((unsigned char *)(tmpbuf+len));
        }
#endif

        if (__wlioctl_set_wsc_ie(pCtx->wlan_interface_name, tmpbuf, len,
        			DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_BEACON) < 0){
                _DEBUG_PRINT("<< EV_START error, IOCTL set beacon IE failed >>\n");
                return -1;
        }
        len = build_probe_rsp_ie(pCtx, selected, type, pCtx->config_method, tmpbuf);

		/* add provisioning service ie ;
		   by microsoft suggest ,for avoid WEP IOT issue when VS MS device*/
#ifndef WPS2DOTX
       	//under WSP2.0+ version shoult not provisioning WEP
        if (pCtx->encrypt_type == WSC_ENCRYPT_WEP) {
        	len += build_provisioning_service_ie((unsigned char *)(tmpbuf+len));
        }
#endif

        if (len > MAX_WSC_IE_LEN) {
        	_DEBUG_PRINT("<< EC_START error, Length of IE exceeds %d>>\n", MAX_WSC_IE_LEN);
        	return -1;
        }
        if (__wlioctl_set_wsc_ie(pCtx->wlan_interface_name, tmpbuf, len,
        			DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_PROBE_RSP) < 0){
        	_DEBUG_PRINT("<< EC_START error, IOCTL set probe IE failed >>\n");
        	return -1;
        }
        return 0;
}

#ifdef FOR_DUAL_BAND
int update_ie2(CTX_Tp pCtx,unsigned char selected , int type)
{

        int len;
        unsigned char tmpbuf[1024];
		//WSC_DEBUG("\n");
        len = build_beacon_ie(pCtx, selected, type, pCtx->config_method, tmpbuf);
#ifndef WPS2DOTX
        if (pCtx->encrypt_type2 == WSC_ENCRYPT_WEP) // add provisioning service ie
        {
        	WSC_DEBUG("!!!	under WSP2.0+ version shoult not provisioning WEP , check!!!\n");
        	len += build_provisioning_service_ie((unsigned char *)(tmpbuf+len));
        }
#endif

        if (__wlioctl_set_wsc_ie(pCtx->wlan_interface_name2, tmpbuf, len,
        			DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_BEACON) < 0){
                _DEBUG_PRINT("<< EV_START error, IOCTL set beacon IE failed >>\n");
                return -1;
        }



        len = build_probe_rsp_ie(pCtx, selected, type, pCtx->config_method, tmpbuf);

		/* add provisioning service ie ;
		   by microsoft suggest ,for avoid WEP IOT issue when VS MS device*/
#ifndef WPS2DOTX
        if (pCtx->encrypt_type2 == WSC_ENCRYPT_WEP) {
        	WSC_DEBUG("!!!	under WSP2.0+ version shoult not provisioning WEP , check!!!\n");
        	len += build_provisioning_service_ie((unsigned char *)(tmpbuf+len));
        }
#endif

        if (len > MAX_WSC_IE_LEN) {
        	_DEBUG_PRINT("<< EC_START error, Length of IE exceeds %d>>\n", MAX_WSC_IE_LEN);
        	return -1;
        }


        if (__wlioctl_set_wsc_ie(pCtx->wlan_interface_name2, tmpbuf, len,
        			DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_PROBE_RSP) < 0){
                _DEBUG_PRINT("<< EV_START error, IOCTL set probe IE failed >>\n");
                return -1;
        }

        return 0;
}
#endif

int reset_pin_procedure(CTX_Tp pCtx, int interval){


#ifdef P2P_SUPPORT
    if(pCtx->p2p_trigger_type==P2P_PRE_CLIENT){
        WSC_DEBUG("p2p GC mode timeout is 30 secs\n");
        pCtx->pin_timeout = 30;
    }else
#endif
    {
        if(pCtx->c_pin_timeout !=0 ){
    		pCtx->pin_timeout = pCtx->c_pin_timeout;
    	} else {
    		pCtx->pin_timeout = interval;
    	}
    }
	WSC_DEBUG("LED START...\n");
	if (wlioctl_set_led(LED_WSC_START) < 0) {
		printf("issue wlan ioctl set_led error!\n");
	}

#ifdef WPS2DOTX	// HIDDEN_AP Deprecated in 2.0
#else
    unsigned char tmpbuf[256];
	if (pCtx->is_ap && pCtx->disable_hidden_ap)
	{
		//DISABLE_HIDDEN_AP(pCtx, tmpbuf);
#ifdef	FOR_DUAL_BAND
		if(pCtx->wlan0_wsc_disabled == 0)
#endif
		{
			sprintf((char*)tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name);
			system((char*)tmpbuf);
		}
#ifdef	FOR_DUAL_BAND
		if(pCtx->wlan1_wsc_disabled == 0)
		{
			sprintf((char*)tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name2);
			system((char*)tmpbuf);
		}
#endif
	}
#endif

	if (pCtx->is_ap)
		pCtx->wps_triggered = 1;

	if(pCtx->pb_pressed || pCtx->pb_timeout) {
		WSC_DEBUG("Clear PBC stuff!\n");
		pCtx->pb_pressed = 0;
		pCtx->pb_timeout = 0;
	}
	if (pCtx->setSelectedRegTimeout) {
		DEBUG_PRINT("Clear setSelectedReg stuff!\n");
		pCtx->setSelectedRegTimeout = 0;
	}
	return 0;
}
int evHandler_pin_input(CTX_Tp pCtx, char *pin)
{
	int code, len;
	DOT11_WSC_PIN_IND *pIndEvt = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
	char *pcode;

	DBFENTER;

	if (!IS_PIN_METHOD(pCtx->config_method)) {
		WSC_DEBUG("PIN method is not configured!\n");
		return -1;
	}

#if defined(DET_WPS_SPEC) || defined(CONFIG_IWPRIV_INTF)
	pCtx->current_config_mode = CONFIG_METHOD_PIN ;
	DET_DEBUG("\evHandler_pin_input() \n\n");
#endif

	WSC_DEBUG("<< Got PIN-code Input event >>\n");

	if (pin)
		pcode =  pin;
	else
		pcode =  pIndEvt->code;

#ifdef DEBUG
	if (pCtx->debug)
		printf("PIN code: %s\n", pcode);
#endif

	#if 0
	//WSC_pthread_mutex_lock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d Lock mutex\n", __FUNCTION__, __LINE__);
	if (pCtx->registration_on >= 1) {
		WSC_DEBUG("Registration protocol is already in progress; ignore PIN!\n");
		//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
		//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
		return -1;
	}
	//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
	#endif

	len = strlen(pcode);
	if (len != PIN_LEN && len != 4) {
		printf("Invalid pin_code length!\n");
		return -1;
	}

#if defined(WSC_CLIENT_MODE) && defined(SUPPORT_REGISTRAR)
	if (!pCtx->is_ap) {
		if (pCtx->role == REGISTRAR) {
			pCtx->start = 1;
			client_set_WlanDriver_WscEnable(pCtx, 1);
		}
		else {
			DEBUG_ERR("Enrollee PIN could not be supported in client mode!\n");
			return -1;
		}
	}
#endif

	code = atoi(pcode);
	if (len == PIN_LEN) {
		if (!validate_pin_code(code)) {
			DEBUG_PRINT("Checksum error! Assume PIN is user specified.\n");
			pCtx->peer_pin_id = PASS_ID_USER;
		}
		else
			pCtx->peer_pin_id = PASS_ID_DEFAULT;
	}
	pCtx->pin_assigned = 1;

	/*for support pin_timeout can configure from config file
	  or use defalut(PIN_WALK_TIME)*/
	reset_pin_procedure(pCtx, PIN_WALK_TIME);



	report_WPS_STATUS(PROTOCOL_START);



	if (pin == NULL){

		strcpy(pCtx->peer_pin_code, pIndEvt->code);
	}
#ifdef P2P_SUPPORT
	else
	{
		/*modify  when add P2P_SUPPORT  ; take care!!*/

		strcpy(pCtx->peer_pin_code, pcode);
	}
#endif

	if (pCtx->is_ap) {

#ifdef FOR_DUAL_BAND
		pCtx->inter0only  = 0;
		pCtx->inter1only  = 0;

		/*2011-11 add for support under dual band mode just trigger single interface*/
		struct stat cancel_status;
		if (stat(WSCD_IND_ONLY_INTERFACE0, &cancel_status) == 0) {
			WSC_DEBUG("%s\n",WSCD_IND_ONLY_INTERFACE0);
			pCtx->inter0only  = 1;

			unlink(WSCD_IND_ONLY_INTERFACE0);
		}
		if (stat(WSCD_IND_ONLY_INTERFACE1, &cancel_status) == 0) {
			WSC_DEBUG("%s\n",WSCD_IND_ONLY_INTERFACE1);
			pCtx->inter1only  = 1;
			unlink(WSCD_IND_ONLY_INTERFACE1);
		}

		WSC_DEBUG("inter0only = %d\n",pCtx->inter0only);
		WSC_DEBUG("inter1only = %d\n",pCtx->inter1only);
		/*2011-11 add for support under dual band mode just trigger single interface*/
#endif
#ifdef CONFIG_IWPRIV_INTF
		if(pCtx->start_config_client )
#endif
		{
#ifdef WPS2DOTX
			registrar_remove_all_authorized_mac(pCtx);
			registrar_add_authorized_mac(pCtx , BroadCastMac);	// 2010-0719
#endif
		   		if (pCtx->use_ie){

#ifdef FOR_DUAL_BAND

					if(pCtx->wlan0_wsc_disabled == 0
					&& pCtx->inter1only != 1	/*ap pin mode support single trigger*/
					)
#endif
					{
						WSC_DEBUG("PIN mode update wlan0 IE\n");
		              	if( update_ie(pCtx,1, PASS_ID_DEFAULT) < 0 )
							return -1;
					}
#ifdef FOR_DUAL_BAND

					if(pCtx->wlan1_wsc_disabled==0
						&& pCtx->inter0only != 1	/*ap pin mode support single trigger*/
					){
						WSC_DEBUG("PIN mode update wlan1 IE\n");
	              		if( update_ie2(pCtx, 1 ,PASS_ID_DEFAULT) < 0 )
							return -1;
					}
#endif
		   		}
			}
		}
#if defined(WSC_CLIENT_MODE) && defined(SUPPORT_REGISTRAR)
		else {
#ifndef __ECOS
			struct sysinfo info ;
#endif

			if (pCtx->use_ie) {
                update_ie_client(pCtx, PASS_ID_DEFAULT);
			}

#ifdef __ECOS
			//pCtx->start_time = cyg_current_time();
			time(&pCtx->start_time);
#else
			sysinfo(&info);
			pCtx->start_time = (unsigned long)info.uptime;
#endif

			WSC_DEBUG("Issue scan\n");
			if( issue_scan_req(pCtx, CONFIG_METHOD_PIN) == -2) {
				reset_ctx_state(pCtx);

				if (wlioctl_set_led(LED_WSC_ERROR) < 0) {
					DEBUG_ERR("issue wlan ioctl set_led error!\n");
				}
				pCtx->start = 0;
				pCtx->start_time = 0;
			}
	}
#endif

#ifdef BLOCKED_ROGUE_STA
	if (pCtx->is_ap && pCtx->blocked_expired_time)
		disassociate_blocked_list(pCtx);
#endif

	return 0;
}

int evHandler_pb_press(CTX_Tp pCtx)
{
	DBFENTER;

	if (!IS_PBC_METHOD(pCtx->config_method)) {
		WSC_DEBUG("PBC method no enabled \n");
		return -1;
	}

#if defined(DET_WPS_SPEC) || defined(CONFIG_IWPRIV_INTF)
	pCtx->current_config_mode = CONFIG_METHOD_PBC;
#endif
	_DEBUG_PRINT("<< Got PB-Pressed event >>\n");

#ifdef WSC_CLIENT_MODE
	if (!pCtx->is_ap) {
		if (pCtx->role == REGISTRAR) {
			DEBUG_ERR("PBC could not be supported in external registrar mode!\n");
			return -1;
		}
		else {
			pCtx->start = 1;
			client_set_WlanDriver_WscEnable(pCtx, 1);
		}
	}
#endif

	if (!pCtx->start) {
		DEBUG_PRINT("Not started yet!\n");
		return 0;
	}

	#if 0
	//WSC_pthread_mutex_lock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d Lock mutex\n", __FUNCTION__, __LINE__);
	if (pCtx->registration_on >= 1) {
		WSC_DEBUG("Registration protocol is already in progress; ignore PBC!\n" );
		//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
		//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
		return -1;
	}
	//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
	#endif

#ifdef MUL_PBC_DETECTTION
#ifdef OVERLAPPING_BY_BAND
	if (!pCtx->disable_MulPBC_detection &&
		(search_active_sta_by_band(pCtx, RF_BAND_2G) > 1 ||
			search_active_sta_by_band(pCtx, RF_BAND_5G) > 1)) {	
#else
	if (!pCtx->disable_MulPBC_detection && pCtx->active_pbc_sta_count > 1) {		
#endif		
		WSC_DEBUG("\n\n		!!! Multiple PBC sessions [%d] detected!\n\n\n", pCtx->active_pbc_sta_count);
		SwitchSessionOverlap_LED_On(pCtx);
		return -1;
	}
	#ifdef DET_WPS_SPEC
	else if(!pCtx->disable_MulPBC_detection && pCtx->active_pbc_sta_count == 1){
		if(pCtx->SessionOverlapTimeout){
			pCtx->SessionOverlapTimeout = 0 ;
			DET_DEBUG("pcb be pressed again,unlock overlap state\n");
		}
	}
	#endif
#endif
    if(pCtx->debug2){
    	WSC_DEBUG("LED START...\n");
    }
    
	if (wlioctl_set_led(LED_WSC_START) < 0) {
		WSC_DEBUG("set_led fail!\n");
		return -1;
	}

#ifdef WPS2DOTX	// HIDDEN_AP Deprecated in 2.0

#else
	if (pCtx->is_ap && pCtx->disable_hidden_ap)
	{
	
    	unsigned char tmpbuf[1024];
		//DISABLE_HIDDEN_AP(pCtx, tmpbuf);
		if(pCtx->wlan0_wsc_disabled==0
			#ifdef	FOR_DUAL_BAND
			&& pCtx->inter1only!=1
			#endif
			)
		{
			sprintf((char*)tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name);
			system((char*)tmpbuf);
		}

		#ifdef	FOR_DUAL_BAND
		if(pCtx->wlan1_wsc_disabled==0
			&& pCtx->inter0only!=1)
		{
			sprintf((char*)tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name2);
			system((char*)tmpbuf);
		}
		#endif
	}
#endif

	if (pCtx->is_ap)
		pCtx->wps_triggered = 1;

	pCtx->pb_pressed = 1;
    #ifdef P2P_SUPPORT
    if(pCtx->p2p_trigger_type==P2P_PRE_CLIENT){
        WSC_DEBUG("p2p GC mode timeout is 30 secs\n");
        pCtx->pb_timeout = 30;
    }else
    #endif
	pCtx->pb_timeout = PBC_WALK_TIME;

    if(pCtx->debug2){
    	WSC_DEBUG("update pb_timeout to %d\n",pCtx->pb_timeout);
    }

	report_WPS_STATUS(PROTOCOL_START);

	if (pCtx->pin_timeout) {
		pCtx->pin_timeout = 0; //clear PIN timeout
		DEBUG_PRINT("Clear PIN stuff!\n");
	}

	if (pCtx->setSelectedRegTimeout) {
		DEBUG_PRINT("Clear setSelectedReg stuff!\n");
		pCtx->setSelectedRegTimeout = 0;
	}

	if (pCtx->role == REGISTRAR) {
		strcpy(pCtx->peer_pin_code, "00000000");
		pCtx->pin_assigned = 1;
	}else {
		strcpy(pCtx->pin_code, "00000000");
	}

	if (pCtx->is_ap) {
		if (pCtx->use_ie) {
#ifdef WPS2DOTX
			registrar_remove_all_authorized_mac(pCtx);
			registrar_add_authorized_mac(pCtx , BroadCastMac);	// 2010-0719
#endif

#ifdef FOR_DUAL_BAND
			if(pCtx->wlan0_wsc_disabled == 0
				&& pCtx->inter1only!=1	)
#endif
			{
				WSC_DEBUG("PBC mode update wlan0 IE\n");
				if( update_ie(pCtx,1, PASS_ID_PB) < 0){
					return -1;
				}
			}

#ifdef FOR_DUAL_BAND
			if(pCtx->wlan1_wsc_disabled == 0
				&& pCtx->inter0only!=1)
			{
				WSC_DEBUG("PBC mode update wlan1 IE\n");
				if(update_ie2(pCtx,1, PASS_ID_PB) < 0){
					return -1;
				}
			}
#endif
		}
	}
#ifdef WSC_CLIENT_MODE	
	else {
#ifndef __ECOS
			struct sysinfo info;
#endif
            //pCtx->start = 1;
            if (pCtx->use_ie) {
                update_ie_client(pCtx, PASS_ID_PB);
			}
#ifdef __ECOS
			//pCtx->start_time = cyg_current_time();
			time(&pCtx->start_time);
#else
			sysinfo(&info);
			pCtx->start_time= (unsigned long)info.uptime;
#endif

			WSC_DEBUG("Issue scan\n");
			if( issue_scan_req(pCtx, CONFIG_METHOD_PBC) == -2 ) {
				reset_ctx_state(pCtx);

				if (wlioctl_set_led(LED_WSC_ERROR) < 0) {
					DEBUG_ERR("issue wlan ioctl set_led error!\n");
				}
				pCtx->start = 0;
				pCtx->start_time = 0;
			}
	}
#endif

#ifdef BLOCKED_ROGUE_STA
	if (pCtx->is_ap && pCtx->blocked_expired_time)
		disassociate_blocked_list(pCtx);
#endif

	return 0;
}

int evHandler_eap(CTX_Tp pCtx)
{
	DOT11_EAP_PACKET *pIndEvt = (DOT11_EAP_PACKET *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
	struct ethernet_t *eth;
	struct eapol_t *eapol;
	struct eap_t *eap;
	struct eap_wsc_t *wsc;
	STA_CTX_Tp pSta;
	int packet_len = (int)pIndEvt->packet_len;
	int ret = 0;
#ifdef WPS2DOTX
	unsigned char* MsgPtr;
	int tmplength;
//	unsigned char* pData;
//	int tag_len;
	int EAP_Length	;
#endif

	//2011-0727 SGS
#ifdef DEBUG
#ifdef SUPPORT_UPNP
			unsigned char *pMsg=NULL;
			unsigned char *pData=NULL;
			int msg_len=0;
			int tag_len = 0;
#endif
#endif
	//2011-0727 SGS

	DBFENTER;

#ifdef DEBUG
	if (pCtx->debug2){
		wsc_debug_out("Rx EAP packet", pIndEvt->packet, packet_len);
	}
#endif

	if (!pCtx->start) {
		//WSC_DEBUG("Not started yet!\n");
		return 0;
	}

	eth = (struct ethernet_t *)pIndEvt->packet;
	eapol = (struct eapol_t *)(((unsigned char *)eth) + ETHER_HDRLEN);
	pSta = search_sta_entry(pCtx, eth->ether_shost);

	if (pSta == NULL)
		return 0;

	if (!pSta->used) {
		//pSta->used = 1;
		pCtx->num_sta++;

		if(pCtx->debug){
			WSC_DEBUG("Rx a EAP packet;from unused STA[%02x:%02x:%02x:%02x:%02x:%02x]\n",
				eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
				eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

			if (eapol->packet_type == EAPOL_KEY ) {
				WSC_DEBUG("EAP type == EAPLO-KEY \n");
			}
		}

		pSta->do_not_rescan = 1;
		reset_sta(pCtx, pSta, 1);
		return 0;
	}

#ifdef WSC_CLIENT_MODE
	if (!pCtx->is_ap)
		pCtx->sta_to_clear = pSta;
#endif

	if (packet_len < (ETHER_HDRLEN + EAPOL_HDRLEN)) {
		WSC_DEBUG("Rx EAPOL packet size too small!\n");
		return -1;
	}

	if (eapol->packet_type != EAPOL_START && eapol->packet_type != EAPOL_EAPPKT) {
		WSC_DEBUG("Invalid EAPOL packet type [0x%x]!\n", eapol->packet_type);
		return -1;
	}
	if (eapol->packet_type == EAPOL_START) {

		_DEBUG_PRINT(">>Received EAPOL_START\n");

		report_WPS_STATUS(RECV_EAPOL_START);

		if (pCtx->is_ap
#ifdef CONFIG_IWPRIV_INTF
				&& pCtx->start_config_client
#endif
                ) {
			if (pSta->state == ST_WAIT_EAPOL_START) {
				struct timeval tod;
				gettimeofday(&tod , NULL);
				srand(tod.tv_sec);
				pSta->eap_reqid = (rand() % 50) + 1;
				send_eap_reqid(pCtx, pSta);
				pSta->state = ST_WAIT_RSP_ID;
				pSta->tx_timeout = pCtx->tx_timeout;
				pSta->retry = 0;
				return 0;
			}
			else {
				WSC_DEBUG("Invalid state![%d]\n", pSta->state);
				return 0;
			}
		}//client mode
		else {
			WSC_DEBUG("!!!Rx EAPOL_START, but ourself is not enable to config. Discard it!\n");
			return -1;
		}
	}
	if (packet_len < (ETHER_HDRLEN + EAPOL_HDRLEN + EAP_HDRLEN)) {
		WSC_DEBUG("!!!Rx EAP packet size too small!\n");
		return -1;
	}
	eap = (struct eap_t *)(((unsigned char *)eapol) + EAPOL_HDRLEN);

	// for debug, for intel sdk


	if (packet_len != (ETHER_HDRLEN + EAPOL_HDRLEN + ntohs(eapol->packet_body_length))) {
		WSC_DEBUG("!!!Rx EAP packet size mismatch with eapol length!\n");
		//return -1; // Some AP may fill wrong length in packet_body_length, skip return for better compatibility 12/26
	}

	if (packet_len != (ETHER_HDRLEN + EAPOL_HDRLEN + ntohs(eap->length))) {
		WSC_DEBUG("!!!Rx EAP packet size mismatch with eap length!\n");
		//return -1;// Some AP may fill wrong length in packet_body_length, skip return for better compatibility 12/26
	}


	if (eapol->packet_type != EAPOL_EAPPKT &&
				eapol->packet_type != EAPOL_START) {
		WSC_DEBUG("Invalid EAPOL type!\n");
		return -1;
	}

	if (eap->code != EAP_REQUEST &&
		eap->code != EAP_RESPONSE &&
			eap->code != EAP_FAIL) {
		WSC_DEBUG("Invalid EAP code [%d]!!!\n", eap->code);
		return -1;
	}

	if (eap->code == EAP_FAIL)
		return pktHandler_eap_fail(pCtx, pSta);

	wsc = (struct eap_wsc_t *)(((unsigned char *)eap) + EAP_HDRLEN);

	if (wsc->type != EAP_TYPE_IDENTITY && wsc->type != EAP_TYPE_EXPANDED) {
		WSC_DEBUG("Invalid WSC type!\n");
		return -1;
	}

	//2011-0727 SGS
#ifdef DEBUG
#ifdef SUPPORT_UPNP
	if(pCtx->is_ap){
		if (pSta->used & IS_UPNP_CONTROL_POINT) {
			msg_len = ntohs(eap->length)-EAP_HDRLEN;
			pMsg = ((struct WSC_packet *)wsc)->rx_buffer;
		}

		pData = search_tag(pMsg, TAG_MSG_TYPE, msg_len, &tag_len);
		if (pData != NULL) {

			if (pData[0] == MSG_TYPE_M1) {
				WSC_DEBUG("RX M1\n");
			}else
			if (pData[0] == MSG_TYPE_M2) {
				WSC_DEBUG("RX M2\n");
			}else
			if (pData[0] == MSG_TYPE_M2D) {
				WSC_DEBUG("RX M2D\n");
			}else
			if (pData[0] == MSG_TYPE_M3) {
				WSC_DEBUG("RX M3\n");
			}else
			if (pData[0] == MSG_TYPE_M4) {
				WSC_DEBUG("RX M4\n");
			}else
			if (pData[0] == MSG_TYPE_M5) {
				WSC_DEBUG("RX M5\n");
			}else
			if (pData[0] == MSG_TYPE_M6) {
				WSC_DEBUG("RX M6\n");
			}else
			if (pData[0] == MSG_TYPE_M7) {
				WSC_DEBUG("RX M7\n");
			}else
			if (pData[0] == MSG_TYPE_M8) {
				WSC_DEBUG("RX M8\n");
			}else
			if (pData[0] == MSG_TYPE_ACK) {
				WSC_DEBUG("RX ACK\n");
			}else
			if (pData[0] == MSG_TYPE_NACK) {
				WSC_DEBUG("RX NACK\n");
			}else
			if (pData[0] == MSG_TYPE_DONE) {
				WSC_DEBUG("RX DONE\n");
			}

		}

	}

#endif
#endif
	//2011-0727 SGS


	if (pCtx->is_ap) {
		if (eap->code != EAP_RESPONSE) {
			DEBUG_ERR("Invalid EAP code [%x]\n", eap->code);
			return -1;
		}


		if (eap->identifier != pSta->eap_reqid) {
			WSC_DEBUG("	!!!EAP identifier is not matched! [in eap=0x%x, in keep =0x%x]!!!\n",eap->identifier, pSta->eap_reqid);
			return -1;
		}

		if (wsc->type == EAP_TYPE_IDENTITY)
			return pktHandler_rspid(pCtx, pSta, wsc->vendor_id, (int)(ntohs(eap->length)-EAP_HDRLEN-1));
	}
	else { // client mode
#ifdef L_ENDIAN
		pSta->eap_reqid = eap->identifier;
#else
		pSta->eap_reqid = ntohs(eap->identifier);
#endif

#ifdef SUPPORT_ENROLLEE
		if (eap->code != EAP_REQUEST) {
			WSC_DEBUG("Invalid EAP code [0x%x]!\n", eap->code);
			return -1;
		}
		if (wsc->type == EAP_TYPE_IDENTITY) {
			return pktHandler_reqid(pCtx, pSta, eap->identifier);
		}


		if (eap->identifier != pSta->eap_reqid) {
			WSC_DEBUG("	!!!EAP identifier is not matched! [in eap=0x%x, in keep=0x%x]!!!\n",eap->identifier, pSta->eap_reqid);
			return -1;
		}

#endif
	}

	if (check_wsc_packet(pCtx, wsc) < 0)
		return -1;


#ifdef WPS2DOTX	/*process reassembly first*/
#ifdef EAP_REASSEMBLY

	// now MsgPtr point to Message data
	MsgPtr = ((unsigned char *)wsc) + sizeof(struct eap_wsc_t);
	EAP_Length = ntohs(eap->length);

	/*tmplength = EAP_Length - 4 - 10*/
	tmplength = EAP_Length - EAP_HDRLEN - sizeof(struct eap_wsc_t) ;


	if (wsc->flags & EAP_FR_MF){
		if (wsc->flags & EAP_FR_LF){

			// when EAP_FR_LF== true ; now MsgPtr point to Message Length (2 bytes)
			pSta->total_message_len = (int)*(unsigned short *)MsgPtr;
			_DEBUG_PRINT("\n<<Receive First Frag EAP identifier=0x%x,total message length=%d\n",
				eap->identifier ,pSta->total_message_len);

			tmplength -= MSG_LEN_LEN;  // if(MF&&LF)the EPA include MessageLength(2B);Reduce that

			WSC_DEBUG("Frag EAP_Length =%d, 0x%x\n" ,EAP_Length,EAP_Length);
			WSC_DEBUG("Msg Data Length =%d, 0x%x \n",tmplength,tmplength);

			/* MsgPtr+MSG_LEN_LEN point to Message Data */
			memset(pSta->ReassemblyData ,'\0', EAP_FRAMENT_LEN);
			memcpy(pSta->ReassemblyData, MsgPtr+MSG_LEN_LEN ,tmplength);

			/* count msg_data_len */
			pSta->each_message_len = tmplength ;

			pSta->frag_state = 1 ; // indicate process frag message now
			send_wsc_frag_ack(pCtx , pSta);
			return 0;

		}
		else{
			_DEBUG_PRINT("\n<<Receive Middle Frag EAP identifier=0x%x\n",eap->identifier );

			WSC_DEBUG("Frag EAP_Length =%d, 0x%x\n" ,EAP_Length,EAP_Length);
			WSC_DEBUG("Msg Data Length =%d, 0x%x \n",tmplength,tmplength);

			/*now , MsgPtr point to Message Data */
			memcpy(&(pSta->ReassemblyData[pSta->each_message_len]), MsgPtr ,tmplength);

			/*count msg_data_len*/
			pSta->each_message_len += tmplength;

			pSta->frag_state = 1 ; // indicate process frag message now
			send_wsc_frag_ack(pCtx , pSta);
			return 0;
		}
	}
	else{

		if(pSta->frag_state==1){

			/* completed EAP reassembly*/
			_DEBUG_PRINT("\n<<Receive Last Frag EAP ,identifier:0x%x\n",eap->identifier);
			WSC_DEBUG("EAP_Length=%d, 0x%x\n",EAP_Length,EAP_Length);
			WSC_DEBUG("MsgDataLength =%d,0x%x\n",tmplength,tmplength);

			/* copy last EAP frag frame's msg data  */
			memcpy(&(pSta->ReassemblyData[pSta->each_message_len]), MsgPtr ,tmplength);

			/*count msg_data_len*/
			pSta->each_message_len += tmplength;

			WSC_DEBUG("verify msglen ;length by count=%d,total message length=%d\n",
				pSta->each_message_len , pSta->total_message_len);

			if(pSta->each_message_len != pSta->total_message_len){
				WSC_DEBUG("		!!!EAP reassem ;total_message_len no match!!\n");
			}

			memcpy(MsgPtr , pSta->ReassemblyData, pSta->total_message_len);

			/* modify EAP's Length */
			tmplength = EAP_HDRLEN + sizeof(struct eap_wsc_t) + pSta->total_message_len ;
			eap->length = htons(tmplength);

			pSta->frag_state = 0 ; // indicate process Last frag message now

			wsc_debug_out("after reassembly EAP message", pSta->ReassemblyData , pSta->total_message_len);


		}
		else{
			/* just for trace ;  this EAP Message is normal ; never do Reassembly */
			/*
			pData = search_tag(MsgPtr, TAG_MSG_TYPE, tmplength, &tag_len);
			if(pData){

				if (pData[0] >= MSG_TYPE_M1 && pData[0] <= MSG_TYPE_M8) {
					WSC_DEBUG("Rec Normal M%d msg length=%d\n",pData[0]-3,tmplength);
				}

			}
			*/
		}
	}

#endif
#endif

	if (wsc->op_code == WSC_OP_ACK){
		return pktHandler_wsc_ack(pCtx, pSta, wsc);
	}
	else if (wsc->op_code == WSC_OP_NACK) {
#ifdef SUPPORT_UPNP
		if (pCtx->role == PROXY && (pSta->state == ST_UPNP_PROXY ||
			pSta->state == ST_UPNP_WAIT_DONE)){

			/* forward WSC_NACK to the external registrar */
			pktHandler_wsc_msg(pCtx, pSta, wsc, ntohs(eap->length)-EAP_HDRLEN);

		}
#endif
		return pktHandler_wsc_nack(pCtx, pSta, wsc);
	}
	else if (wsc->op_code == WSC_OP_MSG) {

			DEBUG_PRINT2("pCtx->role == %d; pSta->state == %d\n",pCtx->role , pSta->state);
		ret = pktHandler_wsc_msg(pCtx, pSta, wsc, ntohs(eap->length)-EAP_HDRLEN);
		if (ret > 0) {
			send_wsc_nack(pCtx, pSta, ret);
			if (!pCtx->is_ap)
				pSta->state = ST_WAIT_EAP_FAIL;
			pSta->tx_timeout = pCtx->tx_timeout;
			pSta->retry = 0;
		}

		// Fix the WLK v1.2 test issue ----------
		if (ret < 0) {
			send_wsc_nack(pCtx, pSta, ret);
			pSta->tx_timeout = pCtx->tx_timeout;
			pSta->retry = 0;
		}
		//-----------------david+2008-05-27

		return ret;
	}
	else if (wsc->op_code == WSC_OP_DONE) {
		#ifdef SUPPORT_UPNP

		DEBUG_PRINT2("pCtx->role == %d; pSta->state == %d\n",pCtx->role , pSta->state);

		/*forward WSC_DONE to the external registrar*/
		/* for fix DTM M1-M2D proxy testing fail ; now we don't forward STA's DONE message to ERs*/
		if (pSta->state == ST_UPNP_WAIT_DONE && pCtx->ERisDTM==0 ) {
			WSC_DEBUG("	>>>Forward DONE msg to ER\n");
			pktHandler_wsc_msg(pCtx, pSta, wsc, ntohs(eap->length)-EAP_HDRLEN);
		}


		#endif
		return pktHandler_wsc_done(pCtx, pSta);
	}
#ifdef SUPPORT_ENROLLEE
	else if (wsc->op_code == WSC_OP_START) {
		if (!pCtx->is_ap)
			return pktHandler_wsc_start(pCtx, pSta);
		else {
			DEBUG_ERR("Rx WSC_OP_START, but ourself is not a client!\n");
			return -1;
		}
	}
#endif
#ifdef WPS2DOTX	/*process when rec Fragment ack*/
	else if (wsc->op_code == WSC_OP_FRAG_ACK) {
		WSC_DEBUG("Rec ACK eap->identifier=0x%x \n",eap->identifier);

		/*enrollee mode sync registrar's EAP id here*/
		if(!pCtx->is_ap){
			pSta->eap_reqid = eap->identifier;
		}

		switch(pSta->state){
			case ST_WAIT_EAPOL_FRAG_ACK_M1:
				WSC_DEBUG("Rx M1_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M1 , 0);

				break;
			case ST_WAIT_EAPOL_FRAG_ACK_M2:
				WSC_DEBUG("Rx M2_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M2 , 0);
				break;

			case ST_WAIT_EAPOL_FRAG_ACK_M3:
				WSC_DEBUG("Rx M3_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M3 , 0);
				break;
			case ST_WAIT_EAPOL_FRAG_ACK_M4:
				WSC_DEBUG("Rx M4_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M4 , 0);
				break;

			case ST_WAIT_EAPOL_FRAG_ACK_M5:
				WSC_DEBUG("Rx M5_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M5 , 0);
				break;
			case ST_WAIT_EAPOL_FRAG_ACK_M6:
				WSC_DEBUG("Rx M6_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M6 , 0);
				break;

			case ST_WAIT_EAPOL_FRAG_ACK_M7:
				WSC_DEBUG("Rx M7_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M7 , 0);
				break;
			case ST_WAIT_EAPOL_FRAG_ACK_M8:
				WSC_DEBUG("Rx M8_FRAG_ACK \n");
				send_frag_msg(pCtx , pSta , ST_WAIT_EAPOL_FRAG_ACK_M8 , 0);
				break;
			default:
				WSC_DEBUG("rec unknow type %d \n",pSta->state);
				break;

		}
	}
#endif
	else {
		DEBUG_ERR("Invalid WSC OP code [0x%x]!\n", wsc->op_code);
		return -1;
	}

	return 0;
}

int evHandler_assocInd(CTX_Tp pCtx, unsigned char assoc_type)
{
	STA_CTX_Tp pSta=NULL;
	DOT11_WSC_ASSOC_IND *msg=NULL;
	unsigned char MACAddr[6];
	unsigned char wscIE_included=0;	

#ifdef FOR_DUAL_BAND    
	unsigned char *pData=NULL;
	int tag_len=0;
#endif	

	DBFENTER;


	msg = (DOT11_WSC_ASSOC_IND *)(pCtx->rx_buffer + FIFO_HEADER_LEN);

#ifdef FOR_DUAL_BAND
	if(pCtx->InterFaceComeIn == COME_FROM_WLAN0){
		if (((pCtx->fix_wzc_wep==1 && !pCtx->config_by_ext_reg) ||pCtx->fix_wzc_wep ==2) && pCtx->is_ap
				&& pCtx->encrypt_type == WSC_ENCRYPT_WEP && !pCtx->wps_triggered) {
			DEBUG_ERR("Discard Assoc-Ind for WZC issue in WEP\n");
			return -1;
		}
	}else if(pCtx->InterFaceComeIn == COME_FROM_WLAN1){
		if (((pCtx->fix_wzc_wep==1 && !pCtx->config_by_ext_reg) ||pCtx->fix_wzc_wep ==2) && pCtx->is_ap
				&& pCtx->encrypt_type2 == WSC_ENCRYPT_WEP && !pCtx->wps_triggered) {
			DEBUG_ERR("Discard Assoc-Ind for WZC issue in WEP\n");
			return -1;
		}
	}
#else
	if (((pCtx->fix_wzc_wep==1 && !pCtx->config_by_ext_reg) ||pCtx->fix_wzc_wep ==2) && pCtx->is_ap
			&& pCtx->encrypt_type == WSC_ENCRYPT_WEP && !pCtx->wps_triggered) {
		DEBUG_ERR("Discard Assoc-Ind for WZC issue in WEP\n");
		return -1;
	}
#endif

#ifdef CONFIG_RTL865X_KLD
	report_WPS_STATUS(PROTOCOL_S0);
#endif

	/*fix unaligment issue, 2007-09-24+david
	  memcpy(MACAddr, msg->MACAddr, ETHER_ADDRLEN);*/
	do_bcopy(MACAddr, msg->MACAddr, ETHER_ADDRLEN);

	wscIE_included = msg->wscIE_included;
#ifdef FOR_DUAL_BAND
	if(pCtx->is_ap && get_both_band_cred_mib(pCtx, GET_CURRENT_INTERFACE)){		
		pData = search_tag(msg->AssocIE, TAG_FOR_BOTH_BAND_CRED, msg->AssocIELen, &tag_len);
		if (pData != NULL) {
			pCtx->both_band_credential = 1;
			WSC_DEBUG("pCtx->both_band_credential = %d\n",pCtx->both_band_credential);
		}else{		
            pCtx->both_band_credential = 0;
			WSC_DEBUG("pCtx->both_band_credential = NULL\n");
		}	
	}
#endif
#ifdef DEBUG
	if (pCtx->debug) {
		char msg_buffer[20];
		convert_bin_to_str(MACAddr, ETHER_ADDRLEN, msg_buffer);
		_DEBUG_PRINT("<<Got Assoc Event>> ");
		if (!pCtx->is_ap)
			_DEBUG_PRINT("from AP(%s)\n", msg_buffer);
		else
			_DEBUG_PRINT("from STA(%s)\n", msg_buffer);
	}
#endif

#ifdef BLOCKED_ROGUE_STA
	if (pCtx->is_ap && pCtx->blocked_expired_time) {
		if (search_blocked_list(pCtx, MACAddr))
			return -1;
	}
#endif

	//WSC_pthread_mutex_lock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d Lock mutex\n", __FUNCTION__, __LINE__);

	if (!pCtx->start) {
		DEBUG_PRINT("Not started yet!\n");
		goto err_handle;
	}

	pSta = search_sta_entry(pCtx, (unsigned char *)MACAddr);
	if (pSta == NULL) {
		DEBUG_ERR("STA table full, can't do simple-config!\n");
		goto err_handle;
	}
	if (pCtx->registration_on >= 1 && pCtx->sta_invoke_reg != pSta) {
		if (!pSta->used)
			pCtx->num_sta++;

		WSC_DEBUG("Registration_on = %d\n", pCtx->registration_on);
		WSC_DEBUG("Registration protocol is already in progress; ignore this association\n");

		goto err_handle;
	}

	if (pSta->used) {
		DEBUG_PRINT("STA entry existed\n");
#ifdef WSC_CLIENT_MODE
		if (!pCtx->is_ap) {
			DEBUG_PRINT("Ignore this association with AP\n");
			return 0;
		}
#endif
		if (pSta->locked) {
			DEBUG_ERR("STA is locked, ignore it!\n");
			goto err_handle;
		}

		// Comment-out the following code by SD1 Mars advise ---------
		#if 0
		if (pCtx->is_ap && (pSta->ap_role != ENROLLEE)) {
			pSta->allow_reconnect_count++;
			if (pSta->allow_reconnect_count >= 2) {
				DEBUG_PRINT("Exceeds re-connect limit, add into the block list\n");
				add_into_blocked_list(pCtx, pSta);
				reset_sta(pCtx, pSta, 1);
				return -1;
			}
		}
		#endif
		//-------------------------------------- david+2007-12-07

		reset_sta(pCtx, pSta, 0);
	}

	pCtx->num_sta++;
#ifdef WSC_CLIENT_MODE	
	if (!pCtx->is_ap) {
		if (pCtx->num_sta >= 2) {
			DEBUG_ERR("Only associate with one AP, ignore this!\n");
			goto err_handle;
		}
	}
#endif
	pSta->used = 1;
	memcpy(pSta->addr, MACAddr, ETHER_ADDRLEN);
	//WSC_DEBUG("number of station = %d\n", pCtx->num_sta);

	if (!pCtx->is_ap) {
#ifdef SUPPORT_ENROLLEE
		send_eapol_start(pCtx, pSta);
		pSta->state = ST_WAIT_REQ_ID;
		pSta->tx_timeout = pCtx->tx_timeout;
#ifdef WSC_CLIENT_MODE		
		pCtx->connect_fail = 0;
		//pCtx->wait_assoc_ind = 0;
#endif
#else
		return -1;
#endif
	}else {
		/*
		  case 1:  make sure STA include WSC IE
  		  case 2:  because auth == open & no SSN or RSN IE ;so we
	  		  treat this case as WSC IE included*/

		pSta->Assoc_wscIE_included = wscIE_included;
		pSta->tx_timeout = pCtx->tx_timeout;
		pSta->state = ST_WAIT_EAPOL_START;
	}

	pSta->reg_timeout = pCtx->reg_timeout;
	pSta->retry = 0;

	//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);

	return 0;

err_handle:
	if (pSta) {
#ifdef WSC_CLIENT_MODE
		if (!pCtx->is_ap)
			pSta->do_not_rescan = 1;
#endif

		reset_sta(pCtx, pSta, 1);
	}

	if (pCtx->is_ap && msg->wscIE_included==1){
		WSC_DEBUG("IssueDisconnect\n");
		IssueDisconnect(msg->MACAddr, 1);
	}

	//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
	return -1;
}

#ifdef SUPPORT_UPNP
#ifdef PREVENT_PROBE_DEADLOCK
static struct probe_node *search_probe_sta(CTX_Tp pCtx, unsigned char *addr)
{
	int i, idx=-1;

	for (i=0; i<MAX_WSC_PROBE_STA; i++) {
		if (pCtx->probe_list[i].used == 0) {
			if (idx < 0)
				idx = i;
			continue;
		}
		if (!memcmp(pCtx->probe_list[i].ProbeMACAddr, addr, ETHER_ADDRLEN))
			break;
	}

	if ( i != WSC_MAX_STA_NUM)
		return (&pCtx->probe_list[i]);

	if (idx >= 0)
		return (&pCtx->probe_list[idx]);
	else{
		unsigned int largest=0;
		idx=0;
		for (i=0; i<MAX_WSC_PROBE_STA; i++) {
			unsigned int time_offset = difftime(time(NULL), pCtx->probe_list[i].time_stamp);
			if (time_offset > largest) {
				idx = i;
				largest = time_offset;
			}
		}
		memset(&pCtx->probe_list[idx], 0, sizeof(struct probe_node));
		pCtx->probe_list_count--;
		return (&pCtx->probe_list[idx]);
	}
}
#endif //PREVENT_PROBE_DEADLOCK

int evHandler_probe_req_Ind(CTX_Tp pCtx)
{
	DOT11_PROBE_REQUEST_IND *msg = (DOT11_PROBE_REQUEST_IND *)(pCtx->rx_buffer + FIFO_HEADER_LEN);
#ifdef MUL_PBC_DETECTTION
	unsigned char *pData;
	int tag_len;
	unsigned short sVal;
	unsigned char *UUIDPtr;	
	int uuid_tag_len;	
#endif
	int ie_len;

#ifdef WPS2DOTX
	unsigned char *Ptr;
	int IS_V2 =0 ;
	int Req_Enroll=0;
	unsigned char *StmpPtr ;
	unsigned char *EVPtr ;
	int msg_len_tmp ;
	int wvfound = 0;
#endif
	DBFENTER;




	if (!pCtx->start) {
		DEBUG_PRINT("Not started yet!\n");
		return -1;
	}

#ifdef DEBUG
/* 0528pbc */
	if(pCtx->debug2){
        WSC_DEBUG("<<Got Probe_Req,from Sta>>\n");
        MAC_PRINT(msg->MACAddr);                
		wsc_debug_out("PROBE_REQUEST WSC IE", msg->ProbeIE, msg->ProbeIELen);
	}
#endif

	memcpy(&sVal, pCtx->rx_buffer+FIFO_HEADER_LEN+8, 2);
	ie_len = (int)sVal;
	unsigned char *MsgStart = (msg->ProbeIE+2+4);
	int MsgLen = (ie_len-2-4);


#ifdef WPS2DOTX
	StmpPtr = MsgStart;
	msg_len_tmp = MsgLen;

	pData = search_tag(StmpPtr, TAG_VENDOR_EXT, msg_len_tmp, &tag_len);
	if (pData) {
		if(!memcmp(pData , WSC_VENDOR_OUI ,3 ))
		{
			//WSC_DEBUG("WFA-OUI\n");
			//wsc_debug_out("verdor ext:",pData,tag_len );				
			wvfound = 1 ;
		}
	}

	if(wvfound){
		int lent2=0;
		EVPtr = search_VendorExt_tag(pData ,VENDOR_VERSION2 , tag_len , &lent2);
		if(EVPtr){
			IS_V2 = 1;
			//_DEBUG_PRINT("ProReq >= v2(0x%x)\n",EVPtr[0]);
		}
	}
	pData = search_tag(MsgStart, TAG_REQ_TO_ENROLL, MsgLen, &tag_len);
	if (pData != NULL && tag_len == 1) {
		Ptr = msg->MACAddr;

		if(pData[0]){
			Req_Enroll = 1;
			//WSC_DEBUG("REQ_TO_ENROLL=%x \n",pData[0]);
		}
	}else{
		Req_Enroll =0 ;
	}
	pData = search_tag(MsgStart, TAG_REQ_DEV_TYPE, MsgLen, &tag_len);
	if (pData != NULL && tag_len == 8) {
		WSC_DEBUG("Requested Device Type:\n	 len=%d, category_id=0x%x, oui=%02x%02x%02x%02x, sub_category_id=0x%x\n",
		tag_len, ntohs(*((unsigned short *)pData)), pData[2],pData[3],pData[4],pData[5],ntohs(*((unsigned short *)&pData[6])));
		if(ntohs(*((unsigned short *)pData))!=6 ||
			!( pData[2]==0x0 && pData[3]==0x50 && pData[4]==0xF2 && pData[5]==0x04)){
			WSC_DEBUG("Requested Device Type not our inster");
		}
	}
#endif

/*
	if (pCtx->debug) {
		char msg_buffer[30];
		convert_bin_to_str(msg->MACAddr, 6, msg_buffer);
		_DEBUG_PRINT("from client mac: %s\n\n\n", msg_buffer);
	}
*/


#ifdef MUL_PBC_DETECTTION
	if (pCtx->is_ap && IS_PBC_METHOD(pCtx->config_method) &&
		!pCtx->disable_MulPBC_detection) 
	{
		pData = search_tag(MsgStart, TAG_DEVICE_PASSWORD_ID, MsgLen, &tag_len);
		if (pData != NULL) {
			memcpy(&sVal, pData, tag_len);
			sVal = ntohs(sVal);
			UUIDPtr = search_tag(MsgStart, TAG_UUID_E, MsgLen, &uuid_tag_len);			
			if (sVal == PASS_ID_PB) {
				/* found PBC ID ; add to active sta list */ 
				if (UUIDPtr != NULL && uuid_tag_len == UUID_LEN) {
					WSC_pthread_mutex_lock(&pCtx->PBCMutex);
					search_active_pbc_sta(pCtx, msg->MACAddr, UUIDPtr, MsgStart, MsgLen);
					WSC_pthread_mutex_unlock(&pCtx->PBCMutex);

				}
			}else{		// 1->0 include WSC_IE 
				/* Sta no included pbc ID ; 
				   check at active pbc sta list ; if exist then remove it */ 
				if (UUIDPtr != NULL && uuid_tag_len == UUID_LEN) {
					//WSC_DEBUG("rm pbc sta from list (1)\n");
					WSC_pthread_mutex_lock(&pCtx->PBCMutex);
					/* 0528pbc */					
					remove_active_pbc_sta(pCtx, msg->MACAddr, 1);
					WSC_pthread_mutex_unlock(&pCtx->PBCMutex);

				}				   

			}
		}
	}
/* 0528pbc */	
#endif
#if	0	//	orig def MUL_PBC_DETECTTION
	if (pCtx->is_ap && IS_PBC_METHOD(pCtx->config_method) &&
		!pCtx->disable_MulPBC_detection) 
	{
		pData = search_tag(MsgStart, TAG_DEVICE_PASSWORD_ID, MsgLen, &tag_len);
		if (pData != NULL) {
			memcpy(&sVal, pData, tag_len);
			sVal = ntohs(sVal);
			if (sVal == PASS_ID_PB) {
				pData = search_tag(MsgStart, TAG_UUID_E, MsgLen, &tag_len);
				if (pData != NULL && tag_len == UUID_LEN) {
					WSC_pthread_mutex_lock(&pCtx->PBCMutex);
					//DEBUG_PRINT("%s %d Lock PBC mutex\n", __FUNCTION__, __LINE__);
					search_active_pbc_sta(pCtx, msg->MACAddr, pData);
					WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
					//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
				}
			}
		}
	}
#endif






#ifdef PREVENT_PROBE_DEADLOCK // scheduled by one second timer ( by sigHandler_alarm() &  PREVENT_PROBE_DEADLOCK)
	if (pCtx->is_ap && (pCtx->role == REGISTRAR || pCtx->role == PROXY) &&
		(pCtx->original_role != ENROLLEE) &&
		!pCtx->pb_pressed && !pCtx->pin_assigned &&
		pCtx->upnp && pCtx->TotalSubscriptions) {
		struct probe_node* probe_sta;

		probe_sta = search_probe_sta(pCtx, msg->MACAddr);
		probe_sta->ProbeIELen = MsgLen;
		memcpy(probe_sta->ProbeIE, ie_len+2+4, probe_sta->ProbeIELen);
		if (!probe_sta->used) {
			probe_sta->used = 1;
			memcpy(probe_sta->ProbeMACAddr, msg->MACAddr, 6);
			pCtx->probe_list_count++;
		}
		probe_sta->time_stamp = time(NULL);
		probe_sta->sent = 0;
	}
#else // will cause eventing problems in UPnP SDK
	if (pCtx->is_ap && (pCtx->role == REGISTRAR || pCtx->role == PROXY) &&
			(pCtx->original_role != ENROLLEE) &&
			!pCtx->pb_pressed && !pCtx->pin_assigned &&
			pCtx->upnp && pCtx->TotalSubscriptions) {
		struct WSC_packet packet;

		packet.EventType = WSC_PROBE_FRAME;
		packet.EventID = WSC_PUTWLANREQUEST;
		convert_bin_to_str_UPnP(msg->MACAddr, 6, packet.EventMac);
		packet.tx_buffer = MsgStart;
		packet.tx_size = MsgLen;

		if (WSCUpnpTxmit(&packet) != WSC_UPNP_SUCCESS) {
			DEBUG_ERR("WSCUpnpTxmit() return error!\n");
			return -1;
		}
	}
#endif

	return 0;
}
#endif

#ifdef WSC_CLIENT_MODE
#ifdef DEBUG

/**
 *	@brief  get WPA/WPA2 information
 *
 *	use 1 timestamp (32-bit variable) to carry WPA/WPA2 info \n
 *	1st 16-bit:                 WPA \n
 *  |          auth       |              unicast cipher              |              multicast cipher            |	\n
 *     15    14    13   12      11      10     9     8       7      6      5       4      3     2       1      0	\n
 *	+-----+-----+----+-----+--------+------+-----+------+-------+-----+--------+------+-----+------+-------+-----+	\n
 *	| Rsv | PSK | 1X | Rsv | WEP104 | CCMP | Rsv | TKIP | WEP40 | Grp | WEP104 | CCMP | Rsv | TKIP | WEP40 | Grp |	\n
 *	+-----+-----+----+-----+--------+------+-----+------+-------+-----+--------+------+-----+------+-------+-----+	\n
 *	2nd 16-bit:                 WPA2 \n
 *            auth       |              unicast cipher              |              multicast cipher            |	\n
 *	  15    14    13   12      11      10     9     8       7      6      5       4      3     2       1      0		\n
 *  +-----+-----+----+-----+--------+------+-----+------+-------+-----+--------+------+-----+------+-------+-----+	\n
 *	| Rsv | PSK | 1X | Rsv | WEP104 | CCMP | Rsv | TKIP | WEP40 | Grp | WEP104 | CCMP | Rsv | TKIP | WEP40 | Grp |	\n
 *  +-----+-----+----+-----+--------+------+-----+------+-------+-----+--------+------+-----+------+-------+-----+	\n
 */
// reference from wlan driver get_security_info()
static void print_bss(CTX_Tp pCtx, BssDscr *pBss, struct wps_ie_info * ie)
{
	char allInfoBuf[140];
	char InfoBuf[10];

	memset(allInfoBuf , '\0' ,140);
	memset(InfoBuf , '\0' , sizeof(InfoBuf));

	sprintf(allInfoBuf,"AP info: %02x:%02x:%02x:%02x:%02x:%02x",
			pBss->bdBssId[0], pBss->bdBssId[1], pBss->bdBssId[2],
			pBss->bdBssId[3], pBss->bdBssId[4], pBss->bdBssId[5]);

	strcat(allInfoBuf , "\n\t type:");
	if(pBss->bdCap & cIBSS)
		strcat(allInfoBuf , "Ad hoc");
	else
		strcat(allInfoBuf , "AP");

	strcat(allInfoBuf , "\n\t ssid:");
	strcat(allInfoBuf ,pBss->bdSsIdBuf );

	strcat(allInfoBuf, "\n\t band:");
	if (pBss->network & BAND_11B)
		strcat(allInfoBuf, "(B)");

	if (pBss->network & BAND_11G)
		strcat(allInfoBuf, "(G)");

	if (pBss->network & BAND_11N)
		strcat(allInfoBuf, "(N)");

	if (pBss->network & BAND_11A)
		strcat(allInfoBuf, "(A)");

	strcat(allInfoBuf , "\n\t channel:");
	sprintf(InfoBuf , "%d" , pBss->ChannelNumber);
	strcat(allInfoBuf , InfoBuf);

	strcat(allInfoBuf , "\n\t security:");

	if ((pBss->bdCap & cPrivacy) == 0){
		strcat(allInfoBuf , "no");
	}else{

		if (pBss->bdTstamp[0] == 0){
			strcat(allInfoBuf , "WEP");
		}else{
			int wpa_exist = 0 ;
			if (pBss->bdTstamp[0] & 0x0000ffff) {
				strcat(allInfoBuf , "WPA");
				if(pBss->bdTstamp[0] & (1<<10))
					strcat(allInfoBuf , "-PSK");
				wpa_exist = 1;

				if(pBss->bdTstamp[0] & (1<<8))
					strcat(allInfoBuf , "+TKIP");
				if(pBss->bdTstamp[0] & (1<<10))
					strcat(allInfoBuf , "+AES");
			}

			if (pBss->bdTstamp[0] & 0xffff0000) {
				if (wpa_exist)
					strcat(allInfoBuf , "/");
				strcat(allInfoBuf , "WPA2");
				if(pBss->bdTstamp[0] & (1<<(14+16)))
					strcat(allInfoBuf , "-PSK");

				if(pBss->bdTstamp[0] & (1<<(8+16)))
					strcat(allInfoBuf , "+TKIP");
				if(pBss->bdTstamp[0] & (1<<(10+16)))
					strcat(allInfoBuf , "+AES");

			}
		}
	}

	WSC_DEBUG("%s\n", allInfoBuf);
	if(pCtx->debug2){        
		if (ie->data[0] == 221 && ie->data[1] > 0)
			wsc_debug_out("WSC IE", &(ie->data[2]), (int)ie->data[1]);
	}

}
#endif

#ifdef MUL_PBC_DETECTTION
static void Search_PBC_AP(CTX_Tp pCtx)
{
	int i,len, tag_len;
	unsigned char *pData;
	unsigned short usVal;
	SS_STATUS_Tp ss_status = NULL;
	SS_IE_Tp ss_ie = NULL;


#ifdef FOR_DUAL_BAND
    int j;
    for(j = 0; j<2; j++) {
        if(j == 0) {
            if(pCtx->wlan0_wsc_disabled == 0) {
                ss_status = &(pCtx->ss_status);
                ss_ie = &(pCtx->ss_ie);
            }
            else
                continue;
        }
        else if(j==1) {
            if(pCtx->wlan1_wsc_disabled == 0) {
                ss_status = &(pCtx->ss_status2);
                ss_ie = &(pCtx->ss_ie2);
            }
            else
                continue;
        }
#else
    ss_status = &(pCtx->ss_status);
    ss_ie = &(pCtx->ss_ie);
    {
#endif
    	for (i=0; i<ss_status->number && ss_status->number!=0xff; i++) {
    		if (ss_ie->ie[i].data[0] == WSC_IE_ID && ss_ie->ie[i].data[1] > 0) {
    			len = (int)ss_ie->ie[i].data[1] - 4;
    			pData = search_tag(&ss_ie->ie[i].data[6], TAG_SELECTED_REGITRAR, len, &tag_len);
    			if (pData == NULL || pData[0] != 1)
    				continue;
    			pData = search_tag(&ss_ie->ie[i].data[6], TAG_DEVICE_PASSWORD_ID, len, &tag_len);
    			if (pData == NULL || tag_len != 2)
    				continue;
    			memcpy(&usVal, pData, 2);
    			usVal = ntohs(usVal);
    			if (usVal == PASS_ID_PB) {
    				pData = search_tag(&ss_ie->ie[i].data[6], TAG_UUID_E, len, &tag_len);
    				if (pData) {
    					if (tag_len != 16)
    						continue;
    					search_active_pbc_sta(pCtx, ss_status->bssdb[i].bdBssId, pData, NULL, 0);
    				}
    				else {
    					unsigned char uuid[16];
    					memset(uuid, 0, 16);
    					search_active_pbc_sta(pCtx, ss_status->bssdb[i].bdBssId, uuid, NULL, 0);
    				}
    			}
    		}
    	}     
    }
}
#endif

static int search_wps_ap(CTX_Tp pCtx, SS_STATUS_Tp ss_status, SS_IE_Tp ss_ie, int method) {
    int found = 0, i, len, tag_len;
    unsigned char *pData;
    unsigned char *wsc_ie_start=NULL;
    BssDscr *pBss;
	unsigned short usVal;    
#ifdef WPS2DOTX
    unsigned char *StmpPtr ;
    int wvfound=0;
#endif

    for (found=0, i=++pCtx->join_idx; i<ss_status->number && ss_status->number!=0xff; i++) {
    
#ifdef CONNECT_PROXY_AP
        if(ss_status->number<=MAX_RETRY_AP_NUM && strlen(pCtx->SPEC_SSID)==0  && is_zero_ether_addr(pCtx->SPEC_MAC)){
            if ((method == CONFIG_METHOD_PIN) && (pCtx->role == ENROLLEE) && (!pCtx->is_ap) )
                if(search_blocked_ap_list(pCtx, i, 1))
                    continue;
        }
#endif
    
        if (ss_ie->ie[i].data[0] == WSC_IE_ID && ss_ie->ie[i].data[1] > 0) {
            len = (int)ss_ie->ie[i].data[1] - 4;
            wsc_ie_start = (&ss_ie->ie[i].data[6]) ;

            pData = search_tag(wsc_ie_start, TAG_SELECTED_REGITRAR, len, &tag_len);
            if (pCtx->role == REGISTRAR) {
                if (pData)
                    continue;
                else {
                    found = 1;
                    break;
                }
            }
            else
            {

                pBss = &ss_status->bssdb[i];
                #ifdef P2P_SUPPORT
                if((pCtx->p2p_trigger_type==P2P_PRE_CLIENT)){
                    /*when dev under p2p pre-client mode filter SSID!="DIRECT-*"*/
                    if(strlen(pBss->bdSsIdBuf)<=7){
                        continue;
                    }
                    if(memcmp(pBss->bdSsIdBuf,"DIRECT-",7)){
                        continue;
                    }
                }
                #endif
                /*we have assigned special SSID to connect,must match*/
                /* support  special SSID , 2011-0505 */
                if( strlen(pCtx->SPEC_SSID) ){

                    if(!strcmp(pBss->bdSsIdBuf,pCtx->SPEC_SSID)){
                        found = 5;
                        break;
                    }else{
                        //continue;
                    }
                }
    
                /*we have assigned special MacAddr to connect,must match*/
                /* support  special MAC Addr , 2011-0505 */
                if( !is_zero_ether_addr(pCtx->SPEC_MAC) ){

                    if(!memcmp(pBss->bdBssId,pCtx->SPEC_MAC,6)){
                        found = 6;
                        break;
                    }else{
                        continue;
                    }
                }
    
		if(strlen(pCtx->SPEC_SSID) && found !=5)
			continue;
    
                /*  skip check TAG_SELECTED_REGITRAR ; for MicroSsft softAp IOT issue  ; don't apply under WPS2x for stable*/
                if (pData == NULL)
                    continue;

                if(pData[0] == 0){
                    pData = search_tag(wsc_ie_start, TAG_MANUFACTURER, len, &tag_len);
                    if(tag_len == strlen("Microsoft")){
                        if(strncmp((char*)pData ,"Microsoft", tag_len)!=0)
                            continue;
                    }else{
                        continue;
                    }
                }

                pData = search_tag(wsc_ie_start, TAG_DEVICE_PASSWORD_ID, len, &tag_len);
                if (pData == NULL || tag_len != 2){
                    continue;
                }else{
                    memcpy(&usVal, pData, 2);
                    usVal = ntohs(usVal);
                }
    
    
    
                if (method == CONFIG_METHOD_PBC && usVal == PASS_ID_PB)
                {
                    found = 2;
                    break;
                }
                if (method == CONFIG_METHOD_PIN &&
                        (usVal == PASS_ID_DEFAULT || usVal == PASS_ID_USER))
                {
                    found = 3;
                    break;
                }
#ifdef P2P_SUPPORT
                if ( (method == CONFIG_METHOD_PIN ||method == CONFIG_METHOD_DISPLAY )
                     &&(usVal == PASS_ID_REG ))
                {
                    found = 4;
                    break;
                }
#endif
#ifdef WPS2DOTX
                pData = search_tag(wsc_ie_start, TAG_VENDOR_EXT, len, &tag_len);
                if (pData != NULL) {
                    if(!memcmp(pData , WSC_VENDOR_OUI ,3 ))
                    {
                        //WSC_DEBUG("found WFA-vendor-OUI!!\n");
                        //wsc_debug_out("verdor ext:",pData,tag_len );
                        wvfound = 1 ;
                    }
                }
    
                if(wvfound){
                    int lent2=0;
                    StmpPtr = search_VendorExt_tag(pData ,VENDOR_VERSION2 , tag_len , &lent2);
                    if(StmpPtr){
                        RX_DEBUG("version2(0x%x) EAP\n",StmpPtr[0]);
    
                        StmpPtr = search_VendorExt_tag(pData ,VENDOR_AUTHMAC, tag_len , &lent2);
                        if(StmpPtr){
                            if(!memcmp(StmpPtr,BroadCastMac,6) || !memcmp(StmpPtr,pCtx->our_addr,6)){
                                RX_DEBUG("      AuthMac match!!!:");
                                MAC_PRINT(StmpPtr);
                                found = 7;
                                break;
                            }
                        }
                    }
                }
#endif
    
    
    
            }
    
        }
    }
#ifdef CONNECT_PROXY_AP
	if(ss_status->number<=MAX_RETRY_AP_NUM
		&& strlen(pCtx->SPEC_SSID)==0
		&& is_zero_ether_addr(pCtx->SPEC_MAC))
	{
		if ((method == CONFIG_METHOD_PIN) && (pCtx->role == ENROLLEE) && (!pCtx->is_ap)) {

    		if (found == 0) {

    			pCtx->join_idx = -1;

    			for (found=0, i=++pCtx->join_idx; i<ss_status->number && ss_status->number!=0xff; i++) {
    				unsigned char *config_state;

    				if(pCtx->blocked_unselected_ap > MAX_RETRY_AP_NUM)
    					break;

    				if(search_blocked_ap_list(pCtx, i, 0))
    					continue;

    				len = (int)ss_ie->ie[i].data[1] - 4;
    				wsc_ie_start = &(ss_ie->ie[i].data[6]) ;

    				pData = search_tag(wsc_ie_start, TAG_SIMPLE_CONFIG_STATE, len, &tag_len);

    				if(pData != NULL)
    					config_state = pData;
    				else
    					continue;

    				if(*config_state == 0x2){
    					found = 8;
    					break;
    				}
    				else{
    					continue;
    				}
    			}

    		}


    		if(found == 0) {
    			WSC_DEBUG("proxy-like NEXT LOOP ~~~~ \n");
    			clear_blocked_ap_list(pCtx);
    			i = ss_status->number;
    		}
    		else if(found == 8) {
    			WSC_DEBUG("Try to connect to an configured(proxy-like) WPS AP\n\n");
    			add_into_blocked_ap_list(pCtx, i, 0);
    		}
    		else{
    			add_into_blocked_ap_list(pCtx, i, 1);
    		}

	    }
	}
#endif

    pCtx->join_idx = i;
    return found;

}

#define	_SPEC_MAC_ 0x001
#define	_SPEC_SSID_ 0x010
static int connect_wps_ap(CTX_Tp pCtx, int method)
{
    int len = 0, tag_len, found = 0, wait_time;
    unsigned char *pData, res;
    unsigned char *wsc_ie_start=NULL;
    BssDscr *pBss;
    struct wps_ie_info * wsc_ie;
    char * wlan_interface;
    
	//get_next:
#ifdef FOR_DUAL_BAND
    if(pCtx->wlan0_wsc_disabled == 0)
#endif
    {
	    DEBUG_PRINT("scan result number =%d, the scan interface is %s\n", pCtx->ss_status.number, pCtx->wlan_interface_name);
    }    
#ifdef FOR_DUAL_BAND
    if(pCtx->wlan1_wsc_disabled == 0) {
        DEBUG_PRINT("scan result number =%d, the scan interface is %s\n", pCtx->ss_status2.number, pCtx->wlan_interface_name2);
    }
#endif

	if( strlen(pCtx->SPEC_SSID) ){
		WSC_DEBUG("SPEC SSID=%s\n",pCtx->SPEC_SSID);
	}

	if( !is_zero_ether_addr(pCtx->SPEC_MAC) ){
		MAC_PRINT(pCtx->SPEC_MAC);
	}

#ifdef FOR_DUAL_BAND
    if(pCtx->prefer_band == 0) { /*search wlan0 first*/
        if(pCtx->wlan0_wsc_disabled == 0 && pCtx->join_band == 0) {
            found = search_wps_ap(pCtx, &(pCtx->ss_status), &(pCtx->ss_ie), method);               
        }
        if(found == 0) {
            if(pCtx->wlan1_wsc_disabled == 0) {  
                if(pCtx->join_band == 0) {
                    pCtx->join_idx = -1;
                    pCtx->join_band = 1;
                }
                found = search_wps_ap(pCtx, &(pCtx->ss_status2), &(pCtx->ss_ie2), method);               
            }
        }
    }
    else { /*search wlan1 first*/
        if(pCtx->wlan1_wsc_disabled == 0 && pCtx->join_band == 1) {   
             found = search_wps_ap(pCtx, &(pCtx->ss_status2), &(pCtx->ss_ie2), method);               
         }

        if(found == 0) {
            if(pCtx->wlan0_wsc_disabled == 0) {                
                if(pCtx->join_band == 1) {                    
                    pCtx->join_idx = -1;
                    pCtx->join_band = 0;      
                }
                 found = search_wps_ap(pCtx, &(pCtx->ss_status), &(pCtx->ss_ie), method);               
             }

        }
    }
#else
    found = search_wps_ap(pCtx, &(pCtx->ss_status), &(pCtx->ss_ie), method);
#endif

	pCtx->connect_method = method;

	if (found) {
		if(found==2){
			WSC_DEBUG("Found AP support WPS PBC\n\n");
		}
		else if(found==3){
			WSC_DEBUG("Found AP support WPS PIN\n\n");
		}
#ifdef P2P_SUPPORT
		else if(found==4){
			WSC_DEBUG("Found P2P-AP support WPS PIN\n\n");
		}
#endif
		else if(found==5){
			/* support  special SSID , 2011-0505 */
			WSC_DEBUG("connect to Assigned SSID(%s) AP\n",pCtx->SPEC_SSID);
		}
		else if(found==6){
			/* support  special MAC , 2011-0505 */
			WSC_DEBUG("connect to Assigned MAC AP\n");
			MAC_PRINT(pCtx->SPEC_MAC);
		}else if(found==7){
			WSC_DEBUG("2.0 AP include authorized Mac\n");
		}



#ifdef FOR_DUAL_BAND
        pCtx->both_band_credential = 0;
        if(pCtx->join_band == 0) {
            pCtx->InterFaceComeIn = COME_FROM_WLAN0;
            pBss = &pCtx->ss_status.bssdb[pCtx->join_idx];
            wsc_ie = &(pCtx->ss_ie.ie[pCtx->join_idx]);
            wlan_interface = pCtx->wlan_interface_name;     

            // For both_band_credential client mode
            if (get_both_band_cred_mib(pCtx, pCtx->wlan_interface_name)) {
                pCtx->both_band_credential = 1;
                WSC_DEBUG("pCtx->both_band_credential = 1\n");
            }
        }
        else {            
            pCtx->InterFaceComeIn = COME_FROM_WLAN1;
            pBss = &pCtx->ss_status2.bssdb[pCtx->join_idx];
            wsc_ie = &(pCtx->ss_ie2.ie[pCtx->join_idx]); 
            wlan_interface = pCtx->wlan_interface_name2;  

            // For both_band_credential client mode
            if (get_both_band_cred_mib(pCtx, pCtx->wlan_interface_name2)) {
                pCtx->both_band_credential = 1;
                WSC_DEBUG("pCtx->both_band_credential = 1\n");
            }
        }        
	    WSC_DEBUG("found band: %d, join_index: %d\n", pCtx->join_band, pCtx->join_idx);
#else    
        pBss = &pCtx->ss_status.bssdb[pCtx->join_idx];
        wsc_ie = &(pCtx->ss_ie.ie[pCtx->join_idx]);
        wlan_interface = pCtx->wlan_interface_name;
	    WSC_DEBUG("found, join_index: %d\n", pCtx->join_idx);        
#endif

#ifdef DEBUG
		print_bss(pCtx, pBss, wsc_ie);
#endif


		res = pCtx->join_idx;
		wait_time = 0;

        #ifdef P2P_SUPPORT // 20160328
        if(pCtx->p2p_trigger_type==P2P_PRE_CLIENT){
            /*do nothing*/
        }else
        #endif
        {
    		IssueDisconnect(pBss->bdBssId, 1);
	    	WSC_DEBUG("issue disconnect to ");
		    MAC_PRINT(pBss->bdBssId);
        }

		while (1) {
			if (!pCtx->start)
				return 0;

			WSC_DEBUG("issue join-req!\n");

			if (getWlJoinRequest(wlan_interface, pBss, &res) < 0) {
				WSC_DEBUG("Join request failed!\n");
				//goto get_next;
				return 0;
			}
			if (res == 1) { // wait
				if (wait_time++ > 5) {
					WSC_DEBUG("connect-request timeout!\n");
					//goto get_next;
					return 0;
				}
				sleep(1);
				continue;
			}
			break;
		}

		if (res == 2) { // invalid index
			WSC_DEBUG("Connect failed, invalid index!\n");
			//goto get_next;
			return 0;
		}
		else {
			wait_time = 0;
			while (1) {
				if (!pCtx->start)
					return 0;
				if (getWlJoinResult(wlan_interface, &res) < 0) {
					WSC_DEBUG("Get Join result failed!\n");
					//goto get_next;
					return 0;
				}
				if (res != 0xff) { // completed
					/*if (wait_time++ > 10) {
						DEBUG_ERR("connect timeout!\n");
						goto get_next;
						return 0;
					}*/
					break;
				}
				if (wait_time++ > 5) {
					WSC_DEBUG("connect timeout!\n");
					//goto get_next;
					return 0;
				}
				sleep(1);
			}

			if (res!=STATE_Bss && res!=STATE_Ibss_Idle && res!=STATE_Ibss_Active) {
				WSC_DEBUG("Connect failed!\n");
				//goto get_next;
				return 0;
			}
			else{
				WSC_DEBUG("\n	>>>connect to AP(channel:%d)\n",pBss->ChannelNumber);

				/*for correctly handle multi-credentials,test plan 5.1.1 ;2012-03-09*/
				/* the two credentials have the same auth and encry ,just ssid different
				   keep AP's SSID and configure state*/ 	
				strcpy(pCtx->negoApSSID,pBss->bdSsIdBuf);
				WSC_DEBUG("negoApSSID = [%s]\n",pCtx->negoApSSID);
				pData = search_tag(wsc_ie_start, TAG_SIMPLE_CONFIG_STATE, len, &tag_len);
				if(pData != NULL){
					pCtx->negoAPConfigStat=pData[0];
					WSC_DEBUG("negoAPConfigStat = [%d]\n",pCtx->negoAPConfigStat);
				}else{
					pCtx->negoAPConfigStat=0;
				}
				/*for correctly handle multi-credentials,test plan 5.1.1 ;2012-03-09*/
				
				if(pBss->ChannelNumber > 14){
					pCtx->STAmodeNegoWith = COMEFROM5G;
				}else{
					pCtx->STAmodeNegoWith = COMEFROM24G;
				}
			}
			pCtx->wait_reinit = 0;
			pCtx->connect_fail = 0;

			//pCtx->wait_assoc_ind = 3;// bug fixed
			//pCtx->connect_method = method;

#ifdef FULL_SECURITY_CLONE
			APConfigStateChk(pCtx);
#endif
			return 1;
		}
	}

	return 0;
}

int issue_scan_req(CTX_Tp pCtx, int method)
{
	int status = 1, wait_time=0;
    int wait_time_define=30;
	//struct sysinfo info;

    #ifdef FOR_DUAL_BAND
    int status1 = 1; 
    #endif

    #ifdef P2P_SUPPORT
    if(pCtx->p2p_trigger_type==P2P_PRE_CLIENT){
        wait_time_define=10;
    }
    #endif

	// issue scan-request
//scan_next:
#if 0
	sysinfo(&info);
	if (pCtx->target_time < info.uptime) {
		pCtx->start = 0;
		return 0;
	}
#endif

	while (1) {
        if (!pCtx->start)
            return 0;        

#ifdef FOR_DUAL_BAND
        if(pCtx->wlan0_wsc_disabled == 0 && status != 0) 
#endif
        {
            WSC_DEBUG("issue scan-req[%s]\n", pCtx->wlan_interface_name);
            if (wlioctl_scan_reqest(pCtx->wlan_interface_name, &status) < 0) {
                WSC_DEBUG("Site-survey request failed!\n");
                return -2;
            }
        }
#ifdef FOR_DUAL_BAND
        if(pCtx->wlan1_wsc_disabled == 0 && status1 != 0) {
            WSC_DEBUG("issue scan-req[%s]\n", pCtx->wlan_interface_name2);
            if (wlioctl_scan_reqest(pCtx->wlan_interface_name2, &status1) < 0) {
                WSC_DEBUG("Site-survey request failed!\n");
                return -2;
            }
        }

#endif
#ifdef FOR_DUAL_BAND                    
        if ((pCtx->wlan0_wsc_disabled == 0 && status != 0) ||
            (pCtx->wlan1_wsc_disabled == 0 && status1 !=0))
#else
        if(status != 0)
#endif
        {  // not ready
            if (wait_time++ > wait_time_define) {
                WSC_DEBUG("scan request timeout!\n");
                return -1;
            }
            sleep(1);
        }
        else{
            break;
        }
	}

	// get scan result, wait until scan completely
	wait_time = 0;
    pCtx->ss_status.number = 0xff;
#ifdef FOR_DUAL_BAND
    pCtx->ss_status2.number = 0xff;
#endif    
	while (1) {
		if (!pCtx->start)
			return 0;

#ifdef FOR_DUAL_BAND
        if(pCtx->wlan0_wsc_disabled == 0 && pCtx->ss_status.number == 0xff)
#endif
        {
    		pCtx->ss_status.number = 1;	// only request request status
    		if (wlioctl_scan_result(pCtx->wlan_interface_name, &pCtx->ss_status) < 0) {
    			WSC_DEBUG("Read site-survey status failed!\n");
    			return -1;
    		}
        }


#ifdef FOR_DUAL_BAND
        if(pCtx->wlan1_wsc_disabled == 0 && pCtx->ss_status2.number == 0xff)
        {
            pCtx->ss_status2.number = 1; // only request request status
            if (wlioctl_scan_result(pCtx->wlan_interface_name2, &pCtx->ss_status2) < 0) {
                WSC_DEBUG("Read site-survey status failed!\n");
                return -1;
            }            
        }
#endif
        
#ifdef FOR_DUAL_BAND
        if((pCtx->wlan0_wsc_disabled == 0 && pCtx->ss_status.number == 0xff) ||
        (pCtx->wlan1_wsc_disabled == 0 && pCtx->ss_status2.number == 0xff)) 
#else
        if(pCtx->ss_status.number == 0xff)
#endif
        {   // in progress
            if (wait_time++ > 30) {
                WSC_DEBUG("scan timeout!\n");
                return -1;
            }
            sleep(1);
        }
        else {
            break;
        }

	}


#ifdef FOR_DUAL_BAND
    if(pCtx->wlan0_wsc_disabled == 0)
#endif
    {
    	memset(&pCtx->ss_status, '\0', sizeof(SS_STATUS_T));
    	memset(&pCtx->ss_ie, '\0', sizeof(SS_IE_T));

    	pCtx->ss_status.number = 0; // request BSS DB
    	if (wlioctl_scan_result(pCtx->wlan_interface_name, &pCtx->ss_status) < 0) {
    		WSC_DEBUG("Read site-survey DB failed!\n");
    		return -1;
    	}

    	pCtx->ss_ie.number = 2; // request WPS IE
    	if (wlioctl_scan_result(pCtx->wlan_interface_name, (SS_STATUS_Tp)&pCtx->ss_ie) < 0) {
    		WSC_DEBUG("Read site-survey IE failed!\n");
    		return -1;
    	}
    }

#ifdef FOR_DUAL_BAND
    if(pCtx->wlan1_wsc_disabled == 0) {
        memset(&pCtx->ss_status2, '\0', sizeof(SS_STATUS_T));
        memset(&pCtx->ss_ie2, '\0', sizeof(SS_IE_T));
        pCtx->ss_status2.number = 0; // request BSS DB
        if (wlioctl_scan_result(pCtx->wlan_interface_name2, &pCtx->ss_status2) < 0) {
            WSC_DEBUG("Read site-survey DB failed!\n");
            return -1;
        }
        
        pCtx->ss_ie2.number = 2; // request WPS IE
        if (wlioctl_scan_result(pCtx->wlan_interface_name2, (SS_STATUS_Tp)&pCtx->ss_ie2) < 0) {
            WSC_DEBUG("Read site-survey IE failed!\n");
            return -1;
        }
    }
#endif    


#ifdef FULL_SECURITY_CLONE
	if(pCtx->waitReScanMode == 1){
		WSC_DEBUG("end of scan\n");
		return 0;
	}
#endif


#ifdef MUL_PBC_DETECTTION
	if (pCtx->role == ENROLLEE && method == CONFIG_METHOD_PBC &&
		!pCtx->disable_MulPBC_detection) {
		Search_PBC_AP(pCtx);
		if (pCtx->active_pbc_sta_count > 1) {
			WSC_DEBUG("\n\n		!!!Multiple PBC sessions [%d] detected!\n\n", pCtx->active_pbc_sta_count);
			SwitchSessionOverlap_LED_On(pCtx);
			return -1;
		}
	#ifdef DET_WPS_SPEC	//0403
		else if(pCtx->active_pbc_sta_count == 1){
		if(pCtx->SessionOverlapTimeout)
			pCtx->SessionOverlapTimeout = 0 ;
			DET_DEBUG("issue scan req,unlock overlap state\n");	// for debug version
		}
	#endif
	}
#endif

    pCtx->join_idx = -1;
#ifdef FOR_DUAL_BAND	
    pCtx->join_band = pCtx->prefer_band; /*search from prefer band*/
#endif
	if (!connect_wps_ap(pCtx, method)) { // fail
		//if (pCtx->start)
			//goto scan_next;
		pCtx->connect_fail = 1;
		return -1;
	}
	return 0;
}
#endif // WSC_CLIENT_MODE

#ifdef NO_IWCONTROL
#define MAXDATALEN      1560	// jimmylin: org:256, enlarge for pass EAP packet by event queue
typedef struct _DOT11_REQUEST{
        unsigned char   EventId;
}DOT11_REQUEST;

static void wlanIndEvt(int sig_no)
{
	CTX_Tp pCtx = pGlobalCtx;
	struct iwreq wrq;
	unsigned char tmpbuf[MAXDATALEN];
	DOT11_REQUEST *req;
	int skfd, evt, next_evt;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
		printf("wscd: socket() error!\n");
		return;
	}

get_next:
	strcpy(wrq.ifr_name, pCtx->wlan_interface_name);
	req = (DOT11_REQUEST *)tmpbuf;
	wrq.u.data.pointer = tmpbuf;
	req->EventId = DOT11_EVENT_REQUEST;
	wrq.u.data.length = sizeof(DOT11_REQUEST);
  	if (ioctl(skfd, SIOCGIWIND, &wrq) < 0) {
		printf("wscd: ioctl(SIOCGIWIND) error!\n");
		close(skfd);
		return;
	}
	memcpy(pCtx->rx_buffer + FIFO_HEADER_LEN, wrq.u.data.pointer, wrq.u.data.length);
	evt = get_wlan_evt(pCtx);
	next_evt = *(pCtx->rx_buffer + FIFO_HEADER_LEN + 1);

	if((evt == EV_CHANGE_MODE) || (evt == EV_SPEC_SSID) || (evt == EV_SET_SPEC_CONNECT_MAC) 
	|| (evt==EV_P2P_SWITCH_MODE) || evt==EV_MAC_HAS_CHANGED) || (evt==EV_HELP_CHANGE_WLAN_MODE)) {
		process_event(pCtx, evt);
	}
	else if ((evt >= 0) &&
		(pCtx->start
		  || ((evt == EV_PIN_INPUT) && !pCtx->is_ap && (pCtx->role == REGISTRAR)))	// client mode is ER
	)
	{
		process_event(pCtx, evt);
	}


	if (next_evt != 0)
		goto get_next;

	close(skfd);
}

#ifndef __ECOS
#define SIOCSAPPPID     0x8b3e
int register_PID(char *ifname)
{
	struct iwreq	wrq;
	pid_t	 pid;
	int	skfd;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
		return -1;
	}

  	/* Get wireless name */
	memset(wrq.ifr_name, 0, sizeof wrq.ifr_name);
  	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	pid = getpid();
	wrq.u.data.pointer = (caddr_t)&pid;
	wrq.u.data.length = sizeof(pid_t);

  	if(ioctl(skfd, SIOCSAPPPID, &wrq) < 0)
	{
    	// If no wireless name : no wireless extensions
//		strerror(errno);
		close(skfd);
		return(-1);
	}
	close(skfd);
	return 1;
}
#endif
#endif // NO_IWCONTROL

#ifdef  TRIGGER_PBC_FROM_GPIO
int register_PID_to_gpio(void)
{
	char tmpbuf[16*4];
	pid_t	 pid;
	pid = getpid();
	sprintf(tmpbuf , "echo %d > /proc/gpio_wscd_pid" , pid);
	WSC_DEBUG("\nissue cmd : %s\n\n\n" ,tmpbuf );
	system(tmpbuf);

	return 1;
}
#endif

int init_wlan(CTX_Tp pCtx, int reinit)
{
	unsigned char tmpbuf[1024];
	int len;
#ifndef __ECOS
#ifdef NO_IWCONTROL
	int fdflags;
#else
	struct stat status;
#endif
#endif

	DBFENTER;

#ifndef __ECOS
	if (!reinit) {
#ifdef NO_IWCONTROL
#ifndef USE_POLLING
		sprintf(tmpbuf, "/dev/wl_chr%c", pCtx->wlan_interface_name[strlen(pCtx->wlan_interface_name)-1]);
		if ((pCtx->wl_chr_fd = open(tmpbuf, O_RDWR, 0)) < 0) {
			int retval;
			retval = register_PID(pCtx->wlan_interface_name);
			if (retval > 0)
				signal(SIGIO, wlanIndEvt);
			else {
				printf("wscd: unable to open an wl_chr device and PID registration fail.\n");
				return -1;
			}
		}
		else {
			signal(SIGIO, wlanIndEvt);
			fcntl(pCtx->wl_chr_fd, F_SETOWN, getpid());
			fdflags = fcntl(pCtx->wl_chr_fd, F_GETFL);
			fcntl(pCtx->wl_chr_fd, F_SETFL, fdflags | FASYNC);
		}
#endif
#else
		/*we are use this case now 0922*/

		/* Create fifo */
#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan0_wsc_disabled)
#endif
		{
			printf("!!!!!!%s\n",__FUNCTION__);
			if (stat(pCtx->fifo_name, &status) == 0)
				unlink(pCtx->fifo_name);

			if (mkfifo(pCtx->fifo_name, FIFO_MODE) < 0) {
				WSC_DEBUG("mkfifo() error1!\n");
				return -1;
			}

			/* Open fifo, indication event queue of wlan driver */
			DEBUG_ERR("%s open wl0 fifo %s\n",__FUNCTION__,pCtx->fifo_name);
		  	pCtx->fifo = open(pCtx->fifo_name, O_RDONLY , 0);
			DEBUG_ERR("%s open wl0 fifo end\n",__FUNCTION__);
			//WSC_DEBUG("mkfifo(%s)\n",pCtx->fifo_name);
		  	if (pCtx->fifo < 0) {
	  			DEBUG_ERR("open fifo(%s) fail!\n",pCtx->fifo_name);
			  	return -1;
			}
		}

#ifdef FOR_DUAL_BAND
		/*for pid naming sync ; any mode will create fifo2  */
		if(pCtx->wlan1_wsc_disabled == 0)
		{
			if (stat(pCtx->fifo_name2, &status) == 0)
				unlink(pCtx->fifo_name2);

			if (mkfifo(pCtx->fifo_name2, FIFO_MODE) < 0) {
				WSC_DEBUG("mkfifo %s fail!\n",pCtx->fifo_name2);
				return -1;
			}

			/* Open fifo, indication event queue of wlan driver */
			DEBUG_ERR("%s open wl1 fifo %s\n",__FUNCTION__,pCtx->fifo_name2);
		  	pCtx->fifo2 = open(pCtx->fifo_name2, O_RDONLY , 0);
			DEBUG_ERR("%s open wl1 fifo\n",__FUNCTION__);
		  	if (pCtx->fifo2 < 0) {
				WSC_DEBUG("open fifo %s fail!\n",pCtx->fifo_name2);
		  		return -1;
			}
		}

#endif	//FOR_DUAL_BAND
#endif	//NO_IWCONTROL

#ifdef  TRIGGER_PBC_FROM_GPIO
		register_PID_to_gpio();
#endif
	}
#endif /* __ECOS */
		

	if (!pCtx->is_ap) {	/* CLIENT mode */
#ifdef WSC_CLIENT_MODE
		if (pCtx->use_ie && pCtx->start) {
            update_ie_client(pCtx, 0);
		}
#endif
	}
	else {	/* AP mode */
		if (pCtx->use_ie) {



			len = build_beacon_ie(pCtx, 0, 0, 0, tmpbuf);

#ifndef WPS2DOTX
			if (((!pCtx->fix_wzc_wep || pCtx->config_by_ext_reg) && pCtx->fix_wzc_wep != 2)
					&& pCtx->encrypt_type == WSC_ENCRYPT_WEP) // add provisioning service ie
				len += build_provisioning_service_ie(tmpbuf+len);
#endif
            if (wlioctl_set_wsc_ie(tmpbuf, len, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_BEACON) < 0) {
                WSC_DEBUG("update IE fail\n");
                return -1;
            }

			len = build_probe_rsp_ie(pCtx, 0, 0, 0, tmpbuf);

#ifndef WPS2DOTX
			if (((!pCtx->fix_wzc_wep || pCtx->config_by_ext_reg) && pCtx->fix_wzc_wep != 2)
					&& pCtx->encrypt_type == WSC_ENCRYPT_WEP) // add provisioning service ie
				len += build_provisioning_service_ie(tmpbuf+len);
#endif

			if (len > MAX_WSC_IE_LEN) {
				DEBUG_ERR("Length of IE exceeds %d\n", MAX_WSC_IE_LEN);
				return -1;
			}
            if (wlioctl_set_wsc_ie(tmpbuf, len, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_PROBE_RSP) < 0){
                WSC_DEBUG("update IE fail\n");
                return -1;
            }

#ifdef WPS2DOTX		//under WPS2.0 we must include WSC IE at assoc rsp
			len = build_assoc_response_ie(pCtx, tmpbuf);
			if (len == 0)
				DEBUG_ERR("Length of assoc rsp IE exceeds %d\n", MAX_WSC_IE_LEN);
            if (wlioctl_set_wsc_ie(tmpbuf, len, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_ASSOC_RSP) < 0){
                WSC_DEBUG("update IE fail\n");
                return -1;
            }
#endif
		}
	}

	if (pCtx->is_ap) {

#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan0_wsc_disabled)
#endif
		{
#ifdef __ECOS
			RunSystemCmd(NULL_FILE, "iwpriv", pCtx->wlan_interface_name, "set_mib", "wsc_enable=3", NULL_STR);
#else
			sprintf((char *)tmpbuf,"iwpriv %s set_mib wsc_enable=3", pCtx->wlan_interface_name);
#ifdef INBAND_WPS_OVER_HOST
			inband_remote_cmd(tmpbuf);
#else
			system((char *)tmpbuf);
#endif	//INBAND_WPS_OVER_HOST
#endif  //__ECOS
		}

#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan1_wsc_disabled){
			sprintf((char *)tmpbuf,"iwpriv %s set_mib wsc_enable=3", pCtx->wlan_interface_name2);
#ifdef INBAND_WPS_OVER_HOST
			inband_remote_cmd(tmpbuf);
#else
			system((char *)tmpbuf);
#endif //INBAND_WPS_OVER_HOST
		}
#endif	//FOR_DUAL_BAND

		/*after update wlan's ie info ; release wlan's tx */
#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan0_wsc_disabled)
#endif
		{
			func_on_wlan_tx(pCtx,pCtx->wlan_interface_name);
		}
#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan1_wsc_disabled ) {
			func_on_wlan_tx(pCtx,pCtx->wlan_interface_name2);
		}
#endif
	}
	DBFEXIT;
	return 0;
}

void process_event(CTX_Tp pCtx, int evt)
{
	int i, ret;
	DBFENTER;

	switch (evt) {
		case EV_START:
#if defined(DEBUG) && defined(OUTPUT_LOG)
			if(outlog_fp==NULL){
				outlog_fp = fopen( LOG_PATH ,"a+" );
			}
#endif
#ifdef WSC_CLIENT_MODE
			if (!pCtx->is_ap) {
#ifndef __ECOS
				struct sysinfo info;
#endif

				WSC_DEBUG("<< Got EV_START >><< Got PIN-code Input event >>\n");
#ifdef SUPPORT_REGISTRAR
				if (pCtx->role == REGISTRAR) {
					DEBUG_ERR("Self-PIN could not be supported in external registrar mode!\n");
					return;
				}
#endif

				pCtx->start = 1;
				client_set_WlanDriver_WscEnable(pCtx, 1);

				if(pCtx->pb_pressed || pCtx->pb_timeout) {
					WSC_DEBUG("Clear PBC stuff!\n");
					pCtx->pb_pressed = 0;
					pCtx->pb_timeout = 0;
				}

				if (pCtx->use_ie) {
                    update_ie_client(pCtx, 0);
				}
			#ifndef DET_WPS_SPEC
				WSC_DEBUG("LED START...\n");
				if (wlioctl_set_led(LED_WSC_START) < 0) {
					DEBUG_ERR("issue wlan ioctl set_led error!\n");
				}
			#endif

				pCtx->pin_timeout = PIN_WALK_TIME;
				report_WPS_STATUS(PROTOCOL_START);
#ifdef __ECOS
				//pCtx->start_time = cyg_current_time();
				time(&pCtx->start_time);
#else
				sysinfo(&info);
				pCtx->start_time = (unsigned long)info.uptime;
#endif

				WSC_DEBUG("Issue scan\n");
				issue_scan_req(pCtx, CONFIG_METHOD_PIN);
			}
			else
#endif
            {
				_DEBUG_PRINT("<< Got EV_START >>\n");
#ifdef CONFIG_IWPRIV_INTF
                if( pCtx->mode == MODE_AP_UNCONFIG ){
            		for (i=0; i<WSC_MAX_STA_NUM; i++){
                        if (pCtx->sta[i]){
                            pCtx->sta[i]->used = 0;

							if(pCtx->num_ext_registrar)
		                        pCtx->num_ext_registrar--;

								WSC_DEBUG("ER count=%d\n", pCtx->num_ext_registrar);
                        }
                    }
#ifdef STAND_ALONE_MINIUPNP
					//sending alive
					WSC_DEBUG("!!sending alive\n\n");

                    SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
                       &pCtx->upnp_info.SSDP, 0, pCtx->upnp_info.SSDP.max_age);
                    pCtx->upnp_info.SSDP.alive_timeout = pCtx->upnp_info.SSDP.max_age/2;
#endif
                    reset_pin_procedure(pCtx, PIN_WALK_TIME);
                    if (pCtx->use_ie) {
                            int len;

							// 2010-11-4
#ifdef FOR_DUAL_BAND
							if(!pCtx->wlan0_wsc_disabled)
#endif
							{
	                            if( update_ie(pCtx,1, PASS_ID_DEFAULT) < 0 )
                                    break;
							}
#ifdef FOR_DUAL_BAND
							if(!pCtx->wlan1_wsc_disabled){
	                            if( update_ie2(pCtx,1, PASS_ID_DEFAULT) < 0 )
                                    break;
							}
#endif
            		}
                    report_WPS_STATUS(PROTOCOL_START);
                }
				else {
                    if (pCtx->is_ap){
                        pCtx->start_config_client = 1;
                        if( IS_PBC_METHOD(pCtx->current_config_mode) ){
                            evHandler_pb_press(pCtx);
                        } else {
                            reset_pin_procedure(pCtx, PIN_WALK_TIME);
                            report_WPS_STATUS(PROTOCOL_START);
                        }
                    }
                }
#endif  //ifdef CONFIG_IWPRIV_INTF
            }
			break;

		case EV_STOP:
			_DEBUG_PRINT("<< Got EV_STOP >>\n");
			for (i=0; i<WSC_MAX_STA_NUM; i++) {
				if (pCtx->sta[i] && pCtx->sta[i]->used)
					reset_sta(pCtx, pCtx->sta[i], 1);
			}
			reset_ctx_state(pCtx);
			if (!pCtx->is_ap)
				pCtx->start = 0;

#ifdef OUTPUT_LOG
			if(outlog_fp){
				fclose(outlog_fp);
			}
#endif

            report_WPS_STATUS(NOT_USED); // 2011-0830
			break;

		case EV_ASSOC_IND:
			evHandler_assocInd(pCtx, DOT11_EVENT_WSC_ASSOC_REQ_IE_IND);
			break;

		case EV_EAP:
			ret = evHandler_eap(pCtx);
#ifdef WSC_CLIENT_MODE
			if (!pCtx->is_ap && ret != 0) {
				reset_sta(pCtx, pCtx->sta_to_clear, 1);
			}
#endif
			break;

		case EV_PIN_INPUT:
#if defined(DEBUG) && defined(OUTPUT_LOG)
			if(outlog_fp==NULL){
				outlog_fp = fopen( LOG_PATH ,"a+" );
			}
#endif
			evHandler_pin_input(pCtx, NULL);
			break;

		case EV_PB_PRESS:
#if defined(DEBUG) && defined(OUTPUT_LOG)
			if(outlog_fp==NULL){
				outlog_fp = fopen( LOG_PATH ,"a+" );
			}
#endif
			evHandler_pb_press(pCtx);
			break;
#ifdef SUPPORT_UPNP
		case EV_PROBEREQ_IND:
			evHandler_probe_req_Ind(pCtx);
			break;
#endif
#ifdef	AUTO_LOCK_DOWN
		case EV_UN_AUTO_LOCK_DOWN:
			if(pCtx->auto_lock_down){
				pCtx->auto_lock_down = 0;
#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION				
				pCtx->ADL_pin_attack_count=0;	
#endif
				InOut_auto_lock_down(pCtx,0);
				printf("user has intervened unlock\n");
			}
			break;
#endif
#ifdef CONFIG_IWPRIV_INTF
    case EV_MODE:
            if(pCtx->is_ap){
                    DOT11_WSC_IND *pIndEvt = (DOT11_WSC_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
                    _DEBUG_PRINT("<< EV_MODE mode:%x >>\n",pIndEvt->value);
	}
            break;
    case EV_STATUS:
            if(pCtx->is_ap){
                    DOT11_WSC_IND *pIndEvt = (DOT11_WSC_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
                    if( pIndEvt->value == 1 ){
                            int i;
                            pCtx->mode = pIndEvt->value;
#ifdef STAND_ALONE_MINIUPNP
							//sending byebye
							WSC_DEBUG("!!	sending byebye\n\n");
                            SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
                                &pCtx->upnp_info.SSDP, 1, 1);
#endif
                            init_config(pCtx,1);
                            if(pCtx->c_pin_timeout !=0 ){
                    		pCtx->pin_timeout = pCtx->c_pin_timeout;
                    	} else {
                    		pCtx->pin_timeout = RESET_WAIT_TIME;
                    	}
                            _DEBUG_PRINT("<< EV_MODE mode:%x >>\n",pCtx->mode);
                    }
            }
            break;
    case EV_METHOD:
            {
                    DOT11_WSC_IND *pIndEvt = (DOT11_WSC_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
                    if( pIndEvt->value == 1 ){
                            pCtx->current_config_mode = CONFIG_METHOD_PIN;
                            pCtx->pin_timeout = RESET_WAIT_TIME;
                    } else {
                            pCtx->current_config_mode = CONFIG_METHOD_PBC;
                            pCtx->pb_timeout = RESET_WAIT_TIME;
                    }
                    pCtx->start_config_client = 0;
            }
            break;
#endif  //ifdef CONFIG_IWPRIV_INTF
#ifdef P2P_SUPPORT
    case EV_HELP_CHANGE_WLAN_MODE:
        {
            DOT11_P2P_INDICATE_WSC *pIndEvt;
            char tmpbuf2[64];
			pIndEvt = (DOT11_P2P_INDICATE_WSC *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
			WSC_DEBUG("\n\n<< P2P event WPS change wlan mode >>\n\n");
           if(pIndEvt->interfacename){
                
                sprintf(tmpbuf2,"ifconfig %s down up",(pIndEvt->interfacename));
                system(tmpbuf2);  
    			WSC_DEBUG("cmd [%s]\n",tmpbuf2);                
           }            

            break;
        }
    case EV_P2P_SWITCH_MODE:
		{
            DOT11_P2P_INDICATE_WSC *pIndEvt;
            char tmpbuf2[64];
			pIndEvt = (DOT11_P2P_INDICATE_WSC *)&pCtx->rx_buffer[FIFO_HEADER_LEN];

			WSC_DEBUG("\n\n<< P2P event WPS >>\n\n");

			// mode
			if(pIndEvt->modeSwitch){

                if(pIndEvt->modeSwitch==P2P_PRE_GO){
                    
				    pCtx->mode = MODE_AP_PROXY_REGISTRAR ;
    				pCtx->p2p_trigger_type=P2P_PRE_GO;                                        
                    
                }else if(pIndEvt->modeSwitch==P2P_TMP_GO){
                
				    pCtx->mode = MODE_AP_PROXY_REGISTRAR ;                
                    
                }else if(pIndEvt->modeSwitch==P2P_PRE_CLIENT){
                
				    pCtx->mode = MODE_CLIENT_UNCONFIG ;      

    				pCtx->p2p_trigger_type=P2P_PRE_CLIENT;                    
                }
                
				P2P_DEBUG("mode switch to %d\n" ,pCtx->mode);
                /*2015 0806*/
                if(pIndEvt->interfacename){
                    if(!memcmp("wl0",pIndEvt->interfacename,strlen("wl0"))){
                        pCtx->InterFaceComeIn = COME_FROM_WLAN0;
        				P2P_DEBUG("COME_FROM_WLAN0\n");
                    }else if(!memcmp("wl1",pIndEvt->interfacename,strlen("wl1"))){
                        pCtx->InterFaceComeIn = COME_FROM_WLAN1;
        				P2P_DEBUG("COME_FROM_WLAN1\n");
                        
                    }else{
        				P2P_DEBUG("unknown wlan interface default let it COME_FROM_WLAN0\n");
                    }
               }
                /*2015 0806*/
				pCtx->mode_switch=1;
				init_config(pCtx, 0);

				if (pCtx->is_ap) {
					pCtx->start = 1;
				} else {
					pCtx->start = 0;
					client_set_WlanDriver_WscEnable(pCtx, 0);
				}

				init_wlan(pCtx, 1);
			}else{
				WSC_DEBUG("mode no need change\n");
			}

			if(pCtx->mode == MODE_AP_PROXY_REGISTRAR){
                if(pCtx->InterFaceComeIn == COME_FROM_WLAN0){
                    //  PSK
                    if(strlen(pIndEvt->network_key)){
                        strcpy(pCtx->network_key , pIndEvt->network_key );
                        pCtx->network_key_len = strlen(pCtx->network_key);
                        P2P_DEBUG("PSK switch to [%s]\n" ,pCtx->network_key);
                    }
                    
                    
                    // SSID
                    strcpy(pCtx->SSID, pIndEvt->gossid);
                    
                    // Auth  Eencrypt
                    pCtx->auth_type_flash = WSC_AUTH_WPA2PSK;
                    pCtx->encrypt_type_flash = WSC_ENCRYPT_AES;

                }else{
                    //  PSK
                    if(strlen(pIndEvt->network_key)){
                        strcpy(pCtx->network_key2 , pIndEvt->network_key );
                        pCtx->network_key_len2 = strlen(pCtx->network_key2);
                        P2P_DEBUG("PSK switch to [%s]\n" ,pCtx->network_key2);
                    }
                    
                    
                    // SSID
                    strcpy(pCtx->SSID2, pIndEvt->gossid);
                    
                    // Auth  Eencrypt
                    pCtx->auth_type_flash2 = WSC_AUTH_WPA2PSK;
                    pCtx->encrypt_type_flash2 = WSC_ENCRYPT_AES;

                }
				//system("udhcpd /var/udhcpd.conf");
				//printf("\n\nsystem: udhcpd /var/udhcpd.conf\n\n");

			}


			if(pIndEvt->trigger_method == P2P_PIN_METHOD){
				P2P_DEBUG("PIN method use\n");

				if(pCtx->mode == MODE_AP_PROXY_REGISTRAR){

					if(pIndEvt->whosPINuse == USE_MY_PIN){
						P2P_DEBUG("USE_MY_PIN(%s)\n",pCtx->pin_code);

						if(pIndEvt->requestor)
							pCtx->device_password_id = PASS_ID_REG ;


						evHandler_pin_input(pCtx,pCtx->pin_code);

					}else if(pIndEvt->whosPINuse == USE_TARGET_PIN){

						P2P_DEBUG("USE_TARGET_PIN(%s)\n",pIndEvt->PINCode);

						if(pIndEvt->requestor)
							pCtx->device_password_id = PASS_ID_DEFAULT ;

						evHandler_pin_input(pCtx,pIndEvt->PINCode);

					}else{

						P2P_DEBUG("unknow type\n");
					}


				}
				else if(pCtx->mode == MODE_CLIENT_UNCONFIG){

					if(pIndEvt->whosPINuse == USE_MY_PIN){
						if(pIndEvt->requestor)
							pCtx->device_password_id = PASS_ID_DEFAULT ;

						sprintf(tmpbuf2,"wscd -sig_start %s",GET_CURRENT_INTERFACE);
						system(tmpbuf2);                        
						P2P_DEBUG("USE_MY_PIN[%s], issue [system cmd[%s]]\n",pCtx->pin_code,tmpbuf2);

					}else if(pIndEvt->whosPINuse == USE_TARGET_PIN){
						strcpy(pCtx->pin_code,pIndEvt->PINCode);
						if(pIndEvt->requestor)
							pCtx->device_password_id = PASS_ID_REG ;

						sprintf(tmpbuf2,"wscd -sig_start %s",GET_CURRENT_INTERFACE);
						system(tmpbuf2);                                              
						P2P_DEBUG("USE_TARGET_PIN[%s] issue [system cmd[%s]]\n",pIndEvt->PINCode,tmpbuf2);                        
					}else{
						P2P_DEBUG("unknow type\n");
					}

				}


			}
			else if(pIndEvt->trigger_method == P2P_PBC_METHOD){
				evHandler_pb_press(pCtx);
			}else{
				WSC_DEBUG("\njust change mode\n");
			}

    	}
        break;

#endif
		/* support  change STA PIN code, 2011-0505 */
	    case EV_CHANGE_MY_PIN:
         {
            DOT11_WSC_PIN_IND *pIndEvt = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
			int code=0;
			if(!pCtx->is_ap){
				if (strlen(pIndEvt->code) == PIN_LEN) {
					code = atoi(pIndEvt->code);
					if (!validate_pin_code(code)) {
						WSC_DEBUG("PIN Checksum error!\n");
					}
					else{
						strcpy(pCtx->peer_pin_code, pIndEvt->code);
						strcpy(pCtx->pin_code, pIndEvt->code);
						strcpy(pCtx->original_pin_code, pIndEvt->code);
					}
				}
			}
         }
         break;

		/* when the mac addr of  wlan interface has changed by macclone ,  2015-1008 */
	    case EV_MAC_HAS_CHANGED:
         {
            DOT11_WSC_PIN_IND *pIndEvt = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
			//int code=0;
			if(!pCtx->is_ap){
				if (strlen(pIndEvt->code) == ETHER_ADDRLEN) {
					memcpy(pCtx->our_addr,pIndEvt->code,ETHER_ADDRLEN);
						//printf("our_addr has changed=[%02x:%02x:%02x:%02x:%02x:%02x]\n",
						//pCtx->our_addr[0], pCtx->our_addr[1], pCtx->our_addr[2],
						//pCtx->our_addr[3], pCtx->our_addr[4], pCtx->our_addr[5]);
				}
			}
         }
         break;


		

		/* support  Assigned SSID, 2011-0505 */
	    case EV_SPEC_SSID:
         {
            DOT11_WSC_PIN_IND *pIndEvt = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
			if(!pCtx->is_ap){
				if (strlen(pIndEvt->code) && strlen(pIndEvt->code) <= 32) {
					strcpy(pCtx->SPEC_SSID , pIndEvt->code);
				}
			}
         }
         break;

		/* support  Assigned MAC Addr, 2011-0505 */
	    case EV_SET_SPEC_CONNECT_MAC:
         {
            DOT11_WSC_PIN_IND *pIndEvt = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
			if(!pCtx->is_ap){
				if(strlen(pIndEvt->code) == 12){
					if(string_to_hex(pIndEvt->code , pCtx->SPEC_MAC, 12)){
						WSC_DEBUG("	Spec Mac Addr:%s\n",pIndEvt->code);
					}else{
						WSC_DEBUG("	invaild Spec Mac Addr:%s\n",pIndEvt->code);
						memset(pCtx->SPEC_MAC,0,6);
					}
				}
			}

         }
         break;
	    case EV_CHANGE_MODE:
         {
            DOT11_WSC_PIN_IND *pIndEvt = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];

			if(strlen(pIndEvt->code) != 1){
				WSC_DEBUG("len!=1, chk!!\n");
				break;
			}

			WSC_DEBUG("mode switch to %s\n" ,pIndEvt->code);
			// mode 3:ER ; 2:enrollee
			i = atoi(pIndEvt->code);
			if(i== MODE_CLIENT_UNCONFIG_REGISTRAR || i==MODE_CLIENT_CONFIG || i==MODE_CLIENT_UNCONFIG){
				pCtx->mode = i ;
				WSC_DEBUG("mode switch to %d\n" ,pCtx->mode);
				pCtx->mode_switch=1;
				init_config(pCtx, 0);

				if (pCtx->is_ap) {
					pCtx->start = 1;
				}else{
					pCtx->start = 0;
					client_set_WlanDriver_WscEnable(pCtx, 0);
				}
				init_wlan(pCtx, 1);
			}else{
				WSC_DEBUG("other case no support now \n");
			}


         }
         break;
	    case EV_RM_PBC_STA:
         {

			
			struct _DOT11_WSC_PIN_IND* wsc_ind=NULL;		
	        wsc_ind= (struct _DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];

			//WSC_DEBUG("EventId should be == %d , real=[%d]",DOT11_EVENT_WSC_RM_PBC_STA,wsc_ind->EventId);

			WSC_DEBUG("rm pbc sta indicate from driver(2)\n");
					
			/* Sta no included pbc ID ; 
		       check at active pbc sta list ; if exist then remove it */ 							
			WSC_pthread_mutex_lock(&pCtx->PBCMutex);
			remove_active_pbc_sta(pCtx, (unsigned char*)wsc_ind->code, 1);
			WSC_pthread_mutex_unlock(&pCtx->PBCMutex);		

         }
         break;

		default:
			printf("======%s(%d), don't support event\n", __FUNCTION__, __LINE__);
			break;
	}
#if 0
//#ifdef WSC_CLIENT_MODE
	if (!pCtx->is_ap && pCtx->start) {
		if (pCtx->connect_fail) {
			DEBUG_PRINT("%s %d Issue re-connect\n", __FUNCTION__, __LINE__);
			if (!connect_wps_ap(pCtx, pCtx->connect_method))
				issue_scan_req(pCtx, pCtx->connect_method);
		}
	}
#endif
}

#ifdef TEST
#include <string.h>
#include <openssl/hmac.h>

typedef struct {
	const char *key, *iv;
	unsigned char kaval[EVP_MAX_MD_SIZE];
} HMAC_KAT;

static const HMAC_KAT vector= {
	"0123456789:;<=>?@ABC",
	"Sample #2",
	{ 0xb8,0xf2,0x0d,0xb5,0x41,0xea,0x43,0x09,
	  0xca,0x4e,0xa9,0x38,0x0c,0xd0,0xe8,0x34,
	  0xf7,0x1f,0xbe,0x91,0x74,0xa2,0x61,0x38,
	  0x0d,0xc1,0x7e,0xae,0x6a,0x34,0x51,0xd9 }
};

static int run_test(CTX_Tp pCtx)
{
	int sel, intv[10], i;
	char tmpbuf[100];
	struct timeval tod;
	unsigned long num;
	DOT11_WSC_ASSOC_IND *pAssocInd;
	DOT11_WSC_PIN_IND *pPinInd;

display_cmd:
	printf("\nTest commands:\n");
	printf("\t1. generate PIN code\n");
	printf("\t2. set local mac address\n");
	printf("\t3. set remote mac address\n");
	printf("\t4. generate asso_ind evnet\n");
	printf("\t5. assign PIN code\n");
	printf("\t6. generate PB pressed\n\n");

	printf("\t7. send EAP rsp-id\n");
	printf("\t8. send EAP M1\n");
	printf("\t9. send EAP M2\n\n");
	printf("\t10. hmac-sha256 test\n");
#ifdef WSC_CLIENT_MODE
	printf("\t11. scan-request\n");
#endif

	printf("\t12. return & continue\n");
	printf("\t0. exit\n");

	printf("\n\tSelect? ");

	scanf("%d", &sel);

	switch(sel) {
	case 1:
		gettimeofday(&tod , NULL);
		srand(tod.tv_sec);
		num = rand() % 10000000;
		num = num*10 + compute_pin_checksum(num);
		convert_hex_to_ascii((unsigned long)num, tmpbuf);
		printf("PIN: %s\n", tmpbuf);
		strcpy(pCtx->pin_code, tmpbuf);
		break;

	case 2:
		printf("\nsrc mac addr? ");
		scanf("%s", tmpbuf);
		sscanf(tmpbuf, "%02x%02x%02x%02x%02x%02x",
				&intv[0], &intv[1], &intv[2],
				&intv[3], &intv[4], &intv[5]);
		for (i=0; i<6; i++)
			pCtx->our_addr[i] = (unsigned char)intv[i];
		break;

	case 3:
		printf("\nremote mac addr? ");
		scanf("%s", tmpbuf);
		sscanf(tmpbuf, "%02x%02x%02x%02x%02x%02x",
				&intv[0], &intv[1], &intv[2],
				&intv[3], &intv[4], &intv[5]);
		for (i=0; i<6; i++)
			pCtx->sta[0]->addr[i] = (unsigned char)intv[i];
		pCtx->sta[0]->used = 1;
		break;

	case 4: // generate assoc_ind
		printf("\npeer mac addr? ");
		scanf("%s", tmpbuf);
		sscanf(tmpbuf, "%02x%02x%02x%02x%02x%02x",
				&intv[0], &intv[1], &intv[2],
				&intv[3], &intv[4], &intv[5]);
		pAssocInd = (DOT11_WSC_ASSOC_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
		for (i=0; i<6; i++)
			pAssocInd->MACAddr[i] = (unsigned char)intv[i];
		process_event(pCtx, EV_ASSOC_IND);
		break;

	case 5:
		printf("\nInput PIN code? ");
		scanf("%s", tmpbuf);
		pPinInd = (DOT11_WSC_PIN_IND *)&pCtx->rx_buffer[FIFO_HEADER_LEN];
		strcpy(pPinInd->code, tmpbuf);
		process_event(pCtx, EV_PIN_INPUT);
		break;

	case 6:
		process_event(pCtx, EV_PB_PRESS);
		break;

	case 7: // send rsp-id
		printf("\nidentifier? ");
		scanf("%d", &i);
		pCtx->sta[0]->eap_reqid = i;
		send_eap_rspid(pCtx, (STA_CTX_Tp)&pCtx->sta[0]);
		break;

	case 8: // send M1
		send_wsc_M1(pCtx, (STA_CTX_Tp)&pCtx->sta[0]);
		break;

	case 9: // send M2
		send_wsc_M2(pCtx, (STA_CTX_Tp)&pCtx->sta[0]);
		break;

	case 10:
//		hmac_sha256(vector.iv, strlen(vector.iv), vector.key, strlen(vector.key), tmpbuf,  &i);
//		if (memcmp(tmpbuf, vector.kaval, BYTE_LEN_256B))
//			printf("test failed!\n");
//		else
//			printf("test ok.\n");
		break;

#ifdef WSC_CLIENT_MODE
	case 11:
		WSC_DEBUG("Issue scan\n");
		issue_scan_req(pCtx ,pCtx->connect_method);
		break;
#endif

	case 12:
		return 0;
	case 0:
		return -1;
	}
	goto display_cmd;
}
#endif // TEST

#ifdef SUPPORT_UPNP
static STA_CTX_Tp search_registra_entry_by_IP(CTX_Tp pCtx, char *addr)
{
	int i, idx=-1;

	for (i=0; i<WSC_MAX_STA_NUM; i++) {
		if (!pCtx->sta[i] || pCtx->sta[i]->used == 0) {
			if (idx < 0)
				idx = i;
			continue;
		}
		if (strcmp(pCtx->sta[i]->ip_addr, addr) == 0)
			break;
	}

	if ( i != WSC_MAX_STA_NUM)
		return (pCtx->sta[i]);

	if (idx >= 0 && pCtx->num_ext_registrar < MAX_EXTERNAL_REGISTRAR_NUM) {
		pCtx->sta[idx] = calloc(1, sizeof(STA_CTX));
		return pCtx->sta[idx];
	}
	else {
		unsigned int largest=0;
		idx=0;

		for (i=0; i<WSC_MAX_STA_NUM; i++) {
			if (!pCtx->sta[i] || !(pCtx->sta[i]->used & IS_UPNP_CONTROL_POINT))
				continue;
			if (strcmp(pCtx->sta[i]->ip_addr, pCtx->SetSelectedRegistrar_ip) == 0)
				continue;
			unsigned int time_offset = difftime(time(NULL), pCtx->sta[i]->time_stamp);
			if (time_offset > largest) {
				idx = i;
				largest = time_offset;
			}
		}
		DEBUG_PRINT("Registrar table full; replace IP[%s]\n", pCtx->sta[idx]->ip_addr);
		if (pCtx->sta[idx]->dh_enrollee){
			DH_free(pCtx->sta[idx]->dh_enrollee);
			pCtx->sta[idx]->dh_enrollee = NULL;

		}

		if (pCtx->sta[idx]->dh_registrar){
			DH_free(pCtx->sta[idx]->dh_registrar);
			pCtx->sta[idx]->dh_registrar = NULL;
		}
		memset(pCtx->sta[idx], 0, sizeof(STA_CTX));

		if(pCtx->num_ext_registrar)
			pCtx->num_ext_registrar--;
		WSC_DEBUG("ER count=%d\n", pCtx->num_ext_registrar);

		return (pCtx->sta[idx]);
	}
}

int PWSCUpnpCallbackEventHandler(struct WSC_packet *packet, void *Cookie)
{
	CTX_Tp pCtx = (CTX_Tp)Cookie;
	STA_CTX_Tp pSta;
	STA_CTX_Tp pSta_enrollee=NULL;
	int tag_len;
	unsigned char *pData;
	int ret = WSC_UPNP_FAIL;
	int num_sta=0;
	int i=0;
	unsigned char tmp[ETHER_ADDRLEN];
	char *ptr=(packet->EventMac);
	unsigned char *DTMPtr=NULL;

	if (pCtx->registration_on >= 1) {
		if (packet->EventID == WSC_GETDEVINFO) {
			DEBUG_PRINT("%s %d Registration protocol is already in progress; uses cached sta context\n", __FUNCTION__, __LINE__);
			if (pCtx->cached_sta.dh_enrollee){
				DH_free(pCtx->cached_sta.dh_enrollee);
				pCtx->cached_sta.dh_enrollee=NULL;
			}
			if(pCtx->cached_sta.dh_registrar){
				DH_free(pCtx->cached_sta.dh_registrar);
				pCtx->cached_sta.dh_registrar=NULL;
			}
			memset(&pCtx->cached_sta, 0, sizeof(STA_CTX));
			pCtx->cached_sta.used = (1 | IS_UPNP_CONTROL_POINT);
			ret = send_wsc_M1(pCtx, &pCtx->cached_sta);


			if (ret == 0) {	// under IS_UPNP_CONTROL_POINT =1 ;not real send M1 ; plus note
				pCtx->cached_sta.state = ST_WAIT_M2;
				pCtx->cached_sta.tx_timeout = 0;
				pCtx->cached_sta.retry = 0;
			}
			else{
				send_wsc_nack(pCtx, &pCtx->cached_sta, CONFIG_ERR_CANNOT_CONNECT_TO_REG);
			}
			packet->tx_buffer = pCtx->cached_sta.tx_buffer;
			packet->tx_size = pCtx->cached_sta.last_tx_msg_size;
			return WSC_UPNP_SUCCESS;
		}
		else if (packet->EventID == WSC_M2M4M6M8) {
			pData = search_tag(packet->rx_buffer, TAG_MSG_TYPE, packet->rx_size, &tag_len);
			if (pData == NULL) {
				WSC_DEBUG("ERROR, Can't find MessageType tag in UPNP msg!\n");
				packet->tx_buffer = NULL;
				packet->tx_size = 0;
				return WSC_UPNP_SUCCESS;
			}
			else {
				if (pData[0] == MSG_TYPE_M2) {
					pData = search_tag(packet->rx_buffer, TAG_REGISTRAR_NONCE, packet->rx_size, &tag_len);
					if (pData == NULL) {
						DEBUG_ERR("ERROR, Can't find REGISTRAR_NONCE tag in UPNP msg!\n");
						packet->tx_buffer = NULL;
						packet->tx_size = 0;
						return WSC_UPNP_SUCCESS;
					}
					memcpy(&pCtx->cached_sta.nonce_registrar, pData, tag_len);
					if (pCtx->cached_sta.used) {
						send_wsc_nack(pCtx, &pCtx->cached_sta, CONFIG_ERR_DEV_BUSY);
						packet->tx_buffer = pCtx->cached_sta.tx_buffer;
						packet->tx_size = pCtx->cached_sta.last_tx_msg_size;
					}
					else {
						packet->tx_buffer = NULL;
						packet->tx_size = 0;
					}

					return WSC_UPNP_SUCCESS;
				}

				// remove SER_AP_SPEC flag ; let it be genernal apply
				//  if ER config us(AP) by upnp base , make sure profile apply to both interface
				if (pData[0] == MSG_TYPE_M8) {

					WSC_DEBUG("\n\n\nM8 message from upnp ER\n\n\n");

					if(pCtx->ProfileDontBothApply)
						pCtx->ProfileDontBothApply = 0 ;
				}

			}
		}
	}
	//else {
		//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
		//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
	//}

	pSta = search_registra_entry_by_IP(pCtx, packet->IP);
	if (pSta == NULL) {
		DEBUG_ERR("ERROR in registrar table!\n");
		goto ret_callback;
	}
	if (packet->EventID == WSC_GETDEVINFO ||
		packet->EventID == WSC_SETSELECTEDREGISTRA ||
		packet->EventID == WSC_PUTWLANRESPONSE) {
		if (!pSta->setip) {
			pCtx->num_ext_registrar++;
			pSta->used = 1 | IS_UPNP_CONTROL_POINT;
			strcpy(pSta->ip_addr, packet->IP);
			pSta->setip = 1;
			WSC_DEBUG("Start commu with upnp ER (%s)\n", pSta->ip_addr);
			WSC_DEBUG("ER count=%d\n", pCtx->num_ext_registrar);
		}
	}
	else {
		if (pSta->setip == 0 || pSta->used == 0) {
			if (pSta->setip)
				pCtx->num_ext_registrar--;
			if (pSta->dh_enrollee){
				DH_free(pSta->dh_enrollee);
				pSta->dh_enrollee = NULL;
			}
			if (pSta->dh_registrar){
				DH_free(pSta->dh_registrar);
				pSta->dh_registrar = NULL;
			}
			memset(pSta, 0, sizeof(STA_CTX));
			WSC_DEBUG("ERROR,chk Registrar's table or invalid state!\n");
			WSC_DEBUG("ER count=%d\n", pCtx->num_ext_registrar);

			goto ret_callback;
		}
	}
	pSta->time_stamp = time(NULL);

	switch (packet->EventID) {
		case WSC_GETDEVINFO:
			if (pSta->state != ST_WAIT_M2) {
				reset_sta(pCtx, pSta, 0);
				ret = send_wsc_M1(pCtx, pSta);
			}
			else // use the cached M1 and send to the external registrar
				ret = 0;
			if (ret == 0) {
				pSta->state = ST_WAIT_M2;
				pSta->tx_timeout = 0;
				pSta->retry = 0;
			}
			else {
				send_wsc_nack(pCtx, pSta, CONFIG_ERR_CANNOT_CONNECT_TO_REG);
				reset_sta_UPnP(pCtx, pSta);
			}
			packet->tx_buffer = pSta->tx_buffer;
			packet->tx_size = pSta->last_tx_msg_size;
			pSta->reg_timeout = pCtx->reg_timeout;

			ret = WSC_UPNP_SUCCESS;
			break;

		case WSC_SETSELECTEDREGISTRA:
			ret = pktHandler_upnp_select_msg(pCtx, pSta, packet);
			if (ret == 0)
				ret = WSC_UPNP_SUCCESS;
			else
				ret = WSC_UPNP_FAIL;
			break;

		case WSC_M2M4M6M8:
			ret = pktHandler_wsc_msg(pCtx, pSta, (struct eap_wsc_t *)packet, packet->rx_size);
			if ((ret > 0) || (ret == 0)) {
				if (ret > 0) {
					send_wsc_nack(pCtx, pSta, ret);
					reset_sta_UPnP(pCtx, pSta);
				}
				packet->tx_buffer = pSta->tx_buffer;
				packet->tx_size = pSta->last_tx_msg_size;
			}
			else {
				reset_sta_UPnP(pCtx, pSta);
				if (pSta->state == ST_WAIT_ACK) {
					packet->tx_buffer = pSta->tx_buffer;
					packet->tx_size = pSta->last_tx_msg_size;
				}
				else {
					packet->tx_buffer = NULL;
					packet->tx_size = 0;
				}
			}

			ret = WSC_UPNP_SUCCESS;
			break;

		case WSC_PUTWLANRESPONSE:
			pData = search_tag(packet->rx_buffer, TAG_MSG_TYPE, packet->rx_size, &tag_len);
			if (pData == NULL) {
				DEBUG_ERR("ERROR, Can't find MessageType tag in UPNP msg!\n");
				return WSC_UPNP_FAIL;
			}

			if (pCtx->setSelectedRegTimeout) {
				if (memcmp(pCtx->SetSelectedRegistrar_ip, packet->IP, IP_ADDRLEN)) {
					DEBUG_PRINT("Ignore UPnP message from external UPnP registrar [%s]\n", packet->IP);
					return WSC_UPNP_SUCCESS;
				}
			}

			if (pData[0] != MSG_TYPE_M2 && pData[0] != MSG_TYPE_M2D &&
				pData[0] != MSG_TYPE_M4 && pData[0] != MSG_TYPE_M6 &&
				pData[0] != MSG_TYPE_M8 && pData[0] != MSG_TYPE_NACK
				)
			{
				DEBUG_ERR("ERROR, invalid MessageType tag [0x%x] in UPNP msg!\n", pData[0]);
				return WSC_UPNP_FAIL;
			}

			if( pData[0] == MSG_TYPE_M2 ) {
				//unsigned char i;
				DTMPtr = search_tag(packet->rx_buffer, TAG_MANUFACTURER, packet->rx_size, &tag_len);
				if (DTMPtr != NULL) {
					unsigned char device[20]={"Manufacturer"}, model_num[10]="TF", serial_num[10]={"TF123456"};
					i = 0;
					if( !memcmp(device,DTMPtr,strlen((char *)device))) {

						DTMPtr = search_tag(packet->rx_buffer, TAG_MODEL_NUMBER, packet->rx_size, &tag_len);
						if (DTMPtr != NULL && !memcmp(DTMPtr,model_num,strlen((char *)model_num)))
							i++;

						DTMPtr = search_tag(packet->rx_buffer, TAG_SERIAL_NUM, packet->rx_size, &tag_len);
						if (DTMPtr != NULL && !memcmp(DTMPtr,serial_num,strlen((char *)serial_num)))
							i++;

						if(i==2)
							pCtx->ERisDTM = 1;

					}


				}
			}

			memset(tmp, 0, ETHER_ADDRLEN);
			for (i=0; i<ETHER_ADDRLEN; i++, ptr+=3) {
				if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
					DEBUG_ERR("Invalid Mac address from UPnP registrar!\n");
					return WSC_UPNP_FAIL;
				}
				tmp[i] = convert_atob(ptr, 16);
			}




			for (num_sta=0; num_sta<WSC_MAX_STA_NUM; num_sta++) {
				if (!pCtx->sta[num_sta] || !pCtx->sta[num_sta]->used || (pCtx->sta[num_sta]->used & IS_UPNP_CONTROL_POINT))
					continue;
				if (memcmp(pCtx->sta[num_sta]->addr, tmp, ETHER_ADDRLEN) == 0) {
					pSta_enrollee = pCtx->sta[num_sta];
					break;
				}
			}

			if (num_sta >= WSC_MAX_STA_NUM) {
				i = -1;
				WSC_DEBUG("Enrollee Mac address not found; trying to search an exist proxyed enrollee!\n");
				for (num_sta=0; num_sta<WSC_MAX_STA_NUM; num_sta++) {
					if (!pCtx->sta[num_sta] || !pCtx->sta[num_sta]->used || (pCtx->sta[num_sta]->used & IS_UPNP_CONTROL_POINT))
						continue;
					if ((pCtx->sta[num_sta]->state < ST_UPNP_DONE) || (pCtx->sta[num_sta]->state > ST_UPNP_WAIT_DONE))
						continue;
					i = num_sta;
					WSC_DEBUG("An Enrollee  has been found!\n");
					MAC_PRINT(pCtx->sta[num_sta]->addr);
					break;
				}
				if (i == -1) {
					DEBUG_ERR("Enrollee Mac address not found\n");
					goto ret_callback;
				}
				else
					pSta_enrollee = pCtx->sta[i];
			}

			/* 20101102 -start */
			//WSC_DEBUG("send_upnp_to_wlan\n");
			ret = send_upnp_to_wlan(pCtx, pSta_enrollee, packet);

			if(ret == 0){	/*sent to STA success*/
				WSC_DEBUG("ER(%s) Rsp ( ",packet->IP);
			   if(pData[0]==MSG_TYPE_M2D){

					pSta_enrollee->state = ST_WAIT_ACK;
					_DEBUG_PRINT("M2D");

			   }else if(pData[0]==MSG_TYPE_M2){

					pSta_enrollee->state = ST_UPNP_PROXY;
					_DEBUG_PRINT("M2");
			   }else if(pData[0]==MSG_TYPE_M4){

					pSta_enrollee->state = ST_UPNP_PROXY;
					_DEBUG_PRINT("M4");
			   }else if(pData[0]==MSG_TYPE_M6){

					pSta_enrollee->state = ST_UPNP_PROXY;
					_DEBUG_PRINT("M6");

			   }else if(pData[0]==MSG_TYPE_M8){

					pSta_enrollee->state = ST_UPNP_WAIT_DONE;
					ret = WSC_UPNP_SUCCESS;
					_DEBUG_PRINT("M8");

			   }

			   _DEBUG_PRINT(" ) to STA\n");
			   //MAC_PRINT(pSta_enrollee->addr);
			}

			/* 20101102 -end */
			break;

#if 0
		case WSC_REBOOT:
			if (pSta->state != ST_UPNP_WAIT_REBOOT) {
				DEBUG_ERR("ERROR, got UPnP WSC_REBOOT evt, but invalid state [%d]!\n", pSta->state);
				ret = WSC_UPNP_FAIL;
			}
			else {
				reset_sta(pCtx, pSta);
				signal_webs(REINIT_SYS);

				ret = WSC_UPNP_SUCCESS;
			}
			break;
#endif

   		default:
	    		WSC_DEBUG("Unknown event type(%d)\n",packet->EventID);
	    		break;
    }

ret_callback:
    return ret;
}

static int start_upnp(CTX_Tp pCtx)
{
	int ret=0;
	struct WSC_profile *profile=NULL;

	_DEBUG_PRINT("<< Start_upnp >>\n");
	profile = (struct WSC_profile *)malloc(sizeof(struct WSC_profile));
	if (profile == NULL)
		return -1;
	memset(profile, 0, sizeof(struct WSC_profile));
	memcpy(profile->uuid, pCtx->uuid, UUID_LEN);
	profile->manufacturer = pCtx->manufacturer;
	profile->model_name = pCtx->model_name;
	profile->model_num = pCtx->model_num;
	profile->serial_num = pCtx->serial_num;
	profile->device_name = pCtx->device_name;
	profile->manufacturerURL = pCtx->manufacturerURL;
	profile->modelURL = pCtx->model_URL;
	profile->modelDescription = pCtx->manufacturerDesc;
	profile->UPC= pCtx->UPC;	
	if(WSCRegisterCallBackFunc(PWSCUpnpCallbackEventHandler, pCtx) != WSC_UPNP_SUCCESS) {
		free(profile);
		return -1;
	}
	if (pCtx->is_ap)
		ret = WSCUpnpStart(pCtx->lan_interface_name, WSC_AP_MODE, profile);
	else
		ret = WSCUpnpStart(pCtx->lan_interface_name, WSC_STA_MODE, profile);
	free(profile);
	if(!ret) {
		SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
			&pCtx->upnp_info.SSDP, 0, pCtx->upnp_info.SSDP.max_age);
		pCtx->upnp_info.SSDP.alive_timeout = pCtx->upnp_info.SSDP.max_age/2;
	}
	return ret;
}
#endif

#if	defined(CONFIG_RTL865x_KLD_REPEATER) || defined(CONFIG_RTL_REPEATER_WPS_SUPPORT)

int checkWlanIfState(char *wlanif_name)
{
	unsigned char tmpStr[100];
	FILE *stream;
	int ret = -1;
	memset(tmpStr,0x00,sizeof(tmpStr));
	sprintf((char *)tmpStr,"/proc/%s/sta_info",wlanif_name);
	stream = fopen ((char *)tmpStr, "r" );
	if ( stream != NULL )
	{		
		char *strtmp;
		char line[100];
		while (fgets(line, sizeof(line), stream))
		{
			unsigned char *p;
			strtmp = line;
			while(*strtmp == ' ')
				strtmp++;
			if(strstr(strtmp,"active") != 0)
			{
				unsigned char str1[10];
				sscanf(strtmp, "%*[^:]:%[^)]",str1);
				p = str1;
				while(*p == ' ')
					p++;										
				if(strcmp((char *)p,"0") == 0)
				{
					ret = 0;	//wlan interface is on, but no active client
				}
				else
				{
					ret = 1;	//wlan interface is on and has active client					
				}										
				break;
			}
		}
		fclose(stream );
	}
	else
		ret = -1; //wlan interface is not on
	return ret;
}
int isWlanRootConnect(unsigned char *wlanif_name)
{
	FILE *stream;
	char tmpStr[100];
	int isLink=0;

	sprintf(tmpStr,"/var/wlan_state");
	stream = fopen (tmpStr, "r" );
	if ( stream != NULL )
	{
		char *strtmp;
		char line[100];
		while (fgets(line, sizeof(line), stream))
		{
			//unsigned char *p;
			strtmp = line;

			while(*strtmp == ' ')
				strtmp++;

			sprintf(tmpStr,"%s LINK",wlanif_name);
			if(strstr(strtmp,tmpStr) != 0)
			{
				isLink = 1;
				break;
			}
		}
		fclose(stream );

	}

	return isLink;
}
#endif




#ifdef WSC_1SEC_TIMER
static int wsc_alarm(void)
{
	struct itimerval val;

// Fix warning message shown in 2.6 -------
	#if 0
	val.it_interval.tv_sec = 0;
	val.it_interval.tv_usec = BASIC_TIMER_UNIT;
	val.it_value.tv_sec = 0;
	val.it_value.tv_usec = BASIC_TIMER_UNIT;
	#endif
	val.it_interval.tv_sec = 1;
	val.it_interval.tv_usec = 0;
	val.it_value.tv_sec = 1;
	val.it_value.tv_usec = 0;
//-------------------- david+2008-06-11

	if (setitimer( ITIMER_REAL, &val, 0 ) == -1)
	{
		DEBUG_ERR("Error in alarm\n");
		return -1;
	}
	else
		return 0;
}
#endif


#ifdef __ECOS
int sigHandler_alarm(int signo)
#else
#ifdef WSC_1SEC_TIMER
static int sigHandler_alarm(int signo)
#else
static void sigHandler_alarm(int signo)
#endif
#endif
{
	int i;
	CTX_Tp pCtx = pGlobalCtx;
#ifdef __ECOS
	time_t timetmp;
#else
	struct stat cancel_status;
#endif
	int wlan0_vxd_state=-1, wlan1_vxd_state=-1;	//-1 means vxd dont do wps now

#ifdef USE_POLLING
	wlanIndEvt(0);
#endif

#ifdef AUTO_LOCK_DOWN

#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION	/*for WFA new means , indefinite lockdown*/
	if(0)
#else
	if(pCtx->auto_lock_down > 0)
#endif
	{
		
		pCtx->auto_lock_down --;

#ifdef DEBUG		
		if(pCtx->auto_lock_down%10 ==0){
			WSC_DEBUG("auto_lock_down [%d]\n",pCtx->auto_lock_down);
		}
#endif
		if(pCtx->auto_lock_down == 0)
			InOut_auto_lock_down(pCtx,0);	// leave lock state

	}
#endif

	for (i=0; i<WSC_MAX_STA_NUM; i++) {
		if (pCtx->sta[i] && pCtx->sta[i]->used) {
			if (pCtx->sta[i]->reg_timeout > 0 &&
			--pCtx->sta[i]->reg_timeout <= 0) {

				DEBUG_ERR("STA's Registration timeout, abort registration!\n");
				MAC_PRINT(pCtx->sta[i]->addr);


				if (pCtx->wait_reinit) {
					WSC_DEBUG("signal_webs\n");
					signal_webs(pCtx->wait_reinit);
				}

				// Reason code 1 : Unspecified reason
				if (pCtx->is_ap && !(pCtx->sta[i]->used & IS_UPNP_CONTROL_POINT) &&
					(pCtx->sta[i]->Assoc_wscIE_included || (pCtx->sta[i]->state >= ST_WAIT_M1 &&
					pCtx->sta[i]->state <= ST_WAIT_EAP_FAIL))) {
#ifdef BLOCKED_ROGUE_STA
					if (pCtx->blocked_expired_time &&
						(pCtx->sta[i]->state >= ST_WAIT_M4 && pCtx->sta[i]->state <= ST_WAIT_M8) &&
						(pCtx->sta_invoke_reg == pCtx->sta[i] && pCtx->registration_on >= 1) &&
						(pCtx->sta[i]->ap_role != ENROLLEE)) {
						add_into_blocked_list(pCtx, pCtx->sta[i]);
					}
					else
#endif
					{
							WSC_DEBUG("IssueDisconnect\n");
							IssueDisconnect(pCtx->sta[i]->addr, 1);
					}
				}
				reset_sta(pCtx, pCtx->sta[i], 1);
				continue;
			}

			/* for delay send eap-fail when ER > 1 ;
			   when ER>1 ,and Enrollee send M1 ,  maybe ER1 Rsp M2D but ER2 Rsp M2
			   then Enrollee's state will change to  ST_UPNP_PROXY
			   then  Enrollee's state != ST_WAIT_ACK , meaning some ER will be regristrar
			   so don't send  send_eap_fail
			   search related code by 20101102
  			   WPS2DOTX,PF#3  Marvell   0925 request*/

			if (pCtx->sta[i]->ER_RspM2D_delaytime > 0 && --pCtx->sta[i]->ER_RspM2D_delaytime <= 0)
			{
				if(pCtx->sta[i]->state == ST_WAIT_ACK){
					send_eap_fail(pCtx, pCtx->sta[i]);

					// Reason code 1 : Unspecified reason
					if (pCtx->is_ap && !pCtx->disable_disconnect){
						IssueDisconnect(pCtx->sta[i]->addr, 1);
						WSC_DEBUG("IssueDisconnect\n\n");
					}

					reset_sta(pCtx, pCtx->sta[i], 1);
					WSC_DEBUG("ER Rsp M2D and no M2 come by close\n");
					continue;
				}else{
					WSC_DEBUG("ER Rsp M2D and M2 come by close\n");
				}
			}
			/* for delay send eap-fail when ER > 1 ;search related code by 20101102 */


			if (pCtx->sta[i]->tx_timeout > 0 &&
					--pCtx->sta[i]->tx_timeout <= 0) {
#ifdef SUPPORT_UPNP
				if (pCtx->sta[i]->used & IS_UPNP_CONTROL_POINT) {
					reset_sta(pCtx, pCtx->sta[i], 1);
					continue;
				}
#endif

				if (pCtx->sta[i]->state == ST_WAIT_EAPOL_START
					#ifdef CONFIG_IWPRIV_INTF
					&& pCtx->start_config_client
					#endif
                )
				{

					/*why????????*/
#if 0
					if (pCtx->encrypt_type == WSC_ENCRYPT_WEP
#ifdef FOR_DUAL_BAND
					    || pCtx->encrypt_type2 == WSC_ENCRYPT_WEP
#endif
					    ) {
							if (pCtx->sta[i]->Assoc_wscIE_included) {
								DEBUG_PRINT("\n	wsc IE included : ST_WAIT_EAPOL_START timeout\n");
								WSC_DEBUG("IssueDisconnect!!!\n");
								IssueDisconnect(pCtx->sta[i]->addr, 1);
							}
							reset_sta(pCtx, pCtx->sta[i], 1);
						}
#endif
						/*why????????*/
					/* since EAPOL-START no receive seem should not on going ; 0925 plus.
					else { // in case EAPOL-START not received
						struct timeval tod;
						gettimeofday(&tod , NULL);
						srand(tod.tv_sec);
						pCtx->sta[i]->eap_reqid = (rand() % 50) + 1;
						// 0925 need check
						WSC_DEBUG("\n\n in case EAPOL-START not received \n\n");
						send_eap_reqid(pCtx, pCtx->sta[i]);
						pCtx->sta[i]->state = ST_WAIT_RSP_ID;
						pCtx->sta[i]->tx_timeout = pCtx->tx_timeout;
						pCtx->sta[i]->retry = 1;
					}
					*/


					continue;
				}

				WSC_DEBUG("Sending packet timeout\n");
				MAC_PRINT(pCtx->sta[i]->addr);

				if (pCtx->sta[i]->retry < pCtx->resent_limit) {
					pCtx->sta[i]->retry++;
					DEBUG_PRINT("Resent packet [%d]\n", pCtx->sta[i]->retry);

					send_wlan(pCtx, pCtx->sta[i]->tx_buffer, pCtx->sta[i]->tx_size);
					pCtx->sta[i]->tx_timeout = pCtx->tx_timeout;
				}
				else {
					DEBUG_ERR("Exceed retry limit, abort registration!\n");

                    /*on open/noisy enrivonment broadCom  test bed sometime send disassoc before EAP-DONE;20130913*/
                    if(pCtx->sta[i]->state == ST_WAIT_DONE){
                            if (pCtx->sta[i]->invoke_security_gen) {
                        
                                #ifdef FOR_DUAL_BAND
                                if(pCtx->InterFaceComeIn == COME_FROM_WLAN0)
                                    pCtx->wait_reinit = write_param_to_flash(pCtx, 1);
                                else if(pCtx->InterFaceComeIn == COME_FROM_WLAN1)
                                    pCtx->wait_reinit = write_param_to_flash2(pCtx, 1); // 1001
                                #else
                                pCtx->wait_reinit = write_param_to_flash(pCtx, 1);
                                #endif
                                pCtx->sta[i]->invoke_security_gen = 0;
                            }
                            
                            if (pCtx->wait_reinit)
                                pCtx->wait_reboot = WAIT_REBOOT_TIME;
                    }                    
                    /*on open/noisy enrivonment broadCOm  test bed sometime send disassoc before EAP-DONE ; 20130913*/                    
                    
					if (pCtx->wait_reinit) {
						WSC_DEBUG("signal_webs\n");
						signal_webs(pCtx->wait_reinit);
					}

					// Reason code 1 : Unspecified reason
					if (!(pCtx->sta[i]->used & IS_UPNP_CONTROL_POINT) && pCtx->is_ap &&
						(pCtx->sta[i]->state > ST_WAIT_RSP_ID || pCtx->sta[i]->Assoc_wscIE_included)) {
#ifdef BLOCKED_ROGUE_STA
							if (pCtx->blocked_expired_time &&
								(pCtx->sta[i]->state >= ST_WAIT_M4 && pCtx->sta[i]->state <= ST_WAIT_M8) &&
								(pCtx->sta_invoke_reg == pCtx->sta[i] && pCtx->registration_on >= 1) &&
								(pCtx->sta[i]->ap_role != ENROLLEE)) {
								add_into_blocked_list(pCtx, pCtx->sta[i]);
							}
							else
#endif
							{
								WSC_DEBUG("IssueDisconnect\n");
								IssueDisconnect(pCtx->sta[i]->addr, 1);

							}

					}
					reset_sta(pCtx, pCtx->sta[i], 1);
				}
			}
		}
	}

	if (IS_PBC_METHOD(pCtx->config_method)) {
		int state;
#ifdef MUL_PBC_DETECTTION
		if (!pCtx->disable_MulPBC_detection) {
			if (pCtx->is_ap
#ifdef WSC_CLIENT_MODE
				|| (!pCtx->is_ap && pCtx->role == ENROLLEE)
#endif
			)

			remove_active_pbc_sta(pCtx, NULL, 0);

			if (pCtx->SessionOverlapTimeout > 0 && --pCtx->SessionOverlapTimeout <= 0) {
				DEBUG_PRINT("overlap walk timeout,unlock overlap state\n");
				if (wlioctl_set_led(LED_WSC_END) < 0) {
					DEBUG_ERR("issue wlan ioctl set_led error!\n");
				}
			}
		}
#endif

#ifdef  TRIGGER_PBC_FROM_GPIO	
#else

#ifdef	DET_WPS_SPEC
		if(pCtx->button_hold_method == BUTTON_NEED_NOT_HOLD){
			if (wlioctl_get_button_state(&state) < 0){
				DEBUG_ERR("issue wlan ioctl get_button_state failed!\n");
			}
			if (state > 0) {
				printf("BUTTON_NEED_NOT_HOLD enter\n");
				process_event(pCtx, EV_PB_PRESS);
			}

		}else{
			if (pCtx->pb_pressed_time < pCtx->button_hold_time) {
				if (wlioctl_get_button_state(&state) < 0)
					DEBUG_ERR("issue wlan ioctl get_button_state failed!\n");

				if (state > 0) {
					//printf("rdy rec event\n");
					if ( ++pCtx->pb_pressed_time == pCtx->button_hold_time){
						process_event(pCtx, EV_PB_PRESS);
						pCtx->pb_pressed_time = 0;
					}
				}
				else{
					pCtx->pb_pressed_time = 0;
				}
			}
		}
#else
#ifdef WPS_FOR_ASUS
		checkPBCBtnStat();
#else
		if(pCtx->is_ap){
			if (wlioctl_get_button_state(&state) < 0){
				DEBUG_ERR("get_button_state failed!\n");
			}

			if (state > 0) {
				DEBUG_ERR("GOT GPIO button!!!!!\n");
				// let hold time can config via wscd.conf
#if	defined(CONFIG_RTL_REPEATER_WPS_SUPPORT)
				struct stat status;

				if ( stat("/var/run/wscd-wlan0-wlan1-c.pid", &status) < 0) {
                    if ( stat("/var/run/wscd-wlan0-vxd.pid", &status) < 0)
                        wlan0_vxd_state = -1;               
                    else
                    {
                        wlan0_vxd_state = checkWlanIfState("wlan0-vxd");
                    }
                    
                    if ( stat("/var/run/wscd-wlan1-vxd.pid", &status) < 0)
                        wlan1_vxd_state = -1;               
                    else
                    {
                        wlan1_vxd_state = checkWlanIfState("wlan1-vxd");
                    }                                    
                }
                else {
                    wlan0_vxd_state = checkWlanIfState("wlan0-vxd");
                    wlan1_vxd_state = checkWlanIfState("wlan1-vxd");
                }
				
				if((wlan0_vxd_state == 1) || (wlan1_vxd_state == 1) || (((wlan0_vxd_state == -1)&& (wlan1_vxd_state==-1))))
#endif
				{
					if ( ++pCtx->pb_pressed_time == pCtx->button_hold_time)
					{
						WSC_DEBUG("pbc pressed time (%d), start PBC...\n",pCtx->button_hold_time);

#ifdef SER_AP_SPEC
#ifdef FOR_DUAL_BAND
						 /*usually we config wlan0 as 5G wlan1 as 2.4G*/
						pCtx->inter1only = 1;
#endif
#endif
						process_event(pCtx, EV_PB_PRESS);
						pCtx->pb_pressed_time = 0;
					}
				}
			}
			else{
				pCtx->pb_pressed_time = 0;
			}

		}
		else
		{		/*client mode*/
			if (pCtx->pb_pressed_time < pCtx->button_hold_time) {
                if (wlioctl_get_button_state(&state) < 0){
                    DEBUG_ERR("issue wlan ioctl get_button_state failed!\n");
                }

                if (state > 0) {
                    //printf("rdy rec event\n");
                    if ( ++pCtx->pb_pressed_time == pCtx->button_hold_time){
                        unsigned char start_pbc = 1;
                        pCtx->pb_pressed_time = 0;
                        #if defined(DEBUG) && defined(OUTPUT_LOG)
                        if(outlog_fp==NULL){
                            outlog_fp = fopen( LOG_PATH ,"a+" );
                        }
                        #endif

                        #if	defined(CONFIG_RTL865x_KLD_REPEATER) || defined(CONFIG_RTL_REPEATER_WPS_SUPPORT)
                        if(strstr(pCtx->wlan_interface_name, "vxd") && checkWlanIfState(pCtx->wlan_interface_name) == 1) {
                            start_pbc = 0;                            
                            DEBUG_PRINT("\r\n do WPS on AP mode interface...");
                        }

                        #ifdef FOR_DUAL_BAND
                        if(start_pbc) {
                            if(strstr(pCtx->wlan_interface_name2, "vxd") && checkWlanIfState(pCtx->wlan_interface_name2) == 1) {
                                start_pbc = 0;                            
                                DEBUG_PRINT("\r\n do WPS on AP mode interface...");
                            }
                        }
                        #endif                        
                        #endif

                        if(start_pbc)
                        {
                            WSC_DEBUG("start PBC...\n");
                            process_event(pCtx, EV_PB_PRESS);
                        }
                    }
                }
                else{
                    pCtx->pb_pressed_time = 0;
                }
			}
		}
#endif

#endif
#endif	// if TRIGGER_PBC_FROM_GPIO if define ; don't polling here(wscd) , GPIO will do itself

#ifdef WSC_CLIENT_MODE
		if (!pCtx->is_ap && (pCtx->pb_timeout || pCtx->pin_timeout) && pCtx->start_time) {
#ifndef __ECOS
			struct sysinfo info;
			sysinfo(&info);
#endif

			if (pCtx->pb_timeout) {
#ifdef __ECOS
				time(&timetmp);
				if ((timetmp - pCtx->start_time) > PBC_WALK_TIME)
#else
				if ((((unsigned long)info.uptime) - pCtx->start_time) > PBC_WALK_TIME)
#endif
				{
					pCtx->pb_timeout = 1; // let timeout happen immedeately
					pCtx->start_time = 0;
				}
			}
			else {
#ifdef __ECOS
				time(&timetmp);
				if ((timetmp - pCtx->start_time) > PIN_WALK_TIME)
#else
				if ((((unsigned long)info.uptime) - pCtx->start_time) > PIN_WALK_TIME)
#endif
				{
					pCtx->pin_timeout = 1; // let timeout happen immedeately
					pCtx->start_time = 0;
				}
			}
		}
#endif

		if (pCtx->pb_timeout > 0 && --pCtx->pb_timeout <= 0) {

#ifdef OUTPUT_LOG
			if(outlog_fp){
				UTIL_DEBUG("close outlog_fp\n");
				fclose(outlog_fp);
			}
#endif


#ifdef CONFIG_IWPRIV_INTF
			if(!pCtx->start_config_client){
			        _DEBUG_PRINT("Reset time-out!\n");
			        pCtx->start_config_client = 1;
			} else
#endif
			{
				WSC_DEBUG("PBC walk time-out!\n");
				report_WPS_STATUS(PROTOCOL_TIMEOUT);
			}
			reset_ctx_state(pCtx);


			if (wlioctl_set_led(LED_WSC_ERROR) < 0) {
				DEBUG_ERR("issue wlan ioctl set_led error!\n");
			}

#ifdef WSC_CLIENT_MODE
			if (!pCtx->is_ap)
				pCtx->start  = 0;
#endif
		}
	}

	if (IS_PIN_METHOD(pCtx->config_method)) {
		if (pCtx->pin_timeout > 0 && --pCtx->pin_timeout <= 0) {

#ifdef OUTPUT_LOG
			if(outlog_fp){
				UTIL_DEBUG("close outlog_fp\n");
				fclose(outlog_fp);
			}
#endif

#ifdef CONFIG_IWPRIV_INTF
            if(!pCtx->start_config_client) {
                _DEBUG_PRINT("Config client time-out!\n");
                pCtx->start_config_client = 1;
            }
			else
#endif
            {

			WSC_DEBUG("PIN time-out!\n");
#ifdef WPS2DOTX
			registrar_remove_authorized_mac(pCtx ,BroadCastMac);
#endif

#ifdef CONNECT_PROXY_AP
			clear_blocked_ap_list(pCtx);
#endif
			report_WPS_STATUS(PROTOCOL_TIMEOUT);
#ifdef CONFIG_IWPRIV_INTF

        		for (i=0; i<WSC_MAX_STA_NUM; i++){
                    if (pCtx->sta[i]){
                        pCtx->sta[i]->used = 0;

						if(pCtx->num_ext_registrar)
	                        pCtx->num_ext_registrar--;

						WSC_DEBUG("ER count=%d\n", pCtx->num_ext_registrar);
                    }
                }
#ifdef STAND_ALONE_MINIUPNP
				WSC_DEBUG("!!	sending byebye\n\n");
                SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
                	&pCtx->upnp_info.SSDP, 1, 1);
#endif
                init_config(pCtx,0);
#ifdef STAND_ALONE_MINIUPNP
				WSC_DEBUG("!!	sending alive\n\n");
                SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
				    &pCtx->upnp_info.SSDP, 0, pCtx->upnp_info.SSDP.max_age);
                pCtx->upnp_info.SSDP.alive_timeout = pCtx->upnp_info.SSDP.max_age/2;
#endif
#endif
            }
			reset_ctx_state(pCtx);
#ifdef WSC_CLIENT_MODE
			if (!pCtx->is_ap)
				pCtx->start  = 0;
#endif

			if (wlioctl_set_led(LED_WSC_ERROR) < 0) {
				DEBUG_ERR("issue wlan ioctl set_led error!\n");
			}

		}
	}


	if (pCtx->LedTimeout > 0 ) {
		if(--pCtx->LedTimeout <= 0)
		if (wlioctl_set_led(LED_WSC_END) < 0) {
			DEBUG_ERR("issue wlan ioctl set_led error!\n");
		}
	}


	if (pCtx->wait_reboot > 0 && --pCtx->wait_reboot <= 0) {
		WSC_DEBUG(">>>WSC REBOOT\n");
#ifdef	WINDOW7
#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan0_wsc_disabled)
#endif
		{
			func_off_wlan_tx(pCtx,pCtx->wlan_interface_name);
		}
#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan1_wsc_disabled )
			func_off_wlan_tx(pCtx,pCtx->wlan_interface_name2);
#endif

#endif
		WSC_DEBUG("signal_webs\n");
		signal_webs(REINIT_SYS);
	}

#ifdef SUPPORT_UPNP

	if (pCtx->setSelectedRegTimeout > 0 && --pCtx->setSelectedRegTimeout <= 0) {
		WSC_DEBUG("SetSelectedReg time-out!\n");
		report_WPS_STATUS(PROTOCOL_TIMEOUT);
		reset_ctx_state(pCtx);
	}

	if (pCtx->upnp && pCtx->status_changed) {
		struct WSC_packet packet;
		unsigned char tmpbuf[1];

		tmpbuf[0] = '1';
		if (pCtx->is_ap)
			packet.EventID = WSC_AP_STATUS;	// ap setting changed
		else
			packet.EventID = WSC_STA_STATUS;
		packet.tx_buffer = tmpbuf;
		packet.tx_size = 1;
		if (WSCUpnpTxmit(&packet) != WSC_UPNP_SUCCESS)
			DEBUG_ERR("WSCUpnpTxmit() return error!\n");
		pCtx->status_changed = 0;
	}

	if (pCtx->upnp && pCtx->upnp_wait_reboot_timeout > 0 && --pCtx->upnp_wait_reboot_timeout <= 0) {
		_DEBUG_PRINT("upnp_config wait_reboot ----->%s----->%d\n", __FUNCTION__, __LINE__);
		WSCUpnpStop();
#ifdef	WINDOW7
#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan0_wsc_disabled)
#endif
		{
			func_off_wlan_tx(pCtx,pCtx->wlan_interface_name);
		}

#ifdef FOR_DUAL_BAND
		if(!pCtx->wlan1_wsc_disabled )
			func_off_wlan_tx(pCtx,pCtx->wlan_interface_name2);
#endif

#endif
		WSC_DEBUG("signal_webs\n");
		signal_webs(REINIT_SYS);
	}

#ifdef PREVENT_PROBE_DEADLOCK
	int idx=-1;
	unsigned int largest=0;

	if (pCtx->is_ap && pCtx->upnp && (pCtx->original_role != ENROLLEE)
		&& pCtx->probe_list_count) {
		for (i=0; i<MAX_WSC_PROBE_STA; i++) {
			if (!pCtx->probe_list[i].used)
				continue;
			else {
				unsigned int time_offset=difftime(time(NULL), pCtx->probe_list[i].time_stamp);
				if (time_offset > PROBE_EXPIRED) {
					memset(&pCtx->probe_list[i], 0, sizeof(struct probe_node));
					pCtx->probe_list_count--;
				}
				else {
					if (!pCtx->probe_list[i].sent && (time_offset > largest)) {
						idx = i;
						largest = time_offset;
					}
				}
			}
		}
	}

	if (pCtx->is_ap && (pCtx->role == REGISTRAR || pCtx->role == PROXY) &&
		(pCtx->original_role != ENROLLEE) &&
		!pCtx->pb_pressed && !pCtx->pin_assigned &&
		pCtx->upnp && pCtx->TotalSubscriptions && (idx != -1)) {
		struct WSC_packet packet;

		packet.EventType = WSC_PROBE_FRAME;
		packet.EventID = WSC_PUTWLANREQUEST;
		convert_bin_to_str_UPnP(pCtx->probe_list[idx].ProbeMACAddr, 6, packet.EventMac);
		packet.tx_buffer = pCtx->probe_list[idx].ProbeIE;
		packet.tx_size = pCtx->probe_list[idx].ProbeIELen;

		if (WSCUpnpTxmit(&packet) != WSC_UPNP_SUCCESS)
			DEBUG_ERR("WSCUpnpTxmit() return error!\n");
		pCtx->probe_list[idx].sent = 1;
	}
#endif // PREVENT_PROBE_DEADLOCK


#ifdef USE_MINI_UPNP
	if (pCtx->upnp) {
#ifdef STAND_ALONE_MINIUPNP
		if (pCtx->upnp_info.SSDP.alive_timeout > 0 && --pCtx->upnp_info.SSDP.alive_timeout <= 0) {

			//sending alive
			WSC_DEBUG("!!	sending alive\n\n");

			SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
				&pCtx->upnp_info.SSDP, 0, pCtx->upnp_info.SSDP.max_age);
			pCtx->upnp_info.SSDP.alive_timeout = pCtx->upnp_info.SSDP.max_age/2;
		}
#endif

		struct EvtRespElement *EvtResp=NULL;
		struct EvtRespElement *EvtResp_next=NULL;
		for(EvtResp = pCtx->upnp_info.subscribe_list.EvtResp_head.lh_first; EvtResp != NULL; )
		{
			EvtResp_next = EvtResp->entries.le_next;
			if(EvtResp->TimeOut > 0 && --EvtResp->TimeOut <= 0) {
				WSC_DEBUG("Eventing response timeout: remove sid[%s]\n", EvtResp->sid);
				if (EvtResp->socket >= 0)
					close(EvtResp->socket);
				LIST_REMOVE(EvtResp, entries);
				free(EvtResp);
			}
			EvtResp = EvtResp_next;
		}

		struct upnp_subscription_element *e;
		struct upnp_subscription_element *next;
		for(e = pCtx->upnp_info.subscribe_list.subscription_head.lh_first; e != NULL; )
		{
			next = e->entries.le_next;

			if(e->subscription_timeout > 0)
			{
				e->subscription_timeout -= 1;

				if(e->subscription_timeout % 10 == 0){
					_DEBUG_PRINT("(ER)[%s][%d]\n" , e->sid , e->subscription_timeout);
				}

				if(e->subscription_timeout<=0){

					/*clean upnp*/
					LIST_REMOVE(e, entries);
					pCtx->upnp_info.subscribe_list.total_subscription--;
					WSC_DEBUG("(UPNP)Remove sid[%s]\n",e->sid);
					WSC_DEBUG("(UPNP)Total_subscription[%d]\n",
		       			(int)pCtx->upnp_info.subscribe_list.total_subscription);

					free(e);
					// 2011-0422 add
					pCtx->TotalSubscriptions = (int)pCtx->upnp_info.subscribe_list.total_subscription;
				}
			}
			e = next;
		}
	}
#endif // USE_MINI_UPNP
#endif //SUPPORT_UPNP

#ifndef __ECOS
	{
		struct stat status;
		if (stat(REINIT_WSCD_FILE, &status) == 0) { // re-init

#ifdef SUPPORT_UPNP
			if (pCtx->upnp)
				WSCUpnpStop();
#endif

			for (i=0; i<WSC_MAX_STA_NUM; i++) {
				if (pCtx->sta[i] && pCtx->sta[i]->used)
					reset_sta(pCtx, pCtx->sta[i], 1);
			}
			init_config(pCtx,0);
			if (pCtx->is_ap) {
				pCtx->start = 1;
			} else {
				pCtx->start = 0;
				client_set_WlanDriver_WscEnable(pCtx, 0);
			}

			if (init_wlan(pCtx, 1) < 0) {
				printf("wscd: init_wlan() failed!\n");
			}

#ifdef SUPPORT_UPNP
			if (pCtx->upnp) {
				if (start_upnp(pCtx) < 0) {
					printf("wscd: start_upnp() failed!\n");
				}
			}
#endif

           	unlink(REINIT_WSCD_FILE);
		}
	}
#endif

#ifdef WSC_CLIENT_MODE
	if (!pCtx->is_ap && pCtx->start && pCtx->connect_fail) {
        i = 0;
#ifdef FOR_DUAL_BAND        
        if(pCtx->wlan0_wsc_disabled == 0 && pCtx->join_band == 0) {
            if (pCtx->join_idx >= pCtx->ss_status.number || pCtx->ss_status.number == 0xff) {                           
                i = 1;
            }
        }
        else if(pCtx->wlan1_wsc_disabled == 0 && pCtx->join_band == 1) {
            if (pCtx->join_idx >= pCtx->ss_status2.number || pCtx->ss_status2.number == 0xff) {                           
                i = 1;
            }
        }
#else
        if (pCtx->join_idx >= pCtx->ss_status.number || pCtx->ss_status.number == 0xff) {
            i = 1;
        }

#endif
        
		if (i) {
			WSC_DEBUG("	Issue Re-Scan\n");
			issue_scan_req(pCtx, pCtx->connect_method);
		}
		else {
			WSC_DEBUG("	Issue Re-Connect\n");
			connect_wps_ap(pCtx, pCtx->connect_method);
		}
	}
#endif

#ifdef BLOCKED_ROGUE_STA
	if (pCtx->is_ap && pCtx->blocked_expired_time)
		countdown_blocked_list(pCtx);
#endif // BLOCKED_ROGUE_STA

#ifdef __ECOS
	//todo no support "Received WSC stop event" from web page 
#else
	if (stat(wscd_cancel_file, &cancel_status) == 0) {
		WSC_DEBUG("		Received WSC stop event \n\n");
		process_event(pCtx, EV_STOP);
		unlink(wscd_cancel_file);
	}
#endif

#ifdef __ECOS
	return 0;
#else
#ifdef WSC_1SEC_TIMER
	return 1;
#else
	return 1;
	//alarm(1);
#endif
#endif
}

#ifndef __ECOS
#ifdef WSC_1SEC_TIMER
static int wsc_init_1sec_Timer(void)
{
	struct sigaction  action;

	action.sa_handler = (void (*)())sigHandler_alarm;
	action.sa_flags = SA_RESTART;

	if (sigaction(SIGALRM,&action,0) == -1)
	{
		DEBUG_ERR("Error in sigaction\n");
		return -1;
	}

	wsc_alarm();

	return 0;
}
#endif

static void sigHandler_user(int signo)
{
	WSC_DEBUG("*****%s******\n",__FUNCTION__);

#ifdef FOR_DUAL_BAND
	CTX_Tp pCtx = pGlobalCtx;
	struct stat cancel_status;
#endif

	if (signo == SIGTSTP){
		process_event(pGlobalCtx, EV_START);
	}
	else if (signo == SIGUSR2){
		WSC_DEBUG("*****%s******SIGUSR2\n",__FUNCTION__);
#ifdef FOR_DUAL_BAND
		/*2011-11 add for support under dual band mode just trigger single interface*/
		pCtx->inter0only  = 0;
		pCtx->inter1only  = 0;

		if (stat(WSCD_IND_ONLY_INTERFACE0, &cancel_status) == 0) {
			WSC_DEBUG("%s\n",WSCD_IND_ONLY_INTERFACE0);
			pCtx->inter0only  = 1;
			unlink(WSCD_IND_ONLY_INTERFACE0);
		}
		if (stat(WSCD_IND_ONLY_INTERFACE1, &cancel_status) == 0) {
			WSC_DEBUG("%s\n",WSCD_IND_ONLY_INTERFACE1);
			pCtx->inter1only  = 1;
			unlink(WSCD_IND_ONLY_INTERFACE1);
		}

		WSC_DEBUG("inter0only = %d\n",pCtx->inter0only);
		WSC_DEBUG("inter1only = %d\n",pCtx->inter1only);

		/*2011-11 add for support under dual band mode just trigger single interface*/
#endif
		process_event(pGlobalCtx, EV_PB_PRESS);
	}
#ifdef	AUTO_LOCK_DOWN
	else if (signo == SIGUSR1){
		process_event(pGlobalCtx, EV_UN_AUTO_LOCK_DOWN);
	}
#endif
	else{
		printf("Got an invalid signal [%d]!\n", signo);
	}
}
#endif /* __ECOS */

#ifdef CONFIG_IWPRIV_INTF
static int get_wps_wltoken(CTX_Tp pCtx, char *token, char *value, int def)
{
	if( strncmp(token, pCtx->wlan_interface_name, strlen(pCtx->wlan_interface_name)) == 0 ) {
		if (strstr(token, "ssid") != NULL) {
			if (pCtx->SSID[0] != 0) // set in argument
				return -1;
			if (strlen(value) > WSC_MAX_SSID_LEN) {
				DEBUG_ERR("Invalid ssid length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->SSID, (def)?(char *)wsc_parms_default[wsc_ssid].value:value);
		} else if(strstr(token, "wps_upnp_enable") != NULL) {
			pCtx->upnp = atoi((def)?(char *)wsc_parms_default[wsc_upnp].value:value);
		} else if (strstr(token, "wps_auth") != NULL) {
			pCtx->auth_type_flash = atoi((def)?(char *)wsc_parms_default[wsc_auth_type].value:value);

			if ((pCtx->auth_type_flash &
 				 (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA
				 | WSC_AUTH_WPA2| WSC_AUTH_WPA2PSK| WSC_AUTH_WPA2PSKMIXED))==0) 
			{
				DEBUG_ERR("Invalid auth_type value [0x%x]! Use default.\n", pCtx->auth_type_flash);
				pCtx->auth_type_flash = WSC_AUTH_OPEN;
			}


			if (pCtx->auth_type_flash == WSC_AUTH_WPA2PSKMIXED)
				pCtx->auth_type = WSC_AUTH_WPA2PSK;
			else
				pCtx->auth_type = pCtx->auth_type_flash;

		} else if ( strstr(token, "wps_enc") != NULL) {
			pCtx->encrypt_type_flash = atoi((def)?(char *)wsc_parms_default[wsc_encrypt].value:value);
			if (pCtx->encrypt_type_flash
				& (WSC_ENCRYPT_NONE | WSC_ENCRYPT_WEP | WSC_ENCRYPT_TKIP | WSC_ENCRYPT_AES )==0 )
			{
				WSC_DEBUG("Invalid encrypt_type[0x%x]! Use default.\n", pCtx->encrypt_type_flash);
				pCtx->encrypt_type_flash = WSC_ENCRYPT_NONE;
			}
			if (pCtx->encrypt_type_flash == WSC_ENCRYPT_TKIPAES) {
				if (pCtx->auth_type == WSC_AUTH_WPA2PSK)
					pCtx->encrypt_type = WSC_ENCRYPT_AES;
				else
					pCtx->encrypt_type = WSC_ENCRYPT_TKIP;
			}
			else{
				pCtx->encrypt_type = pCtx->encrypt_type_flash;
			}
		} else if (strstr(token, "network_key") != NULL) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid network_key length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->network_key, ((def)?(char *)wsc_parms_default[wsc_key].value:value));
			pCtx->network_key_len = strlen((def)?(char *)wsc_parms_default[wsc_key].value:value);
		} else if (strstr(token, "wep_key2") != NULL) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key2 length [%d]!\n", strlen((def)?(char*)wsc_parms_default[wsc_key].value:value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key2, (def)?(char *)wsc_parms_default[wsc_key].value:value);
		} else if (strstr(token, "wep_key3") != NULL) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key3 length [%d]!\n", strlen((def)?(char*)wsc_parms_default[wsc_key].value:value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key3, (def)?(char *)wsc_parms_default[wsc_key].value:value);
		} else if (strstr(token, "wep_key4") != NULL) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key4 length [%d]!\n", strlen((def)?(char*)wsc_parms_default[wsc_key].value:value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key4, (def)?(char *)wsc_parms_default[wsc_key].value:value);
		}
	}
	return 0;
}
#endif // CONFIG_IWPRIV_INTF

#ifndef __ECOS
static int read_config_file(CTX_Tp pCtx, char *filename, int def)
{
	FILE *fp;
	char line[400], token[40], value[300], *ptr;
	int i;
	//int idx=0;			/*2011-0419 WEP,HEX type key issue*/
	DBFENTER;

#ifdef BLOCKED_ROGUE_STA
	pCtx->blocked_expired_time = DEFAULT_BLOCK_TIME;
#endif

    if(pCtx->debug2)
        WSC_DEBUG("Read config file:%s, def:%d \n",pCtx->cfg_filename,def);

	fp = fopen(filename, "r");
	if (fp == NULL) {
		DEBUG_ERR("read config file [%s] failed!\n", filename);
		return -1;
	}


	while ( fgets(line, 200, fp) ) {
		if (line[0] == '#')
			continue;
		ptr = get_token(line, token);
		if (ptr == NULL)
			continue;
		if (get_value(ptr, value)==0){
			continue;
		}
		else if (!strcmp(token, "wlan_fifo0")) {
			if (pCtx->fifo_name[0])
				continue;
			strcpy(pCtx->fifo_name, value);
		}
		else if (!strcmp(token, "wlan_fifo1")) {
#ifdef FOR_DUAL_BAND
			if (pCtx->fifo_name2[0])
				continue;
			strcpy(pCtx->fifo_name2, value);
#endif
		}
		/*
		else if (!strcmp(token, "role")) {
			if (pCtx->role != -1) // set in argument
				continue;
			pCtx->role = atoi(value);
			if (pCtx->role != PROXY && pCtx->role != ENROLLEE &&
				 pCtx->role != REGISTRAR) {
				DEBUG_ERR("Invalid role value [%d]!\n", pCtx->role);
				return -1;
			}
		}
		*/

		else if (!strcmp(token, "mode")) {
			if (pCtx->mode != -1)
				continue;
			pCtx->mode = atoi(value);
		}
		else if (!strcmp(token, "manual_config")) {
			pCtx->manual_config= atoi(value);
		}
		else if (!strcmp(token, "upnp")) {
			if (pCtx->upnp != -1) // set in argument
				continue;
			pCtx->upnp = atoi(value);
        }
		else if (!strcmp(token, "use_ie")) {
			pCtx->use_ie = atoi(value);
		}
		else if (!strcmp(token, "config_method")) {
#ifndef WPS2DOTX
			if (pCtx->config_method != -1) // set in argument
				continue;
			#endif
			if(value[0]=='0' && (value[1]=='x' || value[1]=='X')){
				pCtx->config_method = strtol(value+2 , NULL ,16 );
			}else{
				pCtx->config_method = atoi(value);
			}
			WSC_DEBUG("!!config_method %x\n",pCtx->config_method);
#ifdef WPS2DOTX
			if((pCtx->config_method & (CONFIG_METHOD_VIRTUAL_PIN | CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC ))==0){
				pCtx->config_method = (CONFIG_METHOD_VIRTUAL_PIN |  CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC );
				WSC_DEBUG("For WPS2.0 config_method to %x\n",pCtx->config_method);
			}

#else
			if (!(pCtx->config_method & (CONFIG_METHOD_PIN | CONFIG_METHOD_PBC))) {
				DEBUG_ERR("Invalid config_method value [%d]! Use default.\n", pCtx->config_method);
				pCtx->config_method = (CONFIG_METHOD_PIN | CONFIG_METHOD_PBC | CONFIG_METHOD_ETH);
			}
#endif
		}
#ifdef WPS2DOTX	// should be no need it's only need for as Test Bed
		//EAP_frag_threshold
		else if (!strcmp(token, "EAP_Frag_Len_TH")) {
			pCtx->EAP_frag_threshold = atoi(value);
			WSC_DEBUG("	!!!assigned EAP message Fragment thresold=%d\n",pCtx->EAP_frag_threshold);
			if(pCtx->EAP_frag_threshold < 200 || pCtx->EAP_frag_threshold > 2048){
				pCtx->EAP_frag_threshold = 0;
				WSC_DEBUG("Fragment thresold too small , no fragment\n");
			}

		}
		/*STA mode ; probe_REQ__WSC_IE_Fragment */
		else if (!strcmp(token, "ProbeReq_wscIE_frag")) {
			pCtx->probeReq_need_wscIE_frag = atoi(value);
		}

		/*AP mode ; probe_RSP__WSC_IE_Fragment */
		else if (!strcmp(token, "ProbeRsp_wscIE_frag")) {
			pCtx->probeRsp_need_wscIE_frag = atoi(value);
		}

		/*AP mode ; extension_tag */
		else if (!strcmp(token, "Extension_Tag_test")) {
			pCtx->extension_tag = atoi(value);
		}
#endif
		else if (!strcmp(token, "pin_code")) {
			int code_len;
			if (strlen(pCtx->pin_code) > 0) // set in argument
				continue;

			code_len = strlen(value);
			if (code_len != PIN_LEN && code_len != 4) {
				DEBUG_ERR("Invalid pin_code length!\n");
				return -1;
			}
			i = atoi(value);
			if (code_len == PIN_LEN) {
				if (!validate_pin_code(i)) {
					DEBUG_ERR("Invalid pin_code value (checksum error)!\n");
					return -1;
				}
			}
			strcpy(pCtx->pin_code, value);
		}
		else if (!strcmp(token, "rf_band")) {
			pCtx->rf_band = atoi(value);
		}
		else if (!strcmp(token, "ssid")) {
			if (pCtx->SSID[0] != 0) // set in argument
				continue;
			if (strlen(value) > WSC_MAX_SSID_LEN) {
				DEBUG_ERR("Invalid ssid length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->SSID, value);
		}
#ifdef FOR_DUAL_BAND
		/* FOR_DUAL_BAND --start ; need not under define flag*/
		else if (!strcmp(token, "wlan0_wsc_disabled")) {
			pCtx->wlan0_wsc_disabled = atoi(value);

		}
		else if (!strcmp(token, "wlan1_wsc_disabled")) {
			pCtx->wlan1_wsc_disabled = atoi(value);
		}
		/* FOR_DUAL_BAND  --end  ; need not under define flag*/
		else if (!strcmp(token, "ssid2")) {
			if (pCtx->SSID2[0] != 0) // set in argument
				continue;
			if (strlen(value) > WSC_MAX_SSID_LEN) {
				DEBUG_ERR("Invalid ssid length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->SSID2, value);
		}
		else if (!strcmp(token, "auth_type2")) {
			pCtx->auth_type_flash2 = atoi(value);
			if ((pCtx->auth_type_flash2 &
 				 (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA
				 | WSC_AUTH_WPA2| WSC_AUTH_WPA2PSK| WSC_AUTH_WPA2PSKMIXED))==0)
			{
				DEBUG_ERR("Invalid auth_type value [0x%x]! Use default.\n", pCtx->auth_type_flash2);
				pCtx->auth_type_flash2 = WSC_AUTH_OPEN;
			}

			if (pCtx->auth_type_flash2 == WSC_AUTH_WPA2PSKMIXED)
				pCtx->auth_type2 = WSC_AUTH_WPA2PSK;
			else
				pCtx->auth_type2 = pCtx->auth_type_flash2;


		}
		else if (!strcmp(token, "encrypt_type2")) {
			pCtx->encrypt_type_flash2 = atoi(value);
			if ( (pCtx->encrypt_type_flash2 & (WSC_ENCRYPT_NONE | WSC_ENCRYPT_WEP | WSC_ENCRYPT_TKIP | WSC_ENCRYPT_AES )) ==0 )
			{
				DEBUG_ERR("Invalid encrypt_type2 [0x%x]! Use default.\n", pCtx->encrypt_type_flash2);
				pCtx->encrypt_type_flash2 = WSC_ENCRYPT_NONE;
			}

			if (pCtx->encrypt_type_flash2 == WSC_ENCRYPT_TKIPAES) {
				if (pCtx->auth_type2 == WSC_AUTH_WPA2PSK)
					pCtx->encrypt_type2 = WSC_ENCRYPT_AES;
				else
					pCtx->encrypt_type2 = WSC_ENCRYPT_TKIP;
			}
			else{
				pCtx->encrypt_type2 = pCtx->encrypt_type_flash2;
			}



		}
		else if (!strcmp(token, "mixedmode2")) {
			pCtx->mixedmode2 = atoi(value);

		}
		else if (!strcmp(token, "wep_transmit_key2")) {
			pCtx->wep_transmit_key2 = atoi(value);
			if (pCtx->encrypt_type2 == WSC_ENCRYPT_WEP &&
				(pCtx->wep_transmit_key2 < 1 || pCtx->wep_transmit_key2 > 4)) {
				DEBUG_ERR("Invalid wep_transmit_key value [%d]!\n", pCtx->wep_transmit_key2);
				return -1;
			}
		}
		else if (!strcmp(token, "network_key2")) {

			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid network_key length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->network_key2, value);
            pCtx->network_key_len2 = strlen(value);

		}
		else if (!strcmp(token, "wep_key22")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key2 length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key22, value);
		}
		else if (!strcmp(token, "wep_key32")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key3 length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key32, value);
		}
		else if (!strcmp(token, "wep_key42")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key4 length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key42, value);
		}
#endif	/*  END of FOR_DUAL_BAND */
		else if (!strcmp(token, "auth_type")) {
			pCtx->auth_type_flash = atoi(value);

			if ((pCtx->auth_type_flash &
 				 (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA
				 | WSC_AUTH_WPA2| WSC_AUTH_WPA2PSK| WSC_AUTH_WPA2PSKMIXED))==0)
			{
				DEBUG_ERR("Invalid auth_type value [0x%x]! Use default.\n", pCtx->auth_type_flash);
				pCtx->auth_type_flash = WSC_AUTH_OPEN;
			}

			if (pCtx->auth_type_flash == WSC_AUTH_WPA2PSKMIXED){
				pCtx->auth_type = WSC_AUTH_WPA2PSK;
			}else{
				pCtx->auth_type = pCtx->auth_type_flash;
			}
			
		}
		else if (!strcmp(token, "auth_type_flags")) {
			pCtx->auth_type_flags = atoi(value);
			if (!(pCtx->auth_type_flags & (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA |
					WSC_AUTH_WPA2 | WSC_AUTH_WPA2PSK)))
			{
				WSC_DEBUG("Invalid auth_type_flags value [0x%x]!\n", pCtx->auth_type_flags);
				return -1;
			}

		}
		else if (!strcmp(token, "encrypt_type")) {
			pCtx->encrypt_type_flash = atoi(value);
			if ( (pCtx->encrypt_type_flash & (WSC_ENCRYPT_NONE | WSC_ENCRYPT_WEP | WSC_ENCRYPT_TKIP | WSC_ENCRYPT_AES ))==0)
			{
				DEBUG_ERR("Invalid encrypt_type [0x%x]! Use default.\n", pCtx->encrypt_type_flash);
				pCtx->encrypt_type_flash = WSC_ENCRYPT_NONE;
			}

			if (pCtx->encrypt_type_flash == WSC_ENCRYPT_TKIPAES) {
				if (pCtx->auth_type == WSC_AUTH_WPA2PSK)
					pCtx->encrypt_type = WSC_ENCRYPT_AES;
				else
					pCtx->encrypt_type = WSC_ENCRYPT_TKIP;
			}
			else{
				pCtx->encrypt_type = pCtx->encrypt_type_flash;
			}


		}
		else if (!strcmp(token, "encrypt_type_flags")) {
			pCtx->encrypt_type_flags = atoi(value);
			if (!(pCtx->encrypt_type_flags & (WSC_ENCRYPT_NONE |WSC_ENCRYPT_WEP |WSC_ENCRYPT_TKIP|WSC_ENCRYPT_AES))) {
				DEBUG_ERR("Invalid encrypt_type_flags value [0x%x]!\n", pCtx->encrypt_type_flags);
				return -1;
			}

		}
		else if (!strcmp(token, "mixedmode")) {
			pCtx->mixedmode = atoi(value);
		}
		else if (!strcmp(token, "wep_transmit_key")) {
			pCtx->wep_transmit_key = atoi(value);
			if (pCtx->encrypt_type == WSC_ENCRYPT_WEP &&
				(pCtx->wep_transmit_key < 1 || pCtx->wep_transmit_key > 4)) {
				DEBUG_ERR("Invalid wep_transmit_key value [%d]!\n", pCtx->wep_transmit_key);
				return -1;
			}
		}
		else if (!strcmp(token, "connection_type")) {
			if (pCtx->connect_type != -1) // set in argument
				continue;
			pCtx->connect_type = atoi(value);
			if (pCtx->connect_type != CONNECT_TYPE_BSS && pCtx->connect_type != CONNECT_TYPE_IBSS) {
				DEBUG_ERR("Invalid connection_type value [%d]!\n", pCtx->connect_type);
				return -1;
			}
		}
		else if (!strcmp(token, "uuid")) {
			if (strlen(value) != UUID_LEN*2) {
				DEBUG_ERR("Invalid uuid length!\n");
				return -1;
			}
			ptr = value;
			for (i=0; i<UUID_LEN; i++, ptr+=2) {
				if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
					DEBUG_ERR("Invalid uuid vlaue!\n");
					return -1;
				}
				pCtx->uuid[i] = convert_atob(ptr, 16);
			}
		}
		else if (!strcmp(token, "modelDescription")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid modelDescription length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manufacturerDesc, value);
		}//Brad add 20090206
		else if (!strcmp(token, "UPC")) {
			if (strlen(value) < 12) {
				DEBUG_ERR("Invalid UPC length [%d]!\n", strlen(value));
				return -1;
			}
			
			memcpy(pCtx->UPC, value , 12);
			pCtx->UPC[12]='\0';
			//WSC_DEBUG("pCtx->UPC=%s\n",pCtx->UPC);
		}		
		else if (!strcmp(token, "manufacturer")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid manufacturer length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manufacturer, value);
		}//Brad add 20080721
		else if (!strcmp(token, "manufacturerURL")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid manufacturer URL length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manufacturerURL, value);
		}
		else if (!strcmp(token, "modelURL")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid model URL length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->model_URL, value);
		}//Brad add end
		else if (!strcmp(token, "model_name")) {
			if (strlen(value) > MAX_MODEL_NAME_LEN) {
				DEBUG_ERR("Invalid model_name length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->model_name, value);
		}
		else if (!strcmp(token, "model_num")) {
			if (strlen(value) > MAX_MODEL_NAME_LEN) {
				DEBUG_ERR("Invalid model_num length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->model_num, value);
		}
		else if (!strcmp(token, "serial_num")) {
			if (strlen(value) > MAX_SERIAL_NUM_LEN) {
				DEBUG_ERR("Invalid serial_num length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->serial_num, value);
		}
		else if (!strcmp(token, "device_category_id")) {
			pCtx->device_category_id = atoi(value);
		}
		else if (!strcmp(token, "device_sub_category_id")) {
			pCtx->device_sub_category_id = atoi(value);
		}
		else if (!strcmp(token, "device_oui")) {
			if (strlen(value) != OUI_LEN*2) {
				DEBUG_ERR("Invalid oui length!\n");
				return -1;
			}
			ptr = value;
			for (i=0; i<OUI_LEN; i++, ptr+=2) {
				if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
					DEBUG_ERR("Invalid OUI vlaue!\n");
					return -1;
				}
				pCtx->device_oui[i] = convert_atob(ptr, 16);
			}
		}
		else if (!strcmp(token, "device_name")) {
			if (strlen(value) > MAX_DEVICE_NAME_LEN) {
				DEBUG_ERR("Invalid device_name length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->device_name, value);
		}

		else if (!strcmp(token, "device_password_id")) {
			pCtx->device_password_id = atoi(value);
		}
		else if (!strcmp(token, "disable_configured_by_exReg")) {
			pCtx->disable_configured_by_exReg = atoi(value);


		}
		else if (!strcmp(token, "button_hold_time")) {
			pCtx->button_hold_time = atoi(value);

		}
		else if(!strcmp(token, "button_hold_time_for_first_if")){
			pCtx->button_hold_time_for_first_if = atoi(value);
		}
		else if (!strcmp(token, "PIN_timeout")) {
			pCtx->c_pin_timeout = atoi(value);
			_DEBUG_PRINT("configured pin_timeout = %d\n",pCtx->c_pin_timeout);
		}
		else if (!strcmp(token, "SSID_prefix")) {

			if (strlen(value) > WSC_MAX_SSID_LEN) {
				DEBUG_ERR("Invalid prefix-ssid length [%d] , use default value\n", strlen(value));

			}else if (strlen(value) == 0 ) {
				DEBUG_ERR("Invalid prefix-ssid length [%d] , use default value\n", strlen(value));
			}else if (strlen(value) > 14 ) {
				strncpy(pCtx->ssid_prefix, value ,14);
			}else{
				strcpy(pCtx->ssid_prefix, value);
			}
		}
		else if (!strcmp(token,"PSK_LEN")) {
			printf("\n\nread PSK_LEN tocken\n\n");
			if ( atoi(value) > MAX_NETWORK_KEY_LEN || atoi(value) < MIN_NETWORK_KEY_LEN) {
				DEBUG_ERR("Invalid MAX_NETWORK_KEY_LEN [%d] , use default value\n", atoi(value));
			}else{
				pCtx->random_psk_len = atoi(value) ;

			}
		}
		else if (!strcmp(token, "network_key")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid network_key length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->network_key, value);
            pCtx->network_key_len = strlen(value);
			//WSC_DEBUG("network_key=%s\n",pCtx->network_key);

		}
		else if (!strcmp(token, "wep_key2")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key2 length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key2, value);
		}
		else if (!strcmp(token, "wep_key3")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key3 length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key3, value);
		}
		else if (!strcmp(token, "wep_key4")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid wep_key4 length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy((char*)pCtx->wep_key4, value);

		}
		else if (!strcmp(token, "tx_timeout")) {
			pCtx->tx_timeout = atoi(value);
		}
		else if (!strcmp(token, "resent_limit")) {
			pCtx->resent_limit = atoi(value);
		}
		else if (!strcmp(token, "reg_timeout")) {
			pCtx->reg_timeout = atoi(value);
		}

#ifdef BLOCKED_ROGUE_STA
		else if (!strcmp(token, "block_timeout")) {
			pCtx->blocked_expired_time = (unsigned char)atoi(value);
		}
#endif
#ifdef MUL_PBC_DETECTTION
		else if (!strcmp(token, "WPS_PBC_overlapping_GPIO_number")) {
			pCtx->WPS_PBC_overlapping_GPIO_number= atoi(value);
		}
		else if (!strcmp(token, "PBC_overlapping_LED_time_out")) {
			pCtx->PBC_overlapping_LED_time_out = atoi(value);
		}
#endif
		else if (!strcmp(token, "WPS_END_LED_unconfig_GPIO_number")) {
			pCtx->WPS_END_LED_unconfig_GPIO_number = atoi(value);
		}
		else if (!strcmp(token, "WPS_END_LED_config_GPIO_number")) {
			pCtx->WPS_END_LED_config_GPIO_number = atoi(value);
		}
		else if (!strcmp(token, "WPS_START_LED_GPIO_number")) {
			pCtx->WPS_START_LED_GPIO_number = atoi(value);
		}
		else if (!strcmp(token, "No_ifname_for_flash_set")) {
			pCtx->No_ifname_for_flash_set = atoi(value);
		}
		/* --- Forrest added, 2007.10.31. */
		else if (!strcmp(token, "WPS_ERROR_LED_time_out")) {
			pCtx->WPS_ERROR_LED_time_out = atoi(value);
		}
		else if (!strcmp(token, "WPS_ERROR_LED_GPIO_number")) {
			pCtx->WPS_ERROR_LED_GPIO_number = atoi(value);
		}
		else if (!strcmp(token, "WPS_SUCCESS_LED_time_out")) {
			pCtx->WPS_SUCCESS_LED_time_out = atoi(value);
		}
		else if (!strcmp(token, "WPS_SUCCESS_LED_GPIO_number")) {
			pCtx->WPS_SUCCESS_LED_GPIO_number = atoi(value);
		}
		/* Forrest added, 2007.10.31. --- */
		else if (!strcmp(token,"disable_disconnect")){
			pCtx->disable_disconnect = atoi(value);
        }
		else if (!strcmp(token,"disable_auto_gen_ssid")) {
			pCtx->disable_auto_gen_ssid = atoi(value);
        }
		else if (!strcmp(token,"manual_key_type")) {
			pCtx->manual_key_type = atoi(value);
        }
		else if (!strcmp(token, "manual_key")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid manual_key length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manual_key, value);
		}
		else if (!strcmp(token, "random_key_len")) {
			if (atoi(value) > MAX_NETWORK_KEY_LEN || atoi(value) < MIN_NETWORK_KEY_LEN) {
				DEBUG_ERR("Invalid random_key_len [%d]!\n", atoi(value));
				pCtx->manauall_random_psk_len = 0 ;
			}else{
				pCtx->manauall_random_psk_len = atoi(value) ;
			}

		}
		else if (!strcmp(token,"disable_hidden_ap")){
			pCtx->disable_hidden_ap= atoi(value);
        }
		else if (!strcmp(token,"config_by_ext_reg")) {
			pCtx->config_by_ext_reg = atoi(value);
		}
		else if (!strcmp(token,"fix_wzc_wep")) {
			pCtx->fix_wzc_wep = atoi(value);
		}
		else if (!strcmp(token,"ProfileDontBothApply")) {
			pCtx->ProfileDontBothApply = atoi(value);
		}
		#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION
		else if (!strcmp(token,"MaxPinFailThresHold")) {
			
			pCtx->MaxPinFailThresHold = atoi(value);

			if(pCtx->MaxPinFailThresHold>10 || pCtx->MaxPinFailThresHold <1){
				pCtx->MaxPinFailThresHold=10;
			}
		}		
#endif		
#ifdef CONFIG_IWPRIV_INTF
		else if (!strcmp(token, "wps_rf_band")) {
			pCtx->rf_band = atoi((def)?(char*)wsc_parms_default[wsc_rf_band].value:value);
		}
		else if (!strcmp(token, "wps_mode")) {
			if (pCtx->mode != -1)
				continue;
			pCtx->mode = atoi((def)?(char*)wsc_parms_default[wsc_mode].value:value);
		}
		else if (!strcmp(token, "wps_manual_enabled")) {
			pCtx->manual_config = atoi((def)?(char*)wsc_parms_default[wsc_manual].value:value);
		}
		else if (!strcmp(token, "wps_use_ie")) {
			pCtx->use_ie = atoi(value);
		}
		else if (!strcmp(token, "wps_config_method")) {
			if (pCtx->config_method != -1) // set in argument
				continue;
			pCtx->config_method = atoi((def)?(char*)wsc_parms_default[wsc_config_methods].value:value);
			if (!(pCtx->config_method & (CONFIG_METHOD_PIN | CONFIG_METHOD_PBC))) {
				DEBUG_ERR("Invalid config_method value [%d]! Use default.\n", pCtx->config_method);
				pCtx->config_method = (CONFIG_METHOD_PIN | CONFIG_METHOD_PBC | CONFIG_METHOD_ETH);
			}
		}
		else if (!strcmp(token, "wps_pin_code")) {
			int code_len;
			if (strlen(pCtx->pin_code) > 0) // set in argument
				continue;
			code_len = strlen(value);
			if (code_len != PIN_LEN && code_len != 4) {
				DEBUG_ERR("Invalid pin_code length!\n");
				return -1;
			}
			i = atoi(value);
			if (code_len == PIN_LEN) {
				if (!validate_pin_code(i)) {
					DEBUG_ERR("Invalid pin_code value (checksum error)!\n");
					return -1;
				}
			}
			strcpy(pCtx->pin_code, (def)?(char*)wsc_parms_default[wsc_pin_code].value:value);
		}

		else if (!strcmp(token, "wps_auth_type_flags")) {
			pCtx->auth_type_flags = atoi(value);
			if (!(pCtx->auth_type_flags & (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA |
					WSC_AUTH_WPA2 | WSC_AUTH_WPA2PSK))) {
				DEBUG_ERR("Invalid auth_type_flags value [0x%x]!\n", pCtx->auth_type_flags);
				return -1;
			}
		}
		else if (!strcmp(token, "wps_encrypt_type_flags")) {
			pCtx->encrypt_type_flags = atoi(value);
			if (!(pCtx->encrypt_type_flags & (WSC_ENCRYPT_NONE |WSC_ENCRYPT_WEP |WSC_ENCRYPT_TKIP|WSC_ENCRYPT_AES))) {
				DEBUG_ERR("Invalid encrypt_type_flags value [0x%x]!\n", pCtx->encrypt_type_flags);
				return -1;
			}
		}
		else if (!strcmp(token, "wps_wep_transmit_key")) {
			pCtx->wep_transmit_key = atoi(value);
			if (pCtx->encrypt_type == WSC_ENCRYPT_WEP &&
				(pCtx->wep_transmit_key < 1 || pCtx->wep_transmit_key > 4)) {
				DEBUG_ERR("Invalid wep_transmit_key value [%d]!\n", pCtx->wep_transmit_key);
				return -1;
			}
		}
		else if (!strcmp(token, "wps_connection_type")) {
			if (pCtx->connect_type != -1) // set in argument
				continue;
			pCtx->connect_type = atoi((def)?(char*)wsc_parms_default[wsc_connection_type].value:value);
			if (pCtx->connect_type != CONNECT_TYPE_BSS && pCtx->connect_type != CONNECT_TYPE_IBSS) {
				DEBUG_ERR("Invalid connection_type value [%d]!\n", pCtx->connect_type);
				return -1;
			}
		}
		else if (!strcmp(token, "wps_uuid")) {
			if (strlen(value) != UUID_LEN*2) {
				DEBUG_ERR("Invalid uuid length!\n");
				return -1;
			}
			ptr = value;
			for (i=0; i<UUID_LEN; i++, ptr+=2) {
				if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
					DEBUG_ERR("Invalid uuid vlaue!\n");
					return -1;
				}
				pCtx->uuid[i] = convert_atob(ptr, 16);
			}
		}else if (!strcmp(token, "wps_modelDescription")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid modelDescription length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manufacturerDesc, value);
		}//Brad add 20090206
		else if (!strcmp(token, "wps_manufacturer")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid manufacturer length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manufacturer, value);
		}//Brad add 20080721
		else if (!strcmp(token, "wps_manufacturerURL")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid manufacturer URL length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manufacturerURL, value);
		}
		else if (!strcmp(token, "wps_modelURL")) {
			if (strlen(value) > MAX_MANUFACT_LEN) {
				DEBUG_ERR("Invalid model URL length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->model_URL, value);
		}//Brad add end
		else if (!strcmp(token, "wps_model_name")) {
			if (strlen(value) > MAX_MODEL_NAME_LEN) {
				DEBUG_ERR("Invalid model_name length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->model_name, value);
		}
		else if (!strcmp(token, "wps_model_num")) {
			if (strlen(value) > MAX_MODEL_NAME_LEN) {
				DEBUG_ERR("Invalid model_num length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->model_num, value);
		}
		else if (!strcmp(token, "wps_serial_num")) {
			if (strlen(value) > MAX_SERIAL_NUM_LEN) {
				DEBUG_ERR("Invalid serial_num length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->serial_num, value);
		}
		else if (!strcmp(token, "wps_device_category_id")) {
			pCtx->device_category_id = atoi(value);
		}
		else if (!strcmp(token, "wps_device_sub_category_id")) {
			pCtx->device_sub_category_id = atoi(value);
		}
		else if (!strcmp(token, "wps_device_oui")) {
			if (strlen(value) != OUI_LEN*2) {
				DEBUG_ERR("Invalid oui length!\n");
				return -1;
			}
			ptr = value;
			for (i=0; i<OUI_LEN; i++, ptr+=2) {
				if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
					DEBUG_ERR("Invalid OUI vlaue!\n");
					return -1;
				}
				pCtx->device_oui[i] = convert_atob(ptr, 16);
			}
		}
		else if (!strcmp(token, "wps_device_name")) {
						if(def)
			if (strlen(value) > MAX_DEVICE_NAME_LEN) {
				DEBUG_ERR("Invalid device_name length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->device_name, (def)?(char*)wsc_parms_default[wsc_device_name].value:value);
		}
		else if (!strcmp(token, "wps_device_password_id")) {
			pCtx->device_password_id = atoi(value);
		}
		else if (!strcmp(token, "wps_disable_configured_by_exReg")) {
			pCtx->disable_configured_by_exReg = atoi(value);

		}
#ifdef	DET_WPS_SPEC
		else if (!strcmp(token, "wps_button_hold_time")) {
			pCtx->button_hold_time = atoi(value);
		}
#endif
		else if (!strcmp(token, "wps_tx_timeout")) {
			pCtx->tx_timeout = atoi(value);
		}
		else if (!strcmp(token, "wps_resent_limit")) {
			pCtx->resent_limit = atoi(value);
		}
		else if (!strcmp(token, "wps_reg_timeout")) {
			pCtx->reg_timeout = atoi(value);
		}

#ifdef BLOCKED_ROGUE_STA
		else if (!strcmp(token, "wps_block_timeout")) {
			pCtx->blocked_expired_time = (unsigned char)atoi(value);
		}
#endif
		else if (!strcmp(token, "WPS_No_ifname_for_flash_set")) {
			pCtx->No_ifname_for_flash_set = atoi(value);
		}
		/* Forrest added, 2007.10.31. --- */
		else if (!strcmp(token,"wps_disable_disconnect")){
			pCtx->disable_disconnect = atoi(value);
        }
		else if (!strcmp(token,"wps_disable_auto_gen_ssid")) {
			pCtx->disable_auto_gen_ssid = atoi(value);
        }
		else if (!strcmp(token,"wps_manual_key_type")) {
			pCtx->manual_key_type = atoi(value);
        }
		else if (!strcmp(token, "wps_manual_key")) {
			if (strlen(value) > 64) {
				DEBUG_ERR("Invalid manual_key length [%d]!\n", strlen(value));
				return -1;
			}
			strcpy(pCtx->manual_key, value);
		}

		else if (!strcmp(token,"wps_disable_hidden_ap")){
			pCtx->disable_hidden_ap= atoi(value);
        }
#ifdef	DET_WPS_SPEC
		else if (!strcmp(token, "wps_button_hold_time")) {
			pCtx->button_hold_time = atoi(value);
		}
#endif
		else{
			get_wps_wltoken(pCtx, token, value, def);
		}

#endif //CONFIG_IWPRIV_INTF
	}

#ifdef MUL_PBC_DETECTTION
	if (pCtx->PBC_overlapping_LED_time_out <= 0)
		pCtx->PBC_overlapping_LED_time_out = 30;
#endif
#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION
	if(pCtx->MaxPinFailThresHold==0){
		pCtx->MaxPinFailThresHold=ALD_INDEFINITE_TH;
	}
#endif
	if (pCtx->WPS_ERROR_LED_time_out <= 0)
		pCtx->WPS_ERROR_LED_time_out = 30;
	if (pCtx->WPS_SUCCESS_LED_time_out <= 0)
		pCtx->WPS_SUCCESS_LED_time_out = 300;


#ifdef	DET_WPS_SPEC
	// 2009-0414 for button-hold-time be configurable
	if(pCtx->button_hold_time <=0){
		pCtx->button_hold_method = BUTTON_NEED_NOT_HOLD;	// need not hold button
	}else{
		pCtx->button_hold_method = BUTTON_NEED_HOLD;	// need hold button and wait
	}
#else
	if(pCtx->button_hold_time <=0){
		pCtx->button_hold_time = BUTTON_HOLD_TIME ;
	}
#endif

	if (pCtx->auth_type == WSC_AUTH_OPEN && pCtx->encrypt_type == WSC_ENCRYPT_NONE) {
		memset(pCtx->network_key, 0, MAX_NETWORK_KEY_LEN+1);
		pCtx->network_key_len = 0;
	}

	if ((pCtx->auth_type == WSC_AUTH_OPEN && pCtx->encrypt_type == WSC_ENCRYPT_WEP) ||
		(pCtx->auth_type == WSC_AUTH_SHARED && pCtx->encrypt_type == WSC_ENCRYPT_WEP)) {
		if (pCtx->wep_transmit_key >= 1 && pCtx->wep_transmit_key <= 4) {
			switch (pCtx->wep_transmit_key)
			{
				case 2:
					memcpy(pCtx->network_key, pCtx->wep_key2, MAX_NETWORK_KEY_LEN+1);
					break;
				case 3:
					memcpy(pCtx->network_key, pCtx->wep_key3, MAX_NETWORK_KEY_LEN+1);
					break;
				case 4:
					memcpy(pCtx->network_key, pCtx->wep_key4, MAX_NETWORK_KEY_LEN+1);
					break;
				default:
					break;
			}

			pCtx->network_key_len = strlen((char *)pCtx->network_key);
			#if 0
			/*2011-0419 WEP,HEX type key issue-start*/
			WSC_DEBUG("network_key=%s\n",pCtx->network_key);
			idx = strlen(pCtx->network_key);
			string_to_hex(pCtx->network_key, token, idx);
			memcpy(pCtx->network_key,token,idx/2);
			pCtx->network_key[idx/2]='\0';
			pCtx->network_key_len = idx/2 ;
			#endif

		}
		else {
			DEBUG_ERR("Error wep_transmit_key [%d]!\n", pCtx->wep_transmit_key);
			return -1;
		}
	}

#ifdef FOR_DUAL_BAND
	if (pCtx->auth_type2 == WSC_AUTH_OPEN && pCtx->encrypt_type2 == WSC_ENCRYPT_NONE) {
		memset(pCtx->network_key2, 0, MAX_NETWORK_KEY_LEN+1);
		pCtx->network_key_len2 = 0;
	}
	if ((pCtx->auth_type2 == WSC_AUTH_OPEN && pCtx->encrypt_type2 == WSC_ENCRYPT_WEP) ||
		(pCtx->auth_type2 == WSC_AUTH_SHARED && pCtx->encrypt_type2 == WSC_ENCRYPT_WEP)) {
		if (pCtx->wep_transmit_key2 >= 1 && pCtx->wep_transmit_key2 <= 4) {
			switch (pCtx->wep_transmit_key2)
			{
				case 2:
					memcpy(pCtx->network_key2, pCtx->wep_key22, MAX_NETWORK_KEY_LEN+1);
					break;
				case 3:
					memcpy(pCtx->network_key2, pCtx->wep_key32, MAX_NETWORK_KEY_LEN+1);
					break;
				case 4:
					memcpy(pCtx->network_key2, pCtx->wep_key42, MAX_NETWORK_KEY_LEN+1);
					break;
				default:
					break;
			}
			pCtx->network_key_len2 = strlen((char *)pCtx->network_key2);
#if	0
			/*2011-0419 WEP,HEX type key issue-start*/
			idx = strlen(pCtx->network_key2);
			string_to_hex(pCtx->network_key2, token, idx);
			memcpy(pCtx->network_key2,token,idx/2);
			pCtx->network_key2[idx/2]='\0';
			pCtx->network_key_len2 = idx/2 ;
			WSC_DEBUG("network_key2=%s\n",pCtx->network_key2);
#endif

		}
		else {
			DEBUG_ERR("Error wep_transmit_key [%d]!\n", pCtx->wep_transmit_key2);
			return -1;
		}
	}
#endif

	fclose(fp);

	return 0;
}
#else
static int read_config_file(CTX_Tp pCtx, char *filename, int def)
{
	int i;
	char *ptr;
	char uuid[] = "6304125310192006122800e04c8196c1";
	char device_oui[] = "0050f204";
#ifndef CONFIG_SDIO_HCI
	HW_SETTING_T *hs;
#endif

	// UUID
	if (strlen(uuid) != UUID_LEN*2) {
		printf("Invalid uuid length!\n");
		return -1;
	}
	ptr = uuid;
	for (i=0; i<UUID_LEN; i++, ptr+=2) {
		if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
			printf("Invalid uuid vlaue!\n");
			return -1;
		}
		pCtx->uuid[i] = convert_atob(ptr, 16);
	}
#ifdef CONFIG_SDIO_HCI
	// UUID, replace last 12 char with hw mac address
	for (i=0; i<6; i++)
		pCtx->uuid[10+i] = pCtx->our_addr[i];
#else
	// read hw settings from flash
	hs = (HW_SETTING_T *)read_hw_settings();
	if (hs == NULL) {
		printf("%s failure.\n", __FUNCTION__);
		return 0;
	}
	// UUID, replace last 12 char with hw mac address
	for (i=0; i<6; i++)
		pCtx->uuid[10+i] = hs->wlan[0].macAddr[i];

	// PIN
	if ((hs->wlan[0].wscPin[0] == '\0') ||
	    (strcmp((char *)hs->wlan[0].wscPin, "00000000")==0)) {
		printf("PIN is invalid in hw settings. Use \"12345670\".\n");
		strcpy(pCtx->pin_code, "12345670");
	}
	else {
		int code;
		
		code = atoi((char *)hs->wlan[0].wscPin);
		if (!validate_pin_code(code)) {
			printf("PIN checksum is wrong in hw settings. Use \"12345670\".\n");
			strcpy(pCtx->pin_code, "12345670");
		}
		else {
			strcpy(pCtx->pin_code, (char *)hs->wlan[0].wscPin);
		}
	}

	free(hs);
#endif
	/*--------------------------------------------------------------------*/
	/* 
	 * 0= not use, the registration protocol may not proceed successfully
	 * 1=use ie
	 * 2= used ie & auto generated SSID in the format of ssid+last 2 bytes mac
	 */
	pCtx->use_ie = 1;
	
	/* 
	 * If "use_ie"!=2 and "disable_auto_gen_ssid" != 1 then use this parameter as prefix of SSID
	 * default case use "WPS"  as prefix of SSID.
	 */
#if 0
	strcpy(pCtx->ssid_prefix, "RTKAP_");
#endif
	/* auth_type_flags */
	if ((pCtx->auth_type_flags & (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA | 
			WSC_AUTH_WPA2 | WSC_AUTH_WPA2PSK))==0) 
	{			
		WSC_DEBUG("Invalid auth_type_flags value [0x%x]!\n", pCtx->auth_type_flags);
		pCtx->auth_type_flags = (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK |  WSC_AUTH_WPA2PSK);		
	}

			

	/* encrypt_type_flags */
	if ((pCtx->encrypt_type_flags & 
		(WSC_ENCRYPT_NONE |WSC_ENCRYPT_WEP |WSC_ENCRYPT_TKIP|WSC_ENCRYPT_AES))==0) {			
		WSC_DEBUG("Invalid encrypt_type_flags value [0x%x]!\n", pCtx->encrypt_type_flags);
		pCtx->encrypt_type_flags = 
			(WSC_ENCRYPT_NONE | WSC_ENCRYPT_TKIP | WSC_ENCRYPT_AES );		

	}
//	WSC_DEBUG("encrypt_type_flags:%d\n",pCtx->encrypt_type_flags);			
	/* encrypt_type_flags */

	/*	auth_type	*/
	if((pCtx->auth_type_flash & 
 				 (WSC_AUTH_OPEN | WSC_AUTH_WPAPSK | WSC_AUTH_SHARED | WSC_AUTH_WPA
				 | WSC_AUTH_WPA2| WSC_AUTH_WPA2PSK| WSC_AUTH_WPA2PSKMIXED))==0){
		WSC_DEBUG("Invalid auth_type value [0x%x]! Use default.\n", pCtx->auth_type_flash);				 
		pCtx->auth_type_flash = WSC_AUTH_OPEN;
	}
				 

	if (pCtx->auth_type_flash == WSC_AUTH_WPA2PSKMIXED)
		pCtx->auth_type = WSC_AUTH_WPA2PSK;
	else
		pCtx->auth_type = pCtx->auth_type_flash;
	
	/*	auth_type	*/
	
	/*	encrypt_type	*/
	if ( (pCtx->encrypt_type_flash & (WSC_ENCRYPT_NONE | WSC_ENCRYPT_WEP | WSC_ENCRYPT_TKIP | WSC_ENCRYPT_AES ))==0)
	{
		DEBUG_ERR("Invalid encrypt_type [0x%x]! Use default.\n", pCtx->encrypt_type_flash);
		pCtx->encrypt_type_flash = WSC_ENCRYPT_NONE;
	}
	
	if (pCtx->encrypt_type_flash == WSC_ENCRYPT_TKIPAES) {
		if (pCtx->auth_type == WSC_AUTH_WPA2PSK)
			pCtx->encrypt_type = WSC_ENCRYPT_AES;
		else
			pCtx->encrypt_type = WSC_ENCRYPT_TKIP;
	}
	else{
		pCtx->encrypt_type = pCtx->encrypt_type_flash;

	}
//	WSC_DEBUG("encrypt_type_flash:%d\n",pCtx->encrypt_type_flash);			
//	WSC_DEBUG("encrypt_type:%d\n",pCtx->encrypt_type);
	/*	encrypt_type	*/
#if 0
	strcpy(pCtx->manufacturerDesc, "WLAN Access Point");
	strcpy(pCtx->manufacturer, "Realtek Semiconductor Corp.");
	strcpy(pCtx->manufacturerURL, "http://www.realtek.com/");
	strcpy(pCtx->model_URL, "http://www.realtek.com/");
	strcpy(pCtx->model_name, "RTL8xxx");
	strcpy(pCtx->model_num, "RTK_ECOS");
	strcpy(pCtx->serial_num, "123456789012347");
#endif
	pCtx->device_category_id = 6;			
	pCtx->device_sub_category_id = 1;			

	if (strlen(device_oui) != OUI_LEN*2) {
		printf("Invalid oui length!\n");
		return -1;
	}
	ptr = device_oui;
	for (i=0; i<OUI_LEN; i++, ptr+=2) {
		if ( !isxdigit((int)*ptr) || !isxdigit((int)*(ptr+1)) ) {
			printf("Invalid OUI vlaue!\n");
			return -1;
		}
		pCtx->device_oui[i] = convert_atob(ptr, 16);			
	}
	
	//PASS_ID_DEFAULT=0, PASS_ID_USER=1, PASS_ID_MACHINE=2, PASS_ID_REKEY=3,
	//PASS_ID_PB=4, PASS_ID_REG=5, PASS_ID_RESERVED=6
	pCtx->device_password_id = 0;

	pCtx->tx_timeout = 15;//5
	pCtx->resent_limit = 10;// 2
	pCtx->reg_timeout = 120;
#ifdef BLOCKED_ROGUE_STA
	pCtx->blocked_expired_time = 60; //block_timeout
#endif

	pCtx->WPS_START_LED_GPIO_number = 2;
	pCtx->WPS_END_LED_unconfig_GPIO_number = 0;
	pCtx->WPS_END_LED_config_GPIO_number = 0;
#ifdef MUL_PBC_DETECTTION
	pCtx->WPS_PBC_overlapping_GPIO_number= 1;
	pCtx->PBC_overlapping_LED_time_out = 30;
#endif

	//When 0, WPS daemon will issue command 'flash set wlan0 value' to update setting
	//When 1, WPS daemon will issue command 'flash set value' to update setting
	//When 2, WPS daemon will update setting to a file '/tmp/flash_param'
	pCtx->No_ifname_for_flash_set = 0;

	//Disable to send dis-association to STA after WPS is done. 1:disable, 0:enable
	//pCtx->disable_disconnect = 1;

	//Disable auto generate SSID in un-configured state
	//pCtx->disable_auto_gen_ssid = 1;

	//(A)Manual assigned encryption type. 0:disable, 1:WPA-TKIP, 2:WPA2-AES, 3:Mixed-AES-TKIP
	//pCtx->manual_key_type = 2;

	//(A1)if manual_key_type == 1~3 ,
	//you can alternative select 1)assigned manual psk value(manual_key) 
	//or 2)assigned random key length(random_key_len)
	//PSK valid key length between 8~64 ; if manual_key no assigned  and random_key_len no assigned
	//then use 1234567890 as default
	//strcpy(pCtx->manual_key, "1234567890");
	//pCtx->manauall_random_psk_len = 64;
	
	//(A2)if manual_key_type == 0,you can assigned PSK length between 8~64
	//PSK_LEN = 64
	//pCtx->random_psk_len = 64;
		
	//Disable hidden AP when wsc is activiated
	pCtx->disable_hidden_ap= 1;

	pCtx->button_hold_time = 2;
	
	//Enable the fix for Windows-Zero-Config WEP issue
	pCtx->fix_wzc_wep = 0;	// plus

	/*--------------------------------------------------------------------*/
#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION
	if(pCtx->MaxPinFailThresHold==0){
		pCtx->MaxPinFailThresHold=ALD_INDEFINITE_TH;
	}
#endif
	if (pCtx->WPS_ERROR_LED_time_out <= 0)
		pCtx->WPS_ERROR_LED_time_out = 30;
	if (pCtx->WPS_SUCCESS_LED_time_out <= 0)
		pCtx->WPS_SUCCESS_LED_time_out = 300;


#ifdef	DET_WPS_SPEC
	// 2009-0414 for button-hold-time be configurable
	if(pCtx->button_hold_time <=0){
		pCtx->button_hold_method = BUTTON_NEED_NOT_HOLD;	// need not hold button
	}else{
		pCtx->button_hold_method = BUTTON_NEED_HOLD;	// need hold button and wait
	}
#else
	if(pCtx->button_hold_time <=0){
		pCtx->button_hold_time = BUTTON_HOLD_TIME ;
	}
#endif

	if (pCtx->auth_type == WSC_AUTH_OPEN && pCtx->encrypt_type == WSC_ENCRYPT_NONE) {
		memset(pCtx->network_key, 0, MAX_NETWORK_KEY_LEN+1);
		pCtx->network_key_len = 0;
	}

	if ((pCtx->auth_type == WSC_AUTH_OPEN && pCtx->encrypt_type == WSC_ENCRYPT_WEP) ||
		(pCtx->auth_type == WSC_AUTH_SHARED && pCtx->encrypt_type == WSC_ENCRYPT_WEP)) {
		if (pCtx->wep_transmit_key >= 1 && pCtx->wep_transmit_key <= 4) {
			switch (pCtx->wep_transmit_key)
			{
				case 2:
					memcpy(pCtx->network_key, pCtx->wep_key2, MAX_NETWORK_KEY_LEN+1);
					break;
				case 3:
					memcpy(pCtx->network_key, pCtx->wep_key3, MAX_NETWORK_KEY_LEN+1);
					break;
				case 4:
					memcpy(pCtx->network_key, pCtx->wep_key4, MAX_NETWORK_KEY_LEN+1);
					break;
				default:
					break;
			}

			pCtx->network_key_len = strlen(pCtx->network_key);
		}
		else {
			printf("Error wep_transmit_key [%d]!\n", pCtx->wep_transmit_key);
			return -1;
		}
	}
	return 0;
}
#endif

#ifndef __ECOS
static void show_help()
{
	printf("  Usage: %s [argument]...\n", PROGRAM_NAME);
	printf("    Where arguments is optional as:\n");
	printf("\t-c config_filename, config filename, default is %s\n", DEFAULT_CONFIG_FILENAME);
	printf("\t-w wlan_interface, wlan interface\n");
#ifdef FOR_DUAL_BAND    
	printf("\t-w2 wlan_interface, wlan interface for second band\n");
    printf("\t-prefer_band val, 0:first band, 1:second band, used only for dual-band client\n");
#endif

#ifdef SUPPORT_UPNP
	printf("\t-br bridge_interface, lan interface\n");
#endif
#ifndef NO_IWCONTROL
	printf("\t-fi fifo_name, wlan fifo path name\n");
#ifdef FOR_DUAL_BAND    
    printf("\t-fi2 fifo_name, wlan fifo path name for second band\n");
#endif
#endif
	printf("\t-method val, 1: PIN, 2: PBC, 3: both\n");
	printf("\t-mode val, 1: ap unconfigured, 2: client unconfigured (enrollee),\n");
	printf("\t\t3: client configured (registrar), 4: ap-proxy configured, 5: ap-proxy registrar\n");
	printf("\t-upnp val, 1 - support upnp, 0 - not support (default)\n");
	printf("\t-gen-pin, generate pin code for local entitiy\n");
	printf("\t-peer_pin, assign pin code for peer entitiy\n");
	printf("\t-local_pin, assign pin code for local device\n");
	printf("\t-sig_start, start wsc protocol\n");
	printf("\t-sig_pbc, signal PBC mode\n");
	printf("\t-start_pbc, start PBC mode\n");
	printf("\t-daemon, run as daemon\n");
#ifdef DEBUG
	printf("\t-debug, turn on debug message\n");
#endif
#ifdef TEST
	printf("\t-test, go to test mode\n");
#endif

	printf("\n");
}

void issue_signal_to_wscd(CTX_Tp pCtx , int SIG_NUMBER ,char *interName)
{
	int pid;
	FILE *fp;
	char line[100];
	WSC_DEBUG("interName:%s\n",interName);
	#if 1
	DIR *dir;
	struct dirent *next;
	dir = opendir("/var/run");
	if (!dir) {
			printf("Cannot open %s", "/var/run");
			return 0;
	}
	while ((next = readdir(dir)) != NULL){
		if(!strncmp(next->d_name, "wscd", strlen("wscd"))){
			WSC_DEBUG("d_name:%s\n",next->d_name);
			sprintf(pCtx->pid_filename, "/var/run/%s",next->d_name);
			break;
		}
	}
	closedir(dir);
	#endif
    //sprintf(pCtx->pid_filename, "%s-%s.pid",DEFAULT_PID_FILENAME,interName);
	WSC_DEBUG("pCtx->pid_filename:%s\n",pCtx->pid_filename);
    if ((fp = fopen(pCtx->pid_filename, "r")) != NULL) {
        fgets(line, sizeof(line), fp);
		WSC_DEBUG("line:%s\n",line);
        if (sscanf(line, "%d", &pid)) {
            if (pid > 1){
                kill(pid, SIG_NUMBER);
                WSC_DEBUG("kill sig(%d),pid(%d)\n",SIG_NUMBER ,pid);
            }
        }
        fclose(fp);
        return;
    }

#ifdef FOR_DUAL_BAND

#ifdef CONFIG_RTL_REPEATER_WPS_SUPPORT
    if(strcmp(interName+5, "-vxd") == 0) {
        sprintf(pCtx->pid_filename, "%s-wlan0-wlan1-c.pid", DEFAULT_PID_FILENAME);
        if ((fp = fopen(pCtx->pid_filename, "r")) != NULL) {
            fgets(line, sizeof(line), fp);
            if (sscanf(line, "%d", &pid)) {
                if (pid > 1){
                    kill(pid, SIG_NUMBER);
                    WSC_DEBUG("kill sig(%d),pid(%d)\n",SIG_NUMBER ,pid);
                }
            }
            fclose(fp);
        }        
        return;
    }
#endif    
    sprintf(pCtx->pid_filename, "%s-wlan0-wlan1.pid", 	DEFAULT_PID_FILENAME);
    if ((fp = fopen(pCtx->pid_filename, "r")) != NULL) {
        fgets(line, sizeof(line), fp);
        if (sscanf(line, "%d", &pid)) {
            if (pid > 1){
                kill(pid, SIG_NUMBER);
                WSC_DEBUG("kill sig(%d),pid(%d)\n",SIG_NUMBER ,pid);
            }
        }
        fclose(fp);
        return;
    }

    sprintf(pCtx->pid_filename, "%s-wlan0-wlan1-c.pid", DEFAULT_PID_FILENAME);
    if ((fp = fopen(pCtx->pid_filename, "r")) != NULL) {
        fgets(line, sizeof(line), fp);
        if (sscanf(line, "%d", &pid)) {
            if (pid > 1){
                kill(pid, SIG_NUMBER);
                WSC_DEBUG("kill sig(%d),pid(%d)\n",SIG_NUMBER ,pid);
            }
        }
        fclose(fp);
        return;
    }
#endif
    WSC_DEBUG("trigger sig(%d),pid(%d)\n",SIG_NUMBER ,pid);

}

static int parse_argument(CTX_Tp pCtx, int argc, char *argv[], int *start_pbc)
{
	int argNum=1;
//	int pid;
//	FILE *fp;
//	unsigned char line[100];
	char tmpbuf[100];

	DBFENTER;
	while (argNum < argc) {
		if ( !strcmp(argv[argNum], "-c")) {
			if (++argNum >= argc)
				break;
			strcpy(pCtx->cfg_filename, argv[argNum]);
		}
		else if ( !strcmp(argv[argNum], "-w")) {
            _DEBUG_PRINT("\n");
            if (++argNum >= argc)
                break;
            _DEBUG_PRINT("\n");
            strcpy(pCtx->wlan_interface_name, argv[argNum]);           
		}

#ifdef SUPPORT_UPNP
		else if ( !strcmp(argv[argNum], "-br")) {
			if (++argNum >= argc)
				break;
			strcpy(pCtx->lan_interface_name, argv[argNum]);
		}
#endif
		else if ( !strcmp(argv[argNum], "-fi")) {
			if (++argNum >= argc)
				break;
			strcpy(pCtx->fifo_name, argv[argNum]);
		}
#ifdef FOR_DUAL_BAND
        else if ( !strcmp(argv[argNum], "-fi2")) {
            if (++argNum >= argc)
                break;
            strcpy(pCtx->fifo_name2, argv[argNum]);
        }
        else if ( !strcmp(argv[argNum], "-w2")) {
            if (++argNum >= argc)
                break;
            strcpy(pCtx->wlan_interface_name2, argv[argNum]);
        }        
        else if(!strcmp(argv[argNum], "-prefer_band")) {
            if (++argNum >= argc)
                break;
            pCtx->prefer_band = (argv[argNum][0] == '0')?0:1;
        }        
#endif        
		else if ( !strcmp(argv[argNum], "-mode")) {
			if (++argNum >= argc)
				break;
			pCtx->mode = atoi(argv[argNum]);
			if (pCtx->mode != MODE_AP_UNCONFIG &&
					pCtx->mode != MODE_CLIENT_UNCONFIG &&
					pCtx->mode != MODE_CLIENT_CONFIG &&
					pCtx->mode != MODE_AP_PROXY &&
					pCtx->mode != MODE_AP_PROXY_REGISTRAR &&
					pCtx->mode != MODE_CLIENT_UNCONFIG_REGISTRAR) {
				DEBUG_ERR("Invalid mode value [%d]!\n", pCtx->mode);
				return -1;
			}
		}
		else if ( !strcmp(argv[argNum], "-gen-pin")) {
			struct timeval tod;
			unsigned long num;

			gettimeofday(&tod , NULL);
			srand(tod.tv_sec);
			num = rand() % 10000000;
			num = num*10 + compute_pin_checksum(num);
			convert_hex_to_ascii((unsigned long)num, tmpbuf);
			printf("PIN: %s\n", tmpbuf);
			strcpy(pCtx->pin_code, tmpbuf);
		}
		else if ( !strcmp(argv[argNum], "-upnp")) {
			if (++argNum >= argc)
				break;
			pCtx->upnp = atoi(argv[argNum]);
		}
		else if ( !strcmp(argv[argNum], "-peer_pin")) {
			if (++argNum >= argc)
				break;
			strcpy(pCtx->peer_pin_code, argv[argNum]);
		}
		else if ( !strcmp(argv[argNum], "-local_pin")) {
			if (++argNum >= argc)
				break;
			strcpy(pCtx->pin_code, argv[argNum]);
		}
		else if ( !strcmp(argv[argNum], "-method")) {
			if (++argNum >= argc)
				break;
			pCtx->config_method = atoi(argv[argNum]);
			WSC_DEBUG("pCtx->config_method=%x\n",pCtx->config_method);
		}
		else if ( !strcmp(argv[argNum], "-start")) {
			pCtx->start = 1;
		}
		else if ( !strcmp(argv[argNum], "-sig_start")) {

			if (++argNum >= argc){
				printf("trigger cmd:wscd -sig_start interface\n");
				return -1;
			}
			issue_signal_to_wscd(pCtx , SIGTSTP ,argv[argNum]);

			return -1;
		}
		else if ( !strcmp(argv[argNum], "-sig_pbc")) {
			WSC_DEBUG("-sig_pbc!!!!!!!!!!!!\n");

			if (++argNum >= argc){
				printf("trigger cmd:wscd -sig_pbc interface\n");
				return -1;
			}
			issue_signal_to_wscd(pCtx , SIGUSR2 , argv[argNum]);
			return -1;
		}
#ifdef	AUTO_LOCK_DOWN
		else if ( !strcmp(argv[argNum], "-sig_unlock")) {
			if (++argNum >= argc){
				printf("trigger cmd:wscd -sig_unlock interface\n");
				return -1;
			}
			issue_signal_to_wscd(pCtx , SIGUSR1 ,argv[argNum]);
			return -1;
		}
#endif
		else if ( !strcmp(argv[argNum], "-start_pbc")) {
			*start_pbc = 1;
		}

#ifdef DEBUG
		else if ( !strcmp(argv[argNum], "-debug")) {
				pCtx->debug = 1;
		}
#endif

#ifdef TEST
		else if ( !strcmp(argv[argNum], "-test")) {
				pCtx->test = 1;
		}
#endif
		else if ( !strcmp(argv[argNum], "-connection_type")) {
			if (++argNum >= argc)
				break;
			pCtx->connect_type = atoi(argv[argNum]);
			if (pCtx->connect_type != CONNECT_TYPE_BSS && pCtx->connect_type != CONNECT_TYPE_IBSS) {
				DEBUG_ERR("Invalid connection_type value [%d]!\n", pCtx->connect_type);
				return -1;
			}
		}
		else if ( !strcmp(argv[argNum], "-ssid")) {
			if (++argNum >= argc)
				break;
			if (strlen(argv[argNum]) > WSC_MAX_SSID_LEN) {
				DEBUG_ERR("Invalid ssid length [%d]!\n", strlen(argv[argNum]));
				return -1;
			}
			strcpy(pCtx->SSID, argv[argNum]);
		}
#ifdef MUL_PBC_DETECTTION
		else if ( !strcmp(argv[argNum], "-disable_PBC_detection")) {
			if (++argNum >= argc)
				break;
			pCtx->disable_MulPBC_detection = atoi(argv[argNum]);
			if (pCtx->disable_MulPBC_detection != 0 && pCtx->disable_MulPBC_detection != 1) {
				DEBUG_ERR("Invalid disable_PBC_detection value [%d]!\n", pCtx->disable_MulPBC_detection);
				return -1;
			}
		}
#endif
#ifdef SUPPORT_UPNP
		else if ( !strcmp(argv[argNum], "-64decode") ){

			unsigned char *bistr = NULL;
			int bistr_len=0;

			if (++argNum >= argc)
				break;

			if( strlen(argv[argNum]) < 513 ){
				bistr_len = ILibBase64Decode((unsigned char *)argv[argNum],strlen(argv[argNum]),&bistr);
				//hex_dump(bistr,bistr_len);
			}
			return -1;
		}
#endif
		else if ( !strcmp(argv[argNum], "-daemon")) {
				pCtx->daemon = 1;
		}
#ifdef WPS_FOR_ASUS
		else if (!strcmp(argv[argNum], "-pbc_state_file")){
            if (++argNum >= argc)
                break;
            strcpy(pbc_state_file, argv[argNum]);
			strcpy(pbc_state_lock_file,pbc_state_file);
			strcat(pbc_state_lock_file,"_lock");
			strcpy(wscd_cancel_file,pbc_state_file);
			strcat(wscd_cancel_file,"_cancel");
		}
#endif
		else {
			printf("invalid argument - %s\n", argv[argNum]);
			show_help();
			return -1;
		}
		argNum++;
	}
	return 0;
}
#endif


void dump_wsc_context(void *ptr)
{
	CTX_Tp pCtx=(CTX_Tp)ptr;

#ifdef __ECOS
	if (pCtx == NULL)
		pCtx=&wsc_context;
#endif

	printf("\n<<====WPS argument list=====>>\n");
#ifdef FOR_DUAL_BAND
	printf("FOR_DUAL_BAND be defined\n");
#endif
	printf("is_ap = %d\n", pCtx->is_ap);
	printf("start = %d\n", pCtx->start);
	printf("mode = %d\n", pCtx->mode);
	printf("role = %s\n", (pCtx->role==PROXY ? "Proxy" : (pCtx->role==ENROLLEE ? "Enrollee" : "Registrar")));
	printf("original_role = %s\n", (pCtx->original_role==PROXY ? "Proxy" : (pCtx->original_role==ENROLLEE ? "Enrollee" : "Registrar")));
	printf("use_ie = %d\n", pCtx->use_ie);
	printf("config_state = %s\n", (pCtx->config_state == CONFIG_STATE_UNCONFIGURED ? "unconfigured" : "configured"));
	printf("config_method = 0x%x\n", pCtx->config_method);
	printf("pin_code = %s\n", pCtx->pin_code);
	//printf("use_ie = %d\n", pCtx->use_ie);
	printf("wlan_interface_name=%s\n", pCtx->wlan_interface_name);
	printf("our_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		pCtx->our_addr[0], pCtx->our_addr[1], pCtx->our_addr[2],
		pCtx->our_addr[3], pCtx->our_addr[4], pCtx->our_addr[5]);

	//printf("wep_transmit_key = %d\n", pCtx->wep_transmit_key);
#ifdef SUPPORT_UPNP
	printf("upnp = %d\n", pCtx->upnp);
#endif


	printf("wlan0_wsc_disabled=%d\n",pCtx->wlan0_wsc_disabled);
#ifdef FOR_DUAL_BAND
	printf("wlan1_wsc_disabled=%d\n",pCtx->wlan1_wsc_disabled);
#endif		


#ifdef WPS2DOTX
	printf("auth_type_flags:0x%02X\n",pCtx->auth_type_flags);
	printf("encrypt_type_flags:%d\n",pCtx->encrypt_type_flags);
#endif
	
	printf("---wlan0 setting---\n");
	printf("rf_band = %d; 1=2.4G ;2=5G\n", pCtx->rf_band);
	printf("SSID=%s\n",pCtx->SSID);
	printf("ssid_prefix = %s\n", pCtx->ssid_prefix);
	if(pCtx->is_ap){
		printf("security mixed mode = %d\n",pCtx->mixedmode);			
	}		
	printf("Auth_Type=%d\n",pCtx->auth_type);
	printf("auth_type_flash = %d\n", pCtx->auth_type_flash);
	printf("Encrypt_Type=%d\n",pCtx->encrypt_type);
	printf("encrypt_type_flash = %d\n", pCtx->encrypt_type_flash);
	printf("network_key_len=%d\n", pCtx->network_key_len);
	printf("WSC_PSK = %s\n", pCtx->network_key);
	printf("security mixed mode = %d\n",pCtx->mixedmode);
	if (pCtx->wep_transmit_key > 1) {
		printf("	wep_key2 = %s\n", pCtx->wep_key2);
		printf("	wep_key3 = %s\n", pCtx->wep_key3);
		printf("	wep_key4 = %s\n", pCtx->wep_key4);
	}

	if(pCtx->wlan0_wsc_disabled == 1){
		printf("wlan0 interface wsc is Disabled\n");
	}else{
		printf("wlan0 interface wsc is Enabled\n");
	}

#ifdef FOR_DUAL_BAND
	if(pCtx->wlan1_wsc_disabled==0){        
        printf("wlan_interface_name2=%s\n", pCtx->wlan_interface_name2);
    	printf("our_addr2=%02x:%02x:%02x:%02x:%02x:%02x\n",
		    pCtx->our_addr2[0], pCtx->our_addr2[1], pCtx->our_addr2[2],
		    pCtx->our_addr2[3], pCtx->our_addr2[4], pCtx->our_addr2[5]);        
		printf("==wlan1 setting==\n");
		printf("SSID2=%s\n",pCtx->SSID2);
		printf("security2 mixed mode= %d\n",pCtx->mixedmode2);			
		printf("Auth_Type2=%d\n",pCtx->auth_type2);
		printf("Encrypt_Type2=%d\n",pCtx->encrypt_type2);
		printf("WSC_PSK = \"%s\"\n", pCtx->network_key2);

		if (pCtx->wep_transmit_key2 > 1) {
			printf("wep_key2 = %s\n", pCtx->wep_key22);
			printf("wep_key3 = %s\n", pCtx->wep_key32);
			printf("wep_key4 = %s\n", pCtx->wep_key42);
		}
	}

	if(pCtx->wlan1_wsc_disabled == 1){
		printf("wlan1 interface wsc is Disabled\n");
	}else{
		printf("wlan1 interface wsc is Enabled\n");
	}
#endif

#ifdef MUL_PBC_DETECTTION
	printf("disable_MulPBC_detection=%d\n", pCtx->disable_MulPBC_detection);
	printf("PBC_overlapping_LED_time_out=%d\n", pCtx->PBC_overlapping_LED_time_out);
	printf("SessionOverlapTimeout=%d\n", pCtx->SessionOverlapTimeout);
	printf("active_pbc_sta_count=%d\n", pCtx->active_pbc_sta_count);
	//printf("WPS_PBC_overlapping_GPIO_number = %d\n", pCtx->WPS_PBC_overlapping_GPIO_number);
#endif
	/*
	//printf("connect_type = %d\n", pCtx->connect_type);
	//printf("disable_configured_by_exReg = %d\n", pCtx->disable_configured_by_exReg);
	//	printf("No_ifname_for_flash_set = %d\n", pCtx->No_ifname_for_flash_set);

	printf("WPS_END_LED_unconfig_GPIO_number = %d\n", pCtx->WPS_END_LED_unconfig_GPIO_number);
	printf("WPS_END_LED_config_GPIO_number = %d\n", pCtx->WPS_END_LED_config_GPIO_number);
	printf("WPS_START_LED_GPIO_number = %d\n", pCtx->WPS_START_LED_GPIO_number);
	printf("No_ifname_for_flash_set = %d\n", pCtx->No_ifname_for_flash_set);

	printf("WPS_ERROR_LED_time_out = %d\n", pCtx->WPS_ERROR_LED_time_out);
	printf("WPS_ERROR_LED_GPIO_number = %d\n", pCtx->WPS_ERROR_LED_GPIO_number);
	printf("WPS_SUCCESS_LED_time_out = %d\n", pCtx->WPS_SUCCESS_LED_time_out);
	printf("WPS_SUCCESS_LED_GPIO_number = %d\n", pCtx->WPS_SUCCESS_LED_GPIO_number);
	printf("fix_wzc_wep = %d\n", pCtx->fix_wzc_wep);
	printf("disable_hidden_ap = %d\n", pCtx->disable_hidden_ap);
	*/

	printf("button_hold_time = %d\n",pCtx->button_hold_time); 			
	if(pCtx->is_ap){
		if(strlen(pCtx->ssid_prefix))
			printf("SSID-prefix = %s\n",pCtx->ssid_prefix);

		printf("disable_configured_by_exReg = %d\n", pCtx->disable_configured_by_exReg);
	}

	if(pCtx->manual_key_type){
		printf("manual_key_type =%d \n",pCtx->manual_key_type);

		if(strlen(pCtx->manual_key))
			printf("manual_key =%s \n",pCtx->manual_key);

		if(pCtx->manauall_random_psk_len)
			printf("random_key_len =%d \n",pCtx->manauall_random_psk_len);
	}else{
		if(pCtx->random_psk_len)
			printf("assigned PSK LEN =%d \n",pCtx->random_psk_len);
	}


	if(pCtx->manual_key_type){
		printf("manual_key_type =%d \n",pCtx->manual_key_type);

		if(strlen(pCtx->manual_key))
			printf("manual_key =%s \n",pCtx->manual_key);

		if(pCtx->manauall_random_psk_len)
			printf("random_key_len =%d \n",pCtx->manauall_random_psk_len);
	}else{
		if(pCtx->random_psk_len)
			printf("assigned PSK LEN =%d \n",pCtx->random_psk_len);
	}

#if	0	//def WPS2DOTX
	if(pCtx->EAP_frag_threshold)
		printf("EAP_frag_threshold = %d\n", pCtx->EAP_frag_threshold);
#ifdef EAP_REASSEMBLY
	printf("support EAP_frag reassembly\n");
#endif

#ifdef WSC_IE_FRAGMENT_STASIDE
	if(!pCtx->is_ap){
		printf("STA mode ;support Probe_Req wsc_ie frag = %s\n",
			pCtx->probeReq_need_wscIE_frag?"true":"false");
	}
#endif
#ifdef WSC_IE_FRAGMENT_APSIDE
	if(pCtx->is_ap){
		printf("AP mode; Probe_Rsp wsc_ie frag =%s\n",
			pCtx->probeRsp_need_wscIE_frag?"true":"false");
	}
#endif
	if(pCtx->is_ap){
		printf("AP mode;Extension Tag =%s\n",
			pCtx->extension_tag?"true":"false");
	}
#endif

	if(pCtx->upnp){
		char tmpstr[36];
		convert_bin_to_str(pCtx->uuid, UUID_LEN, tmpstr);
		printf("uuid=%s\n",tmpstr);
	}
#ifdef AUTO_LOCK_DOWN
	if(pCtx->is_ap){
#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION			
		printf("brute_force_attack_mitigation ThresHold[%d]\n",pCtx->MaxPinFailThresHold);
#endif
	}
#endif

#ifdef WSC_CLIENT_MODE
	if(!pCtx->is_ap) {
		printf("SPEC_MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
			pCtx->SPEC_MAC[0], pCtx->SPEC_MAC[1], pCtx->SPEC_MAC[2],
			pCtx->SPEC_MAC[3], pCtx->SPEC_MAC[4], pCtx->SPEC_MAC[5]);
		printf("SPEC_SSID=%s\n",pCtx->SPEC_SSID);
	}
#endif

#ifdef WPS2DOTX
	printf("wsc version=2.0\n");
#else
	printf("wsc version=1.0\n");
#endif
	printf("\n<<====WPS argument list=====>>\n");
}

static int init_config(CTX_Tp pCtx,int def)
{

	if(pCtx->mode_switch){
		pCtx->mode_switch=0;
	}
	else
	{
		/* Read config file and validate parameters */
	    if (read_config_file(pCtx, pCtx->cfg_filename, def) < 0)
			return 0;

	}


	if (pCtx->mode == -1) {
		printf("Parameter \"mode\" must be set!\n");
		return 0;
	}

#if	0	//def WPS2DOTX	// when acl is enabled ; must disabled by uplevel app (scritp or webserver)
	if(pCtx->wlan0_wsc_disabled == 0){
		func_off_wlan_acl(pCtx,pCtx->wlan_interface_name);
	}

	if(pCtx->wlan1_wsc_disabled == 0){
		func_off_wlan_acl(pCtx,pCtx->wlan_interface_name2);
	}
#endif

	switch (pCtx->mode) {
		case MODE_AP_UNCONFIG:
			pCtx->is_ap = 1;
			pCtx->config_state = CONFIG_STATE_UNCONFIGURED;
			pCtx->role = ENROLLEE;
			pCtx->original_role = ENROLLEE;
			break;
		case MODE_AP_PROXY:
			pCtx->is_ap = 1;
			pCtx->config_state = CONFIG_STATE_CONFIGURED;
			pCtx->role = PROXY;
			pCtx->original_role = PROXY;
			break;
		case MODE_AP_PROXY_REGISTRAR:
			pCtx->is_ap = 1;
			pCtx->config_state = CONFIG_STATE_CONFIGURED;
			pCtx->role = REGISTRAR;
			pCtx->original_role = REGISTRAR;
			break;
#ifdef WSC_CLIENT_MODE
		case MODE_CLIENT_UNCONFIG:
			pCtx->is_ap = 0;
			pCtx->config_state = CONFIG_STATE_UNCONFIGURED;
			pCtx->role = ENROLLEE;
			pCtx->original_role = ENROLLEE;
			break;
#ifdef SUPPORT_REGISTRAR
		case MODE_CLIENT_CONFIG:
			pCtx->is_ap = 0;
			pCtx->config_state = CONFIG_STATE_CONFIGURED;
			pCtx->role = REGISTRAR;
			pCtx->original_role = REGISTRAR;
			pCtx->resent_limit = 1;
			pCtx->reg_timeout = PIN_WALK_TIME;
			break;
		case MODE_CLIENT_UNCONFIG_REGISTRAR:
			pCtx->is_ap = 0;
			pCtx->config_state = CONFIG_STATE_UNCONFIGURED;
			pCtx->role = REGISTRAR;
			pCtx->original_role = REGISTRAR;
			pCtx->resent_limit = 1;
			pCtx->reg_timeout = PIN_WALK_TIME;
			break;
#endif
#endif
	}


#ifdef WPS2DOTX
    /*under 2.0 STA mode can accept WPA(TKIP) credential */
    if(pCtx->is_ap){

		pCtx->auth_type_flags &= ~(WSC_AUTH_WPAPSK);

		pCtx->encrypt_type_flags &= ~( WSC_ENCRYPT_TKIP);
				
	}
    /*under 2.0 both AP and STA mode can't accept WEP credential */    
	pCtx->auth_type_flags &= ~(WSC_AUTH_SHARED );
	//WSC_DEBUG("auth_type_flags:%02X\n",pCtx->auth_type_flags);

	pCtx->encrypt_type_flags &= ~(WSC_ENCRYPT_WEP );
	//WSC_DEBUG("encrypt_type_flags:%02X\n",pCtx->encrypt_type_flags);			
	
	/*
	 case1)
	 Disable WSC if the APUT is manually configured for WEP

	 case2)
	 Disable WSC if the APUT is manually configured for WPA/TKIP only,
	 unless the APUT is configured for mixed mode
	*/

    if (pCtx->is_ap
#ifdef FOR_DUAL_BAND
        && pCtx->wlan0_wsc_disabled==0
#endif
        )
    {
        if( pCtx->auth_type == WSC_AUTH_WPAPSK || pCtx->encrypt_type == WSC_ENCRYPT_TKIP ||
            pCtx->encrypt_type == WSC_ENCRYPT_WEP)
        {
            WSC_DEBUG("	!!WPS2.x no support WEP or WPA only or TKIP only; disabled wlan0\n");
#ifdef FOR_DUAL_BAND
            pCtx->wlan0_wsc_disabled = 1;
#else
            WSC_DEBUG("exit wscd...\n");
            return 0;
#endif

        }


        /*2011-0502 if hidden ap is enabled then  close WPS ;2011-0926*/
        if(get_hidden_mib(pCtx  , pCtx->wlan_interface_name)){
            WSC_DEBUG("	!!WPS2.x hidden_SSID is enabled; disabled wlan0\n");
#ifdef FOR_DUAL_BAND
            pCtx->wlan0_wsc_disabled = 1;
#else
            // if under single band exit wscd here
            return 0;
#endif
        }


    }


#ifdef FOR_DUAL_BAND

    if (pCtx->wlan1_wsc_disabled==0 && pCtx->is_ap)
    {
        if( pCtx->auth_type2 == WSC_AUTH_WPAPSK || pCtx->encrypt_type2 == WSC_ENCRYPT_TKIP ||
            pCtx->encrypt_type2 == WSC_ENCRYPT_WEP)
        {
            pCtx->wlan1_wsc_disabled = 1;
            WSC_DEBUG("	!!WPS2.x no support WEP or WPA only or TKIP only; disabled wlan1\n");
        }

        /*2011-0502 if hidden ap is enabled then  close WPS ;2011-0926*/
        if(get_hidden_mib(pCtx  , pCtx->wlan_interface_name2)){
            pCtx->wlan1_wsc_disabled = 1;
            WSC_DEBUG("	!!WPS2.x hidden_SSID is enabled; disabled wlan1\n");
        }

    }

    if(pCtx->wlan0_wsc_disabled && pCtx->wlan1_wsc_disabled){
        WSC_DEBUG("!!both two interface are disabled\n\n");
        return 0;
    }

#endif //FOR_DUAL_BAND


#endif

#ifndef __ECOS

#ifdef FOR_DUAL_BAND
    if(pCtx->wlan0_wsc_disabled == 0 && pCtx->wlan1_wsc_disabled == 0){              
        if (pCtx->is_ap)
            sprintf(pCtx->pid_filename, "%s-wl0-wl1.pid",   DEFAULT_PID_FILENAME);
        else            
            sprintf(pCtx->pid_filename, "%s-wl0-wl1-c.pid",   DEFAULT_PID_FILENAME);
        _DEBUG_PRINT("\n");
    }else{
			if(pCtx->wlan0_wsc_disabled == 0)
				sprintf(pCtx->pid_filename, "%s-%s.pid", DEFAULT_PID_FILENAME,	pCtx->wlan_interface_name);
			else if(pCtx->wlan1_wsc_disabled == 0)
				sprintf(pCtx->pid_filename, "%s-%s.pid", DEFAULT_PID_FILENAME,	pCtx->wlan_interface_name2);
    }
#else
    sprintf(pCtx->pid_filename, "%s-%s.pid", DEFAULT_PID_FILENAME,  pCtx->wlan_interface_name);
#endif //__ECOS
#endif

	if (!pCtx->is_ap) {
		pCtx->device_category_id = 1; // Computer
		pCtx->device_sub_category_id = 1; // PC
	}

#ifdef DEBUG
	if (pCtx->debug2) {
		dump_wsc_context((void *)pCtx);
	}
#endif

	if (pCtx->role == ENROLLEE && pCtx->pin_code[0] == '\0' && (pCtx->config_method&CONFIG_METHOD_PIN)) {
		struct timeval tod;
		int num;

		gettimeofday(&tod , NULL);
		srand(tod.tv_sec);
		num = rand() % 10000000;
		num = num*10 + compute_pin_checksum(num);
		convert_hex_to_ascii((unsigned long)num, pCtx->pin_code);

		_DEBUG_PRINT("Auto-generated PIN = %s\n", pCtx->pin_code);
	}

	return 1;
}

#ifdef __ECOS
#ifdef HAVE_APMIB
int wsc_context_init(CTX_Tp pCtx)
{
	int intVal, intVal2, is_client, is_config, is_registrar, is_wep=0, wep_key_type=0, wep_transmit_key=0;
	char tmpbuf[100], tmp1[100];
	//CTX_Tp pCtx;


	/*for detial mixed mode info*/ 
	int wlan0_encrypt=0;		
	int wlan0_wpa_cipher=0;
	int wlan0_wpa2_cipher=0;
	/*for detial mixed mode info	mixed issue*/ 
	
	//WPS
	memset(pCtx, 0, sizeof(CTX_T));
	//pCtx = &wsc_context;
	/*--------------------------------------------------------------------*/
	strcpy((char *)pCtx->wlan_interface_name, "wl0");
	//strcpy(pCtx->lan_interface_name, "bridge0");
	strcpy(pCtx->lan_interface_name, "eth0");
#ifdef DEBUG
	pCtx->debug = 1;
	//pCtx->debug2 = 1;

#endif

	apmib_get(MIB_WLAN_MODE, (void *)&is_client);
	apmib_get(MIB_WLAN_WSC_CONFIGURED, (void *)&is_config);
	apmib_get(MIB_WLAN_WSC_REGISTRAR_ENABLED, (void *)&is_registrar);	

#ifdef WSC_CLIENT_MODE
	if (is_client != WSC_CLIENT_MODE) 
#endif	
		pCtx->start = 1;

	//WSC_DEBUG("wlan mode=%d\n",is_client);
	if (is_client == WSC_CLIENT_MODE) {
#ifdef __ECOS
		intVal = MODE_CLIENT_UNCONFIG;
#else
		
		if (is_registrar) {
			if (!is_config)
				intVal = MODE_CLIENT_UNCONFIG_REGISTRAR;
			else
				intVal = MODE_CLIENT_CONFIG;			
		}
		else
			intVal = MODE_CLIENT_UNCONFIG;
#endif		
	}
	else {
		if (!is_config)
			intVal = MODE_AP_UNCONFIG;
		else
			intVal = MODE_AP_PROXY_REGISTRAR;
	}
	pCtx->mode = intVal;
	//WSC_DEBUG("wsc mode=%d\n",pCtx->mode);
	
	if (is_client == WSC_CLIENT_MODE)
		intVal = 0;
	else
		apmib_get(MIB_WLAN_WSC_UPNP_ENABLED, (void *)&intVal);
	pCtx->upnp = intVal;

#ifdef WPS2DOTX
	// %d=9864;%x=0x2688
	pCtx->config_method = (CONFIG_METHOD_VIRTUAL_PIN |  CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC );
#else	// wps 1.0 
	intVal = 0;
	apmib_get(MIB_WLAN_WSC_METHOD, (void *)&intVal);
	//Ethernet(0x2)+Label(0x4)+PushButton(0x80) Bitwise OR
	if (intVal == 1) //Pin+Ethernet
		intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN);
	else if (intVal == 2) //PBC+Ethernet
		intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PBC);
	if (intVal == 3) //Pin+PBC+Ethernet
		intVal = (CONFIG_METHOD_ETH | CONFIG_METHOD_PIN | CONFIG_METHOD_PBC);
	pCtx->config_method = intVal;
#endif	

	/*assigned auth support list 2.0*/
	pCtx->auth_type_flags = (WSC_AUTH_OPEN |   WSC_AUTH_WPA2PSK);

	/*assigned Encry support list 2.0*/
	pCtx->encrypt_type_flags = 
		(WSC_ENCRYPT_NONE |  WSC_ENCRYPT_AES );

	
	apmib_get(MIB_WLAN_WSC_AUTH, (void *)&intVal2);
	pCtx->auth_type_flash = intVal2;

	apmib_get(MIB_WLAN_WSC_ENC, (void *)&intVal);
	pCtx->encrypt_type_flash = intVal;
	if (intVal == WSC_ENCRYPT_WEP)
		is_wep = 1;

	if (is_client) {
		apmib_get(MIB_WLAN_NETWORK_TYPE, (void *)&intVal);
		if (intVal == 0)
			intVal = 1;
		else
			intVal = 2;
	}
	else
		intVal = 1;
	pCtx->connect_type = intVal;

	apmib_get(MIB_WLAN_WSC_MANUAL_ENABLED, (void *)&intVal);
	pCtx->manual_config = intVal;

	if (is_wep) { // only allow WEP in none-MANUAL mode (configured by external registrar)
		apmib_get(MIB_WLAN_ENCRYPT, (void *)&intVal);
		if (intVal != ENCRYPT_WEP) {
			printf("WEP mismatched between WPS and host system\n");
			return -1;
		}
		apmib_get(MIB_WLAN_WEP, (void *)&intVal);
		if (intVal <= WEP_DISABLED || intVal > WEP128) {
			printf("WEP encrypt length error\n");
			return -1;
		}
		apmib_get(MIB_WLAN_WEP_KEY_TYPE, (void *)&wep_key_type);
		apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&wep_transmit_key);
		wep_transmit_key++;
		pCtx->wep_transmit_key = wep_transmit_key;
		if (intVal == WEP64) {
			apmib_get(MIB_WLAN_WEP64_KEY1, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}
			strcpy(pCtx->network_key, tmp1);

			apmib_get(MIB_WLAN_WEP64_KEY2, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}
			strcpy((char *)pCtx->wep_key2, tmp1);

			apmib_get(MIB_WLAN_WEP64_KEY3, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}
			strcpy((char *)pCtx->wep_key3, tmp1);

			apmib_get(MIB_WLAN_WEP64_KEY4, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 5);
				tmp1[5] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 5, tmp1);
				tmp1[10] = '\0';
			}
			strcpy((char *)pCtx->wep_key4, tmp1);
		}
		else {
			apmib_get(MIB_WLAN_WEP128_KEY1, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			strcpy(pCtx->network_key, tmp1);

			apmib_get(MIB_WLAN_WEP128_KEY2, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			strcpy((char *)pCtx->wep_key2, tmp1);

			apmib_get(MIB_WLAN_WEP128_KEY3, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			strcpy((char *)pCtx->wep_key3, tmp1);

			apmib_get(MIB_WLAN_WEP128_KEY4, (void *)&tmpbuf);
			if (wep_key_type == KEY_ASCII) {
				memcpy(tmp1, tmpbuf, 13);
				tmp1[13] = '\0';
			}
			else {
				convert_bin_to_str((unsigned char *)tmpbuf, 13, tmp1);
				tmp1[26] = '\0';
			}
			strcpy((char *)pCtx->wep_key4, tmp1);
		}
	}
	else {
		apmib_get(MIB_WLAN_WPA_PSK, (void *)&tmp1);
		strcpy(pCtx->network_key, tmp1);
	}
	pCtx->network_key_len = strlen(pCtx->network_key);
	
	apmib_get(MIB_WLAN_SSID, (void *)&tmp1);	
	strcpy(pCtx->SSID, tmp1);

	apmib_get(MIB_HW_WSC_PIN, (void *)&tmp1);
	strcpy(pCtx->pin_code, tmp1);

	apmib_get(MIB_WLAN_CHANNEL, (void *)&intVal);
	if (intVal > 14)
		intVal = 2;
	else
		intVal = 1;
	pCtx->rf_band = intVal;

	apmib_get(MIB_DEVICE_NAME, (void *)&tmp1);
	strcpy(pCtx->device_name, tmp1);

	apmib_get(MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)&intVal);
	pCtx->config_by_ext_reg = intVal;



	/*for detial mixed mode info*/ 
	//  mixed issue	
	apmib_get(MIB_WLAN_ENCRYPT, (void *)&wlan0_encrypt);
	apmib_get(MIB_WLAN_WPA_CIPHER_SUITE, (void *)&wlan0_wpa_cipher);
	apmib_get(MIB_WLAN_WPA2_CIPHER_SUITE, (void *)&wlan0_wpa2_cipher);

	intVal=0;	
	if(wlan0_encrypt==6){	// mixed mode
		if(wlan0_wpa_cipher==1){
			intVal |= WSC_WPA_TKIP;
		}else if(wlan0_wpa_cipher==2){
			intVal |= WSC_WPA_AES;		
		}else if(wlan0_wpa_cipher==3){
			intVal |= (WSC_WPA_TKIP | WSC_WPA_AES);		
		}
		if(wlan0_wpa2_cipher==1){
			intVal |= WSC_WPA2_TKIP;
		}else if(wlan0_wpa2_cipher==2){
			intVal |= WSC_WPA2_AES;		
		}else if(wlan0_wpa2_cipher==3){
			intVal |= (WSC_WPA2_TKIP | WSC_WPA2_AES);		
		}		
	}
	pCtx->mixedmode = intVal;	
	/*for detial mixed mode info*/ 

	
	return 0;
}
#else
void apply_wps_config_to_wscd(struct wps_config *wpscfg)
{
	CTX_Tp pCtx=&wsc_context;

	pCtx->debug = 1;
	pCtx->debug2 = 1;
	//copy struct wps_config to struct context
	strcpy(pCtx->wlan_interface_name, wpscfg->wlan_interface_name);
	strcpy(pCtx->lan_interface_name, wpscfg->lan_interface_name);
	pCtx->start = wpscfg->start;
	pCtx->mode = wpscfg->mode;
	pCtx->upnp = wpscfg->upnp;
	pCtx->config_method = wpscfg->config_method;
	pCtx->auth_type_flags = wpscfg->auth_type_flags;
	pCtx->encrypt_type_flags = wpscfg->encrypt_type_flags;
	pCtx->auth_type_flash = wpscfg->auth_type_flash;
	pCtx->encrypt_type_flash = wpscfg->encrypt_type_flash;
	pCtx->connect_type = wpscfg->connect_type;
	pCtx->manual_config = wpscfg->manual_config;
	pCtx->wep_transmit_key = wpscfg->wep_transmit_key;
	strcpy(pCtx->network_key, wpscfg->network_key);
	strcpy(pCtx->wep_key2, wpscfg->wep_key2);
	strcpy(pCtx->wep_key3, wpscfg->wep_key3);
	strcpy(pCtx->wep_key4, wpscfg->wep_key4);
	pCtx->network_key_len = wpscfg->network_key_len;
	strcpy(pCtx->SSID, wpscfg->SSID);
	strcpy(pCtx->pin_code, wpscfg->pin_code);
	pCtx->rf_band = wpscfg->rf_band;
	pCtx->config_by_ext_reg = wpscfg->config_by_ext_reg;
	pCtx->mixedmode = wpscfg->mixedmode;
	
	//wscd.conf
	strcpy(pCtx->device_name, wpscfg->device_name);
	strcpy(pCtx->manufacturer, wpscfg->manufacturer);
	strcpy(pCtx->manufacturerURL, wpscfg->manufacturerURL);
	strcpy(pCtx->model_URL, wpscfg->model_URL);
	strcpy(pCtx->model_name, wpscfg->model_name);
	strcpy(pCtx->model_num, wpscfg->model_num);
	strcpy(pCtx->serial_num, wpscfg->serial_num);
	strcpy(pCtx->manufacturerDesc, wpscfg->modelDescription);
	strcpy(pCtx->ssid_prefix, wpscfg->ssid_prefix);

	//reset active_pbc_sta_count to avoid incorrect multiple PBC detection
	pCtx->active_pbc_sta_count = 0;
}
#endif
#endif

/*
 * main program enrty.
 * 	SYNOPSYS:
 *	  autoconf ARGs...
 *	ARGs
 *	  -c config_filename, config filename
 * 	  -w wlan_interface, wlan interface
 *	  -fi fifo_name, wlan fifo path name
 *	  -method val, 1: PIN, 2: PBC, 3: both
 *	  -mode val, 1: ap unconfigured, 2: client unconfigured (enrollee), 3: client configured (registrar)
 *				 4: ap-proxy configured, 5: ap-proxy registrar
 *	  -upnp val, 1 - support upnp, 0 - not support (default)
 *	  -gen-pin, generate pin code for local entitiy
 *	  -peer_pin, assign pin code for peer entitiy
  *	  -local_pin, assign local pin code
 *	  -sig_start, start wsc protocol
 *	  -sig_pbc, start PBC mode
 *	  -start_pbc, start PBC
 *	  -debug, turn on debug message
 *	  -test, go to test mode
 *	  -daemon, run as daemon
 */
#ifndef __ECOS
int main(int argc, char *argv[])
#else
void wscd_main(cyg_addrword_t data)
#endif
{
	CTX_Tp pCtx;
#ifndef __ECOS
	int pid_fd;
#endif
	int start_pbc=0;
#ifdef __ECOS
	int anyErrorAtinit = 0;
#else
#ifdef CONFIG_IWPRIV_INTF
	struct stat status;
#endif
#endif
#ifdef IKD		//IKD LED Control by others daemon
	//KDDI
	//for chage priority
	char strRenice[40];
	
	sprintf(strRenice,"renice %d %d",PRIORITY_WSCD,getpid());
	system(strRenice);
	//KDDI
#endif

#ifdef __ECOS
	cyg_flag_value_t val;
	cyg_handle_t wsc_counter_hdl, sys_clk_hdl;
	int i;
	//extern int wsc_context_init(void);

	wscd_state = 0;
wscd_entry_point:

	pCtx = &wsc_context;
	pGlobalCtx = &wsc_context;
	anyErrorAtinit = 0;	
	
#ifdef HAVE_APMIB

	wsc_context_init(pCtx);

	pCtx->debug = 1;
#else
#ifndef CONFIG_SDIO_HCI
	if (wscd_state==3)
		wsc_flash_param_apply(pCtx, "wlan0", &tmp_flash_param, 1);
#endif
#endif
#endif

#ifdef __ECOS
	wps_done = 0;
	wps_start_interface0 = 0;
	wps_start_interface1 = 0;
#else
		
	/* Allocate context */
	pCtx = (CTX_Tp) calloc(1, sizeof(CTX_T));
	if (pCtx == NULL) {
		printf("allocate context failed!\n");
		return 0;
	}
	pGlobalCtx = pCtx;

	/* Parse input argument */
	if (argc == 1) { // no argument
		show_help();
		return 0;
	}

	pCtx->mode = -1;
	pCtx->config_method = -1;
	pCtx->upnp = -1;
	pCtx->connect_type = -1;

#ifdef FOR_DUAL_BAND
	// default as wlan0 and wlan1 is disabled
	pCtx->wlan0_wsc_disabled = 1;
	pCtx->wlan1_wsc_disabled = 1;
	strcpy(pCtx->wlan_interface_name, "wl0");    
	strcpy(pCtx->wlan_interface_name2, "wl1");
#else
	pCtx->wlan0_wsc_disabled = 0;
#endif

#ifdef DEBUG
	int idx=0;
	pCtx->debug = 1;
	//pCtx->debug2 = 1;

	WSC_DEBUG("daemon parameter:\n");
	for(idx=0;idx<argc ;idx++){
		printf("%s ",argv[idx]);
	}
	_DEBUG_PRINT("\n");
#endif

	if (parse_argument(pCtx, argc, argv, &start_pbc) < 0){
		WSC_DEBUG("!!!return!!!\n\n");
		return 0;
	}
#endif //__ECOS

	report_WPS_STATUS(NOT_USED);	// 2011-0830

#if defined(DEBUG) && defined(OUTPUT_LOG)
	if(outlog_fp == NULL){
		outlog_fp = fopen( LOG_PATH ,"a+" );
	}
#endif

#ifndef __ECOS
#ifdef CONFIG_IWPRIV_INTF
        pCtx->start_config_client = 1;
#endif
	memset(pCtx->SSID, 0, WSC_MAX_SSID_LEN+1);
#endif


#ifdef	AUTO_LOCK_DOWN
#ifdef __ECOS
		wscd_lock_stat=0;
#else
		unlink(WSCD_LOCK_STAT);
#endif
#endif

#ifndef __ECOS
	if (!pCtx->cfg_filename[0]){
#ifdef CONFIG_IWPRIV_INTF
                if( stat(COMPATIBLE_CONFIG_FILE, &status) == 0 )
	               strcpy(pCtx->cfg_filename, COMPATIBLE_CONFIG_FILE);
	        else
#endif
		strcpy(pCtx->cfg_filename, DEFAULT_CONFIG_FILENAME);
        }
#endif

#ifdef SUPPORT_UPNP
	if (!pCtx->lan_interface_name[0])
		strcpy(pCtx->lan_interface_name, DEFAULT_LAN_INTERFACE);
#endif

#ifdef __ECOS
	/* Get local mac address */
	if (get_mac_address((char *)pCtx->wlan_interface_name, (char *)pCtx->our_addr) < 0){
		WSC_DEBUG("get_mac_address fail!! stop wsc service!!\n");
		anyErrorAtinit = 1;
		//return;
	}
#endif

	if (init_config(pCtx,0) == 0) {
#ifdef __ECOS
		WSC_DEBUG("	init_config fail !!stop wsc service!!\n");
		anyErrorAtinit = 1;
#else
		free(pCtx);
		WSC_DEBUG("	!!Exit wsc deamon!!\n\n");
		return 0;
#endif
	}


#if	0	//def FOR_DUAL_BAND
	if(!pCtx->is_ap){	// if client mode default use wlan0 as interface
		pCtx->InterFaceComeIn=COME_FROM_WLAN0;
	}
#endif

	memcpy(pCtx->original_pin_code, pCtx->pin_code, PIN_LEN+1);
	//WSC_DEBUG("pCtx->original_pin_code = %s\n", pCtx->original_pin_code);

#ifndef __ECOS
	if (pCtx->daemon) {
		if (daemon(0,1) == -1) {
			printf("fork wscd daemon error!\n");
			return 0;
		}
	}

	/* Initialize UDP socket */
	if (init_socket(pCtx) < 0) {
		free(pCtx);
		return 0;
	}

	/* Get local mac address */
#ifdef FOR_DUAL_BAND
    if(!pCtx->wlan0_wsc_disabled)
#endif        
    {    
        if (get_mac_addr(pCtx->socket, pCtx->wlan_interface_name, pCtx->our_addr) < 0)
            return 0;
		WSC_DEBUG("wlan0 addr:\n");
		MAC_PRINT(pCtx->our_addr);
#ifdef DEBUG
        if(pCtx->debug2){
            WSC_DEBUG("wlan0 addr:\n");
            MAC_PRINT(pCtx->our_addr);
        }
#endif
    }
#ifdef FOR_DUAL_BAND
    if(!pCtx->wlan1_wsc_disabled){
        if (get_mac_addr(pCtx->socket2, pCtx->wlan_interface_name2, pCtx->our_addr2) < 0)
            return 0;
        WSC_DEBUG("wlan1 addr:\n");
        MAC_PRINT(pCtx->our_addr2);
    }
#endif
#endif

	RAND_seed(rnd_seed, sizeof(rnd_seed));

#ifdef SUPPORT_UPNP
//	if (pCtx->is_ap && pCtx->upnp && pCtx->role == REGISTRAR) {
//		DEBUG_ERR("Invalid config, ap+internal-registrar+external-upnp-registrar!\n");
//		return 0;
//	}

	WSC_pthread_mutex_init(&pCtx->RegMutex, NULL);
	//DEBUG_PRINT("Initialize Registration protocol mutex...\n");

	if (pCtx->upnp) {
		unsigned char init_count=0;

		while (init_count++ <= UPNP_INIT_TIMES) {
			if (start_upnp(pCtx) < 0) {
				printf("start_upnp() error!\n");
				if (init_count == UPNP_INIT_TIMES) {
					printf("wscd init fialed!\n");
					WSC_pthread_mutex_destroy(&pCtx->RegMutex);
#ifndef __ECOS
					return 0;
#else
					WSC_DEBUG("start_upnp fail!! stop wsc service!!\n");
					anyErrorAtinit = 1;
					break;
#endif
				}
				else{
					sleep(1);
				}
			}
			else{
				break;
			}
		}
#ifndef __ECOS
#if defined(USE_MINI_UPNP) && defined(DEBUG)
		/* TODO : change LOG_LOCAL0 to LOG_DAEMON */
		int openlog_option;
		int debug_flag = 1;
		openlog_option = LOG_PID|LOG_CONS;
		if(debug_flag)
			openlog_option |= LOG_PERROR;	/* also log on stderr */
		openlog("wscd", openlog_option, LOG_USER/*LOG_LOCAL0*/);
#endif
#endif
	}
#endif

#ifdef TEST
	if (pCtx->test) {
		if (run_test(pCtx) < 0) {
#ifndef __ECOS
			free(pCtx);
#endif
			WSC_pthread_mutex_destroy(&pCtx->RegMutex);
			return 0;
		}
	}
#endif

	DISPLAY_BANNER;

#ifndef __ECOS
	setsid();

	/* Create daemon */
	pid_fd = pidfile_acquire(pCtx->pid_filename);
	if (pid_fd < 0) {
		WSC_DEBUG("pidfile_acquire fail!!!\n\n");
		WSC_pthread_mutex_destroy(&pCtx->RegMutex);
		return 0;
	}

	pidfile_write_release(pid_fd);
#endif

	/* Issue ioctl to wlan driver to set ssid and enable AUTO_CONFIG */
#ifdef __ECOS
	if (anyErrorAtinit==0)
#endif
	{
		if(init_wlan(pCtx, 0) < 0) 
		{
			WSC_DEBUG("init_wlan fail!!!\n\n");		
			WSC_pthread_mutex_destroy(&pCtx->RegMutex);
#ifdef __ECOS
			WSC_DEBUG("init_wlan fail!! stop wsc service!!\n");
			anyErrorAtinit = 1;
#else
			return 0;
#endif
		}
	}

	if (IS_PBC_METHOD(pCtx->config_method)) {

#ifdef MUL_PBC_DETECTTION
		if (!pCtx->disable_MulPBC_detection) {
			// allocate buffer for dummy header
			if (pCtx->is_ap
#ifdef WSC_CLIENT_MODE
				|| (!pCtx->is_ap && pCtx->role == ENROLLEE)
#endif
			)
			{
				pCtx->active_pbc_staList = (struct pbc_node_context *) malloc(sizeof(struct pbc_node_context));
				if (pCtx->active_pbc_staList == NULL) {
					printf("%s %d Not enough mempry\n", __FUNCTION__, __LINE__);
					WSC_pthread_mutex_destroy(&pCtx->RegMutex);
#ifdef __ECOS
					WSC_DEBUG("init active_pbc_staList fail!! stop wsc service!!\n");
					anyErrorAtinit = 1;
#else
					return 0;
#endif
				}
				memset(pCtx->active_pbc_staList, 0, sizeof(struct pbc_node_context));
				WSC_pthread_mutex_init(&pCtx->PBCMutex, NULL);
				//DEBUG_PRINT("Initialize PBC station list mutex...\n");
			}
		}
#endif
	}

	if (strlen(pCtx->peer_pin_code) > 0) // peer-pin code is assigned
		evHandler_pin_input(pCtx, pCtx->peer_pin_code);

#ifdef __ECOS
	if (wscd_state==0) {
		sys_clk_hdl = cyg_real_time_clock();
		cyg_clock_to_counter(sys_clk_hdl, &wsc_counter_hdl);
		cyg_alarm_create(wsc_counter_hdl, wsc_alarm_func, 0,&wsc_alarm_hdl, &wsc_alarm);
		//WSC_DEBUG("\n");			
	}
#else	/* __ECOS */
	/* Install signal handler */
#ifdef WSC_1SEC_TIMER
	int ret;
	if ((ret = wsc_init_1sec_Timer()) != 0) {
		printf("<<-------Quit wscd!-------->>\n");
		return 0;
	}
#else
	//signal(SIGALRM, sigHandler_alarm);
#endif

	if(signal(SIGUSR2, sigHandler_user)==SIG_ERR)
	{
		printf("WSC cannot receive SIGUSR2 signal!\n");
	}
	if(signal(SIGTSTP, sigHandler_user)==SIG_ERR)
	{
		printf("WSC cannot receive SIGSTP signal!\n");
	}

#ifdef	AUTO_LOCK_DOWN	// process unloced
	signal(SIGUSR1, sigHandler_user);
#endif

#ifndef WSC_1SEC_TIMER
	/* Start one second timer */
	//alarm(1);
#endif
#endif /* __ECOS */

#ifdef IKD		//IKD LED Control by others daemon

#else			
	// enable LED
	enable_WPS_LED();
	if (wlioctl_set_led(LED_WSC_END) < 0) {
		printf("issue wlan ioctl set_led error!\n");
#ifdef __ECOS
		anyErrorAtinit = 1;
#else
		return 0;
#endif
	}
#endif

#ifndef __ECOS
	WSC_DEBUG("alarm(1)---------->\n");

	if (start_pbc)
		process_event(pCtx, EV_PB_PRESS);
#endif

#ifdef WSC_CLIENT_MODE
	if (!pCtx->is_ap && pCtx->start && !start_pbc)
		process_event(pCtx, EV_START);
#endif

	if (pCtx->upnp) {
#ifdef USE_MINI_UPNP
#ifdef STAND_ALONE_MINIUPNP
#ifdef __ECOS
		if(anyErrorAtinit==0)
#endif
		{
			//sending byebye
			WSC_DEBUG("!!	sending byebye\n\n");		
			unsigned char byebye_max_age=1;
			SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
				&pCtx->upnp_info.SSDP, 1, byebye_max_age);
			sleep(byebye_max_age);
			
			//sending alive
			WSC_DEBUG("!!	sending alive\n\n");		
			SendSSDPNotifies(pCtx->upnp_info.snotify, pCtx->upnp_info.lan_ip_address, pCtx->upnp_info.port,
				&pCtx->upnp_info.SSDP, 0, pCtx->upnp_info.SSDP.max_age);
			pCtx->upnp_info.SSDP.alive_timeout = pCtx->upnp_info.SSDP.max_age/2;		
		}

#ifdef __ECOS
		{
			char *buffo=NULL;

			buffo = (char *) malloc(256);
			if (buffo == NULL) {
				WSCUpnpStop();
				return;
			}

			sprintf(wscd_config, "port %d\n", pCtx->upnp_info.port);

			memset(buffo, 0, 256);
			sprintf(buffo, "max_age %d\n", pCtx->upnp_info.SSDP.max_age);
			strcat(wscd_config, buffo);

			memset(buffo, 0, 256);
			sprintf(buffo, "uuid %s\n", pCtx->upnp_info.SSDP.uuid);
			strcat(wscd_config, buffo);

			memset(buffo, 0, 256);
			sprintf(buffo, "root_desc_name %s\n", pCtx->upnp_info.SSDP.root_desc_name);
			strcat(wscd_config, buffo);

			int i=0;
			while (pCtx->upnp_info.SSDP.known_service_types[i]) {
				memset(buffo, 0, 256);
				sprintf(buffo, "known_service_types %s\n", pCtx->upnp_info.SSDP.known_service_types[i]);
				strcat(wscd_config, buffo);
				i++;
			}
			free(buffo);
		}
#endif
#else

		FILE *fp=NULL;

		fp = fopen(WSCD_CONFIG_FILE,"w");
		if (fp == NULL) {
			printf("output file [%s] can not open\n", WSCD_CONFIG_FILE);
			WSCUpnpStop();
			return 0;
		}
		else {
			char *buffo=NULL;

			buffo = (char *) malloc(256);
			if (buffo == NULL) {
				WSCUpnpStop();
				fclose(fp);
				return 0;
			}

			memset(buffo, 0, 256);
			sprintf(buffo, "port %d\n", pCtx->upnp_info.port);
			fputs(buffo, fp);

			memset(buffo, 0, 256);
			sprintf(buffo, "max_age %d\n", pCtx->upnp_info.SSDP.max_age);
			fputs(buffo, fp);

			memset(buffo, 0, 256);
			sprintf(buffo, "uuid %s\n", pCtx->upnp_info.SSDP.uuid);
			fputs(buffo, fp);

			memset(buffo, 0, 256);
			sprintf(buffo, "root_desc_name %s\n", pCtx->upnp_info.SSDP.root_desc_name);
			fputs(buffo, fp);

			int i=0;
			while (pCtx->upnp_info.SSDP.known_service_types[i]) {
				memset(buffo, 0, 256);
				sprintf(buffo, "known_service_types %s\n", pCtx->upnp_info.SSDP.known_service_types[i]);
				fputs(buffo, fp);
				i++;
			}

			fclose(fp);
			free(buffo);
		}
#endif
#endif	// USE_MINI_UPNP
	}

#ifndef __ECOS
#if !defined(NO_IWCONTROL) || defined(USE_MINI_UPNP)
	listen_and_process_event(pCtx); // never return
#else
	// no NO_IWCONTROL is defined
	for(;;) pause();
#endif

	return 0;
#else
	//printf("wscd_config len=%d\n", strlen(wscd_config));
	//printf("%s\n", wscd_config);
	/* Create the thread */
	pCtx->wsc_upnp_thread = NULL;
	if (pCtx->upnp){
		pCtx->kill_wsc_upnp = 0;
		cyg_thread_create(16,
			      wsc_upnp_main,
			      (cyg_addrword_t)pCtx,
			      "wsc_upnp",
			      &wsc_upnp_stack,
			      sizeof(wsc_upnp_stack),
			      &wsc_upnp_thread_handle,
			      &wsc_upnp_thread_obj);
			      
		/* Let the thread run when the scheduler starts */
		cyg_thread_resume(wsc_upnp_thread_handle);
		pCtx->wsc_upnp_thread = &wsc_upnp_thread_handle;
	}

	if (wscd_state==0) {
		cyg_flag_init(&wsc_flag);
//		cyg_alarm_initialize(wsc_alarm_hdl, cyg_current_time()+100, 100); //TBD
		cyg_alarm_initialize(wsc_alarm_hdl, cyg_current_time()+1000, 1000);
	}
	cyg_alarm_enable(wsc_alarm_hdl);
	wscd_state = 1; // ready state
	
	if(anyErrorAtinit == 1){
		cyg_flag_setbits(&wsc_flag, 0x40);// stop service...
	}
	
	while (1) {
		val = cyg_flag_wait(&wsc_flag, 0xff, CYG_FLAG_WAITMODE_OR | CYG_FLAG_WAITMODE_CLR);
		//printf("val=%x\n", val);
		switch (wscd_state) {
		case 1:
			//don't use if/else for DUT may receive more than one event at the same time, it should handle this case and don't ignore any event.
			if (val & 0x01) {
				wlanIndEvt(0);
			}

			if (val & 0x80) {
				process_event(pCtx, EV_STOP);
			}

			if (val & 0x04) {
				process_event(pCtx, EV_START);
			}

			if (val & 0x08) {
				process_event(pCtx, EV_PB_PRESS);
			}
#ifdef	AUTO_LOCK_DOWN
			if (val & 0x10) {
				process_event(pCtx, EV_UN_AUTO_LOCK_DOWN);
			}
#endif

			if ((val & 0x20) || (val & 0x40)) {
				cyg_flag_value_t fval;
				
				WSC_DEBUG("[ wps state ]enter stop/restart state\n");				
				//stop service first
				cyg_alarm_disable(wsc_alarm_hdl); //stop 1 second timer

				if (pCtx->wsc_upnp_thread){
					cyg_flag_init(&pCtx->wsc_upnp_flag);
					pCtx->kill_wsc_upnp = 1;
					WSCUpnpStop();
					WSC_DEBUG("WSCUpnpStop()...\n");					
				}
			
				for (i=0; i<WSC_MAX_STA_NUM; i++) {
					if (pCtx->sta[i] && pCtx->sta[i]->used)
						reset_sta(pCtx, pCtx->sta[i], 1);
				}
				
				WSC_DEBUG("reset_ctx_state\n");							
				reset_ctx_state(pCtx);

				char tmpbuf[256];
				if (pCtx->is_ap) {	// clean wsc_ie from beacon,probe_rsp,assoc_rsp
					WSC_DEBUG("clean wsc IE ;beacon,probe_rsp,assoc_rsp\n");
					if (wlioctl_set_wsc_ie(tmpbuf, 0, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_BEACON) < 0) {
							WSC_DEBUG("fail\n");
					}
					if (wlioctl_set_wsc_ie(tmpbuf, 0, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_PROBE_RSP) < 0) {
							WSC_DEBUG("fail\n");
					}					
					if (wlioctl_set_wsc_ie(tmpbuf, 0, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_ASSOC_RSP) < 0) {
							WSC_DEBUG("fail\n");
					}					
				}
#ifdef MUL_PBC_DETECTTION
				if (pCtx->active_pbc_staList)
					free(pCtx->active_pbc_staList);
#endif

				if (pCtx->wsc_upnp_thread){
					//wait for wsc_upnp exit
					fval = cyg_flag_wait(&pCtx->wsc_upnp_flag, 0x01, CYG_FLAG_WAITMODE_OR | CYG_FLAG_WAITMODE_CLR);
					cyg_flag_destroy(&pCtx->wsc_upnp_flag);

					cyg_thread_kill(wsc_upnp_thread_handle);
					cyg_thread_delete(wsc_upnp_thread_handle);
					pCtx->wsc_upnp_thread = NULL;
				}

				if (val & 0x40) {
					wscd_state = 2; //stop state
					WSC_DEBUG("[ wps state ]enter stop state\n");
				}
				else {

					//restart wscd
					WSC_DEBUG("<<Restart wscd ...>>\n\n\n");

					cyg_flag_maskbits(&wsc_flag, 0); //clear all bits in the flag
					wscd_state = 3; //restart state
					goto wscd_entry_point;
				}
			}

			if (val & 0x02) {
				sigHandler_alarm(SIGALRM);
			}

			/*
			else {
				printf("invalid flag value: 0x%x\n", val);
			}
			*/
			break;
		case 2:
			if (val & 0x20) {
				//restart wscd
				WSC_DEBUG("[ wps state ]restart wscd from stop state\n");
				cyg_flag_maskbits(&wsc_flag, 0); //clear all bits in the flag
				wscd_state = 3; //restart state
				goto wscd_entry_point;
			}
			break;
		}
	}
#endif
}

#ifdef __ECOS
void wsc_upnp_main(cyg_addrword_t data)
{
	CTX_Tp pCtx = (CTX_Tp)data;

	listen_and_process_event(pCtx); // never return
	//diag_printf("wsc_upnp_main exit\n");
	cyg_flag_setbits(&pCtx->wsc_upnp_flag, 0x01);
	cyg_thread_exit();
}

void wsc_alarm_func(cyg_handle_t alarm_hdl, cyg_addrword_t data)
{
	cyg_flag_setbits(&wsc_flag, 0x02);
}

void wsc_sig_pbc(void)
{
	cyg_flag_setbits(&wsc_flag, 0x08);
}

void wsc_sig_pin(void)
{
	cyg_flag_setbits(&wsc_flag, 0x04);
}

void wsc_sig_stop(void)
{
	cyg_flag_setbits(&wsc_flag, 0x80);
}

void wsc_unlock(void)
{
	cyg_flag_setbits(&wsc_flag, 0x10);
}

void wsc_reinit(void)
{
	cyg_flag_setbits(&wsc_flag, 0x20);
}

void wsc_stop_service(void)
{
	cyg_flag_setbits(&wsc_flag, 0x40);
}

int get_wscd_state(void)
{
	return wscd_state;
}

int get_wscd_lock_stat(void)
{
	return wscd_lock_stat;
}

#ifndef CONFIG_SDIO_HCI
#ifndef HAVE_APMIB
void wsc_flash_param_apply(CTX_Tp pCtx, char *ifname, struct wsc_flash_param *param, int flag)
{
	if (param->type == 1) {
		char temp[256];
		
		if (flag)
			RunSystemCmd(NULL_FILE, "ifconfig", ifname, "down", NULL_STR);
		sprintf(temp, "ssid=%s", param->SSID);
		RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
		if (param->WEP) {
			sprintf(temp, "authtype=%d", param->AUTH_TYPE);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			if (param->WEP == 1) //WEP64
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=1", NULL_STR);
			else
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=5", NULL_STR);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "802_1x=0", NULL_STR);
			sprintf(temp, "wepdkeyid=%d", param->WEP_DEFAULT_KEY);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			sprintf(temp, "wepkey1=%s", param->WEP_KEY1);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			sprintf(temp, "wepkey2=%s", param->WEP_KEY2);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			sprintf(temp, "wepkey3=%s", param->WEP_KEY3);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			sprintf(temp, "wepkey4=%s", param->WEP_KEY4);
			RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
		}
		else {
			if (param->WSC_AUTH==WSC_AUTH_OPEN) {
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "psk_enable=0", NULL_STR);
				if (param->WSC_ENC==WSC_ENCRYPT_NONE)
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=0", NULL_STR);
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "802_1x=0", NULL_STR);
			}
			else if (param->WSC_AUTH==WSC_AUTH_WPAPSK) {
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "psk_enable=1", NULL_STR);
				if (param->WSC_ENC==WSC_ENCRYPT_TKIP) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa_cipher=2", NULL_STR);
				}
				else if (param->WSC_ENC==WSC_ENCRYPT_AES) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=4", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa_cipher=8", NULL_STR);
				}
				else if (param->WSC_ENC==WSC_ENCRYPT_TKIPAES) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa_cipher=10", NULL_STR);
				}
				sprintf(temp, "passphrase=%s", param->WSC_PSK);
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			}
			else if (param->WSC_AUTH==WSC_AUTH_WPA2PSK) {
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "psk_enable=2", NULL_STR);
				if (param->WSC_ENC==WSC_ENCRYPT_TKIP) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa2_cipher=2", NULL_STR);
				}
				else if (param->WSC_ENC==WSC_ENCRYPT_AES) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=4", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa2_cipher=8", NULL_STR);
				}
				else if (param->WSC_ENC==WSC_ENCRYPT_TKIPAES) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa2_cipher=10", NULL_STR);
				}
				sprintf(temp, "passphrase=%s", param->WSC_PSK);
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			}
			else if (param->WSC_AUTH==WSC_AUTH_WPA2PSKMIXED) {
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "psk_enable=3", NULL_STR);
				if (param->WSC_ENC==WSC_ENCRYPT_TKIP) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa_cipher=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa2_cipher=2", NULL_STR);
				}
				else if (param->WSC_ENC==WSC_ENCRYPT_AES) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=4", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa_cipher=8", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa2_cipher=8", NULL_STR);
				}
				else if (param->WSC_ENC==WSC_ENCRYPT_TKIPAES) {
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "encmode=2", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa_cipher=10", NULL_STR);
					RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", "wpa2_cipher=10", NULL_STR);
				}
				sprintf(temp, "passphrase=%s", param->WSC_PSK);
				RunSystemCmd(NULL_FILE, "iwpriv", ifname, "set_mib", temp, NULL_STR);
			}
		}
		if (flag)
			RunSystemCmd(NULL_FILE, "ifconfig", ifname, "up", NULL_STR);
		
		memset(pCtx, 0, sizeof(CTX_T));
		//--------------------------------------------------------------------
		pCtx->start = 1;
		strcpy((char *)pCtx->wlan_interface_name, ifname);
		//strcpy(pCtx->lan_interface_name, "bridge0");
		strcpy(pCtx->lan_interface_name, "eth0");
#ifdef DEBUG
		pCtx->debug = 1;
#endif
		//--------------------------------------------------------------------
		pCtx->mode = MODE_AP_PROXY_REGISTRAR;
		pCtx->upnp = 1;
		// Ethernet(0x2)+Label(0x4)+PushButton(0x80) Bitwise OR 

#ifdef WPS2DOTX		
	pCtx->config_method = 
	(CONFIG_METHOD_VIRTUAL_PIN |  CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC );
#else
		pCtx->config_method = CONFIG_METHOD_ETH | CONFIG_METHOD_PIN | CONFIG_METHOD_PBC;
#endif
		pCtx->connect_type = CONNECT_TYPE_BSS;
		pCtx->manual_config = 0;
	
		pCtx->auth_type_flash = param->WSC_AUTH;
		pCtx->encrypt_type_flash = param->WSC_ENC;
		if (param->WEP) {
			pCtx->wep_transmit_key = param->WEP_DEFAULT_KEY+1;
			strcpy(pCtx->network_key, (char *)param->WEP_KEY1);
			strcpy(pCtx->wep_key2, (char *)param->WEP_KEY2);
			strcpy(pCtx->wep_key3, (char *)param->WEP_KEY3);
			strcpy(pCtx->wep_key4, (char *)param->WEP_KEY4);
		}
		else {
			if (param->WSC_AUTH==WSC_AUTH_OPEN)
				strcpy(pCtx->network_key, "");
			else
				strcpy(pCtx->network_key, param->WSC_PSK);
		}
		pCtx->network_key_len = strlen(pCtx->network_key);
		strcpy(pCtx->SSID, param->SSID);
				
		pCtx->rf_band = 1;
		//pCtx->rf_band = 2; //if channel > 14
		strcpy(pCtx->device_name, "Realtek Wireless AP");
		pCtx->config_by_ext_reg = param->WSC_CONFIGBYEXTREG;
		
		memset(param, 0, sizeof(struct wsc_flash_param));
	}
}
#endif
#endif

void create_wscd(void)
{
	/* Create the thread */
	cyg_thread_create(16,
		      wscd_main,
		      0,
		      "wscd",
		      &wscd_stack,
		      sizeof(wscd_stack),
		      &wscd_thread_handle,
		      &wscd_thread_obj);
	/* Let the thread run when the scheduler starts */
	cyg_thread_resume(wscd_thread_handle);
}
#endif
