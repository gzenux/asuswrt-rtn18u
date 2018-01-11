#ifdef __ECOS
#include <network.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef __ECOS
#include <fcntl.h>
#include <sys/file.h>
#include <syslog.h>
#endif
#include <sys/time.h>
#include <time.h>
#include <signal.h>
/* for BSD's sysctl */
#include <sys/param.h>
#ifndef __ECOS
#include <sys/sysctl.h>
#endif

#include "upnphttp.h"
#include "mini_upnp.h"
#include "upnpreplyparse.h"

/* ip et port pour le SSDP */
static int ssdpPort=1900;//#define PORT (1900)
#define UPNP_MCAST_ADDR ("239.255.255.250")

#ifdef USE_SHARED_DAEMON
#include <sys/stat.h>

#if 0
#define DEBUG_PRINT(fmt, args...) printf(fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif


static daemon_CTX_Tp pGlobalCtx;

static char *Get_start(const unsigned long addr)
{
	char *pos;

	pos = (char *)addr;
	while (*pos == ' ' || *pos == '\r' || *pos == '\n')
		pos++;
	return pos;
}

static char *Get_end(const unsigned long addr)
{
	char *pos;

	pos = (char *)addr;
	while (*pos != ' ' && *pos != '\r' && *pos != '\n')
		pos++;
	return pos;
}

static int parse_ssdp_file(const char *line, const int len, device_CTX_Tp device)
{
	unsigned long string_begin=0;
	unsigned long string_end=0;
	unsigned long file_end=0;
	unsigned long file_pos=0;
	char tmp[10];
	unsigned char num_service=0;
	char *service_name;

	if (line == NULL || len == 0 || device == NULL)
		return -1;

	file_pos = (unsigned long) line;
	file_end = file_pos + len;

	while (file_pos < file_end) {
		if (strncmp((char *)file_pos, "port", 4) == 0) {
			string_begin = (unsigned long)Get_start(file_pos+4);
			string_end = (unsigned long)Get_end(string_begin);
			if (string_end <= string_begin)
				return -1;
			memset(tmp, 0, 10);
			memcpy(tmp, (char *)string_begin, string_end - string_begin);
			device->port = atoi(tmp);
			file_pos = string_end;
			continue;
		}
		else if (strncmp((char *)file_pos, "max_age", 7) == 0) {
			string_begin = (unsigned long)Get_start(file_pos+7);
			string_end = (unsigned long)Get_end(string_begin);
			if (string_end <= string_begin)
				return -1;
			memset(tmp, 0, 10);
			memcpy(tmp, (char *)string_begin, string_end - string_begin);
			device->ctx.max_age = atoi(tmp);
			device->ctx.alive_timeout = device->ctx.max_age / 2;
			file_pos = string_end;
			continue;
		}
		else if (strncmp((char *)file_pos, "uuid", 4) == 0) {
			string_begin = (unsigned long)Get_start(file_pos+4);
			string_end = (unsigned long)Get_end(string_begin);
			if (string_end <= string_begin)
				return -1;
			memcpy(device->ctx.uuid, (char *)string_begin, string_end - string_begin);
			file_pos = string_end;
			continue;
		}
		else if (strncmp((char *)file_pos, "root_desc_name", 14) == 0) {
			string_begin = (unsigned long)Get_start(file_pos+14);
			string_end = (unsigned long)Get_end(string_begin);
			if (string_end <= string_begin)
				return -1;
			memcpy(device->ctx.root_desc_name, (char *)string_begin, string_end - string_begin);
			file_pos = string_end;
			continue;
		}
		else if (strncmp((char *)file_pos, "known_service_types", 19) == 0) {
			string_begin = (unsigned long)Get_start(file_pos+19);
			string_end = (unsigned long)Get_end(string_begin);
			if (string_end <= string_begin)
				return -1;
			service_name = (char *) malloc(string_end - string_begin + 1);
			if (service_name == NULL) {
				int i;
				for (i=0; i < MAX_NUMBER_OF_Service; i++) {
					if (device->known_service_types[i])
						free(device->known_service_types[i]);
				}
				return -1;
			}
			memset(service_name, 0, string_end - string_begin + 1);
			memcpy(service_name, (char *)string_begin, string_end - string_begin);
			device->known_service_types[num_service] = service_name;
			num_service++;
			file_pos = string_end;
			continue;
		}
		file_pos++;
	}

	device->ctx.known_service_types = device->known_service_types;
	return 0;
}



static int get_file(char *fname, device_CTX_Tp pDevCtx)
{
	char *ssdp_file;
	int len, ret;
	
	if ((ssdp_file = mini_UPnP_UploadXML(fname)) != NULL) {
		len = strlen(ssdp_file);
		ret = parse_ssdp_file(ssdp_file, len, pDevCtx);

		free(ssdp_file);		
		if (ret != -1)
			return 1;
	}
	return 0;
}

static int parse_argument(daemon_CTX_Tp pCtx, int argc, char *argv[])
{
	int argNum=1;
	IPCon ipcon=NULL;
	char *wsc_file=NULL, *igd_file=NULL;
	int wait_time=5, is_ok;
	char wsc_file_old[200], igd_file_old[200];
	
	while (argNum < argc) {
		if (!strcmp(argv[argNum], "-interface")) {
			if (++argNum >= argc)
				break;
			strcpy(pCtx->interfacename, argv[argNum]);
		}
		else if (!strcmp(argv[argNum], "-wsc")) {
			if (++argNum >= argc)
				break;
			if (pCtx->num_device >= MAX_NUMBER_OF_DEVICE) {
				printf("The max number of supported devices is %d!\n", MAX_NUMBER_OF_DEVICE);
				return -1;
			}
			wsc_file = argv[argNum];
			strcpy(wsc_file_old, wsc_file);
			strcat(wsc_file_old, ".old");			
		}
		else if ( !strcmp(argv[argNum], "-igd")) {
			if (++argNum >= argc)
				break;
			if (pCtx->num_device >= MAX_NUMBER_OF_DEVICE) {
				printf("The max number of supported devices is %d!\n", MAX_NUMBER_OF_DEVICE);
				return -1;
			}
			igd_file = argv[argNum];	
			strcpy(igd_file_old, igd_file);
			strcat(igd_file_old, ".old");			
		}
else if ( !strcmp(argv[argNum], "-daemon")) {
				pCtx->daemon = 1;
		}
		else if ( !strcmp(argv[argNum], "-p")) {
			if (++argNum >= argc)
				break;
			ssdpPort=atoi(argv[argNum]);
			if((ssdpPort<0)||(ssdpPort>65535))
			{
				printf("Wrong -p option: port number should be 0~65535!\n");
				return -1;
			}
		}
		argNum++;
	}
		
	while (wait_time-- > 0 && (wsc_file || igd_file)) {		
		if (wsc_file) {
			is_ok = 0;
			if (!get_file(wsc_file, &pCtx->device[pCtx->num_device])) {
				if (get_file(wsc_file_old, &pCtx->device[pCtx->num_device]))
					is_ok = 2;							
			}
			else {
				is_ok = 1;
				rename(wsc_file, wsc_file_old);				
			}
			if (is_ok) {
				pCtx->device[pCtx->num_device].used = DEVICE_WSC;
				strcpy(pCtx->device[pCtx->num_device].SSDP_file_name, WSCD_BYEBYE_FILE);
				strcpy(pCtx->device[pCtx->num_device].input_file_name, wsc_file);
				DEBUG_PRINT("Mini_upnpd: Read file [%s] success!\n", ((is_ok == 1) ? wsc_file : wsc_file_old));
				pCtx->num_device++;
				wsc_file = NULL;				
			}
		}
		
		if (igd_file) {
			is_ok = 0;
			if (!get_file(igd_file, &pCtx->device[pCtx->num_device])) {
				if (get_file(igd_file_old, &pCtx->device[pCtx->num_device]))
					is_ok = 2;							
			}
			else {
				is_ok = 1;
				rename(igd_file, igd_file_old);				
			}
			if (is_ok) {
				pCtx->device[pCtx->num_device].used = DEVICE_IGD;
				strcpy(pCtx->device[pCtx->num_device].SSDP_file_name, IGD_BYEBYE_FILE);
				strcpy(pCtx->device[pCtx->num_device].input_file_name, igd_file);
				DEBUG_PRINT("Mini_upnpd: Read file [%s] success!\n", ((is_ok == 1) ? igd_file : igd_file_old));
				pCtx->num_device++;
				igd_file = NULL;				
			}
		}
		sleep(1);		
	}

	if (pCtx->interfacename[0] == 0) {
		strcpy(pCtx->interfacename, "br0");
	}

	ipcon = IPCon_New(pCtx->interfacename);
	if (ipcon == NULL) {
		printf("Error in IPCon_New!\n");
		return -1;
	}
	strcpy(pCtx->lan_ip_address, IPCon_GetIpAddrByStr(ipcon));  
	IPCon_Destroy(ipcon);
	
	return 0;
}

static void free_resource(daemon_CTX_Tp pCtx)
{
	 int i, j;
	 
	 for (i=0; i<MAX_NUMBER_OF_DEVICE; i++)
	 	for (j=0; j<MAX_NUMBER_OF_Service; j++) {
			if (pCtx->device[i].known_service_types[j])
				free(pCtx->device[i].known_service_types[j]);
	 	}
	if (pCtx->sudp >= 0)
		close(pCtx->sudp);
	if (pCtx->snotify >= 0)
		close(pCtx->snotify);
	free(pCtx);
}

static void sigHandler_alarm(int signo) {
	daemon_CTX_Tp pCtx=pGlobalCtx;
	unsigned char device_num=0;
	FILE *fp = NULL;
	struct stat status;
	char tmpbuf[100];

	for (device_num=0; device_num<MAX_NUMBER_OF_DEVICE; device_num++) {
		if (pCtx->device[device_num].used == 0)
			continue;

		if (get_file(pCtx->device[device_num].input_file_name, &pCtx->device[device_num])) {
			DEBUG_PRINT("Mini_upnpd-Alarm: Read file [%s] success!\n", pCtx->device[device_num].input_file_name);
			// when wscd case ; don't send "bye-bye+alive " for fix windows7 IOT issue;
			if(strcmp(pCtx->device[device_num].input_file_name ,"/tmp/wscd_config"))
			{
				SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
					&pCtx->device[device_num].ctx, 1, 1);
				SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
					&pCtx->device[device_num].ctx, 0, pCtx->device[device_num].ctx.max_age);
			}
			strcpy(tmpbuf, pCtx->device[device_num].input_file_name);
			strcat(tmpbuf, ".old");
			rename(pCtx->device[device_num].input_file_name, tmpbuf);			

		}
		
		if (pCtx->device[device_num].ctx.alive_timeout > 0 && --pCtx->device[device_num].ctx.alive_timeout <= 0) {
			//sending alive
			SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
				&pCtx->device[device_num].ctx, 0, pCtx->device[device_num].ctx.max_age);
			pCtx->device[device_num].ctx.alive_timeout = pCtx->device[device_num].ctx.max_age/2;
		}

		//check whether the bye-bye file is there
		if (stat(pCtx->device[device_num].SSDP_file_name, &status) != 0)
			continue;
		
		if ((fp = fopen(pCtx->device[device_num].SSDP_file_name, "r")) != NULL) {
			int event=0;
			unsigned char line[3];

			memset(line, 0, 3);
			fgets(line, sizeof(line), fp);
			if (sscanf(line, "%d", &event)) {
				if (event == 1) {
					//sending byebye
					SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
						&pCtx->device[device_num].ctx, 1, 1);
					//syslog(LOG_INFO, "Sending bye bye...");
					DEBUG_PRINT("Sending bye bye...\n");

					//sending alive
					SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
						&pCtx->device[device_num].ctx, 0, pCtx->device[device_num].ctx.max_age);
					//syslog(LOG_INFO, "Sending Advertisement...");
					DEBUG_PRINT("Sending Advertisement...\n");
				
					pCtx->device[device_num].ctx.alive_timeout = pCtx->device[device_num].ctx.max_age/2;
				}
				else if (event == 2) {
					//sending byebye
					SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
						&pCtx->device[device_num].ctx, 1, 1);
					//syslog(LOG_INFO, "Sending bye bye...");
					DEBUG_PRINT("Sending bye bye...\n");
				}
			}
				
			fclose(fp);
			remove(pCtx->device[device_num].SSDP_file_name);
		}
	}

	alarm(1);
}

int main(int argc, char *argv[])
{
	daemon_CTX_Tp pCtx=NULL;
	unsigned char device_num=0;
	int selret;
	fd_set netFD;

	/* Allocate context */
	pCtx = (daemon_CTX_Tp) calloc(1, sizeof(daemon_CTX_T));
	if (pCtx == NULL) {
		printf("allocate context failed!\n");
		return 0;
	}
	pGlobalCtx = pCtx;

	pCtx->sudp = -1;
	pCtx->snotify = -1;
	
//	sleep(3);
	if (parse_argument(pCtx, argc, argv) < 0) {
		printf("Parse argument failed!\n");
		free_resource(pCtx);
		return 0;
	}

	if (pCtx->num_device <= 0) {
		DEBUG_PRINT("Number of device is 0!\n");
		free_resource(pCtx);
		return 0;
	}

	if (pCtx->daemon) {
		if (daemon(0,1) == -1) {
			printf("fork mini_upnp daemon error!\n");
			return 0;
		}
	}
#if 0
	int openlog_option;
	int debug_flag = 1;
	openlog_option = LOG_PID|LOG_CONS;
	if(debug_flag)
		openlog_option |= LOG_PERROR;	/* also log on stderr */
	openlog("mini_upnpd", openlog_option, LOG_USER/*LOG_LOCAL0*/);
#endif

	DEBUG_PRINT("Interface name : %s\n", pCtx->interfacename);
	DEBUG_PRINT("IP : %s\n", pCtx->lan_ip_address);
	DEBUG_PRINT("Number of devices : %d\n", pCtx->num_device);
	for (device_num=0; device_num<MAX_NUMBER_OF_DEVICE; device_num++) {
		if (pCtx->device[device_num].used) {
			DEBUG_PRINT("Device port : %d\n", pCtx->device[device_num].port);
			DEBUG_PRINT("\t%s\n", pCtx->device[device_num].ctx.uuid);
			DEBUG_PRINT("\tmax_age : %d\n", pCtx->device[device_num].ctx.max_age);
			DEBUG_PRINT("\troot_desc_name : %s\n", pCtx->device[device_num].ctx.root_desc_name);
			int i=0;
			while (pCtx->device[device_num].ctx.known_service_types[i]) {
				DEBUG_PRINT("\t%s%s\n", pCtx->device[device_num].ctx.known_service_types[i],
					(i==0?"":"1"));
				i++;
			}
		}
	}
		
	/* socket d'ecoute pour le SSDP */
	pCtx->sudp = OpenAndConfUdpSocket(pCtx->lan_ip_address);
	if (pCtx->sudp < 0)
	{
		printf("Failed to open socket for SSDP. EXITING\n");
		free_resource(pCtx);
		return 0;
	}
		
	/* open socket for sending notifications */
	pCtx->snotify = OpenAndConfNotifySocket(pCtx->lan_ip_address);
	if (pCtx->snotify < 0)
	{
		printf("Failed to open socket for SSDP notify messages\n");
		free_resource(pCtx);
		return 0;
	}
	
	signal(SIGALRM, sigHandler_alarm);

	for (device_num=0; device_num<MAX_NUMBER_OF_DEVICE; device_num++) {
		//sending byebye
		if (pCtx->device[device_num].used)
			SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
				&pCtx->device[device_num].ctx, 1, 1);
	}

	sleep(1);

	for (device_num=0; device_num<MAX_NUMBER_OF_DEVICE; device_num++) {
		//sending alive
		if (pCtx->device[device_num].used)
			SendSSDPNotifies(pCtx->snotify, pCtx->lan_ip_address, pCtx->device[device_num].port,
				&pCtx->device[device_num].ctx, 0, pCtx->device[device_num].ctx.max_age);
	}

	/* Start one second timer */
	alarm(1);
		
	while (1) {
		FD_ZERO(&netFD);
		if (pCtx->sudp >= 0)
			FD_SET(pCtx->sudp, &netFD);
		selret = select(pCtx->sudp+1, &netFD, NULL, NULL, NULL);
		if (selret >= 0) {
			if(pCtx->sudp >= 0 && FD_ISSET(pCtx->sudp, &netFD))
			{
				ProcessSSDPRequest(pCtx);
			}
		}
	}
}
#endif

static int AddMulticastMembership(int s, const char * ifaddr)
{
	struct ip_mreq imr;	/* Ip multicast membership */

    	/* setting up imr structure */
    	imr.imr_multiaddr.s_addr = inet_addr(UPNP_MCAST_ADDR);
    	/*imr.imr_interface.s_addr = htonl(INADDR_ANY);*/
    	imr.imr_interface.s_addr = inet_addr(ifaddr);
	
	if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&imr, sizeof(struct ip_mreq)) < 0)
	{
        	syslog(LOG_ERR, "setsockopt(udp, IP_ADD_MEMBERSHIP): %m");
		return -1;
    	}

	return 0;
}

int OpenAndConfUdpSocket(const char * ifaddr)
{
	int s, onOff=1;
	struct sockaddr_in sockname;
	
	if( (s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		syslog(LOG_ERR, "socket(udp): %m");
		return -1;
	}	
	
	if( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (char *)&onOff, sizeof(onOff) ) != 0 ) {
		syslog(LOG_ERR, "setsockopt(udp): %m");
		close(s);
		return -1;
	}
	
	memset(&sockname, 0, sizeof(struct sockaddr_in));
    	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(ssdpPort);//PORT=>ssdpPort
	/* NOTE : it seems it doesnt work when binding on the specific address */
    	/*sockname.sin_addr.s_addr = inet_addr(UPNP_MCAST_ADDR);*/
    	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
    	/*sockname.sin_addr.s_addr = inet_addr(ifaddr);*/

    	if(bind(s, (struct sockaddr *)&sockname, sizeof(struct sockaddr_in)) < 0)
	{
		syslog(LOG_ERR, "bind(udp): %m");
		close(s);
		return -1;
    	}

	if(AddMulticastMembership(s, ifaddr) < 0)
	{
		close(s);
		return -1;
	}

	return s;
}

/* open the UDP socket used to send SSDP notifications to
 * the multicast group reserved for them */
int OpenAndConfNotifySocket(const char * addr)
{
	int s;
	unsigned char loopchar = 0;
	struct in_addr mc_if;
	struct sockaddr_in sockname;
	
	if( (s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		syslog(LOG_ERR, "socket(udp_notify): %m");
		return -1;
	}

	mc_if.s_addr = inet_addr(addr);

	if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopchar, sizeof(loopchar)) < 0)
	{
		syslog(LOG_ERR, "setsockopt(udp_notify, IP_MULTICAST_LOOP): %m");
		close(s);
		return -1;
	}

	if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (char *)&mc_if, sizeof(mc_if)) < 0)
	{
		syslog(LOG_ERR, "setsockopt(udp_notify, IP_MULTICAST_IF): %m");
		close(s);
		return -1;
	}

	memset(&sockname, 0, sizeof(struct sockaddr_in));
    	sockname.sin_family = AF_INET;
#ifdef __ECOS
#ifdef CYGPKG_NET_FREEBSD_STACK
    	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
#else
    	sockname.sin_addr.s_addr = inet_addr(addr);
#endif
#else
    	sockname.sin_addr.s_addr = inet_addr(addr);
#endif

    	if (bind(s, (struct sockaddr *)&sockname, sizeof(struct sockaddr_in)) < 0)
	{
		syslog(LOG_ERR, "bind(udp_notify): %m");
		close(s);
		return -1;
    	}

	return s;
}

/*
 * response from a LiveBox (Wanadoo)
HTTP/1.1 200 OK
CACHE-CONTROL: max-age=1800
DATE: Thu, 01 Jan 1970 04:03:23 GMT
EXT:
LOCATION: http://192.168.0.1:49152/gatedesc.xml
SERVER: Linux/2.4.17, UPnP/1.0, Intel SDK for UPnP devices /1.2
ST: upnp:rootdevice
USN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::upnp:rootdevice

 * response from a Linksys 802.11b :
HTTP/1.1 200 OK
Cache-Control:max-age=120
Location:http://192.168.5.1:5678/rootDesc.xml
Server:NT/5.0 UPnP/1.0
ST:upnp:rootdevice
USN:uuid:upnp-InternetGatewayDevice-1_0-0090a2777777::upnp:rootdevice
EXT:
 */

/* not really an SSDP "announce" as it is the response
 * to a SSDP "M-SEARCH" */
void SendSSDPAnnounce2(int s, struct sockaddr_in sockname,
				const char * st, int st_len,
				const char * host, unsigned short port,
				SSDP_CTX_Tp SSDP)
{
	int l, n;
	char *buf=NULL;
	/* TODO :
	 * follow guideline from document "UPnP Device Architecture 1.0"
	 * put in uppercase.
	 * DATE: is recommended
	 * SERVER: OS/ver UPnP/1.0 miniupnpd/1.0
	 * */
	if (st == NULL || host == NULL || SSDP == NULL)
		return;

	buf = (char *) malloc(512);
	if (buf == NULL) {
		syslog(LOG_ERR, "SendSSDPAnnounce2: out of memory!");
		return;
	}
	memset(buf, 0, 512);
	
	l = sprintf(buf,
		"HTTP/1.1 200 OK\r\n"
		"Cache-Control: max-age=%d\r\n"
		"ST: %.*s\r\n"
		"USN: %s::%.*s\r\n"
		"EXT:\r\n"
		"Server: " MINIUPNPD_SERVER_STRING "\r\n"
		"Location: http://%s:%u/%s.xml" "\r\n"
		"\r\n",
		SSDP->max_age,
		st_len, st,
		SSDP->uuid, st_len, st,
		host, (unsigned int)port, SSDP->root_desc_name);
	n = sendto(s, buf, l, 0,
	           (struct sockaddr *)&sockname, sizeof(struct sockaddr_in) );
	if(n<0)
	{
		syslog(LOG_ERR, "sendto: %m");
	}

	free(buf);
}

// type = 0 (alive); type = 1 (byebye)
void SendSSDPNotifies(int s, const char * host, unsigned short port,
						SSDP_CTX_Tp SSDP, 
						unsigned char type, unsigned int max_age)
{
	struct sockaddr_in sockname;
	int n, i, j;
	char *bufr=NULL;

	if (host == NULL || SSDP->root_desc_name == NULL || SSDP->uuid == NULL ||
		SSDP->known_service_types == NULL)
		return;

	bufr = (char *) malloc(512);
	if (bufr == NULL) {
		syslog(LOG_ERR, "SendSSDPNotifies: out of memory!");
		return;
	}
	memset(bufr, 0, 512);
	
	memset(&sockname, 0, sizeof(struct sockaddr_in));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(ssdpPort);//PORT=>ssdpPort
	sockname.sin_addr.s_addr = inet_addr(UPNP_MCAST_ADDR);

	for (j=0; j <2; j++) {
		i = 0;
		while(SSDP->known_service_types[i])
		{
			if (i == 1) {
				sprintf(bufr,
					"NOTIFY * HTTP/1.1\r\n"
					"Host:%s:%d\r\n"
					"Cache-Control:max-age=%d\r\n"
					"Location:http://%s:%d/%s.xml" "\r\n"
					"Server:" MINIUPNPD_SERVER_STRING "\r\n"
					"NT:%s\r\n"
					"USN:%s\r\n"
					"NTS:ssdp:%s\r\n"
					"\r\n",
					UPNP_MCAST_ADDR, ssdpPort, max_age,//PORT=>ssdpPort
					host, port, SSDP->root_desc_name,
					SSDP->uuid,
					SSDP->uuid,
					(type==0?"alive":"byebye"));
				n = sendto(s, bufr, strlen(bufr), 0,
					(struct sockaddr *)&sockname, sizeof(struct sockaddr_in) );
				if(n<0)
				{
					syslog(LOG_ERR, "sendto: %m");
				}
			}
			sprintf(bufr,
				"NOTIFY * HTTP/1.1\r\n"
				"Host:%s:%d\r\n"
				"Cache-Control:max-age=%d\r\n"
				"Location:http://%s:%d/%s.xml" "\r\n"
				"Server:" MINIUPNPD_SERVER_STRING "\r\n"
				"NT:%s%s\r\n"
				"USN:%s::%s%s\r\n"
				"NTS:ssdp:%s\r\n"
				"\r\n",
				UPNP_MCAST_ADDR, ssdpPort, max_age,//PORT=>ssdpPort
				host, port, SSDP->root_desc_name,
				SSDP->known_service_types[i], (i==0?"":"1"),
				SSDP->uuid, SSDP->known_service_types[i], (i==0?"":"1"),
				(type==0?"alive":"byebye"));
			n = sendto(s, bufr, strlen(bufr), 0,
				(struct sockaddr *)&sockname, sizeof(struct sockaddr_in) );
			if(n<0)
			{
				syslog(LOG_ERR, "sendto: %m");
			}
			i++;
		}
	}

	free(bufr);
}

#ifdef USE_SHARED_DAEMON
void ProcessSSDPRequest(daemon_CTX_Tp pCtx)
{
	int n;
	char *bufr=NULL;
	socklen_t len_r;
	struct sockaddr_in sendername;
	int i, l, j;
	char * st = 0;
	int st_len = 0;

	if (pCtx == NULL)
		return;

	bufr = (char *) malloc(2048);
	if (bufr == NULL) {
		syslog(LOG_ERR, "ProcessSSDPRequest: out of memory!");
		return;
	}
	memset(bufr, 0, 2048);
	
	len_r = sizeof(struct sockaddr_in);
	n = recvfrom(pCtx->sudp, bufr, 2048, 0,
	             (struct sockaddr *)&sendername, &len_r);
	if(n<0)
	{
		syslog(LOG_ERR, "recvfrom: %m");
		free(bufr);
		return;
	}
	if(memcmp(bufr, "NOTIFY", 6) == 0)
	{
		/* ignore NOTIFY packets. We could log the sender and device type */
		free(bufr);
		return;
	}
	else if(memcmp(bufr, "M-SEARCH", 8) == 0)
	{
		i = 0;
		while(i<n)
		{
			while((i<n-1) && (bufr[i] != '\r' || bufr[i+1] != '\n'))
					i++;
				if(i>=n)
					goto err_out;
			i += 2;
			if((i < n - 3) && (strncasecmp(bufr+i, "st:", 3) == 0))
			{
				st = bufr+i+3;
				st_len = 0;
				while((*st == ' ' || *st == '\t') && (st < bufr + n)) st++;
				while(st[st_len]!='\r' && st[st_len]!='\n' && (st + st_len < bufr + n)) st_len++;
				/*syslog(LOG_INFO, "ST: %.*s", st_len, st);*/
				/*j = 0;*/
				/*while(bufr[i+j]!='\r') j++;*/
				/*syslog(LOG_INFO, "%.*s", j, bufr+i);*/
			}
		}
		/*syslog(LOG_INFO, "SSDP M-SEARCH packet received from %s:%d",
	           inet_ntoa(sendername.sin_addr),
	           ntohs(sendername.sin_port) );*/
		if(st)
		{
			for (j=0; j<MAX_NUMBER_OF_DEVICE; j++) {
				if (pCtx->device[j].used) {
					i = 0;
					while(pCtx->device[j].known_service_types[i])
					{
						l = (int)strlen(pCtx->device[j].known_service_types[i]);
						if(l<=st_len && (0 == memcmp(st, pCtx->device[j].known_service_types[i], l)))
						{
							/* TODO : doesnt answer at once but wait for a random time */
							/*syslog(LOG_INFO, "ST: %.*s", st_len, st);*/
							syslog(LOG_INFO, "SSDP M-SEARCH from %s:%d ST: %.*s",
		      		  	   			inet_ntoa(sendername.sin_addr),
	      		     		   			ntohs(sendername.sin_port),
						   		st_len, st);
			
							SendSSDPAnnounce2(pCtx->sudp, sendername, st, st_len, pCtx->lan_ip_address, pCtx->device[j].port,
								&pCtx->device[j].ctx);
							break;
						}
						i++;
					}
					l = (int)strlen(pCtx->device[j].ctx.uuid);
					if(l==st_len && (0 == memcmp(st, pCtx->device[j].ctx.uuid, l)))
					{
						/* TODO : doesnt answer at once but wait for a random time */
						/*syslog(LOG_INFO, "ST: %.*s", st_len, st);*/
						syslog(LOG_INFO, "SSDP M-SEARCH from %s:%d ST: %.*s",
		        		   		inet_ntoa(sendername.sin_addr),
	      		     	   			ntohs(sendername.sin_port),
					   		st_len, st);
						SendSSDPAnnounce2(pCtx->sudp, sendername, st, st_len, pCtx->lan_ip_address, pCtx->device[j].port,
							&pCtx->device[j].ctx);
					}
				}
			}
		}
		else
		{
			syslog(LOG_INFO, "invalid SSDP M-SEARCH from %s:%d",
	        	   inet_ntoa(sendername.sin_addr),
	           	   ntohs(sendername.sin_port) );
		}
	}
	else
	{
		syslog(LOG_NOTICE, "Unknown udp packet received from %s:%d",
		       inet_ntoa(sendername.sin_addr),
			   ntohs(sendername.sin_port) );
	}
err_out:
	free(bufr);
}
#else
void ProcessSSDPRequest(int s, const char * host, unsigned short port,
								SSDP_CTX_Tp SSDP)
{
	int n;
	char *bufr=NULL;
	socklen_t len_r;
	struct sockaddr_in sendername;
	int i, l;
	char * st = 0;
	int st_len = 0;

	if (SSDP == NULL || host == NULL)
		return;

	bufr = (char *) malloc(2048);
	if (bufr == NULL) {
		syslog(LOG_ERR, "ProcessSSDPRequest: out of memory!");
		return;
	}
	memset(bufr, 0, 2048);
	
	len_r = sizeof(struct sockaddr_in);
	n = recvfrom(s, bufr, 2048, 0,
	             (struct sockaddr *)&sendername, &len_r);
	if(n<0)
	{
		syslog(LOG_ERR, "recvfrom: %m");
		free(bufr);
		return;
	}
	if(memcmp(bufr, "NOTIFY", 6) == 0)
	{
		/* ignore NOTIFY packets. We could log the sender and device type */
		free(bufr);
		return;
	}
	else if(memcmp(bufr, "M-SEARCH", 8) == 0)
	{
		i = 0;

		while(i<n)
		{
			while((i<n-1) && (bufr[i] != '\r' || bufr[i+1] != '\n'))
				i++;
			if(i>=n)
				goto err_out;
			i += 2;
			if((i < n - 3) &&(strncasecmp(bufr+i, "st:", 3) == 0))
			{
				st = bufr+i+3;
				st_len = 0;
				while((*st == ' ' || *st == '\t') && (st < bufr + n)) st++;
				while(st[st_len]!='\r' && st[st_len]!='\n' && (st + st_len < bufr + n)) st_len++;
				/*syslog(LOG_INFO, "ST: %.*s", st_len, st);*/
				/*j = 0;*/
				/*while(bufr[i+j]!='\r') j++;*/
				/*syslog(LOG_INFO, "%.*s", j, bufr+i);*/
			}
		}
		/*syslog(LOG_INFO, "SSDP M-SEARCH packet received from %s:%d",
	           inet_ntoa(sendername.sin_addr),
	           ntohs(sendername.sin_port) );*/
		if(st)
		{
			i = 0;
			while(SSDP->known_service_types[i])
			{
				l = (int)strlen(SSDP->known_service_types[i]);
				if(l<=st_len && (0 == memcmp(st, SSDP->known_service_types[i], l)))
				{
					/* TODO : doesnt answer at once but wait for a random time */
					/*syslog(LOG_INFO, "ST: %.*s", st_len, st);*/
					syslog(LOG_INFO, "SSDP M-SEARCH from %s:%d ST: %.*s",
	        	   			inet_ntoa(sendername.sin_addr),
	           	   			ntohs(sendername.sin_port),
				   		st_len, st);
					SendSSDPAnnounce2(s, sendername, st, st_len, host, port,
						SSDP);
					break;
				}
				i++;
			}
			l = (int)strlen(SSDP->uuid);
			if(l==st_len && (0 == memcmp(st, SSDP->uuid, l)))
			{
				/* TODO : doesnt answer at once but wait for a random time */
				/*syslog(LOG_INFO, "ST: %.*s", st_len, st);*/
				syslog(LOG_INFO, "SSDP M-SEARCH from %s:%d ST: %.*s",
	        	   		inet_ntoa(sendername.sin_addr),
	           	   		ntohs(sendername.sin_port),
				   	st_len, st);
				SendSSDPAnnounce2(s, sendername, st, st_len, host, port,
					SSDP);
			}
		}
		else
		{
			syslog(LOG_INFO, "invalid SSDP M-SEARCH from %s:%d",
	        	   inet_ntoa(sendername.sin_addr),
	           	   ntohs(sendername.sin_port) );
		}
	}
	else
	{
		syslog(LOG_NOTICE, "Unknown udp packet received from %s:%d",
		       inet_ntoa(sendername.sin_addr),
			   ntohs(sendername.sin_port) );
	}
err_out:
	free(bufr);
}
#endif

