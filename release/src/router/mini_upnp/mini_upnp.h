#ifndef MINI_UPNP_H
#define MINI_UPNP_H

#include <sys/queue.h>

#include "mini_upnp_global.h"
#include "upnphttp.h"

#ifdef CONFIG_SDIO_NOVA
#ifndef LIST_HEAD
#define LIST_HEAD	DLIST_HEAD //for Nova platform
#endif
#endif

typedef struct SSDP_context {
	char **known_service_types;
	char root_desc_name[100];
	char uuid[42];
	unsigned int max_age;
	unsigned int alive_timeout;
} SSDP_CTX_T, *SSDP_CTX_Tp;

#ifdef USE_SHARED_DAEMON
#define MAX_NUMBER_OF_DEVICE 			2
#define MAX_NUMBER_OF_Service 			10
#define WSCD_BYEBYE_FILE				("/tmp/wscd_byebye")
#define IGD_BYEBYE_FILE					("/tmp/igd_byebye")

enum { DEVICE_UNUSED=0, DEVICE_IGD=1, DEVICE_WSC=2 };

typedef struct device_context {
	unsigned char used;
	int port;
	char SSDP_file_name[30];
	SSDP_CTX_T ctx;
	char *known_service_types[MAX_NUMBER_OF_Service];
	char input_file_name[40];
} device_CTX_T, *device_CTX_Tp;

typedef struct daemon_context {
	char lan_ip_address[IP_ADDRLEN];
	char interfacename[20];
	unsigned char num_device;
	device_CTX_T device[MAX_NUMBER_OF_DEVICE];
	int sudp;
	int snotify;
	int daemon; // run as daemon
} daemon_CTX_T, *daemon_CTX_Tp;
#endif

typedef struct mini_upnp_context {
	LIST_HEAD(httplisthead, upnphttp) upnphttphead;
	SSDP_CTX_T SSDP;
	char lan_ip_address[IP_ADDRLEN];
	struct _soapMethods *soapMethods;
	struct _sendDesc *sendDesc;
	struct upnp_subscription_record subscribe_list;
	int port;
	int sudp; 
	int shttpl; 
	int snotify;
	char *rootXML;
	unsigned int rootXML_len;
	char *serviceXML;
	unsigned int serviceXML_len;
} mini_upnp_CTX_T, *mini_upnp_CTX_Tp;

extern int OpenAndConfUdpSocket(const char * ifaddr);
extern int OpenAndConfNotifySocket(const char * addr);
extern void SendSSDPAnnounce2(int s, struct sockaddr_in sockname,
				const char * st, int st_len,
				const char * host, unsigned short port,
				SSDP_CTX_Tp SSDP);
extern void SendSSDPNotifies(int s, const char * host, unsigned short port,
						SSDP_CTX_Tp SSDP, 
						unsigned char type, unsigned int max_age);
#ifdef USE_SHARED_DAEMON
extern void ProcessSSDPRequest(daemon_CTX_Tp pCtx);
#else
extern void ProcessSSDPRequest(int s, const char * host, unsigned short port, SSDP_CTX_Tp SSDP);
#endif
#endif
