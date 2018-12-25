#ifndef _MINI_UPNP_GLOBAL_H
#define _MINI_UPNP_GLOBAL_H

/* Server: HTTP header returned in all HTTP responses : */
#define MINIUPNPD_SERVER_STRING "OS 1.0 UPnP/1.0 Realtek/V1.3"
#ifndef __ECOS
#define IP_ADDRLEN 				17
#else
#define IP_ADDRLEN 				16
#endif
#define SID_LEN 					44
#define URL_MAX_LEN				200
#define IP_V4_DOT_COUNT		3
#define MAX_SUB_TIMEOUT		7200

#define syslog(x, fmt, args...);
#endif
