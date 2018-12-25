#ifdef __ECOS
#include <network.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef __ECOS
#include <syslog.h>
#endif
#include <arpa/inet.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "upnphttp.h"
#include "upnpsoap.h"

static int get_sockfd(void)
{
#ifndef __ECOS
	static int sockfd = -1;
#else
	int sockfd = -1;
#endif

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			perror("user: socket creation failed");
			return(-1);
		}
	}
	return sockfd;
}

IPCon IPCon_New(char * ifname)
{
	IPCon ipcon=NULL;

	ipcon = (IPCon)malloc(sizeof(_IPCon));
	if (!ipcon) { 
		printf("Error in IPCon_New:Cannot allocate memory\n");
		return NULL;
	}

	ipcon->ifname = ifname;
	return (ipcon);
}


IPCon IPCon_Destroy(IPCon this)
{
	if (!this) 
		return (NULL);

	free(this);
	return (NULL);
}

#ifndef __ECOS
struct in_addr *IPCon_GetIpAddr(IPCon this)
{
    	struct ifreq ifr;
	struct sockaddr_in *saddr;
    	int fd;

    	fd = get_sockfd();
    	if (fd >= 0) {
	    	strcpy(ifr.ifr_name, this->ifname);
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			saddr = (struct sockaddr_in *)&ifr.ifr_addr;
			return &saddr->sin_addr;
		} else {
			return NULL;
		}
		close(fd);
	}
	return NULL;
}


char *IPCon_GetIpAddrByStr(IPCon this)
{
	struct in_addr *adr;

	adr = IPCon_GetIpAddr(this);
	if (adr == NULL) {
		return NULL;
	} else {
		return inet_ntoa(*adr);
	}
}
#else
void IPCon_GetIpAddr(IPCon this, struct in_addr *inaddr)
{
    	struct ifreq ifr;
	struct sockaddr_in *saddr;
    	int fd;

	inaddr->s_addr = 0;
    	fd = get_sockfd();
    	if (fd >= 0) {
	    	strcpy(ifr.ifr_name, this->ifname);
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			saddr = (struct sockaddr_in *)&ifr.ifr_addr;
			*inaddr = saddr->sin_addr;
		}
		close(fd);
	}
}

char *IPCon_GetIpAddrByStr(IPCon this)
{
	struct in_addr addr;

	IPCon_GetIpAddr(this, &addr);

	if (addr.s_addr == 0) {
		return NULL;
	} else {
		return inet_ntoa(addr);
	}
}
#endif

int OpenAndConfHTTPSocket(const char * addr, unsigned short port)
{
	int s;
	int i = 1;
	struct sockaddr_in listenname;

	if( (s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		syslog(LOG_ERR, "socket(http): %m");
		return -1;
	}

	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0)
	{
		syslog(LOG_WARNING, "setsockopt(http, SO_REUSEADDR): %m");
	}

	memset(&listenname, 0, sizeof(struct sockaddr_in));
	listenname.sin_family = AF_INET;
	listenname.sin_port = htons(port);
	listenname.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(s, (struct sockaddr *)&listenname, sizeof(struct sockaddr_in)) < 0)
	{
		syslog(LOG_ERR, "bind(http): %m");
		close(s);
		return -1;
	}

	if(listen(s, 6) < 0)
	{
		syslog(LOG_ERR, "listen(http): %m");
		close(s);
		return -1;
	}

	return s;
}

int ReliableSend(int socket, const char *data, const int len)
{
	int n;
	unsigned int byte_left = len;
	int bytes_sent = 0;

	if (socket < 0 || data == NULL || len <= 0)
		return -1;

	while (byte_left > 0) {
		// write data
		n = send(socket, data + bytes_sent, byte_left,
#ifndef __ECOS
			MSG_DONTROUTE | MSG_NOSIGNAL );
#else
			MSG_DONTROUTE );
#endif
		if( n == -1 ) {
			syslog(LOG_ERR, "ReliableSend: sending failed!");
			return -1;
		}

		byte_left = byte_left - n;
		bytes_sent += n;
	}

	n = bytes_sent;
	return n;
}

struct upnphttp * New_upnphttp(int s)
{
	struct upnphttp * ret;
	if(s<0)
		return NULL;
	ret = (struct upnphttp *)malloc(sizeof(struct upnphttp));
	if(ret == NULL)
		return NULL;
	memset(ret, 0, sizeof(struct upnphttp));
	ret->socket = s;
	return ret;
}

void CloseSocket_upnphttp(struct upnphttp * h)
{
	close(h->socket);
	h->socket = -1;
	h->state = 100;
}

void Delete_upnphttp(struct upnphttp * h)
{
	if(h)
	{
		if(h->socket >= 0)
		{

			close(h->socket);
			h->socket=-1; 
		}


		if(h->req_buf)
		{
			free(h->req_buf);
			h->req_buf=NULL;
		}


		if(h->res_buf)
		{

			free(h->res_buf);
			h->res_buf=NULL;
		}
		free(h);
	}
}

/* parse HttpHeaders of the REQUEST */
static void ParseHttpHeaders(struct upnphttp * h)
{
	char * line;
	char * colon;
	char * p;
	int n;
	line = h->req_buf;
	/* TODO : check if req_buf, contentoff are ok */
	while(line < (h->req_buf + h->req_contentoff))
	{
		colon = strchr(line, ':');
		if(colon)
		{
			if(strncasecmp(line, "Content-Length", 14)==0)
			{
				p = colon;
				while(*p < '0' || *p > '9')
					p++;
				h->req_contentlen = atoi(p);
				/*printf("*** Content-Lenght = %d ***\n", h->req_contentlen);
				printf("    readbufflen=%d contentoff = %d\n",
					h->req_buflen, h->req_contentoff);*/
			}
			else if(strncasecmp(line, "SOAPAction", 10)==0)
			{
				p = colon;
				n = 0;
				while(*p == ':' || *p == ' ' || *p == '\t')
					p++;
				while(p[n]>=' ')
				{
					n++;
				}
				if((p[0] == '"' && p[n-1] == '"')
				  || (p[0] == '\'' && p[n-1] == '\''))
				{
					p++; n -= 2;
				}
				h->req_soapAction = p;
				h->req_soapActionLen = n;
			}
		}
		while(!(line[0] == '\r' && line[1] == '\n'))
			line++;
		line += 2;
	}
}

/* very minimalistic 404 error message */
static void Send404(struct upnphttp * h)
{
	static const char error404[] = "HTTP/1.1 404 Not found\r\n"
		"Connection: close\r\n"
		"Content-type: text/html\r\n"
		"\r\n"
		"<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>"
		"<BODY><H1>Not Found</H1>The requested URL was not found"
		" on this server.</BODY></HTML>\r\n";
	int n;
	
	n = ReliableSend(h->socket, error404, sizeof(error404) - 1);
	if (n != (sizeof(error404) - 1))
	{
		syslog(LOG_ERR, "Send404: %d bytes sent (out of %d)",
						n, (sizeof(error404) - 1));
	}
	CloseSocket_upnphttp(h);
}

// support HNAP1
void SendError(struct upnphttp * h, const int code, const char *title, const char *realm, const char *body)
{
	char *error_title=NULL;
	char *error_realm=NULL;
	char *error_body=NULL;
	int len;
	int n;
	
	if (code <=0 || title == NULL) {
		Send404(h);
		return;
	}
	
	error_title = (char *)malloc(2048);
	if(NULL == error_title) {
		printf("%s:malloc fail\n", __FUNCTION__);
		return;
	}
	
	sprintf(error_title, "HTTP/1.1 %d %s\r\n"
					"Connection: close\r\n"
					"Content-type: text/html\r\n", code, title);
	if (realm) {
		error_realm = (char *)malloc(256);
		sprintf(error_realm, "WWW-Authenticate: Basic realm=\"%s\"\r\n", realm);
		strcat(error_title, error_realm);
	}
	
	strcat(error_title, "\r\n");
	
	if (body) {
		error_body = (char *)malloc(1024);
		sprintf(error_body, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>"
						"<BODY><H1>%s</H1>%s</BODY></HTML>\r\n", code, title, title, body);
		strcat(error_title, error_body);
	}

	len = strlen(error_title);

	n = ReliableSend(h->socket, error_title, len);
	if (n != len)
	{
		syslog(LOG_ERR, "Send%d: %d bytes sent (out of %d)", code,
						n, len);
	}
	CloseSocket_upnphttp(h);
	if (error_title)
	{
		free(error_title);
		error_title=NULL;
	}
	
	if (error_realm)
	{
		free(error_realm);
		error_realm=NULL;
	}
	
	if(error_body)
	{
		free(error_body);
		error_body=NULL;
	}
	
}

/* Precondition Failed */
static void Send412PreconditionFailed(struct upnphttp * h)
{
	static const char error412[] = "HTTP/1.1 412 Precondition Failed\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n\r\n";
	int n;
	
	n = ReliableSend(h->socket, error412, sizeof(error412) - 1);
	if (n != (sizeof(error412) - 1))
	{
		syslog(LOG_ERR, "Send412PreconditionFailed: %d bytes sent (out of %d)",
						n, (sizeof(error412) - 1));
	}
	CloseSocket_upnphttp(h);
}

/* Too Many Subscribers */
static void Send412TooManySubscribers(struct upnphttp * h)
{
	static const char error412[] = "HTTP/1.1 412 Too Many Subscribers\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n\r\n";
	int n;
	
	n = ReliableSend(h->socket, error412, sizeof(error412) - 1);
	if (n != (sizeof(error412) - 1))
	{
		syslog(LOG_ERR, "Send412TooManySubscribers: %d bytes sent (out of %d)",
						n, (sizeof(error412) - 1));
	}
	CloseSocket_upnphttp(h);
}

/* very minimalistic 501 error message */
static void Send501(struct upnphttp * h)
{
	static const char error501[] = "HTTP/1.1 501 Not Implemented\r\n"
		"Connection: close\r\n"
		"Content-type: text/html\r\n"
		"\r\n"
		"<HTML><HEAD><TITLE>501 Not Implemented</TITLE></HEAD>"
		"<BODY><H1>Not Implemented</H1>The HTTP Method "
		"is not implemented by this server.</BODY></HTML>\r\n";
	int n;
	
	n = ReliableSend(h->socket, error501, sizeof(error501) - 1);
	if (n != (sizeof(error501) - 1))
	{
		syslog(LOG_ERR, "Send501: %d bytes sent (out of %d)",
						n, (sizeof(error501) - 1));
	}
	CloseSocket_upnphttp(h);
}

static const char * findendheaders(const char * s, int len)
{
	while(len-->0)
	{
		if(s[0]=='\r' && s[1]=='\n' && s[2]=='\r' && s[3]=='\n')
			return s;
		s++;
	}
	return NULL;
}

/* Sends the description generated by the parameter */
static void sendXMLdesc(struct upnphttp * h, char * (f)(int *))
{
	char * desc;
	int len;
	desc = f(&len);
	if(!desc)
	{
		syslog(LOG_ERR, "XML description generation failed");
		return;
	}
	BuildResp_upnphttp(h, desc, len);
	SendResp_upnphttp(h);
	CloseSocket_upnphttp(h);
	free(desc);
}

/* ProcessHTTPPOST_upnphttp()
 * executes the SOAP query if it is possible */
static void ProcessHTTPPOST_upnphttp(struct upnphttp * h)
{
	if((h->req_buflen - h->req_contentoff) >= h->req_contentlen)
	{
		if(h->req_soapAction)
		{
			/* we can process the request */
			syslog(LOG_INFO, "SOAPAction: %.*s",
		    	   h->req_soapActionLen, h->req_soapAction);
			ExecuteSoapAction(h, 
				h->req_soapAction,
				h->req_soapActionLen);
		}
		else
		{
			static const char err400str[] =
				"<html><body>Bad request</body></html>";
			syslog(LOG_INFO, "No SOAPAction in HTTP headers");
			BuildResp2_upnphttp(h, 400, "Bad Request",
			                    err400str, sizeof(err400str) - 1);
			SendResp_upnphttp(h);
			CloseSocket_upnphttp(h);
		}
	}
	else
	{
		/* waiting for remaining data */
		h->state = 1;
	}
}

Upnp_Document CreatePropertySet(void)
{
	Upnp_Document PropSet=NULL;

	PropSet = (Upnp_Document) malloc(sizeof(Upnp_Document_CTX));
	if (PropSet == NULL) {
		syslog(LOG_ERR, "CreatePropertySet: out of memory!");
		return NULL;
	}
	memset(PropSet, 0, sizeof(Upnp_Document_CTX));
	LIST_INIT(&PropSet->doc_head);
	return PropSet;
}

int UpnpAddToPropertySet(Upnp_Document PropSet,
								const char *VarName, const char *message)
{
	struct Upnp_Document_element *tmp=NULL;
	char *name=NULL;
	char *content=NULL;
	
	if (PropSet == NULL || VarName == NULL || message == NULL)
		return UPNP_E_INVALID_PARAM;

	tmp = (struct Upnp_Document_element *) malloc(sizeof(struct Upnp_Document_element));
	if (tmp == NULL) {
		syslog(LOG_ERR, "UpnpAddToPropertySet: out of memory!");
		return UPNP_E_OUTOF_MEMORY;
	}
	memset(tmp, 0, sizeof(struct Upnp_Document_element));

	name = (char *) malloc(strlen(VarName) + 1);
	if (name == NULL) {
		syslog(LOG_ERR, "UpnpAddToPropertySet: out of memory!");
		free(tmp);
		return UPNP_E_OUTOF_MEMORY;
	}
	memset(name, 0, strlen(VarName) + 1);
	memcpy(name, VarName, strlen(VarName));

	content = (char *) malloc(strlen(message) + 1);
	if (content == NULL) {
		syslog(LOG_ERR, "UpnpAddToPropertySet: out of memory!");
		free(tmp);
		free(name);
		return UPNP_E_OUTOF_MEMORY;
	}
	memset(content, 0, strlen(message) + 1);
	memcpy(content, message, strlen(message));

	PropSet->NumOfVarName += 1;
	PropSet->TotalMessageLen = strlen(message) + (strlen(VarName) * 2);
	tmp->VarName = name;
	tmp->message = content;
	LIST_INSERT_HEAD(&PropSet->doc_head, tmp, entries);
	
	return UPNP_E_SUCCESS;
}

static char *MakeEventBody(Upnp_Document PropSet, unsigned int *total_len)
{
	unsigned int len=0;
	char *buf=NULL;
	unsigned int buf_len=0;
	struct Upnp_Document_element *e;
	
	if (PropSet == NULL || PropSet->NumOfVarName == 0)
		return NULL;

	buf_len = (strlen("<e:property><></></e:property>") * PropSet->NumOfVarName)
				+ PropSet->TotalMessageLen + 100;
	buf = (char *) malloc(buf_len);
	if (buf == NULL) {
		syslog(LOG_ERR, "MakeEventBody: out of memory!");
		return NULL;
	}
	memset(buf, 0, buf_len);
	
	for(e = PropSet->doc_head.lh_first; e != NULL; e = e->entries.le_next)
	{
		if (e->VarName) {
			char *tmpbuf=NULL;
			unsigned int tmpbuf_len=0;
			unsigned int propertyLen=0;

			tmpbuf_len = strlen("<e:property><></></e:property>")
						+ (strlen(e->VarName) * 2)
						+ strlen(e->message) + 1;
			tmpbuf = (char *) malloc(tmpbuf_len);
			if (tmpbuf == NULL) {
				syslog(LOG_ERR, "MakeEventBody: out of memory!");
				free(buf);
				return NULL;
			}
			memset(tmpbuf, 0, tmpbuf_len);
			propertyLen = sprintf(tmpbuf, 
				"<e:property><%s>%s</%s></e:property>",
				e->VarName, e->message, e->VarName);
			len += propertyLen;
			strcat(buf, tmpbuf);
			free(tmpbuf);
		}
	}

	*total_len = len;
	return buf;
}

static void UpnpSendEvent(char *packet,
								const char *EventBody, const unsigned int bodylength,
								struct upnp_subscription_record *subscribe_list,
								struct upnp_subscription_element *sub)
{
	unsigned int packetLength;
	struct sockaddr_in dest;
	int n, sockfd=-1;
	struct EvtRespElement *EvtResp=NULL;
	
	if (packet == NULL || EventBody == NULL || bodylength == 0 ||
		subscribe_list == NULL || sub == NULL)
		return;

	packetLength = sprintf(packet,
		"NOTIFY %s HTTP/1.1\r\n"
		"SERVER: " MINIUPNPD_SERVER_STRING "\r\n"
		"HOST: %s:%d\r\n"
		"Content-Type: text/xml; charset=\"utf-8\"\r\n"
		"NT: upnp:event\r\n"
		"NTS: upnp:propchange\r\n"
		"SID: %s\r\n"
		"SEQ: %d\r\n"
		"Content-Length: %d\r\n\r\n"
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<e:propertyset xmlns:e=\"urn:schemas-upnp-org:event-1-0\">"
		"%s"
		"</e:propertyset>",
		sub->callback_url,
		sub->IP,
		sub->port,
		sub->sid,
		(int)sub->seq,
		bodylength+110,
		EventBody);
	
	sub->seq++;
	if (sub->seq >= UINT_MAX)
		sub->seq = 1;
	//printf("Packet------------>\n%s\n<-----------------Packet\n\n", packet);

	memset(&dest,0,sizeof(struct sockaddr_in));
	dest.sin_addr.s_addr = sub->IP_inet_addr;
	dest.sin_port = htons(sub->port);
	dest.sin_family = AF_INET;

	// create a socket
	if ((sockfd = socket( AF_INET, SOCK_STREAM, 0 )) == -1) {
		syslog(LOG_ERR, "UpnpSendEvent: creating a socket falied!");
		return;
	}
	if (connect( sockfd, ( struct sockaddr * )&dest,
                 sizeof( struct sockaddr_in ) ) == -1) {
		syslog(LOG_ERR, "UpnpSendEvent: connecting a socket falied!");
		close(sockfd);
		return;
    	}

	n = ReliableSend(sockfd, packet, packetLength);
	if (n != packetLength)
	{
		syslog(LOG_ERR, "UpnpSendEvent: %d bytes sent (out of %d)",
						n, packetLength);
		close(sockfd);
		return;
	}

	EvtResp = (struct EvtRespElement *) malloc(sizeof(struct EvtRespElement));
	if (EvtResp == NULL) {
		syslog(LOG_ERR, "UpnpSendEvent: out of memory!");
		close(sockfd);
		return;
	}
	memset(EvtResp, 0, sizeof(struct EvtRespElement));
	EvtResp->socket = sockfd;
	memcpy(EvtResp->sid, sub->sid, strlen(sub->sid));
	EvtResp->TimeOut = 30;
	LIST_INSERT_HEAD(&subscribe_list->EvtResp_head, EvtResp, entries);
}

void UpnpSendEventSingle(Upnp_Document PropSet,
								struct upnp_subscription_record *subscribe_list,
								struct upnp_subscription_element *sub)
{
	char *packet=NULL;
	unsigned int bodylength=0;
	char *EventBody=NULL;

	if (PropSet == NULL || sub == NULL || subscribe_list == NULL ||
		subscribe_list->subscription_head.lh_first == NULL)
		return;

	EventBody = MakeEventBody(PropSet, &bodylength);
	if (EventBody == NULL) {
		syslog(LOG_ERR, "UpnpSendEventSingle: MakeEventBody failed!");
		return;
	}

	packet = (char *) malloc(bodylength + 483);
	if (packet == NULL) {
		syslog(LOG_ERR, "UpnpSendEventSingle: out of memory!");
		free(EventBody);
		return;
	}
	memset(packet, 0, bodylength + 483);

	UpnpSendEvent(packet, EventBody, bodylength, subscribe_list, sub);
	free(EventBody);
	free(packet);
}

void ProcessEventingResp(struct EvtRespElement *EvtResp)
{
	char *buf=NULL;
	int n;

	if (EvtResp == NULL)
		return;

	buf = (char *) malloc(512);
	if (buf == NULL) {
		close(EvtResp->socket);
		return;
	}
	memset(buf, 0, 512);
	
	if ((n = recv(EvtResp->socket, buf, 512, 0)) == -1) {
		syslog(LOG_ERR, "ProcessEventingResp: Receive failed!");
	}
	else if(n==0)
	{
		syslog(LOG_WARNING, "ProcessEventingResp: connection closed inexpectedly");
	}
	
	//printf("------------>\nProcessEventingResp: sid[%s]\n%s\n<--------------\n", EvtResp->sid, buf);
	close(EvtResp->socket);
	free(buf);
}

void UpnpSendEventAll(Upnp_Document PropSet,
							struct upnp_subscription_record *sub_list)
{
	struct upnp_subscription_element *sub;
	unsigned int bodylength=0;
	char *EventBody=NULL;
	char *packet=NULL;

	if (PropSet == NULL || sub_list == NULL || sub_list->subscription_head.lh_first == NULL)
		return;

	EventBody = MakeEventBody(PropSet, &bodylength);
	if (EventBody == NULL) {
		syslog(LOG_ERR, "UpnpSendEventAll: MakeEventBody failed!");
		return;
	}

	packet = (char *) malloc(bodylength + 483);
	if (packet == NULL) {
		syslog(LOG_ERR, "UpnpSendEventAll: out of memory!");
		free(EventBody);
		return;
	}
	
	for (sub = sub_list->subscription_head.lh_first; sub != NULL; sub = sub->entries.le_next)
	{
		memset(packet, 0, bodylength + 483);
		UpnpSendEvent(packet, EventBody, bodylength, sub_list, sub);
	}
	free(EventBody);
	free(packet);
}

void UpnpDocument_free(Upnp_Document PropSet)
{
	struct Upnp_Document_element *e;
	struct Upnp_Document_element *next;
	
	if (PropSet == NULL)
		return;

	for(e = PropSet->doc_head.lh_first; e != NULL; )
	{
		next = e->entries.le_next;
		if (e->VarName)
			free(e->VarName);
		if (e->message)
			free(e->message);
		LIST_REMOVE(e, entries);
		free(e);
		e = next;
	}

	free(PropSet);
}

static int BuildSubscribeResponse(struct upnphttp * h, struct process_upnp_subscription *sub)
{
	char *Subresp=NULL;
	int n, packet_len, ret=UPNP_E_SUCCESS;

	Subresp = (char *) malloc(300);
	if (Subresp == NULL) {
		CloseSocket_upnphttp(h);
		syslog(LOG_ERR, "BuildSubscribeResponse: out of memory!");
		return UPNP_E_OUTOF_MEMORY;
	}
	memset(Subresp, 0, 300);
	
	packet_len = sprintf(Subresp, 
		"HTTP/1.1 200 OK \r\n"
		"Server: " MINIUPNPD_SERVER_STRING "\r\n"
		"SID: %s\r\n"
		"TIMEOUT: Second-%d\r\n"
		"Content-Length: 0\r\n"
		"\r\n",
		sub->sid, (int)h->subscribe_list->max_subscription_time);
	
	//printf("BuildSubscribeResponse------->\n%s<------------BuildSubscribeResponse\n", Subresp);

	n = ReliableSend(h->socket, Subresp, packet_len);
	if (n != packet_len)
	{
		syslog(LOG_ERR, "BuildSubscribeResponse: %d bytes sent (out of %d)",
						n, packet_len);
	}
	
	free(Subresp);
	CloseSocket_upnphttp(h);
	return ret;
}

static void BuildUnSubscribeResponse(struct upnphttp * h)
{
	static const char UnSubresp[] =
		"HTTP/1.1 200 OK \r\n"
		"Content-Length: 0\r\n"
		"\r\n";

	int n;
	
	n = ReliableSend(h->socket, UnSubresp, sizeof(UnSubresp) - 1);
	if (n != (sizeof(UnSubresp) - 1))
	{
		syslog(LOG_ERR, "BuildUnSubscribeResponse: %d bytes sent (out of %d)",
						n, (sizeof(UnSubresp) - 1));
	}
	CloseSocket_upnphttp(h);
}

static struct upnp_subscription_element *UPnPTryToSubscribe
	(struct upnphttp * h, struct process_upnp_subscription *sub)
{
	int SIDNumber,rnumber;
	char *SID=NULL;
	struct upnp_subscription_element *new_sub=NULL;
	
	if (h == NULL || sub == NULL)
		return NULL;
	
	if (h->subscribe_list->total_subscription >= h->subscribe_list->max_subscription_num)	
		return NULL;

	new_sub = (struct upnp_subscription_element *) malloc(sizeof(struct upnp_subscription_element));
	if (new_sub == NULL)
		return NULL;
	memset(new_sub, 0, sizeof(struct upnp_subscription_element));
	
	//
	// The SID must be globally unique, so lets generate it using
	// a bunch of random hex characters
	//
	SID = (char*)malloc(SID_LEN);
	if (SID == NULL) {
		free(new_sub);
		return NULL;
	}
	memset(SID,0,SID_LEN);
	sprintf(SID,"uuid:");
	for(SIDNumber=5;SIDNumber<=12;++SIDNumber)
	{
		rnumber = rand()%16;
		sprintf(SID+SIDNumber,"%x",rnumber);
	}
	sprintf(SID+SIDNumber,"-");
	for(SIDNumber=14;SIDNumber<=17;++SIDNumber)
	{
		rnumber = rand()%16;
		sprintf(SID+SIDNumber,"%x",rnumber);
	}
	sprintf(SID+SIDNumber,"-");
	for(SIDNumber=19;SIDNumber<=22;++SIDNumber)
	{
		rnumber = rand()%16;
		sprintf(SID+SIDNumber,"%x",rnumber);
	}
	sprintf(SID+SIDNumber,"-");
	for(SIDNumber=24;SIDNumber<=27;++SIDNumber)
	{
		rnumber = rand()%16;
		sprintf(SID+SIDNumber,"%x",rnumber);
	}
	sprintf(SID+SIDNumber,"-");
	for(SIDNumber=29;SIDNumber<=40;++SIDNumber)
	{
		rnumber = rand()%16;
		sprintf(SID+SIDNumber,"%x",rnumber);
	}

	memcpy(sub->sid, SID, SID_LEN);
	if (BuildSubscribeResponse(h, sub) != UPNP_E_SUCCESS) {
		free(SID);
		free(new_sub);
		return NULL;
	}

	memcpy(new_sub->IP, sub->IP, SID_LEN);
	new_sub->IP_inet_addr = sub->IP_inet_addr;
	new_sub->port = sub->port;
	memcpy(new_sub->sid, SID, SID_LEN);
	memcpy(new_sub->callback_url, sub->callback_url, URL_MAX_LEN);
	new_sub->TimeOut = sub->TimeOut;
//WPS2DOTX
//	new_sub->subscription_timeout = h->subscribe_list->subscription_timeout;
	new_sub->subscription_timeout = sub->TimeOut;

//	printf("\n\nsubscription_timeout=%d\n",new_sub->subscription_timeout);
	
	new_sub->eventID = UPNP_EVENT_SUBSCRIPTION_REQUEST;
	LIST_INSERT_HEAD(&h->subscribe_list->subscription_head, new_sub, entries);
	h->subscribe_list->total_subscription++;
	syslog(LOG_INFO, "Subscribe: total_subscription [%d]",
	       (int)h->subscribe_list->total_subscription);
		
	free(SID);
	return new_sub;
}

static char *GetTokenValue(const unsigned long buf, const unsigned long len, unsigned int *Value_len)
{
	unsigned long start=0, end=0;
	unsigned long buffer_end;
	char *line;
	
	if (len == 0)
		return NULL;
	
	line = (char *)buf;
	buffer_end = (unsigned long)line + len;
	
	while ((unsigned long)line < buffer_end) {
		if ((*line == ' ') || (*line == ':') || (*line == '-'))
			line++;
		else {
			start = (unsigned long)line;
			break;
		}
	}
	if (start == 0) {
		*Value_len = 0;
		return NULL;
	}
	
	while ((unsigned long)line < buffer_end) {
		if ((*line == ' ') || (*line == '\r') || (*line == '\n')) {
			end = (unsigned long)line;
			break;
		}
		else
			line++;
	}
	if (end == 0) {
		*Value_len = 0;
		return NULL;
	}

	*Value_len = (unsigned int)(end - start);
	return (char *)start;
}

static __inline__ void GetLineLen(const unsigned long buf, unsigned int *line_len)
{
	unsigned long start=0;
	const unsigned short MaxCharsPerLine = 1000;
	unsigned short NumChars=0;
	char *line;

	line = (char *)buf;
	start = (unsigned long)line;
	while (*line != '\n') {
		NumChars++;
		if (NumChars >= MaxCharsPerLine) {
			syslog(LOG_WARNING, "Too many characters in a line!");
			*line_len = 0;
			return;
		}
		line++;
	}

	*line_len = (unsigned long)line + 1 - start;
	return;
}


// To do : support IPv6
static __inline__ int GetIPandPortandCallBack(const unsigned long buf, const unsigned int buf_len,
							struct process_upnp_subscription *sub)
{
	char *line=NULL;
	unsigned long buffer_end=0;
	unsigned char dot_count=0;
	unsigned long start=0;
	unsigned long end=0;
	unsigned char GotIPandPort=0;

	line = (char *)buf;
	buffer_end = (unsigned long)line + buf_len;
	while ((unsigned long)line < buffer_end) {
		if (*line == ' ') {
			line++;
			continue;
		}
		if (strncasecmp("<http://", line, 8) != 0)
			return UPNP_E_INVALID_PARAM;
		else
			break;
	}
	
	line += 8;
	start =(unsigned long) line;
	while ((unsigned long)line < buffer_end) {
		if (*line == '.')
			dot_count++;
		if ((*line == ':') || (*line == '/')) {
			if (dot_count != IP_V4_DOT_COUNT)
				return UPNP_E_INVALID_PARAM;
			memcpy(sub->IP, (char *)start, (unsigned long)line-start);
			if ((sub->IP_inet_addr = inet_addr(sub->IP)) == -1)
				return UPNP_E_INVALID_PARAM;
			break;
		}
		line++;
	}

	if (*line == '/') {
		sub->port = 80;
		GotIPandPort = 1;
		start = (unsigned long)line;
		end = 0;
		goto get_callback;
	}
		
	line += 1;
	start = (unsigned long)line;
	while ((unsigned long)line < buffer_end) {
		if (*line == '/') {
			end = (unsigned long)line;
			if (end <= start)
				return UPNP_E_INVALID_PARAM;
			else {
				char port[10];
				memset(port, 0, 10);
				memcpy(port, (char *)start, end-start);
				sub->port = atoi(port);
				GotIPandPort = 1;
				start = (unsigned long)line;
				end = 0;
				break;
			}
		}
		line++;
	}

get_callback:
	if (!GotIPandPort)
		return UPNP_E_INVALID_PARAM;
	while ((unsigned long)line < buffer_end) {
		if (*line == '>') {
			end = (unsigned long)line;
			if (end <= start)
				return UPNP_E_INVALID_PARAM;
			else {
				memcpy(sub->callback_url, (char *)start, end-start);
				return UPNP_E_SUCCESS;
			}
		}
		line++;
	}
	
	return UPNP_E_INVALID_PARAM;
}

static int ParseSUBSCRIBEPacket(struct upnphttp * h,
							struct process_upnp_subscription *sub)
{
	char *line=NULL, *value=NULL, *tmp=NULL;
	unsigned int line_len=0, value_len=0, tmp_len=0;
	unsigned long buffer_end=0;
	
	if (h->req_buf == NULL || h->req_contentoff == 0)
		return UPNP_E_INVALID_PARAM;

	line = h->req_buf;
	buffer_end = (unsigned long)h->req_buf + h->req_contentoff;
	while ((unsigned long)line < buffer_end) {
		if (*line == ' ') {
			line++;
			continue;
		}
		GetLineLen((const unsigned long)line, &line_len);
		if (line_len == 0)
			return UPNP_E_INVALID_PARAM;
		else if (line_len > 2) {
			if (strncasecmp("SUBSCRIBE", line, 9) == 0) {
				value = GetTokenValue((const unsigned long)line+9, line_len-9, &value_len);
				if (value == NULL || value_len == 0)
					return UPNP_E_INVALID_PARAM;
				
				if (strncasecmp(h->subscribe_list->event_url, value, value_len) != 0) {
					syslog(LOG_WARNING, "SUBSCRIBE event url mismatched!");
					return UPNP_E_INVALID_PARAM;
				}
			}
			else if (strncasecmp("UNSUBSCRIBE", line, 11) == 0) {
				value = GetTokenValue((const unsigned long)line+11, line_len-11, &value_len);
				if (value == NULL || value_len == 0)
					return UPNP_E_INVALID_PARAM;
				
				if (strncasecmp(h->subscribe_list->event_url, value, value_len) != 0) {
					syslog(LOG_WARNING, "UNSUBSCRIBE event url mismatched!");
					return UPNP_E_INVALID_PARAM;
				}
			}
			else if (strncasecmp("Host", line, 4) == 0) {
				value = GetTokenValue((const unsigned long)line+4, line_len-4, &value_len);
				if (value == NULL || value_len == 0)
					return UPNP_E_INVALID_PARAM;
				
				char host_info[30];
				memset(host_info, 0, 30);
				sprintf(host_info, "%s:%d", h->subscribe_list->my_IP, h->subscribe_list->my_port);
				if (strncmp(value, host_info, value_len) != 0) {
					syslog(LOG_WARNING, "Wrong host [%s]", host_info);
					return UPNP_E_INVALID_PARAM;
				}
			}
			else if (strncasecmp("Callback", line, 8) == 0) {
				value = GetTokenValue((const unsigned long)line+8, line_len-8, &value_len);
				if (value == NULL || value_len == 0 || (value_len > (URL_MAX_LEN-1)))
					return UPNP_E_INVALID_PARAM;

				if (GetIPandPortandCallBack((const unsigned long) value, value_len, sub) != UPNP_E_SUCCESS)
					return UPNP_E_INVALID_PARAM;
			}
			else if (strncasecmp("Timeout", line, 7) == 0) {
				value = GetTokenValue((const unsigned long)line+7, line_len-7, &value_len);
				if (value == NULL || value_len == 0 || value_len < 8)
					return UPNP_E_INVALID_PARAM;
				
				if (strncasecmp("Second", value, 6) != 0)
					return UPNP_E_INVALID_PARAM;
				tmp = value + 6;
				tmp_len = value_len - 6;
				value = GetTokenValue((const unsigned long)tmp, tmp_len+1, &value_len);
				if (value_len == 0)
					return UPNP_E_INVALID_PARAM;
				else if (value_len == 8 && (strncasecmp("infinite", line, 8) == 0))
					sub->TimeOut = MAX_SUB_TIMEOUT;
				else {
					if (value_len > 4)
						sub->TimeOut = MAX_SUB_TIMEOUT;
					else {
						char time_out[5];
						memset(time_out, 0, 5);
						memcpy(time_out, value, value_len);
						sub->TimeOut = atoi(time_out);
					}
				}
			}
			else if (strncasecmp("SID", line, 3) == 0) {
				value = GetTokenValue((const unsigned long)line+3, line_len-3, &value_len);
				if (value == NULL || value_len == 0 || value_len < 4)
					return UPNP_E_INVALID_PARAM;
				
				if (strncasecmp("uuid", value, 4) != 0)
					return UPNP_E_INVALID_PARAM;
				tmp = value + 4;
				tmp_len = value_len - 4;
				value = GetTokenValue((const unsigned long)tmp, tmp_len+1, &value_len);
				if (value == NULL || value_len == 0 || value_len != 36)
					return UPNP_E_INVALID_PARAM;

				char sid[SID_LEN];
				memset(sid, 0, SID_LEN);
				memcpy(sub->sid, "uuid:", 5);
				memcpy(sub->sid+5, value, value_len);
			}
		}
		
		line += line_len;
	}

	return UPNP_E_SUCCESS;
}

static void UPnPProcessSUBSCRIBE(struct upnphttp * h)
{
	struct process_upnp_subscription sub;
	struct upnp_subscription_element *new_sub=NULL;
	int ret;

	memset(&sub, 0, sizeof(struct process_upnp_subscription));
	ret = ParseSUBSCRIBEPacket(h, &sub);
	if (ret != UPNP_E_SUCCESS) {
		Send412PreconditionFailed(h);
		return;
	}
	else {
#ifdef DEBUG
		printf("IP [%s]\n", sub.IP);
		printf("Host [%d.%d.%d.%d:%d]\n", (sub.IP_inet_addr>>24)&0xFF,
			(sub.IP_inet_addr>>16)&0xFF,
			(sub.IP_inet_addr>>8)&0xFF,
			(sub.IP_inet_addr)&0xFF, sub.port);
		printf("SID [%s]\n", sub.sid);
		printf("CallBack %s\n", sub.callback_url);
		printf("Timeout [%d]\n", (int)sub.TimeOut);
#endif

		if (sub.TimeOut == 0)
			sub.TimeOut = MAX_SUB_TIMEOUT;
		
		if (sub.sid[0] == 0) 
		{ //Subscribe
			if (sub.callback_url[0] == 0) {
				Send412PreconditionFailed(h);
				return;
			}

			new_sub = UPnPTryToSubscribe(h, &sub);
			if (new_sub == NULL) {
				Send412TooManySubscribers(h);
				return;
			}

			if (h->subscribe_list->EventCallBack)
				h->subscribe_list->EventCallBack(new_sub);
		}
		else 
		{ // Renewal subscription
			struct upnp_subscription_element *e;
			struct upnp_subscription_element *next;
			unsigned char count=0;

			for(e = h->subscribe_list->subscription_head.lh_first; e != NULL; )
			{
				next = e->entries.le_next;
				if(strcmp(e->sid, sub.sid) == 0)
				{
					count++;
					if (BuildSubscribeResponse(h, &sub) != UPNP_E_SUCCESS) {
						LIST_REMOVE(e, entries);
						h->subscribe_list->total_subscription--;
						free(e);
						syslog(LOG_ERR, "UPnPProcessSUBSCRIBE : renew failed!");
						return;
					}
					else {
						//WPS2DOTX
						//e->subscription_timeout = h->subscribe_list->subscription_timeout;
						e->subscription_timeout = (int)sub.TimeOut;
						
						e->eventID = UPNP_EVENT_RENEWAL_COMPLETE;
					}
					syslog(LOG_INFO, "Renewal subscription: total_subscription [%d]",
	       				(int)h->subscribe_list->total_subscription);
					if (h->subscribe_list->EventCallBack){
						h->subscribe_list->EventCallBack(e);
						if(e->wscdReNewState == 1){
							Send412PreconditionFailed(h);
							e->wscdReNewState = 0;
						}						
					}
				}
				e = next;
			}
			if (count == 0) {
				Send412PreconditionFailed(h);
				syslog(LOG_ERR, "UPnPProcessSUBSCRIBE[renew] : Could not find the sid[%s]!", sub.sid);
				if (new_sub == NULL) {
					new_sub = (struct upnp_subscription_element *)malloc(sizeof(struct upnp_subscription_element));
					if (new_sub == NULL)
						return;
					memset(new_sub, 0, sizeof(struct upnp_subscription_element));
					new_sub->eventID = UPNP_EVENT_RENEWAL_COMPLETE;
					memcpy(new_sub->sid, sub.sid, strlen(sub.sid));
					if (h->subscribe_list->EventCallBack)
						h->subscribe_list->EventCallBack(new_sub);
					free(new_sub);
				}
				else
					syslog(LOG_ERR, "UPnPProcessSUBSCRIBE[renew] : Could not allocate buffer for new_sub!");
			}
		}
	}
}

static void UPnPProcessUNSUBSCRIBE(struct upnphttp * h)
{
	struct process_upnp_subscription sub;
	struct upnp_subscription_element *e;
	struct upnp_subscription_element *next;
	int ret;
	unsigned char count=0;

	memset(&sub, 0, sizeof(struct process_upnp_subscription));
	ret = ParseSUBSCRIBEPacket(h, &sub);
	if (ret != UPNP_E_SUCCESS) {
		Send412PreconditionFailed(h);
		return;
	}
	else {
#ifdef DEBUG
		printf("IP [%s]\n", sub.IP);
		printf("Host [%d.%d.%d.%d:%d]\n", (sub.IP_inet_addr>>24)&0xFF,
			(sub.IP_inet_addr>>16)&0xFF,
			(sub.IP_inet_addr>>8)&0xFF,
			(sub.IP_inet_addr)&0xFF, sub.port);
		printf("SID [%s]\n", sub.sid);
		printf("CallBack %s\n", sub.callback_url);
		printf("Timeout [%d]\n", (int)sub.TimeOut);
#endif

		if (sub.sid[0] == 0) {
			Send412PreconditionFailed(h);
			return;
		}

		for(e = h->subscribe_list->subscription_head.lh_first; e != NULL; )
		{
			next = e->entries.le_next;
			if(strcmp(e->sid, sub.sid) == 0)
			{
				count++;
				LIST_REMOVE(e, entries);
				BuildUnSubscribeResponse(h);
				h->subscribe_list->total_subscription--;
				syslog(LOG_INFO, "UNSUBSCRIBE: total_subscription [%d]",
	       			(int)h->subscribe_list->total_subscription);
				
				e->eventID = UPNP_EVENT_UNSUBSCRIBE_COMPLETE;
				if (h->subscribe_list->EventCallBack)
					h->subscribe_list->EventCallBack(e);
				free(e);
			}
			e = next;
		}

		if (count == 0) {
			BuildUnSubscribeResponse(h);
			syslog(LOG_ERR, "UPnPProcessUNSUBSCRIBE : Could not find the sid!");
		}
	}
}

/* Parse and process Http Query 
 * called once all the HTTP headers have been received. */
static void ProcessHttpQuery_upnphttp(struct upnphttp * h)
{
	char HttpCommand[16];
	char HttpUrl[128];
	char * HttpVer;
	char * p;
	int i;
	p = h->req_buf;
	if(!p)
		return;
	for(i = 0; i<15 && *p != ' ' && *p != '\r'; i++)
		HttpCommand[i] = *(p++);
	HttpCommand[i] = '\0';
	while(*p==' ')
		p++;
	for(i = 0; i<127 && *p != ' ' && *p != '\r'; i++)
		HttpUrl[i] = *(p++);
	HttpUrl[i] = '\0';
	while(*p==' ')
		p++;
	HttpVer = h->HttpVer;
	for(i = 0; i<15 && *p != '\r'; i++)
		HttpVer[i] = *(p++);
	HttpVer[i] = '\0';
	syslog(LOG_INFO, "HTTP REQUEST : %s %s (%s)",
	       HttpCommand, HttpUrl, HttpVer);
	ParseHttpHeaders(h);
	if(strcmp("POST", HttpCommand) == 0)
	{
		h->req_command = EPost;
		ProcessHTTPPOST_upnphttp(h);
	}
	else if(strcmp("GET", HttpCommand) == 0)
	{
		h->req_command = EGet;

		if (strncasecmp((char *)h->req_buf, "GET /HNAP", 9) == 0) {
			i = 0;
			int len;
			while(h->soapMethods[i].methodName)
			{
				len = strlen(h->soapMethods[i].methodName);
				if(strncmp("GetDeviceSettings", h->soapMethods[i].methodName, len) == 0)
				{
					h->soapMethods[i].methodImpl(h);
					return;
				}
				i++;
			}
			syslog(LOG_NOTICE, "%s not found, responding ERROR 404", HttpUrl);
			Send404(h);
			return;
		}
		i = 0;
		if (h->sendDesc) {
		while(h->sendDesc[i].DescName)
		{
			if(strcmp(h->sendDesc[i].DescName, HttpUrl) == 0)
			{
				sendXMLdesc(h, h->sendDesc[i].sendDescImpl);
				return;
			}
			i++;
		}
		}

		syslog(LOG_NOTICE, "%s not found, responding ERROR 404", HttpUrl);
		Send404(h);
	}
	else if(strcmp("SUBSCRIBE", HttpCommand) == 0)
	{
		//printf("<<--------------------\n%s\n------------------->>\n", h->req_buf);
		UPnPProcessSUBSCRIBE(h);
	}
	else if(strcmp("UNSUBSCRIBE", HttpCommand) == 0) 
	{
		//printf("<<--------------------\n%s\n------------------->>\n", h->req_buf);
		UPnPProcessUNSUBSCRIBE(h);
	}
	else
	{
		syslog(LOG_NOTICE, "Unsupported HTTP Command %s", HttpCommand);
		Send501(h);
	}
}


void Process_upnphttp(struct upnphttp * h)
{
	char *buf=NULL;
	int n;
	
	if(!h)
		return;

	buf = (char *) malloc(2048);
	if (buf == NULL) {
		syslog(LOG_ERR, "Process_upnphttp: out of memory!");
		return;
	}
	memset(buf, 0, 2048);
	
	switch(h->state)
	{
	case 0:
		n = recv(h->socket, buf, 2048, 0);
		if(n<0)
		{
			syslog(LOG_ERR, "recv (state0): %m");
			h->state = 100;
		}
		else if(n==0)
		{
			syslog(LOG_WARNING, "connection closed inexpectedly");
			h->state = 100;
		}
		else
		{
			const char * endheaders;
			/*printf("== PACKET RECEIVED (%d bytes) ==\n", n);
			fwrite(buf, 1, n, stdout);	// debug
			printf("== END OF PACKET RECEIVED ==\n");*/
			/* if 1st arg of realloc() is null,
			 * realloc behaves the same as malloc() */
			//h->req_buf = (char *)realloc(h->req_buf, n + h->req_buflen + 1);
			h->req_buf = (char *)realloc(h->req_buf, 2048); //Brad modify for HNAP, bug fix
			memcpy(h->req_buf + h->req_buflen, buf, n);
			h->req_buflen += n;
			h->req_buf[h->req_buflen] = '\0';
			/* search for the string "\r\n\r\n" */
			endheaders = findendheaders(h->req_buf, h->req_buflen);
			if(endheaders)
			{
				h->req_contentoff = endheaders - h->req_buf + 4;
				ProcessHttpQuery_upnphttp(h);
			}
		}
		break;
	case 1:
		n = recv(h->socket, buf, 2048, 0);
		if(n<0)
		{
			syslog(LOG_ERR, "recv (state1): %m");
			h->state = 100;
		}
		else if(n==0)
		{
			syslog(LOG_WARNING, "connection closed inexpectedly");
			h->state = 100;
		}
		else
		{
			/*fwrite(buf, 1, n, stdout);*/	/* debug */
			h->req_buf = (char *)realloc(h->req_buf, n + h->req_buflen);
			memcpy(h->req_buf + h->req_buflen, buf, n);
			h->req_buflen += n;
			if((h->req_buflen - h->req_contentoff) >= h->req_contentlen)
			{
				ProcessHTTPPOST_upnphttp(h);
			}
		}
		break;
	default:
		syslog(LOG_WARNING, "unexpected state (%d)", h->state);
	}

	free(buf);
}

static const char httpresphead[] =
	"%s %d %s\r\n"
	"Content-Type: text/xml; charset=\"utf-8\"\r\n"
	"Connection: close\r\n"
	"Content-Length: %d\r\n"
	"Server: " MINIUPNPD_SERVER_STRING "\r\n"
	"Ext:\r\n"
	"\r\n";
/*
		"<?xml version=\"1.0\"?>\n"
		"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<s:Body>"

		"</s:Body>"
		"</s:Envelope>";
*/
/* with response code and response message
 * also allocate enough memory */
void
BuildHeader_upnphttp(struct upnphttp * h, int respcode,
                     const char * respmsg,
                     int bodylen)
{
	int templen;
	if(!h->res_buf)
	{
		templen = sizeof(httpresphead) + 64 + bodylen;
		h->res_buf = (char *)malloc(templen);
		memset(h->res_buf, 0, templen);
		h->res_buf_alloclen = templen;
	}
	h->res_buflen = snprintf(h->res_buf, h->res_buf_alloclen,
	                         httpresphead, h->HttpVer,
	                         respcode, respmsg, bodylen);
	if(h->res_buf_alloclen < (h->res_buflen + bodylen))
	{
		h->res_buf = (char *)realloc(h->res_buf, (h->res_buflen + bodylen));
		memset(h->res_buf, 0, (h->res_buflen + bodylen));
		h->res_buf_alloclen = h->res_buflen + bodylen;
	}
}

void
BuildResp2_upnphttp(struct upnphttp * h, int respcode,
                    const char * respmsg,
                    const char * body, int bodylen)
{
	BuildHeader_upnphttp(h, respcode, respmsg, bodylen);
	memcpy(h->res_buf + h->res_buflen, body, bodylen);
	h->res_buflen += bodylen;
}

/* responding 200 OK ! */
void BuildResp_upnphttp(struct upnphttp * h,
                        const char * body, int bodylen)
{
	BuildResp2_upnphttp(h, 200, "OK", body, bodylen);
}

void SendResp_upnphttp(struct upnphttp * h)
{
	int n;
	
	n = ReliableSend(h->socket, h->res_buf, h->res_buflen);
	if (n != h->res_buflen)
	{
		syslog(LOG_ERR, "SendResp_upnphttp: %d bytes sent (out of %d)",
						n, h->res_buflen);
	}
}

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/* encode 3 8-bit binary bytes as 4 '6-bit' characters */
static void ILibencodeblock( unsigned char in[3], unsigned char out[4], int len )
{
	out[0] = cb64[ in[0] >> 2 ];
	out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
	out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*! \fn ILibBase64Encode(unsigned char* input, const int inputlen, unsigned char** output)
	\brief Base64 encode a stream adding padding and line breaks as per spec.
	\par
	\b Note: The encoded stream must be freed
	\param input The stream to encode
	\param inputlen The length of \a input
	\param output The encoded stream
	\returns The length of the encoded stream
*/
int ILibBase64Encode(unsigned char* input, const int inputlen, unsigned char** output)
{
	unsigned char* out=NULL;
	unsigned char* in;
	
	*output = (unsigned char*)malloc(((inputlen * 4) / 3) + 5);
	out = *output;
	if (out == NULL)
		return 0;
	in  = input;
	
	if (input == NULL || inputlen == 0)
	{
		*output = NULL;
		return 0;
	}
	
	while ((in+3) <= (input+inputlen))
	{
		ILibencodeblock(in, out, 3);
		in += 3;
		out += 4;
	}
	if ((input+inputlen)-in == 1)
	{
		ILibencodeblock(in, out, 1);
		out += 4;
	}
	else
	if ((input+inputlen)-in == 2)
	{
		ILibencodeblock(in, out, 2);
		out += 4;
	}
	*out = 0;
	
	return (int)(out-*output);
}

/* Decode 4 '6-bit' characters into 3 8-bit binary bytes */
static void ILibdecodeblock( unsigned char in[4], unsigned char out[3] )
{
	out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
	out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
	out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

/*! \fn ILibBase64Decode(unsigned char* input, const int inputlen, unsigned char** output)
	\brief Decode a base64 encoded stream discarding padding, line breaks and noise
	\par
	\b Note: The decoded stream must be freed
	\param input The stream to decode
	\param inputlen The length of \a input
	\param output The decoded stream
	\returns The length of the decoded stream
*/
int ILibBase64Decode(unsigned char* input, const int inputlen, unsigned char** output)
{
	unsigned char* inptr;
	unsigned char* out=NULL;
	unsigned char v;
	unsigned char in[4];
	int i, len;
	
	if (input == NULL || inputlen == 0)
	{
		*output = NULL;
		return 0;
	}
	
	*output = (unsigned char*)malloc(((inputlen * 3) / 4) + 4);
	out = *output;
	if (out == NULL)
		return 0;
	inptr = input;
	
	while( inptr <= (input+inputlen) )
	{
		for( len = 0, i = 0; i < 4 && inptr <= (input+inputlen); i++ )
		{
			v = 0;
			while( inptr <= (input+inputlen) && v == 0 ) {
				v = (unsigned char) *inptr;
				inptr++;
				v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
				if( v ) {
					v = (unsigned char) ((v == '$') ? 0 : v - 61);
				}
			}
			if( inptr <= (input+inputlen) ) {
				len++;
				if( v ) {
					in[ i ] = (unsigned char) (v - 1);
				}
			}
			else {
				in[i] = 0;
			}
		}
		if( len )
		{
			ILibdecodeblock( in, out );
			out += len-1;
		}
	}
	*out = 0;
	return (int)(out-*output);
}

#ifndef __ECOS
int OpenAndConfUNIXSocket(const char *file_path)
{
	int s, len;
	struct sockaddr_un local;

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            	perror("UNIXSocket");
            	return -1;
    	}
	
    	local.sun_family = AF_UNIX;
     	strcpy(local.sun_path, file_path);
     	unlink(local.sun_path);
     	//len = strlen(local.sun_path) + sizeof(local.sun_family);
     	len = sizeof(struct sockaddr_un);
    	if (bind(s, (struct sockaddr *)&local, len) == -1) {
            	perror("UNIXSocket bind");
            	return -1;
     	}

     	if (listen(s, 5) == -1) {
            	perror("UNIXSocket listen");
            	return -1;
     	}

	return s;
}

int CreateUnixSocket(const char *function_name,
								const char *file_path,
								const int time_out)
{
	struct sockaddr_un remote;
	struct timeval tv;
	int len, s;

	if (file_path == NULL)
		return -1;

	if (time_out < 0)
		return -1;
	
	// Inter Process Communication
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            	return -1;
      	}
	
	tv.tv_sec = time_out;
	tv.tv_usec = 0;
	if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) < 0)
	{
		if (function_name) {
			syslog(LOG_WARNING, "%s : setsockopt(unix_socket, SO_RCVTIMEO): %m", function_name);
		}
		else {
			syslog(LOG_WARNING, "setsockopt(unix_socket, SO_RCVTIMEO): %m");
		}
	}
	
	remote.sun_family = AF_UNIX;
      	strcpy(remote.sun_path, file_path);
     	//len = strlen(remote.sun_path) + sizeof(remote.sun_family);
     	len = sizeof(struct sockaddr_un);
     	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		close(s);
           	return -1;
     	}
	return s;
}

int UnixSocketSendAndReceive(const char *function_name,
								const char *file_path,
								const int time_out,
								const char *in, char *out, const int out_len)
{
	int s=-1, t, in_len, ret=-1;

	if (file_path == NULL || in == NULL || out == NULL || out_len < 1)
		return -1;
	
	s = CreateUnixSocket(function_name, file_path, time_out);
	if (s == -1) {
		if (function_name)
			syslog(LOG_ERR, "%s : CreateUnixSocket failed", function_name);
		goto finish;
	}

	in_len = strlen(in);
	if (ReliableSend(s, in, in_len) != in_len) {
		if (function_name) {
			syslog(LOG_ERR, "%s : Unix socket send: %m", function_name);
		}
            	goto finish;
     	}
	if ((t = recv(s, out, out_len, 0)) > 0) {
           	out[t] = '\0';
		ret = 0;
	}
	else {
           	if (t < 0) {
			if (function_name) {
				syslog(LOG_ERR, "%s : Unix socket recv: %m", function_name);
			}
           	}
          	else {
			if (function_name) {
				syslog(LOG_WARNING, "%s : Server closed connection: %m", function_name);
			}
          	}
    	}

finish:
	if (s >= 0)
		close(s);
	return ret;
}
#endif
