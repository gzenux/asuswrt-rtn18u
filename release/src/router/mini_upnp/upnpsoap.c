#ifdef __ECOS
#include <network.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef __ECOS
#include <syslog.h>
#endif
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "upnphttp.h"
#include "upnpsoap.h"

void
BuildSendAndCloseSoapResp(struct upnphttp * h,
                          const char * body, int bodylen)
{
	static const char beforebody[] =
		"<?xml version=\"1.0\"?>\n"
		"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<s:Body>";
	static const char afterbody[] =
		"</s:Body>"
		"</s:Envelope>";

	BuildHeader_upnphttp(h, 200, "OK",  sizeof(beforebody) - 1
	                                  + sizeof(afterbody) - 1
									  + bodylen );
	memcpy(h->res_buf + h->res_buflen, beforebody, sizeof(beforebody) - 1);
	h->res_buflen += sizeof(beforebody) - 1;
	memcpy(h->res_buf + h->res_buflen, body, bodylen);
	h->res_buflen += bodylen;
	memcpy(h->res_buf + h->res_buflen, afterbody, sizeof(afterbody) - 1);
	h->res_buflen += sizeof(afterbody) - 1;
	SendResp_upnphttp(h);
	CloseSocket_upnphttp(h);
}

void ExecuteSoapAction(struct upnphttp * h, const char * action, int n)
{
	char * p;
	int i, len;
	i = 0;

	// support HNAP1
	len = strlen("http://purenetworks.com/HNAP");
	if (strncasecmp((char *)action, "http://purenetworks.com/HNAP", len) == 0) {
		char *pos;	
		pos = (char *)(action + len);
		p = strchr(pos, '/');
		//if (p)
			//printf("action [%s]\n", p+1);
	}
	else
		p = strchr(action, '#');
	if (p)
	{
		p++;
		while(h->soapMethods[i].methodName)
		{
			len = strlen(h->soapMethods[i].methodName);
			if(strncmp(p, h->soapMethods[i].methodName, len) == 0)
			{
				h->soapMethods[i].methodImpl(h);
				return;
			}
			i++;
		}
	}
	syslog(LOG_NOTICE, "Unknown soap method");
	SoapError(h, 401, "Invalid Action");
}

/* Standard errors : 
errorCode  	errorDescription  	Description
401 	Invalid Action 	No action by that name at this service.
402 	Invalid Args 	Could be any of the following: not enough in args, too many in args, no in arg by that name, one or more in args are of the wrong data type.
403 	Out of Sync 	Out of synchronization.
501 	Action Failed 	May be returned in current state of service prevents invoking that action.
600-699 	TBD 	Common action errors. Defined by UPnP Forum Technical Committee.
700-799 	TBD 	Action-specific errors for standard actions. Defined by UPnP Forum working committee.
800-899 	TBD 	Action-specific errors for non-standard actions. Defined by UPnP vendor.
*/
void
SoapError(struct upnphttp * h, int errCode, const char * errDesc)
{
	char *body=NULL;
	int bodylen;
	static const char resp[] = 
		"<s:Envelope "
		"xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<s:Body>"
		"<s:Fault>"
		"<faultcode>s:Client</faultcode>"
		"<faultstring>UPnPError</faultstring>"
		"<detail>"
		"<UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">"
		"<errorCode>%d</errorCode>"
		"<errorDescription>%s</errorDescription>"
		"</UPnPError>"
		"</detail>"
		"</s:Fault>"
		"</s:Body>"
		"</s:Envelope>";

	body = (char *) malloc(2048);
	if (body == NULL) {
		syslog(LOG_ERR, "SoapError: out of memory!");
		return;
	}
	memset(body, 0, 2048);
	
	bodylen = sprintf(body, resp, errCode, errDesc);
	BuildResp2_upnphttp(h, 500, "Internal Server Error", body, bodylen);
	SendResp_upnphttp(h);
	CloseSocket_upnphttp(h);
	free(body);
}


