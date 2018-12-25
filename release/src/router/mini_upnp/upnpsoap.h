#ifndef _UPNPSOAP_H_
#define _UPNPSOAP_H_

/* ExecuteSoapAction() :
 * This method execute the requested Soap Action */
void ExecuteSoapAction(struct upnphttp *, const char *, int);

/* Sends a correct SOAP error with an UPNPError code and 
 * description */
void
SoapError(struct upnphttp * h, int errCode, const char * errDesc);

extern void BuildSendAndCloseSoapResp(struct upnphttp * h, const char * body, int bodylen);

#endif
