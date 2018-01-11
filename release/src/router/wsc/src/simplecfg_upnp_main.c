#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "sample_util.h"
#include "upnp.h"
#include "simplecfg_upnp.h"
#include "wsc.h"

#define UpnpDocument_free ixmlDocument_free
#define UpnpParse_Buffer ixmlParseBuffer

typedef IXML_Document *Upnp_Document;

static char *PsimplecfgDeviceType = NULL;
static char *PsimplecfgServiceType = NULL;
static char *PsimplecfgServiceId = NULL;

/* The amount of time before advertisements
   will expire */
static const int default_advr_expire = 1800;

static char *psimplecfg_udn = NULL;
static UpnpDevice_Handle device_handle = -1;

/* Mutex for protecting the global state table data
   in a multi-threaded, asynchronous environment.
   All functions should lock this mutex before reading
   or writing the state table data. */
//pthread_mutex_t PsimplecfgDevMutex = PTHREAD_MUTEX_INITIALIZER;
WSC_pthread_mutex_t PsimplecfgDevMutex;

WSC_FunPtr WSCCallBack = NULL;
char *user_priv_data = NULL;
unsigned char WSCCallBack_registered = 0;
OpMode upnp_op_mode = WSC_AP_MODE;
static unsigned char RootDevRegistered = 0;
OpStatus upnp_op_status = WSC_INITIAL;

static int Astrcmp(char *s1, char *s2)
{
  	int ret;
  
  	if (s1==NULL || s2==NULL)  
    		return(1);
  	else
    	{ 
    		ret=strcmp(s1, s2);
    		return(ret);
    	}
}

static int gen_simplecfg_xml(char *IP, int port, char *docpath, char *outfile, struct WSC_profile *profile)
{
	FILE *fpo;
	char *patho=NULL;
	char *buffo=NULL;
	char uuid[2*UPNP_UUID_LEN+4];

	patho = (char *) malloc(256);
	if (patho == NULL)
		return WSC_UPNP_FAIL;
	buffo = (char *) malloc(256);
	if (buffo == NULL) {
		free(patho);
		return WSC_UPNP_FAIL;
	}
	
	sprintf(patho, "%s%s", docpath, outfile);
	if ((fpo = fopen(patho,"w")) == NULL) {
		free(buffo);
		free(patho);
		DEBUG_ERR("output file can not open\n");
		return WSC_UPNP_FAIL;
	}
	memset(buffo, 0, 256);

	fputs("<?xml version=\"1.0\"?>\n" , fpo);
	fputs("<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n" , fpo);
		fputs("\t<specVersion>\n" , fpo);
			fputs("\t\t<major>1</major>\n" , fpo);
			fputs("\t\t<minor>0</minor>\n" , fpo);
		fputs("\t</specVersion>\n" , fpo);
		sprintf(buffo, "\t<URLBase>http://%s:%u</URLBase>\n", IP, port);
		fputs(buffo, fpo); memset(buffo, 0, 256);
		fputs("\t<device>\n" , fpo);
			fputs("\t\t<deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>\n" , fpo);
			if (profile->device_name == NULL)
				fputs("\t\t<friendlyName>RTL8186 WFA Device</friendlyName>\n", fpo);
			else {
				sprintf(buffo, "\t\t<friendlyName>%s</friendlyName>\n", profile->device_name);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->manufacturer == NULL)
				fputs("\t\t<manufacturer>Realtek Semiconductor</manufacturer>\n", fpo);
			else {
				sprintf(buffo, "\t\t<manufacturer>%s</manufacturer>\n", profile->manufacturer);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->manufacturerURL == NULL)
				fputs("\t\t<manufacturerURL>http://www.realtek.com.tw</manufacturerURL>\n" , fpo);
			else {
				sprintf(buffo, "\t\t<manufacturerURL>%s</manufacturerURL>\n", profile->manufacturerURL);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->modelDescription == NULL)
				fputs("\t\t<modelDescription>Simple Config UPnP Proxy</modelDescription>\n" , fpo);
			else {
				sprintf(buffo, "\t\t<modelDescription>%s</modelDescription>\n", profile->modelDescription);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->model_name == NULL)
				fputs("\t\t<modelName>Simple Config UPnP Proxy Version 1.0</modelName>\n", fpo);
			else {
				sprintf(buffo, "\t\t<modelName>%s</modelName>\n", profile->model_name);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->model_num == NULL)
				fputs("\t\t<modelNumber>RTL8186</modelNumber>\n", fpo);
			else {
				sprintf(buffo, "\t\t<modelNumber>%s</modelNumber>\n", profile->model_num);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->modelURL == NULL)
				fputs("\t\t<modelURL>http://www.realtek.com.tw</modelURL>\n" , fpo);
			else {
				sprintf(buffo, "\t\t<modelURL>%s</modelURL>\n", profile->modelURL);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
			if (profile->serial_num == NULL)
				fputs("\t\t<serialNumber>12345678</serialNumber>\n" , fpo);
			else {
				sprintf(buffo, "\t\t<serialNumber>%s</serialNumber>\n", profile->serial_num);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}

			sprintf(uuid, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				profile->uuid[0],
				profile->uuid[1],profile->uuid[2],profile->uuid[3],profile->uuid[4],profile->uuid[5],
				profile->uuid[6],profile->uuid[7],profile->uuid[8],profile->uuid[9],profile->uuid[10],
				profile->uuid[11],profile->uuid[12],profile->uuid[13],profile->uuid[14],profile->uuid[15]);
			sprintf(buffo, "\t\t<UDN>uuid:%s</UDN>\n", uuid);
			fputs(buffo, fpo); 
			memset(buffo, 0, 256);

			if (profile->UPC == NULL)
				fputs("\t\t<UPC>112233445566</UPC>\n" , fpo); //must be 12 digit
			else {
				sprintf(buffo, "\t\t<UPC>%s</UPC>\n", profile->UPC);
				fputs(buffo, fpo); memset(buffo, 0, 256);
			}
#if 0
			fputs("\t\t<iconList>\n" , fpo);
				fputs("\t\t\t<icon>\n" , fpo);
					fputs("\t\t\t\t<mimetype>image/gif</mimetype>\n" , fpo);
					fputs("\t\t\t\t<width>118</width>\n" , fpo);
					fputs("\t\t\t\t<height>119</height>\n" , fpo);
					fputs("\t\t\t\t<depth>8</depth>\n" , fpo);
					fputs("\t\t\t\t<url>/ligd.gif</url>\n" , fpo);
				fputs("\t\t\t</icon>\n" , fpo);
			fputs("\t\t</iconList>\n" , fpo);
#endif
			fputs("\t\t<serviceList>\n" , fpo);
				fputs("\t\t\t<service>\n" , fpo);
					fputs("\t\t\t\t<serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType>\n" , fpo);
					fputs("\t\t\t\t<serviceId>urn:wifialliance-org:serviceId:WFAWLANConfig1</serviceId>\n" , fpo);
					fputs("\t\t\t\t<SCPDURL>/simplecfgservice.xml</SCPDURL>\n" , fpo);
					fputs("\t\t\t\t<controlURL>/upnp/control/WFAWLANConfig1</controlURL>\n" , fpo);
					fputs("\t\t\t\t<eventSubURL>/upnp/event/WFAWLANConfig1</eventSubURL>\n" , fpo);
				fputs("\t\t\t</service>\n" , fpo);
			fputs("\t\t</serviceList>\n" , fpo);
#if 0
			fputs("\t\t<deviceList>\n" , fpo);
			fputs("\t\t</deviceList>\n" , fpo);
			sprintf(buffo, "\t\t<presentationURL>http://%s/</presentationURL>\n", IP);
			fputs(buffo, fpo);
#endif
		fputs("\t</device>\n" , fpo);
	fputs("</root>\n" , fpo);

	fclose(fpo);
	free(buffo);
	free(patho);
		
	return WSC_UPNP_SUCCESS;
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
static int ILibBase64Encode(unsigned char* input, const int inputlen, unsigned char** output)
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
static int ILibBase64Decode(unsigned char* input, const int inputlen, unsigned char** output)
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

static int SendMsgToSM_Dir_In(struct Upnp_Action_Request *ca_event, 
							WSC_EventID eid,
							char *tag, char *InMsgName)
{
	char *p_NewInMessage=NULL;
	struct WSC_packet *packet=NULL;
	int p_NewInMessageLength=0;
	unsigned char* _NewInMessage=NULL;
	int _NewInMessageLength=0;
	char *IP=NULL;
	
	p_NewInMessage = SampleUtil_GetFirstDocumentItem(ca_event->ActionRequest, InMsgName);
	if (p_NewInMessage == NULL) {
		DEBUG_ERR("%s : No %s!\n", tag, InMsgName);
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	p_NewInMessageLength = strlen(p_NewInMessage);
	_NewInMessageLength = ILibBase64Decode(p_NewInMessage, p_NewInMessageLength,&_NewInMessage);
	if (_NewInMessageLength > MAX_MSG_LEN || _NewInMessageLength <= 0 || _NewInMessage == NULL) {
		DEBUG_ERR("Unreasonable rx length!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}

	packet = (struct WSC_packet *)malloc(sizeof(struct WSC_packet));
	if (packet == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}
	memset(packet, 0, sizeof(struct WSC_packet));
	packet->EventID = eid;
	
	IP = inet_ntoa(ca_event->CtrlPtIPAddr);
	memcpy(packet->IP, IP, strlen(IP));
	packet->IP[strlen(IP)] = '\0';
	_DEBUG_PRINT("Receive Upnp message from IP : %s\n", packet->IP);
	
	packet->rx_size = _NewInMessageLength;
	memcpy(packet->rx_buffer, _NewInMessage, _NewInMessageLength);
#ifdef DEBUG
	wsc_debug_out(tag, packet->rx_buffer, packet->rx_size);
#endif

	if (WSCCallBack(packet, user_priv_data) != WSC_UPNP_SUCCESS) {
		DEBUG_ERR("WSCCallBack Fail!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}

	ca_event->ActionResult = UpnpMakeActionResponse(ca_event->ActionName, PsimplecfgServiceType, 0, NULL);
	ca_event->ErrCode = UPNP_E_SUCCESS;
	
error_handle:
	if (p_NewInMessage)
		free(p_NewInMessage);
	if (_NewInMessage)
		free(_NewInMessage);
	//if (IP)
		//free(IP);
	if (packet)
		free(packet);

       return (ca_event->ErrCode);
}

static int SendMsgToSM_Dir_InOut(struct Upnp_Action_Request *ca_event, 
							WSC_EventID eid,
							char *tag, char *InMsgName, char *OutMsgName)
{
	char *result_str=NULL, *IP=NULL;
	char *body=NULL;
	struct WSC_packet *packet=NULL;
	unsigned char* NewOutMessage_Base64=NULL;
	int NewOutMessage_Base64Length=0, TotalLen=0, body_len=0;
	char *p_NewInMessage=NULL;
	int p_NewInMessageLength=0;
	unsigned char* _NewInMessage=NULL;
	int _NewInMessageLength=0;
	
	p_NewInMessage = SampleUtil_GetFirstDocumentItem(ca_event->ActionRequest, InMsgName);
	if (p_NewInMessage == NULL) {
		DEBUG_ERR("%s : No %s!\n", tag, InMsgName);
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	p_NewInMessageLength = strlen(p_NewInMessage);
	_NewInMessageLength = ILibBase64Decode(p_NewInMessage, p_NewInMessageLength, &_NewInMessage);
	if (_NewInMessageLength > MAX_MSG_LEN || _NewInMessageLength <= 0 || _NewInMessage == NULL) {
		DEBUG_ERR("Unreasonable rx length!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}
	
	packet = (struct WSC_packet *)malloc(sizeof(struct WSC_packet));
	if (packet == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}	
	memset(packet, 0, sizeof(struct WSC_packet));

	packet->EventID = eid;
	
	IP = inet_ntoa(ca_event->CtrlPtIPAddr);
	memcpy(packet->IP, IP, strlen(IP));
	packet->IP[strlen(IP)] = '\0';
	_DEBUG_PRINT("Receive Upnp message from IP : %s\n", packet->IP);
	
	packet->rx_size = _NewInMessageLength;
	memcpy(packet->rx_buffer, _NewInMessage, _NewInMessageLength);
#ifdef DEBUG
	wsc_debug_out(tag, packet->rx_buffer, packet->rx_size);
#endif
	
	if (WSCCallBack(packet, user_priv_data) != WSC_UPNP_SUCCESS) {
		DEBUG_ERR("WSCCallBack Fail!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}

	if ((packet->tx_size > MAX_MSG_LEN) || (packet->tx_size < 0)) {
		DEBUG_ERR("Unreasonable tx length!\n");
		ca_event->ErrCode = UPNP_E_INTERNAL_ERROR;
		goto error_handle;
	}
	
#ifdef DEBUG
	wsc_debug_out(tag, packet->tx_buffer, packet->tx_size);
#endif
	NewOutMessage_Base64Length = ILibBase64Encode(packet->tx_buffer, packet->tx_size, &NewOutMessage_Base64);
	body_len = 2*strlen(OutMsgName) + 5 + NewOutMessage_Base64Length;
	body = (char *)malloc(body_len);
	if (body == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}

	if (NewOutMessage_Base64)
		sprintf(body,"<%s>%s</%s>", OutMsgName, NewOutMessage_Base64, OutMsgName);
	else
		sprintf(body,"<%s></%s>", OutMsgName, OutMsgName);

	TotalLen = strlen("<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>") +
		strlen("urn:schemas-wifialliance-org:WFAWLANConfig:1") +
		2 * strlen(ca_event->ActionName) + (body_len);
	result_str = (char *)malloc(TotalLen);
	if (result_str == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}
      	 sprintf(result_str, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>", ca_event->ActionName,
                "urn:schemas-wifialliance-org:WFAWLANConfig:1",
                body,
      	          ca_event->ActionName);

	ca_event->ActionResult = UpnpParse_Buffer(result_str);
		ca_event->ErrCode = UPNP_E_SUCCESS;
	
error_handle:
	if (body)
		free(body);
	if (NewOutMessage_Base64)
		free(NewOutMessage_Base64);
	if (result_str)
		free(result_str);
	if (p_NewInMessage)
		free(p_NewInMessage);
	if (_NewInMessage)
		free(_NewInMessage);
	//if (IP)
		//free(IP);
	if (packet)
		free(packet);

       return (ca_event->ErrCode);
}

static int WFAGetDeviceInfo(struct Upnp_Action_Request *ca_event)
{
	char *result_str=NULL;
	struct WSC_packet *packet=NULL;
	char *body=NULL;
	unsigned char *NewDeviceInfo_Base64=NULL;
	int NewDeviceInfo_Base64Length=0, TotalLen=0;
	char *IP=NULL;

	if (upnp_op_status == WSC_LOCKED) {
		_DEBUG_PRINT("Status : locked\n");
		ca_event->ErrCode = UPNP_E_INTERNAL_ERROR;
		return (ca_event->ErrCode);
	}
	
	packet = (struct WSC_packet *)malloc(sizeof(struct WSC_packet));
	if (packet == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}	
	memset(packet, 0, sizeof(struct WSC_packet));
	packet->EventType = WSC_NOT_PROXY;
	packet->EventID = WSC_GETDEVINFO;
	IP = inet_ntoa(ca_event->CtrlPtIPAddr);
	memcpy(packet->IP, IP, strlen(IP));
	packet->IP[strlen(IP)] = '\0';

	_DEBUG_PRINT("WFAGetDeviceInfo\n");
	if (WSCCallBack(packet, user_priv_data) != WSC_UPNP_SUCCESS) {
		DEBUG_ERR("WSCCallBack Fail!\n");
		ca_event->ErrCode = UPNP_E_INTERNAL_ERROR;
		goto error_handle;
	}

	if ((packet->tx_size > MAX_MSG_LEN) || (packet->tx_size <= 0)) {
		DEBUG_ERR("Unreasonable tx length!\n");
		ca_event->ErrCode = UPNP_E_INTERNAL_ERROR;
		goto error_handle;
	}
	
#ifdef DEBUG
	wsc_debug_out("M1", packet->tx_buffer, packet->tx_size);
#endif
	NewDeviceInfo_Base64Length = ILibBase64Encode(packet->tx_buffer, packet->tx_size, &NewDeviceInfo_Base64);
	body = (char *)malloc(32 + NewDeviceInfo_Base64Length);
	if (body == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}
	sprintf(body,"<NewDeviceInfo>%s</NewDeviceInfo>", NewDeviceInfo_Base64);

	TotalLen = strlen("<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>") +
		strlen("urn:schemas-wifialliance-org:WFAWLANConfig:1") +
		2 * strlen(ca_event->ActionName) + (32 + NewDeviceInfo_Base64Length);
	result_str = (char *)malloc(TotalLen);
	if (result_str == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}
      	sprintf(result_str, "<u:%sResponse xmlns:u=\"%s\">\n%s\n</u:%sResponse>", ca_event->ActionName,
               "urn:schemas-wifialliance-org:WFAWLANConfig:1",
                body,
                ca_event->ActionName);
	   
	ca_event->ActionResult = UpnpParse_Buffer(result_str);
	ca_event->ErrCode = UPNP_E_SUCCESS;
	
error_handle:
	if (packet)
		free(packet);
	if (body)
		free(body);
	if (NewDeviceInfo_Base64)
		free(NewDeviceInfo_Base64);
	if (result_str)
		free(result_str);
	//if (IP)
		//free(IP);
	
       return (ca_event->ErrCode);
}

static int WFAPutMessage(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_status == WSC_LOCKED) {
		_DEBUG_PRINT("Status : locked\n");
		ca_event->ErrCode = UPNP_E_INTERNAL_ERROR;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_InOut(ca_event, 
					WSC_M2M4M6M8, "PutMessage", "NewInMessage", "NewOutMessage");
}

static int WFAPutWLANResponse(struct Upnp_Action_Request *ca_event)
{
	char *IP=NULL;
	struct WSC_packet *packet=NULL;
	char *p_NewInMessage=NULL;
	int p_NewInMessageLength=0;
	unsigned char* _NewInMessage=NULL;
	int _NewInMessageLength=0;
	unsigned char EType=0;

	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	
	p_NewInMessage = SampleUtil_GetFirstDocumentItem(ca_event->ActionRequest, "NewMessage");
	if (p_NewInMessage == NULL) {
		DEBUG_ERR("No NewMessage!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}
	
	p_NewInMessageLength = strlen(p_NewInMessage);
	_NewInMessageLength = ILibBase64Decode(p_NewInMessage, p_NewInMessageLength,&_NewInMessage);
	if (_NewInMessageLength > MAX_MSG_LEN || _NewInMessageLength <= 0 || _NewInMessage == NULL) {
		DEBUG_ERR("Unreasonable rx length!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}

	packet = (struct WSC_packet *)malloc(sizeof(struct WSC_packet));
	if (packet == NULL) {
		DEBUG_ERR("Not enough memory!\n");
		ca_event->ErrCode = UPNP_E_OUTOF_MEMORY;
		goto error_handle;
	}
	memset(packet, 0, sizeof(struct WSC_packet));
	
	memcpy(packet->rx_buffer, _NewInMessage, _NewInMessageLength);
	packet->rx_size = _NewInMessageLength;

	if (p_NewInMessage)
		free(p_NewInMessage);
	p_NewInMessage = SampleUtil_GetFirstDocumentItem(ca_event->ActionRequest, "NewWLANEventType");
	if (p_NewInMessage != NULL)
		EType = atoi(p_NewInMessage);
	
	if (EType == WSC_8021XEAP_FRAME) {
#ifdef DEBUG
		wsc_debug_out("WFAPutWLANResponse : forward message to enrollee", packet->rx_buffer, packet->rx_size);
#endif
		packet->EventType = WSC_8021XEAP_FRAME;
	}
	else {
		DEBUG_ERR("Unknown event type!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}

	if (p_NewInMessage)
		free(p_NewInMessage);
	p_NewInMessage = SampleUtil_GetFirstDocumentItem(ca_event->ActionRequest, "NewWLANEventMAC");
	if (p_NewInMessage == NULL) {
		DEBUG_ERR("No NewWLANEventMAC!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}
	memcpy(packet->EventMac, p_NewInMessage, MACLEN);
	_DEBUG_PRINT("EventMac : %s\n", packet->EventMac);

	packet->EventID = WSC_PUTWLANRESPONSE;
	IP = inet_ntoa(ca_event->CtrlPtIPAddr);
	memcpy(packet->IP, IP, strlen(IP));
	packet->IP[strlen(IP)] = '\0';
	
	if (WSCCallBack(packet, user_priv_data) != WSC_UPNP_SUCCESS) {
		DEBUG_ERR("WSCCallBack Fail!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		goto error_handle;
	}

	ca_event->ActionResult = UpnpMakeActionResponse(
		ca_event->ActionName, PsimplecfgServiceType, 0,
		NULL);
	ca_event->ErrCode = UPNP_E_SUCCESS;
	
	
error_handle:
	if (packet)
		free(packet);
	if (p_NewInMessage)
		free(p_NewInMessage);
	if (_NewInMessage)
		free(_NewInMessage);
	//if (IP)
		//free(IP);

       return (ca_event->ErrCode);
}

static int WFATxmitWLANEventToRegistra(struct WSC_packet *packet)
{
    	Upnp_Document PropSet=NULL;
	int ret=WSC_UPNP_FAIL, err_code=0;
	unsigned char *WLANEvent=NULL;
	unsigned char *WLANEvent_Base64=NULL;
	int WLANEvent_Base64Length=0;
	unsigned int TotalLen=0;
	
	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		goto error_handle;
	}
	
	if (packet == NULL) {
		DEBUG_ERR("No message for WFATxmitWLANEventToRegistra!\n");
		goto error_handle;
	}
	else {
		if ((packet->tx_size > MAX_MSG_LEN) || (packet->tx_size <= 0)) {
			DEBUG_ERR("Unreasonable tx length!\n");
			goto error_handle;
		}
		else
			TotalLen += packet->tx_size;

		if ((packet->EventType == WSC_PROBE_FRAME) || (packet->EventType == WSC_8021XEAP_FRAME))
			TotalLen++;
		else {
			DEBUG_ERR("Unknown event type!\n");
			goto error_handle;
		}

		TotalLen += MACLEN; // Length of Mac address
		WLANEvent = (unsigned char *)malloc(TotalLen);
		if (WLANEvent == NULL) {
			DEBUG_ERR("Not enough memory!\n");
			goto error_handle;
		}

		WLANEvent[0] = packet->EventType;
		sprintf(WLANEvent+1, packet->EventMac);
		memcpy(WLANEvent+18, packet->tx_buffer, packet->tx_size);
#ifdef DEBUG
		if (WLANEvent[0] != WSC_PROBE_FRAME) {
			_DEBUG_PRINT("WLANEventType = %d\n", WLANEvent[0]);
			_DEBUG_PRINT("WLANEventMac = %s\n", packet->EventMac);
			wsc_debug_out("Forward WLANEvent to registra", WLANEvent+18, packet->tx_size);
		}
#endif
		WLANEvent_Base64Length = ILibBase64Encode(WLANEvent, TotalLen, &WLANEvent_Base64);
		if (WLANEvent_Base64 == NULL || WLANEvent_Base64Length <= 0) {
			DEBUG_ERR("ILibBase64Encode failed!\n");
			goto error_handle;
		}
		else {
			err_code = UpnpAddToPropertySet(&PropSet, "WLANEvent", WLANEvent_Base64);
			if (err_code != UPNP_E_SUCCESS) {
				DEBUG_ERR("Error code %d : UpnpAddToPropertySet failed!\n", err_code);
				goto error_handle;
			}

			err_code = UpnpNotifyExt(device_handle, psimplecfg_udn, PsimplecfgServiceId, PropSet);
			if (err_code != UPNP_E_SUCCESS) {
				DEBUG_ERR("Error code %d : UpnpNotifyExt failed!\n", err_code);
				goto error_handle;
			}
			else{
				ret = WSC_UPNP_SUCCESS;
			}
		}
	}

error_handle:
	
	if (PropSet)
		UpnpDocument_free(PropSet);
	if (WLANEvent)
		free(WLANEvent);
	if (WLANEvent_Base64)
		free(WLANEvent_Base64);

    	return ret;
}

static int WFATxmitStatus(struct WSC_packet *packet)
{
	int ret=WSC_UPNP_FAIL, err_code=0;
	Upnp_Document PropSet=NULL;
	char *pstatus=NULL;
	int status=0;

	if (packet == NULL) {
		DEBUG_ERR("No message for WFATxmitStatus!\n");
		goto error_handle;
	}
	else {
		if ((packet->tx_size > MAX_MSG_LEN) || (packet->tx_size <= 0)) {
			DEBUG_ERR("Unreasonable tx length!\n");
			goto error_handle;
		}

		pstatus = (char *)malloc(packet->tx_size);
		if (pstatus == NULL) {
			DEBUG_ERR("Not enough memory!\n");
			goto error_handle;
		}
		memcpy(pstatus, packet->tx_buffer, packet->tx_size);
		status = atoi(pstatus);
	}

	switch (packet->EventID)
	{
		case WSC_AP_STATUS:
			if (upnp_op_mode != WSC_AP_MODE) {
				DEBUG_ERR("Not AP mode!\n");
				goto error_handle;
			}
			else {
				if (status == WSC_CONFIG_CHANGE)
					UpnpAddToPropertySet(&PropSet, "APStatus", "1");
				else if (status == WSC_LOCKED)
					UpnpAddToPropertySet(&PropSet, "APStatus", "2");
				else {
					DEBUG_ERR("Unknown status!\n");
					goto error_handle;
				}
			}
			break;
		case WSC_STA_STATUS:
			if (upnp_op_mode != WSC_STA_MODE) {
				DEBUG_ERR("Not STA mode!\n");
				goto error_handle;
			}
			else {
				if (status == WSC_CONFIG_CHANGE)
					UpnpAddToPropertySet(&PropSet, "STAStatus", "1");
				else if (status == WSC_LOCKED)
					UpnpAddToPropertySet(&PropSet, "STAStatus", "2");
				else {
					DEBUG_ERR("Unknown status!\n");
					goto error_handle;
				}
			}
			break;
		default:
			_DEBUG_PRINT("Unknown EventID in WFATxmitStatus!\n");
			goto error_handle;
	}

	err_code = UpnpNotifyExt(device_handle, psimplecfg_udn, PsimplecfgServiceId, PropSet);
	if (err_code != UPNP_E_SUCCESS) {
		DEBUG_ERR("Error code %d : Sending Status to registra failed!\n", err_code);
		goto error_handle;
	}
	else {
		upnp_op_status = status;
		ret = WSC_UPNP_SUCCESS;
	}

error_handle:
	
	if (PropSet)
		UpnpDocument_free(PropSet);

	if (pstatus)
		free(pstatus);
	
	return ret;
}

int WSCUpnpTxmit(struct WSC_packet *packet)
{
	switch (packet->EventID)
	{
		case WSC_PUTWLANREQUEST:
			return (WFATxmitWLANEventToRegistra(packet));
		case WSC_AP_STATUS:
		case WSC_STA_STATUS:
			return (WFATxmitStatus(packet));

		default:
			_DEBUG_PRINT("Unknown EventID in WSCUpnpTxmit!\n");
			return WSC_UPNP_FAIL;
	}
}

static int WFAGetAPSettings(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_InOut(ca_event, 
					WSC_GETAPSETTINGS, "GetAPSettings", "NewMessage", "NewAPSettings");
}

static int WFASetAPSettings(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	return
		SendMsgToSM_Dir_In(ca_event, 
					WSC_SETAPSETTINGS, "SetAPSettings", "APSettings");
}

static int WFADelAPSettings(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_In(ca_event, 
					WSC_DELAPSETTINGS, "DelAPSettings", "NewAPSettings");
}

static int WFARebootAP(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_In(ca_event, 
					WSC_REBOOTAP, "RebootAP", "NewAPSettings");
}

static int WFAResetAP(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_AP_MODE) {
		DEBUG_ERR("Not AP mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	return
		SendMsgToSM_Dir_In(ca_event, WSC_RESETAP, "ResetAP", "NewMessage");
}

static int WFAGetSTASettings(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_STA_MODE) {
		DEBUG_ERR("Not STA mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_InOut(ca_event, 
					WSC_GETSTASETTINGS, "GetSTASettings", "NewMessage", "NewSTASettings");
}

static int WFASetSTASettings(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_STA_MODE) {
		DEBUG_ERR("Not STA mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_In(ca_event, 
					WSC_SETSTASETTINGS, "SetSTASettings", "NewSTASettings");
}

static int WFADelSTASettings(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_STA_MODE) {
		DEBUG_ERR("Not STA mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_In(ca_event, 
					WSC_DELSTASETTINGS, "DelSTASettings", "NewSTASettings");
}

static int WFARebootSTA(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_STA_MODE) {
		DEBUG_ERR("Not STA mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_In(ca_event, 
					WSC_REBOOTSTA, "RebootSTA", "NewSTASettings");
}

static int WFAResetSTA(struct Upnp_Action_Request *ca_event)
{
	if (upnp_op_mode != WSC_STA_MODE) {
		DEBUG_ERR("Not STA mode!\n");
		ca_event->ErrCode = UPNP_E_INVALID_PARAM;
		return (ca_event->ErrCode);
	}
	else
		return SendMsgToSM_Dir_In(ca_event, 
					WSC_RESETSTA, "ResetSTA", "NewMessage");
}

static int WFASetSelectedRegistrar(struct Upnp_Action_Request *ca_event)
{
	return SendMsgToSM_Dir_In(ca_event, 
					WSC_SETSELECTEDREGISTRA, "SetSelectedRegistrar", "NewMessage");
}

/********************************************************************************
 * PsimplecfgDeviceHandleActionRequest
 *
 * Description: 
 *       Called during an action request callback.  If the
 *       request is for this device and either its control service
 *       or picture service, then perform the action and respond.
 *
 * Parameters:
 *   ca_event -- The control action request event structure
 *
 ********************************************************************************/
static int PsimplecfgDeviceHandleActionRequest(struct Upnp_Action_Request *ca_event) 
{
    	/* Defaults if action not found */
    	int result=UPNP_E_INVALID_PARAM;

	if (Astrcmp(ca_event->DevUDN, psimplecfg_udn) == 0) {
		if (Astrcmp(ca_event->ServiceID, PsimplecfgServiceId) == 0) {
			if (Astrcmp(ca_event->ActionName,"GetDeviceInfo") == 0)
				result = WFAGetDeviceInfo(ca_event);
			else if (Astrcmp(ca_event->ActionName,"PutMessage") == 0)
				result = WFAPutMessage(ca_event);
			else if (Astrcmp(ca_event->ActionName,"PutWLANResponse") == 0)
				result = WFAPutWLANResponse(ca_event);
			else if (Astrcmp(ca_event->ActionName,"SetSelectedRegistrar") == 0)
				result = WFASetSelectedRegistrar(ca_event);
			else if (Astrcmp(ca_event->ActionName,"GetAPSettings") == 0)
				result = WFAGetAPSettings(ca_event);
			else if (Astrcmp(ca_event->ActionName,"SetAPSettings") == 0)
				result = WFASetAPSettings(ca_event);
			else if (Astrcmp(ca_event->ActionName,"DelAPSettings") == 0)
				result = WFADelAPSettings(ca_event);
			else if (Astrcmp(ca_event->ActionName,"RebootAP") == 0)
				result = WFARebootAP(ca_event);
			else if (Astrcmp(ca_event->ActionName,"ResetAP") == 0)
				result = WFAResetAP(ca_event);
			else if (Astrcmp(ca_event->ActionName,"GetSTASettings") == 0)
				result = WFAGetSTASettings(ca_event);
			else if (Astrcmp(ca_event->ActionName,"SetSTASettings") == 0)
				result = WFASetSTASettings(ca_event);
			else if (Astrcmp(ca_event->ActionName,"DelSTASettings") == 0)
				result = WFADelSTASettings(ca_event);
			else if (Astrcmp(ca_event->ActionName,"RebootSTA") == 0)
				result = WFARebootSTA(ca_event);
			else if (Astrcmp(ca_event->ActionName,"ResetSTA") == 0)
				result = WFAResetSTA(ca_event);
			else
				DEBUG_ERR("   Unknown ActionName = %s\n", ca_event->ActionName);
		}
		else
			DEBUG_ERR("   Unknown ServiceId = %s\n", ca_event->ServiceID);
	}
	else {
		DEBUG_ERR("Error in UPNP_CONTROL_ACTION_REQUEST callback:\n");
		DEBUG_ERR("   Unknown UDN = %s\n", ca_event->DevUDN);
    	}
	
      	ca_event->ErrCode = result;

    	return(ca_event->ErrCode);
}

static struct subscription_info *search_sid_entry(CTX_Tp pCtx, char *Sid)
{
	int i, idx=-1;

	for (i=0; i<MAX_SUBSCRIPTION_NUM; i++) {
		if (pCtx->upnp_subscription_info[i].used == 0) {
			if (idx < 0)
				idx = i;
			continue;
		}
		if (Astrcmp(pCtx->upnp_subscription_info[i].Sid, Sid) == 0)
			break;
	}

	if ( i < MAX_SUBSCRIPTION_NUM)
		return (&pCtx->upnp_subscription_info[i]);

	if (idx >= 0)
		return (&pCtx->upnp_subscription_info[idx]);

	return NULL;
}

/********************************************************************************
 * PsimplecfgDeviceHandleSubscriptionRequest
 *
 * Description: 
 *       Called during a subscription request callback.  If the
 *       subscription request is for this device and either its
 *       control service or picture service, then accept it.
 *
 * Parameters:
 *   sr_event -- The subscription request event structure
 *
 ********************************************************************************/
static int PsimplecfgDeviceHandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event) 
{
    	Upnp_Document PropSet=NULL;
	unsigned char WLANEvent[21];
	unsigned char *WLANEvent_Base64=NULL;
	int WLANEvent_Base64Length=0;
	struct subscription_info *subscription=NULL;
	CTX_Tp pCtx = (CTX_Tp)user_priv_data;

    	WSC_pthread_mutex_lock(&PsimplecfgDevMutex);
	if (Astrcmp(sr_event->UDN, psimplecfg_udn) == 0) {
		if (Astrcmp(sr_event->ServiceId, PsimplecfgServiceId) == 0) {
			subscription = search_sid_entry(pCtx, sr_event->Sid);
			if (subscription == NULL) {
				WSC_pthread_mutex_unlock(&PsimplecfgDevMutex);
				DEBUG_ERR("SID table full\n");
				return UPNP_E_OUTOF_MEMORY;
			}
			if (!subscription->used) {
				subscription->used = 1;
				pCtx->TotalSubscriptions++;
				memcpy(subscription->Sid, sr_event->Sid, UPNP_SID_LEN);
				subscription->subscription_timeout = UPNP_EXTERNAL_REG_EXPIRED;
			}
			_DEBUG_PRINT("Total subscription is %d\n", pCtx->TotalSubscriptions);
			
			if (upnp_op_mode == WSC_STA_MODE)
				UpnpAddToPropertySet(&PropSet, "STAStatus", "1");
			else {
				WLANEvent[0] = WSC_8021XEAP_FRAME;
				sprintf(WLANEvent+1, "00:01:02:03:04:05");
				memcpy(WLANEvent+18, "123", 3);
				WLANEvent_Base64Length = ILibBase64Encode(WLANEvent, 21, &WLANEvent_Base64);
				
				UpnpAddToPropertySet(&PropSet, "APStatus", "1");
				UpnpAddToPropertySet(&PropSet, "WLANEvent", WLANEvent_Base64);
			}
            		UpnpAcceptSubscriptionExt(device_handle, sr_event->UDN, sr_event->ServiceId, PropSet, sr_event->Sid);
			//_DEBUG_PRINT("sr_event->UDN = %s\n", sr_event->UDN);
			//_DEBUG_PRINT("sr_event->ServiceId = %s\n", sr_event->ServiceId);
			_DEBUG_PRINT("sr_event->Sid = %s\n\n", sr_event->Sid);
            		UpnpDocument_free(PropSet);
		}
		else
			DEBUG_ERR("   Unknown ServiceId = %s\n", sr_event->ServiceId);
    	}
	else {
		DEBUG_ERR("Error in UPNP_EVENT_SUBSCRIPTION_REQUEST:\n");
		DEBUG_ERR("   Unknown UDN = %s\n", sr_event->UDN);
    	}
    	WSC_pthread_mutex_unlock(&PsimplecfgDevMutex);	

	if (WLANEvent_Base64)
		free(WLANEvent_Base64);
    	return 1;
}

/********************************************************************************
 * PsimplecfgDeviceHandleRenewalSubscriptionRequest
 *
 * Description: 
 *       Called during a renewal subscription request callback.  If the
 *       renewal subscription request is for this device and either its
 *       control service or picture service, then accept it.
 *
 * Parameters:
 *   sr_event -- The renewal subscription request event structure
 *
 ********************************************************************************/
static int PsimplecfgDeviceHandleRenewalSubscriptionRequest(struct Upnp_Subscription_Request *sr_event) 
{
	int ret, reset=0;
	CTX_Tp pCtx = (CTX_Tp)user_priv_data;
	struct subscription_info *subscription=NULL;
	
    	WSC_pthread_mutex_lock(&PsimplecfgDevMutex);
	if (Astrcmp(sr_event->UDN, psimplecfg_udn) == 0) {
		if (Astrcmp(sr_event->ServiceId, PsimplecfgServiceId) == 0) {
			//_DEBUG_PRINT("sr_event->UDN = %s\n", sr_event->UDN);
			//_DEBUG_PRINT("sr_event->ServiceId = %s\n", sr_event->ServiceId);
			_DEBUG_PRINT("sr_event->Sid = %s\n\n", sr_event->Sid);
			subscription = search_sid_entry(pCtx, sr_event->Sid);
			if (subscription) {
				if (!subscription->used) {
					if (pCtx->setSelectedRegTimeout == 0)
						reset = 1;
				}
				else
					subscription->subscription_timeout = UPNP_EXTERNAL_REG_EXPIRED;
			}
			else {
				WSC_pthread_mutex_unlock(&PsimplecfgDevMutex);	
				DEBUG_ERR("Error : Sid table full or renewal subscription expired!\n");
			    	return UPNP_E_INVALID_PARAM;
			}
			
			if (reset) { //deal with Vista's bug
				memset(pCtx->upnp_subscription_info, 0, (MAX_SUBSCRIPTION_NUM * sizeof(struct subscription_info)));
				pCtx->TotalSubscriptions = 0;
			
				// sends bye bye to clean up receiver's state table
				if ((ret = Upnp_WSC_AdvertiseAndReply( -1, device_handle, 0, ( struct sockaddr_in * )NULL,
                                ( char * )NULL, ( char * )NULL,
                                ( char * )NULL, 1)) != UPNP_E_SUCCESS) {
					DEBUG_ERR("Error with AdvertiseAndReply bye bye -- %d\n", ret);
				}
				_DEBUG_PRINT("Sending bye bye...\n");
				
				if ((ret = Upnp_WSC_AdvertiseAndReply( 1, device_handle, 0, ( struct sockaddr_in * )NULL,
                                ( char * )NULL, ( char * )NULL,
                                ( char * )NULL, default_advr_expire )) != UPNP_E_SUCCESS) {
					DEBUG_ERR("Error with AdvertiseAndReply -- %d\n", ret);
				}
				_DEBUG_PRINT("Sending Advertisement...\n\n");
			}
		}
		else
			DEBUG_ERR("   Unknown ServiceId = %s\n", sr_event->ServiceId);
    	}
	else {
		DEBUG_ERR("Error in UPNP_EVENT_RENEWAL_COMPLETE:\n");
		DEBUG_ERR("   Unknown UDN = %s\n", sr_event->UDN);
    	}
    	WSC_pthread_mutex_unlock(&PsimplecfgDevMutex);	

    	return 1;
}

/********************************************************************************
 * PsimplecfgDeviceHandleUnSubscribeRequest
 *
 * Description: 
 *       Called during an unsubscription request callback.  If the
 *       unsubscription request is for this device and either its
 *       control service or picture service, then accept it.
 *
 * Parameters:
 *   sr_event -- The unsubscription request event structure
 *
 ********************************************************************************/
static int PsimplecfgDeviceHandleUnSubscribeRequest(struct Upnp_Subscription_Request *sr_event) 
{
	CTX_Tp pCtx = (CTX_Tp)user_priv_data;
	struct subscription_info *subscription=NULL;
	
    	WSC_pthread_mutex_lock(&PsimplecfgDevMutex);
	if (Astrcmp(sr_event->UDN, psimplecfg_udn) == 0) {
		if (Astrcmp(sr_event->ServiceId, PsimplecfgServiceId) == 0) {
			//_DEBUG_PRINT("sr_event->UDN = %s\n", sr_event->UDN);
			//_DEBUG_PRINT("sr_event->ServiceId = %s\n", sr_event->ServiceId);
			_DEBUG_PRINT("sr_event->Sid = %s\n\n", sr_event->Sid);

			subscription = search_sid_entry(pCtx, sr_event->Sid);
			if (subscription) {
				if (subscription->used) {
					_DEBUG_PRINT("Remove Sid [%s]\n", subscription->Sid);
					memset(subscription, 0, sizeof(struct subscription_info));
					pCtx->TotalSubscriptions--;
					_DEBUG_PRINT("Total subscription is %d\n", pCtx->TotalSubscriptions);
				}
			}
			else {
				WSC_pthread_mutex_unlock(&PsimplecfgDevMutex);	
				DEBUG_ERR("Error : Sid table full or invalid unsubscription!\n");
			    	return UPNP_E_INVALID_PARAM;
			}
		}
		else
			DEBUG_ERR("   Unknown ServiceId = %s\n", sr_event->ServiceId);
    	}
	else {
		DEBUG_ERR("Error in UPNP_EVENT_UNSUBSCRIBE_COMPLETE:\n");
		DEBUG_ERR("   Unknown UDN = %s\n", sr_event->UDN);
    	}
    	WSC_pthread_mutex_unlock(&PsimplecfgDevMutex);	

    	return 1;
}

/********************************************************************************
 * PsimplecfgDeviceCallbackEventHandler
 *
 * Description:
 *       The callback handler registered with the SDK while registering
 *       root device or sending a search request.  Detects the type of
 *       callback, and passes the request on to the appropriate procedure.
 *
 * Parameters:
 *   EventType -- The type of callback event
 *   Event -- Data structure containing event data
 *   Cookie -- Optional data specified during callback registration
 *
 ********************************************************************************/
static int PsimplecfgDeviceCallbackEventHandler(Upnp_EventType EventType,
			 void *Event,
			 void *Cookie)
{  
	switch ( EventType) {
		case UPNP_EVENT_SUBSCRIPTION_REQUEST:
			_DEBUG_PRINT("UPNP_EVENT_SUBSCRIPTION_REQUEST\n");
			PsimplecfgDeviceHandleSubscriptionRequest((struct Upnp_Subscription_Request *) Event);
			break;

		case UPNP_CONTROL_GET_VAR_REQUEST:
			_DEBUG_PRINT("UPNP_CONTROL_GET_VAR_REQUEST\n");
			break;

		case UPNP_CONTROL_ACTION_REQUEST:
			_DEBUG_PRINT("UPNP_CONTROL_ACTION_REQUEST\n");
			PsimplecfgDeviceHandleActionRequest((struct Upnp_Action_Request *) Event);
			break;

		case UPNP_EVENT_RENEWAL_COMPLETE:
			_DEBUG_PRINT("UPNP_EVENT_RENEWAL_COMPLETE\n");
			PsimplecfgDeviceHandleRenewalSubscriptionRequest((struct Upnp_Subscription_Request *) Event);
			break;

		case UPNP_EVENT_UNSUBSCRIBE_COMPLETE:
			_DEBUG_PRINT("UPNP_EVENT_UNSUBSCRIBE_COMPLETE\n");
			PsimplecfgDeviceHandleUnSubscribeRequest((struct Upnp_Subscription_Request *) Event);
			break;

		/* ignore these cases, since this is not a control point */
	    	case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
			_DEBUG_PRINT("UPNP_DISCOVERY_ADVERTISEMENT_ALIVE\n");
			break;

	    	case UPNP_DISCOVERY_SEARCH_RESULT:
			_DEBUG_PRINT("UPNP_DISCOVERY_SEARCH_RESULT\n");
			break;

	    	case UPNP_DISCOVERY_SEARCH_TIMEOUT:
			_DEBUG_PRINT("UPNP_DISCOVERY_SEARCH_TIMEOUT\n");
			break;

	    	case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
			_DEBUG_PRINT("UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE\n");
			break;

	    	case UPNP_CONTROL_ACTION_COMPLETE:
			_DEBUG_PRINT("UPNP_CONTROL_ACTION_COMPLETE\n");
			break;

    		case UPNP_CONTROL_GET_VAR_COMPLETE:
			_DEBUG_PRINT("UPNP_CONTROL_GET_VAR_COMPLETE\n");
			break;

    		case UPNP_EVENT_RECEIVED:
			_DEBUG_PRINT("UPNP_EVENT_RECEIVED\n");
			break;

    		case UPNP_EVENT_SUBSCRIBE_COMPLETE:
			_DEBUG_PRINT("UPNP_EVENT_SUBSCRIBE_COMPLETE\n");
			break;
	    
    		default:
	    		_DEBUG_PRINT("Error in PsimplecfgDeviceCallbackEventHandler: unknown event type %d\n", EventType);
    }

    return(0);
}

/********************************************************************************
 * PsimplecfgDeviceStateTableInit
 *
 * Description: 
 *       Initialize the device state table for 
 * 	   this WFADevice, pulling identifier info
 *       from the description Document.  Note that 
 *       knowledge of the service description is
 *       assumed.  State table variables and default
 *       values are currently hard coded in this file
 *       rather than being read from service description
 *       documents.
 *
 * Parameters:
 *   DescDocURL -- The description document URL
 *
 ********************************************************************************/
static int PsimplecfgDeviceStateTableInit(char* DescDocURL) 
{
    	Upnp_Document DescDoc=NULL;
    	int ret = UPNP_E_SUCCESS;
	char *evnturl_ctrl = NULL, *ctrlurl_ctrl = NULL;
	
    	if (UpnpDownloadXmlDoc(DescDocURL, &DescDoc) != UPNP_E_SUCCESS) {
		DEBUG_ERR("PsimplecfgDeviceStateTableInit -- Error Parsing %s\n", DescDocURL);
		ret = UPNP_E_INVALID_DESC;
    	}

	PsimplecfgDeviceType = SampleUtil_GetFirstDocumentItem(DescDoc, "deviceType");
	PsimplecfgServiceType = SampleUtil_GetFirstDocumentItem(DescDoc, "serviceType");
	PsimplecfgServiceId = SampleUtil_GetFirstDocumentItem(DescDoc, "serviceId");
    	psimplecfg_udn = SampleUtil_GetFirstDocumentItem(DescDoc, "UDN");

	if( !SampleUtil_FindAndParseService( DescDoc, DescDocURL,
                                         PsimplecfgServiceType,
                                         &PsimplecfgServiceId, &evnturl_ctrl,
                                         &ctrlurl_ctrl ) ) {
        	DEBUG_ERR( "PsimplecfgDeviceStateTableInit -- Error: Could not find"
                          " Service: %s\n",
                          PsimplecfgServiceType);

        	ret = UPNP_E_INVALID_DESC;
    	}

	_DEBUG_PRINT("\tPsimplecfgDeviceType = %s\n", PsimplecfgDeviceType);
	_DEBUG_PRINT("\tPsimplecfgServiceType = %s\n", PsimplecfgServiceType);
	_DEBUG_PRINT("\tPsimplecfgServiceId = %s\n", PsimplecfgServiceId);
	_DEBUG_PRINT("\tpsimplecfg_udn = %s\n", psimplecfg_udn);
	_DEBUG_PRINT("\tevnturl_ctrl = %s\n", evnturl_ctrl);
	_DEBUG_PRINT("\tctrlurl_ctrl = %s\n", ctrlurl_ctrl);

	if (evnturl_ctrl)
		free(evnturl_ctrl);
	if (ctrlurl_ctrl)
		free(ctrlurl_ctrl);
	if (DescDoc)
        	ixmlDocument_free( DescDoc );
	
    	return(ret);
}

int WSCRegisterCallBackFunc(WSC_FunPtr Fun, void *Cookie) 
{
	if (WSCCallBack_registered >= 1) {
		DEBUG_ERR("CallBack already registered!\n");
		return WSC_UPNP_FAIL;
	}
	
	if (Fun == NULL) {
		DEBUG_ERR("No Function handler!\n");
		return WSC_UPNP_FAIL;
	}
	else {
		_DEBUG_PRINT("WSCRegisterCallBackFunc successfully!\n");
		WSCCallBack = Fun;
		WSCCallBack_registered = 1;
		user_priv_data = (char *)Cookie;
	}

	return WSC_UPNP_SUCCESS;
}

int WSCUpnpStart(char *ifname, OpMode mode, struct WSC_profile *profile)
{
	int ret=0;
    	int port;
    	char lan_ip_address[16];
	char *desc_doc_name=NULL, *conf_dir_path=NULL;
    	char desc_doc_url[200];
	char profile_name[20];
	IPCon ipcon=NULL;
	struct timeval tod;

	if (WSCCallBack_registered != 1)
		return WSC_UPNP_FAIL;

	if (mode == WSC_AP_MODE || mode == WSC_STA_MODE)
		upnp_op_mode = mode;
	else
		return WSC_UPNP_FAIL;

	WSC_pthread_mutex_init(&PsimplecfgDevMutex, NULL);

	ipcon = IPCon_New(ifname);
	if (ipcon == NULL)
		return WSC_UPNP_FAIL;
    	strcpy(lan_ip_address, IPCon_GetIpAddrByStr(ipcon));  
	IPCon_Destroy(ipcon);

	gettimeofday(&tod , NULL);
	srand(tod.tv_sec);
	port = 50000 + (rand() % 10000);
    	
    	desc_doc_name = PSIMPLECFG_INIT_DESC_DOC;
    	conf_dir_path = PSIMPLECFG_INIT_CONF_DIR;  
    	sprintf(desc_doc_url, "http://%s:%d/%s.xml", lan_ip_address, port, desc_doc_name);
    	_DEBUG_PRINT("Intializing Simple Config UPnP \n\tdesc_doc_url=%s\n", desc_doc_url);
    	_DEBUG_PRINT("\tipaddress=%s port=%d\n", lan_ip_address, port);
    	_DEBUG_PRINT("\tconf_dir_path=%s\n", conf_dir_path);

	memset(profile_name, 0, 20);
	sprintf(profile_name, "%s.xml", desc_doc_name);

	if(gen_simplecfg_xml(lan_ip_address, port, conf_dir_path, profile_name, profile) != WSC_UPNP_SUCCESS)
	{
		DEBUG_ERR("Error in gen_simplecfg_xml!\n");
		WSCUpnpStop();
		return WSC_UPNPINIT_FAIL;
	}

    	if ((ret = UpnpInit(lan_ip_address, port)) != UPNP_E_SUCCESS) {
		DEBUG_ERR("Error with UpnpInit -- %d\n", ret);
		WSCUpnpStop();
		return WSC_UPNPINIT_FAIL;
    	}
    	_DEBUG_PRINT("Simple Config UPnP Initialized...\n");
    	_DEBUG_PRINT("Specifying the webserver root directory -- %s\n", conf_dir_path);
    	if (UpnpSetWebServerRootDir(conf_dir_path) != UPNP_E_SUCCESS) {
		DEBUG_ERR("Error specifying webserver root directory -- %s: %d\n", conf_dir_path, ret);
		WSCUpnpStop();
		return WSC_UPNPWEBSERVER_FAIL;
    	}

	_DEBUG_PRINT("Registering the RootDevice...\n");
    	if ((ret = UpnpRegisterRootDevice(desc_doc_url, PsimplecfgDeviceCallbackEventHandler, &device_handle, &device_handle)) != UPNP_E_SUCCESS) {
		DEBUG_ERR("Error registering the rootdevice : %d\n", ret);
		WSCUpnpStop();
		return WSC_UPNPROOTDEV_FAIL;
    	} 
	else { 
		RootDevRegistered = 1;
		
		if ((ret = UpnpSetMaxSubscriptions(device_handle, MAX_SUBSCRIPTION_NUM)) != UPNP_E_SUCCESS) {
			DEBUG_ERR("Error with UpnpSetMaxSubscriptions -- %d\n", ret);
			WSCUpnpStop();
			return WSC_UPNPINIT_FAIL;
		}
		
		if ((ret = UpnpSetMaxSubscriptionTimeOut(device_handle, MAX_SUBSCRIPTION_TIMEOUT)) != UPNP_E_SUCCESS) {
			DEBUG_ERR("Error with UpnpSetMaxSubscriptionTimeOut -- %d\n", ret);
			WSCUpnpStop();
			return WSC_UPNPINIT_FAIL;
		}
		
		// sends bye bye to clean up receiver's state table
		if ((ret = Upnp_WSC_AdvertiseAndReply( -1, device_handle, 0, ( struct sockaddr_in * )NULL,
                                ( char * )NULL, ( char * )NULL,
                                ( char * )NULL, 1)) != UPNP_E_SUCCESS) {
			DEBUG_ERR("Error with AdvertiseAndReply bye bye -- %d\n", ret);
			WSCUpnpStop();
			return WSC_UPNPINIT_FAIL;
		}
		sleep(1);
		
		_DEBUG_PRINT("RootDevice Registered...\n");
		_DEBUG_PRINT("Initializing State Table...\n");
		if (PsimplecfgDeviceStateTableInit(desc_doc_url)!=UPNP_E_SUCCESS) {
			DEBUG_ERR("State Table Initialized fail!\n");
			WSCUpnpStop();
			return WSC_UPNPSTATETABLE_FAIL;
		}
		else
			_DEBUG_PRINT("State Table Initialized...\n");

		if ((ret = UpnpSendAdvertisement(device_handle, default_advr_expire)) != UPNP_E_SUCCESS) {
		    	DEBUG_ERR("Error sending advertisements : %d\n", ret);
			WSCUpnpStop();
		    	return WSC_UPNPSENDADV_FAIL;
		}

		_DEBUG_PRINT("Advertisements Sent...\n");
    	}

    	return WSC_UPNP_SUCCESS;
}

void WSCUpnpStop(void)
{	
	if (RootDevRegistered) {
		_DEBUG_PRINT("Enter UpnpUnRegisterRootDevice...\n");
		UpnpUnRegisterRootDevice(device_handle);
		RootDevRegistered = 0;
	}
	if (UpnpFinish() != UPNP_E_SUCCESS)
		DEBUG_ERR("UpnpFinish() failed...\n");
    	WSC_pthread_mutex_destroy(&PsimplecfgDevMutex);
	
	WSCCallBack_registered = 0;
	if (PsimplecfgDeviceType)
		free(PsimplecfgDeviceType);
	if (PsimplecfgServiceType)
		free(PsimplecfgServiceType);
	if (PsimplecfgServiceId)
		free(PsimplecfgServiceId);
	if (psimplecfg_udn)
		free(psimplecfg_udn);

	_DEBUG_PRINT("WSC UPNP shutting down...\n");
}

