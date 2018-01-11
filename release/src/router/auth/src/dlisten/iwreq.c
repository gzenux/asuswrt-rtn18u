#include "iwcommon.h"
#include "1x_ioctl.h"
#include <string.h>
#include <error.h>

#define Dot1XDataLen(payloadlen)        sizeof(DOT1X_EVENT) + sizeof (unsigned short) + payloadlen


#define MAXDATALEN      1560	// jimmylin: org:256, enlarge for pass EAP packet by event queue
/*------------------------------------------------------------------*/
/*
 * Request indication from driver with ioctl. If there is no ,
 * indication from driver, the function blocks.
 */

int RequestIndication(
	int                    skfd,
	char *                 ifname,
	char *		       out,
	int  *		       outlen)
{

	struct iwreq          wrq;
	DOT11_REQUEST	      * req;



  	/* Get wireless name */
	memset(wrq.ifr_name, 0, sizeof wrq.ifr_name);
  	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	req = (DOT11_REQUEST *)malloc(MAXDATALEN);
	wrq.u.data.pointer = (caddr_t)req;
	req->EventId = DOT11_EVENT_REQUEST;
	wrq.u.data.length = sizeof(DOT11_REQUEST);

	//iw_message(MESS_DBG_IWCONTROL, "[RequestIndication] : Start\n");
	//printf("\n[RequestIndication] : Start\n");
  	if(ioctl(skfd, SIOCGIWIND, &wrq) < 0)
	{
    	// If no wireless name : no wireless extensions
		free(req);
		strerror(errno);
    		return(-1);
	}
  	else{
		//iw_message(MESS_DBG_IWCONTROL, "[RequestIndication]"," : Return\n");
		//iw_ctldump("RequestIndication", wrq.u.data.pointer, wrq.u.data.length, "receive message from driver");
		memcpy(out, wrq.u.data.pointer, wrq.u.data.length);
		*outlen = wrq.u.data.length;
		//write(1, "RequestIndication<1>\n", sizeof("RequestIndication<1>\n"));

	}
	free(req);
	return 1;
}
/*
int InitialEventQueue(
	int                    skfd,
	char *                 ifname,
        struct wireless_info * info)
{

	struct iwreq          wrq;
	DOT11_RESET_QUEUE	* ResetQueue;
	int i;
	

  	memset((char *) info, 0, sizeof(struct wireless_info));

  	//Get wireless name 
  	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	ResetQueue = (DOT11_RESET_QUEUE *)malloc(sizeof(DOT11_RESET_QUEUE));
	wrq.u.data.pointer = (caddr_t)ResetQueue;
	ResetQueue->EventId = DOT11_EVENT_RESET_QUEUE;
	wrq.u.data.length = sizeof(DOT11_RESET_QUEUE);

	iw_message(MESS_DBG_IWCONTROL, "[InitialEventQueue] : Start\n");
	write(1, "[InitialEventQueue] : Start\n", sizoef("[InitialEventQueue] : Start\n"));
	printf("\n[InitialEvenetQueue] : Start\n");
  	if(ioctl(skfd, SIOCGIWIND, &wrq) < 0)
    	// If no wireless name : no wireless extensions 
    		return(-1);
  	else{
		iw_message(MESS_DBG_IWCONTROL, "[InitialEventQueue] : Return\n");
		for(i=0; i<wrq.u.data.length;i++)
	       		printf("%x ", wrq.u.data.pointer[i]);
		
	}

	return 1;
}
*/
int RegisterPID(
	int                    skfd,
	char *                 ifname)
{
	struct iwreq          wrq;
	pid_t                 pid;

  	/* Get wireless name */
	memset(wrq.ifr_name, 0, sizeof wrq.ifr_name);
  	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	pid = getpid();
	wrq.u.data.pointer = (caddr_t)&pid;
	wrq.u.data.length = sizeof(pid_t);

  	if(ioctl(skfd, SIOCSAPPPID, &wrq) < 0)
	{
    	// If no wireless name : no wireless extensions
		strerror(errno);
		return(-1);
	}
	return 1;
}

