#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define DAEMON_FIFO	"/root/802.1x/open1x/src/FIFO/daemon_fifo"


#ifdef _DAEMON_SIDE
#define DAEMON_FIFO 	"/var/auth-%s.fifo"
#else
//sc_yang for dual mode
#define DAEMON_FIFO 	"/var/auth-%s.fifo"
#endif

#ifdef _LISTEN_SIDE
#define LISTEN_FIFO   "fifo.dat"
#else
#define LISTEN_FIFO   "fifo.dat"
#endif

#define MAXLINE	20000
#define RWFIFOSIZE	1600	// jimmylin: org: 160, for passing EAP packet by event queue

#define FILE_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
			/* default permission for new files */


#define	FIFO_TYPE_WLISTEN	0x01
#define FIFO_TYPE_DLISTEN	0x02
#define FIFO_TYPE_RLISTEN	0x03

#define FIFO_HEADER_LEN		5

