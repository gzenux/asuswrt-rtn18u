#ifndef INCLUDE_RSCERTCOMMON_H
#define INCLUDE_RSCERTCOMMON_H
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h> 

#define SUCCESS 0
#define FAILED -1

#ifdef CONFIG_RTL_FLASH_MAPPING_ENABLE
#define FLASH_SIZE CONFIG_RTL_FLASH_SIZE
#define KERNEL_IMAGE_OFFSET CONFIG_RTL_LINUX_IMAGE_OFFSET
#define ROOT_IMAGE_OFFSET CONFIG_RTL_ROOT_IMAGE_OFFSET
#else
#define FLASH_SIZE 0x400000				//default for 4M flash
#define KERNEL_IMAGE_OFFSET 0x30000	//default for 4M flash
#define ROOT_IMAGE_OFFSET 0x130000		//default for 4M flash
#endif

#define FLASH_DEVICE_NAME0		("/dev/mtdblock0")

// For 8196C and 8198
#define KERNEL_SIGNATURE	((char *)"cr6c")
#define SIG_LEN			4

#define RS_1X_SIGNATURE		"1xRS"
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define CERT_SIZE 0x12000	//48KB, should be sync with users/goahead-2.1.1/LINUX/apmib.h
#else
#define CERT_SIZE 0x8000	//32KB, should be sync with users/goahead-2.1.1/LINUX/apmib.h
#endif
#define CERT_AREA_HEADER_SIZE	8
#define CERT_FILE_HEADER_SIZE 4
#define USER_CERT_MAX_SIZE 0x2000	// 8KB, note: user cert file include user cert and user private key.
#define ROOT_CERT_MAX_SIZE 0x2000	// 8KB, note: root cert file only include root cert.

#define CERT_AREA_BASE	(ROOT_IMAGE_OFFSET-CERT_SIZE)
#define USER_CERT_BASE_5G	(CERT_AREA_BASE+CERT_AREA_HEADER_SIZE)
#define ROOT_CERT_BASE_5G	(USER_CERT_BASE_5G+USER_CERT_MAX_SIZE)
#define USER_CERT_BASE_2G	(ROOT_CERT_BASE_5G+ROOT_CERT_MAX_SIZE)
#define ROOT_CERT_BASE_2G	(USER_CERT_BASE_2G+USER_CERT_MAX_SIZE)
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define USER_CERT_BASE_ETH	(ROOT_CERT_BASE_2G+ROOT_CERT_MAX_SIZE)
#define ROOT_CERT_BASE_ETH	(USER_CERT_BASE_ETH+USER_CERT_MAX_SIZE)
#define CERT_AREA_END (ROOT_CERT_BASE_ETH+ROOT_CERT_MAX_SIZE)
#else
#define CERT_AREA_END (ROOT_CERT_BASE_2G+ROOT_CERT_MAX_SIZE)
#endif


#define FLAG_NO_CERT			0
#define FLAG_USER_CERT_5G		1
#define FLAG_ROOT_CERT_5G		2
#define FLAG_USER_CERT_2G		4
#define FLAG_ROOT_CERT_2G		8
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define FLAG_USER_CERT_ETH		16
#define FLAG_ROOT_CERT_ETH		32
#endif

#define TYPE_NO_CERT			0
#define TYPE_USER_CERT_5G		1
#define TYPE_ROOT_CERT_5G		2
#define TYPE_USER_CERT_2G		4
#define TYPE_ROOT_CERT_2G		8
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define TYPE_USER_CERT_ETH		16
#define TYPE_ROOT_CERT_ETH		32
#endif


//#define RS_USER_CERT "/var/1x/client.pem"
//#define RS_ROOT_CERT "/var/1x/ca.pem"
#define RS_USER_CERT_5G	"/var/1x/client_5g.pem"
#define RS_ROOT_CERT_5G	"/var/1x/ca_5g.pem"
#define RS_USER_CERT_2G	"/var/1x/client_2g.pem"
#define RS_ROOT_CERT_2G	"/var/1x/ca_2g.pem"
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define RS_USER_CERT_ETH	"/var/1x/client_eth.pem"
#define RS_ROOT_CERT_ETH	"/var/1x/ca_eth.pem"
#endif


#define TRACE(x...) x
#if 0
#define DEBUG(x...) TRACE(printf(x))
#else
#define DEBUG(x...)
#endif
#if 0
#define ERR_PRINT(x...) TRACE(printf(x))
#else
#define ERR_PRINT(x...)
#endif

/* Firmware image header */
typedef struct _header_ {
	unsigned char signature[SIG_LEN];
	unsigned long startAddr;
	unsigned long burnAddr;
	unsigned long len;
} IMG_HEADER_T, *IMG_HEADER_Tp;

/* Flash store format: cert area header */
// related to CERT_AREA_HEADER_SIZE
typedef struct _certAreaHeader_ {
	unsigned char signature[SIG_LEN];	// user "1xRS" here for 802.1x RADIUS certs
	unsigned char certFlag;			// flag of certs, defined as TYPE_*
	unsigned char reserved[3];			// reserved
} CERT_AREA_HEADER_T, *CERT_AREA_HEADER_Tp;

/* Flash store format: cert file header */
// related to CERT_FILE_HEADER_SIZE
typedef struct _certFileHeader_ {
	unsigned char fileType;	// type of cert file, defined as TYPE_*
	unsigned char reserved;	// reserved
	unsigned short fileLen;		// length of cert file
} CERT_FILE_HEADER_T, *CERT_FILE_HEADER_Tp;

#if 0
//For debug
void dumpHex(const unsigned char * buf, int bufLen);
void dumpStr(const char * buf, int bufLen);
#endif

int isFileExist(char *file_name);
int kernelImageOverSize(void);
int updateCertAreaHeader(const unsigned char certFlag);
int storeFile(const unsigned long dstAddr, const char * srcFile, const char initFlag);
int loadFile(const char * dstFile, const unsigned long srcAddr);

#endif // end of INCLUDE_RSCERTCOMMON_H
