#include "rsCertCommon.h"

#if 0
//For debug
void dumpHex(const unsigned char * buf, int bufLen)
{
	int i;

	for(i=0;i<bufLen;i++)
	{
		DEBUG("%2x  ",buf[i]);
		if(((i+1)>=16)&&((i+1)%16==0))
		{
			DEBUG("\n");
		}
	}
	DEBUG("\n");

}

//For debug
void dumpStr(const char * buf, int bufLen)
{
	int i;

	for(i=0;i<bufLen;i++)
	{
		DEBUG("%c",buf[i]);
		if(((i+1)>=16)&&((i+1)%16==0))
		{
			DEBUG("\n");
		}
	}
	DEBUG("\n");
}
#endif

int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}


/*
*  check kernel image is oversize or not
*  return 1: kernel image is oversize
*  return 0: kernel image is not oversize
*  return -1: check failed 
*/
int kernelImageOverSize(void)
{
	int fh;
	int ret, toRet;
	unsigned long offset,kenelImgLen, cmpLen;
	unsigned char tmpBuf[16];
	IMG_HEADER_Tp pHeader;

	fh = open(FLASH_DEVICE_NAME0, O_RDONLY); 

	if ( fh == -1 ) 
	{
		ERR_PRINT("%s(%d): open %s error.\n",__FUNCTION__, __LINE__, FLASH_DEVICE_NAME0);//Added for test
		toRet=FAILED;
		goto err;
	}

	//To read flash
	offset=KERNEL_IMAGE_OFFSET;
	lseek(fh,offset,SEEK_SET);
	
	memset(tmpBuf,0, sizeof(tmpBuf));//To initial
	ret=read(fh,(void *)tmpBuf,sizeof(tmpBuf));
//	dumpHex(tmpBuf, ret);

	pHeader=(IMG_HEADER_Tp)tmpBuf;
	if ( memcmp(pHeader->signature, KERNEL_SIGNATURE, SIG_LEN) !=0) {
		ERR_PRINT("%s(%d): [error] pHeader->signature. \n",__FUNCTION__, __LINE__);
		toRet=FAILED;
		goto err;
	}

	kenelImgLen = pHeader->len+sizeof(IMG_HEADER_T);
	cmpLen = ROOT_IMAGE_OFFSET-KERNEL_IMAGE_OFFSET-CERT_SIZE;
//	DEBUG("%s(%d),kenelImgLen=0x%x, cmpLen=0x%x \n",__FUNCTION__,__LINE__,kenelImgLen, cmpLen);//Added for test
	if(kenelImgLen > cmpLen){
		ERR_PRINT("%s(%d): kernel image is oversize.\n",__FUNCTION__, __LINE__);
		toRet=1;
		goto err;
	}

	toRet=0;
	
err:
	if(fh!=-1)
		close(fh);
	
	return toRet;
}

/*
*  function description: update cert area header at flash
*  parameters:
*  certFlag(input): flag of cert info, defined as FLAG_*
*  return 0: success; -1: failed
*/
int updateCertAreaHeader(const unsigned char certFlag)
{
	int fh;
	int ret, toRet;
	unsigned long offset;
	CERT_AREA_HEADER_T certAreaHeader, rdCertAreaHeader;

	//To open FLASH_DEVICE_NAME1
	fh = open(FLASH_DEVICE_NAME0, O_RDWR | O_SYNC); 

	if ( fh == -1 ) 
	{
		ERR_PRINT("%s(%d): open %s error.\n",__FUNCTION__, __LINE__, FLASH_DEVICE_NAME0);//Added for test
		toRet=FAILED;
		goto err;
	}
	
	//To set certAreaHeader
	memset((void *)&certAreaHeader, 0, sizeof(certAreaHeader));
	strncpy(certAreaHeader.signature, RS_1X_SIGNATURE, SIG_LEN);

	if(certFlag == FLAG_NO_CERT)
	{
		//cert area reset
		certAreaHeader.certFlag=certFlag;
	}
	else
	{
		//To read cert area header
		offset=CERT_AREA_BASE;
		lseek(fh,offset,SEEK_SET);//Point to the (MTD1_SIZE-WAPI_SIZE) of file
		ret=read(fh,(void *)&rdCertAreaHeader,sizeof(rdCertAreaHeader));
		if((ret==-1)||(ret < sizeof(rdCertAreaHeader)))
		{
			ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}

		certAreaHeader.certFlag = (rdCertAreaHeader.certFlag | certFlag);
	}
	
	//To write flash
	offset=CERT_AREA_BASE;
	lseek(fh,offset,SEEK_SET);//Point to the (MTD1_SIZE-WAPI_SIZE) of file
	ret=write(fh,(void *)&certAreaHeader,sizeof(certAreaHeader));
	if((ret==-1)||(ret < sizeof(certAreaHeader)))
	{
		ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
		toRet=FAILED;
		goto err;
	}

	toRet=SUCCESS;

err:
	if(fh!=-1)
		close(fh);
	
	return toRet;
}

/*
*  function description: update cert area header at flash
*  parameters:
*  certFlagMsk(input): flag of cert info to mask, defined as FLAG_*
*  return 0: success; -1: failed
*/
int updateCertAreaHeader2(const unsigned char certFlagMsk)
{
	int fh;
	int ret, toRet;
	unsigned long offset;
	CERT_AREA_HEADER_T certAreaHeader, rdCertAreaHeader;

	//To open FLASH_DEVICE_NAME1
	fh = open(FLASH_DEVICE_NAME0, O_RDWR | O_SYNC); 

	if ( fh == -1 ) 
	{
		ERR_PRINT("%s(%d): open %s error.\n",__FUNCTION__, __LINE__, FLASH_DEVICE_NAME0);//Added for test
		toRet=FAILED;
		goto err;
	}
	
	//To set certAreaHeader
	memset((void *)&certAreaHeader, 0, sizeof(certAreaHeader));
	strncpy(certAreaHeader.signature, RS_1X_SIGNATURE, SIG_LEN);

	//To read cert area header
	offset=CERT_AREA_BASE;
	lseek(fh,offset,SEEK_SET);//Point to the (MTD1_SIZE-WAPI_SIZE) of file
	ret=read(fh,(void *)&rdCertAreaHeader,sizeof(rdCertAreaHeader));
	if((ret==-1)||(ret < sizeof(rdCertAreaHeader)))
	{
		ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
		toRet=FAILED;
		goto err;
	}

	certAreaHeader.certFlag = (rdCertAreaHeader.certFlag & certFlagMsk);
	
	//To write flash
	offset=CERT_AREA_BASE;
	lseek(fh,offset,SEEK_SET);//Point to the (MTD1_SIZE-WAPI_SIZE) of file
	ret=write(fh,(void *)&certAreaHeader,sizeof(certAreaHeader));
	if((ret==-1)||(ret < sizeof(certAreaHeader)))
	{
		ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
		toRet=FAILED;
		goto err;
	}

	toRet=SUCCESS;

err:
	if(fh!=-1)
		close(fh);
	
	return toRet;
}

/*
*  function description: To store cert file to the last CERT_SIZE of /dev/mtdblock0
*
*  parameters: 
*  dstAddr (input): destination to store source file
*  srcFile (input): source file name
*  initFlag (input): 0 -- normal mode (store cert file header and body); 1 -- initial mode (only initial cert file header and store it)
*
* return 0: success, -1: failed
*/
int storeFile(const unsigned long dstAddr, const char * srcFile, const char initFlag)
{
	int fh, fd;		// fh: /dev/mtdblock0 handler; fd: srcfile handler
	struct stat fileStat;
	unsigned long offset, totalLen, storeSize;
	CERT_FILE_HEADER_T certFileHeader;
	unsigned char buffer[1300];
	int ret, readSize, lenLeft;
	int toRet;
	char rwFlag;// 0: indicate first time; 1: indicate not first time


	//To initial
	fh=-1;
	fd=-1;
	memset((void *)&certFileHeader, 0, sizeof(certFileHeader));
	
	offset=dstAddr;

	if((offset >= CERT_AREA_END)||(offset< CERT_AREA_BASE))
	{
		ERR_PRINT("Error: dstAddr(0x%x) is out of cert area 0x%x - 0x%x\n",offset,CERT_AREA_BASE, CERT_AREA_END);//Added for test
		toRet=FAILED;
		goto err;
	}

	//To check srcFile store area
	if(strcmp(srcFile, RS_USER_CERT_5G)==0)
	{
		if(offset!= USER_CERT_BASE_5G)
		{
			ERR_PRINT("Error: %s should store at 0x%x\n",RS_USER_CERT_5G, USER_CERT_BASE_5G);//Added for test
			toRet=FAILED;
			goto err;
		}
		
		certFileHeader.fileType=TYPE_USER_CERT_5G;
	}
	else if(strcmp(srcFile, RS_ROOT_CERT_5G)==0)
	{
		if(offset!= ROOT_CERT_BASE_5G)
		{
			ERR_PRINT("Error: %s should store at 0x%x\n",RS_ROOT_CERT_5G, ROOT_CERT_BASE_5G);//Added for test
			toRet=FAILED;
			goto err;
		}

		certFileHeader.fileType=TYPE_ROOT_CERT_5G;
	}
	else if(strcmp(srcFile, RS_USER_CERT_2G)==0)
	{
		if(offset!= USER_CERT_BASE_2G)
		{
			ERR_PRINT("Error: %s should store at 0x%x\n",RS_USER_CERT_2G, USER_CERT_BASE_2G);//Added for test
			toRet=FAILED;
			goto err;
		}
		
		certFileHeader.fileType=TYPE_USER_CERT_2G;
	}
	else if(strcmp(srcFile, RS_ROOT_CERT_2G)==0)
	{
		if(offset!= ROOT_CERT_BASE_2G)
		{
			ERR_PRINT("Error: %s should store at 0x%x\n",RS_ROOT_CERT_2G, ROOT_CERT_BASE_2G);//Added for test
			toRet=FAILED;
			goto err;
		}

		certFileHeader.fileType=TYPE_ROOT_CERT_2G;
	}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	else if(strcmp(srcFile, RS_USER_CERT_ETH)==0)
	{
		if(offset!= USER_CERT_BASE_ETH)
		{
			ERR_PRINT("Error: %s should store at 0x%x\n",RS_USER_CERT_ETH, USER_CERT_BASE_ETH);//Added for test
			toRet=FAILED;
			goto err;
		}
		
		certFileHeader.fileType=TYPE_USER_CERT_ETH;
	}
	else if(strcmp(srcFile, RS_ROOT_CERT_ETH)==0)
	{
		if(offset!= ROOT_CERT_BASE_ETH)
		{
			ERR_PRINT("Error: %s should store at 0x%x\n",RS_ROOT_CERT_ETH, ROOT_CERT_BASE_ETH);//Added for test
			toRet=FAILED;
			goto err;
		}

		certFileHeader.fileType=TYPE_ROOT_CERT_ETH;
	}
#endif
	else
	{
		ERR_PRINT("Error: %s stored at 0x%x is not supported!\n",srcFile, offset);//Added for test
		toRet=FAILED;
		goto err;
	}
		
	if(initFlag==0)
	{
		//Normal mode
		fd=open(srcFile, O_RDONLY);
		if ( fd == -1 ) 
		{
			ERR_PRINT("open %s error.\n", srcFile);//Added for test
			toRet=FAILED;
			goto err;
		}

	       if((fstat(fd,&fileStat) ==0) && (fileStat.st_size > 0))
	       {
	       	certFileHeader.fileLen=(unsigned short)fileStat.st_size;
	       }
		else
		{
			certFileHeader.fileLen=0;
			ERR_PRINT("fstat %s error.\n", srcFile);//Added for test
			toRet=FAILED;
			goto err;
		}
//		DEBUG("%s(%d),certFileHeader.fileLen=%d\n",__FUNCTION__,__LINE__,certFileHeader.fileLen);//Added for test

		//To check store size whether oversize or not
		storeSize=certFileHeader.fileLen+CERT_FILE_HEADER_SIZE;
		if((offset == USER_CERT_BASE_5G) || (offset == USER_CERT_BASE_2G))
		{
			if(storeSize>=USER_CERT_MAX_SIZE)
			{
				ERR_PRINT("Error: storeSize(0x%x) >= USER_CERT_MAX_SIZE(0x%x)\n", storeSize, USER_CERT_MAX_SIZE);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
		else if((offset == ROOT_CERT_BASE_5G) || (offset == ROOT_CERT_BASE_2G))
		{
			if(storeSize>=ROOT_CERT_MAX_SIZE)
			{
				ERR_PRINT("Error: storeSize(0x%x) >= ROOT_CERT_MAX_SIZE(0x%x)\n", storeSize, ROOT_CERT_MAX_SIZE);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		else if(offset == USER_CERT_BASE_ETH )
		{
			if(storeSize>=USER_CERT_MAX_SIZE)
			{
				ERR_PRINT("Error: storeSize(0x%x) >= USER_CERT_MAX_SIZE(0x%x)\n", storeSize, USER_CERT_MAX_SIZE);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
		else if(offset == ROOT_CERT_BASE_ETH)
		{
			if(storeSize>=ROOT_CERT_MAX_SIZE)
			{
				ERR_PRINT("Error: storeSize(0x%x) >= ROOT_CERT_MAX_SIZE(0x%x)\n", storeSize, ROOT_CERT_MAX_SIZE);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
#endif
		//To store srcfile into flash at dstAddr
		rwFlag=0;
		lenLeft=(int)certFileHeader.fileLen;
		while(lenLeft>0)
		{
			//To read srcfile into buffer
			readSize=read(fd, (void *)buffer, sizeof(buffer));
			if(readSize==-1)
			{
				ERR_PRINT("%s(%d),read file failed.\n",__FUNCTION__,__LINE__);//Added for test
				toRet=FAILED;
				goto err;
			}

			if(rwFlag==0)
			{				
				//To write srcfile (include cert file header) into flash
				fh = open(FLASH_DEVICE_NAME0, O_RDWR | O_SYNC); 
				if ( fh == -1 ) 
				{
					ERR_PRINT("open %s error.\n", FLASH_DEVICE_NAME0);//Added for test
					toRet=FAILED;
					goto err;
				}
				
				lseek(fh,offset,SEEK_SET);//Point to flash related to the start of cert file
				ret=write(fh,(void *)&certFileHeader,sizeof(certFileHeader));
				if((ret==-1)||(ret < sizeof(certFileHeader)))
				{
					ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
					toRet=FAILED;
					goto err;
				}
			}

			ret=write(fh,(void *)&buffer,readSize);
			if((ret==-1)||(ret < readSize))
			{
				ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
				toRet=FAILED;
				goto err;
			}

			lenLeft-=readSize;
			
			rwFlag=1;
		}
	}
	else
	{
		//initial mode
#if 0
		//To set certFileHeader
		if(!strcmp(srcFile,RS_USER_CERT))
		{
			certFileHeader.fileType=TYPE_USER_CERT;
		}
		else if(!strcmp(srcFile,RS_ROOT_CERT))
		{
			certFileHeader.fileType=TYPE_ROOT_CERT;
		}
#endif
		certFileHeader.fileLen=0;

		//To write srcfile (include cert file header) into flash
		fh = open(FLASH_DEVICE_NAME0, O_RDWR | O_SYNC); 

		if ( fh == -1 ) 
		{
			ERR_PRINT("open %s error.\n", FLASH_DEVICE_NAME0);//Added for test
			toRet=FAILED;
			goto err;
		}
				
		lseek(fh,offset,SEEK_SET);//Point to flash related to the start of cert file
		ret=write(fh,(void *)&certFileHeader,sizeof(certFileHeader));
//		DEBUG("%s(%d),ret=%d, sizeof(certFileHeader)=%d, sizeof(CERT_AREA_HEADER_T)=%d\n",__FUNCTION__,__LINE__,ret, sizeof(certFileHeader), sizeof(CERT_AREA_HEADER_T));//Added for test
		if((ret==-1)||(ret < sizeof(certFileHeader)))
		{
			ERR_PRINT("%s(%d),error: write flash failed.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
	
	toRet=SUCCESS;
	
err:
	if(fd!=-1)
		close(fd);
	
	if(fh!=-1)
		close(fh);
		
	return toRet;
}

/*
*  function description: load file from srcAddr to dstFile
* parameters:
* dstFile (input) : destination filename
* srcAddr (input) : source file address at flash
* return 0: success, -1: failed
*/
int loadFile(const char * dstFile, const unsigned long srcAddr)
{
	int fh, fd;
	int ret, toRet;
	int readSize, lenLeft, bufSize;
	unsigned long offset;
	CERT_FILE_HEADER_T certFileHeader;

	unsigned char buffer[1300];
//	char tmpBuf[USER_CERT_DIR_MAX_LEN+FILE_NAME_MAX_LEN];

	char rwFlag;// 0: indicate first time; 1: indicate not first time

	//To initial
	fh=-1;
	fd=-1;
	
	offset=srcAddr;

	if((offset >= CERT_AREA_END)||(offset< CERT_AREA_BASE))
	{
		ERR_PRINT("Error: srcAddr is out of cert area 0x%x - 0x%x\n", CERT_AREA_BASE, CERT_AREA_END);//Added for test
		toRet=FAILED;
		goto err;
	}

	//To read flash
	fh = open(FLASH_DEVICE_NAME0, O_RDONLY); 
	if ( fh == -1 ) 
	{
		ERR_PRINT("open %s error.\n", FLASH_DEVICE_NAME0);//Added for test
		toRet=FAILED;
		goto err;
	}

	// Initial
	memset(&certFileHeader, 0, sizeof(certFileHeader));
	
	lseek(fh,offset,SEEK_SET);//Point to the flash related to the start of cert file
	ret=read(fh,(void *)&certFileHeader,sizeof(certFileHeader));
//	DEBUG("%s(%d),ret=%d, fileType=0x%x, fileSerial=0x%x, fileLen=0x%x\n",__FUNCTION__,__LINE__,ret,wapiFileHeader.fileType, wapiFileHeader.fileSerial, wapiFileHeader.fileLen);//Added for test
	if((ret==FAILED)||(ret< sizeof(certFileHeader)))
	{
		ERR_PRINT("%s(%d),error: read flash failed.\n",__FUNCTION__,__LINE__);//Added for test
		toRet=FAILED;
		goto err;
	}

	if((certFileHeader.fileType!=TYPE_USER_CERT_5G)&&(certFileHeader.fileType!=TYPE_ROOT_CERT_5G)&&(certFileHeader.fileType!=TYPE_USER_CERT_2G)&&(certFileHeader.fileType!=TYPE_ROOT_CERT_2G)
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	&&(certFileHeader.fileType!=TYPE_USER_CERT_ETH) &&(certFileHeader.fileType!=TYPE_ROOT_CERT_ETH)
#endif
	)
	{
		ERR_PRINT("%s(%d),unknow file type (0x%x).\n",__FUNCTION__,__LINE__,certFileHeader.fileType);//Added for test
		toRet=FAILED;
		goto err;
	}

#if 1 
	//To check srcAddr with fileType stored in flash
	if(strcmp(dstFile, RS_USER_CERT_5G)==0)
	{
		if(certFileHeader.fileType!=TYPE_USER_CERT_5G)
		{
			ERR_PRINT("Error: dstFile(%s), but fileType(0x%x) not match.\n",dstFile, certFileHeader.fileType);//Added for test
			toRet=FAILED;
			goto err;
		}	
	}
	else if(strcmp(dstFile, RS_ROOT_CERT_5G)==0)
	{
		if(certFileHeader.fileType!=TYPE_ROOT_CERT_5G)
		{
			ERR_PRINT("Error: dstFile(%s), but fileType(0x%x) not match.\n",dstFile, certFileHeader.fileType);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
	else if(strcmp(dstFile, RS_USER_CERT_2G)==0)
	{
		if(certFileHeader.fileType!=TYPE_USER_CERT_2G)
		{
			ERR_PRINT("Error: dstFile(%s), but fileType(0x%x) not match.\n",dstFile, certFileHeader.fileType);//Added for test
			toRet=FAILED;
			goto err;
		}	
	}
	else if(strcmp(dstFile, RS_ROOT_CERT_2G)==0)
	{
		if(certFileHeader.fileType!=TYPE_ROOT_CERT_2G)
		{
			ERR_PRINT("Error: dstFile(%s), but fileType(0x%x) not match.\n",dstFile, certFileHeader.fileType);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	else if(strcmp(dstFile, RS_USER_CERT_ETH)==0)
	{
		if(certFileHeader.fileType!=TYPE_USER_CERT_ETH)
		{
			ERR_PRINT("Error: dstFile(%s), but fileType(0x%x) not match.\n",dstFile, certFileHeader.fileType);//Added for test
			toRet=FAILED;
			goto err;
		}	
	}
	else if(strcmp(dstFile, RS_ROOT_CERT_ETH)==0)
	{
		if(certFileHeader.fileType!=TYPE_ROOT_CERT_ETH)
		{
			ERR_PRINT("Error: dstFile(%s), but fileType(0x%x) not match.\n",dstFile, certFileHeader.fileType);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
#endif
	else
	{
		ERR_PRINT("Error: %s read from 0x%x is not supported!\n",dstFile, offset);//Added for test
		toRet=FAILED;
		goto err;
	}
#endif

	lenLeft=(int)certFileHeader.fileLen;
	if(lenLeft<=0)
	{
		ERR_PRINT("%s(%d),file length <= 0.\n",__FUNCTION__,__LINE__);//Added for test
		toRet=FAILED;
		goto err;
	}
	
	rwFlag=0;
	bufSize=sizeof(buffer);
	while(lenLeft>0)
	{
		if(lenLeft>bufSize)
		{
			readSize=read(fh,(void *)&buffer,bufSize);
			if((readSize==FAILED) || (readSize<bufSize))
			{
				ERR_PRINT("%s(%d),error: read flash failed(%d).\n",__FUNCTION__,__LINE__, readSize);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
		else
		{
			readSize=read(fh,(void *)&buffer,lenLeft);
			if((readSize==FAILED) || (readSize<lenLeft))
			{
				ERR_PRINT("%s(%d),error: read flash failed(%d).\n",__FUNCTION__,__LINE__, readSize);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
//		DEBUG("%s(%d): readSize=%d\n",__FUNCTION__,__LINE__,readSize);//Added for test

		if(rwFlag==0)
		{
			fd=open(dstFile, O_WRONLY | O_CREAT | O_TRUNC);
			if ( fd == -1 ) 
			{
				ERR_PRINT("%s(%d): open %s error.\n",__FUNCTION__,__LINE__, dstFile);//Added for test
				toRet=FAILED;
				goto err;
			}
		}

		ret=write(fd, (void *)buffer, readSize);
		if((ret==FAILED)||(ret< readSize))
		{
			ERR_PRINT("%s(%d),error: write file failed(%d).\n",__FUNCTION__,__LINE__,ret);//Added for test
			toRet=FAILED;
			goto err;
		}

		lenLeft-=readSize;
		rwFlag=1;
	}

	toRet=SUCCESS;

err:
	if(fd!=-1)
		close(fd);
	
	if(fh!=-1)
		close(fh);
	
	return toRet;
}

