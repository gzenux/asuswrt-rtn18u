#include "rsCertCommon.h"

static const char *cmd[]={
"usage: rsCert args\n",
"\n",
" -rst		- reset all cert files at running system and reset flash space for cert area (include cert area header, cert file header of user cert and root cert)\n",
" -rst_5g		- reset all cert files at running system and reset flash space for cert area of 5GHz \n",
" -rst_2g		- reset all cert files at running system and reset flash space for cert area of 2.4GHz \n",
" -wrAll		- store user cert and root cert\n",
" -wrUser		- store user cert\n",
" -wrUser_5g	- store 5g user cert\n",
" -wrUser_2g	- store 2g user cert\n",
" -wrRoot	- store root cert\n",
" -wrRoot_5g	- store 5g root cert\n",
" -wrRoot_2g	- store 2g root cert\n",
" -rd			- load user cert and root cert\n",
NULL
};

int main(int argc, char **argv)
{
	char badops;
	char **pp;
	char resetCert,resetCert_5g, resetCert_2g, storeAllCert, storeUserCert,storeUserCert_5g,storeUserCert_2g, storeRootCert,storeRootCert_5g, storeRootCert_2g, loadCert;
	unsigned char certFlag,certFlagMask;
	char tmpFile[50];
	int offset;
	int ret;
	int toRet;
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	char storeUserCert_eth,storeRootCert_eth,resetCert_eth;

	storeUserCert_eth = 0;
	storeRootCert_eth = 0;
	resetCert_eth = 0;
#endif

//	DEBUG("%s(%d): FLASH_SIZE(0x%x),KERNEL_IMAGE_OFFSET(0x%x), ROOT_IMAGE_OFFSET(0x%x) \n", __FUNCTION__,__LINE__,FLASH_SIZE,KERNEL_IMAGE_OFFSET,ROOT_IMAGE_OFFSET);//Added for test

	//Initial
	resetCert=0;
	resetCert_5g=0;
	resetCert_2g=0;
	storeAllCert=0;
	storeUserCert=0;
	storeUserCert_5g=0;
	storeUserCert_2g=0;
	storeRootCert=0;
	storeRootCert_5g=0;
	storeRootCert_2g=0;
	loadCert=0;

	argc--;
	argv++;

	if(argc==0)
	{
		badops=1;
		goto bad;
	}
	
	while (argc >= 1)
	{
		if(strcmp(*argv,"-rst") == 0)
		{
			resetCert=1;
		}
		else if(strcmp(*argv,"-rst_5g") == 0)
		{
			resetCert_5g=1;
		}
		else if(strcmp(*argv,"-rst_2g") == 0)
		{
			resetCert_2g=1;
		}
		else if(strcmp(*argv,"-wrAll") == 0)
		{
			storeAllCert=1;
		}
		else if(strcmp(*argv,"-wrUser") == 0)
		{
			storeUserCert=1;
		}
		else if(strcmp(*argv,"-wrUser_5g") == 0)
		{
			storeUserCert_5g=1;
		}
		else if(strcmp(*argv,"-wrUser_2g") == 0)
		{
			storeUserCert_2g=1;
		}
		else if(strcmp(*argv,"-wrRoot") == 0)
		{
			storeRootCert=1;
		}
		else if(strcmp(*argv,"-wrRoot_5g") == 0)
		{
			storeRootCert_5g=1;
		}
		else if(strcmp(*argv,"-wrRoot_2g") == 0)
		{
			storeRootCert_2g=1;
		}
		else if(strcmp(*argv,"-rd") == 0)
		{
			loadCert=1;
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		else if(strcmp(*argv,"-wrRoot_eth") == 0)
		{
			storeRootCert_eth=1;
		}
		else if(strcmp(*argv,"-wrUser_eth") == 0)
		{
			storeUserCert_eth=1;
		}
		else if(strcmp(*argv,"-rst_eth") == 0)
		{
			resetCert_eth=1;
		}
#endif
		else
		{
bad:
			ERR_PRINT("unknown option %s\n",*argv);
			badops=1;
			break;
		}
		argc--;
		argv++;	
	}

	if(badops==1)
	{
		for (pp=cmd; (*pp != NULL); pp++)
			ERR_PRINT("%s",*pp);
		toRet=FAILED;
		goto err;
	} 

	// initial
	certFlag=FLAG_NO_CERT;

	if(resetCert == 1)
	{
		//rm cert related first
		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT_5G);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT_5G);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT_2G);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT_2G);
		system(tmpFile);
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT_ETH);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT_ETH);
		system(tmpFile);
#endif
	}
	else if(resetCert_5g == 1)
	{
		//rm 5g cert related first
		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT_5G);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT_5G);
		system(tmpFile);
	}
	else if(resetCert_2g == 1)
	{
		//rm 2g cert related first
		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT_2G);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT_2G);
		system(tmpFile);
	}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	else if(resetCert_eth == 1)
	{
		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT_ETH);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT_ETH);
		system(tmpFile);
	}
#endif

	ret=kernelImageOverSize();
	if((ret==FAILED)||(ret==1))
	{
		ERR_PRINT("%s(%d): can't use cert area, ret=%d\n",__FUNCTION__, __LINE__,ret);
		toRet=FAILED;
		goto err;
	}

	if(resetCert == 1)
	{
		//reset cert related at flash
		//Initial certAreaHeader
		certFlag=FLAG_NO_CERT;
		ret=updateCertAreaHeader(certFlag);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),updateCertAreaHeader failed!\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 5g user cert file header
		offset=USER_CERT_BASE_5G;
		ret=storeFile(offset, RS_USER_CERT_5G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 5g root cert file header
		offset=ROOT_CERT_BASE_5G;
		ret=storeFile(offset, RS_ROOT_CERT_5G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 2g user cert file header
		offset=USER_CERT_BASE_2G;
		ret=storeFile(offset, RS_USER_CERT_2G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 2g root cert file header
		offset=ROOT_CERT_BASE_2G;
		ret=storeFile(offset, RS_ROOT_CERT_2G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}
		
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		//To initial eth user cert file header
		offset=USER_CERT_BASE_ETH;
		ret=storeFile(offset, RS_USER_CERT_ETH, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial eth root cert file header
		offset=ROOT_CERT_BASE_ETH;
		ret=storeFile(offset, RS_ROOT_CERT_ETH, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}
#endif
	}
	else if(resetCert_5g == 1)
	{
		//reset 5g cert related at flash
		//Initial certAreaHeader
		certFlagMask = (unsigned char)(~(FLAG_USER_CERT_5G | FLAG_ROOT_CERT_5G));
		ret=updateCertAreaHeader2(certFlagMask);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),updateCertAreaHeader failed!\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 5g user cert file header
		offset=USER_CERT_BASE_5G;
		ret=storeFile(offset, RS_USER_CERT_5G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 5g root cert file header
		offset=ROOT_CERT_BASE_5G;
		ret=storeFile(offset, RS_ROOT_CERT_5G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
	else if(resetCert_2g == 1)
	{
		//reset 2g cert related at flash
		//Initial certAreaHeader
		certFlagMask = (unsigned char)(~(FLAG_USER_CERT_2G | FLAG_ROOT_CERT_2G));
		ret=updateCertAreaHeader2(certFlagMask);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),updateCertAreaHeader failed!\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 2g user cert file header
		offset=USER_CERT_BASE_2G;
		ret=storeFile(offset, RS_USER_CERT_2G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial 2g root cert file header
		offset=ROOT_CERT_BASE_2G;
		ret=storeFile(offset, RS_ROOT_CERT_2G, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	else if(resetCert_eth == 1)
	{
		//reset eth cert related at flash
		//Initial certAreaHeader
		certFlagMask = (unsigned char)(~(FLAG_USER_CERT_ETH | FLAG_ROOT_CERT_ETH));
		ret=updateCertAreaHeader2(certFlagMask);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),updateCertAreaHeader failed!\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}
		//To initial eth user cert file header
		offset=USER_CERT_BASE_ETH;
		ret=storeFile(offset, RS_USER_CERT_ETH, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial eth root cert file header
		offset=ROOT_CERT_BASE_ETH;
		ret=storeFile(offset, RS_ROOT_CERT_ETH, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
#endif
	else if(storeAllCert == 1)
	{		
		//store 5g user cert
		offset=USER_CERT_BASE_5G;
		if(isFileExist(RS_USER_CERT_5G))
		{
			ret=storeFile(offset, RS_USER_CERT_5G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_5G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_5G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_5G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		//store 5g root cert
		offset=ROOT_CERT_BASE_5G;
		if(isFileExist(RS_ROOT_CERT_5G))
		{
			ret=storeFile(offset, RS_ROOT_CERT_5G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_5G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_5G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_5G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		//store 2g user cert
		offset=USER_CERT_BASE_2G;
		if(isFileExist(RS_USER_CERT_2G))
		{
			ret=storeFile(offset, RS_USER_CERT_2G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_2G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_2G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_2G);//Added for test
			toRet=FAILED;
			//goto err;
		}
		//store 2g root cert
		offset=ROOT_CERT_BASE_2G;
		if(isFileExist(RS_ROOT_CERT_2G))
		{
			ret=storeFile(offset, RS_ROOT_CERT_2G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_2G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_2G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_2G);//Added for test
			toRet=FAILED;
			//goto err;
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		//store eth user cert
		offset=USER_CERT_BASE_ETH;
		if(isFileExist(RS_USER_CERT_ETH))
		{
			ret=storeFile(offset, RS_USER_CERT_ETH, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_ETH, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_ETH;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_ETH);//Added for test
			toRet=FAILED;
			//goto err;
		}
		//store eth root cert
		offset=ROOT_CERT_BASE_ETH;
		if(isFileExist(RS_ROOT_CERT_ETH))
		{
			ret=storeFile(offset, RS_ROOT_CERT_ETH, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_ETH, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_ETH;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_ETH);//Added for test
			toRet=FAILED;
			//goto err;
		}		
#endif

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeUserCert == 1)
	{		
		//store 5g user cert
		offset=USER_CERT_BASE_5G;
		if(isFileExist(RS_USER_CERT_5G))
		{
			ret=storeFile(offset, RS_USER_CERT_5G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_5G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_5G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_5G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		//store 2g user cert
		offset=USER_CERT_BASE_2G;
		if(isFileExist(RS_USER_CERT_2G))
		{
			ret=storeFile(offset, RS_USER_CERT_2G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_2G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_2G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_2G);//Added for test
			toRet=FAILED;
			//goto err;
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
				//store eth user cert
		offset=USER_CERT_BASE_ETH;
		if(isFileExist(RS_USER_CERT_ETH))
		{
			ret=storeFile(offset, RS_USER_CERT_ETH, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_ETH, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_ETH;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_ETH);//Added for test
			toRet=FAILED;
			//goto err;
		}
#endif

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeUserCert_5g == 1)
	{		
		//store 5g user cert
		offset=USER_CERT_BASE_5G;
		if(isFileExist(RS_USER_CERT_5G))
		{
			ret=storeFile(offset, RS_USER_CERT_5G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_5G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_5G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_5G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeUserCert_2g== 1)
	{
		//store 2g user cert
		offset=USER_CERT_BASE_2G;
		if(isFileExist(RS_USER_CERT_2G))
		{
			ret=storeFile(offset, RS_USER_CERT_2G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_2G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_2G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_2G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	if(storeUserCert_eth == 1)
	{
					//store eth user cert
		offset=USER_CERT_BASE_ETH;
		if(isFileExist(RS_USER_CERT_ETH))
		{
			ret=storeFile(offset, RS_USER_CERT_ETH, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT_ETH, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT_ETH;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT_ETH);//Added for test
			toRet=FAILED;
			//goto err;
		}
		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
#endif

	else if(storeRootCert == 1)
	{		
		//store 5g root cert
		offset=ROOT_CERT_BASE_5G;
		if(isFileExist(RS_ROOT_CERT_5G))
		{
			ret=storeFile(offset, RS_ROOT_CERT_5G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_5G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_5G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_5G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		//store 2g root cert
		offset=ROOT_CERT_BASE_2G;
		if(isFileExist(RS_ROOT_CERT_2G))
		{
			ret=storeFile(offset, RS_ROOT_CERT_2G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_2G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_2G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_2G);//Added for test
			toRet=FAILED;
			//goto err;
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		//store eth root cert
		offset=ROOT_CERT_BASE_ETH;
		if(isFileExist(RS_ROOT_CERT_ETH))
		{
			ret=storeFile(offset, RS_ROOT_CERT_ETH, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_ETH, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_ETH;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_ETH);//Added for test
			toRet=FAILED;
			//goto err;
		}		
#endif

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeRootCert_5g== 1)
	{		
		//store 5g root cert
		offset=ROOT_CERT_BASE_5G;
		if(isFileExist(RS_ROOT_CERT_5G))
		{
			ret=storeFile(offset, RS_ROOT_CERT_5G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_5G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_5G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_5G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeRootCert_2g == 1)
	{
		//store 2g root cert
		offset=ROOT_CERT_BASE_2G;
		if(isFileExist(RS_ROOT_CERT_2G))
		{
			ret=storeFile(offset, RS_ROOT_CERT_2G, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_2G, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_2G;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_2G);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	if(storeRootCert_eth == 1)
	{
		//store eth root cert
		offset=ROOT_CERT_BASE_ETH;
		if(isFileExist(RS_ROOT_CERT_ETH))
		{
			ret=storeFile(offset, RS_ROOT_CERT_ETH, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_ETH, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT_ETH;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT_ETH);//Added for test
			toRet=FAILED;
			//goto err;
		}
		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
#endif

	else if(loadCert == 1)
	{
		//load 5g user cert
		offset=USER_CERT_BASE_5G;
		ret=loadFile(RS_USER_CERT_5G, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no 5g user cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}

		//load 5g root cert
		offset=ROOT_CERT_BASE_5G;
		ret=loadFile(RS_ROOT_CERT_5G, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no 5g root cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}

		//load 2g user cert
		offset=USER_CERT_BASE_2G;
		ret=loadFile(RS_USER_CERT_2G, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no 2g user cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}

		//load 2g root cert
		offset=ROOT_CERT_BASE_2G;
		ret=loadFile(RS_ROOT_CERT_2G, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no 2g root cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
		//load eth user cert
		offset=USER_CERT_BASE_ETH;
		ret=loadFile(RS_USER_CERT_ETH, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no eth user cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}

		//load eth root cert
		offset=ROOT_CERT_BASE_ETH;
		ret=loadFile(RS_ROOT_CERT_ETH, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no eth root cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
		}
			
#endif
	}

	toRet=SUCCESS;

err:
	return toRet;
}

