#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <shared.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <utils.h>

#include <sysdeps/realtek/realtek.h>

#if 0
#define RTK_FIELD_OFFSET(type, field)       ((unsigned long)(long *)&(((type *)0)->field))
#define RTK_OFFSET_HW(field)               ((int)RTK_FIELD_OFFSET(HW_SETTING_T,field))
#define RTK_OFFSET_HW_WLAN(field)          ((int)RTK_FIELD_OFFSET(HW_WLAN_SETTING_T,field))

#define RTK_SIZE_HW(field)                 sizeof(((HW_SETTING_T *)0)->field)
#define RTK_SIZE_HW_WLAN(field)            sizeof(((HW_WLAN_SETTING_T *)0)->field)
#endif

static void
usage(void)
{
	fprintf(stderr, "usage: flash [get name] [set name value]  [all] \n");
	fprintf(stderr, "sizeof hw setting is %x \n",sizeof(HW_SETTING_T));
	exit(0);
}


int flash_get(char* name)
{
	unsigned int offset,size,i;
	MIB_TYPE_T type;
	unsigned char buff[MIB_BUFF_MAX_SIZE]={0};
	if(flash_get_mib_info(name,&offset,&size,&type)==0){
		rtk_flash_read(buff,offset,size);
		if(size>=MIB_BUFF_MAX_SIZE){
			fprintf(stderr,"buff oversize, need %d but max %d\n",size,MIB_BUFF_MAX_SIZE);
			return -1;
		}
		switch(type){
			case BYTE_T:
				printf("%s=%d\n",name,buff[0]);
				break;
			case STRING_T:
				printf("%s=%s\n",name,buff);
				break;
			case BYTE_ARRAY_T:
				printf("%s=",name);
				for(i=0;i<size;i++)
					printf("%02x",buff[i]);
				printf("\n");
				break;
			case WLAN_T:
				fprintf(stderr,"can not get total WLAN! try wlan0_name/wlan1_name!\n");
				return -1;

			default:
				fprintf(stderr,"invalid type %d\n",type);
				return -1;				
		}
		return 0;
	}
	return -1;
}

int flash_set(char* name,char* value)
{
	unsigned int offset,size,i;
	MIB_TYPE_T type;
	unsigned char buff[MIB_BUFF_MAX_SIZE]={0};
	unsigned char tmpBuf[16]={0};
	if(!value){
		fprintf(stderr,"invalid input %s\n",__FUNCTION__);
		return -1;
	}
	if(flash_get_mib_info(name,&offset,&size,&type)==0){
		switch(type){
			case BYTE_T:
				buff[0]=atoi(value);
				printf("set %s=%d\n",name,atoi(value));
				break;
			case STRING_T:
				strcpy(buff,value);
				printf("set %s=%s\n",name,buff);
				break;
			case BYTE_ARRAY_T:
				//%02x%02x...
				if(strlen(value)!=2*size){
					fprintf(stderr,"invalid input! length should be %d but now %d\n",2*size,strlen(value));
					return -1;
				}
				for(i=0;i<size;i++){
					bzero(tmpBuf,sizeof(tmpBuf));
                    memcpy(tmpBuf,value+i*2,2);
					buff[i]=(unsigned char)strtol(tmpBuf,NULL,16);					
				}
				printf("set %s=%s\n",name,value);				
				break;
			case WLAN_T:
					fprintf(stderr,"can not set WLAN\n");
				return -1;	
			default:
				fprintf(stderr,"invalid type %d\n",type);
				return -1;				
		}
		rtk_flash_write(buff,offset,size);
		return 0;
	}
	return -1;
}
int flash_dump()
{
	int i=0,j=0,k=0;

	for(i=0;hw_mib[i].name[0];i++){
		
		if(strcmp(hw_mib[i].name,"wlan")==0){
			char wlan_name[64]={0};
			for(j=0;j<NUM_WLAN_INTERFACE;j++){
				for(k=0;hw_wlan_mib[k].name[0];k++){
					sprintf(wlan_name,"wlan%d_%s",j,hw_wlan_mib[k].name);
					flash_get(wlan_name);
				}
			}
		}
		else
			flash_get(hw_mib[i].name);
	}
	
#ifdef BLUETOOTH_HW_SETTING_SUPPORT
	for(i=0;bluetooth_hw_mib[i].name[0];i++){
		char bluetooth_hw_name[64]={0};
		sprintf(bluetooth_hw_name,"bluetooth_%s",bluetooth_hw_mib[i].name);
		flash_get(bluetooth_hw_name);
	}
#endif
	return 0;
}
#ifdef RTCONFIG_BT_CONN
#define BT_CONFIG_FILE "/lib/firmware/rtlbt/rtl8822b_config"
static int dump_bt_config_file(void)
{
	int fd,size,i;
	unsigned char buffer[256];
	fd = open(BT_CONFIG_FILE,O_RDONLY);
	if(fd!=-1)
	{
		fprintf(stderr,"%s:\n",BT_CONFIG_FILE);
		size = read(fd,buffer,sizeof(buffer));
		for(i=0;i<size;i++)
		{
			fprintf(stderr,"%02x ",buffer[i]);
			if(((i+1)%16) == 0)
			{
				fprintf(stderr,"\n");
			}
		}
		fprintf(stderr,"\n");
		close(fd);
	}
	else
	{
		fprintf(stderr,"Failed to open Bluetooth config file!\n");
		return -1;
	}
}
#endif
int main(int argc, char **argv)
{
	char *name, *value, *buf;
	int size;
	/* Skip program name */
	--argc;
	++argv;

	if (!*argv) 
		usage();


	/* Process the remaining arguments. */
//	for (; *argv; argv++) {
		if (!strncmp(*argv, "get", 3)) {
			if (*++argv) {
				if ((value = flash_get(*argv)))
					printf("%s\n",value);
			}
		}
		else if (!strncmp(*argv, "set", 3)) {
			if (*++argv) {
				name=*argv;
				if(*++argv)
					value=*argv;				
				flash_set(name,value);
			}
		}
		else if (!strncmp(*argv, "all", 3)) {
			flash_dump();
		}
#ifdef RTCONFIG_BT_CONN
		else if (!strncmp(*argv, "dump_btconfig", strlen("dump_btconfig"))) {
			dump_bt_config_file();
		}
#endif
		return 0;
}
