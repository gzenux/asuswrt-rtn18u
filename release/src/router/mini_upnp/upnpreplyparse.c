
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#include "upnpreplyparse.h"
#include "minixml.h"

static void
NameValueParserStartElt(void * d, const char * name, int l)
{
    struct NameValueParserData * data = (struct NameValueParserData *)d;
    if(l>63)
        l = 63;
    memcpy(data->curelt, name, l);
    data->curelt[l] = '\0';
}

static void
NameValueParserGetData(void * d, const char * datas, int l)
{
    	struct NameValueParserData * data = (struct NameValueParserData *)d;
    	struct NameValue * nv;
	
    	nv = malloc(sizeof(struct NameValue));
	memset(nv, 0, sizeof(struct NameValue));
	nv->value = (char *) malloc(l+1);
	memset(nv->value, 0, l+1);
    	
    	strncpy(nv->name, data->curelt, 64);
    	memcpy(nv->value, datas, l);
    	LIST_INSERT_HEAD( &(data->head), nv, entries);
}

void ParseNameValue(const char * buffer, int bufsize,
                    struct NameValueParserData * data)
{
    struct xmlparser parser;
    LIST_INIT(&(data->head));
    /* init xmlparser object */
    parser.xmlstart = buffer;
    parser.xmlsize = bufsize;
    parser.data = data;
    parser.starteltfunc = NameValueParserStartElt;
    parser.endeltfunc = 0;
    parser.datafunc = NameValueParserGetData;
	parser.attfunc = 0;
    parsexml(&parser);
}

void ClearNameValueList(struct NameValueParserData * pdata)
{
    	struct NameValue * nv;
	
    	while((nv = pdata->head.lh_first) != NULL)
    	{
    		if (nv->value)
			free(nv->value);
        	LIST_REMOVE(nv, entries);
        	free(nv);
    	}
}

char * 
GetValueFromNameValueList(struct NameValueParserData * pdata,
                          const char * Name)
{
    struct NameValue * nv;
    char * p = NULL;
    for(nv = pdata->head.lh_first;
        (nv != NULL) && (p == NULL);
        nv = nv->entries.le_next)
    {
        if(strcmp(nv->name, Name) == 0)
            p = nv->value;
    }
    return p;
}

char *
GetValueFromNameValueListIgnoreNS(struct NameValueParserData * pdata,
                                  const char * Name)
{
	struct NameValue * nv;
	char * p = NULL;
	char * pname;
	for(nv = pdata->head.lh_first;
	    (nv != NULL) && (p == NULL);
		nv = nv->entries.le_next)
	{
		pname = strrchr(nv->name, ':');
		if(pname)
			pname++;
		else
			pname = nv->name;
		if(strcmp(pname, Name)==0)
			p = nv->value;
	}
	return p;
}

/* debug all-in-one function 
 * do parsing then display to stdout */
void DisplayNameValueList(char * buffer, int bufsize)
{
    struct NameValueParserData pdata;
    struct NameValue * nv;
    ParseNameValue(buffer, bufsize, &pdata);
    for(nv = pdata.head.lh_first;
        nv != NULL;
        nv = nv->entries.le_next)
    {
        printf("%s = %s\n", nv->name, nv->value);
    }
    ClearNameValueList(&pdata);
}

/* MUST free the returned buffer after this call */
char *mini_UPnPGetFirstElement(char *file_start, unsigned int len, char *tag_name, unsigned int tag_name_len)
{
	char * line;
	unsigned long file_end;
	unsigned long string_begin=0;
	unsigned long string_end=0;
	char *tag_name_first=NULL;
	char *tag_name_second=NULL;
	char *buf=NULL;
	unsigned int string_len=0;

	if (file_start == NULL || tag_name == NULL)
		return NULL;

	if (len <= 0 || tag_name_len <= 0)
		return NULL;

	tag_name_first = (char*)malloc(tag_name_len+3);
	if (tag_name_first == NULL)
		return NULL;
	memcpy(tag_name_first+1, tag_name, tag_name_len);
	tag_name_first[0] = '<';
	tag_name_first[tag_name_len+1] = '>';
	tag_name_first[tag_name_len+2] = 0;

	tag_name_second = (char*)malloc(tag_name_len+4);
	if (tag_name_second == NULL) {
		free(tag_name_first);
		return NULL;
	}
	memcpy(tag_name_second+2, tag_name, tag_name_len);
	tag_name_second[0] = '<';
	tag_name_second[1] = '/';
	tag_name_second[tag_name_len+2] = '>';
	tag_name_second[tag_name_len+3] = 0;
	
	line = file_start;
	file_end = (unsigned long)file_start + len;
	while ((unsigned long)line < (file_end-tag_name_len-3))
	{
		if (strncasecmp(line, tag_name_first, tag_name_len+2) == 0) {
			if (string_begin == 0) {
				string_begin = (unsigned long)line + tag_name_len + 2;
			}
			else {
				//DEBUG_ERR("Duplicated tag %s\n", tag_name_first);
				free(tag_name_first);
				free(tag_name_second);
				return NULL;
			}
		}
		else if (strncasecmp(line, tag_name_second, tag_name_len+3) == 0) {
			if (string_begin == 0) {
				//DEBUG_ERR("Missing tag %s\n", tag_name_first);
				free(tag_name_first);
				free(tag_name_second);
				return NULL;
			}
			else {
				string_end = (unsigned long)line;
				break;
			}
		}

		line++;
	}

	free(tag_name_first);
	free(tag_name_second);
	if (string_begin < string_end) {
		string_len = string_end - string_begin;
		buf = (char*)malloc(string_len+1);
		if (buf == NULL)
			return NULL;
		memcpy(buf, (char *)string_begin, string_len);
		buf[string_len] = 0;
		return buf;
	}
	else {
		//DEBUG_ERR("XML parse erroe!\n");
		return NULL;
	}
}

char *mini_UPnPGetFirstElementAndReturnAddr(char *file_start, unsigned int len, char *tag_name, unsigned int tag_name_len, char *buf)
{
	char * line;
	unsigned long file_end;
	unsigned long string_begin=0;
	unsigned long string_end=0;
	char *tag_name_first=NULL;
	char *tag_name_second=NULL;
	unsigned int string_len=0;
	char *end=NULL;
	unsigned char found=0;

	if (file_start == NULL || tag_name == NULL || buf == NULL)
		return NULL;

	if (len <= 0 || tag_name_len <= 0)
		return NULL;

	tag_name_first = (char*)malloc(tag_name_len+3);
	if (tag_name_first == NULL)
		return NULL;
	memcpy(tag_name_first+1, tag_name, tag_name_len);
	tag_name_first[0] = '<';
	tag_name_first[tag_name_len+1] = '>';
	tag_name_first[tag_name_len+2] = 0;

	tag_name_second = (char*)malloc(tag_name_len+4);
	if (tag_name_second == NULL) {
		free(tag_name_first);
		return NULL;
	}
	memcpy(tag_name_second+2, tag_name, tag_name_len);
	tag_name_second[0] = '<';
	tag_name_second[1] = '/';
	tag_name_second[tag_name_len+2] = '>';
	tag_name_second[tag_name_len+3] = 0;
	
	line = file_start;
	file_end = (unsigned long)file_start + len;
	while ((unsigned long)line < (file_end-tag_name_len-3))
	{
		if (strncasecmp(line, tag_name_first, tag_name_len+2) == 0) {
			if (string_begin == 0) {
				string_begin = (unsigned long)line + tag_name_len + 2;
			}
			else {
				//DEBUG_ERR("Duplicated tag %s\n", tag_name_first);
				free(tag_name_first);
				free(tag_name_second);
				return NULL;
			}
		}
		else if (strncasecmp(line, tag_name_second, tag_name_len+3) == 0) {
			if (string_begin == 0) {
				//DEBUG_ERR("Missing tag %s\n", tag_name_first);
				free(tag_name_first);
				free(tag_name_second);
				return NULL;
			}
			else {
				string_end = (unsigned long)line;
				end = (char *)(line + (tag_name_len+3));
				found = 1;
				break;
			}
		}

		line++;
	}

	free(tag_name_first);
	free(tag_name_second);
	if (string_begin < string_end) {
		string_len = string_end - string_begin;
		memcpy(buf, (char *)string_begin, string_len);
		buf[string_len] = 0;
		return end;
	}
	else {
		if (found) {
			buf[0] = 0;
			return end;
		}
		else
			return NULL;
	}
}

#ifndef __ECOS
char *mini_UPnP_UploadXML(char *file_path)
{
	FILE *fp = NULL;
	int retVal = 0;
	struct stat file_info;
	char *buf=NULL;
	unsigned int fileLen=0;
	unsigned int num_read=0;
	char *membuf=NULL;

	buf = file_path;
	retVal = stat(buf, &file_info );
	if ( retVal == -1 ) {
		//printf("Failed to get file info. EXITING\n");
		return NULL;
	}
	
	fileLen = file_info.st_size;
	if ( ( fp = fopen( buf, "rb" ) ) == NULL ) {
		printf("Failed to open file [%s]. EXITING\n", buf);
		return NULL;
	}

	if ( ( membuf = ( char * )malloc( fileLen + 1 ) ) == NULL ) {
            	fclose( fp );
		printf("mini_UPnP_UploadXML Out of memory! EXITING\n");
            	return NULL;
	}

	num_read = fread( membuf, 1, fileLen, fp );
	if ( num_read != fileLen ) {
            	fclose( fp );
            	free( membuf );
            	printf("mini_UPnP_UploadXML File length mismatched! EXITING\n");
		return NULL;
	}

	membuf[fileLen] = 0;
	fclose( fp );

	return membuf;
}
#endif

char *get_token(char *data, char *token)
{
	char *ptr=data;
	int len=0, idx=0;

	while (*ptr && *ptr != '\n' ) {
		if (*ptr == '=') {
			if (len <= 1)
				return NULL;
			memcpy(token, data, len);

			/* delete ending space */
			for (idx=len-1; idx>=0; idx--) {
				if (token[idx] !=  ' ')
					break;
			}
			token[idx+1] = '\0';

			return ptr+1;
		}
		len++;
		ptr++;
	}
	return NULL;
}

int get_value(char *data, char *value)
{
	char *ptr=data;	
	int len=0, idx, i;

	while (*ptr && *ptr != '\n' && *ptr != '\r') {
		len++;
		ptr++;
	}

	/* delete leading space */
	idx = 0;
	while (len-idx > 0) {
		if (data[idx] != ' ') 
			break;	
		idx++;
	}
	len -= idx;

	/* delete bracing '"' */
	if (data[idx] == '"') {
		for (i=idx+len-1; i>idx; i--) {
			if (data[i] == '"') {
				idx++;
				len = i - idx;
			}
			break;
		}
	}

	if (len > 0) {
		memcpy(value, &data[idx], len);
		value[len] = '\0';
	}
	return len;
}

