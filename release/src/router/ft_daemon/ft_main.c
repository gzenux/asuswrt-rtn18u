#include "ft_main.h"

CTX_Tp pGlobalCtx=NULL;

/* debug function */
void dump_mem(char *title, u8 *ptr, int len)
{
#ifdef DEBUG_DUMP
	int ii;

	if (pGlobalCtx && pGlobalCtx->debug_level>=4)
	{
		printf("%s (length=%d)\n", title, len);
		for (ii=0; ii<len; ii++)
		{
			printf("%02x ", ptr[ii]);
			if (ii % 16 == 15)
				printf("\n");
		}
		if (ii % 16 != 0)
			printf("\n");
	}
#endif
}

/* key wrap/unwrap */
int aes_wrap(u8 *plain, u8 *cipher, u8 *kek, int n)
{
	AES_KEY key;
	u8 *a, *r, b[16];
	int j, i;
	
	if (AES_set_encrypt_key(kek, 128, &key) < 0)
	{
		FT_ERROR("aes_set_key failed\n");
		return -1;	
	}
	
	a = cipher;
	r = cipher + 8;
	
	// 1) Initialize variables.
	memset(a, 0xa6, 8);
	memcpy(r, plain, n*8);
	
	// 2) Calculate intermediate values.
	for (j=0; j<=5; j++)
	{
		r = cipher + 8;
		for (i=1; i<=n; i++)
		{
			memcpy(b, a, 8);
			memcpy(b+8, r, 8);
			AES_encrypt(b, b, &key);
			memcpy(a, b, 8);
			a[7] ^= (n*j+i);
			memcpy(r, b+8, 8);
			r += 8;
		}
	}
	
	return 0;
}

int aes_unwrap(u8 *cipher, u8 *plain, u8 *kek, int n)
{
	AES_KEY key;
	u8 a[8], *r, b[16];
	int j, i;
	
	if (AES_set_decrypt_key(kek, 128, &key) < 0)
	{
		FT_ERROR("aes_set_key failed\n");
		return -1;	
	}
	
	// 1) Initialize variables.
	memcpy(a, cipher, 8);
	r = plain;
	memcpy(r, cipher+8, n*8);
	
	// 2) Calculate intermediate values.
	for (j=5; j>=0; j--)
	{
		r = plain + (n-1)*8;
		for (i=n; i>=1; i--)
		{
			memcpy(b, a, 8);
			b[7] ^= (n*j+i);
			memcpy(b+8, r, 8);
			AES_decrypt(b, b, &key);
			memcpy(a, b, 8);
			memcpy(r, b+8, 8);
			r -= 8;
		}
	}
	
	// 3) Output results.
	for (i=0; i<7; i++)
		if (a[i] != 0xa6)
			return -1;
	
	return 0;
}

/* wlan ioctl socket */
static int init_wlan_socket(CTX_Tp pCtx)
{
	struct ifreq ifr;
	int i;

	pCtx->wlan_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (pCtx->wlan_socket < 0)
	{
		FT_ERROR("wlan socket[PF_PACKET] failed\n");
		return -1;
	}

	for (i=0; i<pCtx->wlan_intf_num; i++)
	{
		FT_DEBUG("init wifi: %s (%d/%d)\n", pCtx->wlan_intf_name[i], i+1, pCtx->wlan_intf_num);

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, pCtx->wlan_intf_name[i], IFNAMSIZ);
		if (ioctl(pCtx->wlan_socket, SIOCGIFHWADDR, &ifr) < 0) {
			FT_ERROR("%s ioctl[SIOCGIFHWADDR] failed! (%d)\n", pCtx->wlan_intf_name[i], i);
			close(pCtx->wlan_socket);
			return -1;
		}
		memcpy(pCtx->wlan_intf_addr[i], ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		FT_DEBUG("  %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(pCtx->wlan_intf_addr[i]));
	}
	
	return 0;
}

static int wlioctl_get_mib(CTX_Tp pCtx, char *intfName, char *mibName, int *result)
{
    struct iwreq wrq;
	unsigned char tmp[10];

	/* Set device name */	
	strcpy(wrq.ifr_name, intfName);	
	strcpy(tmp, mibName);
	
    wrq.u.data.pointer = tmp;
    wrq.u.data.length = strlen(tmp);

	/* Do the request */
	if(ioctl(pCtx->wlan_socket, SIOCGIWRTLGETMIB, &wrq) < 0)
	{
		FT_ERROR("get_mib %s failed\n", mibName);
		return -1;	
	}
  	
	*result = *(unsigned int*)tmp;
	return 0;
}

/* L2 packet handler */
static int init_eth_socket(CTX_Tp pCtx)
{
	struct ifreq ifr;
	struct sockaddr_ll ll;

	pCtx->socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RRB));
	if (pCtx->socket < 0)
	{
		FT_ERROR("socket[PF_PACKET] failed\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pCtx->eth_intf_name, IFNAMSIZ);
	while (ioctl(pCtx->socket, SIOCGIFINDEX, &ifr) < 0)
	{
		FT_ERROR("%s ioctl[SIOCGIFINDEX] failed!\n", pCtx->eth_intf_name);
		close(pCtx->socket);
		return -1;
	}
	pCtx->eth_intf_index = ifr.ifr_ifindex;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = pCtx->eth_intf_index;
	ll.sll_protocol = htons(ETH_P_RRB);
	if (bind(pCtx->socket, (struct sockaddr *)&ll, sizeof(ll)) < 0)
	{
		FT_ERROR("bind[PF_PACKET] failed\n");
		close(pCtx->socket);
		return -1;
	}

	if (ioctl(pCtx->socket, SIOCGIFHWADDR, &ifr) < 0) {
		FT_ERROR("ioctl[SIOCGIFHWADDR] failed!\n");
		close(pCtx->socket);
		return -1;
	}
	memcpy(pCtx->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	
	return 0;
}

static int l2_packet_send(CTX_Tp pCtx, u8 *src, u8 *dest, u8 *data, int data_len)
{
	struct l2_ethhdr *buf;
	int ret, size;
	
	size = sizeof(*buf) + data_len;
	buf = malloc(size);
	if (buf == NULL)
		return -1;
	
	memcpy(buf->h_dest, dest, ETH_ALEN);
	memcpy(buf->h_source, src, ETH_ALEN);
	buf->h_proto = htons(ETH_P_RRB);
	memcpy(buf + 1, data, data_len);

	dump_mem("FRAME", (u8 *)buf, size);
	if ((ret = send(pCtx->socket, buf, sizeof(*buf)+data_len, 0)) < 0)
	{
		FT_ERROR("ERROR! send() call failed (Error No: %d \"%s\").\n", errno, strerror(errno));
		free(buf);
		return -1;
	}
	FT_TRACE("  Send success (%d)\n", ret);
	
	free(buf);
	return 0;
}

static int dot11r_push_pmk_r1(CTX_Tp pCtx, u8 *src, R1KH_Tp r1kh, u8 *data, int length)
{
	struct ft_r0kh_r1kh_push_frame frame;
	int size = offsetof(struct ft_r0kh_r1kh_push_frame, pad) - offsetof(struct ft_r0kh_r1kh_push_frame, timestamp);
	
	if (length != size)
	{
		FT_ERROR("R1KH push frame size mismatch (%d, should be %d)\n", length, size);
		return -1;
	}
	
	frame.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame.packet_type = FT_PACKET_R0KH_R1KH_PUSH;
	frame.data_length = htole16(FT_R0KH_R1KH_PUSH_DATA_LEN);
	memcpy(frame.ap_address, src, ETH_ALEN);
	aes_wrap((u8 *)data, (u8 *)frame.timestamp, r1kh->key, (FT_R0KH_R1KH_PUSH_DATA_LEN+7)/8);

	FT_TRACE("TX Key Push Frame to R1KH %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(r1kh->addr));
	l2_packet_send(pCtx, src, r1kh->addr, (unsigned char *)&frame, sizeof(frame));

	return 0;
}

static int dot11r_pull_pmk_r1(CTX_Tp pCtx, u8 *src, R0KH_Tp r0kh, u8 *data, int length)
{
	struct ft_r0kh_r1kh_pull_frame frame;
	int size = offsetof(struct ft_r0kh_r1kh_pull_frame, pad) - offsetof(struct ft_r0kh_r1kh_pull_frame, nonce);

	if (length != size)
	{
		FT_ERROR("R1KH pull frame size mismatch (%d, should be %d)\n", length, size);
		return -1;
	}
	
	frame.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame.packet_type = FT_PACKET_R0KH_R1KH_PULL;
	frame.data_length = htole16(FT_R0KH_R1KH_PULL_DATA_LEN);
	memcpy(frame.ap_address, src, ETH_ALEN);
	aes_wrap((u8 *)data, (u8 *)frame.nonce, r0kh->key, (FT_R0KH_R1KH_PULL_DATA_LEN+7)/8);

	FT_TRACE("TX Key Pull Frame to R0KH %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(r0kh->addr));
	l2_packet_send(pCtx, src, r0kh->addr, (unsigned char *)&frame, sizeof(frame));

	return 0;
}

static int dot11r_resp_pmk_r1(CTX_Tp pCtx, u8 *src, R1KH_Tp r1kh, u8 *data, int length)
{
	struct ft_r0kh_r1kh_resp_frame frame;
	int size = offsetof(struct ft_r0kh_r1kh_resp_frame, pad) - offsetof(struct ft_r0kh_r1kh_resp_frame, nonce);

	if (length != size)
	{
		FT_ERROR("R1KH resp frame size mismatch (%d, should be %d)\n", length, size);
		return -1;
	}
	
	frame.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame.packet_type = FT_PACKET_R0KH_R1KH_RESP;
	frame.data_length = htole16(FT_R0KH_R1KH_RESP_DATA_LEN);
	memcpy(frame.ap_address, src, ETH_ALEN);
	aes_wrap((u8 *)data, (u8 *)frame.nonce, r1kh->key, (FT_R0KH_R1KH_RESP_DATA_LEN+7)/8);

	FT_TRACE("TX Key Resp Frame to R1KH %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(r1kh->addr));
	l2_packet_send(pCtx, src, r1kh->addr, (unsigned char *)&frame, sizeof(frame));

	return 0;
}

static int dot11r_send_ft_action(CTX_Tp pCtx, u8 *src, u8 *dest, u8 *data, int length, u8 type)
{
	struct l2_ethhdr *buf;
	struct ft_rrb_frame *rrb;
	u8 *pos;
	int ret, size;
	
	size = sizeof(*buf) + sizeof(*rrb) + length;
	buf = malloc(size);
	if (buf == NULL)
		return -1;
	rrb = (struct ft_rrb_frame *)(buf + 1);
	pos = (u8 *)(rrb + 1);
	
	//prepare l2 header
	memcpy(buf->h_dest, dest, ETH_ALEN);
	memcpy(buf->h_source, src, ETH_ALEN);
	buf->h_proto = htons(ETH_P_RRB);
	//prepare rrb header
	rrb->frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	rrb->packet_type = type;
	rrb->action_length = htole16(length);
	memcpy(rrb->ap_address, src, ETH_ALEN);
	//copy action content
	memcpy(pos, data, length);

	//send frame
	FT_TRACE("TX FT Action Frame to %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(buf->h_dest));
	dump_mem("ACTION", (u8 *)buf, size);
	if ((ret = send(pCtx->socket, buf, size, 0)) < 0)
	{
		FT_ERROR("ERROR! send() call failed (Error No: %d \"%s\").\n", errno, strerror(errno));
		free(buf);
		return -1;
	}
	FT_TRACE("  Send success (%d)\n", ret);

	free(buf);
	return 0;
}

static int dot11r_send_inform(CTX_Tp pCtx, u8 *src, u8 *data, u8 type, u8 *intf_name)
{
	struct ft_inform_frame frame, f;
	struct timeval tv;
	R1KH_Tp r1kh = pCtx->r1kh_list;

	frame.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame.packet_type = FT_PACKET_INFORM;
	frame.data_length = htole16(FT_INFORM_DATA_LEN);
	memcpy(frame.ap_address, src, ETH_ALEN);

	memset(&f, 0, sizeof(f));
	gettimeofday(&tv, NULL);
	FT_DEBUG("timestamp: %d\n", tv.tv_sec);
	f.timestamp = htole32((u32)tv.tv_sec);
	f.inform_type = type;
	memcpy(f.addr, data, ETH_ALEN);

	while (r1kh && !strcmp(r1kh->intf, intf_name))
	{
		aes_wrap((u8 *)&f.timestamp, (u8 *)&frame.timestamp, r1kh->key, (FT_INFORM_DATA_LEN+7)/8);

		FT_TRACE("TX Inform(%d) Frame to R1KH %02x:%02x:%02x:%02x:%02x:%02x\n", type, MAC2STR(r1kh->addr));
		l2_packet_send(pCtx, src, r1kh->addr, (unsigned char *)&frame, sizeof(frame));

		r1kh = r1kh->next;
	}

	return 0;
}
/* pid file handler */
static int pidfile_acquire(char *pidfile)
{
	int pid_fd;

	if(pidfile == NULL)
		return -1;

	pid_fd = open(pidfile, O_CREAT | O_WRONLY, 0644);
	if (pid_fd < 0)
		FT_DEBUG("Unable to open pidfile %s\n", pidfile);
	else
		lockf(pid_fd, F_LOCK, 0);

	return pid_fd;
}

static void pidfile_write_release(int pid_fd)
{
	FILE *out;

	if(pid_fd < 0)
		return;

	if((out = fdopen(pid_fd, "w")) != NULL) {
		fprintf(out, "%d\n", getpid());
		fclose(out);
	}
	lockf(pid_fd, F_UNLCK, 0);
	close(pid_fd);
}

static int RegisterPID(CTX_Tp pCtx)
{
	struct iwreq wrq;
	pid_t pid=getpid();
	int i;

	wrq.u.data.pointer = (caddr_t)&pid;
	wrq.u.data.length = sizeof(pid_t);
	FT_DEBUG("Register PID %d\n", pid);

	for (i=0; i<pCtx->wlan_intf_num; i++)
	{
		/* Get wireless name */
		memset(wrq.ifr_name, 0, sizeof wrq.ifr_name);
		strncpy(wrq.ifr_name, pCtx->wlan_intf_name[i], IFNAMSIZ);
		
		if(ioctl(pCtx->wlan_socket, SIOCSIWRTLSETFTPID, &wrq) < 0)
		{
			FT_ERROR("RegisterPID failed\n");
			return -1;
		}
	}
	
	return 0;
}

/* Key holder config handler */
static int register_r0kh(CTX_Tp pCtx, int act, u8 *addr, u8 *id, u8 *key, u8 *intf)
{
	R0KH_Tp r0kh, prev=NULL;
	
	if (pCtx == NULL)
	{
		FT_ERROR("CTX is not initialized.");
		return -1;
	}
	
	FT_DEBUG("%s[R0KH] %02x:%02x:%02x:%02x:%02x:%02x %s\n", (act==FT_KH_ADD)?"+":"-", MAC2STR(addr), id);
	if (FT_KH_ADD == act)
	{
		// check if address already exists
		r0kh = pCtx->r0kh_list;
		while (r0kh)
		{
			if (!memcmp(r0kh->addr, addr, ETH_ALEN) && !strcmp(r0kh->intf, intf))
			{
				if (!strcmp(r0kh->id, id))
				{
					FT_DEBUG("ADD r0kh: %02x:%02x:%02x:%02x:%02x:%02x already exists\n", MAC2STR(addr));
					return 1;
				}
				else
				{
					FT_DEBUG("Update r0kh: %02x:%02x:%02x:%02x:%02x:%02x %s\n", MAC2STR(addr), id);
					strcpy(r0kh->id, id);
					r0kh->id_len = strlen(id);
					memcpy(r0kh->key, key, 16);
					return 0;
				}
			}
			r0kh = r0kh->next;
		}

		r0kh = malloc(sizeof(*r0kh));
		if (r0kh == NULL)
			return -1;
		
		memset(r0kh, 0, sizeof(*r0kh));
		memcpy(r0kh->addr, addr, ETH_ALEN);
		memcpy(r0kh->id, id, strlen(id));
		r0kh->id_len = strlen(id);
		memcpy(r0kh->key, key, 16);
		strncpy(r0kh->intf, intf, IFNAMSIZ);

		r0kh->next = pCtx->r0kh_list;
		pCtx->r0kh_list = r0kh;
		FT_DEBUG("ADD r0kh: %02x:%02x:%02x:%02x:%02x:%02x %s\n", MAC2STR(addr), intf);
	}
	else if (FT_KH_DEL == act)
	{
		r0kh = pCtx->r0kh_list;
		while (r0kh)
		{
			if (!memcmp(r0kh->addr, addr, ETH_ALEN))
			{
				prev->next = r0kh->next;
				free(r0kh);
				FT_DEBUG("DEL r0kh: %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(addr));
				return 1;
			}
			prev = r0kh;
			r0kh = r0kh->next;
		}
	}
	else
		FT_ERROR("Incorrect KH action\n");
	
	return 0;
}

static int register_r1kh(CTX_Tp pCtx, int act, u8 *addr, u8 *id, u8 *key, u8 *intf)
{
	R1KH_Tp r1kh, prev=NULL;
	
	if (pCtx == NULL)
	{
		FT_ERROR("CTX is not initialized.");
		return -1;
	}
	
	FT_DEBUG("%s[R1KH] %02x:%02x:%02x:%02x:%02x:%02x\n", (act==FT_KH_ADD)?"+":"-", MAC2STR(addr));
	if (FT_KH_ADD == act)
	{
		// check if address already exists
		r1kh = pCtx->r1kh_list;
		while (r1kh)
		{
			if (!memcmp(r1kh->addr, addr, ETH_ALEN) && !strcmp(r1kh->intf, intf))
			{
				FT_DEBUG("ADD r1kh: %02x:%02x:%02x:%02x:%02x:%02x already exists\n", MAC2STR(addr));
				return 1;
			}
			r1kh = r1kh->next;
		}
		
		// new address
		r1kh = malloc(sizeof(*r1kh));
		if (r1kh == NULL)
			return -1;
		
		memset(r1kh, 0, sizeof(*r1kh));
		memcpy(r1kh->addr, addr, ETH_ALEN);
		memcpy(r1kh->id, id, FT_R1KH_ID_LEN);
		memcpy(r1kh->key, key, 16);
		strncpy(r1kh->intf, intf, IFNAMSIZ);

		r1kh->next = pCtx->r1kh_list;
		pCtx->r1kh_list = r1kh;
		FT_DEBUG("ADD r1kh: %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x %s\n", MAC2STR(addr), MAC2STR(id), intf);
	}
	else if (FT_KH_DEL == act)
	{
		r1kh = pCtx->r1kh_list;
		while (r1kh)
		{
			if (!memcmp(r1kh->addr, addr, ETH_ALEN))
			{
				if (prev)
					prev->next = r1kh->next;
				else
					pCtx->r1kh_list = r1kh->next;
				free(r1kh);
				FT_DEBUG("DEL r1kh: %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(addr));
				return 1;
			}
			prev = r1kh;
			r1kh = r1kh->next;
		}
	}
	else
		FT_ERROR("Incorrect KH action\n");
	
	return 0;
}

int parse_mac(const char *str, char *addr)
{
	int i;

	i = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
//	FT_DEBUG("  (%d) %02x-%02x-%02x-%02x-%02x-%02x\n", i, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	
	if (i != ETH_ALEN)
		return -1;
	return 0;
}

static int parse_key(char *str, u8 *key)
{
	int i, j;
	u8 c;
	
	memset(key, 0, 16);
	for (i=0; i<16; i++)
	{
		for (j=0; j<2; j++)
		{
			c = str[i*2+j];
			if (c>='0' && c<='9')
				key[i] += (c - '0');
			else if (c>='a' && c<='f')
				key[i] += (c - 'a' + 10);
			else if (c>='A' && c<='F')
				key[i] += (c - 'A' + 10);
			else
			{
				FT_ERROR("invalid hex string: %c\n", c);
				return -1;
			}
			if (j == 0)
				key[i] *= 16;;
		}
		//FT_DEBUG2("%02x ", key[i]);
		// if (i==15) FT_DEBUG2("\n");
	}
	
	return 0;
}

static int CalcMD5(char *in, char *key)
{
	MD5_CTX mc;
	unsigned char final[16];
	int ii;
	
	MD5_Init(&mc);
	MD5_Update(&mc, in, strlen(in));
	MD5_Final(key, &mc);

	return 0;
}

static int parse_r0kh(char *line, int act)
{
	char mac[ETH_ALEN], id[FT_R0KH_ID_MAX_LEN+1], key[16], intf[IFNAMSIZ+1];
	char *pos, *next;
	
	// MAC address
	pos = line;
	next = strchr(pos, ' ');
	if (next)
		*next++ = '\0';
	if (next==NULL || parse_mac(pos, mac)<0)
	{
		FT_ERROR("R0KH: invalid mac address: %s", pos);
		return -1;
	}
	
	// Network Access Server ID
	pos = next;
	next = strchr(pos, ' ');
	if (next)
		*next++ = '\0';
	if (strlen(pos)>FT_R0KH_ID_MAX_LEN || strlen(pos)<1)
	{
		FT_ERROR("R0KH: invalid length of ID: %d\n", strlen(pos));
		return -1;
	}
	memset(id, 0, sizeof(id));
	memcpy(id, pos, FT_R0KH_ID_MAX_LEN);
	
	// Key
	pos = next;
	if (pos[0] == '\"') //passphrase
	{
		pos++;
		next = strchr(pos, '\"');
		if (next)
			*next++ = '\0';
		else
		{
			FT_ERROR("R0KH: invalid passphrase\n");
			return -1;
		}
		next = strchr(next, ' ');
		if (next)
			*next++ = '\0';
		CalcMD5(pos, key);
	}
	else //hex key
	{
		next = strchr(pos, ' ');
		if (next)
			*next++ = '\0';
		if (parse_key(pos, key))
		{
			FT_ERROR("R0KH: invalid key string: %d\n", strlen(pos));
			return -1;
		}
	}

	// Interface name
	pos = next;
	if (pos==NULL)
	{
		FT_ERROR("R0KH: interface name is not set\n");
		return -1;
	}
	next = strchr(pos, '\r');
	if (next)
		*next++ = '\0';
	next = strchr(pos, '\n');
	if (next)
		*next++ = '\0';
	next = strchr(pos, ' ');
	if (next)
		*next++ = '\0';
	if (strlen(pos)>IFNAMSIZ || strlen(pos)<1)
	{
		FT_ERROR("R0KH: invalid interface name: %s\n", pos);
		return -1;
	}
	strcpy(intf, pos);
	
	// register R0KH
	register_r0kh(pGlobalCtx, act, mac, id, key, intf);
	
	return 0;
}

static int parse_r1kh(char *line, int act)
{
	char mac[ETH_ALEN], id[FT_R1KH_ID_LEN], key[16], intf[IFNAMSIZ+1];
	char *pos, *next, push;
	
	// MAC address
	pos = line;
	next = strchr(pos, ' ');
	if (next)
		*next++ = '\0';
	if (next==NULL || parse_mac(pos, mac))
	{
		FT_ERROR("R1KH: invalid mac address: %s\n", pos);
		return -1;
	}

	// R1KH-ID
	pos = next;
	next = strchr(pos, ' ');
	if (next)
		*next++ = '\0';
	if (next==NULL || parse_mac(pos, id))
	{
		FT_ERROR("R1KH: invalid R1KH ID: %s\n", pos);
		return -1;
	}
	
	// Key
	pos = next;
	if (pos[0] == '\"') //passphrase
	{
		pos++;
		next = strchr(pos, '\"');
		if (next)
			*next++ = '\0';
		else
		{
			FT_ERROR("R1KH: invalid passphrase\n");
			return -1;
		}
		next = strchr(next, ' ');
		if (next)
			*next++ = '\0';
		CalcMD5(pos, key);
	}
	else //hex key
	{
		next = strchr(pos, ' ');
		if (next)
			*next++ = '\0';
		if (parse_key(pos, key))
		{
			FT_ERROR("R1KH: invalid key string: %s\n", pos);
			return -1;
		}
	}
	
	// Interface name
	pos = next;
	if (pos==NULL)
	{
		FT_ERROR("R0KH: interface name is not set\n");
		return -1;
	}
	next = strchr(pos, '\r');
	if (next)
		*next++ = '\0';
	next = strchr(pos, '\n');
	if (next)
		*next++ = '\0';
	next = strchr(pos, ' ');
	if (next)
		*next++ = '\0';
	if (strlen(pos)>IFNAMSIZ || strlen(pos)<1)
	{
		FT_ERROR("R1KH: invalid interface name: %s\n", pos);
		return -1;
	}
	strcpy(intf, pos);
	
	// register R1KH
	register_r1kh(pGlobalCtx, act, mac, id, key, intf);

	return 0;
}

static R0KH_Tp search_r0kh_by_id(CTX_Tp pCtx, u8 *id)
{
	R0KH_Tp r0kh=pCtx->r0kh_list;
	
	while (r0kh)
	{
		if (!strcmp(r0kh->id, id))
			return r0kh;
		r0kh = r0kh->next;
	}
	
	return NULL;
}

static R0KH_Tp search_r0kh_by_addr(CTX_Tp pCtx, u8 *addr, u8 *intf_name)
{
	R0KH_Tp r0kh=pCtx->r0kh_list;
	
	while (r0kh)
	{
		if (!memcmp(r0kh->addr, addr, ETH_ALEN) && !strcmp(r0kh->intf, intf_name))
			return r0kh;
		r0kh = r0kh->next;
	}
	
	return NULL;
}

static R1KH_Tp search_r1kh_by_addr(CTX_Tp pCtx, u8 *addr, u8 *intf_name)
{
	R1KH_Tp r1kh=pCtx->r1kh_list;
	
	while (r1kh)
	{
		if (!memcmp(r1kh->addr, addr, ETH_ALEN) && !strcmp(r1kh->intf, intf_name))
			return r1kh;
		r1kh = r1kh->next;
	}
	
	return 0;
}

static int clear_config(CTX_Tp pCtx)
{
	R0KH_Tp r0kh;
	R1KH_Tp r1kh;
	
	if (pCtx == NULL)
	{
		FT_ERROR("CTX is not initialized.");
		return -1;
	}
	
	r0kh = pCtx->r0kh_list;
	while (r0kh)
	{
		pCtx->r0kh_list = r0kh->next;
		free(r0kh);
		r0kh = pCtx->r0kh_list;
	}

	r1kh = pCtx->r1kh_list;
	while (r1kh)
	{
		pCtx->r1kh_list = r1kh->next;
		free(r1kh);
		r1kh = pCtx->r1kh_list;
	}

	return 0;
}

static int read_config(CTX_Tp pCtx)
{
	FILE *fd;
	char buf[512], *pos;
	int act;
	
	if ((fd = fopen(pCtx->config_filename, "r")) == NULL)
	{
		FT_ERROR("open config(%s) fail!\n", pCtx->config_filename);
		return -1;
	}
	
	while (fgets(buf, sizeof(buf), fd) != NULL)
	{
		FT_DEBUG("line: %s", buf);

		if ((buf[0]=='#') || ((buf[0]=='\n')))
			continue;

		if (buf[0]=='-')
			act = FT_KH_DEL;
		else
			act = FT_KH_ADD;

		pos = strchr(buf, '=');
		if (pos == NULL)
		{
			FT_ERROR("invalid line in %s\n", pCtx->config_filename);
			continue;
		}
		*pos++ = '\0';

		if (strstr(buf, "r0kh"))
			parse_r0kh(pos, act);
		else if (strstr(buf, "r1kh"))
			parse_r1kh(pos, act);
		else
			FT_ERROR("invalid key holder\n", buf);
	}

	fclose(fd);
	return 0;
}

static void dump_KH(CTX_Tp pCtx)
{
	R0KH_Tp r0kh=pCtx->r0kh_list;
	R1KH_Tp r1kh=pCtx->r1kh_list;
	int i;
	
	printf("[R0KH]\n");
	while (r0kh)
	{
		printf("  %02x:%02x:%02x:%02x:%02x:%02x %s(%d) ", MAC2STR(r0kh->addr), r0kh->id, r0kh->id_len);
		for (i=0; i<16; i++)
			printf("%02x", r0kh->key[i]);
		printf(" %s\n", r0kh->intf);
		r0kh = r0kh->next;
	}
	printf("[R1KH]\n");
	while (r1kh)
	{
		printf("  %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x ", MAC2STR(r1kh->addr), MAC2STR(r1kh->id));
		for (i=0; i<16; i++)
			printf("%02x", r1kh->key[i]);
		printf(" %s\n", r1kh->intf);
		r1kh = r1kh->next;
	}
}

/* find wlan interface */
u8 *find_wlan_addr_by_name(CTX_Tp pCtx, u8 *name)
{
	int i;

	for (i=0; i<pCtx->wlan_intf_num; i++)
	{
		if (!strcmp(name, pCtx->wlan_intf_name[i]))
			return pCtx->wlan_intf_addr[i];
	}
	
	return NULL;
}

char *find_wlan_name_by_addr(CTX_Tp pCtx, u8 *addr)
{
	int i;

	for (i=0; i<pCtx->wlan_intf_num; i++)
	{
		if (!memcmp(addr, pCtx->wlan_intf_addr[i], ETH_ALEN))
			return pCtx->wlan_intf_name[i];
	}
	
	return NULL;
}

/* event handler */
static int handleDrvEvent(CTX_Tp pCtx, char *intf_name)
{
	struct iwreq wrq;
	unsigned char buf[MSGLEN];
	u8 *src_addr;

	memset(wrq.ifr_name, 0, sizeof wrq.ifr_name);
  	strncpy(wrq.ifr_name, intf_name, IFNAMSIZ);
	src_addr = find_wlan_addr_by_name(pCtx, intf_name);

	do
	{
		wrq.u.data.pointer = (caddr_t)buf;
		wrq.u.data.length = sizeof(buf);
		buf[0] = DOT11_EVENT_FT_GET_EVENT;
		
		// get event from driver
		if (ioctl(pCtx->wlan_socket, SIOCGIFTGETEVENT, &wrq) < 0)
		{
			FT_ERROR("%s ioctl[SIOCGIFTGETEVENT] failed!\n", intf_name);
			return -1;
		}

		FT_DEBUG("Wlan Interface: %s\n", intf_name);
		FT_DEBUG("  EventId: %d\n", buf[0]);
		FT_DEBUG("  IsMoreEvent: %d\n", buf[1]);

		// process event
		switch (buf[0])
		{
			case DOT11_EVENT_FT_IMD_ASSOC_IND:
				FT_DEBUG("[EVENT_FT_IMD_ASSOC_IND]\n");
			{
				R1KH_Tp r1kh = pCtx->r1kh_list;
				DOT11_FT_IMD_ASSOC_IND *ind;
				DOT11_FT_GET_KEY *getkey;
				DOT11_FT_GET_KEY_PUSH *push;
				DOT11_FT_KEY_EXPIRE_IND *exp;
				u8 staAddr[ETH_ALEN];
				struct timeval tv;
				int push_enable=0;
				
				// get STA MAC address
				ind = (DOT11_FT_IMD_ASSOC_IND *)buf;
				memcpy(staAddr, ind->MACAddr, ETH_ALEN);
				FT_DEBUG("STA: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(staAddr));
				
				// get PUSH option
				wlioctl_get_mib(pGlobalCtx, intf_name, "ft_push", &push_enable);
				if (push_enable)
				{
					// send Key Push Frame to all R1KH
					while (r1kh)
					{
						if (strlen(r1kh->intf) == strlen(intf_name) &&
							!strncmp(r1kh->intf, intf_name, strlen(intf_name)))
						{
							// generate PMK-R1
							getkey = (DOT11_FT_GET_KEY *)buf;
							getkey->EventId = DOT11_EVENT_FT_GET_KEY;
							getkey->Type = FTKEY_TYPE_PUSH;
							memcpy(getkey->r1kh_id, r1kh->addr, ETH_ALEN);
							FT_DEBUG("R1KH-ID: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(getkey->r1kh_id));
							memcpy(getkey->s1kh_id, staAddr, ETH_ALEN);
							FT_DEBUG("S1KH-ID: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(getkey->s1kh_id));
							wrq.u.data.length = sizeof(*getkey);
							if (ioctl(pCtx->wlan_socket, SIOCGIFTGETKEY, &wrq) < 0)
							{
								FT_ERROR("ioctl[SIOCGIFTGETKEY] failed!\n");
								return -1;
							}
							
							// get PMK-R1 push frame
							push = (DOT11_FT_GET_KEY_PUSH *)buf;
							gettimeofday(&tv, NULL);
							FT_DEBUG("timestamp: %d\n", tv.tv_sec);
							push->timestamp = htole32((u32)tv.tv_sec);
							dot11r_push_pmk_r1(pCtx, src_addr, r1kh, (u8 *)&push->timestamp, (int)push->Length);
						}
						r1kh = r1kh->next;
					}
				}
				else
				{
					// notify change of R0KH
					exp = (DOT11_FT_KEY_EXPIRE_IND *)buf;
					dot11r_send_inform(pCtx, src_addr, exp->MACAddr, INFORM_TYPE_KEY_EXPIRE, intf_name);
				}
			}
				break;
			case DOT11_EVENT_FT_PULL_KEY_IND:
				FT_DEBUG("[EVENT_FT_PULL_KEY_IND]\n");
			{
				R0KH_Tp r0kh;
				DOT11_FT_PULL_KEY_IND *pull;
				char r0kh_id[FT_R0KH_ID_MAX_LEN+1]={0};
				
				pull = (DOT11_FT_PULL_KEY_IND *)buf;
				strncpy(r0kh_id, pull->r0kh_id, MAX_R0KHID_LEN);
				r0kh = search_r0kh_by_id(pCtx, pull->r0kh_id);
				//send Key Pull Frame to R0KH-ID
				if (r0kh)
					dot11r_pull_pmk_r1(pCtx, src_addr, r0kh, (u8 *)pull->nonce, (int)pull->Length);
				else
					FT_ERROR("unregistered R0KH-ID: %s\n", r0kh_id);
			}
				break;
			case DOT11_EVENT_FT_ACTION_IND:
				FT_DEBUG("[EVENT_FT_ACTION_IND]\n");
			{
				DOT11_FT_ACTION *act;
				
				act = (DOT11_FT_ACTION *)buf;
				dot11r_send_ft_action(pCtx, src_addr, act->MACAddr, (u8 *)act->packet, act->packet_len, act->ActionCode);
			}
				break;
			case DOT11_EVENT_FT_ASSOC_IND:
				FT_DEBUG("[EVENT_FT_ASSOC_IND]\n");
			{
				DOT11_FT_ASSOC_IND *ind;
				
				ind = (DOT11_FT_ASSOC_IND *)buf;
				dot11r_send_inform(pCtx, src_addr, ind->MACAddr, INFORM_TYPE_ROAMING, intf_name);
			}
				break;
			case DOT11_EVENT_FT_KEY_EXPIRE_IND:
				FT_DEBUG("[EVENT_FT_KEY_EXPIRE_IND]\n");
			{
				DOT11_FT_KEY_EXPIRE_IND *ind;
				
				ind = (DOT11_FT_KEY_EXPIRE_IND *)buf;
				dot11r_send_inform(pCtx, src_addr, ind->MACAddr, INFORM_TYPE_KEY_EXPIRE, intf_name);
			}
				break;
			default:
				FT_DEBUG("[Unhandled EVENT (%d)]\n", buf[0]);
		}
	} while (buf[1]);

	return 0;
}

static void sigHandler_user(int signo)
{
	int i;
	
	if (signo == SIGUSR1)
	{
		FT_DEBUG("Got signal - SIGUSR1\n");
		for (i=0; i<pGlobalCtx->wlan_intf_num; i++)
			handleDrvEvent(pGlobalCtx, pGlobalCtx->wlan_intf_name[i]);
	}
	else if (signo == SIGUSR2) //for debug
	{
		R0KH_Tp r0kh;
		FT_DEBUG("Got signal - SIGUSR2\n");
		read_config(pGlobalCtx);	//reload ft.conf
		dump_KH(pGlobalCtx);		//dump KH
	}
	else if (signo == SIGALRM) //for debug
	{
		FT_DEBUG("Got signal - SIGALRM\n");
		clear_config(pGlobalCtx);	//clear KH
		dump_KH(pGlobalCtx);		//dump KH
		pGlobalCtx->debug_level = (pGlobalCtx->debug_level+1)%5;	//increase debug_level
		printf("Current debug_level=%d\n", pGlobalCtx->debug_level);
	}
	else
		FT_DEBUG("Got an invalid signal [%d]!\n", signo);
}

/* network event handler */
static int process_rrb(CTX_Tp pCtx, u8 *src, u8 *data, int data_len)
{
	struct l2_ethhdr *ethhdr;
	struct ft_rrb_frame *frame;
	struct ft_action_frame *act_frame;
	int i;
	struct iwreq wrq;
	char *intf_name;
	
	if (data_len < sizeof(*ethhdr))
		return -1;
	
	if ((data_len-sizeof(*ethhdr)) < sizeof(*frame))
		return -1;

	ethhdr = (struct l2_ethhdr *)data;
	frame = (struct ft_rrb_frame *)(ethhdr + 1);
	
	FT_DEBUG("  frame_type: %d\n", frame->frame_type);
	FT_DEBUG("  packet_type: %d\n", frame->packet_type);
	FT_DEBUG("  action_length: %d\n", le16toh(frame->action_length));
	FT_DEBUG("  ap_address: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(frame->ap_address));

	intf_name = find_wlan_name_by_addr(pCtx, ethhdr->h_dest);
	if (intf_name == NULL)
	{
		FT_ERROR("unknown packet destination: %02x:%02x:%02x:%02x:%02x:%02x\n", MAC2STR(ethhdr->h_dest));
		return -1;
	}
	else
		FT_TRACE(" RRB to %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", intf_name, MAC2STR(ethhdr->h_dest));
	memset(wrq.ifr_name, 0, sizeof wrq.ifr_name);
	strncpy(wrq.ifr_name, intf_name, IFNAMSIZ);

	if (frame->packet_type == FT_PACKET_R0KH_R1KH_PULL)
	{
		R1KH_Tp r1kh;
		struct ft_r0kh_r1kh_pull_frame *f;
		DOT11_FT_PULL_KEY_IND pull_ind;
		DOT11_FT_GET_KEY_PULL *resp;
		u8 nonce[FT_R0KH_R1KH_PULL_NONCE_LEN];
		u8 src_addr[ETH_ALEN];

		FT_TRACE("RX Key Pull Frame\n");
		memcpy(src_addr, ethhdr->h_dest, ETH_ALEN);
		r1kh = search_r1kh_by_addr(pCtx, ethhdr->h_source, intf_name);
		if (r1kh == NULL)
		{
			FT_DEBUG("KEY_PULL from unregistered R1KH(%02x:%02x:%02x:%02x:%02x:%02x)\n", MAC2STR(ethhdr->h_source));
			return 0;
		}
		
		f = (struct ft_r0kh_r1kh_pull_frame *)frame;
		memset(&pull_ind, 0, sizeof(pull_ind));
		if (aes_unwrap((u8 *)f->nonce, (u8 *)pull_ind.nonce, r1kh->key, (FT_R0KH_R1KH_PULL_DATA_LEN+7)/8) != 0)
		{
			FT_ERROR("decode error\n");
			return -1;
		}
		
		FT_DEBUG("    nonce: "); for (i=0; i<FT_R0KH_R1KH_PULL_NONCE_LEN; i++) FT_DEBUG2("%02x", pull_ind.nonce[i]); FT_DEBUG2("\n");
		FT_DEBUG("    pmk_r0_name: "); for (i=0; i<16; i++) FT_DEBUG2("%02x", pull_ind.pmk_r0_name[i]); FT_DEBUG2("\n");
		FT_DEBUG("    r1kh_id: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(pull_ind.r1kh_id));
		FT_DEBUG("    s1kh_id: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(pull_ind.s1kh_id));
		memcpy(nonce, pull_ind.nonce, FT_R0KH_R1KH_PULL_NONCE_LEN);

		pull_ind.EventId = DOT11_EVENT_FT_GET_KEY;
		pull_ind.Type = FTKEY_TYPE_PULL;
		pull_ind.Length = FT_R0KH_R1KH_PULL_DATA_LEN;

		wrq.u.data.pointer = (caddr_t)&pull_ind;
		wrq.u.data.length = sizeof(pull_ind);
		dump_mem("Pull", wrq.u.data.pointer, wrq.u.data.length);
		if (ioctl(pCtx->wlan_socket, SIOCGIFTGETKEY, &wrq) < 0)
		{
			FT_DEBUG("ioctl[SIOCGIFTGETKEY] failed! (pull)\n");
			return -1;
		}
		
		resp = (DOT11_FT_GET_KEY_PULL *)wrq.u.data.pointer;
		memcpy(resp->nonce, nonce, FT_R0KH_R1KH_PULL_NONCE_LEN);
		dot11r_resp_pmk_r1(pCtx, src_addr, r1kh, (u8 *)resp->nonce, (int)resp->Length);
		
		return 0;
	}
	
	if (frame->packet_type == FT_PACKET_R0KH_R1KH_RESP)
	{
		R0KH_Tp r0kh;
		struct ft_r0kh_r1kh_resp_frame *f;
		DOT11_FT_SET_KEY_PULL resp;
		int i;
		
		FT_TRACE("RX Key Resp Frame\n");
		r0kh = search_r0kh_by_addr(pCtx, ethhdr->h_source, intf_name);
		if (r0kh == NULL)
		{
			FT_DEBUG("KEY_RESP from unregistered R0KH(%02x:%02x:%02x:%02x:%02x:%02x)\n", MAC2STR(ethhdr->h_source));
			return 0;
		}
		
		f = (struct ft_r0kh_r1kh_resp_frame *)frame;
		memset(&resp, 0, sizeof(resp));
		if (aes_unwrap((u8 *)f->nonce, (u8 *)resp.nonce, r0kh->key, (FT_R0KH_R1KH_RESP_DATA_LEN+7)/8) != 0)
		{
			FT_ERROR("decode error\n");
			return -1;
		}
		
		FT_DEBUG("    nonce: "); for (i=0; i<FT_R0KH_R1KH_PULL_NONCE_LEN; i++) FT_DEBUG2("%02x", resp.nonce[i]); FT_DEBUG2("\n");
		FT_DEBUG("    r1kh_id: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(resp.r1kh_id));
		FT_DEBUG("    s1kh_id: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(resp.s1kh_id));
		FT_DEBUG("    pmk_r1_name: "); for (i=0; i<16; i++) FT_DEBUG2("%02x", resp.pmk_r1_name[i]); FT_DEBUG2("\n");
		FT_DEBUG("    pairwise: %d\n", le16toh(resp.pairwise));
		
		resp.EventId = DOT11_EVENT_FT_SET_KEY;
		resp.Type = FTKEY_TYPE_PULL;
		resp.Length = FT_R0KH_R1KH_RESP_DATA_LEN;
		
		wrq.u.data.pointer = (caddr_t)&resp;
		wrq.u.data.length = sizeof(resp);
		dump_mem("Resp", wrq.u.data.pointer, wrq.u.data.length);
		if (ioctl(pCtx->wlan_socket, SIOCSIFTSETKEY, &wrq) < 0)
		{
			FT_ERROR("ioctl[SIOCSIFTSETKEY] failed! (resp)\n");
			return -1;
		}
		
		return 0;
	}
	
	if (frame->packet_type == FT_PACKET_R0KH_R1KH_PUSH)
	{
		R0KH_Tp r0kh;
		struct ft_r0kh_r1kh_push_frame *f;
		DOT11_FT_SET_KEY_PUSH push;
		int i;
		
		FT_TRACE("RX Key Push Frame\n");
		r0kh = search_r0kh_by_addr(pCtx, frame->ap_address, intf_name);
		if (r0kh == NULL)
		{
			FT_DEBUG("KEY_PUSH from unregistered R0KH(%02x:%02x:%02x:%02x:%02x:%02x)\n", MAC2STR(frame->ap_address));
			return 0;
		}
		
		f = (struct ft_r0kh_r1kh_push_frame *)frame;
		memset(&push, 0, sizeof(push));
		if (aes_unwrap((u8 *)f->timestamp, (u8 *)&push.timestamp, r0kh->key, (FT_R0KH_R1KH_PUSH_DATA_LEN+7)/8) != 0)
		{
			FT_ERROR("decode error\n");
			return -1;
		}
		
		FT_DEBUG("    timestamp: %08x\n", push.timestamp);
		FT_DEBUG("    r1kh_id: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(push.r1kh_id));
		FT_DEBUG("    s1kh_id: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(push.s1kh_id));
		FT_DEBUG("    pmk_r0_name: "); for (i=0; i<16; i++) FT_DEBUG2("%02x", push.pmk_r0_name[i]); FT_DEBUG2("\n");
		FT_DEBUG("    pmk_r1: "); for (i=0; i<PMK_LEN; i++) FT_DEBUG2("%02x", push.pmk_r1[i]); FT_DEBUG2("\n");
		FT_DEBUG("    pmk_r1_name: "); for (i=0; i<16; i++) FT_DEBUG2("%02x", push.pmk_r1_name[i]); FT_DEBUG2("\n");
		FT_DEBUG("    pairwise: %d\n", le16toh(push.pairwise));

		push.EventId = DOT11_EVENT_FT_SET_KEY;
		push.Type = FTKEY_TYPE_PUSH;
		push.Length = FT_R0KH_R1KH_PUSH_DATA_LEN;
		
		wrq.u.data.pointer = (caddr_t)&push;
		wrq.u.data.length = sizeof(push);
		dump_mem("Push", wrq.u.data.pointer, wrq.u.data.length);
		if (ioctl(pCtx->wlan_socket, SIOCSIFTSETKEY, &wrq) < 0)
		{
			FT_ERROR("ioctl[SIOCSIFTSETKEY] failed! (push)\n");
			return -1;
		}
		
		return 0;
	}

	if (frame->packet_type == FT_PACKET_INFORM)
	{
		R1KH_Tp r1kh;
		struct ft_inform_frame ind, *f;
		
		FT_TRACE("RX Inform Frame\n");
		r1kh = search_r1kh_by_addr(pCtx, ethhdr->h_source, intf_name);
		if (r1kh == NULL)
		{
			FT_DEBUG("INFORM from unregistered R1KH(%02x:%02x:%02x:%02x:%02x:%02x)\n", MAC2STR(ethhdr->h_source));
			return 0;
		}
		
		f = (struct ft_inform_frame *)frame;
		memset(&ind, 0, sizeof(ind));
		if (aes_unwrap((u8 *)&f->timestamp, (u8 *)&ind.timestamp, r1kh->key, (FT_INFORM_DATA_LEN+7)/8) != 0)
		{
			FT_ERROR("decode error\n");
			return -1;
		}
		
		FT_DEBUG("    timestamp: %d\n", le32toh(ind.timestamp));
		FT_DEBUG("    inform_type: %d\n", ind.inform_type);
		FT_DEBUG("    addr: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(ind.addr));
		
		switch (ind.inform_type)
		{
			case INFORM_TYPE_ROAMING:
			{
				DOT11_FT_ASSOC_IND assoc_ind;
				
				memset(&assoc_ind, 0, sizeof(assoc_ind));
				assoc_ind.EventId = DOT11_EVENT_FT_ASSOC_IND;
				memcpy(assoc_ind.MACAddr, &ind.addr, ETH_ALEN);

				wrq.u.data.pointer = (caddr_t)&assoc_ind;
				wrq.u.data.length = sizeof(assoc_ind);
				dump_mem("Roaming", wrq.u.data.pointer, wrq.u.data.length);
				if (ioctl(pCtx->wlan_socket, SIOCSIFTINFORM, &wrq) < 0)
				{
					FT_ERROR("ioctl[SIOCSIFTINFORM] failed! (roaming)\n");
					return -1;
				}
			}
				break;
			case INFORM_TYPE_KEY_EXPIRE:
			{
				DOT11_FT_KEY_EXPIRE_IND expire_ind;
				
				memset(&expire_ind, 0, sizeof(expire_ind));
				expire_ind.EventId = DOT11_EVENT_FT_KEY_EXPIRE_IND;
				memcpy(expire_ind.MACAddr, &ind.addr, ETH_ALEN);

				wrq.u.data.pointer = (caddr_t)&expire_ind;
				wrq.u.data.length = sizeof(expire_ind);
				dump_mem("Key Expire", wrq.u.data.pointer, wrq.u.data.length);
				if (ioctl(pCtx->wlan_socket, SIOCSIFTINFORM, &wrq) < 0)
				{
					FT_ERROR("ioctl[SIOCSIFTINFORM] failed! (key_expire)\n");
					return -1;
				}
			}
				break;
			default:
				FT_ERROR("Unknown Inform type\n");
				return -1;
		}
		
		return 0;
	}
	
	FT_TRACE("RX FT Action Frame\n");
	act_frame = (struct ft_action_frame *)(frame + 1);
	
	if ((le16toh(frame->action_length)<14) || (act_frame->category!=6))
		return -1;
	else
	{
		DOT11_FT_ACTION act;
		
		FT_DEBUG("    category: %d\n", act_frame->category);
		FT_DEBUG("    ft_action: %d\n", act_frame->ft_action);
		FT_DEBUG("    sta_address: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(act_frame->sta_address));
		FT_DEBUG("    target_ap_address: %02x-%02x-%02x-%02x-%02x-%02x\n", MAC2STR(act_frame->target_ap_address));

		memset(&act, 0, sizeof(act));
		act.EventId = DOT11_EVENT_FT_ACTION_IND;
		act.ActionCode = frame->packet_type;
		act.packet_len = le16toh(frame->action_length);
		memcpy(act.MACAddr, frame->ap_address, ETH_ALEN);
		memcpy(act.packet, act_frame, act.packet_len);

		wrq.u.data.pointer = (caddr_t)&act;
		wrq.u.data.length = sizeof(act);
		dump_mem("Action", wrq.u.data.pointer, offsetof(DOT11_FT_ACTION, packet)+act.packet_len);
		if (ioctl(pCtx->wlan_socket, SIOCSIFTACTION, &wrq) < 0)
		{
			FT_ERROR("ioctl[SIOCSIFTACTION] failed! (action)\n");
			return -1;
		}
	}
	
	return 0;
}

static void listen_and_process_event(CTX_Tp pCtx)
{
	int selret=0;
	fd_set fdr;
	struct timeval tv;
	int nRead;
	char *buffer;
	struct sockaddr_ll ll;
	socklen_t ll_size;
	
	buffer = malloc(PKTLEN);
	if (buffer == NULL)
	{
		FT_ERROR("allocate recv_buf failed!\n");
		return;
	}
	
	FT_DEBUG("daemon ready...\n");
	while (1)
	{
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&fdr);
		FD_SET(pCtx->socket, &fdr);
		ll_size = sizeof(ll);
		selret = select(pCtx->socket+1, &fdr, NULL, NULL, &tv);
		switch (selret)
		{
			case -1:
				//FT_DEBUG("select error\n");
				break;
			case 0:
				//FT_DEBUG("select timeout\n");
				break;
			default:
				if (FD_ISSET(pCtx->socket, &fdr))
				{
					nRead = recvfrom(pCtx->socket, buffer, PKTLEN, 0, (struct sockaddr *)&ll, &ll_size);
					FT_DEBUG("=> read %d bytes from socket(%d)\n", nRead, pCtx->socket);
					//dump_mem("PKT", buffer, nRead);
					process_rrb(pCtx, ll.sll_addr, buffer, nRead);
				}
        }
	}
}

static void issue_signal_to_ftd(CTX_Tp pCtx , int signo)
{
	FILE *fp;
	char line[100];
	int pid;

	if ((fp = fopen(pCtx->pid_filename, "r")) != NULL)
	{
		fgets(line, sizeof(line), fp);
		if (sscanf(line, "%d", &pid))
		{
			if (pid > 1){
				kill(pid, signo);
				FT_DEBUG("kill sig(%d), pid(%d)\n", signo, pid);
			}
		}
		fclose(fp);
		return;
	}
}

void print_usage()
{
	printf("Usage:\n");
	printf("  -br <bridge>     Bridge interface  (%s)\n", DEF_ETH_INTF_NAME);
	printf("  -w <wlan list>   WiFi interface list  (%s)\n", DEF_WLAN_INTF_NAME);
	printf("  -pid <filename>  PID file  (%s)\n", DEF_PID_FILENAME);
	printf("  -c <config>      Key Holder config file  (%s)\n", DEF_CONFIG_FILENAME);
}

static int parse_arg(int argc, char *argv[])
{
	CTX_Tp pCtx=pGlobalCtx;
	int argNum=1, update_config=0, clear_config=0;

	while (argNum < argc)
	{
		if (!strcmp(argv[argNum], "-update"))
		{
			update_config = 1;
			argNum++;
			continue;
		}
		if (!strcmp(argv[argNum], "-clear"))
		{
			clear_config = 1;
			argNum++;
			continue;
		}
		if ((argNum+1<argc) && (argv[argNum+1][0]!='-'))
		{
			if (!strcmp(argv[argNum], "-br"))
			{
				FT_DEBUG("eth: %s\n", argv[argNum+1]);
				strncpy(pCtx->eth_intf_name, argv[argNum+1], IFNAMSIZ);
				argNum++;
			}
			else if (!strcmp(argv[argNum], "-w"))
			{
				pCtx->wlan_intf_num = 0;
				while ((argNum+1<argc) && (argv[argNum+1][0] != '-'))
				{
					if (pCtx->wlan_intf_num >= MAX_WLAN_INF_NUM)
					{
						FT_ERROR("Too many wlan interfaces\n");
						argNum++;
						continue;
					}
					FT_DEBUG("wlan: %s\n", argv[argNum+1]);
					strncpy(pCtx->wlan_intf_name[pCtx->wlan_intf_num], argv[argNum+1], IFNAMSIZ);
					pCtx->wlan_intf_num++;
					argNum++;
				}
				if (!pCtx->wlan_intf_num)
				{
					FT_ERROR("No valid wlan interface!!\n");
					return -1;
				}
			}
			else if (!strcmp(argv[argNum], "-pid"))
			{
				FT_DEBUG("pid: %s\n", argv[argNum+1]);
				strncpy(pCtx->pid_filename, argv[argNum+1], MAX_FILENAME_SIZE);
				argNum++;
			}
			else if (!strcmp(argv[argNum], "-c"))
			{
				FT_DEBUG("config: %s\n", argv[argNum+1]);
				strncpy(pCtx->config_filename, argv[argNum+1], MAX_FILENAME_SIZE);
				argNum++;
			}
			else if (!strcmp(argv[argNum], "-v"))
			{
				pCtx->debug_level = atoi(argv[argNum+1]);
				argNum++;
			}
			else
			{
				printf("Unrecognized parameter: %s\n", argv[argNum]);
				print_usage();
				return -1;
			}
		}
		else
		{
			printf("Incorrect parameter: %s\n", argv[argNum]);
			print_usage();
			return -1;
		}
		argNum++;
	}

	/* process special parameter */
	if (update_config)
	{
		issue_signal_to_ftd(pCtx, SIGUSR2);
		return 1;
	}
	if (clear_config)
	{
		issue_signal_to_ftd(pCtx, SIGALRM);
		return 1;
	}
	
	return 0;
}

int main(int argc, char *argv[])
{
	CTX_Tp pCtx;
	pid_t pid_fd;

	printf("\nFT Daemon v1.0 (%s %s)\n\n", __DATE__, __TIME__);
	
	/* Allocate context */
	pCtx = (CTX_Tp) calloc(1, sizeof(CTX_T));
	if (pCtx == NULL) {
		FT_ERROR("allocate context failed!\n");
		return 0;
	}
	pGlobalCtx = pCtx;
	
	/* Initialize config */
	strncpy(pCtx->eth_intf_name, DEF_ETH_INTF_NAME, IFNAMSIZ);
	strncpy(pCtx->wlan_intf_name[0], DEF_WLAN_INTF_NAME, IFNAMSIZ);
	pCtx->wlan_intf_num = 1;
	strncpy(pCtx->pid_filename, DEF_PID_FILENAME, MAX_FILENAME_SIZE);
	strncpy(pCtx->config_filename, DEF_CONFIG_FILENAME, MAX_FILENAME_SIZE);
	pCtx->debug_level = 3;

	/* Parse argument */
	if (parse_arg(argc, argv))
		return -1;
	
	FT_DEBUG("pid: %s\n", pCtx->pid_filename);
	FT_DEBUG("config: %s\n", pCtx->config_filename);

	/* register R0KH/R1KH form config file */
	read_config(pCtx);
	
	/* Initialize sockets */
	if (init_eth_socket(pCtx) < 0)
	{
		free(pCtx);
		return 0;
	}
	if (init_wlan_socket(pCtx) < 0)
	{
		free(pCtx);
		return 0;
	}

	pthread_mutex_init(&pCtx->RegMutex, NULL);

	/* Create daemon */
	pid_fd = pidfile_acquire(pCtx->pid_filename);
	if (pid_fd < 0) {
		FT_ERROR("pidfile_acquire fail!!!\n");
		pthread_mutex_destroy(&pCtx->RegMutex);
		return 0;
	}
	pidfile_write_release(pid_fd);
	RegisterPID(pCtx);

	signal(SIGUSR1, sigHandler_user);
	signal(SIGUSR2, sigHandler_user);
	signal(SIGALRM, sigHandler_user);

	listen_and_process_event(pCtx);

	FT_DEBUG("End process...\n");
	return 0;
}
