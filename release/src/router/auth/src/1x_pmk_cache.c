//--------------------------------------------------
// IEEE 802.1x + 802.11i Implementation
//
// File		: 1x_pmk_cache.c
// Programmer	: Kenneth Lin
// PMK Cache routine
//
//
// Copyright (c) Kenneth Lin 2004
// All rights reserved.
// Realtek Semi.
//--------------------------------------------------

#include <string.h>
#include "1x_common.h"
#include "1x_list.h"

extern Dot1x_Authenticator     RTLAuthenticator;

struct _WPA2_PMKSA_Node* get_pmksa_node()
{
        struct _WPA2_PMKSA_Node* pmksa_node;
        if ( (pmksa_node = (struct _WPA2_PMKSA_Node* )malloc(sizeof (struct _WPA2_PMKSA_Node))) == NULL)
		printf("%s: malloc fails\n", __FUNCTION__);
	return pmksa_node;
}

void free_pmksa_node(struct _WPA2_PMKSA_Node* pmksa_node)
{
	free(pmksa_node);
}

void wpa2_hexdump(char* name, u_char * buf, int size )
{
	int i;
	printf("%s:", name);
	for (i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n\t\t");
		}
		printf("%02X ", *(buf+i));
	}
	printf("\n");
}


void dump_pmk_cache()
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
        struct list_head* head = &auth->pmksa_list.pmk_cache;
	struct list_head *pos, *n;
        struct _WPA2_PMKSA_Node* node;
	printf("\nPMK Cache:\n");
	list_for_each_safe(pos, n, head) {
                node = list_entry(pos, struct _WPA2_PMKSA_Node, node);
		wpa2_hexdump("PMKID", node->pmksa.pmkid, PMKID_LEN);
		wpa2_hexdump("PMK", node->pmksa.pmk, PMK_LEN);
		wpa2_hexdump("SPA", node->pmksa.spa, ETHER_ADDRLEN);
        printf("Aging: %u", node->pmksa.aging);
		printf("\n");
	}
	printf("\n");
}


void del_pmksa_by_pmkid(u_char* pmkid)
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
	struct list_head* head = &auth->pmksa_list.pmk_cache;
	struct list_head *pos, *n;
	struct _WPA2_PMKSA_Node* node;
    
	list_for_each_safe(pos, n, head) {
                node = list_entry(pos, struct _WPA2_PMKSA_Node, node);
		if ( !memcmp(node->pmksa.pmkid, pmkid, PMKID_LEN ) ) {
			list_del(pos);
			free_pmksa_node(node);
			auth->pmksa_list.quota++;
		}
	}
}

void del_pmksa_by_spa(u_char* spa)
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
	struct list_head* head = &auth->pmksa_list.pmk_cache;
	struct list_head *pos, *n;
	struct _WPA2_PMKSA_Node* node;

	list_for_each_safe(pos, n, head) {
                node = list_entry(pos, struct _WPA2_PMKSA_Node, node);
		if ( !memcmp(node->pmksa.spa, spa, 6 ) ) {
			list_del(pos);
			free_pmksa_node(node);
            auth->pmksa_list.quota++;
		}
	}
}

struct _WPA2_PMKSA_Node* find_pmksa(u_char* pmkid)
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
	struct list_head* head = &auth->pmksa_list.pmk_cache;
	struct list_head *pos, *n;
        struct _WPA2_PMKSA_Node* node;
	list_for_each_safe(pos, n, head) {
                node = list_entry(pos, struct _WPA2_PMKSA_Node, node);
		//wpa2_hexdump("request pmkid", pmkid, PMKID_LEN);
		//wpa2_hexdump("cached pmkid", node->pmksa.pmkid, PMKID_LEN);
		if ( !memcmp(node->pmksa.pmkid, pmkid, PMKID_LEN ) ) {
			return node;
		}
	}
	return NULL;
}

struct _WPA2_PMKSA_Node* find_pmksa_by_supp(u_char* mac)
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
        struct list_head* head = &auth->pmksa_list.pmk_cache;
	struct list_head *pos, *n;
        struct _WPA2_PMKSA_Node* node;
	list_for_each_safe(pos, n, head) {
                node = list_entry(pos, struct _WPA2_PMKSA_Node, node);
		//wpa2_hexdump("request supp", mac, ETHER_ADDRLEN);
		//wpa2_hexdump("cached pmkid", node->pmksa.spa, ETHER_ADDRLEN);
		if ( !memcmp(node->pmksa.spa, mac, ETHER_ADDRLEN ) ) {
			return node;
		}
	}
	return NULL;
}

void squize_pmksa_entry()
{
	int max_aging=0;
    unsigned char *supp[ETHER_ADDRLEN] = {0};
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
	struct list_head* head = &auth->pmksa_list.pmk_cache;
	struct list_head *pos, *n;
	struct _WPA2_PMKSA_Node* node;
	list_for_each_safe(pos, n, head) {
                node = list_entry(pos, struct _WPA2_PMKSA_Node, node);
		//wpa2_hexdump("request pmkid", pmkid, PMKID_LEN);
		//wpa2_hexdump("cached pmkid", node->pmksa.pmkid, PMKID_LEN);
		if ( node->pmksa.aging > max_aging ) {
			max_aging = node->pmksa.aging;
            memcpy(supp, &node->pmksa.spa, ETHER_ADDRLEN);
		}
	}

    del_pmksa_by_spa(supp);
}

void cache_pmksa(struct _WPA2_PMKSA_Node* pmksa_node)
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;
	struct list_head* head = &auth->pmksa_list.pmk_cache;

	/* NOTE **************** */
	del_pmksa_by_spa(pmksa_node->pmksa.spa);
	//del_pmksa_by_pmkid(pmksa_node->pmksa.pmkid);

	if(auth->pmksa_list.quota == 0)
		squize_pmksa_entry(head);

	auth->pmksa_list.quota--;
	list_add_tail(&pmksa_node->node, head);
}

int is_pmksa_empty(void)
{
	Dot1x_Authenticator   *auth = &RTLAuthenticator;

	return list_empty(&auth->pmksa_list.pmk_cache);
}

