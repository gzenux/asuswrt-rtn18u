/*
 * $Id: bmd_shcmd_tx.c,v 1.30 Broadcom SDK $
 * $Copyright: Copyright 2013 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * Chip packet transmit command
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_field.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_higig_defs.h>

#include <bmd/bmd.h>
#include <bmd/bmd_dma.h>
#include <bmd/shell/shcmd_tx.h>

#include "bmd_shell_util.h"

#if BMD_CONFIG_INCLUDE_DMA == 1

#define ETH_CRC_SIZE 4
#define ETH_HDR_SIZE 18
#define STK_HDR_SIZE 16
#define MH_SIZE 16
#define MH_WSIZE CDK_BYTES2WORDS(MH_SIZE)

static uint8_t stk_hdr[STK_HDR_SIZE];
static int stk_hdr_len;

static uint8_t dst_mac[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
static uint8_t src_mac[6] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
static uint8_t vlan_tag[4] = { 0x81, 0x00, 0x00, 0x01 };

static bmd_pkt_t test_pkt;
static int pkt_size;

static int
_get_mac(const char *str, uint8_t *mac)
{
    const char *p = str;
    int i = 0;

    mac[0] = CDK_STRTOUL(p, NULL, 16);
    while (++i < 6) {
        if ((p = CDK_STRCHR(p, ':')) == NULL || *(++p) < '0') {
            return -1;
        }
        mac[i] = CDK_STRTOUL(p, NULL, 16);
    }
    return 0;
}

static int
_get_shdr(const char *str, uint8_t *shdr, int max_len)
{
    const char *p = str;
    int i = 0;

    shdr[0] = CDK_STRTOUL(p, NULL, 16);
    while (++i < max_len) {
        if ((p = CDK_STRCHR(p, ':')) == NULL || *(++p) < '0') {
            return i;
        }
        shdr[i] = CDK_STRTOUL(p, NULL, 16);
    }
    return i;
}

static int
_hg_parse(char *arg, uint32_t *mh)
{
#if BMD_CONFIG_INCLUDE_HIGIG == 1 && CDK_CONFIG_INCLUDE_FIELD_NAMES == 1
    int hg2 = (*arg == '2') ? 1 : 0;
    int sop = mh[0] >> 24;
    cdk_symbols_t *hg_syms = &higig_symbols;
    const char **fnames = hg_syms->field_names;
    char *sym_name = "HIGIG";
    const char *fname;
    cdk_shell_tokens_t cst;
    cdk_symbol_t symbol;
    cdk_field_info_t finfo; 
    uint32_t val;

    if (sop == 0) {
        if (hg2) {
            mh[0] = (CDK_HIGIG2_SOF << 24);
        } else {
            mh[0] = (CDK_HIGIG_SOF << 24) | (0x80 << 16); /* HGI=2 */
        }
    } else if ((hg2 && sop == CDK_HIGIG_SOF) ||
               (!hg2 && sop == CDK_HIGIG2_SOF)) {
        CDK_PRINTF("%sCannot mix HiGig and HiGig2 arguments\n",
                   CDK_CONFIG_SHELL_ERROR_STR); 
        return -1;
    }
    if (hg2) {
        arg++;
        sym_name = "HIGIG2";
    }
    if (cdk_shell_tokenize(arg, &cst, "=") < 0 || cst.argc != 2) {
        return -1;
    }
    if (cdk_shell_parse_uint32(cst.argv[1], &val) < 0) {
        return -1;
    }
    if (cdk_symbols_find(sym_name, hg_syms, &symbol) == 0) {
        CDK_SYMBOL_FIELDS_ITER_BEGIN(symbol.fields, finfo, fnames) {
            /* Skip encoding part of field name if present */
            if ((fname = CDK_STRCHR(finfo.name, '}')) != NULL) {
                fname++;
            } else {
                fname = finfo.name;
            }
            if (CDK_STRCASECMP(fname, cst.argv[0]) != 0) {
                continue; 
            }
            cdk_field_be_set(mh, CDK_SYMBOL_INDEX_SIZE_GET(symbol.index) >> 2, 
                             finfo.minbit, finfo.maxbit, &val);
            return 0;
        } CDK_SYMBOL_FIELDS_ITER_END(); 
        CDK_PRINTF("%sUnrecognized field name: %s\n",
                   CDK_CONFIG_SHELL_ERROR_STR, cst.argv[0]);
    }
#endif
    return -1;
}

static void
_hg_list(char *arg)
{
#if BMD_CONFIG_INCLUDE_HIGIG == 1 && CDK_CONFIG_INCLUDE_FIELD_NAMES == 1
    int hg2 = (*arg == '2') ? 1 : 0;
    cdk_symbols_t *hg_syms = &higig_symbols;
    char *sym_name = "HIGIG";
    cdk_symbol_t symbol;

    if (hg2) {
        sym_name = "HIGIG2";
    }
    if (cdk_symbols_find(sym_name, hg_syms, &symbol) == 0) {
        CDK_PRINTF("Valid %s fields:\n", sym_name);
        cdk_shell_list_fields(&symbol, hg_syms->field_names);
    }
#endif
}

static int
_mh_to_shdr_list(uint32_t *mh, uint8_t *shdr, int max_len)
{
    int shdr_len = 0;
#if BMD_CONFIG_INCLUDE_HIGIG == 1
    int sop = mh[0] >> 24;
    int mdx, idx;

    if (sop == CDK_HIGIG_SOF) {
        shdr_len = 12;
    } else if (sop == CDK_HIGIG2_SOF) {
        shdr_len = 16;
    } else {
        return 0;
    }
    if (shdr_len > max_len) {
        return 0;
    }
    for (mdx = idx = 0; idx < shdr_len; mdx++) {
        shdr[idx++] = (uint8_t)(mh[mdx] >> 24);
        shdr[idx++] = (uint8_t)(mh[mdx] >> 16);
        shdr[idx++] = (uint8_t)(mh[mdx] >> 8);
        shdr[idx++] = (uint8_t)(mh[mdx]);
    }
#endif
    return shdr_len;
}

#endif

int 
bmd_shcmd_tx(int argc, char* argv[])
{
    int rv = CDK_E_NONE;
#if BMD_CONFIG_INCLUDE_DMA == 1
    bmd_pkt_t *pkt;
    char *ptr;
    int unit;
    cdk_pbmp_t pbmp;
    int lport, port = -1;
    int count = -1;
    int shdr_len;
    int data_len;
    int ax;
    int px;
    int vlan;
    uint8_t mac[6];
    uint32_t mh[MH_WSIZE];

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    pkt = &test_pkt;
    pkt->flags = BMD_PKT_F_CRC_REGEN;

    stk_hdr_len = 0;
    CDK_MEMSET(mh, 0, MH_SIZE);

    for (ax = 0; ax < argc; ax++) {
        if ((ptr = cdk_shell_opt_val(argc, argv, "size", &ax)) != NULL) {
            pkt_size = CDK_STRTOL(ptr, NULL, 0);
        } else if ((ptr = cdk_shell_opt_val(argc, argv, "vlan", &ax)) != NULL) {
            vlan = CDK_STRTOL(ptr, NULL, 0);
            vlan_tag[2] = (uint8_t)(vlan >> 8);
            vlan_tag[3] = (uint8_t)(vlan);
        } else if ((ptr = cdk_shell_opt_val(argc, argv, "dmac", &ax)) != NULL) {
            if (_get_mac(ptr, mac) == 0) {
                CDK_MEMCPY(dst_mac, mac, 6);
            } else {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        } else if ((ptr = cdk_shell_opt_val(argc, argv, "smac", &ax)) != NULL) {
            if (_get_mac(ptr, mac) == 0) {
                CDK_MEMCPY(src_mac, mac, 6);
            } else {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        } else if (CDK_STRNCMP(argv[ax], "hg", 2) == 0) {
            if (CDK_STRCMP(argv[ax], "hglist") == 0 ||
                CDK_STRCMP(argv[ax], "hg2list") == 0) {
                _hg_list(&argv[ax][2]);
                return CDK_SHELL_CMD_OK;
            } else if (_hg_parse(&argv[ax][2], mh) < 0) {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        } else if ((ptr = cdk_shell_opt_val(argc, argv, "shdr", &ax)) != NULL) {
            if ((shdr_len = _get_shdr(ptr, stk_hdr, sizeof(stk_hdr))) >= 0) {
                stk_hdr_len = shdr_len;
            } else {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        } else if (CDK_STRCMP(argv[ax], "untag") == 0) {
            pkt->flags |= BMD_PKT_F_UNTAGGED;
        } else if (count < 0) {
            count = CDK_STRTOL(argv[ax], NULL, 0);
        } else if (port < 0) {
            port = bmd_shell_parse_port_str(unit, argv[ax], &pbmp);
        } else {
            return CDK_SHELL_CMD_BAD_ARG;
        }
    }

    if (pkt_size < 14) {
        pkt_size = 68;
    }

    if (count < 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (stk_hdr_len == 0) {
        stk_hdr_len = _mh_to_shdr_list(mh, stk_hdr, sizeof(stk_hdr));
    }

    px = 0;
    pkt->port = port;
    pkt->size = pkt_size + stk_hdr_len;
    data_len = pkt_size - ETH_HDR_SIZE - ETH_CRC_SIZE;

    pkt->data = bmd_dma_alloc_coherent(unit, pkt->size, &pkt->baddr);
    CDK_ASSERT(pkt->data);

    CDK_MEMCPY(&pkt->data[px], stk_hdr, stk_hdr_len); 
    px += stk_hdr_len;
    CDK_MEMCPY(&pkt->data[px], dst_mac, 6); 
    px += 6;
    CDK_MEMCPY(&pkt->data[px], src_mac, 6); 
    px += 6;
    CDK_MEMCPY(&pkt->data[px], vlan_tag, 4); 
    px += 4;
    pkt->data[px++] = data_len >> 8;
    pkt->data[px++] = data_len & 0xff;

    for (; px < (pkt->size - ETH_CRC_SIZE); px++) {
        pkt->data[px] = px ^ 0xff;
    }

    for (; px < pkt->size; px++) {
        pkt->data[px] = 0;
    }

    BMD_DMA_CACHE_FLUSH(pkt->data, pkt->size);

    CDK_DEBUG_PACKET(("bmd_tx[%d]: port = %d, size = %d\n",
                      unit, CDK_PORT_MAP_P2L(unit, pkt->port), pkt->size));
    for (ax = 0; ax < 128 && ax < pkt->size; ax++) {
        if ((ax & 0xf) == 0) {
            CDK_DEBUG_PACKET(("\t%04x:", ax));
        }
        CDK_DEBUG_PACKET(("%c%02x", (ax & 0xf) == 8 ? '-' : ' ', pkt->data[ax]));
        if ((ax & 0xf) == 0xf || ax == (pkt->size - 1)) {
            CDK_DEBUG_PACKET(("\n"));
        }
    }

    if (port < 0) {
        rv = bmd_tx(unit, pkt);
    } else {
        CDK_LPORT_ITER(unit, pbmp, lport, port) {
            px = count;
            pkt->port = port;
            do {
                rv = bmd_tx(unit, pkt);
            } while (CDK_SUCCESS(rv) && --px > 0);
        }
    }

    bmd_dma_free_coherent(unit, pkt->size, pkt->data, pkt->baddr);
#else
    CDK_PRINTF("No DMA support.\n");
#endif

    return cdk_shell_error(rv);
}
