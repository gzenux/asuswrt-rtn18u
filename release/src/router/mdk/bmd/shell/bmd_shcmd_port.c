/*
 * $Id
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * Chip packet vlan command
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_debug.h>

#include <bmd/bmd.h>
#include <bmd/shell/shcmd_port.h>

#include "bmd_shell_util.h"

int 
bmd_shcmd_port(int argc, char *argv[])
{
    int unit;
    cdk_pbmp_t pbmp, pbpbmp;
    int lport, port, pbport;
    int value, rate, burst;
    int rv = CDK_E_NONE;
    bmd_traffic_ctrl_t traffic_ctrl;
	bmd_pause_t pause;
	bmd_tag_sel_t tagsel;
    bmd_pkt_type_mask_t type = bmdPktTypeAll;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    if (argc < 2) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    port = bmd_shell_parse_port_str(unit, argv[1], &pbmp);
    if (port < 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (CDK_STRCMP(argv[0], "irc") == 0) {
		CDK_LPORT_ITER(unit, pbmp, lport, port) {
 		    if (argc == 4) {
			    rate = CDK_STRTOUL(argv[2], NULL, 0);
			    burst = CDK_STRTOUL(argv[3], NULL, 0);
				rv = bmd_port_rate_ingress_set(unit, port, type, rate, burst);
    		} else if (argc == 2) {
				rv = bmd_port_rate_ingress_get(unit, port, &type, (uint32_t *)&rate, (uint32_t *)&burst);
				if (rv == CDK_E_NONE) {
   					CDK_PRINTF("Port %d ingress rate is %d kbps and burst size is %d kbits \n", port, rate, burst);
				}
	    	} else {
		    	return CDK_SHELL_CMD_BAD_ARG;
		    }
		}
    } else if (CDK_STRCMP(argv[0], "erc") == 0) {
		CDK_LPORT_ITER(unit, pbmp, lport, port) {
    		if (argc == 4) {
	    		rate = CDK_STRTOUL(argv[2], NULL, 0);
		    	burst = CDK_STRTOUL(argv[3], NULL, 0);
				rv = bmd_port_rate_egress_set(unit, port, type, rate, burst);
    		} else if (argc == 2) {
				rv = bmd_port_rate_egress_get(unit, port, &type, (uint32_t *)&rate, (uint32_t *)&burst);
				if (rv == CDK_E_NONE) {
   					CDK_PRINTF("Port %d egress rate is %d kbps and burst size is %d kbits \n", port, rate, burst);
				}
	    	} else {
		    	return CDK_SHELL_CMD_BAD_ARG;
    		}
		}
    } else if (CDK_STRCMP(argv[0], "remaptagop") == 0) {
		CDK_LPORT_ITER(unit, pbmp, lport, port) {
			if (argc == 4) {
				if (CDK_STRCMP(argv[2], "tpid") == 0) {
					tagsel = bmdVlanTpid;
				} else if (CDK_STRCMP(argv[2], "pid") == 0) {
					tagsel = bmdVlan8021p;
				} else if (CDK_STRCMP(argv[2], "cid") == 0) {
					tagsel = bmdVlanCfi;
				} else if (CDK_STRCMP(argv[2], "vid") == 0) {
					tagsel = bmdVlanVid;
				} else {
					return CDK_SHELL_CMD_BAD_ARG;
				}
				if (CDK_STRCMP(argv[3], "enable") == 0) {
					value = 1;
				} else if (CDK_STRCMP(argv[3], "disable") == 0) {
					value = 0;
				} else {
					return CDK_SHELL_CMD_BAD_ARG;
				}
				rv = bmd_port_tag_mangle_set(unit, port, tagsel, value);
			} else if (argc == 3) {
				if (CDK_STRCMP(argv[2], "tpid") == 0) {
					tagsel = bmdVlanTpid;
				} else if (CDK_STRCMP(argv[2], "pid") == 0) {
					tagsel = bmdVlan8021p;
				} else if (CDK_STRCMP(argv[2], "cid") == 0) {
					tagsel = bmdVlanCfi;
				} else if (CDK_STRCMP(argv[2], "vid") == 0) {
					tagsel = bmdVlanVid;
				} else {
					return CDK_SHELL_CMD_BAD_ARG;
				}
				rv = bmd_port_tag_mangle_get(unit, port, tagsel, &value);			
				if (rv == CDK_E_NONE) {
        	        if (value)
    					CDK_PRINTF("Enabled \n");
					else 
    					CDK_PRINTF("Disabled \n");
				}
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}
	   	}
	} else if (argc == 3) {
		if (CDK_STRCMP(argv[0], "jumbo") == 0) {
			if (CDK_STRCMP(argv[2], "enable") == 0) {
                value = 1;
			} else if (CDK_STRCMP(argv[2], "disable") == 0) {
                value = 0;
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
                rv = bmd_port_jumbo_control_set(unit, port, value);
		    }
        } else if (CDK_STRCMP(argv[0], "traffic") == 0) {
		    if (CDK_STRCMP(argv[2], "onlytx") == 0) {
				traffic_ctrl = bmdNoRxButTx;
			} else if (CDK_STRCMP(argv[2], "onlyrx") == 0) {
				traffic_ctrl = bmdNoTxButRx;
           	} else if (CDK_STRCMP(argv[2], "both") == 0) {
				traffic_ctrl = bmdTxAndRx;
			} else if (CDK_STRCMP(argv[2], "none") == 0) {
				traffic_ctrl = bmdNoTxAndRx;
   			} else {
   				return CDK_SHELL_CMD_BAD_ARG;
    		}
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
                rv = bmd_port_traffic_control_set(unit, port, traffic_ctrl);
		    }
        } else if (CDK_STRCMP(argv[0], "pause") == 0) {
			if (CDK_STRCMP(argv[2], "onlytx") == 0) {
				pause = bmdPauseTx;
			} else if (CDK_STRCMP(argv[2], "onlyrx") == 0) {
				pause = bmdPauseRx;
            } else if (CDK_STRCMP(argv[2], "both") == 0) {
				pause = bmdPauseBoth;
			} else if (CDK_STRCMP(argv[2], "none") == 0) {
				pause = bmdPauseNone;
    		} else {
	   			return CDK_SHELL_CMD_BAD_ARG;
	    	}
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
                rv = bmd_port_pause_capability_set(unit, port, pause);
			}
        } else if (CDK_STRCMP(argv[0], "pbvlan") == 0) {
			pbport = bmd_shell_parse_port_str(unit, argv[2], &pbpbmp);
			if (pbport < 0) {
				return CDK_SHELL_CMD_BAD_ARG;
			}
			value = CDK_PBMP_WORD_GET(pbpbmp, 0);
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
			    rv = bmd_port_pbvlanmap_set(unit, port, value);
			}
		} else if (CDK_STRCMP(argv[0], "remaptag") == 0) {
			value = CDK_STRTOUL(argv[2], NULL, 0);
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
				rv = bmd_port_replace_egress_tag_set(unit, port, value);
			}
		} else if (CDK_STRCMP(argv[0], "remapmatchvid") == 0) {
			tagsel = bmdVlanMatchVid;
			value = CDK_STRTOUL(argv[2], NULL, 0);
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
				rv = bmd_port_tag_mangle_set(unit, port, tagsel, value);
			}
		} else if (CDK_STRCMP(argv[0], "pvlanpri") == 0) {
			value = CDK_STRTOUL(argv[2], NULL, 0);
			CDK_LPORT_ITER(unit, pbmp, lport, port) {
				rv = bmd_port_vlan_priority_set(unit, port, value);
			}
        } else {
				return CDK_SHELL_CMD_BAD_ARG;
        }
    } else if (argc == 2) {
        CDK_LPORT_ITER(unit, pbmp, lport, port) {
			if (CDK_STRCMP(argv[0], "jumbo") == 0) {
                rv = bmd_port_jumbo_control_get(unit, port, &value);
                if (rv == CDK_E_NONE) {
					if (value) {
						CDK_PRINTF("The port %d Jumbo Frame Support is Enabled \n", port);
					} else {
						CDK_PRINTF("The port %d Jumbo Frame Support is Disabled \n", port);
                	}
                }					

            } else if (CDK_STRCMP(argv[0], "traffic") == 0) {
                rv = bmd_port_traffic_control_get(unit, port, &traffic_ctrl);
                if (rv == CDK_E_NONE) {
					if (traffic_ctrl == bmdNoRxButTx) {
						CDK_PRINTF("The port %d Tx is Enabled and Rx is Disabled \n", port);
					} else if (traffic_ctrl == bmdNoTxButRx) {
						CDK_PRINTF("The port %d Tx is Disabled and Rx is Enabled \n", port);
					} else if (traffic_ctrl == bmdTxAndRx) {
						CDK_PRINTF("The port %d Tx and Rx are Enabled \n", port);
					} else {
						CDK_PRINTF("The port %d Tx and Rx are Disabled \n", port);
					}
                }
            } else if (CDK_STRCMP(argv[0], "pause") == 0) {
                rv = bmd_port_pause_capability_get(unit, port, &pause);
                if (rv == CDK_E_NONE) {
					if (pause == bmdPauseTx) {
						CDK_PRINTF("The port %d Tx Pause is Enabled \n", port);
					} else if (pause == bmdPauseRx) {
						CDK_PRINTF("The port %d Rx Pause is Enabled \n", port);
					} else if (pause == bmdPauseBoth) {
						CDK_PRINTF("The port %d Tx and Rx Pause is Enabled \n", port);
					} else if (pause == bmdPauseAuto) {
						CDK_PRINTF("The port %d Pause is based on AutoNegotiation \n", port);
					} else {
						CDK_PRINTF("The port %d Pause is Disabled \n", port);
					}
                }
            } else if (CDK_STRCMP(argv[0], "pbvlan") == 0) {
				rv = bmd_port_pbvlanmap_get(unit, port, (uint32_t *)&value);
                if (rv == CDK_E_NONE)
    				CDK_PRINTF("The port %d pbvlan portmap is 0x%x \n", port, value);
			} else if (CDK_STRCMP(argv[0], "remaptag") == 0) {
				rv = bmd_port_replace_egress_tag_get(unit, port, (uint32_t *)&value);
                if (rv == CDK_E_NONE)
    				CDK_PRINTF("The port %d remaptag for egress tag remapping is 0x%x \n", port, value);
			} else if (CDK_STRCMP(argv[0], "remapmatchvid") == 0) {
			    tagsel = bmdVlanMatchVid;
				rv = bmd_port_tag_mangle_get(unit, port, tagsel, &value);
                if (rv == CDK_E_NONE)
    				CDK_PRINTF("The port %d Match VID for egress tag remapping is 0x%x \n", port, value);
			} else if (CDK_STRCMP(argv[0], "pvlanpri") == 0) {
				rv = bmd_port_vlan_priority_get(unit, port, &value);
                if (rv == CDK_E_NONE)
    				CDK_PRINTF("The port %d default vlan priority is %d \n", port, value);
            } else {
				return CDK_SHELL_CMD_BAD_ARG;
            }
        }
    } else {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    return cdk_shell_error(rv);
}
