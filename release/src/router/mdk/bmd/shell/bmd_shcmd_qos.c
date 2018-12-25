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
#include <bmd/shell/shcmd_qos.h>

#include "bmd_shell_util.h"

int 
bmd_shcmd_qos(int argc, char *argv[])
{
    int unit;
    cdk_pbmp_t pbmp;
    int lport, port;
    int dscp, priority, queue, value, channel;
    int rv = CDK_E_NONE;
	bmd_cosq_qos_type_t method;
	bmd_cosq_sched_t sched;
	bmd_cosq_txqsel_t txqsel;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    if (argc < 1) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (CDK_STRCMP(argv[0], "multiq") == 0) {
	    if (argc == 2) {
			if (CDK_STRCMP(argv[1], "enable") == 0) {
				value = 4;
			} else if (CDK_STRCMP(argv[1], "disable") == 0) {
				value = 1;
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}
			rv = bmd_cosq_config_set(unit, value);
   		} else if (argc == 1) {
			rv = bmd_cosq_config_get(unit, &value);
			if (rv == CDK_E_NONE) {
                if (value > 1) { 
				    CDK_PRINTF("QoS multiple queues is enabled \n");
                } else {
				    CDK_PRINTF("QoS multiple queues is disabled \n");
                }
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
	    }
    } else if (CDK_STRCMP(argv[0], "dscpmap") == 0) {
   		if (argc == 3) {
    		dscp = CDK_STRTOUL(argv[1], NULL, 0);
	    	priority = CDK_STRTOUL(argv[2], NULL, 0);
			rv = bmd_cosq_dscp_priority_mapping_set(unit, dscp, priority);
   		} else if (argc == 2) {
    		dscp = CDK_STRTOUL(argv[1], NULL, 0);
			rv = bmd_cosq_dscp_priority_mapping_get(unit, dscp, &priority);
			if (rv == CDK_E_NONE) {
				CDK_PRINTF("dscp %d is mapped to priority %d \n", dscp, priority);
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
   		}
    } else if (CDK_STRCMP(argv[0], "portprimap") == 0) {
		if (argc < 3) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
		port = bmd_shell_parse_port_str(unit, argv[1], &pbmp);
		if (port < 0) {
			return CDK_SHELL_CMD_BAD_ARG;
		}
		CDK_LPORT_ITER(unit, pbmp, lport, port) {
			if (argc == 4) {
				priority = CDK_STRTOUL(argv[2], NULL, 0);
				queue = CDK_STRTOUL(argv[3], NULL, 0);
				rv = bmd_cosq_port_mapping_set(unit, port, priority, queue);
			} else if (argc == 3) {
				priority = CDK_STRTOUL(argv[2], NULL, 0);
				rv = bmd_cosq_port_mapping_get(unit, port, priority, &queue);			
				if (rv == CDK_E_NONE) {
					CDK_PRINTF("port %d priority %d is mapped to egress queue %d \n", port, priority, queue);
				}
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}
	   	}
    } else if (CDK_STRCMP(argv[0], "method") == 0) {
		if (argc == 2) {
			if (CDK_STRCMP(argv[1], "port") == 0) {
				method = bmdPortQoS;
			} else if (CDK_STRCMP(argv[1], "mac") == 0) {
				method = bmdMacQoS;
			} else if (CDK_STRCMP(argv[1], "8021p") == 0) {
				method = bmdPrio8021PQoS;
			} else if (CDK_STRCMP(argv[1], "diffserv") == 0) {
				method = bmdDiffServQoS;
			} else if (CDK_STRCMP(argv[1], "traffictype") == 0) {
				method = bmdTrafficTypeQoS;
			} else if (CDK_STRCMP(argv[1], "combo") == 0) {
				method = bmdComboQoS;
			} else if (CDK_STRCMP(argv[1], "combohigh") == 0) {
				method = bmdComboHighestQoS;
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}
			rv = bmd_cosq_priority_method_set(unit, method);
		} else if (argc == 1) {
			rv = bmd_cosq_priority_method_get(unit, &method);			
			if (rv == CDK_E_NONE) {
				if (method == bmdPortQoS) {
					CDK_PRINTF("Port Based QoS \n");
				} else if (method == bmdMacQoS) {
					CDK_PRINTF("MAC Based QoS \n");
				} else if (method == bmdPrio8021PQoS) {
					CDK_PRINTF("802.1p Based QoS \n");
				} else if (method == bmdDiffServQoS) {
					CDK_PRINTF("Diffserv Based QoS \n");
				} else if (method == bmdTrafficTypeQoS) {
					CDK_PRINTF("Traffic Type Based QoS \n");
				} else if (method == bmdComboQoS) {
					CDK_PRINTF("Combo QoS (Diffserv else 802.1p else MAC) \n");
				} else if (method == bmdComboHighestQoS) {
					CDK_PRINTF("Combo Highest QoS (Highest priority of avialable types) \n");
				} else {
					CDK_PRINTF("None \n");
				}
			} else {
	    	    return CDK_SHELL_CMD_BAD_ARG;
			}
	   	}
    } else if (CDK_STRCMP(argv[0], "qtodma") == 0) {
   		if (argc == 3) {
    		queue = CDK_STRTOUL(argv[1], NULL, 0);
	    	channel = CDK_STRTOUL(argv[2], NULL, 0);
			rv = bmd_cosq_rxchannel_mapping_set(unit, queue, channel);
   		} else if (argc == 2) {
    		queue = CDK_STRTOUL(argv[1], NULL, 0);
			rv = bmd_cosq_rxchannel_mapping_get(unit, queue, &channel);
			if (rv == CDK_E_NONE) {
				CDK_PRINTF("The IMP port egress queue %d is mapped to IUDMA channel (Switch to MIPS) %d \n", queue, channel);
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
   		}
    } else if (CDK_STRCMP(argv[0], "dmatoq") == 0) {
   		if (argc == 3) {
    		channel = CDK_STRTOUL(argv[1], NULL, 0);
	    	queue = CDK_STRTOUL(argv[2], NULL, 0);
			rv = bmd_cosq_txchannel_mapping_set(unit, channel, queue);
   		} else if (argc == 2) {
    		channel = CDK_STRTOUL(argv[1], NULL, 0);
			rv = bmd_cosq_txchannel_mapping_get(unit, channel, &queue);
			if (rv == CDK_E_NONE) {
				CDK_PRINTF("The IUDMA channel (MIPS to Switch) %d is mapped to egress queue %d \n", channel, queue);
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
   		}
    } else if (CDK_STRCMP(argv[0], "sched") == 0) {
   		if (argc >= 2) {
			if (CDK_STRCMP(argv[1], "strict") == 0) {
			    if (argc != 2)
					return CDK_SHELL_CMD_BAD_ARG;
				sched = bmdStrictPriority;
			} else if (CDK_STRCMP(argv[1], "wrr") == 0) {
			    if (argc != 2)
					return CDK_SHELL_CMD_BAD_ARG;
				sched = bmdWeightedRoundRobin;
			} else if (CDK_STRCMP(argv[1], "combo") == 0) {
			    if (argc != 3)
					return CDK_SHELL_CMD_BAD_ARG;
				sched = bmdSpWrrCombo;
                if (argv[2])
    				value = CDK_STRTOUL(argv[2], NULL, 0);
				else 
					return CDK_SHELL_CMD_BAD_ARG;
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}            
			rv = bmd_cosq_sched_set(unit, sched, value);
   		} else if (argc == 1) {
			rv = bmd_cosq_sched_get(unit, &sched, &value);
			if (rv == CDK_E_NONE) {
				if (sched == bmdStrictPriority) {
					CDK_PRINTF("Strict Priority \n");
				} else if (sched == bmdWeightedRoundRobin) {
					CDK_PRINTF("Weighted Round Robin \n");
				} else if (sched == bmdSpWrrCombo) {
					CDK_PRINTF("Strict Priority from highest queue to queue %d. "
						        "Weighted Round Robin for remaining queues\n", value);
				} else {
					CDK_PRINTF("QoS (multiple queues) is probably not enabled \n");
				}
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
   		}
    } else if (CDK_STRCMP(argv[0], "txqsel") == 0) {
   		if (argc == 2) {
			if (CDK_STRCMP(argv[1], "usebd") == 0) {
				txqsel = bmdUseTxBdPrio;
			} else if (CDK_STRCMP(argv[1], "usedmaq") == 0) {
				txqsel = bmdUseTxDmaChannel;
			} else if (CDK_STRCMP(argv[1], "none") == 0) {
				txqsel = bmdUseNone;
			} else {
				return CDK_SHELL_CMD_BAD_ARG;
			}            
			rv = bmd_cosq_txq_selection_set(unit, txqsel);
   		} else if (argc == 1) {
			rv = bmd_cosq_txq_selection_get(unit, &txqsel);
			if (rv == CDK_E_NONE) {
				if (txqsel == bmdUseTxBdPrio) {
					CDK_PRINTF("The priority in Tx BD is used for egress queue selection \n");
				} else if (txqsel == bmdUseTxDmaChannel) {
					CDK_PRINTF("The DMA channel is used for egress queue selection \n");
				} else {
					CDK_PRINTF("Neither TxBD nor DMA channel is used \n");
				}
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
   		}
	} else if (CDK_STRCMP(argv[0], "wrr") == 0) {
   		if (argc == 3) {
	    	queue = CDK_STRTOUL(argv[1], NULL, 0);
	    	value = CDK_STRTOUL(argv[2], NULL, 0);
			rv = bmd_cosq_wrr_weight_set(unit, queue, value);
   		} else if (argc == 2) {
	    	queue = CDK_STRTOUL(argv[1], NULL, 0);
			rv = bmd_cosq_wrr_weight_get(unit, queue, &value);
			if (rv == CDK_E_NONE) {
				CDK_PRINTF("Queue %d WRR weight is %d \n", queue, value);
			}
    	} else {
	    	return CDK_SHELL_CMD_BAD_ARG;
   		}
    } else {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    return cdk_shell_error(rv);
}
