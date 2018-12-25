/* @file: apac_hyfi20_ctrl.h
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#ifndef _APAC_HYFI20_CTRL_H
#define _APAC_HYFI20_CTRL_H

#define CTRL_KEEPLIVE_TIMEOUT 5
#define CTRL_REATTACH_TIMEOUT 1

int apac_ctrl_unregister_IF(apacHyfi20IF_t *pIF, apacHyfi20Data_t *pApacData);
int apac_ctrl_register_IF(apacHyfi20IF_t *pIF, apacHyfi20Data_t *pApacData);
int apac_ctrl_activate_PBC(apacHyfi20IF_t *pIF);
int apac_ctrl_init(apacHyfi20Data_t* pApacData);
int apac_ctrl_deinit(apacHyfi20Data_t* pApacData);

#endif
