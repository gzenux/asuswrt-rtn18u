// vim: set et sw=4 sts=4 cindent:
/*
 * @File: lb_module.h
 *
 * @Abstract: Load balancing module names
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015-2016 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#ifndef md__h
#error "This file should not be included directly. Include module.h instead"
#endif

/**
 * This is meant to be included into the source file that contains the
 * complete set of module identifiers.
 */

    mdModuleID_WlanIF,
    mdModuleID_BandMon,

    mdModuleID_WlanIF_Config_24G,
    mdModuleID_WlanIF_Config_5G,

    mdModuleID_StaDB,
    mdModuleID_SteerExec,

    mdModuleID_StaMon,

    mdModuleID_DiagLog,

    mdModuleID_Estimator,

    mdModuleID_SteerAlg,

    mdModuleID_Persist,
