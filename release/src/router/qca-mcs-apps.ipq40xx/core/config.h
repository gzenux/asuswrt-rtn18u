/*
 * @File: config.h
 *
 * @Abstract: configuration file definitions and declarations;
 *
 * @Notes:
 * configuration files contain named parts where each part may
 * contain one of more named items that have text definitions;
 *
 * the named file can be searched for the first occurrence of a
 * named part then the first occurrence of a named item;
 *
 *   [part1]
 *   item1=text
 *   item2=text
 *
 *   [part1]
 *   item1=text
 *   item2=text
 *
 *   an example fetch might look like ...
 *
 *   const char * text = configstring ("myfile.conf", "part2", "item 2", "");
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef CONFIG_HEADER
#define CONFIG_HEADER

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

const char *configstring(const char *file, const char *part, const char *item, const char *text);

/*====================================================================*
 *   end definitions;
 *--------------------------------------------------------------------*/

#endif


