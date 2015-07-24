/**************************************************************************
 * Copyright 2010-2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	nlinkreg.h.c
 *
 * Description: Header file that contains the APIs that the ASF ARP/Routing 
 * 	        can call to register the netlink glue layer
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/*
 * History
 * Venkataramanan Subhashini: Initial Version
 *
 */
#ifndef _NLINK_REG_H
#define _NLINK_REG_H

/* Function defintions */
int nLinkRegister(int protocol, int msgtype,
	rtnl_doit_funct doit);

int nLinkDeRegister(int protocol, int msgtype);
#endif
