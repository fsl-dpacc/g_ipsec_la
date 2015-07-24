/**************************************************************************
 * Copyright 2010-2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	arpcctrl.c
 *
 * Description: This file contains the glue layer that registers with the
 *              the netlink layer for ARP messages. Upon notification,
 *              it calls ASF APIs for updating the ARP tables. It also 
 *              provides registration functions that ASF Layer can call 
 *              into when ARP entries are not found/invalid? 
 *		
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/*
 * History
 * Venkataramanan Subhashini: Initial Version
 *
 */
 /* Includes */
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>
#include <linux/netdevice.h>
#include <uapi/linux/neighbour.h>
#include <uapi/linux/netlink.h>
#include "nlnkreg.h"



/* Defines */


/* Structure Defintions */



/* Declarations */



/* Function Prototypes */



/* Static Functions */
/* Function code loosely based on code in neighbour.c */
static int arpcCtrlAdd(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct ndmsg *ndm;
	struct nlattr *tb[NDA_MAX+1];
//	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	int err;

	err = nlmsg_parse(nlh, sizeof(*ndm), tb, NDA_MAX, NULL);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (tb[NDA_DST] == NULL)
		goto out;

	ndm = nlmsg_data(nlh);
	if (ndm->ndm_ifindex) {
		dev = __dev_get_by_index(net, ndm->ndm_ifindex);
		if (dev == NULL) {
			err = -ENODEV;
			goto out;
		}

		if (tb[NDA_LLADDR] && nla_len(tb[NDA_LLADDR]) < dev->addr_len)
			goto out;
	}
	printk(


	err = -EAFNOSUPPORT;
out:
	return err;
}


/* APIs */



/* Init - De-Init routines */
void arpCtrlDeInit(void)
{
	nLinkDeRegister(PF_UNSPEC, RTM_NEWNEIGH);
	nLinkDeRegister(PF_UNSPEC, RTM_DELNEIGH);
  
}

void arpCtrlInit(void)
{
   nLinkRegister(PF_UNSPEC, RTM_NEWNEIGH, arpcCtrlAdd, NULL, NULL);
   nLinkRegister(PF_UNSPEC, RTM_DELNEIGH, arpcCtrlDel, NULL, NULL);
	
}



